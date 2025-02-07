package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/lib/jwt"
	"github.com/Homyakadze14/AuthMicroservice/internal/services/mocks"
	userv1 "github.com/Homyakadze14/AuthMicroservice/proto/gen/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type cfg struct {
	log         *slog.Logger
	accRepo     *mocks.AccountRepo
	tokRepo     *mocks.TokenRepo
	linkRepo    *mocks.LinkRepo
	jwtAcc      *config.JWTAccessConfig
	jwtRef      *config.JWTRefreshConfig
	mailer      *mocks.Mailer
	pwdLinkRepo *mocks.PwdLinkRepo
	userService *mocks.UserServiceI
}

func NewService(cfg cfg) *AuthService {
	ctx := context.Background()

	accRepo := cfg.accRepo
	if accRepo == nil {
		accRepo = &mocks.AccountRepo{}
		accRepo.On("Create", ctx, mock.AnythingOfType("*entities.Account")).Return(0, nil).Once()
	}

	tokenRepo := cfg.tokRepo
	if tokenRepo == nil {
		tokenRepo = &mocks.TokenRepo{}
		tokenRepo.On("Create", ctx, mock.AnythingOfType("*entities.Token")).Return(nil).Once()
	}

	linkRepo := cfg.linkRepo
	if linkRepo == nil {
		linkRepo = &mocks.LinkRepo{}
		linkRepo.On("Create", ctx, mock.AnythingOfType("*entities.Link")).Return(nil).Once()
	}

	pwdLinkRepo := cfg.pwdLinkRepo
	if pwdLinkRepo == nil {
		pwdLinkRepo = &mocks.PwdLinkRepo{}
		pwdLinkRepo.On("Create", ctx, mock.AnythingOfType("*entities.PwdLink")).Return(nil).Once()
	}

	jwtAcc := &config.JWTAccessConfig{
		Secret:   "test_acc",
		Duration: 3 * time.Second,
	}

	jwtRef := &config.JWTRefreshConfig{
		Secret:   "test_ref",
		Duration: 5 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mailer := cfg.mailer
	if mailer == nil {
		mailer = &mocks.Mailer{}
	}
	userService := cfg.userService
	if userService == nil {
		userService = &mocks.UserServiceI{}
	}

	return NewAuthService(log, accRepo, tokenRepo, linkRepo, jwtAcc, jwtRef, mailer, pwdLinkRepo, userService)
}

func TestRegister(t *testing.T) {
	ctx := context.Background()

	oldPass := "Test"
	testAcc := &entities.Account{
		ID:       1,
		Username: "Test",
		Password: oldPass,
		Email:    "Test",
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("Create", ctx, testAcc).Return(testAcc.ID, nil).Once()

	mailer := &mocks.Mailer{}
	mailer.On("SendActivationMail", testAcc.Email, mock.Anything).Return(nil).Once()

	sCfg := cfg{
		accRepo: accRepo,
		mailer:  mailer,
	}

	t.Log("Check registration")
	service := NewService(sCfg)
	err := service.Register(ctx, testAcc)

	assert.NotEqual(t, testAcc.Password, oldPass)
	assert.Nil(t, err)
}

func TestRegisterAccountError(t *testing.T) {
	ctx := context.Background()

	err := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("Create", ctx, mock.AnythingOfType("*entities.Account")).Return(-1, err).Once()

	sCfg := cfg{
		accRepo: accRepo,
	}

	service := NewService(sCfg)
	err = service.Register(ctx, &entities.Account{})

	assert.Error(t, err)
}

func TestRegisterLinkError(t *testing.T) {
	ctx := context.Background()

	err := errors.New("test")

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Create", ctx, mock.AnythingOfType("*entities.Link")).Return(err).Once()

	userService := &mocks.UserServiceI{}
	userService.On("CreateDefault", ctx,
		&userv1.CreateDefaultRequest{UserId: 0}).Return(&userv1.CreateDefaultResponse{}, nil).Once()

	sCfg := cfg{
		linkRepo:    linkRepo,
		userService: userService,
	}

	service := NewService(sCfg)
	err = service.Register(ctx, &entities.Account{})

	assert.Error(t, err)
}

func TestLoginByUsername(t *testing.T) {
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "Test",
		Email:    "",
		Password: pwd,
	}

	hashPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	bdTestAccount := &entities.Account{
		Username: "Test",
		Email:    "Test",
		Password: string(hashPwd),
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByUsername", ctx, testAccount.Username).Return(bdTestAccount, nil).Once()

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("IsActivated", ctx, testAccount.ID).Return(true, nil).Once()

	sCfg := cfg{
		accRepo:  accRepo,
		linkRepo: linkRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.Nil(t, err)
	assert.NotEmpty(t, pair)
}

func TestLoginByEmail(t *testing.T) {
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "",
		Email:    "test@mail.com",
		Password: pwd,
	}

	hashPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	bdTestAccount := &entities.Account{
		Username: "Test",
		Email:    "test@mail.com",
		Password: string(hashPwd),
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, testAccount.Email).Return(bdTestAccount, nil).Once()

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("IsActivated", ctx, testAccount.ID).Return(true, nil).Once()

	sCfg := cfg{
		accRepo:  accRepo,
		linkRepo: linkRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.Nil(t, err)
	assert.NotEmpty(t, pair)
}

func TestTokenExpirationAndVerification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "Test",
		Email:    "",
		Password: pwd,
	}

	hashPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	bdTestAccount := &entities.Account{
		Username: "Test",
		Email:    "Test",
		Password: string(hashPwd),
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByUsername", ctx, testAccount.Username).Return(bdTestAccount, nil).Once()

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("IsActivated", ctx, testAccount.ID).Return(true, nil).Once()

	sCfg := cfg{
		accRepo:  accRepo,
		linkRepo: linkRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.Nil(t, err)
	assert.NotEmpty(t, pair)

	t.Log("Check token expiration")
	wg := &sync.WaitGroup{}
	wg.Add(2)

	verified, err := service.Verify(ctx, pair.AccessToken)
	assert.NoError(t, err, jwt.ErrTokenExpired)
	assert.True(t, verified)

	go func() {
		defer wg.Done()
		time.Sleep(service.jwtAcc.Duration)
		verified, err := service.Verify(ctx, pair.AccessToken)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
		assert.False(t, verified)
	}()

	go func() {
		defer wg.Done()
		time.Sleep(service.jwtRef.Duration)
		_, err := jwt.ParseToken(pair.RefreshToken, service.jwtRef.Secret)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	}()

	wg.Wait()
}

func TestLoginEmptyFieldsError(t *testing.T) {
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "",
		Email:    "",
		Password: pwd,
	}

	sCfg := cfg{}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.ErrorIs(t, err, ErrBadCredentials)
	assert.Empty(t, pair)
}

func TestLoginWrongPasswordError(t *testing.T) {
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "",
		Email:    "test@mail.com",
		Password: pwd,
	}

	hashPwd, _ := bcrypt.GenerateFromPassword([]byte("Test1"), bcrypt.DefaultCost)
	bdTestAccount := &entities.Account{
		Username: "Test",
		Email:    "test@mail.com",
		Password: string(hashPwd),
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, testAccount.Email).Return(bdTestAccount, nil).Once()

	sCfg := cfg{
		accRepo: accRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.ErrorIs(t, err, ErrBadCredentials)
	assert.Empty(t, pair)
}

func TestLoginActivationErr(t *testing.T) {
	ctx := context.Background()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "",
		Email:    "test@mail.com",
		Password: pwd,
	}

	hashPwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	bdTestAccount := &entities.Account{
		Username: "Test",
		Email:    "test@mail.com",
		Password: string(hashPwd),
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, testAccount.Email).Return(bdTestAccount, nil).Once()

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("IsActivated", ctx, testAccount.ID).Return(false, nil).Once()

	sCfg := cfg{
		accRepo:  accRepo,
		linkRepo: linkRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Login(ctx, testAccount)

	assert.Error(t, err)
	assert.Empty(t, pair)
}

func TestLogout(t *testing.T) {
	ctx := context.Background()

	refreshToken := &entities.LogoutRequest{RefreshToken: "testtoken"}

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken.RefreshToken).Return(&entities.Token{}, nil).Once()
	tokenRepo.On("Delete", ctx, refreshToken.RefreshToken).Return(nil).Once()

	sCfg := cfg{
		tokRepo: tokenRepo,
	}

	service := NewService(sCfg)
	err := service.Logout(ctx, refreshToken)

	assert.NoError(t, err)
}

func TestLogoutErrNotFoundToken(t *testing.T) {
	ctx := context.Background()

	refreshToken := &entities.LogoutRequest{RefreshToken: "testtoken"}
	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken.RefreshToken).Return(nil, err).Once()
	tokenRepo.On("Delete", ctx, refreshToken.RefreshToken).Return(nil).Once()

	sCfg := cfg{
		tokRepo: tokenRepo,
	}

	service := NewService(sCfg)
	err = service.Logout(ctx, refreshToken)

	assert.Error(t, err)
}

func TestLogoutErrDelete(t *testing.T) {
	ctx := context.Background()

	refreshToken := &entities.LogoutRequest{RefreshToken: "testtoken"}
	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken.RefreshToken).Return(&entities.Token{}, nil).Once()
	tokenRepo.On("Delete", ctx, refreshToken.RefreshToken).Return(err).Once()

	sCfg := cfg{
		tokRepo: tokenRepo,
	}

	service := NewService(sCfg)
	err = service.Logout(ctx, refreshToken)

	assert.Error(t, err)
}

func TestActivateAccount(t *testing.T) {
	ctx := context.Background()

	link := "testlink"
	bdLink := &entities.Link{
		ID:          1,
		UserID:      1,
		Link:        link,
		IsActivated: false,
	}

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Get", ctx, link).Return(bdLink, nil).Once()
	linkRepo.On("Update", ctx, bdLink.ID, bdLink).Return(nil).Once()

	userService := &mocks.UserServiceI{}
	userService.On("CreateDefault", ctx,
		&userv1.CreateDefaultRequest{UserId: int64(bdLink.UserID)}).Return(&userv1.CreateDefaultResponse{}, nil).Once()

	sCfg := cfg{
		linkRepo:    linkRepo,
		userService: userService,
	}

	service := NewService(sCfg)
	err := service.ActivateAccount(ctx, link)

	assert.NoError(t, err)
	assert.Equal(t, bdLink.IsActivated, true)
}

func TestActivateAccountGetErr(t *testing.T) {
	ctx := context.Background()

	link := "testlink"
	err := errors.New("test")

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Get", ctx, link).Return(nil, err).Once()

	sCfg := cfg{
		linkRepo: linkRepo,
	}

	service := NewService(sCfg)
	err = service.ActivateAccount(ctx, link)

	assert.Error(t, err)
}

func TestActivateAccountUpdateErr(t *testing.T) {
	ctx := context.Background()

	link := "testlink"
	bdLink := &entities.Link{
		ID:          1,
		UserID:      1,
		Link:        link,
		IsActivated: false,
	}
	err := errors.New("test")

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Get", ctx, link).Return(bdLink, nil).Once()
	linkRepo.On("Update", ctx, bdLink.ID, bdLink).Return(err).Once()

	userService := &mocks.UserServiceI{}
	userService.On("CreateDefault", ctx,
		&userv1.CreateDefaultRequest{UserId: int64(bdLink.UserID)}).Return(&userv1.CreateDefaultResponse{}, nil).Once()

	sCfg := cfg{
		linkRepo:    linkRepo,
		userService: userService,
	}

	service := NewService(sCfg)
	err = service.ActivateAccount(ctx, link)

	assert.Error(t, err)
}

func TestActivateCreateUserErr(t *testing.T) {
	ctx := context.Background()

	link := "testlink"
	bdLink := &entities.Link{
		ID:          1,
		UserID:      1,
		Link:        link,
		IsActivated: false,
	}
	err := errors.New("test")

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Get", ctx, link).Return(bdLink, nil).Once()
	linkRepo.On("Update", ctx, bdLink.ID, bdLink).Return(nil).Once()

	userService := &mocks.UserServiceI{}
	userService.On("CreateDefault", ctx,
		&userv1.CreateDefaultRequest{UserId: int64(bdLink.UserID)}).Return(&userv1.CreateDefaultResponse{}, err).Once()

	sCfg := cfg{
		linkRepo:    linkRepo,
		userService: userService,
	}

	service := NewService(sCfg)
	err = service.ActivateAccount(ctx, link)

	assert.Error(t, err)
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()

	testAcc := &entities.Account{ID: 1, Username: "test"}
	jwtRef := &config.JWTRefreshConfig{
		Secret:   "test_ref",
		Duration: 5 * time.Second,
	}

	refreshToken, _ := jwt.NewToken(testAcc, jwtRef.Secret, jwtRef.Duration)

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken).Return(&entities.Token{UserID: 1}, nil).Once()

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByUserID", ctx, "1").Return(testAcc, nil).Once()

	sCfg := cfg{
		accRepo: accRepo,
		tokRepo: tokenRepo,
		jwtRef:  jwtRef,
	}

	service := NewService(sCfg)
	pair, err := service.Refresh(ctx, refreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, pair)
}

func TestRefreshTokErr(t *testing.T) {
	ctx := context.Background()

	refreshToken := "testtoken"
	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken).Return(nil, err).Once()

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByUserID", ctx, "1").Return(&entities.Account{ID: 1, Username: "test"}, nil).Once()

	sCfg := cfg{
		accRepo: accRepo,
		tokRepo: tokenRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Refresh(ctx, refreshToken)

	assert.Error(t, err)
	assert.Empty(t, pair)
}

func TestRefreshAccErr(t *testing.T) {
	ctx := context.Background()

	refreshToken := "testtoken"
	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", ctx, refreshToken).Return(&entities.Token{UserID: 1}, nil).Once()

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByUserID", ctx, "1").Return(nil, err).Once()

	sCfg := cfg{
		accRepo: accRepo,
		tokRepo: tokenRepo,
	}

	service := NewService(sCfg)
	pair, err := service.Refresh(ctx, refreshToken)

	assert.Error(t, err)
	assert.Empty(t, pair)
}

func TestSendPwdLink(t *testing.T) {
	ctx := context.Background()

	email := "test"
	link := "test"

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, email).Return(&entities.Account{}, nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByEmail", ctx, email).Return(&entities.PwdLink{Email: email, Link: link}, nil).Once()

	mailer := &mocks.Mailer{}
	mailer.On("SendPwdMail", email, link).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		mailer:      mailer,
	}

	service := NewService(sCfg)

	success, err := service.SendPwdLink(ctx, email)

	assert.NoError(t, err)
	assert.NotEmpty(t, success)
}

func TestSendPwdLinkCreateLink(t *testing.T) {
	ctx := context.Background()

	email := "test"

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, email).Return(&entities.Account{}, nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByEmail", ctx, email).Return(nil, ErrLinkNotFound).Once()
	pwdLinkRepo.On("Create", ctx, mock.AnythingOfType("*entities.PwdLink")).Return(nil).Once()

	mailer := &mocks.Mailer{}
	mailer.On("SendPwdMail", email, mock.AnythingOfType("string")).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		mailer:      mailer,
	}

	service := NewService(sCfg)
	success, err := service.SendPwdLink(ctx, email)

	assert.NoError(t, err)
	assert.NotEmpty(t, success)
}

func TestSendPwdLinkErr(t *testing.T) {
	ctx := context.Background()

	email := "test"
	tErr := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("GetByEmail", ctx, email).Return(&entities.Account{}, nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByEmail", ctx, email).Return(nil, tErr).Once()

	mailer := &mocks.Mailer{}
	mailer.On("SendPwdMail", email, mock.AnythingOfType("string")).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		mailer:      mailer,
	}

	service := NewService(sCfg)
	success, err := service.SendPwdLink(ctx, email)

	assert.ErrorIs(t, err, tErr)
	assert.Empty(t, success)
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()

	link := "test"
	email := "test"

	accRepo := &mocks.AccountRepo{}
	accRepo.On("UpdatePwdByEmail", ctx, email, mock.AnythingOfType("string")).Return(nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByLink", ctx, link).Return(&entities.PwdLink{Email: email}, nil).Once()
	pwdLinkRepo.On("Delete", ctx, link).Return(nil).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("DeleteAllByEmail", ctx, email).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		tokRepo:     tokenRepo,
	}

	service := NewService(sCfg)
	success, err := service.ChangePwd(ctx, &entities.ChPwdLink{Link: link, Password: "test"})

	assert.NoError(t, err)
	assert.NotEmpty(t, success)
}

func TestChangePasswordGetByLinkErr(t *testing.T) {
	ctx := context.Background()

	link := "test"
	email := "test"
	tErr := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("UpdatePwdByEmail", ctx, email, mock.AnythingOfType("string")).Return(nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByLink", ctx, link).Return(nil, tErr).Once()
	pwdLinkRepo.On("Delete", ctx, link).Return(nil).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("DeleteAllByEmail", ctx, email).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		tokRepo:     tokenRepo,
	}

	service := NewService(sCfg)
	success, err := service.ChangePwd(ctx, &entities.ChPwdLink{Link: link, Password: "test"})

	assert.ErrorIs(t, err, tErr)
	assert.Empty(t, success)
}

func TestChangePasswordUpdatePwdByEmailErr(t *testing.T) {
	ctx := context.Background()

	link := "test"
	email := "test"
	tErr := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("UpdatePwdByEmail", ctx, email, mock.AnythingOfType("string")).Return(tErr).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByLink", ctx, link).Return(&entities.PwdLink{Email: email}, nil).Once()
	pwdLinkRepo.On("Delete", ctx, link).Return(nil).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("DeleteAllByEmail", ctx, email).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		tokRepo:     tokenRepo,
		pwdLinkRepo: pwdLinkRepo,
	}

	service := NewService(sCfg)
	success, err := service.ChangePwd(ctx, &entities.ChPwdLink{Link: link, Password: "test"})

	assert.ErrorIs(t, err, tErr)
	assert.Empty(t, success)
}

func TestChangePasswordDeleteErr(t *testing.T) {
	ctx := context.Background()

	link := "test"
	email := "test"
	tErr := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("UpdatePwdByEmail", ctx, email, mock.AnythingOfType("string")).Return(nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByLink", ctx, link).Return(&entities.PwdLink{Email: email}, nil).Once()
	pwdLinkRepo.On("Delete", ctx, link).Return(tErr).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("DeleteAllByEmail", ctx, email).Return(nil).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		tokRepo:     tokenRepo,
	}

	service := NewService(sCfg)
	success, err := service.ChangePwd(ctx, &entities.ChPwdLink{Link: link, Password: "test"})

	assert.ErrorIs(t, err, tErr)
	assert.Empty(t, success)
}

func TestChangePasswordDeleteAllAccsByEmail(t *testing.T) {
	ctx := context.Background()

	link := "test"
	email := "test"
	tErr := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("UpdatePwdByEmail", ctx, email, mock.AnythingOfType("string")).Return(nil).Once()

	pwdLinkRepo := &mocks.PwdLinkRepo{}
	pwdLinkRepo.On("GetByLink", ctx, link).Return(&entities.PwdLink{Email: email}, nil).Once()
	pwdLinkRepo.On("Delete", ctx, link).Return(nil).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("DeleteAllByEmail", ctx, email).Return(tErr).Once()

	sCfg := cfg{
		accRepo:     accRepo,
		pwdLinkRepo: pwdLinkRepo,
		tokRepo:     tokenRepo,
	}

	service := NewService(sCfg)
	success, err := service.ChangePwd(ctx, &entities.ChPwdLink{Link: link, Password: "test"})

	assert.ErrorIs(t, err, tErr)
	assert.Empty(t, success)
}
