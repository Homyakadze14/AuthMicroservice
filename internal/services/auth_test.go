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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type DefaultTestData struct {
	ctx      context.Context
	log      *slog.Logger
	accRepo  *mocks.AccountRepo
	tokRepo  *mocks.TokenRepo
	linkRepo *mocks.LinkRepo
	jwtAcc   *config.JWTAccessConfig
	jwtRef   *config.JWTRefreshConfig
}

func NewDefaultTestData() *DefaultTestData {
	ctx := context.Background()

	accRepo := &mocks.AccountRepo{}
	accRepo.On("Create", ctx, mock.AnythingOfType("*entities.Account")).Return(0, nil).Once()

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Create", ctx, mock.AnythingOfType("*entities.Token")).Return(nil).Once()

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Create", ctx, mock.AnythingOfType("*entities.Link")).Return(nil).Once()

	jwtAcc := &config.JWTAccessConfig{
		Secret:   "test_acc",
		Duration: 3 * time.Second,
	}

	jwtRef := &config.JWTRefreshConfig{
		Secret:   "test_ref",
		Duration: 5 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	return &DefaultTestData{
		log:      log,
		ctx:      ctx,
		accRepo:  accRepo,
		tokRepo:  tokenRepo,
		linkRepo: linkRepo,
		jwtAcc:   jwtAcc,
		jwtRef:   jwtRef,
	}
}

func TestRegister(t *testing.T) {
	testData := NewDefaultTestData()

	oldPass := "Test"
	testAcc := &entities.Account{
		Username: "Test",
		Password: oldPass,
		Email:    "Test",
	}

	accRepo := &mocks.AccountRepo{}
	accRepo.On("Create", testData.ctx, testAcc).Return(0, nil).Once()
	testData.accRepo = accRepo

	t.Log("Check registration")
	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Register(testData.ctx, testAcc)

	assert.NotEqual(t, testAcc.Password, oldPass)
	assert.Nil(t, err)
	assert.NotEmpty(t, pair)

	t.Log("Check token expiration")
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		time.Sleep(testData.jwtAcc.Duration)
		_, err := jwt.ParseToken(pair.AccessToken, testData.jwtAcc.Secret)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	}()

	go func() {
		defer wg.Done()
		time.Sleep(testData.jwtRef.Duration)
		_, err := jwt.ParseToken(pair.RefreshToken, testData.jwtRef.Secret)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	}()

	wg.Wait()
}

func TestRegisterAccountError(t *testing.T) {
	testData := NewDefaultTestData()

	err := errors.New("test")

	accRepo := &mocks.AccountRepo{}
	accRepo.On("Create", testData.ctx, mock.AnythingOfType("*entities.Account")).Return(-1, err).Once()
	testData.accRepo = accRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Register(testData.ctx, &entities.Account{})

	assert.Error(t, err)
	assert.Nil(t, pair)
}

func TestRegisterLinkError(t *testing.T) {
	testData := NewDefaultTestData()

	err := errors.New("test")

	linkRepo := &mocks.LinkRepo{}
	linkRepo.On("Create", testData.ctx, mock.AnythingOfType("*entities.Link")).Return(err).Once()
	testData.linkRepo = linkRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Register(testData.ctx, &entities.Account{})

	assert.Error(t, err)
	assert.Nil(t, pair)
}

func TestRegisterTokenError(t *testing.T) {
	testData := NewDefaultTestData()

	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Create", testData.ctx, mock.AnythingOfType("*entities.Token")).Return(err).Once()
	testData.tokRepo = tokenRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Register(testData.ctx, &entities.Account{})

	assert.Error(t, err)
	assert.Nil(t, pair)
}

func TestLoginByUsername(t *testing.T) {
	testData := NewDefaultTestData()

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
	accRepo.On("GetByUsername", testData.ctx, testAccount.Username).Return(bdTestAccount, nil).Once()
	testData.accRepo = accRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Login(testData.ctx, testAccount)

	assert.Nil(t, err)
	assert.NotEmpty(t, pair)
}

func TestLoginByEmail(t *testing.T) {
	testData := NewDefaultTestData()

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
	accRepo.On("GetByEmail", testData.ctx, testAccount.Email).Return(bdTestAccount, nil).Once()
	testData.accRepo = accRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Login(testData.ctx, testAccount)

	assert.Nil(t, err)
	assert.NotEmpty(t, pair)
}

func TestLoginEmptyFieldsError(t *testing.T) {
	testData := NewDefaultTestData()

	pwd := "Test"
	testAccount := &entities.Account{
		Username: "",
		Email:    "",
		Password: pwd,
	}

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Login(testData.ctx, testAccount)

	assert.ErrorIs(t, err, ErrBadCredentials)
	assert.Empty(t, pair)
}

func TestLoginWrongPasswordError(t *testing.T) {
	testData := NewDefaultTestData()

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
	accRepo.On("GetByEmail", testData.ctx, testAccount.Email).Return(bdTestAccount, nil).Once()
	testData.accRepo = accRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	pair, err := service.Login(testData.ctx, testAccount)

	assert.ErrorIs(t, err, ErrBadCredentials)
	assert.Empty(t, pair)
}

func TestLogout(t *testing.T) {
	testData := NewDefaultTestData()

	refreshToken := &entities.LogoutRequest{RefreshToken: "testtoken"}

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", testData.ctx, refreshToken.RefreshToken).Return(&entities.Token{}, nil).Once()
	tokenRepo.On("Delete", testData.ctx, refreshToken.RefreshToken).Return(nil).Once()
	testData.tokRepo = tokenRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	err := service.Logout(testData.ctx, refreshToken)

	assert.NoError(t, err)
}

func TestLogoutErrNotFoundToken(t *testing.T) {
	testData := NewDefaultTestData()

	refreshToken := &entities.LogoutRequest{RefreshToken: "testtoken"}
	err := errors.New("test")

	tokenRepo := &mocks.TokenRepo{}
	tokenRepo.On("Get", testData.ctx, refreshToken.RefreshToken).Return(nil, err).Once()
	tokenRepo.On("Delete", testData.ctx, refreshToken.RefreshToken).Return(nil).Once()
	testData.tokRepo = tokenRepo

	service := NewAuthService(testData.log, testData.accRepo, testData.tokRepo, testData.linkRepo, testData.jwtAcc, testData.jwtRef)
	err = service.Logout(testData.ctx, refreshToken)

	assert.Error(t, err)
}
