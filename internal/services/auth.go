package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/lib/jwt"
	userv1 "github.com/Homyakadze14/AuthMicroservice/proto/gen/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

var (
	ErrAccountAlreadyExists = errors.New("account with this credentials already exists")
	ErrAccountNotFound      = errors.New("account with this credentials not found")
	ErrBadCredentials       = errors.New("bad credentials")
	ErrTokenNotFound        = errors.New("token not found")
	ErrLinkNotFound         = errors.New("link not found")
	ErrNotActivated         = errors.New("not activated account")
)

type AccountRepo interface {
	Create(ctx context.Context, account *entities.Account) (id int, err error)
	GetByUsername(ctx context.Context, username string) (*entities.Account, error)
	GetByEmail(ctx context.Context, email string) (*entities.Account, error)
	GetByUserID(ctx context.Context, uid string) (*entities.Account, error)
	UpdatePwdByEmail(ctx context.Context, email string, password string) error
	Delete(ctx context.Context, uid int) error
}

type TokenRepo interface {
	Create(ctx context.Context, token *entities.Token) error
	Get(ctx context.Context, refreshToken string) (*entities.Token, error)
	Delete(ctx context.Context, refreshToken string) error
	DeleteAllByEmail(ctx context.Context, email string) error
}

type LinkRepo interface {
	Create(ctx context.Context, link *entities.Link) error
	Get(ctx context.Context, link string) (*entities.Link, error)
	Update(ctx context.Context, id int, link *entities.Link) error
	IsActivated(ctx context.Context, uid int) (bool, error)
}

type PwdLinkRepo interface {
	Create(ctx context.Context, link *entities.PwdLink) error
	GetByEmail(ctx context.Context, email string) (*entities.PwdLink, error)
	GetByLink(ctx context.Context, link string) (*entities.PwdLink, error)
	Delete(ctx context.Context, link string) error
}

type Mailer interface {
	SendActivationMail(email, link string) error
	SendPwdMail(email, link string) error
}

type AuthService struct {
	log         *slog.Logger
	accRepo     AccountRepo
	tokRepo     TokenRepo
	linkRepo    LinkRepo
	jwtAcc      *config.JWTAccessConfig
	jwtRef      *config.JWTRefreshConfig
	mailer      Mailer
	pwdLinkRepo PwdLinkRepo
	userService UserServiceI
}

type UserServiceI interface {
	CreateDefault(ctx context.Context, in *userv1.CreateDefaultRequest, opts ...grpc.CallOption) (*userv1.CreateDefaultResponse, error)
}

func NewAuthService(
	log *slog.Logger,
	accRepo AccountRepo,
	tokRepo TokenRepo,
	linkRepo LinkRepo,
	jwtAcc *config.JWTAccessConfig,
	jwtRef *config.JWTRefreshConfig,
	mailer Mailer,
	pwdLinkRepo PwdLinkRepo,
	userService UserServiceI,
) *AuthService {
	return &AuthService{
		log:         log,
		accRepo:     accRepo,
		tokRepo:     tokRepo,
		linkRepo:    linkRepo,
		jwtAcc:      jwtAcc,
		jwtRef:      jwtRef,
		mailer:      mailer,
		pwdLinkRepo: pwdLinkRepo,
		userService: userService,
	}
}

func (s *AuthService) Register(ctx context.Context, acc *entities.Account) error {
	const op = "Auth.Register"

	log := s.log.With(
		slog.String("op", op),
		slog.String("acc", acc.String()),
	)

	log.Info("trying to register account")
	// Hash password
	passHash, err := bcrypt.GenerateFromPassword([]byte(acc.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash")
		return fmt.Errorf("%s: %w", op, err)
	}
	acc.Password = string(passHash)

	// Create user
	uid, err := s.accRepo.Create(ctx, acc)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	// Create activation link
	link := &entities.Link{
		UserID: uid,
		Link:   uuid.NewString(),
	}
	err = s.linkRepo.Create(ctx, link)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	// Send activation link
	go func() {
		log.Info("trying to send activation mail")
		err := s.mailer.SendActivationMail(acc.Email, link.Link)
		if err != nil {
			log.Error(fmt.Errorf("%s: %w", op, err).Error())
		}
		log.Info("mail successfully sended")
	}()
	log.Info("successfully registered account")

	return nil
}

func (s *AuthService) getAccount(ctx context.Context, acc *entities.Account) (*entities.Account, error) {
	getFunc := s.accRepo.GetByUsername
	getFuncArg := acc.Username
	if acc.Username == "" {
		getFunc = s.accRepo.GetByEmail
		getFuncArg = acc.Email
	}

	if acc.ID != 0 && acc.Username == "" && acc.Email == "" {
		getFunc = s.accRepo.GetByUserID
		getFuncArg = strconv.Itoa(acc.ID)
	}

	if getFuncArg == "" {
		return nil, ErrBadCredentials
	}

	return getFunc(ctx, getFuncArg)
}

func (s *AuthService) Login(ctx context.Context, acc *entities.Account) (*entities.TokenPair, error) {
	const op = "Auth.Login"

	log := s.log.With(
		slog.String("op", op),
		slog.String("acc", acc.String()),
	)

	log.Info("trying to login in to account")
	// Getting account
	dbAcc, err := s.getAccount(ctx, acc)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(dbAcc.Password), []byte(acc.Password))
	if err != nil {
		log.Error("failed to compare passwords")
		return nil, fmt.Errorf("%s: %w", op, ErrBadCredentials)
	}

	// Check activation
	isActiv, err := s.linkRepo.IsActivated(ctx, dbAcc.ID)
	if err != nil || !isActiv {
		return nil, fmt.Errorf("%s: %w", op, ErrNotActivated)
	}

	// Generate tokens
	accTok, err := jwt.NewToken(dbAcc, s.jwtAcc.Secret, s.jwtAcc.Duration)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	refTok, err := jwt.NewToken(dbAcc, s.jwtRef.Secret, s.jwtRef.Duration)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Add refresh token to db
	expires_at := time.Now().Add(s.jwtRef.Duration)
	token := &entities.Token{
		UserID:       dbAcc.ID,
		RefreshToken: refTok,
		ExpiresAt:    expires_at,
	}
	err = s.tokRepo.Create(ctx, token)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("account login completed successfully")

	return &entities.TokenPair{
		AccessToken:  accTok,
		RefreshToken: refTok,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, tok *entities.LogoutRequest) error {
	const op = "Auth.Logout"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to logout")
	_, err := s.tokRepo.Get(ctx, tok.RefreshToken)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.tokRepo.Delete(ctx, tok.RefreshToken)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully logout")

	return nil
}

func (s *AuthService) ActivateAccount(ctx context.Context, link string) error {
	const op = "Auth.ActivateAccount"

	log := s.log.With(
		slog.String("op", op),
		slog.String("link", link),
	)

	log.Info("trying to activate account")
	bdLink, err := s.linkRepo.Get(ctx, link)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = s.userService.CreateDefault(ctx, &userv1.CreateDefaultRequest{UserId: int64(bdLink.UserID)})
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	bdLink.IsActivated = true

	err = s.linkRepo.Update(ctx, bdLink.ID, bdLink)
	if err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("activation has been successfully completed")

	return nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*entities.TokenPair, error) {
	const op = "Auth.Refresh"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to refresh token")
	// Get refresh token
	token, err := s.tokRepo.Get(ctx, refreshToken)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Check refresh token
	err = s.checkToken(refreshToken, s.jwtRef.Secret)
	if err != nil {
		// Delete token
		if errors.Is(err, jwt.ErrTokenExpired) {
			err2 := s.tokRepo.Delete(ctx, refreshToken)
			if err2 != nil {
				err = errors.Join(err, fmt.Errorf("%s: %w", op, err2))
			}
		}

		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Getting account
	acc, err := s.getAccount(ctx, &entities.Account{ID: token.UserID})
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Generate tokens
	accTok, err := jwt.NewToken(acc, s.jwtAcc.Secret, s.jwtAcc.Duration)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("refreshing has been successfully completed")

	return &entities.TokenPair{RefreshToken: refreshToken, AccessToken: accTok}, nil
}

func (s *AuthService) checkToken(token, secret string) error {
	const op = "Auth.checkToken"
	_, err := jwt.ParseToken(token, secret)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *AuthService) Verify(ctx context.Context, accToken string) (bool, error) {
	const op = "Auth.Verify"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to verify")
	err := s.checkToken(accToken, s.jwtAcc.Secret)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("verification has been successfully completed")

	return true, nil
}

func (s *AuthService) createPwdLink(ctx context.Context, email string) (*entities.PwdLink, error) {
	link := &entities.PwdLink{
		Email: email,
		Link:  uuid.NewString(),
	}

	err := s.pwdLinkRepo.Create(ctx, link)
	if err != nil {
		return nil, err
	}

	return link, nil
}

func (s *AuthService) SendPwdLink(ctx context.Context, email string) (bool, error) {
	const op = "Auth.SendPwdLink"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to send password link")
	_, err := s.accRepo.GetByEmail(ctx, email)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}

	link, err := s.pwdLinkRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			// Create pwd link
			link, err = s.createPwdLink(ctx, email)
			if err != nil {
				log.Error(err.Error())
				return false, fmt.Errorf("%s: %w", op, err)
			}
		} else {
			log.Error(err.Error())
			return false, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Send pwd link
	go func() {
		log.Info("trying to send activation mail")
		err := s.mailer.SendPwdMail(link.Email, link.Link)
		if err != nil {
			log.Error(fmt.Errorf("%s: %w", op, err).Error())
		}
		log.Info("mail successfully sended")
	}()
	log.Info("password link has been sent")

	return true, nil
}

func (s *AuthService) ChangePwd(ctx context.Context, link *entities.ChPwdLink) (bool, error) {
	const op = "Auth.ChangePwd"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to change password")
	dbLink, err := s.pwdLinkRepo.GetByLink(ctx, link.Link)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}

	// Hash password
	passHash, err := bcrypt.GenerateFromPassword([]byte(link.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash")
		return false, fmt.Errorf("%s: %w", op, err)
	}
	link.Password = string(passHash)

	err = s.accRepo.UpdatePwdByEmail(ctx, dbLink.Email, link.Password)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}

	err = s.tokRepo.DeleteAllByEmail(ctx, dbLink.Email)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}

	err = s.pwdLinkRepo.Delete(ctx, link.Link)
	if err != nil {
		log.Error(err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("password has been changed")

	return true, nil
}
