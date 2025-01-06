package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/lib/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrAccountAlreadyExists = errors.New("account with this credentials already exists")
	ErrBadCredentials       = errors.New("bad credentials")
	ErrTokenNotFound        = errors.New("token not found")
)

type AccountRepo interface {
	Create(ctx context.Context, account *entities.Account) (id int, err error)
	GetByUsername(ctx context.Context, username string) (*entities.Account, error)
	GetByEmail(ctx context.Context, email string) (*entities.Account, error)
}

type TokenRepo interface {
	Create(ctx context.Context, token *entities.Token) error
	Get(ctx context.Context, refreshToken string) (*entities.Token, error)
	Delete(ctx context.Context, refreshToken string) error
}

type LinkRepo interface {
	Create(ctx context.Context, link *entities.Link) error
	IsActivated(ctx context.Context, userID int) (bool, error)
	Get(ctx context.Context, link string) (*entities.Link, error)
	Update(ctx context.Context, id int, link *entities.Link) error
}

type AuthService struct {
	log      *slog.Logger
	accRepo  AccountRepo
	tokRepo  TokenRepo
	linkRepo LinkRepo
	jwtAcc   *config.JWTAccessConfig
	jwtRef   *config.JWTRefreshConfig
}

func NewAuthService(
	log *slog.Logger,
	accRepo AccountRepo,
	tokRepo TokenRepo,
	linkRepo LinkRepo,
	jwtAcc *config.JWTAccessConfig,
	jwtRef *config.JWTRefreshConfig,
) *AuthService {
	return &AuthService{
		log:      log,
		accRepo:  accRepo,
		tokRepo:  tokRepo,
		linkRepo: linkRepo,
		jwtAcc:   jwtAcc,
		jwtRef:   jwtRef,
	}
}

func (s *AuthService) Register(ctx context.Context, acc *entities.Account) (*entities.TokenPair, error) {
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
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	acc.Password = string(passHash)

	// Create user
	uid, err := s.accRepo.Create(ctx, acc)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Create activation link
	link := &entities.Link{
		UserID: uid,
		Link:   uuid.NewString(),
	}
	err = s.linkRepo.Create(ctx, link)
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

	refTok, err := jwt.NewToken(acc, s.jwtRef.Secret, s.jwtRef.Duration)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Add refresh token to db
	expires_at := time.Now().Add(s.jwtRef.Duration)
	token := &entities.Token{
		UserID:       uid,
		RefreshToken: refTok,
		ExpiresAt:    expires_at,
	}
	err = s.tokRepo.Create(ctx, token)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully registered account")

	return &entities.TokenPair{
		AccessToken:  accTok,
		RefreshToken: refTok,
	}, nil
}

func (s *AuthService) getAccount(ctx context.Context, acc *entities.Account) (*entities.Account, error) {
	getFunc := s.accRepo.GetByUsername
	getFuncArg := acc.Username
	if acc.Username == "" {
		getFunc = s.accRepo.GetByEmail
		getFuncArg = acc.Email
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

	// Generate tokens
	accTok, err := jwt.NewToken(acc, s.jwtAcc.Secret, s.jwtAcc.Duration)
	if err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	refTok, err := jwt.NewToken(acc, s.jwtRef.Secret, s.jwtRef.Duration)
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

func (s *AuthService) Verify(ctx context.Context, link string) error {
	const op = "Auth.Logout"

	log := s.log.With(
		slog.String("op", op),
		slog.String("link", link),
	)

	log.Info("trying to verify user")
	bdLink, err := s.linkRepo.Get(ctx, link)
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
	log.Info("verification has been successfully completed")

	return nil
}
