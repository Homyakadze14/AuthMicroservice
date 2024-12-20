package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/lib/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AccountRepo interface {
	Create(ctx *context.Context, account *entities.Account) (id int, err error)
	GetByUsername(ctx *context.Context, username string) (*entities.Account, error)
}

type TokenRepo interface {
	Create(ctx *context.Context, token *entities.Token) error
	Get(ctx *context.Context, refreshToken string) (*entities.Account, error)
}

type LinkRepo interface {
	Create(ctx *context.Context, link *entities.Link) error
	IsActivated(ctx *context.Context, userID int) (bool, error)
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

func (s *AuthService) Register(ctx *context.Context, acc *entities.Account) (*entities.TokenPair, error) {
	const op = "Auth.Register"

	log := s.log.With(
		slog.String("op", op),
		slog.String("acc", acc.String()),
	)

	log.Info("trying to create account")
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

	return &entities.TokenPair{
		AccessToken:  accTok,
		RefreshToken: refTok,
	}, nil
}
