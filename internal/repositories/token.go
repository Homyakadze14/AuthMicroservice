package repositories

import (
	"context"
	"fmt"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
)

type TokenRepository struct {
	*postgres.Postgres
}

func NewTokenRepository(pg *postgres.Postgres) *TokenRepository {
	return &TokenRepository{pg}
}

func (r *TokenRepository) Create(ctx context.Context, token *entities.Token) error {
	const op = "repositories.TokenRepository.Create"

	_, err := r.Pool.Exec(
		ctx,
		"INSERT INTO token(user_id, refresh_token, expires_at) VALUES ($1, $2, $3)",
		token.UserID, token.RefreshToken, token.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
