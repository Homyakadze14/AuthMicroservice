package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/services"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
	"github.com/jackc/pgx/v5"
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
		token.UserID, token.RefreshToken, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *TokenRepository) Get(ctx context.Context, refreshToken string) (*entities.Token, error) {
	const op = "repositories.TokenRepository.Get"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, user_id, refresh_token, expires_at FROM token WHERE refresh_token=$1",
		refreshToken)

	token := &entities.Token{}
	err := row.Scan(&token.ID, &token.UserID, &token.RefreshToken, &token.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, services.ErrTokenNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (r *TokenRepository) Delete(ctx context.Context, refreshToken string) error {
	const op = "repositories.TokenRepository.Delete"

	_, err := r.Pool.Exec(
		ctx,
		"DELETE FROM token WHERE refresh_token=$1",
		refreshToken)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *TokenRepository) DeleteAllByEmail(ctx context.Context, email string) error {
	const op = "repositories.TokenRepository.DeleteAllByUserID"

	_, err := r.Pool.Exec(
		ctx,
		"DELETE FROM token WHERE user_id IN (SELECT user_id FROM account WHERE email=$1)",
		email)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
