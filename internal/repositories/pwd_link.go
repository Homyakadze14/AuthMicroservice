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

type PasswordLinkRepository struct {
	*postgres.Postgres
}

func NewPasswordLinkRepository(pg *postgres.Postgres) *PasswordLinkRepository {
	return &PasswordLinkRepository{pg}
}

func (r *PasswordLinkRepository) Create(ctx context.Context, link *entities.PwdLink) error {
	const op = "repositories.PasswordLinkRepository.Create"

	_, err := r.Pool.Exec(
		ctx,
		"INSERT INTO password_link(email, link) VALUES ($1, $2)",
		link.Email, link.Link)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *PasswordLinkRepository) GetByEmail(ctx context.Context, email string) (*entities.PwdLink, error) {
	const op = "repositories.PasswordLinkRepository.GetByEmail"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, email, link FROM password_link WHERE email=$1",
		email)

	dblink := &entities.PwdLink{}
	err := row.Scan(&dblink.ID, &dblink.Email, &dblink.Link)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, services.ErrLinkNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return dblink, nil
}

func (r *PasswordLinkRepository) Exists(ctx context.Context, link string) (bool, error) {
	const op = "repositories.PasswordLinkRepository.Get"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id FROM password_link WHERE link=$1",
		link)

	var id int
	err := row.Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, services.ErrLinkNotFound
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return true, nil
}
