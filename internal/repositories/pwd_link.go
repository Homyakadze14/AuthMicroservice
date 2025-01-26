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

func (r *PasswordLinkRepository) GetByLink(ctx context.Context, link string) (*entities.PwdLink, error) {
	const op = "repositories.PasswordLinkRepository.GetByLink"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, email, link FROM password_link WHERE link=$1",
		link)

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

func (r *PasswordLinkRepository) Delete(ctx context.Context, link string) error {
	const op = "repositories.PasswordLinkRepository.Delete"

	_, err := r.Pool.Exec(
		ctx,
		"DELETE FROM password_link WHERE link=$1",
		link)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
