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

type LinkRepository struct {
	*postgres.Postgres
}

func NewLinkRepository(pg *postgres.Postgres) *LinkRepository {
	return &LinkRepository{pg}
}

func (r *LinkRepository) Create(ctx context.Context, link *entities.Link) error {
	const op = "repositories.LinkRepository.Create"

	_, err := r.Pool.Exec(
		ctx,
		"INSERT INTO activation_link(user_id, link) VALUES ($1, $2)",
		link.UserID, link.Link)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *LinkRepository) Get(ctx context.Context, link string) (*entities.Link, error) {
	const op = "repositories.LinkRepository.Get"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, user_id, link, is_activated FROM activation_link WHERE link=$1",
		link)

	dblink := &entities.Link{}
	err := row.Scan(&dblink.ID, &dblink.UserID, &dblink.Link, &dblink.IsActivated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, services.ErrLinkNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return dblink, nil
}

func (r *LinkRepository) IsActivated(ctx context.Context, uid int) (bool, error) {
	const op = "repositories.LinkRepository.IsActivated"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT is_activated FROM activation_link WHERE user_id=$1",
		uid)

	var isActivated bool
	err := row.Scan(&isActivated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, services.ErrLinkNotFound
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isActivated, nil
}

func (r *LinkRepository) Update(ctx context.Context, id int, link *entities.Link) error {
	const op = "repositories.LinkRepository.Update"

	_, err := r.Pool.Exec(
		ctx,
		"UPDATE activation_link SET user_id=$1, link=$2, is_activated=$3 WHERE id=$4",
		link.UserID, link.Link, link.IsActivated, id)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
