package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/services"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
	"github.com/jackc/pgx/v5"
)

type AccountRepository struct {
	*postgres.Postgres
}

func NewAccountRepository(pg *postgres.Postgres) *AccountRepository {
	return &AccountRepository{pg}
}

func (r *AccountRepository) Create(ctx context.Context, acc *entities.Account) (id int, err error) {
	const op = "repositories.AccountRepository.Create"

	row := r.Pool.QueryRow(
		ctx,
		"INSERT INTO account(username, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		acc.Username, acc.Email, acc.Password, time.Now(), time.Now())

	err = row.Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			return -1, services.ErrAccountAlreadyExists
		}
		return -1, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func getUser(op string, row pgx.Row) (*entities.Account, error) {
	acc := &entities.Account{}
	err := row.Scan(&acc.ID, &acc.Username, &acc.Email, &acc.Password, &acc.CreatedAt, &acc.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, services.ErrAccountNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return acc, nil
}

func (r *AccountRepository) GetByUserID(ctx context.Context, uid string) (*entities.Account, error) {
	const op = "repositories.AccountRepository.GetByUserID"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, username, email, password, created_at, updated_at FROM account WHERE id=$1",
		uid)

	return getUser(op, row)
}

func (r *AccountRepository) GetByUsername(ctx context.Context, username string) (*entities.Account, error) {
	const op = "repositories.AccountRepository.GetByUsername"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, username, email, password, created_at, updated_at FROM account WHERE username=$1",
		username)

	return getUser(op, row)
}

func (r *AccountRepository) GetByEmail(ctx context.Context, email string) (*entities.Account, error) {
	const op = "repositories.AccountRepository.GetByEmail"

	row := r.Pool.QueryRow(
		ctx,
		"SELECT id, username, email, password, created_at, updated_at FROM account WHERE email=$1",
		email)

	return getUser(op, row)
}

func (r *AccountRepository) UpdatePwdByEmail(ctx context.Context, email string, password string) error {
	const op = "repositories.AccountRepository.UpdateByEmail"

	_, err := r.Pool.Exec(
		ctx,
		"UPDATE account SET password=$1 WHERE email=$2",
		password, email)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *AccountRepository) Delete(ctx context.Context, uid int) error {
	const op = "repositories.AccountRepository.Delete"

	_, err := r.Pool.Exec(
		ctx,
		"DELETE FROM account WHERE id=$1",
		uid)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
