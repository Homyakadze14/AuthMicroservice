package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
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
		"INSERT INTO account(usernmae, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		acc.Username, acc.Email, acc.Password, time.Now(), time.Now(),
	)

	err = row.Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, err
}
