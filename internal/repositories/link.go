package repositories

import (
	"context"
	"fmt"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
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
		"INSERT INTO link(user_id, link) VALUES ($1, $2, $3)",
		link.UserID, link.Link,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
