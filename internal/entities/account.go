package entities

import (
	"fmt"
	"time"
)

type Account struct {
	ID        int
	Username  string
	Email     string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (a Account) String() string {
	return fmt.Sprintf("Username: %v; Email: %v", a.Username, a.Email)
}
