package entities

import "time"

type Token struct {
	ID           int
	UserID       int
	RefreshToken string
	ExpiresAt    time.Time
}
