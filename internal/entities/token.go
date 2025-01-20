package entities

import "time"

type Token struct {
	ID           int
	UserID       int
	RefreshToken string
	ExpiresAt    time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type LogoutRequest struct {
	RefreshToken string
}
