package jwt

import (
	"time"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/golang-jwt/jwt/v5"
)

func NewToken(acc *entities.Account, secret string, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = acc.ID
	claims["username"] = acc.Username
	claims["exp"] = time.Now().Add(duration).Unix()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
