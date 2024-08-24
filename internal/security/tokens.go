package sec

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtUserClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type TokenPayload struct {
	ID    string
	Email string
}

const ISSUER = "go-auth"

func GenTokenPair(pl *TokenPayload) (at, rt string, err error) {
	JWT_SECRET := os.Getenv("JWT_SECRET")

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtUserClaims{
		Email: pl.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ISSUER,
			Subject:   pl.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    ISSUER,
		Subject:   pl.ID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 6)),
	},
	)

	at, err = accessToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", err
	}

	rt, err = refreshToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", err
	}

	return at, rt, nil
}
