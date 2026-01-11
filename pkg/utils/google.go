package utils

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/idtoken"
)

type GoogleUser struct {
	Email   string
	Name    string
	Picture string
	Sub     string
}

func VerifyGoogleIDToken(ctx context.Context, token string) (*GoogleUser, error) {
	payload, err := idtoken.Validate(ctx, token, os.Getenv("GOOGLE_CLIENT_ID"))
	if err != nil {
		return nil, errors.New("invalid google id token")
	}

	return &GoogleUser{
		Email:   payload.Claims["email"].(string),
		Name:    payload.Claims["name"].(string),
		Picture: payload.Claims["picture"].(string),
		Sub:     payload.Subject,
	}, nil
}

func GenerateJWT(userID, email string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"iss":   os.Getenv("JWT_ISSUER"),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
