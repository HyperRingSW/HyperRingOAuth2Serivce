package util

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

var jwtSecret = []byte("86194778010")

// GenerateJWT
func GenerateJWT(userID uint, provider string, expirationTime int64, deviceUUID string) (string, int64, error) {
	claims := jwt.MapClaims{
		"user_id":     userID,
		"provider":    provider,
		"exp":         expirationTime,
		"device_uuid": deviceUUID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", 0, err
	}

	return signedToken, expirationTime, nil
}

// ParseJWT
func ParseJWT(tokenString string, requestPath string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil && (strings.Contains(err.Error(), "expired") && (requestPath != "/auth/token/refresh" && requestPath != "/user/logout")) {
		return nil, err
	}

	if requestPath == "/auth/token/refresh" || requestPath == "/user/logout" {
		token.Valid = true
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
