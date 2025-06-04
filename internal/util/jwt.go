package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
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

func ParseUnverifiedJWT(tokenString string) (jwt.MapClaims, error) {
	// Парсинг токена без проверки подписи
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	// Извлечение claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// DecodeJWT
func DecodeJWT(tokenString string) (map[string]interface{}, error) {
	// Разделяем токен на части
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Декодируем header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	// Декодируем payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	// Парсим JSON
	var header, payload map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}

	// Форматируем время, если оно есть
	if exp, ok := payload["exp"].(float64); ok {
		payload["exp"] = time.Unix(int64(exp), 0).Format(time.RFC3339)
	}
	if iat, ok := payload["iat"].(float64); ok {
		payload["iat"] = time.Unix(int64(iat), 0).Format(time.RFC3339)
	}

	return map[string]interface{}{
		"header":  header,
		"payload": payload,
	}, nil
}
