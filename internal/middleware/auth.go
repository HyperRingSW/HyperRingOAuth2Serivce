package middleware

import (
	"context"
	"errors"
	"net/http"
	"oauth2-server/internal/util"
	"strings"
)

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			util.LogError(errors.New("authorization header format is incorrect"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := util.ParseJWT(token, requestPath)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		idFloat, ok := claims["user_id"].(float64)
		if !ok {
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		userID := uint(idFloat)

		// Set context KV
		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "provider", claims["provider"])
		ctx = context.WithValue(ctx, "deviceUUID", claims["device_uuid"])
		next(w, r.WithContext(ctx))
	}
}
