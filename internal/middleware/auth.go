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
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			util.LogError(errors.New("Authorization header format is incorrect"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := util.ParseJWT(token)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Преобразуем user_id из float64 (если он таковой) в uint.
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
		next(w, r.WithContext(ctx))
	}
}
