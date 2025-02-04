package middleware

import (
	"context"
	"net/http"
	"oauth2-server/internal/util"
	"strings"
)

// AuthMiddleware JWT
/*func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := util.ParseJWT(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims["user_id"])
		ctx = context.WithValue(ctx, "role", claims["role"])
		next(w, r.WithContext(ctx))
	}
}*/

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := util.ParseJWT(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Преобразуем user_id из float64 (если он таковой) в uint.
		idFloat, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid user_id in token", http.StatusUnauthorized)
			return
		}
		userID := uint(idFloat)

		// Set context KV
		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "provider", claims["provider"])
		next(w, r.WithContext(ctx))
	}
}
