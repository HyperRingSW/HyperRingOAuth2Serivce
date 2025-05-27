package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/util"
)

type Middleware struct {
	repo dependency.Repository
}

func NewMiddleware(repo dependency.Repository) *Middleware {
	return &Middleware{
		repo: repo,
	}
}

type middlewareHandler struct {
	*Middleware
}

func (h *Middleware) MiddleHandler() dependency.MiddleHandler {
	return &middlewareHandler{
		h,
	}
}

func (h *Middleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path

		logs := make(map[string]map[string]any)
		logs["info"] = make(map[string]any)
		logs["error"] = make(map[string]any)
		defer func() {
			logs["info"]["request"] = requestPath
			util.LogInfoMap(logs)
		}()

		/*authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			util.LogInfo(fmt.Sprintf("authorization header format is incorrect: %s", authHeader))
			util.LogError(errors.New("authorization header format is incorrect"))

			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")*/
		token, err := util.GetJWT(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, err = h.repo.JwtDeviceRepository().GetJwtDevice(token)
		if err != nil {
			util.LogError(fmt.Errorf("get jwt device error: %v", err))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, err := util.ParseJWT(token, requestPath)
		if err != nil {
			util.LogInfo("AuthMiddleware invalid token")
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		idFloat, ok := claims["user_id"].(float64)
		if !ok {
			util.LogInfo("invalid user id")
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		userID := uint(idFloat)
		logs["info"]["user_id"] = userID

		us := h.repo.UserRepository().GetUserByID(userID)
		if us == nil {
			util.LogInfo("AuthMiddleware user not found")
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !util.IsValidEmail(us.Email) {
			util.LogInfo("AuthMiddleware invalid email")
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenDB := h.repo.TokenRepository().UserToken(userID, claims["provider"].(string))
		if tokenDB == nil {
			util.LogError(errors.New("token is not found"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set context KV
		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "provider", claims["provider"])
		ctx = context.WithValue(ctx, "deviceUUID", claims["device_uuid"])
		next(w, r.WithContext(ctx))
	}
}
