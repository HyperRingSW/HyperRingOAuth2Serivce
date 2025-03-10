package middleware

import (
	"context"
	"fmt"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/util"
	"strings"
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

		authHeader := r.Header.Get("Authorization")
		logs["info"]["authHeader"] = authHeader
		if !strings.HasPrefix(authHeader, "Bearer ") {
			logs["error"]["authHeader"] = "authorization header format is incorrect"
			//w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		logs["info"]["token"] = token

		claims, err := util.ParseJWT(token, requestPath)
		if err != nil {
			logs["error"]["ParseJWT"] = "invalid token"
			logs["error"]["ParseJWTMsg"] = err.Error()
			//w.WriteHeader(http.StatusUnauthorized)
			return
		}

		idFloat, ok := claims["userId"].(float64)
		logs["info"]["id"] = idFloat
		if !ok {
			logs["error"]["userId"] = "invalid user id"
			logs["error"]["userIdMsg"] = err.Error()
			//w.WriteHeader(http.StatusUnauthorized)
			return
		}
		userID := uint(idFloat)

		tokenDB := h.repo.TokenRepository().UserToken(userID, claims["provider"].(string))
		if tokenDB == nil {
			logs["error"]["UserTokenParams"] = fmt.Sprintf("userID, provider: %s, %s", userID, claims["provider"].(string))
			logs["error"]["UserTokenParamsMsg"] = "token is not found"
			//w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set context KV
		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "provider", claims["provider"])
		ctx = context.WithValue(ctx, "deviceUUID", claims["device_uuid"])
		logs["info"]["ctxUserID"] = userID
		logs["info"]["ctxProvider"] = claims["provider"]
		logs["info"]["ctxDeviceUuid"] = claims["device_uuid"]
		next(w, r.WithContext(ctx))
	}
}
