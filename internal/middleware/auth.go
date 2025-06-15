package middleware

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"time"
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
		tnow := time.Now().UTC().Unix()
		requestPath := r.URL.Path

		logs := make(map[string]map[string]any)
		logs["info"] = make(map[string]any)
		logs["error"] = make(map[string]any)
		defer func() {
			logs["info"]["request"] = requestPath
			util.LogInfoMap(logs)
		}()

		requestJWT, err := util.GetJWT(r)
		if err != nil {
			logs["error"]["getJWT"] = err.Error()
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		dbJwt, err := h.repo.JwtDeviceRepository().FindJwt(requestJWT)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			util.LogInfo("AuthMiddleware failed find requestJWT")
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if dbJwt == nil {
			rClaims, err := util.ParseUnverifiedJWT(requestJWT)
			if err != nil {
				util.LogInfo("AuthMiddleware invalid requestJWT")
				util.LogError(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			var exp int64
			if expValue, ok := rClaims["exp"].(float64); ok {
				exp = int64(expValue)
			} else {
				util.LogError(fmt.Errorf("AuthMiddleware exp not found or invalid type"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			idFloat, ok := rClaims["user_id"].(float64)
			if !ok {
				util.LogInfo("invalid user id")
				util.LogError(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			userID := uint(idFloat)

			var provider string
			if providerValue, ok := rClaims["provider"].(string); ok {
				provider = providerValue
			} else {
				util.LogError(fmt.Errorf("AuthMiddleware provider not found or invalid type"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			var rDevice string
			if deviceValue, ok := rClaims["device_uuid"].(string); ok {
				rDevice = deviceValue
			} else {
				util.LogError(fmt.Errorf("AuthMiddleware device_uuid not found or invalid type"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			status := true
			if time.Now().UTC().Unix() > exp {
				status = false
			}

			newJWTDevice := &models.JwtDevice{
				JWT:        requestJWT,
				DeviceUUID: rDevice,
				Status:     status,
			}

			dbJwt, err = h.repo.JwtDeviceRepository().SaveJwtDevice(userID, provider, newJWTDevice)
			if err != nil {
				util.LogError(fmt.Errorf("AuthMiddleware failed to save jwt device: %v", err))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if dbJwt != nil {
			rClaims, err := util.ParseUnverifiedJWT(dbJwt.JWT)
			if err != nil {
				util.LogInfo("AuthMiddleware invalid db jwt token")
				util.LogError(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			var exp int64
			if expValue, ok := rClaims["exp"].(float64); ok {
				exp = int64(expValue)
			} else {
				util.LogError(fmt.Errorf("AuthMiddleware exp not found or invalid type"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if tnow > exp {
				err = h.repo.JwtDeviceRepository().DeleteJwtDevice(dbJwt.JWT)
				if err != nil {
					util.LogError(fmt.Errorf("AuthMiddleware failed to delete jwt device: %v", err))
					return
				}
				util.LogInfo("AuthMiddleware expired db jwt token")
				util.LogError(err)
				return
			}
		}

		_, err = h.repo.JwtDeviceRepository().GetJwtDevice(requestJWT)
		if err != nil {
			util.LogError(fmt.Errorf("get jwt device error: %v", err))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, err := util.ParseJWT(requestJWT, requestPath)
		if err != nil {
			util.LogInfo("AuthMiddleware invalid requestJWT")
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

		tokenDB := h.repo.TokenRepository().UserToken(userID, claims["provider"].(string), claims["device_uuid"].(string))
		if tokenDB == nil {
			util.LogError(errors.New("token is not found"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		dbJwt.ID = tokenDB.ID
		err = h.repo.JwtDeviceRepository().AddRefreshTokenJwtDevice(dbJwt.JWT, tokenDB.RefreshToken)
		if err != nil {
			util.LogError(fmt.Errorf("AuthMiddleware failed to AddTokenIDJwtDevice: %v", err))
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
