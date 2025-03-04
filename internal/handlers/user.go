package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
)

type userHandler struct {
	*Handler
}

func (h *Handler) UserHandler() dependency.UserHandler {
	return &userHandler{
		h,
	}
}

func (h *Handler) GetUserProfile(w http.ResponseWriter, r *http.Request) {
	util.LogInfo("GetUserProfile")
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		util.LogError(errors.New("user not found"))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	userRings, err := h.repo.UserRingRepository().GetUserRing(user.ID)
	if err != nil {
		util.LogInfo("GetUserRing")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	rings := make([]models.RingResponse, 0)
	for _, userRing := range userRings {
		ringDB, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
			util.LogInfo("error getting ring from db")
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var service []string
		for _, v := range ringDB.Services {
			service = append(service, string(v.Service))
		}

		rings = append(rings, models.RingResponse{
			Id:          ringDB.Id,
			Name:        ringDB.Name,
			UserNamed:   ringDB.UserNamed,
			Description: ringDB.Description,
			Services:    service,
			DeviceDescription: models.DeviceDescriptionResponse{
				CIN:         ringDB.DeviceDescription.CIN,
				IIN:         ringDB.DeviceDescription.IIN,
				Name:        ringDB.DeviceDescription.Name,
				Description: ringDB.DeviceDescription.Description,
				Batch: models.RingBatchResponse{
					BatchId:    ringDB.DeviceDescription.Batch.BatchId,
					IsUser:     ringDB.DeviceDescription.Batch.IsUser,
					IsUserName: ringDB.DeviceDescription.Batch.IsUserName,
				},
				ImageURL: ringDB.DeviceDescription.ImageURL,
				SiteURL:  ringDB.DeviceDescription.SiteURL,
			},
		})
	}

	demo := false
	if h.cfg.App.DemoMode && h.cfg.App.DemoEmail == user.Email {
		demo = true
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserProfileGETResponse{
		UserId: int(userID),
		Name:   user.Name,
		Email:  user.Email,
		Rings:  rings,
		Demo:   demo,
	})
}

func (h *Handler) ExportUserData(w http.ResponseWriter, r *http.Request) {
	util.LogInfo("ExportUserData")
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		util.LogError(errors.New("user not found"))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	userRings, err := h.repo.UserRingRepository().GetUserRing(user.ID)
	if err != nil {
		util.LogInfo("GetUserRing")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	rings := make([]models.RingResponse, 0)
	for _, userRing := range userRings {
		ringDB, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
			util.LogInfo("error getting ring from db")
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var service []string
		for _, v := range ringDB.Services {
			service = append(service, string(v.Service))
		}

		rings = append(rings, models.RingResponse{
			Id:          ringDB.Id,
			Name:        ringDB.Name,
			UserNamed:   ringDB.UserNamed,
			Description: ringDB.Description,
			Services:    service,
			DeviceDescription: models.DeviceDescriptionResponse{
				CIN:         ringDB.DeviceDescription.CIN,
				IIN:         ringDB.DeviceDescription.IIN,
				Name:        ringDB.DeviceDescription.Name,
				Description: ringDB.DeviceDescription.Description,
				Batch: models.RingBatchResponse{
					BatchId:    ringDB.DeviceDescription.Batch.BatchId,
					IsUser:     ringDB.DeviceDescription.Batch.IsUser,
					IsUserName: ringDB.DeviceDescription.Batch.IsUserName,
				},
				ImageURL: ringDB.DeviceDescription.ImageURL,
				SiteURL:  ringDB.DeviceDescription.SiteURL,
			},
		})
	}

	tokens, err := h.repo.TokenRepository().UserTokens(userID)
	if err != nil {
		util.LogInfo("GetUserTokens")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseTokens := make([]models.UserDataExportTokenResponse, 0)
	if len(tokens) > 0 {
		for _, token := range tokens {
			if token.AccessToken != "" {
				decryptAccess, err := util.Decrypt(token.AccessToken)
				if err != nil {
					util.LogInfo("error decrypting access token")
					util.LogError(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				token.AccessToken = decryptAccess
			}

			if token.RefreshToken != "" {
				decryptRefresh, err := util.Decrypt(token.RefreshToken)
				if err != nil {
					util.LogInfo(fmt.Sprintf("error decrypting refresh token: %s", token.RefreshToken))
					util.LogError(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				token.RefreshToken = decryptRefresh
			}

			if token.IDToken != "" {
				decryptIDToken, err := util.Decrypt(token.IDToken)
				if err != nil {
					util.LogInfo("error decrypting ID token")
					util.LogError(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				token.IDToken = decryptIDToken
			}

			if token.Data != "" {
				decryptData, err := util.Decrypt(token.Data)
				if err != nil {
					util.LogInfo("error decrypting ID token")
					util.LogError(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				token.Data = decryptData
			}

			responseTokens = append(responseTokens, models.UserDataExportTokenResponse{
				Provider:     token.Provider,
				IdToken:      token.IDToken,
				AccessToken:  token.AccessToken,
				RefreshToken: token.RefreshToken,
				ExpirationIn: token.ExpirationIn,
				ExpiresAt:    token.ExpiresAt.Unix(),
				Data:         token.Data,
				UpdatedAt:    token.UpdatedAt.Unix(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserDataExportResponse{
		UserId: int(userID),
		Name:   user.Name,
		Email:  user.Email,
		Rings:  rings,
		Tokens: responseTokens,
	})
}
