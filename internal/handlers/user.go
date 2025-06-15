package handlers

import (
	"encoding/json"
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
	response := models.UserProfileGETResponse{}
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["handler"] = "GetUserProfile"

	defer func() {
		logs["info"]["response"] = response
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		logs["error"]["userId"] = "invalid user ID in context"
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["userId"] = userID

	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		logs["error"]["GetUserByIDParams"] = fmt.Sprintf("userID: %s", userID)
		logs["error"]["GetUserByID"] = "user not found"
		//w.WriteHeader(http.StatusNotFound)
		return
	}
	logs["info"]["user"] = user

	userRings, err := h.repo.UserRingRepository().GetUserRing(user.ID)
	if err != nil {
		logs["error"]["GetUserRingParams"] = fmt.Sprintf("GetUserRing, UserID: %s", userID)
		logs["error"]["GetUserRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["userRings"] = userRings

	rings := make([]models.RingResponse, 0)
	for _, userRing := range userRings {
		ringDB, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
			logs["info"]["GetRingParams"] = fmt.Sprintf("userRing.RingID: %s", userRing.RingID)
			logs["info"]["GetRing"] = err.Error()
			/*w.WriteHeader(http.StatusInternalServerError)
			return*/
			continue
		}
		logs["info"]["ringDB"] = ringDB

		var service []string
		for _, v := range ringDB.Services {
			service = append(service, string(v.Service))
		}

		ringResponse := models.RingResponse{
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
		}

		logs["info"]["ringResponse"] = ringResponse

		rings = append(rings, ringResponse)
	}

	demo := false
	if h.cfg.App.DemoMode && h.cfg.App.DemoEmail == user.Email {
		demo = true
	}

	logs["info"]["h.cfg.App.DemoMode"] = h.cfg.App.DemoMode
	logs["info"]["h.cfg.App.DemoEmail"] = h.cfg.App.DemoEmail
	logs["info"]["demoMode"] = demo

	response = models.UserProfileGETResponse{
		UserId: int(userID),
		Name:   user.Name,
		Email:  user.Email,
		Rings:  rings,
		Demo:   demo,
	}

	return
}

func (h *Handler) ExportUserData(w http.ResponseWriter, r *http.Request) {
	response := models.UserDataExportResponse{}
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["handler"] = "ExportUserData"

	defer func() {
		logs["info"]["response"] = response
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=\"export.json\"")
			w.WriteHeader(http.StatusOK)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		logs["error"]["userId"] = "invalid user ID in context"
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["userId"] = userID

	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		logs["error"]["GetUserByIDParams"] = fmt.Sprintf("userID: %s", userID)
		logs["error"]["GetUserByID"] = "user not found"
		//w.WriteHeader(http.StatusNotFound)
		return
	}
	logs["info"]["user"] = user

	userRings, err := h.repo.UserRingRepository().GetUserRing(user.ID)
	if err != nil {
		logs["error"]["GetUserRingParams"] = fmt.Sprintf("user.ID: %s", user.ID)
		logs["error"]["GetUserRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["userRings"] = userRings

	rings := make([]models.RingResponse, 0)
	for _, userRing := range userRings {
		ringDB, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
			logs["error"]["GetRingParams"] = fmt.Sprintf("userRing.RingID: %s", userID)
			logs["error"]["GetRing"] = err.Error()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logs["info"]["ringDB"] = ringDB

		var service []string
		for _, v := range ringDB.Services {
			service = append(service, string(v.Service))
		}

		ringResponse := models.RingResponse{
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
		}
		logs["info"]["ringResponse"] = ringResponse
		rings = append(rings, ringResponse)
	}

	tokens, err := h.repo.TokenRepository().UserTokens(userID)
	if err != nil {
		logs["error"]["GetUserTokens"] = fmt.Sprintf("userID: %s", userID)
		logs["error"]["GetUserToken"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseTokens := make([]models.UserDataExportTokenResponse, 0)
	for _, token := range tokens {
		if token.AccessToken != "" {
			decryptAccess, err := util.Decrypt(token.AccessToken)
			if err != nil {
				logs["error"]["decryptAccessMsg"] = fmt.Sprintf("decryptAccess: %s", token.AccessToken)
				logs["error"]["decryptAccess"] = err.Error()
				//w.WriteHeader(http.StatusInternalServerError)
				return
			}
			token.AccessToken = decryptAccess
			logs["info"]["decryptAccess"] = decryptAccess
		}

		if token.RefreshToken != "" {
			decryptRefresh, err := util.Decrypt(token.RefreshToken)
			if err != nil {
				logs["error"]["decryptRefreshMsg"] = fmt.Sprintf("decryptRefresh: %s", token.RefreshToken)
				logs["error"]["decryptRefresh"] = err.Error()
				//w.WriteHeader(http.StatusInternalServerError)
				return
			}
			token.RefreshToken = decryptRefresh
			logs["info"]["decryptRefresh"] = decryptRefresh
		}

		if token.IDToken != "" {
			decryptIDToken, err := util.Decrypt(token.IDToken)
			if err != nil {
				logs["error"]["decryptIDTokenMsg"] = fmt.Sprintf("decryptIDToken: %s", token.IDToken)
				logs["error"]["decryptIDToken"] = err.Error()
				//w.WriteHeader(http.StatusInternalServerError)
				return
			}
			token.IDToken = decryptIDToken
			logs["info"]["decryptIDToken"] = decryptIDToken
		}

		// Обрабатываем поле Data как вложенный JSON
		var tokenData json.RawMessage
		if token.Data != "" {
			decryptData, err := util.Decrypt(token.Data)
			if err != nil {
				logs["error"]["decryptDataMsg"] = fmt.Sprintf("decryptData: %s", token.Data)
				logs["error"]["decryptData"] = err.Error()
				//w.WriteHeader(http.StatusInternalServerError)
				return
			}
			tokenData = json.RawMessage(decryptData)
			logs["info"]["decryptData"] = decryptData
		}

		responseTokens = append(responseTokens, models.UserDataExportTokenResponse{
			Provider:     token.Provider,
			IdToken:      token.IDToken,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpirationIn: token.ExpirationIn,
			ExpiresAt:    token.ExpiresAt.Unix(),
			Data:         tokenData,
			UpdatedAt:    token.UpdatedAt.Unix(),
		})
		logs["info"]["responseTokens"] = responseTokens
	}

	response = models.UserDataExportResponse{
		UserId: int(userID),
		Name:   user.Name,
		Email:  user.Email,
		Rings:  rings,
		Tokens: responseTokens,
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logs["error"]["ExportUserDataMsg"] = fmt.Sprintf("UserDataExportResponse encode: %s", response)
		logs["error"]["ExportUserData"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
	}

	return
}
