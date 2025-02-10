package handlers

import (
	"encoding/json"
	"errors"
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
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	rings := make([]models.RingResponse, 0)
	for _, userRing := range userRings {
		ringDB, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
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
			ImageURL:    ringDB.ImageURL,
			SiteURL:     ringDB.SiteURL,
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
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserProfileGETResponse{
		Name:  user.Name,
		Email: user.Email,
		Rings: rings,
	})
}
