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

	rings := make([]models.Ring, 0)
	for _, userRing := range userRings {
		ring, err := h.repo.RingRepository().GetRing(userRing.RingID)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rings = append(rings, *ring)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserProfileGETResponse{
		UserId: user.ID,
		Name:   user.Name,
		Email:  user.Email,
		Rings:  rings,
	})
}
