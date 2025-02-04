package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
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

	// Получаем пользователя из базы данных
	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	//rings, err := h.repo.RingRepository().SaveRing()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserProfileGETResponse{
		UserId: user.ID,
		Name:   user.Email,
		Email:  user.Name,
		Rings:  make([]models.Ring, 0),
	})
}

// UpdateUserProfile UNUSED
func (h *Handler) UpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, `{"error": "Invalid input"}`, http.StatusBadRequest)
		return
	}

	err := h.repo.UserRepository().UpdateUser(userID, updates)
	if err != nil {
		http.Error(w, `{"error": "Unable to update user"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Profile updated",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
