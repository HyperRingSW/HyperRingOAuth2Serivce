package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"strings"
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
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error": "Unauthorized:11 Invalid token format"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := util.ParseJWT(tokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid token4"}`, http.StatusUnauthorized)
		return
	}

	userId, ok := claims["user_id"].(float64)
	if !ok {
		http.Error(w, `{"error": "Invalid token payload"}`, http.StatusUnauthorized)
		return
	}

	// Получаем пользователя из базы данных
	user := h.repo.UserRepository().GetUserByID(uint(userId))
	if user == nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.UserProfileGETResponse{
		UserId: user.ID,
		Name:   user.Email,
		Email:  user.Name,
	})
}

// UpdateUserProfile
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

// DeleteUserAccount
func (h *Handler) DeleteUserAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	err := h.repo.UserRepository().DeleteUser(userID)
	if err != nil {
		http.Error(w, `{"error": "Unable to delete user"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Account deleted",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// BackupUserData
func (h *Handler) BackupUserData(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	user := h.repo.UserRepository().GetUserByID(userID)
	if user == nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	backup := map[string]interface{}{
		"id":    user.ID,
		"email": user.Email,
		"name":  user.Name,
	}

	response := map[string]interface{}{
		"status": "success",
		"data":   backup,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RestoreUserData
func (h *Handler) RestoreUserData(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	var backupData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&backupData); err != nil {
		http.Error(w, `{"error": "Invalid backup data"}`, http.StatusBadRequest)
		return
	}

	updates := map[string]interface{}{
		"email": backupData["email"],
		"name":  backupData["name"],
	}

	err := h.repo.UserRepository().UpdateUser(userID, updates)
	if err != nil {
		http.Error(w, `{"error": "Unable to restore user data"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Data restored",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
