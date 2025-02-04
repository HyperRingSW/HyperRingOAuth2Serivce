package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
)

type ringHandler struct {
	*Handler
}

func (h *Handler) RingHandler() dependency.RingHandler {
	return &ringHandler{
		h,
	}
}

func (h *Handler) CreateRingHandler(w http.ResponseWriter, r *http.Request) {
	var ring models.Ring

	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		http.Error(w, fmt.Sprintf("Error decode JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Easy validations
	if ring.Id == "" {
		http.Error(w, "", http.StatusBadRequest) //TODO: add error text
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest) //TODO: add error text
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(ring.Id); err != nil { //TODO: add response
		fmt.Printf("failed JSON decoding: %v", err)
	}
}

func (h *Handler) AttachRingHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	var ring models.Ring
	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		http.Error(w, fmt.Sprintf("Error decode JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Easy validations
	if ring.Id == "" {
		http.Error(w, "", http.StatusBadRequest) //TODO: add error text
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest) //TODO: add error text
	}

	//Attach ring to user
	userRing := models.UserRing{
		RingID: ring.Id,
		UserID: userID,
	}
	err = h.repo.UserRingRepository().SaveUserRing(&userRing)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest) //TODO: add log error
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	//TODO: add response ???
}

func (h *Handler) UnlinkRingHandler(w http.ResponseWriter, r *http.Request) {

}
