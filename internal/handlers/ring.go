package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
)

type ringHandler struct {
	*Handler
}

func (h *Handler) RingHandler() dependency.RingHandler {
	return &ringHandler{
		h,
	}
}

func (h *Handler) AttachRingHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		util.LogError(errors.New("invalid user ID in context"))
		w.WriteHeader(http.StatusInternalServerError)
		//http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	var ring models.Ring
	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		//http.Error(w, fmt.Sprintf("Error decode JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Easy validations
	if ring.Id == "" {
		util.LogError(errors.New("missing ring id"))
		w.WriteHeader(http.StatusBadRequest)
		//http.Error(w, "", http.StatusBadRequest)
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
		//http.Error(w, "", http.StatusBadRequest)
	}

	//Attach ring to user
	userRing := models.UserRing{
		RingID: ring.Id,
		UserID: userID,
	}
	err = h.repo.UserRingRepository().SaveUserRing(&userRing)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
		//http.Error(w, "", http.StatusBadRequest)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) UnlinkRingHandler(w http.ResponseWriter, r *http.Request) {

}

/*func (h *Handler) CreateRingHandler(w http.ResponseWriter, r *http.Request) {
	var ring models.Ring

	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		//http.Error(w, fmt.Sprintf("Error decode JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Easy validations
	if ring.Id == "" {
		util.LogError(errors.New("missing ring id"))
		w.WriteHeader(http.StatusBadRequest)
		//http.Error(w, "", http.StatusBadRequest) //TODO: add error text
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
		//http.Error(w, "", http.StatusBadRequest) //TODO: add error text
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(ring.Id); err != nil { //TODO: add response
		fmt.Printf("failed JSON decoding: %v", err)
	}
}*/
