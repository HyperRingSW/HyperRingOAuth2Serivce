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

type ringHandler struct {
	*Handler
}

func (h *Handler) RingHandler() dependency.RingHandler {
	return &ringHandler{
		h,
	}
}

func (h *Handler) AttachRingHandler(w http.ResponseWriter, r *http.Request) {
	util.LogInfo("AttachRingHandler")
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		util.LogError(errors.New("invalid user ID in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	util.LogInfo(fmt.Sprintf("AttachRingHandler called with userID %d", userID))

	var ring models.Ring
	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		util.LogInfo("Failed to decode ring body")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Easy validations
	if ring.Id == "" {
		util.LogError(errors.New("missing ring id"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		util.LogInfo("failed to save ring in repo")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Attach ring to user
	userRing := models.UserRing{
		RingID: ring.Id,
		UserID: userID,
	}
	err = h.repo.UserRingRepository().SaveUserRing(&userRing)
	if err != nil {
		util.LogInfo("failed to save user-ring in repo")
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) UpdateRingHandler(w http.ResponseWriter, r *http.Request) {
	util.LogInfo("UpdateRingHandler")
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		util.LogError(errors.New("invalid user ID in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var body struct {
		RingId    string `json:"ringId"`
		UserNamed string `json:"userNamed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, err := h.repo.UserRingRepository().CheckUserRing(userID, body.RingId); err != nil {
		util.LogInfo(fmt.Sprintf("user ring not found. userId: %d ringId: %s", userID, body.RingId))
		util.LogError(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := h.repo.RingRepository().UpdateRingName(body.RingId, body.UserNamed); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) UnlinkRingHandler(w http.ResponseWriter, r *http.Request) {
	util.LogInfo("UnlinkRingHandler")
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		util.LogError(errors.New("invalid user ID in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var body struct {
		RingId string `json:"ringId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if body.RingId == "" {
		util.LogInfo(fmt.Sprintf("missing ring id, userID: %s ", userID))
		util.LogError(errors.New("missing ring id"))
		w.WriteHeader(http.StatusBadRequest)
	}

	if err := h.repo.UserRingRepository().DeleteUserRing(userID, body.RingId); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := h.repo.RingRepository().DeleteRing(body.RingId); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
