package handlers

import (
	"encoding/json"
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
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)

	defer func() {
		logs["info"]["handler"] = "AttachRingHandler"
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
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

	var ring models.Ring
	// Decode JSON to Ring model
	if err := json.NewDecoder(r.Body).Decode(&ring); err != nil {
		logs["error"]["body"] = r.Body
		logs["error"]["bodyMsg"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["ring"] = ring

	// Easy validations
	if ring.Id == "" {
		logs["error"]["ring.id"] = "ring id is required"
		//w.WriteHeader(http.StatusBadRequest)
		return
	}

	ring.DeviceDescription.RingID = ring.Id

	_, err := h.repo.RingRepository().SaveRing(&ring)
	if err != nil {
		logs["error"]["saveRingParams"] = fmt.Sprintf("ring: %s", ring)
		logs["error"]["SaveRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Attach ring to user
	userRing := models.UserRing{
		RingID: ring.Id,
		UserID: userID,
	}
	err = h.repo.UserRingRepository().SaveUserRing(&userRing)
	if err != nil {
		logs["error"]["SaveUserRingParams"] = fmt.Sprintf("userRing: %s", userRing)
		logs["error"]["SaveUserRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//w.WriteHeader(http.StatusCreated)
	return
}

func (h *Handler) UpdateRingHandler(w http.ResponseWriter, r *http.Request) {
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)

	defer func() {
		logs["info"]["handler"] = "UpdateRingHandler"
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
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

	var body struct {
		RingId    string `json:"ringId"`
		UserNamed string `json:"userNamed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		logs["error"]["body"] = r.Body
		logs["error"]["bodyMsg"] = err.Error()
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["body"] = r.Body

	if _, err := h.repo.UserRingRepository().CheckUserRing(userID, body.RingId); err != nil {
		logs["error"]["CheckUserRingParams"] = fmt.Sprintf("userID, body.RingId: %s, %s", userID, body.RingId)
		logs["error"]["CheckUserRing"] = err.Error()
		//w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := h.repo.RingRepository().UpdateRingName(body.RingId, body.UserNamed); err != nil {
		logs["error"]["UpdateRingNameParams"] = fmt.Sprintf("body.RingId, body.UserNamed: %s, %s", body.RingId, body.UserNamed)
		logs["error"]["UpdateRingName"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//w.WriteHeader(http.StatusOK)
	return
}

func (h *Handler) UnlinkRingHandler(w http.ResponseWriter, r *http.Request) {
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)

	defer func() {
		logs["info"]["handler"] = "UnlinkRingHandler"
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
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

	var body struct {
		RingId string `json:"ringId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		logs["error"]["body"] = r.Body
		logs["error"]["bodyMsg"] = err.Error()
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["body"] = r.Body

	if body.RingId == "" {
		logs["error"]["ringId"] = fmt.Sprintf("missing ring id, userID: %s ", userID)
		//w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.repo.UserRingRepository().DeleteUserRing(userID, body.RingId); err != nil {
		logs["error"]["DeleteUserRingParams"] = fmt.Sprintf("userID, body.RingId: %s, %s", userID, body.RingId)
		logs["error"]["DeleteUserRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := h.repo.RingRepository().DeleteRing(body.RingId); err != nil {
		logs["error"]["DeleteRingParams"] = fmt.Sprintf("ring: %s", body.RingId)
		logs["error"]["DeleteRing"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(http.StatusOK)
	return
}
