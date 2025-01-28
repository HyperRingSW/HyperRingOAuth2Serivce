package handlers

import (
	"net/http"
	"oauth2-server/internal/config"
	"oauth2-server/internal/dependency"
)

type Handler struct {
	w    http.ResponseWriter
	r    *http.Request
	cfg  *config.Config
	repo dependency.Repository
}

func NewHandler(cfg *config.Config, repo dependency.Repository) *Handler {
	return &Handler{
		cfg:  cfg,
		repo: repo,
	}
}
