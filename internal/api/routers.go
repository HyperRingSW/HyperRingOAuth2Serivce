package api

import (
	"github.com/gorilla/mux"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/middleware"
)

func RegisterRoutes(router *mux.Router, handler dependency.Handler) {
	//OAuth2
	router.HandleFunc("/auth/user", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().AuthUserHandler(w, r)
	}).Methods("POST")

	router.HandleFunc("/auth/token/refresh", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().RefreshTokenHandler(w, r)
	})).Methods("POST")

	router.HandleFunc("/auth/logout", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().LogoutHandler(w, r)
	})).Methods("POST")

	//User Management
	router.HandleFunc("/user/profile", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.UserHandler().GetUserProfile(w, r)
	})).Methods("GET")

	//Attach User Ring
	router.HandleFunc("/user/ring", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.RingHandler().AttachRingHandler(w, r)
	})).Methods("PATCH")

	//Unlink ring
	router.HandleFunc("/user/ring", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.RingHandler().UnlinkRingHandler(w, r)
	})).Methods("DELETE")
}
