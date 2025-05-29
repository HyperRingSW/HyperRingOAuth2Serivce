package api

import (
	"net/http"
	"oauth2-server/internal/dependency"

	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, handler dependency.Handler, middlewares dependency.MiddleHandler) {
	//OAuth2
	router.HandleFunc("/auth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		pr := mux.Vars(r)
		provider := pr["provider"]
		handler.AuthHandler().AuthUserHandler(w, r, provider)
	}).Methods("POST")

	router.HandleFunc("/auth/token/refresh", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().RefreshTokenHandler(w, r)
	})).Methods("POST")

	router.HandleFunc("/user/logout", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().LogoutHandler(w, r)
	})).Methods("POST")

	router.HandleFunc("/user/remove", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().RemoveHandler(w, r)
	})).Methods("POST")

	//User Management
	router.HandleFunc("/user/profile", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.UserHandler().GetUserProfile(w, r)
	})).Methods("GET")

	router.HandleFunc("/user/data-export", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.UserHandler().ExportUserData(w, r)
	})).Methods("GET")

	//Attach User Ring
	router.HandleFunc("/user/ring", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.RingHandler().AttachRingHandler(w, r)
	})).Methods("POST")

	//Update ring user name
	router.HandleFunc("/user/ring", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.RingHandler().UpdateRingHandler(w, r)
	})).Methods("PATCH")

	//Unlink ring
	router.HandleFunc("/user/ring", middlewares.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.RingHandler().UnlinkRingHandler(w, r)
	})).Methods("DELETE")

	// Маршрут для обработки callback от Google
	router.HandleFunc("/auth/web/google", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().WebGoogleHandler(w, r)
	}).Methods("POST")

	router.HandleFunc("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/public/swagger.html")
	}).Methods("GET")

	router.HandleFunc("/swagger/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/public/swagger.html")
	}).Methods("GET")

	router.HandleFunc("/swagger.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "swagger.yaml")
	}).Methods("GET")
}
