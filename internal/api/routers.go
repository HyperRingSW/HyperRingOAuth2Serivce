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

	router.HandleFunc("/auth/web/{provider}", func(w http.ResponseWriter, r *http.Request) {
		pr := mux.Vars(r)
		provider := pr["provider"]
		handler.AuthHandler().AuthWebHandler(w, r, provider)
	}).Methods("GET")

	router.HandleFunc("/auth/web/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		pr := mux.Vars(r)
		provider := pr["provider"]
		handler.AuthHandler().AuthWebCallbackHandler(w, r, provider)
	}).Methods("POST")

	// Маршрут для обработки callback от Apple
	router.HandleFunc("/auth/apple/callback", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().AppleCallbackHandler(w, r)
	}).Methods("POST")

	// Маршрут для обработки callback от Google
	router.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().GoogleCallbackHandler(w, r)
	}).Methods("GET")

	// Маршрут для отображения кнопки авторизации Google
	router.HandleFunc("/auth/google/button", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().GoogleAuthButtonHandler(w, r)
	}).Methods("GET")

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
