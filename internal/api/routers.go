package api

import (
	"github.com/gorilla/mux"
	"net/http"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/middleware"
)

func RegisterRoutes(router *mux.Router, handler dependency.Handler) { //repo dependency.Repository, cfg *config.Config
	// OAuth2 маршруты
	router.HandleFunc("/auth/auths", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().AuthsHandler(w, r)
	}).Methods("POST")

	/*router.HandleFunc("/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().SignUpHandler(w, r)
	}).Methods("POST")

	router.HandleFunc("/auth/signin", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().SignInHandler(w, r)
	}).Methods("POST")

	router.HandleFunc("/auth/redirect", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().RedirectHandler(w, r)
	}).Methods("GET")

	router.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().CallbackHandler(w, r)
	}).Methods("POST")*/

	router.HandleFunc("/auth/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().RefreshTokenHandler(w, r) //
	}).Methods("POST")

	router.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthHandler().LogoutHandler(w, r)
	}).Methods("POST")

	// User Management маршруты
	router.HandleFunc("/user/profile", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.UserHandler().GetUserProfile(w, r)
	})).Methods("GET") //

	router.HandleFunc("/user/profile", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handler.UserHandler().UpdateUserProfile(w, r)
	})).Methods("PATCH") //?
}
