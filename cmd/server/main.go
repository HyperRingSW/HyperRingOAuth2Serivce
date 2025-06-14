package main

import (
	corsHandler "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"oauth2-server/internal/api"
	"oauth2-server/internal/config"
	"oauth2-server/internal/handlers"
	"oauth2-server/internal/middleware"
	"oauth2-server/internal/repository"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed load config: %v", err)
	}

	repo, err := repository.New(cfg.Database, cfg.AutoMigration)
	if err != nil {
		log.Fatalf("failed connect to db: %v", err)
	}

	handler := handlers.NewHandler(cfg, repo)
	middlewares := middleware.NewMiddleware(repo)

	router := mux.NewRouter()
	api.RegisterRoutes(router, handler, middlewares)

	// Add rate limiting middleware
	rateLimitedRouter := middleware.RateLimiter(router)

	// setting CORS
	corsOptions := corsHandler.CORS()

	log.Printf("Server running %s", cfg.App.Addr)
	log.Fatal(http.ListenAndServe(cfg.App.Addr, corsOptions(rateLimitedRouter)))
}
