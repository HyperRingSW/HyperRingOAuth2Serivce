/*package main

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

	httpSwagger "github.com/swaggo/http-swagger"
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

	router := mux.NewRouter()
	api.RegisterRoutes(router, handler)

	// Маршрут для Swagger UI
	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Добавление rate limiting middleware
	rateLimitedRouter := middleware.RateLimiter(router)

	// Настройка CORS
	corsOptions := corsHandler.CORS(
		corsHandler.AllowedOrigins([]string{"http://localhost:3000"}),
		corsHandler.AllowedMethods([]string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}),
		corsHandler.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	log.Printf("Server running %s", cfg.App.Addr)
	log.Fatal(http.ListenAndServe(cfg.App.Addr, corsOptions(rateLimitedRouter)))
}*/

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

	router := mux.NewRouter()
	api.RegisterRoutes(router, handler)

	// Add rate limiting middleware
	rateLimitedRouter := middleware.RateLimiter(router)

	// setting CORS
	corsOptions := corsHandler.CORS(
		corsHandler.AllowedOrigins([]string{"http://localhost:3000"}),
		corsHandler.AllowedMethods([]string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}),
		corsHandler.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	log.Printf("Server running %s", cfg.App.Addr)
	log.Fatal(http.ListenAndServe(cfg.App.Addr, corsOptions(rateLimitedRouter)))
}
