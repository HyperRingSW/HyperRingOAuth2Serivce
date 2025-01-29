package config

import (
	"fmt"
	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
	"os"
)

type AppConfig struct {
	Addr string `env:"APP_ADDR" env-default:"localhost:8090"`
}

type OAuht2Config struct {
	JWTSecret string `env:"JWT_SECRET"`
}

type DatabaseConfig struct {
	Host     string `env:"DB_HOST" env-default:"localhost"`
	Port     int    `env:"DB_PORT" env-default:"5432"`
	User     string `env:"DB_USER" env-default:"skydb"`
	Password string `env:"DB_PASSWORD" env-default:"12345"`
	Name     string `env:"DB_NAME" env-default:"fidoauth"`
	SSLMode  string `env:"DB_SSLMODE" env-default:"disable"`
}

type OAuthProviderConfig struct {
	ClientID     string `env:"OAUTH_CLIENT_ID" env-default:""`
	ClientSecret string `env:"OAUTH_CLIENT_SECRET" env-default:""`
}

type MFAConfig struct {
	Enabled bool `env:"MFA_ENABLED" env-default:"false"`
}

type GoogleAuthConfig struct {
	OAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:"https://oauth2.googleapis.com/token"`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:"https://oauth2.googleapis.com/revoke"`
}

type AppleAuthConfig struct {
	OAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:"https://oauth2.googleapis.com/token"`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:"https://www.facebook.com/logout.php"`
}

type FacebookAuthConfig struct {
	OAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:"https://graph.facebook.com/v12.0/oauth/access_token"`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
}
type Authorization struct {
	JWTSecret string             `env:"JWT_SECRET" env-default:"86194778010"`
	Google    GoogleAuthConfig   `envPrefix:"GOOGLE_"`
	Apple     AppleAuthConfig    `envPrefix:"APPLE_"`
	Facebook  FacebookAuthConfig `envPrefix:"FACEBOOK_"`
}

type Config struct {
	App           AppConfig      `env:"-"`
	Authorization Authorization  `env:"-"`
	Database      DatabaseConfig `env:"-"`
	AutoMigration bool           `env:"DB_AUTO_MIGRATION" env-default:"true"`
	MFA           MFAConfig      `env:"-"`
}

const envFile = ".env"

func LoadConfig() (*Config, error) {
	var cfg Config

	if CheckFileExistence(envFile) {
		err := godotenv.Load(envFile)
		if err != nil {
			fmt.Println("No .env file found, loading from environment variables.")
		}
	}
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	return &cfg, nil
}

func CheckFileExistence(path string) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
