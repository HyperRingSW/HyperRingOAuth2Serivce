package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
)

const (
	DeleteModeSoft         = "soft"
	DeleteModeHard         = "hard"
	AnonymizePhraseDefault = "delete"
)

type AppConfig struct {
	Addr              string `env:"APP_ADDR" env-default:"localhost:8090"`
	ExpiresTime       int    `env:"EXPIRES_TIME" env-default:"60"`
	CustomRefreshTime int    `env:"CUSTOM_REFRESH_TIME" env-default:"180"`
	CustomAccessTime  int    `env:"CUSTOM_ACCESS_TIME" env-default:"180"`
	CustomExpiresTime bool   `env:"CUSTOM_EXPIRES_TIME" env-default:"false"`
	DemoEmail         string `env:"DEMO_EMAIL" env-default:"admin@example.com"`
	DemoMode          bool   `env:"DEMO_MODE" env-default:"false"`
	AnonymizePhrase   string `env:"ANONYMIZE_PHRASE" env-default:"delete"`
	DeleteMode        string `env:"DELETE_MODE" env-default:"soft"`
	DisableJWTMode    bool   `env:"DISABLE_JWT_MODE" env-default:"true"`
	RedirectURL       string `env:"REDIRECT_URL" env-default:"http://localhost:8090/auth/callback"`
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

type WebOAuthProviderConfig struct {
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
	RedirectURL string `env:"OAUTH_REDIRECT_URL" env-default:"http://localhost:8090/auth/google/callback"`
	SecretKey   string `env:"OAUTH_SECRET_KEY" env-default:"http://localhost:8090/auth/google/callback"`
}

type WebGoogleAuthConfig struct {
	WebOAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:"https://oauth2.googleapis.com/token"`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:"https://oauth2.googleapis.com/revoke"`
	RedirectURL string `env:"OAUTH_REDIRECT_URL" env-default:"http://localhost:8090/auth/google/callback"`
	SecretKey   string `env:"OAUTH_SECRET_KEY" env-default:"http://localhost:8090/auth/google/callback"`
}

type AppleAuthConfig struct {
	OAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:""`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:""`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:""`
	TeamID      string `env:"OAUTH_TEAM_ID" env-default:""`
	SecretPath  string `env:"OAUTH_CLIENT_SECRET_PATH" env-default:""`
	KeyID       string `env:"OAUTH_KEY_ID" env-default:""`
	RedirectURL string `env:"APPLE_REDIRECT_URL" env-default:"http://localhost:8090/auth/apple/callback"`
	SecretKey   string `env:"OAUTH_SECRET_KEY" env-default:"http://localhost:8090/auth/google/callback"`
}

type FacebookAuthConfig struct {
	OAuthProviderConfig
	TokenURL    string `env:"OAUTH_TOKEN_URL" env-default:"https://graph.facebook.com/v12.0/oauth/access_token"`
	UserInfoURL string `env:"OAUTH_USER_INFO_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
	RevokeURL   string `env:"OAUTH_REVOKE_URL" env-default:"https://www.googleapis.com/oauth2/v3/userinfo"`
}
type Authorization struct {
	JWTSecret string              `env:"JWT_SECRET" env-default:"86194778010"`
	Google    GoogleAuthConfig    `envPrefix:"GOOGLE_"`
	WebGoogle WebGoogleAuthConfig `envPrefix:"WEB_GOOGLE_"`
	Apple     AppleAuthConfig     `envPrefix:"APPLE_"`
	Facebook  FacebookAuthConfig  `envPrefix:"FACEBOOK_"`
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

	if cfg.App.DeleteMode == "" {
		cfg.App.DeleteMode = DeleteModeSoft
	}

	if cfg.App.AnonymizePhrase == "" {
		cfg.App.AnonymizePhrase = AnonymizePhraseDefault
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
