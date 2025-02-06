package models

var AuthBodyRequest struct {
	IdToken      string `json:"idToken,omitempty"`      // Google, Apple
	AccessToken  string `json:"accessToken,omitempty"`  // Facebook, Google
	RefreshToken string `json:"refreshToken,omitempty"` // Google
}

type AuthResponse struct {
	JWTToken  string `json:"token"` //jwt token
	ExpiresAt int64  `json:"expiresAt"`
}
