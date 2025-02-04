package models

type AuthResponse struct {
	JWTToken  string `json:"token"` //jwt token
	ExpiresAt int64  `json:"expires_at"`
}
