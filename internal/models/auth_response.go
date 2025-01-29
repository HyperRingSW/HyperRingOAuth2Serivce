package models

type AuthResponse struct {
	JWTToken     string `json:"jwt_token"` //jwt token
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}
