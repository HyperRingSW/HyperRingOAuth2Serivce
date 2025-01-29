package models

type TokenServiceResponse struct {
	UserID       uint   `json:"user_id"`
	Provider     string `json:"provider"`
	JWTToken     string `json:"jwt_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpirationIn int    `json:"expiration_in"`
	ExpiresAt    int64  `json:"expires_at"`
	Data         string `json:"data"`
}
