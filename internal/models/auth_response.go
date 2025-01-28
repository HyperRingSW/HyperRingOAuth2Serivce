package models

type AuthResponse struct {
	JWTToken             string `json:"jwt_token"` //jwt token
	AccessToken          string `json:"access_token"`
	AccessTokenOriginal  string `json:"access_token_original"`
	RefreshToken         string `json:"refresh_token"`
	RefreshTokenOriginal string `json:"refresh_token_original"`
	ExpiresAt            int64  `json:"expires_at"`
}
