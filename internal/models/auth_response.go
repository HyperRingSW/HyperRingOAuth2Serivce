package models

var AuthBodyRequest struct {
	IdToken      string `json:"idToken,omitempty"`      // Google, Apple
	AccessToken  string `json:"accessToken,omitempty"`  // Facebook, Google
	RefreshToken string `json:"refreshToken,omitempty"` // Google
	DeviceUUID   string `json:"uuid,omitempty"`
}

type AuthResponse struct {
	JWTToken  string `json:"token"` //jwt token
	ExpiresAt int64  `json:"expiresAt"`
}

var AuthWebGoogleBodyRequest struct {
	IdToken    string `json:"idToken"`
	DeviceUUID string `json:"uuid,omitempty"`
}
