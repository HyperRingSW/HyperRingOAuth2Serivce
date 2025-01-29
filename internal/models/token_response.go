package models

type TokenServiceResponse struct {
	UserID       uint
	Provider     string
	AccessToken  string
	RefreshToken string
	ExpirationIn int
	ExpiresAt    int64
	Data         string
}
