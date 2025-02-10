package providers

// ProviderConfig
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	UserInfoURL  string
	RevokeURL    string
	TeamID       string //for apple
	SecretPath   string //for apple
	KeyID        string //for apple
}
