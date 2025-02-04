package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/config"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/providers"
	"oauth2-server/internal/util"
	"strings"
	"time"
)

type authHandler struct {
	*Handler
}

func (h *Handler) AuthHandler() dependency.AuthHandler {
	return &authHandler{
		h,
	}
}

func (h *Handler) AuthUserHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider     string `json:"provider"`
		IdToken      string `json:"idToken,omitempty"`      // Google, Apple
		AccessToken  string `json:"accessToken,omitempty"`  // Facebook, Google
		RefreshToken string `json:"refreshToken,omitempty"` // Google
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Get provider config (URL user info, client id and etc)
	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var claims map[string]interface{}

	switch strings.ToLower(body.Provider) {
	case models.PROVIDER_GOOGLE:
		if body.IdToken == "" {
			http.Error(w, `{"error": "idToken is required"}`, http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyGoogleIDToken(body.IdToken, providerConfig)
		if err != nil {
			http.Error(w, `{"error": "invalid google idToken"}`, http.StatusUnauthorized)
			return
		}
	case models.PROVIDER_FB:
		if body.AccessToken == "" {
			http.Error(w, `{"error": "accessToken required for facebook"}`, http.StatusBadRequest)
			return
		}
		claims, err = providers.GetFacebookUserInfo(body.AccessToken, providerConfig.UserInfoURL)
		if err != nil {
			http.Error(w, `{"error": "invalid facebook accessToken"}`, http.StatusUnauthorized)
			return
		}
	case models.PROVIDER_APPLE:
		if body.IdToken == "" {
			http.Error(w, `{"error": "idToken is required"}`, http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyAppleIdentityToken(body.IdToken, providerConfig)
		if err != nil {
			http.Error(w, `{"error": "invalid Apple idToken"}`, http.StatusUnauthorized)
			return
		}
	default:
		http.Error(w, `{"error": "unknown provider"}`, http.StatusBadRequest)
		return
	}

	// get email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		http.Error(w, `{"error": "email not found in token data"}`, http.StatusUnauthorized)
		return
	}
	// get user name
	name, _ := claims["name"].(string)

	// Save claims JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, `{"error": "failed serialization token data"}`, http.StatusInternalServerError)
		return
	}

	// Create user
	userAuth := models.UserAuth{
		Email:     email,
		Name:      name,
		Data:      string(claimsJSON),
		CreatedAt: time.Now(),
	}
	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		http.Error(w, `{"error": "failed create or update user"}`, http.StatusInternalServerError)
		return
	}

	var expiresAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		expiresAt = time.Now().Add(time.Hour)
	}

	// Create token
	newToken := models.Token{
		UserID:       user.ID,
		Provider:     body.Provider,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		IDToken:      body.IdToken,
		ExpirationIn: int(expiresAt.Sub(time.Now()).Seconds()),
		ExpiresAt:    expiresAt,
		Data:         string(claimsJSON),
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "failed save or update token", "error_msg": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Генерируем JWT токен для вашего сервиса
	jwtToken, _, err := util.GenerateJWT(user.ID, body.Provider, expiresAt.Unix())
	if err != nil {
		http.Error(w, `{"error": "failed generate JWT"}`, http.StatusInternalServerError)
		return
	}

	response := models.AuthResponse{
		JWTToken:  jwtToken,
		ExpiresAt: savedToken.ExpiresAt.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RefreshTokenHandler
func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	token := h.repo.TokenRepository().UserToken(userID)
	if token == nil {
		http.Error(w, `{"error": "Token record not found"}`, http.StatusUnauthorized)
		return
	}

	decryptAccess, err := util.Decrypt(token.AccessToken)
	if err != nil {
		http.Error(w, `{"error": "Invalid or expired access token"}`, http.StatusUnauthorized)
		return
	}
	token.AccessToken = decryptAccess

	if token.RefreshToken != "" {
		decryptRefresh, err := util.Decrypt(token.RefreshToken)
		if err != nil {
			http.Error(w, `{"error": "Invalid or expired refresh token"}`, http.StatusUnauthorized)
			return
		}
		token.RefreshToken = decryptRefresh
	}

	providerConfig, err := getProviderConfig(token.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := url.Values{}
	switch token.Provider {
	case models.PROVIDER_FB:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("grant_type", "fb_exchange_token")
		data.Set("fb_exchange_token", token.AccessToken)
	case models.PROVIDER_GOOGLE, models.PROVIDER_APPLE:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", "")
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", token.RefreshToken)
	default:
		http.Error(w, `{"error": "Unsupported provider"}`, http.StatusBadRequest)
		return
	}

	// Send POST request to refresh token URL
	resp, err := http.PostForm(providerConfig.TokenURL, data)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to exchange token: %v"}`, err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf(`{"error": "Token exchange failed: %s, response: %s"}`, resp.Status, string(bodyBytes)), http.StatusBadRequest)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error": "Failed to read response body"}`, http.StatusBadRequest)
		return
	}

	var bodyResponse map[string]interface{}
	if err = json.Unmarshal(bodyBytes, &bodyResponse); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode token response: %w", err.Error()), http.StatusBadRequest)
		return
	}

	dataJSON, err := util.UserInfoToJSON(bodyResponse)
	if err != nil {
		http.Error(w, `{"error": "Unable to marshal user info"}`, http.StatusInternalServerError)
		return
	}

	// Decode providers response
	var tokenResponse providers.TokenResponse
	if err = json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to decode token response: %v"}`, err), http.StatusBadRequest)
		return
	}

	expiresAt := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	// Update token
	_, err = h.repo.TokenRepository().UpdateToken(
		models.Token{
			ID:           token.ID,
			UserID:       token.UserID,
			Provider:     token.Provider,
			AccessToken:  tokenResponse.AccessToken,  // new access token
			RefreshToken: tokenResponse.RefreshToken, // new refresh token
			ExpirationIn: tokenResponse.ExpiresIn,
			ExpiresAt:    expiresAt,
			Data:         string(dataJSON),
			UpdatedAt:    time.Now(),
		},
		token.Provider,
	)
	if err != nil {
		http.Error(w, `{"error": "Failed to update token"}`, http.StatusInternalServerError)
		return
	}

	newJWT, _, err := util.GenerateJWT(token.UserID, provider, expiresAt.Unix())
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	response := models.AuthResponse{
		JWTToken:  newJWT,
		ExpiresAt: expiresAt.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LogoutHandler
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID in context"}`, http.StatusUnauthorized)
		return
	}

	token := h.repo.TokenRepository().UserToken(userID)
	if token == nil {
		http.Error(w, `{"error": "Token not found"}`, http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, `{"error": "Invalid provider"}`, http.StatusBadRequest)
		return
	}

	decryptAccess, err := util.Decrypt(token.AccessToken)
	if err != nil {
		http.Error(w, `{"error": "Invalid or expired access token"}`, http.StatusUnauthorized)
		return
	}

	// Set data for provider
	data := url.Values{}
	switch provider {
	case models.PROVIDER_FB:
		data.Set("next", "http://localhost:3000/")
		data.Set("access_token", decryptAccess)
	case models.PROVIDER_GOOGLE,
		models.PROVIDER_APPLE:
		data.Set("token", decryptAccess)
	default:
		http.Error(w, `{"error": "Unsupported provider"}`, http.StatusBadRequest)
		return
	}

	resp, err := http.PostForm(providerConfig.RevokeURL, data)
	if err != nil {
		http.Error(w, `{"error": "Failed to revoke token"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, `{"error": "Token revocation failed"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.TokenRepository().InvalidateToken(token.AccessToken); err != nil {
		http.Error(w, `{"error": "Failed to logout"}`, http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// getProviderConfig
func getProviderConfig(provider string, cfg config.Authorization) (providers.ProviderConfig, error) {
	switch provider {
	case models.PROVIDER_GOOGLE:
		return providers.ProviderConfig{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			TokenURL:     cfg.Google.TokenURL,
			UserInfoURL:  cfg.Google.UserInfoURL,
			RevokeURL:    cfg.Google.RevokeURL,
		}, nil
	case models.PROVIDER_FB:
		return providers.ProviderConfig{
			ClientID:     cfg.Facebook.ClientID,
			ClientSecret: cfg.Facebook.ClientSecret,
			TokenURL:     cfg.Facebook.TokenURL,
			UserInfoURL:  cfg.Facebook.UserInfoURL,
			RevokeURL:    cfg.Facebook.RevokeURL,
		}, nil
	case models.PROVIDER_APPLE:
		return providers.ProviderConfig{
			ClientID:     cfg.Apple.ClientID,
			ClientSecret: cfg.Apple.ClientSecret,
			TokenURL:     cfg.Apple.TokenURL,
			UserInfoURL:  cfg.Apple.UserInfoURL,
			RevokeURL:    cfg.Apple.RevokeURL,
		}, nil
	default:
		return providers.ProviderConfig{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}
