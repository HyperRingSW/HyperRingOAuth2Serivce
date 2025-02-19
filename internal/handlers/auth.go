package handlers

import (
	"encoding/json"
	"errors"
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

func (h *Handler) AuthUserHandler(w http.ResponseWriter, r *http.Request, provider string) {
	body := models.AuthBodyRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get provider config (URL user info, client id and etc)
	providerConfig, err := getProviderConfig(provider, h.cfg.Authorization)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var claims map[string]interface{}

	switch strings.ToLower(provider) {
	case models.PROVIDER_GOOGLE:
		if body.IdToken == "" {
			util.LogError(errors.New("idToken is required"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyGoogleIDToken(body.IdToken, providerConfig)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		//Checking info on provider
		_, err := providers.GetUserInfo(body.AccessToken, providerConfig.UserInfoURL, provider)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

	case models.PROVIDER_APPLE:
		if body.IdToken == "" {
			util.LogError(errors.New("idToken is required"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyAppleIdentityToken(body.IdToken, providerConfig)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		util.LogError(errors.New("provider not supported"))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// get email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		util.LogError(errors.New("email is required"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// get user name
	name, _ := claims["name"].(string)

	// Save claims JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
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
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var expiresAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		expiresAt = time.Now().Add(time.Hour)
	}

	if h.cfg.App.CustomExpiresTime {
		expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
	}

	if body.DeviceUUID == "" {
		body.DeviceUUID = models.DefaultUUID
	}

	// Create token
	newToken := models.Token{
		UserID:       user.ID,
		Provider:     provider,
		DeviceUUID:   body.DeviceUUID,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		IDToken:      body.IdToken,
		ExpirationIn: int(expiresAt.Sub(time.Now()).Seconds()),
		ExpiresAt:    expiresAt,
		Data:         string(claimsJSON),
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	jwtToken, _, err := util.GenerateJWT(user.ID, provider, expiresAt.Unix(), body.DeviceUUID)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.AuthResponse{
		JWTToken:  jwtToken,
		ExpiresAt: savedToken.ExpiresAt.Unix(),
	})
}

func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		util.LogError(errors.New("invalid user ID in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		util.LogError(errors.New("invalid provider in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	deviceUUID, ok := r.Context().Value("deviceUUID").(string)
	if !ok {
		util.LogError(errors.New("invalid provider in context"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	token := h.repo.TokenRepository().UserToken(userID, provider)
	if token == nil {
		util.LogError(errors.New("token is not found"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if token.AccessToken != "" {
		decryptAccess, err := util.Decrypt(token.AccessToken)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token.AccessToken = decryptAccess
	}

	if token.RefreshToken != "" {
		decryptRefresh, err := util.Decrypt(token.RefreshToken)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token.RefreshToken = decryptRefresh
	}

	if token.IDToken != "" {
		decryptIDToken, err := util.Decrypt(token.IDToken)
		if err != nil {
			util.LogInfo("error decrypting ID token")
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token.IDToken = decryptIDToken
	}

	providerConfig, err := getProviderConfig(token.Provider, h.cfg.Authorization)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data := url.Values{}
	switch token.Provider {
	case models.PROVIDER_APPLE:
		_, err := providers.VerifyAppleIdentityToken(token.IDToken, providerConfig)
		if err != nil {
			util.LogInfo("error verifying apple")
			util.LogError(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expiresAt := time.Now().Add(180 * 24 * time.Hour)
		if h.cfg.App.CustomExpiresTime {
			expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
		}

		jwtToken, _, err := util.GenerateJWT(userID, provider, expiresAt.Unix(), deviceUUID)
		if err != nil {
			util.LogInfo("error generating jwt")
			util.LogError(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		response := models.AuthResponse{
			JWTToken:  jwtToken,
			ExpiresAt: expiresAt.Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	case models.PROVIDER_FB:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("grant_type", "fb_exchange_token")
		data.Set("fb_exchange_token", token.AccessToken)
	case models.PROVIDER_GOOGLE:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", "")
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", token.RefreshToken)
	default:
		util.LogError(errors.New("invalid provider"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Send POST request to refresh token URL
	resp, err := http.PostForm(providerConfig.TokenURL, data)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		util.LogError(errors.New("Token exchange failed"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var bodyResponse map[string]interface{}
	if err = json.Unmarshal(bodyBytes, &bodyResponse); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	dataJSON, err := util.UserInfoToJSON(bodyResponse)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Decode providers response
	var tokenResponse providers.TokenResponse
	if err = json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	if h.cfg.App.CustomExpiresTime {
		expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
	}

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
		deviceUUID,
	)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	newJWT, _, err := util.GenerateJWT(token.UserID, provider, expiresAt.Unix(), deviceUUID)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusInternalServerError)
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
		util.LogError(errors.New("Invalid user ID in context"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		util.LogError(errors.New("Invalid provider in context"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	deviceUUID, ok := r.Context().Value("device_uuid").(string)
	if !ok {
		util.LogError(errors.New("Invalid deviceUUID in context"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := h.repo.TokenRepository().UserToken(userID, provider)
	if token == nil {
		util.LogError(errors.New("Token not found"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(provider, h.cfg.Authorization)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	decryptAccess := ""
	if token.AccessToken != "" {
		decryptAccess, err = util.Decrypt(token.AccessToken)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Set data for provider
	data := url.Values{}
	switch provider {
	case models.PROVIDER_APPLE:
		err = h.repo.TokenRepository().InvalidateIdToken(token.IDToken, deviceUUID)
		if err != nil {
			util.LogError(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case models.PROVIDER_GOOGLE:
		data.Set("token", decryptAccess)
	default:
		util.LogError(errors.New("Unsupported provider"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, err := http.PostForm(providerConfig.RevokeURL, data)
	if err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		util.LogError(errors.New("Token revocation failed"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.repo.TokenRepository().InvalidateAccessToken(token.AccessToken, deviceUUID); err != nil {
		util.LogError(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Send response
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
			TeamID:       cfg.Apple.TeamID,
			SecretPath:   cfg.Apple.SecretPath,
			KeyID:        cfg.Apple.KeyID,
		}, nil
	default:
		return providers.ProviderConfig{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}
