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

func (h *Handler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		Provider    string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := providers.ExchangeCodeForToken(body.Code, body.RedirectURI, providerConfig, "")
	if err != nil {
		http.Error(w, `{"error": "Unable to exchange code for token", "err_token:"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	userInfo, err := providers.GetUserInfo(token, providerConfig.UserInfoURL, body.Provider)
	if err != nil {
		http.Error(w, `{"error": "Unable to fetch user info"}`, http.StatusUnauthorized)
		return
	}

	dataJSON, err := util.UserInfoToJSON(userInfo)
	if err != nil {
		http.Error(w, `{"error": "Unable to marshal user info"}`, http.StatusInternalServerError)
		return
	}

	userAuth := models.UserAuth{
		Email:     userInfo["email"].(string),
		Name:      userInfo["name"].(string),
		Data:      string(dataJSON),
		CreatedAt: time.Now(),
	}

	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		http.Error(w, `{"error": "Unable to save user info"}`, http.StatusInternalServerError)
		return
	}

	newToken := models.Token{
		UserID:       user.ID,
		Provider:     body.Provider,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpirationIn: token.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		Data:         string(dataJSON),
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": \"Failed to save token\", \"error_msg\": \"\t\"}", err.Error()), http.StatusInternalServerError)
		return
	}

	jwt, _, err := util.GenerateJWT(user.ID, "user")
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.AuthResponse{
		JWTToken:    jwt,
		AccessToken: newToken.AccessToken,
		//AccessTokenOriginal:  token.AccessToken,
		RefreshToken: newToken.RefreshToken,
		//RefreshTokenOriginal: token.RefreshToken,
		ExpiresAt: savedToken.ExpiresAt.Unix(),
	})
}

// SignInHandler
func (h *Handler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code         string `json:"code"`
		RedirectURI  string `json:"redirect_uri"`
		Provider     string `json:"provider"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := providers.ExchangeCodeForToken(body.Code, body.RedirectURI, providerConfig, body.CodeVerifier)
	if err != nil {
		http.Error(w, `{"error": "Failed to exchange code for token"}`, http.StatusUnauthorized)
		return
	}

	userInfo, err := providers.GetUserInfo(token, providerConfig.UserInfoURL, body.Provider)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch user info"}`, http.StatusUnauthorized)
		return
	}

	dataJSON, err := util.UserInfoToJSON(userInfo)
	if err != nil {
		http.Error(w, `{"error": "Unable to marshal user info"}`, http.StatusInternalServerError)
		return
	}

	userAuth := models.UserAuth{
		Email:     userInfo["email"].(string),
		Name:      userInfo["name"].(string),
		Data:      string(dataJSON),
		CreatedAt: time.Now(),
	}

	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		http.Error(w, `{"error": "Failed to save user info"}`, http.StatusInternalServerError)
		return
	}

	newToken := models.Token{
		UserID:       user.ID,
		Provider:     body.Provider,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpirationIn: token.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		Data:         string(dataJSON),
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": \"Failed to save token\", \"error_msg\": \"\t\"}", err.Error()), http.StatusInternalServerError)
		return
	}

	jwt, _, err := util.GenerateJWT(user.ID, "user")
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.AuthResponse{
		JWTToken:    jwt,
		AccessToken: newToken.AccessToken,
		//AccessTokenOriginal:  token.AccessToken,
		RefreshToken: newToken.RefreshToken,
		//RefreshTokenOriginal: token.RefreshToken,
		ExpiresAt: savedToken.ExpiresAt.Unix(),
	})
}

// RedirectHandler
func (h *Handler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	redirectURI := r.URL.Query().Get("redirect_uri")
	codeChallenge := r.URL.Query().Get("code_challenge")

	if provider == "" || redirectURI == "" {
		http.Error(w, "Missing required parameters: provider or redirect_ur", http.StatusBadRequest)
		return
	}

	if strings.HasSuffix(provider, models.PKCE_SUFIX) && codeChallenge == "" {
		http.Error(w, "Missing required parameter: code_challenge", http.StatusBadRequest)
		return
	}

	var authURL string
	switch provider {
	case models.PROVIDER_GOOGLE + models.PKCE_SUFIX:
		authURL = fmt.Sprintf(
			"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile%%20openid&access_type=offline&prompt=consent&state=google&code_challenge=%s&code_challenge_method=S256",
			h.cfg.Authorization.Google.ClientID,
			redirectURI,
			codeChallenge,
		)
	case models.PROVIDER_FB + models.PKCE_SUFIX:
		// FB PKCE может игнорировать, но передадим:
		authURL = fmt.Sprintf(
			"https://www.facebook.com/v12.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=code&scope=email&state=facebook&code_challenge=%s&code_challenge_method=S256",
			h.cfg.Authorization.Facebook.ClientID,
			redirectURI,
			codeChallenge,
		)
	case models.PROVIDER_APPLE + models.PKCE_SUFIX:
		authURL = fmt.Sprintf(
			"https://appleid.apple.com/auth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=name%%20email&state=apple&code_challenge=%s&code_challenge_method=S256",
			h.cfg.Authorization.Apple.ClientID,
			redirectURI,
			codeChallenge,
		)
	case models.PROVIDER_GOOGLE:
		authURL = fmt.Sprintf(
			"https://accounts.google.com/o/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email profile&access_type=offline&prompt=consent&state=google",
			h.cfg.Authorization.Google.ClientID, redirectURI,
		)
	case models.PROVIDER_FB:
		authURL = fmt.Sprintf(
			"https://www.facebook.com/v12.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=code&scope=email&state=facebook",
			h.cfg.Authorization.Facebook.ClientID, redirectURI,
		)
	case models.PROVIDER_APPLE:
		authURL = fmt.Sprintf(
			"https://appleid.apple.com/auth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=name email&state=apple",
			h.cfg.Authorization.Apple.ClientID, redirectURI,
		)
	default:
		http.Error(w, "Unsupported provider", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// RefreshTokenHandler
func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
		Provider     string `json:"provider"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if body.Provider == "" {
		http.Error(w, `{"error": "Missing refresh_token or provider"}`, http.StatusBadRequest)
		return
	}

	token, err := h.repo.TokenRepository().RefreshAccessToken(body.RefreshToken, false)
	if err != nil || token == nil {
		http.Error(w, `{"error": "Invalid or expired refresh token"}`, http.StatusUnauthorized)
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
		}
		token.RefreshToken = decryptRefresh
	}

	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := url.Values{}
	switch body.Provider {
	case models.PROVIDER_FB:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("grant_type", "fb_exchange_token")
		data.Set("fb_exchange_token", token.AccessToken)
	case models.PROVIDER_GOOGLE,
		models.PROVIDER_APPLE:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("refresh_token", token.RefreshToken)
		data.Set("grant_type", "refresh_token")
		data.Set("prompt", "consent")
		data.Set("access_type", "offline")
	}

	resp, err := http.PostForm(providerConfig.TokenURL, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to exchange code for token: %w", err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("token exchange failed: %s, response: %s", resp.Status, string(body)), http.StatusBadRequest)
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

	var tokenResponse providers.TokenResponse
	if err = json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode token response: %w", err.Error()), http.StatusBadRequest)
		return
	}

	dataJSON, err := util.UserInfoToJSON(tokenResponse)
	if err != nil {
		http.Error(w, `{"error": "Unable to marshal user info"}`, http.StatusInternalServerError)
		return
	}

	//TODO encrypt вынести в отдельный метод
	expiresAt := time.Now().Add(time.Duration(token.ExpirationIn) * time.Second)
	updatedToken, err := h.repo.TokenRepository().UpdateToken(
		models.Token{
			ID:           token.ID,
			UserID:       token.UserID,
			Provider:     token.Provider,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpirationIn: token.ExpirationIn,
			ExpiresAt:    expiresAt,
			Data:         string(dataJSON),
			UpdatedAt:    time.Now(),
		},
		body.Provider,
	)
	if err != nil {
		http.Error(w, `{"error": "Failed to save user info"}`, http.StatusInternalServerError)
		return
	}

	jwt, _, err := util.GenerateJWT(token.UserID, "user")
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.TokenServiceResponse{
		JWTToken:     jwt,
		UserID:       updatedToken.UserID,
		Provider:     updatedToken.Provider,
		AccessToken:  updatedToken.AccessToken,
		RefreshToken: updatedToken.RefreshToken,
		ExpirationIn: updatedToken.ExpirationIn,
		ExpiresAt:    expiresAt.Unix(),
		Data:         updatedToken.Data,
	})
}

// CallbackHandler
func (h *Handler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code         string `json:"code"`
		RedirectURI  string `json:"redirect_uri"`
		Provider     string `json:"provider"`
		CodeVerifier string `json:"code_verifier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if body.Provider == "" || body.Code == "" {
		http.Error(w, "Missing required parameters: provider or code", http.StatusBadRequest)
		return
	}

	if strings.HasSuffix(body.Provider, models.PKCE_SUFIX) && body.CodeVerifier == "" {
		http.Error(w, "Missing required parameter: code_verifier", http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := providers.ExchangeCodeForToken(body.Code, body.RedirectURI, providerConfig, body.CodeVerifier)
	if err != nil {
		http.Error(w, `{"error": "Unable to exchange code for token"}`, http.StatusBadRequest)
		return
	}

	userInfo, err := providers.GetUserInfo(token, providerConfig.UserInfoURL, body.Provider)
	if err != nil {
		http.Error(w, `{"error": "Unable to fetch user info"}`, http.StatusUnauthorized)
		return
	}

	dataJSON, err := util.UserInfoToJSON(userInfo)
	if err != nil {
		http.Error(w, `{"error": "Failed to serialize user info"}`, http.StatusInternalServerError)
		return
	}

	userAuth := models.UserAuth{
		Email:     userInfo["email"].(string),
		Name:      userInfo["name"].(string),
		Data:      string(dataJSON),
		CreatedAt: time.Now(),
	}

	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		http.Error(w, `{"error": "Failed to save user info"}`, http.StatusInternalServerError)
		return
	}

	newToken := models.Token{
		UserID:       user.ID,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpirationIn: token.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		Data:         string(dataJSON),
		Provider:     body.Provider,
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": \"Failed to save token\", \"error_msg\": \"\t\"}", err.Error()), http.StatusInternalServerError)
		return
	}

	jwt, _, err := util.GenerateJWT(user.ID, "user")
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.AuthResponse{
		JWTToken:     jwt,
		AccessToken:  savedToken.AccessToken,
		RefreshToken: savedToken.RefreshToken,
		ExpiresAt:    savedToken.ExpiresAt.Unix(),
	})
}

// LogoutHandler
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AccessToken == "" {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.TokenRepository().InvalidateToken(body.AccessToken); err != nil {
		http.Error(w, `{"error": "Failed to logout"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
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
		}, nil
	case models.PROVIDER_FB:
		return providers.ProviderConfig{
			ClientID:     cfg.Facebook.ClientID,
			ClientSecret: cfg.Facebook.ClientSecret,
			TokenURL:     cfg.Facebook.TokenURL,
			UserInfoURL:  cfg.Facebook.UserInfoURL,
		}, nil
	case models.PROVIDER_APPLE:
		return providers.ProviderConfig{
			ClientID:     cfg.Apple.ClientID,
			ClientSecret: cfg.Apple.ClientSecret,
			TokenURL:     cfg.Apple.TokenURL,
			UserInfoURL:  cfg.Apple.UserInfoURL,
		}, nil
	default:
		return providers.ProviderConfig{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}
