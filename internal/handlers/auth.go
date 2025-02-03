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
	// Ожидаем, что клиент пришлёт данные авторизации.
	// Для Google и Apple используется id_token (JWT), для Facebook – access_token.
	var body struct {
		Provider     string `json:"provider"`
		IdToken      string `json:"id_token,omitempty"`      // Google, Apple
		AccessToken  string `json:"access_token,omitempty"`  // Facebook, Google
		RefreshToken string `json:"refresh_token,omitempty"` // Google
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Неверное тело запроса"}`, http.StatusBadRequest)
		return
	}

	// Получаем конфигурацию провайдера (например, URL для получения user info, client id и т.п.)
	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var claims map[string]interface{}

	// В зависимости от провайдера используем разные механизмы валидации токена
	switch strings.ToLower(body.Provider) {
	case models.PROVIDER_GOOGLE:
		if body.IdToken == "" {
			http.Error(w, `{"error": "id_token обязателен для Google"}`, http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyGoogleIDToken(body.IdToken, providerConfig)
		if err != nil {
			http.Error(w, `{"error": "Неверный Google id_token"}`, http.StatusUnauthorized)
			return
		}
	case models.PROVIDER_FB:
		if body.AccessToken == "" {
			http.Error(w, `{"error": "access_token обязателен для Facebook"}`, http.StatusBadRequest)
			return
		}
		// Для Facebook вызываем функцию, которая обращается к Graph API (или debug_token) для проверки токена
		claims, err = providers.GetFacebookUserInfo(body.AccessToken, providerConfig.UserInfoURL)
		if err != nil {
			http.Error(w, `{"error": "Неверный Facebook access_token"}`, http.StatusUnauthorized)
			return
		}
	case models.PROVIDER_APPLE:
		if body.IdToken == "" {
			http.Error(w, `{"error": "id_token обязателен для Apple"}`, http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyAppleIdentityToken(body.IdToken, providerConfig)
		if err != nil {
			http.Error(w, `{"error": "Неверный Apple id_token"}`, http.StatusUnauthorized)
			return
		}
	default:
		http.Error(w, `{"error": "Неподдерживаемый провайдер"}`, http.StatusBadRequest)
		return
	}

	// Извлекаем email — он должен присутствовать в claims
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		http.Error(w, `{"error": "Email не найден в данных токена"}`, http.StatusUnauthorized)
		return
	}
	// Имя пользователя может отсутствовать, поэтому используем пустую строку, если нет
	name, _ := claims["name"].(string)

	// Сохраним данные claims в JSON (это опционально, для отладки или хранения дополнительной информации)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, `{"error": "Ошибка сериализации данных токена"}`, http.StatusInternalServerError)
		return
	}

	// Создаем или обновляем пользователя в БД
	userAuth := models.UserAuth{
		Email:     email,
		Name:      name,
		Data:      string(claimsJSON),
		CreatedAt: time.Now(),
	}
	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		http.Error(w, `{"error": "Ошибка сохранения данных пользователя"}`, http.StatusInternalServerError)
		return
	}

	// Определяем время истечения токена.
	// Если в claims есть поле "exp" (timestamp), используем его, иначе выставляем по умолчанию 1 час.
	var expiresAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		expiresAt = time.Now().Add(time.Hour)
	}

	// Формируем запись токена для сохранения в БД.
	// Здесь для Google/Apple мы можем использовать id_token как источник информации, а для Facebook – access_token.
	newToken := models.Token{
		UserID:       user.ID,
		Provider:     body.Provider,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		// Вычисляем оставшееся время жизни токена в секундах
		ExpirationIn: int(expiresAt.Sub(time.Now()).Seconds()),
		ExpiresAt:    expiresAt,
		Data:         string(claimsJSON),
	}

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Ошибка сохранения токена", "error_msg": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Генерируем JWT токен для вашего сервиса
	jwtToken, _, err := util.GenerateJWT(user.ID, "user", expiresAt.Unix())
	if err != nil {
		http.Error(w, `{"error": "Ошибка генерации JWT"}`, http.StatusInternalServerError)
		return
	}

	// Формируем и отправляем ответ клиенту
	response := models.AuthResponse{
		JWTToken:     jwtToken,
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		ExpiresAt:    savedToken.ExpiresAt.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RefreshTokenHandler
func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Missing Authorization header"}`, http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, `{"error": "Invalid Authorization header format. Expected 'Bearer <token>'"}`, http.StatusBadRequest)
		return
	}
	jwtTokenString := parts[1]

	// Парсим JWT-токен и извлекаем user_id.
	claims, err := util.ParseJWT(jwtTokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid parse JWT token"}`, http.StatusUnauthorized)
		return
	}
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		http.Error(w, `{"error": "user_id not found in token claims"}`, http.StatusUnauthorized)
		return
	}
	userID := uint(userIDFloat)

	// Получаем запись токена для данного пользователя.
	token := h.repo.TokenRepository().UserToken(int(userID))
	if token == nil {
		http.Error(w, `{"error": "Token record not found"}`, http.StatusUnauthorized)
		return
	}

	// Если токены хранятся в зашифрованном виде – дешифруем их.
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

	// Получаем конфигурацию провайдера.
	providerConfig, err := getProviderConfig(token.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Формируем параметры запроса для обновления токена.
	data := url.Values{}
	switch token.Provider {
	case models.PROVIDER_FB:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("grant_type", "fb_exchange_token")
		data.Set("fb_exchange_token", token.AccessToken)
	case models.PROVIDER_GOOGLE, models.PROVIDER_APPLE:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", providerConfig.ClientSecret)
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", token.RefreshToken)
		// Дополнительные параметры (если требуются)
		data.Set("prompt", "consent")
		data.Set("access_type", "offline")
	default:
		http.Error(w, `{"error": "Unsupported provider"}`, http.StatusBadRequest)
		return
	}

	// Отправляем POST-запрос на URL обновления токена.
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

	// Декодируем ответ от провайдера.
	var tokenResponse providers.TokenResponse
	if err = json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to decode token response: %v"}`, err), http.StatusBadRequest)
		return
	}

	expiresAt := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	// Обновляем запись токена в БД.
	updatedToken, err := h.repo.TokenRepository().UpdateToken(
		models.Token{
			ID:           token.ID,
			UserID:       token.UserID,
			Provider:     token.Provider,
			AccessToken:  tokenResponse.AccessToken,  // новый access token
			RefreshToken: tokenResponse.RefreshToken, // новый refresh token
			ExpirationIn: tokenResponse.ExpiresIn,
			ExpiresAt:    expiresAt,
			Data:         string(dataJSON), // Дополнительные данные можно не сохранять
			UpdatedAt:    time.Now(),
		},
		token.Provider,
	)
	if err != nil {
		http.Error(w, `{"error": "Failed to update token"}`, http.StatusInternalServerError)
		return
	}

	// Генерируем новый JWT для нашего сервиса.
	newJWT, _, err := util.GenerateJWT(token.UserID, "user", expiresAt.Unix())
	if err != nil {
		http.Error(w, `{"error": "Failed to generate JWT token"}`, http.StatusInternalServerError)
		return
	}

	// Формируем и отправляем минимальный ответ для мобильного SDK.
	response := map[string]interface{}{
		"jwt_token":     newJWT,
		"access_token":  updatedToken.AccessToken,
		"refresh_token": updatedToken.RefreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LogoutHandler
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем заголовок Content-Type
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		UserID   int    `json:"user_id"`
		Provider string `json:"provider"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 || body.Provider == "" {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	token := h.repo.TokenRepository().UserToken(body.UserID)
	if token == nil {
		http.Error(w, `{"error": "Token not found"}`, http.StatusBadRequest)
		return
	}

	providerConfig, err := getProviderConfig(body.Provider, h.cfg.Authorization)
	if err != nil {
		http.Error(w, `{"error": "Invalid provider"}`, http.StatusBadRequest)
		return
	}

	decryptAccess, err := util.Decrypt(token.AccessToken)
	if err != nil {
		http.Error(w, `{"error": "Invalid or expired access token"}`, http.StatusUnauthorized)
		return
	}

	// Формируем данные для запроса ревокации
	data := url.Values{}
	switch body.Provider {
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
		fmt.Printf("Error revoking token: %v\n", err)
		http.Error(w, `{"error": "Failed to revoke token"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		fmt.Printf("Token revocation failed: %s, response: %s\n", resp.Status, string(responseBody))
		http.Error(w, `{"error": "Token revocation failed"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.TokenRepository().InvalidateToken(token.AccessToken); err != nil {
		fmt.Printf("Error invalidating token: %v\n", err)
		http.Error(w, `{"error": "Failed to logout"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем успешный ответ
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

/*
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

	jwt, _, err := util.GenerateJWT(user.ID, "user", newToken.ExpiresAt.Unix())
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

	jwt, _, err := util.GenerateJWT(user.ID, "user", savedToken.ExpiresAt.Unix())
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
*/

/*
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
}*/

// CallbackHandler
/*func (h *Handler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
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

	jwt, _, err := util.GenerateJWT(user.ID, "user", savedToken.ExpiresAt.Unix())
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
*/
