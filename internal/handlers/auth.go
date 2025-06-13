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

	"github.com/google/uuid"
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
	response := models.AuthResponse{}
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	jwtToken := ""
	var expiresAt time.Time

	defer func() {
		logs["info"]["response"] = response
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	logs["info"]["handler"] = "AuthUserHandler"
	logs["info"]["provider"] = provider

	body := models.AuthBodyRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		logs["error"]["bodyRequestMsg"] = err.Error()
		logs["error"]["bodyRequest"] = body
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["body"] = body

	// Get provider config (URL user info, client id and etc)
	providerConfig, err := getProviderConfig(provider, h.cfg.Authorization)
	if err != nil {
		logs["error"]["providerConfigMessage"] = fmt.Sprintf("error getting provider config, provider and confing: %s, %w", provider, h.cfg.Authorization)
		logs["error"]["providerConfigError"] = err.Error()
		//w.WriteHeader(http.StatusNotFound)
		return
	}
	logs["info"]["providerConfig"] = providerConfig

	var claims map[string]interface{}

	switch strings.ToLower(provider) {
	case models.PROVIDER_GOOGLE:
		if body.IdToken == "" {
			logs["error"]["idTokenRequired"] = "idToken is required"
			//w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyGoogleIDToken(body.IdToken, providerConfig)
		if err != nil {
			logs["error"]["providerConfigMessage"] = fmt.Sprintf("error getting provider config, provider and confing: %s, %w", provider, providerConfig)
			logs["error"]["VerifyGoogleIDToken"] = err.Error()
			//w.WriteHeader(http.StatusBadRequest)
			return
		}
		logs["info"]["claims"] = claims

		//Checking info on provider
		_, err := providers.GetUserInfo(body.AccessToken, providerConfig.UserInfoURL, provider)
		if err != nil {
			logs["error"]["GetUserInfoParams"] = fmt.Sprintf("body.AccessToken, providerConfig.UserInfoURL, provider: %s, %w, %s, %s", body.AccessToken, providerConfig.UserInfoURL, provider)
			logs["error"]["GetUserInfo"] = err.Error()
			//w.WriteHeader(http.StatusBadRequest)
			return
		}

	case models.PROVIDER_APPLE:
		if body.IdToken == "" {
			logs["error"]["idTokenRequired"] = "idToken is required"
			//w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err = providers.VerifyAppleIdentityToken(body.IdToken, providerConfig)
		if err != nil {
			logs["error"]["VerifyAppleIdentityTokenParams"] = fmt.Sprintf("body.IdToken, providerConfig: %s, %w,", body.IdToken, providerConfig)
			logs["error"]["VerifyAppleIdentityToken"] = err.Error()
			//w.WriteHeader(http.StatusBadRequest)
			return
		}
		logs["info"]["claims"] = claims

	default:
		logs["error"]["providerConfigMessage"] = "provider not supported"
		//w.WriteHeader(http.StatusNotFound)
		return
	}

	// get email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		logs["error"]["emailRequired"] = "email is required"
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	// get user name
	name, _ := claims["name"].(string)

	// Save claims JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		logs["error"]["claimsMarshalMsg"] = err.Error()
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["claimsJSON"] = string(claimsJSON)

	// Create user
	userAuth := models.UserAuth{
		Email:     email,
		Name:      name,
		Data:      string(claimsJSON),
		CreatedAt: time.Now(),
	}
	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		logs["error"]["CreateUserParams"] = fmt.Sprintf("userAuth: %w,", userAuth)
		logs["error"]["CreateUser"] = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["user"] = user

	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		expiresAt = time.Now().Add(time.Hour)
	}

	if h.cfg.App.CustomExpiresTime {
		expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
	}

	if body.DeviceUUID == "" {
		body.DeviceUUID = uuid.New().String()
	}

	access, refresh, err := util.GenerateTokens(user.ID, h.cfg.App.ExpiresTime, h.cfg.App.ExpiresRefreshTime)
	if err != nil {
		logs["error"]["GenerateTokens"] = fmt.Sprintf("error generating tokens: %+d", err)
		logs["error"]["GenerateTokens"] = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if body.RefreshToken == "" {
		body.RefreshToken = refresh
	}
	if body.AccessToken == "" {
		body.AccessToken = access
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

	logs["info"]["newToken"] = newToken

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		logs["error"]["CreateOrUpdateTokenParams"] = fmt.Sprintf("newToken: %w,", newToken)
		logs["error"]["SaveToken"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["savedToken"] = savedToken

	// Generate JWT token
	jwtToken, _, err = util.GenerateJWT(user.ID, provider, expiresAt.Unix(), body.DeviceUUID)
	if err != nil {
		logs["error"]["GenerateJWTParams"] = fmt.Sprintf("user.ID, provider, expiresAt.Unix(), body.DeviceUUID: %s, %s, %w, %s", user.ID, provider, expiresAt.Unix(), body.DeviceUUID)
		logs["error"]["GenerateJWT"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["jwtToken"] = jwtToken

	_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
		JWT:        jwtToken,
		DeviceUUID: body.DeviceUUID,
		Status:     true,
	})
	if err != nil {
		logs["error"]["SaveJwtDevice"] = err.Error()
		return
	}

	response = models.AuthResponse{
		JWTToken:  jwtToken,
		ExpiresAt: expiresAt.Unix(),
	}

	return
}

func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	response := models.AuthResponse{}
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["handler"] = "RefreshTokenHandler"

	defer func() {
		logs["info"]["response"] = response
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	jwtOld, err := util.GetJWT(r)
	if err != nil {
		logs["error"]["GetJWT"] = err.Error()
		return
	}

	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		logs["error"]["userId"] = "invalid user ID in context"
		return
	}
	logs["info"]["userId"] = userID

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		logs["error"]["provider"] = "invalid provider in context"
		return
	}
	logs["info"]["provider"] = provider

	deviceUUID, ok := r.Context().Value("deviceUUID").(string)
	if !ok {
		logs["error"]["deviceUUID"] = "invalid device UUID in context"
		return
	}
	logs["info"]["deviceUUID"] = deviceUUID

	/*	jwtT, err := util.GetJWT(r)
		if err != nil {
			logs["error"]["GetJWT"] = err.Error()
			return
		}*/

	token := h.repo.TokenRepository().UserToken(userID, provider, deviceUUID)
	if token == nil {
		logs["error"]["token"] = "not found"
		return
	}
	logs["info"]["token"] = token

	if token.AccessToken != "" {
		decryptAccess, err := util.Decrypt(token.AccessToken)
		if err != nil {
			logs["error"]["accessTokenError"] = fmt.Sprintf("error decrypting access token: %s", token.AccessToken)
			return
		}
		token.AccessToken = decryptAccess
	}

	if token.RefreshToken != "" {
		decryptRefresh, err := util.Decrypt(token.RefreshToken)
		if err != nil {
			logs["error"]["refreshTokenErrorMessage"] = fmt.Sprintf("error decrypting refresh token: %s", token.RefreshToken)
			logs["error"]["refreshError"] = err.Error()
			return
		}
		token.RefreshToken = decryptRefresh
	}

	if token.IDToken != "" {
		decryptIDToken, err := util.Decrypt(token.IDToken)
		if err != nil {
			logs["error"]["idTokenErrorMessage"] = fmt.Sprintf("error decrypting ID token: %s", token.IDToken)
			logs["error"]["idTokenError"] = err.Error()
			return
		}
		token.IDToken = decryptIDToken
	}

	providerConfig, err := getProviderConfig(token.Provider, h.cfg.Authorization)
	if err != nil {
		logs["error"]["providerConfigMessage"] = fmt.Sprintf("error getting provider config, provider and confing: %s, %w", token.Provider, h.cfg.Authorization)
		logs["error"]["providerConfigError"] = err.Error()
		return
	}
	logs["info"]["providerConfig"] = providerConfig

	data := url.Values{}
	switch token.Provider {
	case models.PROVIDER_APPLE:
		_, err := providers.VerifyAppleIdentityToken(token.IDToken, providerConfig)
		if err != nil {
			logs["error"]["appleIdErrorMessage"] = fmt.Sprintf("error verifying apple: %s", token.IDToken)
			logs["error"]["appleIdError"] = err.Error()
			return
		}

		expiresAt := time.Now().Add(180 * 24 * time.Hour)
		if h.cfg.App.CustomExpiresTime {
			expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
		}

		jwtToken, _, err := util.GenerateJWT(userID, provider, expiresAt.Unix(), deviceUUID)
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error generating jwt: %s", token.IDToken)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtOld)
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error deleting jwt: %s", jwtOld)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}
		_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
			JWT:        jwtToken,
			DeviceUUID: deviceUUID,
			Status:     true,
		})
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error save jwt: %s", jwtOld)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		response = models.AuthResponse{
			JWTToken:  jwtToken,
			ExpiresAt: expiresAt.Unix(),
		}

		return
	case models.WEB_PROVIDER_GOOGLE:
		_, err := providers.VerifyGoogleIDToken(token.IDToken, providerConfig)
		if err != nil {
			logs["error"]["idToken"] = fmt.Sprintf("error verifying web google: %s", token.IDToken)
			logs["error"]["msg"] = err.Error()
			return
		}

		access, refresh, err := util.RefreshCustomTokens(token.RefreshToken, h.cfg.App.ExpiresTime, h.cfg.App.ExpiresRefreshTime)
		if err != nil {
			logs["error"]["refreshTokenErrorMessage"] = fmt.Sprintf("error refreshing custom tokens: %s", token.RefreshToken)
			logs["error"]["refreshCustomError"] = err.Error()
			return
		}

		expiresAt := time.Now().Add(180 * 24 * time.Hour)
		if h.cfg.App.CustomExpiresTime {
			expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
		}

		tokendb := models.Token{
			ID:           token.ID,
			UserID:       token.UserID,
			Provider:     token.Provider,
			AccessToken:  access,
			RefreshToken: refresh,
			ExpirationIn: int(expiresAt.Sub(time.Now()).Seconds()),
			ExpiresAt:    expiresAt,
			UpdatedAt:    time.Now(),
		}
		_, err = h.repo.TokenRepository().UpdateToken(
			tokendb,
			token.Provider,
			deviceUUID,
		)
		if err != nil {
			logs["error"]["tokenErrorParams"] = fmt.Sprintf("token, provider, deviceUUID: %s, %w, %s", tokendb, token.Provider, deviceUUID)
			logs["error"]["tokenError"] = err.Error()
			//w.WriteHeader(http.StatusInternalServerError)
			return
		}

		newJWT, _, err := util.GenerateJWT(token.UserID, provider, expiresAt.Unix(), deviceUUID)
		if err != nil {
			logs["error"]["tokenErrorParams"] = fmt.Sprintf("token.UserID, provider, expiresAt.Unix(), deviceUUID: %s, %w, %s, %s", token.UserID, provider, expiresAt.Unix(), deviceUUID)
			logs["error"]["tokenError"] = err.Error()
			//w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logs["info"]["newJWT"] = newJWT

		err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtOld)
		if err != nil {
			logs["error"]["tokenError"] = fmt.Sprintf("error deleting jwt: %s", token.ID)
			logs["error"]["tokenError"] = err.Error()
			return
		}

		_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
			JWT:        newJWT,
			DeviceUUID: deviceUUID,
			Status:     true,
		})
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error save jwt: %s", jwtOld)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		response = models.AuthResponse{
			JWTToken:  newJWT,
			ExpiresAt: expiresAt.Unix(),
		}

		return

		/*expiresAt := time.Now().Add(180 * 24 * time.Hour)
		if h.cfg.App.CustomExpiresTime {
			expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
		}

		jwtToken, _, err := util.GenerateJWT(userID, provider, expiresAt.Unix(), deviceUUID)
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error generating jwt: %s", token.IDToken)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtOld)
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error deleting jwt: %s", jwtOld)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
			JWT:        jwtToken,
			DeviceUUID: deviceUUID,
			Status:     true,
		})
		if err != nil {
			logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error save jwt: %s", jwtOld)
			logs["error"]["jwtTokenError"] = err.Error()
			return
		}

		response = models.AuthResponse{
			JWTToken:  jwtToken,
			ExpiresAt: expiresAt.Unix(),
		}

		return*/
	case models.PROVIDER_GOOGLE:
		data.Set("client_id", providerConfig.ClientID)
		data.Set("client_secret", "")
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", token.RefreshToken)
	default:
		logs["error"]["provider"] = fmt.Sprintf("invalid provider: %s", token.Provider)
		return
	}

	// Send POST request to refresh token URL
	resp, err := http.PostForm(providerConfig.TokenURL, data)
	if err != nil {
		logs["error"]["tokenErrorParams"] = fmt.Sprintf("providerConfig.TokenURL, data: %s, %s", providerConfig.TokenURL, data)
		logs["error"]["tokenError"] = err.Error()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logs["error"]["tokenErrorMessage"] = fmt.Sprintf("error posting data: %s", data)
		//w.WriteHeader(http.StatusBadRequest)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logs["error"]["bodyErrorMessage"] = fmt.Sprintf("error reading body: %s", data)
		logs["error"]["bodyError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["body"] = string(bodyBytes)

	var bodyResponse map[string]interface{}
	if err = json.Unmarshal(bodyBytes, &bodyResponse); err != nil {
		logs["error"]["bodyErrorMessage"] = fmt.Sprintf("error unmarshalling body: %s", data)
		logs["error"]["bodyError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["bodyResponse"] = bodyResponse

	dataJSON, err := util.UserInfoToJSON(bodyResponse)
	if err != nil {
		logs["error"]["bodyErrorMessage"] = fmt.Sprintf("error unmarshalling body: %s", data)
		logs["error"]["bodyError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["bodyJson"] = dataJSON

	// Decode providers response
	var tokenResponse providers.TokenResponse
	if err = json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		logs["error"]["bodyErrorMessage"] = fmt.Sprintf("error unmarshalling body: %s", data)
		logs["error"]["bodyError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["tokenResponse"] = tokenResponse

	expiresAt := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	if h.cfg.App.CustomExpiresTime {
		expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
	}

	// Update token
	tokendb := models.Token{
		ID:           token.ID,
		UserID:       token.UserID,
		Provider:     token.Provider,
		AccessToken:  tokenResponse.AccessToken,  // new access token
		RefreshToken: tokenResponse.RefreshToken, // new refresh token
		ExpirationIn: tokenResponse.ExpiresIn,
		ExpiresAt:    expiresAt,
		Data:         string(dataJSON),
		UpdatedAt:    time.Now(),
	}
	_, err = h.repo.TokenRepository().UpdateToken(
		tokendb,
		token.Provider,
		deviceUUID,
	)
	if err != nil {
		logs["error"]["tokenErrorParams"] = fmt.Sprintf("token, provider, deviceUUID: %s, %w, %s", tokendb, token.Provider, deviceUUID)
		logs["error"]["tokenError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}

	newJWT, _, err := util.GenerateJWT(token.UserID, provider, expiresAt.Unix(), deviceUUID)
	if err != nil {
		logs["error"]["tokenErrorParams"] = fmt.Sprintf("token.UserID, provider, expiresAt.Unix(), deviceUUID: %s, %w, %s, %s", token.UserID, provider, expiresAt.Unix(), deviceUUID)
		logs["error"]["tokenError"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["newJWT"] = newJWT

	err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtOld)
	if err != nil {
		logs["error"]["tokenError"] = fmt.Sprintf("error deleting jwt: %s", token.ID)
		logs["error"]["tokenError"] = err.Error()
		return
	}

	_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
		JWT:        newJWT,
		DeviceUUID: deviceUUID,
		Status:     true,
	})
	if err != nil {
		logs["error"]["jwtTokenErrorMessage"] = fmt.Sprintf("error save jwt: %s", jwtOld)
		logs["error"]["jwtTokenError"] = err.Error()
		return
	}

	response = models.AuthResponse{
		JWTToken:  newJWT,
		ExpiresAt: expiresAt.Unix(),
	}

	return
}

// LogoutHandler
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	defer func() {
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	logs["info"]["handler"] = "LogoutHandler"
	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		logs["error"]["userId"] = "invalid user ID in context"
		return
	}
	logs["info"]["userId"] = userID

	provider, ok := r.Context().Value("provider").(string)
	if !ok {
		logs["error"]["provider"] = "invalid provider in context"
		return
	}
	logs["info"]["provider"] = provider

	deviceUUID, ok := r.Context().Value("deviceUUID").(string)
	if !ok {
		logs["error"]["deviceUUID"] = "invalid device UUID in context"
		return
	}
	logs["info"]["deviceUUID"] = deviceUUID

	token := h.repo.TokenRepository().UserToken(userID, provider, deviceUUID)
	if token == nil {
		logs["error"]["tokenError"] = "Token not found"
		return
	}
	logs["info"]["token"] = token

	switch provider {
	case models.PROVIDER_APPLE:
		err := h.repo.TokenRepository().InvalidateIdToken(token.IDToken)
		if err != nil {
			logs["error"]["InvalidateIdTokenParams"] = fmt.Sprintf("token.IDToken: %s, %s", token.IDToken)
			logs["error"]["InvalidateIdToken"] = err.Error()
			return
		}

		jwtToken, err := util.GetJWT(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtToken)
		if err != nil {
			logs["error"]["tokenError"] = fmt.Sprintf("error deleting jwt: %s", token.ID)
			logs["error"]["tokenError"] = err.Error()
			return
		}
		return
	case models.PROVIDER_GOOGLE:
	case models.WEB_PROVIDER_GOOGLE:
		//data.Set("token", decryptAccess)
	default:
		logs["error"]["provider"] = fmt.Sprintf("Unsupported provider: %s", provider)
		return
	}

	/*if err := h.repo.TokenRepository().InvalidateAccessToken(token.AccessToken); err != nil {
		logs["error"]["tokenError"] = "invalid access token"
		return
	}*/
	jwtToken, err := util.GetJWT(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtToken)
	if err != nil {
		logs["error"]["tokenError"] = fmt.Sprintf("error deleting jwt: %s", token.ID)
		logs["error"]["tokenError"] = err.Error()
		return
	}

	if err := h.repo.TokenRepository().InvalidateIdToken(token.IDToken); err != nil {
		logs["error"]["tokenError"] = "invalid google id token"
		return
	}

	// Send response
	return
}

func (h *Handler) RemoveHandler(w http.ResponseWriter, r *http.Request) {
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)

	defer func() {
		logs["info"]["handler"] = "RemoveHandler"
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	userID, ok := r.Context().Value("userID").(uint)
	if !ok {
		logs["error"]["userId"] = "invalid user ID in context"
		return
	}
	logs["info"]["userId"] = userID

	if h.cfg.App.DeleteMode == "" {
		h.cfg.App.DeleteMode = config.DeleteModeSoft
	}

	logs["info"]["deleteMode"] = h.cfg.App.DeleteMode

	switch h.cfg.App.DeleteMode {
	case config.DeleteModeSoft:
		err := h.repo.UserRepository().AnonymizeUserData(h.cfg.App.AnonymizePhrase, userID)
		if err != nil {
			logs["error"]["AnonymizePhraseParams"] = fmt.Sprintf("h.cfg.App.AnonymizePhrase, userID: %s, %s", h.cfg.App.AnonymizePhrase, userID)
			logs["error"]["anonymizePhraseError"] = err.Error()
			//w.WriteHeader(http.StatusInternalServerError)
			return
		}

	case config.DeleteModeHard:
		err := h.repo.UserRepository().DeleteUser(userID)
		if err != nil {
			logs["error"]["DeleteUserParams"] = fmt.Sprintf("userID: %s", userID)
			logs["error"]["DeleteUser"] = err.Error()
			//w.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		logs["error"]["deleteMode"] = "Unsupported delete mode"
		//w.WriteHeader(http.StatusBadRequest)
		return
	}

	jwtToken, err := util.GetJWT(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = h.repo.JwtDeviceRepository().DeleteJwtDevice(jwtToken)
	if err != nil {
		logs["error"]["tokenError"] = fmt.Sprintf("error deleting jwt: %s", jwtToken)
		logs["error"]["tokenError"] = err.Error()
		return
	}

	return
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
			RedirectURL:  cfg.Google.RedirectURL,
		}, nil
	case models.WEB_PROVIDER_GOOGLE:
		return providers.ProviderConfig{
			ClientID:     cfg.WebGoogle.ClientID,
			ClientSecret: cfg.WebGoogle.ClientSecret,
			TokenURL:     cfg.WebGoogle.TokenURL,
			UserInfoURL:  cfg.WebGoogle.UserInfoURL,
			RevokeURL:    cfg.WebGoogle.RevokeURL,
			RedirectURL:  cfg.WebGoogle.RedirectURL,
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
			RedirectURL:  cfg.Apple.RedirectURL,
		}, nil
	default:
		return providers.ProviderConfig{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (h *Handler) WebGoogleHandler(w http.ResponseWriter, r *http.Request) {
	response := models.AuthResponse{}
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["handler"] = "WebGoogleHandler"
	var expiresAt time.Time

	defer func() {
		logs["info"]["response"] = response
		util.LogInfoMap(logs)
		if len(logs["error"]) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}()

	body := models.AuthBodyRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		logs["error"]["bodyRequestMsg"] = err.Error()
		logs["error"]["bodyRequest"] = body
		//w.WriteHeader(http.StatusBadRequest)
		return
	}

	deviceUUID := body.DeviceUUID
	if deviceUUID == "" {
		deviceUUID = uuid.New().String()
	}
	logs["info"]["deviceUUID"] = deviceUUID

	logs["info"]["idToken"] = body.IdToken
	provider := models.WEB_PROVIDER_GOOGLE
	// Get provider config (URL user info, client id and etc)
	providerConfig, err := getProviderConfig(provider, h.cfg.Authorization)
	if err != nil {
		logs["error"]["providerConfigMessage"] = fmt.Sprintf("error getting provider config, provider and confing: %s, %s", provider, h.cfg.Authorization)
		logs["error"]["providerConfigError"] = err.Error()
		//w.WriteHeader(http.StatusNotFound)
		return
	}
	logs["info"]["providerConfig"] = providerConfig

	var claims map[string]interface{}

	switch strings.ToLower(provider) {
	case models.WEB_PROVIDER_GOOGLE:
		if body.IdToken == "" {
			logs["error"]["idTokenRequired"] = "idToken is required"
			return
		}
		claims, err = providers.VerifyGoogleIDToken(body.IdToken, providerConfig)
		if err != nil {
			logs["error"]["providerConfigMessage"] = fmt.Sprintf("error getting provider config, provider and confing: %s, %+v", provider, providerConfig)
			logs["error"]["VerifyGoogleIDToken"] = err.Error()
			return
		}
		logs["info"]["claims"] = claims

	default:
		logs["error"]["providerConfigMessage"] = "provider not supported"
		return
	}

	// get email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		logs["error"]["emailRequired"] = "email is required"
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	// get user name
	name, _ := claims["name"].(string)

	// Save claims JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		logs["error"]["claimsMarshalMsg"] = err.Error()
		//w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["claimsJSON"] = string(claimsJSON)

	// Create user
	userAuth := models.UserAuth{
		Email:     email,
		Name:      name,
		Data:      string(claimsJSON),
		CreatedAt: time.Now(),
	}
	user, err := h.repo.UserRepository().CreateOrUpdateUser(userAuth)
	if err != nil {
		logs["error"]["CreateUserParams"] = fmt.Sprintf("userAuth: %w,", userAuth)
		logs["error"]["CreateUser"] = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	logs["info"]["user"] = user

	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		expiresAt = time.Now().Add(time.Hour)
	}

	if h.cfg.App.CustomExpiresTime {
		expiresAt = time.Now().Add(time.Second * time.Duration(h.cfg.App.ExpiresTime))
	}

	access, refresh, err := util.GenerateTokens(user.ID, h.cfg.App.ExpiresTime, h.cfg.App.ExpiresRefreshTime)
	if err != nil {
		logs["error"]["GenerateTokens"] = fmt.Sprintf("error generating tokens: %+d", err)
		logs["error"]["GenerateTokens"] = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if body.RefreshToken == "" {
		body.RefreshToken = refresh
	}
	if body.AccessToken == "" {
		body.AccessToken = access
	}

	// Create token
	//provider = models.PROVIDER_GOOGLE
	newToken := models.Token{
		UserID:       user.ID,
		Provider:     provider,
		DeviceUUID:   deviceUUID,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		IDToken:      body.IdToken,
		ExpirationIn: int(expiresAt.Sub(time.Now()).Seconds()),
		ExpiresAt:    expiresAt,
		Data:         string(claimsJSON),
	}

	logs["info"]["newToken"] = newToken

	savedToken, err := h.repo.TokenRepository().CreateOrUpdateToken(newToken)
	if err != nil {
		logs["error"]["CreateOrUpdateTokenParams"] = fmt.Sprintf("newToken: %w,", newToken)
		logs["error"]["SaveToken"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["savedToken"] = savedToken

	// Generate JWT token
	jwtToken, _, err := util.GenerateJWT(user.ID, provider, expiresAt.Unix(), deviceUUID)
	if err != nil {
		logs["error"]["GenerateJWTParams"] = fmt.Sprintf("user.ID, provider, expiresAt.Unix(), body.DeviceUUID: %s, %s, %w, %s", user.ID, provider, expiresAt.Unix(), deviceUUID)
		logs["error"]["GenerateJWT"] = err.Error()
		//w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs["info"]["jwtToken"] = jwtToken

	_, err = h.repo.JwtDeviceRepository().SaveJwtDevice(&models.JwtDevice{
		JWT:        jwtToken,
		DeviceUUID: body.DeviceUUID,
		Status:     true,
	})
	if err != nil {
		logs["error"]["SaveJwtDevice"] = err.Error()
		return
	}

	response = models.AuthResponse{
		JWTToken:  jwtToken,
		ExpiresAt: expiresAt.Unix(),
	}

	return
}
