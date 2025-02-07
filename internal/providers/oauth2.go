package providers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"math/big"
	"net/http"
	"oauth2-server/internal/models"
	"time"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func GetUserInfo(accessToken string, userInfoURL string, provider string) (map[string]interface{}, error) {
	var req *http.Request
	var err error

	switch provider {
	case models.PROVIDER_FB:
		fullURL := fmt.Sprintf("%s?fields=id,name,email&access_token=%s", userInfoURL, accessToken)
		req, err = http.NewRequest("GET", fullURL, nil)
	case models.PROVIDER_GOOGLE, models.PROVIDER_APPLE:
		req, err = http.NewRequest("GET", userInfoURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
		}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info fetch failed: %s, response: %s", resp.Status, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

// ParseRSAPublicKeyFromJWK извлекает RSA публичный ключ из JWK (JSON Web Key).
func ParseRSAPublicKeyFromJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, errors.New("поле 'n' отсутствует в JWK")
	}
	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, errors.New("поле 'e' отсутствует в JWK")
	}

	// Декодируем значения, представленные в формате base64 URL без отступов.
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования e: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// fetchCerts получает сертификаты (JWK) с указанного URL.
func fetchCerts(url string) ([]map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить сертификаты с %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %v", err)
	}

	var data struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("ошибка парсинга JSON: %v", err)
	}
	return data.Keys, nil
}

// VerifyGoogleIDToken checking Google id_token, using public keys Google, and retrieve claims.
func VerifyGoogleIDToken(idToken string, providerConfig ProviderConfig) (map[string]interface{}, error) {
	certs, err := fetchCerts("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}

	// Parsing token for getting kid.
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed parsing unverified token: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("kid header not found")
	}

	// find kid
	var jwk map[string]interface{}
	for _, key := range certs {
		if key["kid"] == kid {
			jwk = key
			break
		}
	}
	if jwk == nil {
		return nil, errors.New("error fetching jwk")
	}

	pubKey, err := ParseRSAPublicKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed getting public key: %v", err)
	}

	// Get and check token, using public key.
	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("incorrect sign method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed token validation: %v", err)
	}
	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("cannot parse claims")
	}

	// Others checking: audience и expiration.
	if aud, ok := claims["aud"].(string); !ok || aud != providerConfig.ClientID {
		return nil, errors.New("invalid audience")
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// GetFacebookUserInfo получает информацию о пользователе из Facebook, используя access_token и указанный URL API.
func GetFacebookUserInfo(accessToken string, userInfoURL string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %v", err)
	}

	q := req.URL.Query()
	q.Add("access_token", accessToken)
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса к Facebook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Facebook вернул статус: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ошибка декодирования ответа Facebook: %v", err)
	}
	return result, nil
}

// VerifyAppleIdentityToken проверяет Apple identity token, используя публичные ключи Apple, и возвращает claims.
func VerifyAppleIdentityToken(idToken string, providerConfig ProviderConfig) (map[string]interface{}, error) {
	certs, err := fetchCerts("https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, err
	}

	// Разбираем заголовок токена для получения параметра kid.
	token, err := jwt.Parse(idToken, nil)
	if err != nil {
		return nil, fmt.Errorf("error decode token: %v", err)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("kid header not found")
	}

	// Находим соответствующий ключ по kid.
	var jwk map[string]interface{}
	for _, key := range certs {
		if key["kid"] == kid {
			jwk = key
			break
		}
	}
	if jwk == nil {
		return nil, errors.New("error fetching jwk")
	}

	pubKey, err := ParseRSAPublicKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	// Разбираем и проверяем токен.
	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("incorrect sign method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error token validation: %v", err)
	}
	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("cannot parse claims")
	}

	// Other checking: audience и issuer.
	if aud, ok := claims["aud"].(string); !ok || aud != providerConfig.ClientID {
		return nil, errors.New("invalid audience")
	}
	if iss, ok := claims["iss"].(string); !ok || iss != "https://appleid.apple.com" {
		return nil, errors.New("invalid iss")
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return claims, nil
}
