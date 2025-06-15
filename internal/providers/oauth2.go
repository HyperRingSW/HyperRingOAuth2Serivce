package providers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// ParseRSAPublicKeyFromJWK extracts the RSA public key from the JWK (JSON Web Key).
func ParseRSAPublicKeyFromJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, errors.New("jwk n is not a string")
	}
	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, errors.New("jwk e is not a string")
	}

	// Decode values that are encoded in base64 URL format without padding.
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwk e: %w", err)
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

// fetchCerts retrieves certificates (JWK) from the specified URL.
func fetchCerts(url string) ([]map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates %s: %w", url, err)
	}

	var data struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificates %s: %w", url, err)
	}
	return data.Keys, nil
}

// VerifyGoogleIDToken checking Google id_token, using public keys Google, and retrieve claims.
func VerifyGoogleIDToken(idToken string, providerConfig ProviderConfig) (map[string]interface{}, error) {
	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["method"] = "VerifyGoogleIDToken"
	logs["info"]["idToken"] = idToken
	logs["info"]["providerConfig"] = providerConfig

	defer func() {
		util.LogInfoMap(logs)
	}()

	certs, err := fetchCerts("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		logs["error"]["fetchCerts"] = fmt.Sprintf("VerifyGoogleIDToken failed to fetch certs: %s", err.Error())
		return nil, err
	}

	// Parsing token for getting kid.
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		logs["error"]["parseToken"] = fmt.Sprintf("VerifyGoogleIDToken failed to parse token: %s", err.Error())
		return nil, fmt.Errorf("failed parsing unverified token: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		logs["error"]["kid"] = "VerifyGoogleIDToken kid header not found"
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
		logs["error"]["jwk"] = "VerifyGoogleIDToken error fetching google jwk"
		return nil, errors.New("error fetching google jwk")
	}
	logs["info"]["jwk"] = jwk

	pubKey, err := ParseRSAPublicKeyFromJWK(jwk)
	if err != nil {
		logs["error"]["ParseRSAPublicKeyFromJWK"] = fmt.Sprintf("VerifyGoogleIDToken failed getting public key: %s", err.Error())
		return nil, fmt.Errorf("failed getting public key: %v", err)
	}

	// Get and check token, using public key.
	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			logs["error"]["parsedTokenSing"] = fmt.Sprintf("VerifyGoogleIDToken incorrect sign method: %v", token.Header["alg"])
			return nil, fmt.Errorf("incorrect sign method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		logs["error"]["parsedToken"] = fmt.Sprintf("VerifyGoogleIDToken failed token validation: %s", err.Error())
		return nil, fmt.Errorf("failed token validation: %v", err)
	}
	if !parsedToken.Valid {
		logs["error"]["parsedTokenValid"] = fmt.Sprintf("VerifyGoogleIDToken invalid token")
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		logs["error"]["parsedTokenClaims"] = fmt.Sprintf("VerifyGoogleIDToken failed to parse claims")
		return nil, errors.New("cannot parse claims")
	}
	logs["info"]["claims"] = claims

	// Others checking: audience и expiration.
	if aud, ok := claims["aud"].(string); !ok || aud != providerConfig.ClientID {
		if !ok {
			logs["error"]["parsedTokenClaimsAUD"] = fmt.Sprintf("VerifyGoogleIDToken audience header not found")
		}
		if aud != providerConfig.ClientID {
			logs["error"]["parsedTokenClaimsAUD"] = fmt.Sprintf("VerifyGoogleIDToken audience mismatch. Getting aud: %s", aud)
		}
		return nil, errors.New("google invalid audience")
	}

	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().UTC().Unix() {
		logs["info"]["parsedTokenClaimsEXP"] = fmt.Sprintf("VerifyGoogleIDToken expired")
		return nil, errors.New("google token expired")
	}

	return claims, nil
}

// VerifyAppleIdentityToken verifies the Apple identity token using Apple's public keys and returns the claims.
func VerifyAppleIdentityToken(idToken string, providerConfig ProviderConfig) (map[string]interface{}, error) {

	logs := make(map[string]map[string]any)
	logs["info"] = make(map[string]any)
	logs["error"] = make(map[string]any)
	logs["info"]["method"] = "VerifyAppleIdentityToken"
	logs["info"]["idToken"] = idToken
	logs["info"]["providerConfig"] = providerConfig

	defer func() {
		util.LogInfoMap(logs)
	}()

	certs, err := fetchCerts("https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, err
	}
	logs["info"]["certs"] = certs

	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		logs["error"]["parseToken"] = fmt.Sprintf("VerifyAppleIdentityToken failed to parse token: %s", err.Error())
		return nil, fmt.Errorf("failed parsing unverified token: %v", err)
	}
	logs["info"]["token"] = token

	kid, ok := token.Header["kid"].(string)
	if !ok {
		logs["error"]["kid"] = "kid header not found"
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
		logs["error"]["jwk"] = fmt.Sprintf("VerifyAppleIdentityToken failed to find jwk")
		return nil, errors.New("error fetching jwk")
	}
	logs["info"]["jwk"] = jwk

	pubKey, err := ParseRSAPublicKeyFromJWK(jwk)
	if err != nil {
		logs["error"]["parseToken"] = fmt.Sprintf("VerifyAppleIdentityToken failed to parse public key: %s", err.Error())
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	logs["info"]["pubKey"] = pubKey

	// Parse and verify the token.
	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			logs["error"]["parsedTokenSign"] = fmt.Sprintf("VerifyAppleIdentityToken incorrect sign method: %v", token.Header["alg"])
			return nil, fmt.Errorf("incorrect sign method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		logs["error"]["parsedToken"] = fmt.Sprintf("VerifyAppleIdentityToken failed token validation: %s", err.Error())
		return nil, fmt.Errorf("error token validation: %v", err)
	}
	if !parsedToken.Valid {
		logs["error"]["parsedTokenValid"] = fmt.Sprintf("VerifyAppleIdentityToken invalid token")
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		logs["error"]["parsedTokenClaims"] = fmt.Sprintf("VerifyAppleIdentityToken failed to parse claims")
		return nil, errors.New("cannot parse claims")
	}

	if aud, ok := claims["aud"].(string); !ok || aud != providerConfig.ClientID {
		if !ok {
			logs["error"]["parsedTokenAUD"] = fmt.Sprintf("VerifyAppleIdentityToken audience header not found")
		}
		if aud != providerConfig.ClientID {
			logs["error"]["parsedTokenAUD"] = fmt.Sprintf("VerifyAppleIdentityToken audience mismatch. Getting aud: %s", aud)
		}
		return nil, errors.New("apple invalid audience")
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().UTC().Unix() {
		logs["info"]["parsedTokenClaims"] = fmt.Sprintf("VerifyAppleIdentityToken expired")
		return nil, errors.New("apple token expired")
	}

	/*// Other checking: audience и issuer.
	if aud, ok := claims["aud"].(string); !ok || aud != providerConfig.ClientID {
		if !ok {
			logs["error"]["parsedTokenClaims"] = fmt.Sprintf("VerifyAppleIdentityToken audience header not found")
			util.LogInfo("apple audience header not found")
		}
		if aud != providerConfig.ClientID {
			util.LogInfo(fmt.Sprintf("apple audience mismatch: %s", aud))
		}
		return nil, errors.New("invalid audience")
	}*/
	if iss, ok := claims["iss"].(string); !ok || iss != "https://appleid.apple.com" {
		if !ok {
			logs["error"]["parsedTokenIss"] = fmt.Sprintf("VerifyAppleIdentityToken iss header not found")
		}
		if iss != "https://appleid.apple.com" {
			logs["error"]["parsedTokenIss"] = fmt.Sprintf("VerifyAppleIdentityToken iss mismatch. Getting iss: %s", iss)
		}
		return nil, errors.New("invalid iss")
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().UTC().Unix() {
		logs["info"]["parsedTokenClaims"] = fmt.Sprintf("VerifyAppleIdentityToken expired")
		return nil, errors.New("token expired")
	}

	return claims, nil
}

func VerifyAccessToken(idToken string, refreshToken string, provider string, providerConfig ProviderConfig) (map[string]interface{}, error) {
	switch provider {
	case models.WEB_PROVIDER_GOOGLE,
		models.PROVIDER_APPLE:
		result, err := ValidateAccessToken(idToken)
		if err != nil {
			fmt.Println("IF YOU WANT TOO EXPIRED")
			rs, err := ValidateRefreshToken(refreshToken)
			if err != nil {
				fmt.Println("VerifyAccessToken failed to validate refreshToken", err.Error())
				return nil, err
			}

			return rs, nil
		}

		return result, nil
		//case models.PROVIDER_APPLE:
		//return VerifyAppleIdentityToken(idToken, providerConfig)
	}

	return nil, errors.New("invalid provider")
}

var jwtSecret = []byte("86194778010") // вынеси в конфиг при необходимости

func ValidateAccessToken(tokenString string) (map[string]interface{}, error) {
	// Создаём парсер без авто-проверки claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	// Парсим токен
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	// Получаем claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	// Проверка "type"
	if typ, ok := claims["type"].(string); !ok || typ != "access" {
		return nil, fmt.Errorf("invalid token type: %v", claims["type"])
	}

	// Проверка "exp"
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("missing exp in token")
	}

	fmt.Println()
	fmt.Println("ValidateAcccessTokenTimeNow", time.Now().UTC().Unix())
	fmt.Println("ValidateAcccessTokenEXP", int64(exp))

	if int64(exp) < time.Now().UTC().Unix() {
		return nil, errors.New("access token expired")
	}

	// Проверка "sub"
	if _, ok := claims["sub"].(float64); !ok {
		return nil, errors.New("invalid sub in token")
	}

	return claims, nil
}

func ValidateRefreshToken(tokenString string) (map[string]interface{}, error) {
	// Создаём парсер без авто-проверки claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	// Парсим токен
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка метода подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	// Получаем claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	// Проверка "type"
	if typ, ok := claims["type"].(string); !ok || typ != "refresh" {
		return nil, fmt.Errorf("invalid token type: %v", claims["type"])
	}

	// Проверка "exp"
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("missing exp in token")
	}
	if int64(exp) < time.Now().UTC().Unix() {
		return nil, errors.New("refresh token expired")
	}

	// Проверка "sub"
	if _, ok := claims["sub"].(float64); !ok {
		return nil, errors.New("invalid sub in token")
	}

	return claims, nil
}
