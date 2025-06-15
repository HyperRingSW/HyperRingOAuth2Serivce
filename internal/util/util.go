package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var encryptionKey, _ = base64.StdEncoding.DecodeString("IqXlJzrpPI+M2jICFM7E0VAgHBZuv2J0e5NEvlgsy+Y=")

func UserInfoToJSON(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

func LoadECDSAPrivateKeyFromPEM(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {

		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not of type *ecdsa.PrivateKey")
	}
	return ecKey, nil
}

func GetHash(phrase, input string) string {
	data := fmt.Sprintf("%s_%d", input, time.Now().UnixNano())
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x_%x", phrase, sum)
}

func IsValidEmail(email string) bool {
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

func GetJWT(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		LogInfo(fmt.Sprintf("authorization header format is incorrect: %s", authHeader))
		LogError(errors.New("authorization header format is incorrect"))

		return "", errors.New("authorization header format is incorrect")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	return token, nil
}

func EncryptString(t string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(t))
	nonceSize := aesGCM.NonceSize()
	nonce := hash[:nonceSize]

	cipherText := aesGCM.Seal(nil, nonce, []byte(t), nil)
	final := append(nonce, cipherText...)
	return base64.StdEncoding.EncodeToString(final), nil
}

func DecryptString(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("malformed encrypted data")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
