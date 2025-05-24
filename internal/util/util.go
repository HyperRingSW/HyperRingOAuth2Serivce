package util

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"time"
)

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
