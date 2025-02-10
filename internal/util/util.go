package util

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
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
