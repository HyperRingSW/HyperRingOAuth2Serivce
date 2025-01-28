package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

func getSecretKey() ([]byte, error) {
	key := "12345678901234567890123456789012" // TODO .env os.Getenv("SECRET_KEY") 32 байта для AES-256
	if len(key) != 32 {
		return nil, errors.New("invalid secret key length: must be 32 bytes")
	}
	return []byte(key), nil
}

func Encrypt(plainText string) (string, error) {
	secretKey, err := getSecretKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}
	
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt(encryptedText string) (string, error) {
	secretKey, err := getSecretKey()
	if err != nil {
		return "", err
	}

	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherText) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

/*package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var secretKey = []byte("12345678901234567890123456789012") //TODO to .env

// Encrypt
func Encrypt(plainText string) (string, error) {
	//create AES block
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	//init cipher text
	//use 32 byte
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//generate IV with rand.Reader
	//first 16 byte needed for IV genera
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	//creating cipher stream
	stream := cipher.NewCFBEncrypter(block, iv)
	//crypt by XORKeyStream
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))

	//return base64 string
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt
func Decrypt(encryptedText string) (string, error) {
	//base64 decode
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	//init AES bock
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//decrypting
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
*/
