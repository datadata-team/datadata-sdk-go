package apikey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	UserID     string     `json:"userId"`
	SecretKey  string     `json:"secretKey"`
	AccessKey  string     `json:"accessKey"`
	Expiration *time.Time `json:"expiration,omitempty"`
}

// 通过 Payload 生成 Token
func (apiKey *APIKey) DecryptAPIToken(token string) (payload *APITokenPayload, err error) {
	var tokenParts = strings.Split(token, ".")
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("invalid api token")
	}
	var ciphertext = tokenParts[1]

	var value []byte
	value, err = apiKey.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	payload = new(APITokenPayload)
	err = json.Unmarshal(value, payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// 解密 Token 并返回 Payload
func (apiKey *APIKey) GenerateAPIToken(payload APITokenPayload) (token string, err error) {
	var value []byte
	value, err = json.Marshal(payload)
	if err != nil {
		return "", err
	}

	var ciphertext string
	ciphertext, err = apiKey.encrypt(value)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s", apiKey.AccessKey, ciphertext), nil
}

func (apiKey *APIKey) encrypt(value []byte) (result string, err error) {
	var hash = md5.New()
	hash.Write([]byte(apiKey.SecretKey))
	var key = hash.Sum(nil)

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	hash.Reset()
	hash.Write(value)
	value = append(value, hash.Sum(nil)...)

	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], value)

	return hex.EncodeToString(ciphertext), nil
}

func (apiKey *APIKey) decrypt(ciphertext string) (result []byte, err error) {
	var cipherData []byte
	cipherData, err = hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	var hash = md5.New()
	hash.Write([]byte(apiKey.SecretKey))
	var key = hash.Sum(nil)

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherData) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	var iv []byte
	iv = cipherData[:aes.BlockSize]
	cipherData = cipherData[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherData, cipherData)

	if len(cipherData) > 16 {
		raw := cipherData[:len(cipherData)-16]
		hash.Reset()
		hash.Write(raw)
		if hmac.Equal(cipherData[len(cipherData)-16:], hash.Sum(nil)) {
			return raw, nil
		}
	}

	return nil, errors.New("decrypt failed")
}
