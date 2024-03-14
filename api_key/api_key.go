package apikey

import (
	"encoding/json"
	"fmt"
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
	value, err = Decrypt(apiKey.SecretKey, ciphertext)
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
	ciphertext, err = Encrypt(apiKey.SecretKey, value)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s", apiKey.AccessKey, ciphertext), nil
}
