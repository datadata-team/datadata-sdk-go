package apikey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	cryptoutils "github.com/datadata-team/datadata-sdk-go/internal/utils/crypto_utils"
)

func Encrypt(key string, value []byte) (result string, err error) {
	var hash = md5.New()

	_, err = hash.Write([]byte(key))
	if err != nil {
		return "", err
	}

	var block cipher.Block
	block, err = aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return "", err
	}

	hash.Reset()
	hash.Write(value)
	value = append(value, hash.Sum(nil)...)
	value, err = cryptoutils.PKCS7Pad(value, aes.BlockSize)
	if err != nil {
		return "", err
	}

	var iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	var stream = cipher.NewCFBEncrypter(block, iv)
	var ciphertext = make([]byte, len(value))
	stream.XORKeyStream(ciphertext, value)

	return hex.EncodeToString(append(iv, ciphertext...)), nil
}

func Decrypt(key string, cryptoText string) (result []byte, err error) {
	var ciphertext []byte
	ciphertext, err = hex.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	var hash = md5.New()
	_, err = hash.Write([]byte(key))
	if err != nil {
		return nil, err
	}

	var block cipher.Block
	block, err = aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	var iv = ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	ciphertext, err = cryptoutils.PKCS7Unpad(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) > 16 {
		raw := ciphertext[:len(ciphertext)-16]
		hash.Reset()
		hash.Write(raw)
		if hmac.Equal(ciphertext[len(ciphertext)-16:], hash.Sum(nil)) {
			return raw, nil
		}
	}

	return nil, errors.New("decrypt failed")
}
