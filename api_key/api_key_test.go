package apikey_test

import (
	"strings"
	"testing"
	"time"

	apikey "github.com/datadata-team/datadata-sdk-go/api_key"
	"github.com/google/uuid"
)

func TestGenerateAPIToken(t *testing.T) {
	var apiKey = createFakeAPIKey()
	token, err := apiKey.GenerateAPIToken(apikey.APITokenPayload{
		UID:     "1",
		Host:    "example.com",
		Expired: uint64(time.Now().AddDate(0, 0, 1).Unix()),
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if token == "" {
		t.Error("token is empty")
	}
}

func TestDecryptAPIToken(t *testing.T) {
	var apiKey = createFakeAPIKey()
	token, err := apiKey.GenerateAPIToken(apikey.APITokenPayload{
		UID:     "1",
		Host:    "example.com",
		Expired: uint64(time.Now().AddDate(0, 0, 1).Unix()),
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	payload, err := apiKey.DecryptAPIToken(token)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if payload.UID != "1" {
		t.Errorf(`payload.uid = "%v"; expected: "1"`, payload.UID)
	}
	if payload.Host != "example.com" {
		t.Errorf(`payload.host = "%v"; expected: "example.com"`, payload.Host)
	}
}

func createFakeAPIKey() *apikey.APIKey {
	return &apikey.APIKey{
		Name:      "fake api key",
		AccessKey: generateKey(),
		SecretKey: generateKey(),
	}
}

func generateKey() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}
