package apikey_test

import (
	"testing"

	apikey "github.com/datadata-team/datadata-sdk-go/api_key"
)

func Test_APIKey(t *testing.T) {
	var apiKey = &apikey.APIKey{
		Name:      "test",
		AccessKey: "987f9b5d5e4a46799281d5487372425c",
		SecretKey: "1b9c39e77eb1480cb887-ecbcbf557b13",
	}
	token, err := apiKey.GenerateAPIToken(apikey.APITokenPayload{
		UID:     "001",
		Host:    "www.example.com",
		Expired: 1741918889,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := apiKey.DecryptAPIToken(token)
	if err != nil {
		t.Fatal(err)
	}

	if payload.UID != "001" {
		t.Fatalf("Payload UID does not match: %v", payload.UID)
	}
	if payload.Host != "www.example.com" {
		t.Fatalf("Payload Host does not match: %v", payload.Host)
	}
	if payload.Expired != 1741918889 {
		t.Fatalf("Payload Expired does not match: %v", payload.Expired)
	}
}
