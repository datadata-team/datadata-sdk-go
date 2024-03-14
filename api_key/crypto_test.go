package apikey_test

import (
	"encoding/json"
	"testing"

	apikey "github.com/datadata-team/datadata-sdk-go/api_key"
)

func Test_Crypto(t *testing.T) {
	var key = "500c33c5485e4d7eb5c89dd8f33084dc"
	var data = `{ "uid": "001", "host": "www.example.com", "expired": 1741918889 }`

	result, err := apikey.Encrypt(key, []byte(data))
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	decrypted, err := apikey.Decrypt(key, result)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if data != string(decrypted) {
		t.Errorf("Decrypted data does not match: %v", string(decrypted))
		t.Fail()
	}
}

func Test_CryptoDecrypt(t *testing.T) {
	var key = "500c33c5485e4d7eb5c89dd8f33084dc"
	var token = "1aef5a2a464463f3111968a24fe7263a73eb18382e883fa9e72c7e419db9d04b962c4fb2eab794dcbe11c48e3bf981e543d04cd2b39ff2ad14906b9e0b16ab94c4e78bde3a7e671cb3079c6e046cd9145029cdc35de2524bbc654f53c3742cb63c35b77643593daf2c353becc884d07d"
	var data = `{ "uid": "001", "host": "www.example.com", "expired": 1741918889 }`

	decrypted, err := apikey.Decrypt(key, token)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if data != string(decrypted) {
		t.Error("Decrypted data does not match")
		t.Fail()
	}
}

func Test_CryptoDecryptJSON(t *testing.T) {
	var key = "500c33c5485e4d7eb5c89dd8f33084dc"
	var token = "cd46ec08a408b2714520970c859afbeaed9a9f9bd1c65181723bf4b11d1685010535777a6f6be0dda1812cc1832ca2f6c0f1f8106762fc666ab97faf03ad41df866cf07b07fd2d20453ed4fefa3ad477"

	decrypted, err := apikey.Decrypt(key, token)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	var value apikey.APITokenPayload
	err = json.Unmarshal(decrypted, &value)
	if err != nil {
		t.Fatal(err)
	}

	if value.UID != "007" {
		t.Fatalf("Payload UID does not match: %v", value.UID)
	}
}

func Test_CryptoDecryptJavascript(t *testing.T) {
	var key = "500c33c5485e4d7eb5c89dd8f33084dc"
	var encrypted = "5d4b6fca80e74550ff2f4c814f10d79f0b38534742dcea4827f7e5c7a01510a8a66cd790e7c747801b00e95d3bfe3e79aa4bbbda5a7ce78c73d422ab489bc094cc4eaf5ab09d6460001366cec7ff563fac6a711ccc2eda93b5061a56a863875ea745a35a314efba54947d7cc57974cd0"

	decrypted, err := apikey.Decrypt(key, encrypted)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	var value apikey.APITokenPayload
	err = json.Unmarshal(decrypted, &value)
	if err != nil {
		t.Fatal(err)
	}

	if value.UID != "001" {
		t.Fatalf("Payload UID does not match: %v", value.UID)
	}
	if value.Host != "www.example.com" {
		t.Fatalf("Payload Host does not match: %v", value.Host)
	}
	if value.Expired != 1741918889 {
		t.Fatalf("Payload Expired does not match: %v", value.Expired)
	}
}
