# API Key

## Usage

通过 Payload 生成 API-Token

```go
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
```

解析 API-Token 获取 Payload

```go
payload, err := apiKey.DecryptAPIToken(token)
```
