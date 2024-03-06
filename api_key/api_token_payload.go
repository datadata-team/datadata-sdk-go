package apikey

type APITokenPayload struct {
	UID     string `json:"uid"`
	Host    string `json:"host"`
	Expired uint64 `json:"expired"`
}
