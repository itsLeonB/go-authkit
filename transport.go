package authkit

import "net/http"

// TokenTransport abstracts how tokens are sent to/read from clients.
type TokenTransport interface {
	SetTokens(w http.ResponseWriter, access, refresh, fingerprint string)
	ReadAccessToken(r *http.Request) (string, error)
	ReadRefreshToken(r *http.Request) (string, error)
	ReadFingerprint(r *http.Request) (string, error)
	ClearTokens(w http.ResponseWriter)
}
