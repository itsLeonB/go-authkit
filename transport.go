package authkit

import "net/http"

// TokenTransport abstracts how auth tokens are delivered to and read from HTTP clients.
// Implementations typically use cookies (CookieTransport) or Bearer headers.
type TokenTransport interface {
	// SetTokens writes the access token, refresh token, and fingerprint to the response.
	SetTokens(w http.ResponseWriter, access, refresh, fingerprint string)
	// ReadAccessToken extracts the access token from the request.
	ReadAccessToken(r *http.Request) (string, error)
	// ReadRefreshToken extracts the refresh token from the request.
	ReadRefreshToken(r *http.Request) (string, error)
	// ReadFingerprint extracts the fingerprint value from the request.
	ReadFingerprint(r *http.Request) (string, error)
	// ClearTokens removes all auth tokens from the response (used on logout).
	ClearTokens(w http.ResponseWriter)
}
