package authgin

import (
	"errors"
	"net/http"
	"strings"
)

// BearerTransport implements authkit.TokenTransport using Authorization header
// and JSON response bodies. Suitable for mobile/API clients that don't use cookies.
type BearerTransport struct{}

// NewBearerTransport creates a new BearerTransport.
func NewBearerTransport() *BearerTransport {
	return &BearerTransport{}
}

// SetTokens is a no-op for BearerTransport; tokens are returned in JSON response body by the handler.
func (bt *BearerTransport) SetTokens(_ http.ResponseWriter, _, _, _ string) {}

// ReadAccessToken extracts the Bearer token from the Authorization header.
func (bt *BearerTransport) ReadAccessToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimPrefix(auth, "Bearer "), nil
}

// ReadRefreshToken reads the refresh token from the X-Refresh-Token header.
func (bt *BearerTransport) ReadRefreshToken(r *http.Request) (string, error) {
	token := r.Header.Get("X-Refresh-Token")
	if token == "" {
		return "", errors.New("missing refresh token")
	}
	return token, nil
}

// ReadFingerprint returns empty — fingerprinting is disabled for bearer transport.
func (bt *BearerTransport) ReadFingerprint(_ *http.Request) (string, error) {
	return "", nil
}

// ClearTokens is a no-op for BearerTransport; client discards tokens locally.
func (bt *BearerTransport) ClearTokens(_ http.ResponseWriter) {}
