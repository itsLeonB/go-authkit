package authgin

import (
	"errors"
	"net/http"
	"time"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
	csrfTokenCookie    = "csrf_token"
	fingerprintCookie  = "__Secure-Fgp"
)

// CookieConfig holds cookie parameters.
type CookieConfig struct {
	Domain     string
	Secure     bool
	SameSite   http.SameSite
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// CookieTransport implements authkit.TokenTransport using HTTP cookies.
type CookieTransport struct {
	cfg CookieConfig
}

// NewCookieTransport creates a new CookieTransport.
func NewCookieTransport(cfg CookieConfig) *CookieTransport {
	return &CookieTransport{cfg: cfg}
}

func (ct *CookieTransport) SetTokens(w http.ResponseWriter, access, refresh, fingerprint string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     accessTokenCookie,
		Value:    access,
		Path:     "/api",
		Domain:   ct.cfg.Domain,
		MaxAge:   int(ct.cfg.AccessTTL.Seconds()),
		HttpOnly: true,
		Secure:   ct.cfg.Secure,
		SameSite: ct.cfg.SameSite,
	})
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     refreshTokenCookie,
		Value:    refresh,
		Path:     "/api/v1/auth",
		Domain:   ct.cfg.Domain,
		MaxAge:   int(ct.cfg.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   ct.cfg.Secure,
		SameSite: ct.cfg.SameSite,
	})
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     fingerprintCookie,
		Value:    fingerprint,
		Path:     "/api",
		Domain:   ct.cfg.Domain,
		MaxAge:   int(ct.cfg.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: ct.cfg.SameSite,
	})
}

func (ct *CookieTransport) ReadAccessToken(r *http.Request) (string, error) {
	c, err := r.Cookie(accessTokenCookie)
	if err != nil {
		return "", errors.New("missing access token")
	}
	return c.Value, nil
}

func (ct *CookieTransport) ReadRefreshToken(r *http.Request) (string, error) {
	c, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		return "", errors.New("missing refresh token")
	}
	return c.Value, nil
}

func (ct *CookieTransport) ReadFingerprint(r *http.Request) (string, error) {
	c, err := r.Cookie(fingerprintCookie)
	if errors.Is(err, http.ErrNoCookie) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func (ct *CookieTransport) ClearTokens(w http.ResponseWriter) {
	for _, cookie := range []http.Cookie{
		{Name: accessTokenCookie, Path: "/api", MaxAge: -1, Domain: ct.cfg.Domain, HttpOnly: true, Secure: ct.cfg.Secure, SameSite: ct.cfg.SameSite},
		{Name: refreshTokenCookie, Path: "/api/v1/auth", MaxAge: -1, Domain: ct.cfg.Domain, HttpOnly: true, Secure: ct.cfg.Secure, SameSite: ct.cfg.SameSite},
		{Name: csrfTokenCookie, Path: "/api", MaxAge: -1, Domain: ct.cfg.Domain, HttpOnly: false, Secure: ct.cfg.Secure, SameSite: ct.cfg.SameSite},
		{Name: fingerprintCookie, Path: "/api", MaxAge: -1, Domain: ct.cfg.Domain, HttpOnly: true, Secure: true, SameSite: ct.cfg.SameSite},
	} {
		http.SetCookie(w, &cookie) //nolint:gosec
	}
}

// SetCSRFCookie writes a CSRF token cookie.
func (ct *CookieTransport) SetCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     csrfTokenCookie,
		Value:    token,
		Path:     "/api",
		Domain:   ct.cfg.Domain,
		MaxAge:   int(ct.cfg.AccessTTL.Seconds()),
		HttpOnly: false,
		Secure:   ct.cfg.Secure,
		SameSite: ct.cfg.SameSite,
	})
}
