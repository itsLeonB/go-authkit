package authgin

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/go-authkit"
	"github.com/itsLeonB/ungerr"
)

var (
	ErrCSRFMissing = errors.New("authkit: missing CSRF token")
	ErrCSRFInvalid = errors.New("authkit: invalid CSRF token")
)

// AuthMiddleware returns a Gin middleware that validates access tokens.
// Accepts any authkit.TokenTransport (CookieTransport, BearerTransport, etc.).
func AuthMiddleware(kit *authkit.AuthKit, transport authkit.TokenTransport, _ authkit.MWRequirements) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := transport.ReadAccessToken(c.Request)
		if err != nil {
			_ = c.Error(ungerr.UnauthorizedError(err.Error()))
			c.Abort()
			return
		}

		fgp, _ := transport.ReadFingerprint(c.Request)

		claims, err := kit.VerifyToken(c.Request.Context(), token, fgp)
		if err != nil {
			_ = c.Error(ungerr.UnauthorizedError(err.Error()))
			c.Abort()
			return
		}

		for k, v := range claims {
			c.Set(k, v)
		}
		c.Next()
	}
}

// CSRFMiddleware validates the double-submit CSRF cookie against the X-CSRF-Token header.
// Safe methods (GET, HEAD, OPTIONS) are skipped.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		csrfCookie, err := c.Cookie(csrfTokenCookie)
		if err != nil || csrfCookie == "" {
			_ = c.Error(ungerr.ForbiddenError(ErrCSRFMissing.Error()))
			c.Abort()
			return
		}

		csrfHeader := c.GetHeader("X-CSRF-Token")
		if csrfHeader == "" || csrfHeader != csrfCookie {
			_ = c.Error(ungerr.ForbiddenError(ErrCSRFInvalid.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}
