package authgin

import (
	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/go-authkit"
)

// AuthMiddleware returns a Gin middleware that validates access tokens.
func AuthMiddleware(kit *authkit.AuthKit, transport *CookieTransport, _ authkit.MWRequirements) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := transport.ReadAccessToken(c.Request)
		if err != nil {
			_ = c.Error(err)
			c.Abort()
			return
		}

		fgp, _ := transport.ReadFingerprint(c.Request)

		claims, err := kit.VerifyToken(c.Request.Context(), token, fgp)
		if err != nil {
			_ = c.Error(err)
			c.Abort()
			return
		}

		for k, v := range claims {
			c.Set(k, v)
		}
		c.Next()
	}
}
