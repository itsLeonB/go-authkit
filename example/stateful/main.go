// Package main demonstrates a stateful auth flow using go-authkit with Gin.
// Uses in-memory mock stores — no real database needed.
//
// Run: go run ./example/stateful
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/go-authkit"
	"github.com/itsLeonB/go-authkit/authgin"
	"github.com/itsLeonB/go-authkit/authkittest"
)

func main() {
	kit := authkittest.NewKit()
	defer kit.Shutdown()

	transport, err := authgin.NewCookieTransport(authgin.CookieConfig{
		Domain:     "localhost",
		Secure:     false,
		SameSite:   http.SameSiteLaxMode,
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := authgin.NewHandler(kit, transport, authgin.HandlerConfig{})

	r := gin.Default()
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/register", handler.Register())
		auth.POST("/login", handler.Login())
		auth.GET("/verify", handler.VerifyRegistration())
		auth.POST("/password/forgot", handler.SendPasswordReset())
		auth.POST("/password/reset", handler.ResetPassword())
		auth.POST("/refresh", handler.RefreshToken())
	}

	protected := r.Group("/api/v1")
	protected.Use(authgin.AuthMiddleware(kit, transport, authkit.RequireAuth))
	protected.Use(authgin.CSRFMiddleware())
	{
		protected.POST("/auth/logout", handler.Logout())
		protected.GET("/me", func(c *gin.Context) {
			userID, _ := c.Get(authkit.ClaimUserID)
			c.JSON(http.StatusOK, gin.H{"userID": userID})
		})
	}

	log.Println("stateful example listening on :8080")
	log.Fatal(r.Run(":8080"))
}
