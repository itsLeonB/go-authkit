// Package main demonstrates a stateless (Bearer token) auth flow using go-authkit with Gin.
// Uses in-memory mock stores — no real database needed.
//
// Run: go run ./example/stateless
package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/go-authkit"
	"github.com/itsLeonB/go-authkit/authgin"
	"github.com/itsLeonB/go-authkit/authkittest"
)

func main() {
	kit := authkittest.NewKit(authkittest.WithStateless())
	defer kit.Shutdown()

	handler := authgin.NewStatelessHandler(kit)

	r := gin.Default()
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/register", handler.Register())
		auth.POST("/login", handler.Login())
	}

	protected := r.Group("/api/v1")
	protected.Use(bearerAuthMiddleware(kit))
	{
		protected.GET("/me", func(c *gin.Context) {
			userID, _ := c.Get(authkit.ClaimUserID)
			c.JSON(http.StatusOK, gin.H{"userID": userID})
		})
	}

	log.Println("stateless example listening on :8081")
	log.Fatal(r.Run(":8081"))
}

func bearerAuthMiddleware(kit *authkit.AuthKit) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == "" || token == header {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		claims, err := kit.VerifyToken(c.Request.Context(), token, "")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		for k, v := range claims {
			c.Set(k, v)
		}
		c.Next()
	}
}
