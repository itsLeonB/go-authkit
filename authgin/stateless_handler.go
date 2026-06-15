package authgin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/ginkgo/pkg/server"
	"github.com/itsLeonB/go-authkit"
)

// StatelessHandler provides ready-to-use Gin handlers for stateless (Bearer token) auth flows.
type StatelessHandler struct {
	kit *authkit.AuthKit
}

// NewStatelessHandler creates a new stateless auth handler.
func NewStatelessHandler(kit *authkit.AuthKit) *StatelessHandler {
	return &StatelessHandler{kit: kit}
}

// Register handles user registration.
func (h *StatelessHandler) Register() gin.HandlerFunc {
	return server.Handler("StatelessHandler.Register", http.StatusCreated, func(ctx *gin.Context) (any, error) {
		var req struct {
			Email                string `json:"email" binding:"required,email"`
			Password             string `json:"password" binding:"required,eqfield=PasswordConfirmation"`
			PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			return nil, err
		}
		verified, err := h.kit.Register(ctx.Request.Context(), req.Email, req.Password, "")
		if err != nil {
			return nil, err
		}
		return map[string]bool{"verified": verified}, nil
	})
}

// Login handles email/password login, returning a Bearer token in the response body.
func (h *StatelessHandler) Login() gin.HandlerFunc {
	return server.Handler("StatelessHandler.Login", http.StatusOK, func(ctx *gin.Context) (any, error) {
		var req struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			return nil, err
		}
		tokens, err := h.kit.Login(ctx.Request.Context(), req.Email, req.Password)
		if err != nil {
			return nil, err
		}
		return map[string]string{"type": "Bearer", "token": tokens.AccessToken}, nil
	})
}
