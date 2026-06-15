package authgin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/ginkgo/pkg/server"
	"github.com/itsLeonB/go-authkit"
)

// CaptchaVerifier is an optional interface for CAPTCHA validation.
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string) error
}

// RateLimiter is an optional interface for per-value rate limiting.
type RateLimiter interface {
	Allow(key string) bool
}

// HandlerConfig holds optional handler dependencies.
type HandlerConfig struct {
	Captcha CaptchaVerifier
	Limiter RateLimiter
}

// Handler provides ready-to-use Gin handler functions for auth routes.
type Handler struct {
	kit       *authkit.AuthKit
	transport *CookieTransport
	cfg       HandlerConfig
}

// NewHandler creates a new auth handler.
func NewHandler(kit *authkit.AuthKit, transport *CookieTransport, cfg HandlerConfig) *Handler {
	return &Handler{kit: kit, transport: transport, cfg: cfg}
}

func (h *Handler) setTokenCookies(ctx *gin.Context, tokens authkit.TokenSet) string {
	h.transport.SetTokens(ctx.Writer, tokens.AccessToken, tokens.RefreshToken, tokens.Fingerprint)
	return h.setCSRFCookie(ctx)
}

func (h *Handler) setCSRFCookie(ctx *gin.Context) string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	token := hex.EncodeToString(b)
	h.transport.SetCSRFCookie(ctx.Writer, token)
	return token
}

// Register handles user registration.
func (h *Handler) Register() gin.HandlerFunc {
	return server.Handler("AuthHandler.Register", http.StatusCreated, func(ctx *gin.Context) (any, error) {
		var req struct {
			Email                string `json:"email" binding:"required,email"`
			Password             string `json:"password" binding:"required,eqfield=PasswordConfirmation"`
			PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
			Slug                 string `json:"slug"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			return nil, err
		}

		verified, err := h.kit.Register(ctx.Request.Context(), req.Email, req.Password, req.Slug)
		if err != nil {
			return nil, err
		}

		msg := "check your email to confirm your registration"
		if verified {
			msg = "success registering, please login"
		}
		return map[string]string{"message": msg}, nil
	})
}

// Login handles email/password login.
func (h *Handler) Login() gin.HandlerFunc {
	return server.Handler("AuthHandler.Login", http.StatusOK, func(ctx *gin.Context) (any, error) {
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

		csrf := h.setTokenCookies(ctx, tokens)
		return map[string]string{"message": "ok", "csrfToken": csrf}, nil
	})
}

// OAuthLogin initiates OAuth login by redirecting to the provider.
func (h *Handler) OAuthLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		provider := ctx.Param("provider")
		url, err := h.kit.GetOAuthURL(ctx.Request.Context(), provider)
		if err != nil {
			_ = ctx.Error(err)
			return
		}
		ctx.Redirect(http.StatusTemporaryRedirect, url)
	}
}

// OAuthCallback handles the OAuth provider callback.
func (h *Handler) OAuthCallback() gin.HandlerFunc {
	return server.Handler("AuthHandler.OAuthCallback", http.StatusOK, func(ctx *gin.Context) (any, error) {
		provider := ctx.Param("provider")
		tokens, err := h.kit.HandleOAuthCallback(ctx.Request.Context(), provider, ctx.Query("code"), ctx.Query("state"))
		if err != nil {
			return nil, err
		}

		csrf := h.setTokenCookies(ctx, tokens)
		return map[string]string{"message": "ok", "csrfToken": csrf}, nil
	})
}

// VerifyRegistration handles email verification.
func (h *Handler) VerifyRegistration() gin.HandlerFunc {
	return server.Handler("AuthHandler.VerifyRegistration", http.StatusOK, func(ctx *gin.Context) (any, error) {
		token := ctx.Query("token")
		tokens, err := h.kit.VerifyRegistration(ctx.Request.Context(), token)
		if err != nil {
			return nil, err
		}

		csrf := h.setTokenCookies(ctx, tokens)
		return map[string]string{"message": "ok", "csrfToken": csrf}, nil
	})
}

// SendPasswordReset sends a password reset email.
func (h *Handler) SendPasswordReset() gin.HandlerFunc {
	return server.Handler("AuthHandler.SendPasswordReset", http.StatusCreated, func(ctx *gin.Context) (any, error) {
		var req struct {
			Email        string `json:"email" binding:"required,email"`
			CaptchaToken string `json:"captchaToken"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			return nil, err
		}

		if h.cfg.Limiter != nil && !h.cfg.Limiter.Allow(req.Email) {
			return nil, authkit.ErrTooManyRequests
		}
		if h.cfg.Captcha != nil {
			if err := h.cfg.Captcha.Verify(ctx.Request.Context(), req.CaptchaToken); err != nil {
				return nil, err
			}
		}

		return nil, h.kit.SendPasswordReset(ctx.Request.Context(), req.Email)
	})
}

// ResetPassword handles password reset submission.
func (h *Handler) ResetPassword() gin.HandlerFunc {
	return server.Handler("AuthHandler.ResetPassword", http.StatusOK, func(ctx *gin.Context) (any, error) {
		var req struct {
			Token                string `json:"token" binding:"required"`
			Password             string `json:"password" binding:"required,eqfield=PasswordConfirmation"`
			PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
		}
		if err := ctx.ShouldBindJSON(&req); err != nil {
			return nil, err
		}

		tokens, err := h.kit.ResetPassword(ctx.Request.Context(), req.Token, req.Password)
		if err != nil {
			return nil, err
		}

		csrf := h.setTokenCookies(ctx, tokens)
		return map[string]string{"message": "ok", "csrfToken": csrf}, nil
	})
}

// RefreshToken handles token refresh.
func (h *Handler) RefreshToken() gin.HandlerFunc {
	return server.Handler("AuthHandler.RefreshToken", http.StatusOK, func(ctx *gin.Context) (any, error) {
		refreshToken, err := h.transport.ReadRefreshToken(ctx.Request)
		if err != nil {
			return nil, err
		}

		tokens, err := h.kit.RefreshToken(ctx.Request.Context(), refreshToken)
		if err != nil {
			return nil, err
		}

		csrf := h.setTokenCookies(ctx, tokens)
		return map[string]string{"message": "ok", "csrfToken": csrf}, nil
	})
}

// Logout handles session logout.
func (h *Handler) Logout() gin.HandlerFunc {
	return server.Handler("AuthHandler.Logout", http.StatusNoContent, func(ctx *gin.Context) (any, error) {
		sessionID, _ := ctx.Get(authkit.ClaimSessionID)
		sid, _ := sessionID.(string)
		if sid == "" {
			return nil, authkit.ErrSessionNotFound
		}
		if err := h.kit.Logout(ctx.Request.Context(), sid); err != nil {
			return nil, err
		}
		h.transport.ClearTokens(ctx.Writer)
		return nil, nil
	})
}
