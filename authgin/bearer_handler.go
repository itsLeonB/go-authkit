package authgin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/itsLeonB/ginkgo/pkg/server"
	"github.com/itsLeonB/go-authkit"
)

// BearerHandler provides Gin handlers for session-based auth with Bearer token transport.
// Tokens are returned in JSON responses instead of cookies. Suitable for mobile/API clients.
type BearerHandler struct {
	kit       *authkit.AuthKit
	transport *BearerTransport
	cfg       HandlerConfig
}

// NewBearerHandler creates a new bearer auth handler.
func NewBearerHandler(kit *authkit.AuthKit, cfg HandlerConfig) *BearerHandler {
	return &BearerHandler{kit: kit, transport: NewBearerTransport(), cfg: cfg}
}

// tokenResponse is the JSON response for auth endpoints returning tokens.
type tokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func tokenResp(ts authkit.TokenSet) tokenResponse {
	return tokenResponse{AccessToken: ts.AccessToken, RefreshToken: ts.RefreshToken}
}

// Transport returns the underlying BearerTransport for use with middleware.
func (h *BearerHandler) Transport() *BearerTransport {
	return h.transport
}

// Register handles user registration.
func (h *BearerHandler) Register() gin.HandlerFunc {
	return server.Handler("BearerHandler.Register", http.StatusCreated, func(ctx *gin.Context) (any, error) {
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

// Login handles email/password login, returning tokens in JSON body.
func (h *BearerHandler) Login() gin.HandlerFunc {
	return server.Handler("BearerHandler.Login", http.StatusOK, func(ctx *gin.Context) (any, error) {
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

		return tokenResp(tokens), nil
	})
}

// OAuthLogin initiates OAuth login by redirecting to the provider.
func (h *BearerHandler) OAuthLogin() gin.HandlerFunc {
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

// OAuthCallback handles the OAuth provider callback, returning tokens in JSON body.
func (h *BearerHandler) OAuthCallback() gin.HandlerFunc {
	return server.Handler("BearerHandler.OAuthCallback", http.StatusOK, func(ctx *gin.Context) (any, error) {
		provider := ctx.Param("provider")
		tokens, err := h.kit.HandleOAuthCallback(ctx.Request.Context(), provider, ctx.Query("code"), ctx.Query("state"))
		if err != nil {
			return nil, err
		}

		return tokenResp(tokens), nil
	})
}

// VerifyRegistration handles email verification, returning tokens in JSON body.
func (h *BearerHandler) VerifyRegistration() gin.HandlerFunc {
	return server.Handler("BearerHandler.VerifyRegistration", http.StatusOK, func(ctx *gin.Context) (any, error) {
		token := ctx.Query("token")
		tokens, err := h.kit.VerifyRegistration(ctx.Request.Context(), token)
		if err != nil {
			return nil, err
		}

		return tokenResp(tokens), nil
	})
}

// SendPasswordReset sends a password reset email.
func (h *BearerHandler) SendPasswordReset() gin.HandlerFunc {
	return server.Handler("BearerHandler.SendPasswordReset", http.StatusCreated, func(ctx *gin.Context) (any, error) {
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

// ResetPassword handles password reset submission, returning tokens in JSON body.
func (h *BearerHandler) ResetPassword() gin.HandlerFunc {
	return server.Handler("BearerHandler.ResetPassword", http.StatusOK, func(ctx *gin.Context) (any, error) {
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

		return tokenResp(tokens), nil
	})
}

// RefreshToken handles token refresh, reading refresh token from X-Refresh-Token header.
func (h *BearerHandler) RefreshToken() gin.HandlerFunc {
	return server.Handler("BearerHandler.RefreshToken", http.StatusOK, func(ctx *gin.Context) (any, error) {
		refreshToken, err := h.transport.ReadRefreshToken(ctx.Request)
		if err != nil {
			return nil, err
		}

		tokens, err := h.kit.RefreshToken(ctx.Request.Context(), refreshToken)
		if err != nil {
			return nil, err
		}

		return tokenResp(tokens), nil
	})
}

// Logout handles session logout.
func (h *BearerHandler) Logout() gin.HandlerFunc {
	return server.Handler("BearerHandler.Logout", http.StatusNoContent, func(ctx *gin.Context) (any, error) {
		sessionID, _ := ctx.Get(authkit.ClaimSessionID)
		sid, _ := sessionID.(string)
		if sid == "" {
			return nil, authkit.ErrSessionNotFound
		}
		return nil, h.kit.Logout(ctx.Request.Context(), sid)
	})
}
