package authkittest

import (
	"time"

	"github.com/itsLeonB/go-authkit"
)

// Option configures a test AuthKit instance.
type Option func(*authkit.Config, *authkit.Deps)

// WithStateless enables stateless mode.
func WithStateless() Option {
	return func(cfg *authkit.Config, _ *authkit.Deps) {
		cfg.Stateless = true
	}
}

// NewKit creates an AuthKit instance wired with in-memory mock stores.
// Panics on configuration error (intended for tests only).
func NewKit(opts ...Option) *authkit.AuthKit {
	cfg := authkit.Config{
		JWTIssuer:        "authkittest",
		JWTSecret:        "test-secret-that-is-long-enough-for-hs256-signing",
		JWTDuration:      15 * time.Minute,
		RefreshTokenTTL:  24 * time.Hour,
		VerificationURL:  "http://localhost/verify",
		ResetPasswordURL: "http://localhost/reset",
	}
	deps := authkit.Deps{
		Tx:       NewTransactor(),
		Users:    NewUserStore(),
		Sessions: NewSessionStore(),
		Refresh:  NewRefreshTokenStore(),
		Resets:   NewResetTokenStore(),
		OAuth:    NewOAuthAccountStore(),
		Mail:     NewMailService(),
		Cache:    NewSessionCache(),
		State:    NewStateStore(),
	}

	for _, o := range opts {
		o(&cfg, &deps)
	}

	kit, err := authkit.New(cfg, deps, authkit.Hooks{})
	if err != nil {
		panic("authkittest.NewKit: " + err.Error())
	}
	return kit
}
