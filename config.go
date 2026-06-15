package authkit

import (
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Config holds all configuration needed by the auth library.
type Config struct {
	// Stateless disables sessions, refresh tokens, and fingerprinting.
	// Login returns only an access token. VerifyToken only validates JWT.
	Stateless bool

	// RequireFingerprint enables token fingerprinting. Ignored when Stateless is true.
	// nil defaults to true.
	RequireFingerprint *bool

	// VerificationURL is the base URL for email verification links.
	// Leave empty to skip email verification (user is verified on register).
	VerificationURL string

	// ResetPasswordURL is the base URL for password reset links.
	ResetPasswordURL string

	// RefreshTokenTTL is the duration refresh tokens remain valid.
	RefreshTokenTTL time.Duration

	// JWTIssuer is the `iss` claim in issued tokens.
	JWTIssuer string

	// JWTSecret is the HS256 signing key.
	JWTSecret string

	// JWTDuration is the access token TTL.
	JWTDuration time.Duration

	// Tracer is an optional OpenTelemetry tracer. If nil, tracing is disabled.
	Tracer trace.Tracer
}

func (c Config) fingerprintEnabled() bool {
	if c.Stateless {
		return false
	}
	if c.RequireFingerprint == nil {
		return true
	}
	return *c.RequireFingerprint
}
