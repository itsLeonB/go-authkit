package authkit

import (
	"crypto/rsa"
	"errors"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// JWTAlgorithm selects the JWT signing algorithm.
type JWTAlgorithm string

const (
	AlgorithmHS256 JWTAlgorithm = "HS256"
	AlgorithmRS256 JWTAlgorithm = "RS256"
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

	// JWTAlgorithm selects the signing algorithm. Default: HS256.
	JWTAlgorithm JWTAlgorithm

	// JWTIssuer is the `iss` claim in issued tokens.
	JWTIssuer string

	// JWTSecret is the HS256 signing key. Required when JWTAlgorithm is HS256.
	JWTSecret string

	// JWTPrivateKey is the RS256 private key. Required when JWTAlgorithm is RS256.
	// The public key is derived from it for verification.
	JWTPrivateKey *rsa.PrivateKey

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

func (c Config) validate() error {
	switch c.JWTAlgorithm {
	case AlgorithmHS256, "":
		if c.JWTSecret == "" {
			return errors.New("authkit: JWTSecret required for HS256")
		}
	case AlgorithmRS256:
		if c.JWTPrivateKey == nil {
			return errors.New("authkit: JWTPrivateKey required for RS256")
		}
	default:
		return errors.New("authkit: unsupported JWTAlgorithm")
	}
	if c.JWTIssuer == "" {
		return errors.New("authkit: JWTIssuer required")
	}
	if c.JWTDuration <= 0 {
		return errors.New("authkit: JWTDuration must be positive")
	}
	return nil
}
