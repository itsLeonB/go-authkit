package authkit

import "time"

// Config holds all configuration needed by the auth library.
type Config struct {
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
}
