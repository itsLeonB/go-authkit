package authkit

import (
	"context"
	"time"
)

// Transactor abstracts database transaction management.
// Implementations should propagate the transaction context through ctx.
type Transactor interface {
	WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// MailService sends transactional auth emails.
type MailService interface {
	// SendVerification sends an email verification link to the user.
	SendVerification(ctx context.Context, email, name, url string) error
	// SendPasswordReset sends a password reset link to the user.
	SendPasswordReset(ctx context.Context, email, name, url string) error
}

// SessionCache provides fast session validation without DB round-trips.
// Implementations should be thread-safe.
type SessionCache interface {
	// Get returns the cached userID for a session. If not cached, calls loader
	// to fetch it. Returns ("", false) if the session does not exist.
	Get(sessionID string, loader func(string) (string, bool)) (userID string, hit bool)
	// Delete evicts a session from the cache (used on logout).
	Delete(sessionID string)
	// Shutdown releases resources (e.g., background eviction goroutines).
	Shutdown() error
}

// StateStore manages short-lived OAuth state tokens for CSRF protection.
type StateStore interface {
	// Store saves a state/value pair with a TTL.
	Store(ctx context.Context, state, value string, expiry time.Duration) error
	// VerifyAndDelete atomically retrieves and deletes a state entry.
	VerifyAndDelete(ctx context.Context, state string) (value string, err error)
}
