package authkit

import (
	"context"
	"time"
)

// Transactor abstracts database transaction management.
type Transactor interface {
	WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// MailService sends verification and password-reset emails.
type MailService interface {
	SendVerification(ctx context.Context, email, name, url string) error
	SendPasswordReset(ctx context.Context, email, name, url string) error
}

// SessionCache provides fast session validation without DB round-trips.
type SessionCache interface {
	Get(sessionID string, loader func(string) (string, bool)) (userID string, hit bool)
	Delete(sessionID string)
	Shutdown() error
}

// StateStore manages short-lived OAuth state tokens.
type StateStore interface {
	Store(ctx context.Context, state, value string, expiry time.Duration) error
	VerifyAndDelete(ctx context.Context, state string) (value string, err error)
}
