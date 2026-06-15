package authkit

import (
	"context"
	"time"
)

// UserStore handles user persistence for auth operations.
type UserStore interface {
	// FindByID retrieves a user by their unique identifier.
	FindByID(ctx context.Context, userID string) (User, error)
	// FindByEmail retrieves a user by email address.
	FindByEmail(ctx context.Context, email string) (User, error)
	// Create creates a new user with email/password credentials.
	Create(ctx context.Context, email, passwordHash string) (User, error)
	// CreateOAuth creates a new user from an OAuth login (no password).
	CreateOAuth(ctx context.Context, email, name, avatar string) (User, error)
	// SetVerified marks a user as email-verified and updates profile info.
	SetVerified(ctx context.Context, userID string, name, avatar string) (User, error)
	// UpdatePassword replaces the user's password hash.
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	// Exists returns nil if the user exists, ErrUserNotFound otherwise.
	Exists(ctx context.Context, userID string) error
}

// SessionStore handles session persistence.
type SessionStore interface {
	// Create starts a new session for the given user.
	Create(ctx context.Context, userID string) (Session, error)
	// GetByID retrieves a session by ID.
	GetByID(ctx context.Context, id string) (Session, error)
	// Delete removes a session.
	Delete(ctx context.Context, id string) error
	// Touch updates the session's last-activity timestamp.
	Touch(ctx context.Context, id string) error
}

// RefreshTokenStore handles refresh token persistence.
type RefreshTokenStore interface {
	// Create stores a new hashed refresh token.
	Create(ctx context.Context, sessionID, tokenHash string, expiresAt time.Time) error
	// FindByHash looks up a refresh token by its SHA-256 hash.
	FindByHash(ctx context.Context, hash string) (RefreshToken, error)
	// Delete removes a specific refresh token.
	Delete(ctx context.Context, sessionID string, tokenHash string) error
	// DeleteBySession removes all refresh tokens for a session.
	DeleteBySession(ctx context.Context, sessionID string) error
}

// OAuthAccountStore handles OAuth account linking.
type OAuthAccountStore interface {
	// FindByProvider looks up an OAuth link by provider and provider user ID.
	FindByProvider(ctx context.Context, provider, providerID string) (OAuthAccount, error)
	// Link creates an association between a user and an OAuth identity.
	Link(ctx context.Context, userID, provider, providerID, email string) error
}

// ResetTokenStore handles password reset tokens using the selector/verifier pattern.
type ResetTokenStore interface {
	// Create stores a new reset token with selector and hashed verifier.
	Create(ctx context.Context, userID, selector, verifierHash string, expiresAt time.Time) error
	// FindBySelector retrieves a reset token by its selector.
	FindBySelector(ctx context.Context, selector string) (ResetToken, error)
	// DeleteByUser removes all reset tokens for a user (after successful reset).
	DeleteByUser(ctx context.Context, userID string) error
}
