package authkit

import (
	"time"

	"github.com/markbates/goth"
)

// User is the minimal user representation needed by authkit.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Verified     bool
	ProfileID    string
}

// IsZero reports whether u is the zero value.
func (u User) IsZero() bool { return u.ID == "" }

// Session represents an active auth session.
type Session struct {
	ID     string
	UserID string
}

// IsZero reports whether s is the zero value.
func (s Session) IsZero() bool { return s.ID == "" }

// RefreshToken is the stored refresh token record.
type RefreshToken struct {
	ID        string
	SessionID string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsZero reports whether rt is the zero value.
func (rt RefreshToken) IsZero() bool { return rt.ID == "" }

// OAuthAccount links an OAuth provider identity to a user.
type OAuthAccount struct {
	UserID     string
	Provider   string
	ProviderID string
	Email      string
}

// IsZero reports whether oa is the zero value.
func (oa OAuthAccount) IsZero() bool { return oa.UserID == "" }

// ResetToken uses the selector/verifier pattern for timing-safe validation.
type ResetToken struct {
	UserID       string
	Selector     string
	VerifierHash string
	ExpiresAt    time.Time
}

// IsZero reports whether t is the zero value.
func (t ResetToken) IsZero() bool { return t.UserID == "" }

// OAuthUserInfo holds user data returned by an OAuth provider callback.
type OAuthUserInfo struct {
	Provider    string
	ProviderID  string
	Email       string
	Name        string
	Avatar      string
	AccessToken string
}

// TokenSet is the library's output for successful auth operations.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	Fingerprint  string
}

// ProviderConfig defines an OAuth provider with its trust level.
type ProviderConfig struct {
	Provider goth.Provider
	Trusted  bool
}
