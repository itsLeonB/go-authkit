package authkit

import "errors"

var (
	ErrUserNotFound       = errors.New("authkit: user not found")
	ErrUserExists         = errors.New("authkit: user already exists")
	ErrSessionNotFound    = errors.New("authkit: session not found")
	ErrTokenNotFound      = errors.New("authkit: token not found")
	ErrTokenExpired       = errors.New("authkit: token expired")
	ErrTokenInvalid       = errors.New("authkit: token invalid")
	ErrInvalidCredentials = errors.New("authkit: invalid credentials")
	ErrNotVerified        = errors.New("authkit: user not verified")
	ErrProviderDisabled   = errors.New("authkit: provider disabled")
	ErrTooManyRequests    = errors.New("authkit: too many requests")
)
