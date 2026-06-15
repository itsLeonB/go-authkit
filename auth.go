package authkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Register creates a new user account. If VerificationURL is configured,
// a verification email is sent and verified=false is returned. Otherwise
// the user is verified immediately.
func (kit *AuthKit) Register(ctx context.Context, email, password, slug string) (verified bool, err error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.Register")
	defer endSpan(span)

	isVerified := kit.cfg.VerificationURL == ""
	err = kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		user, err := kit.users.FindByEmail(ctx, email)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return err
		}
		if !user.IsZero() {
			return ErrUserExists
		}

		hash, err := kit.hash.hash(password)
		if err != nil {
			return err
		}

		newUser, err := kit.users.Create(ctx, email, hash)
		if err != nil {
			return err
		}

		if isVerified {
			name := nameFromEmail(email)
			_, err = kit.users.SetVerified(ctx, newUser.ID, name, "")
			return err
		}

		return kit.sendVerificationMail(ctx, newUser, slug)
	})
	return isVerified, err
}

func (kit *AuthKit) sendVerificationMail(ctx context.Context, user User, slug string) error {
	claims := map[string]any{
		"id":    user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(30 * time.Minute).Unix(),
	}
	if slug != "" {
		claims["slug"] = slug
	}

	token, err := kit.jwt.createToken(claims)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s?token=%s", kit.cfg.VerificationURL, token)
	name := nameFromEmail(user.Email)
	return kit.mail.SendVerification(ctx, user.Email, name, url)
}

// Login authenticates with email/password and returns a token set.
func (kit *AuthKit) Login(ctx context.Context, email, password string) (TokenSet, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.Login")
	defer endSpan(span)

	user, err := kit.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return TokenSet{}, ErrInvalidCredentials
		}
		return TokenSet{}, err
	}
	if !user.Verified {
		return TokenSet{}, ErrInvalidCredentials
	}

	ok, err := kit.hash.verify(user.PasswordHash, password)
	if err != nil {
		return TokenSet{}, err
	}
	if !ok {
		return TokenSet{}, ErrInvalidCredentials
	}

	return kit.createTokenAndSession(ctx, user)
}

// VerifyRegistration verifies a user's email using the registration token.
func (kit *AuthKit) VerifyRegistration(ctx context.Context, token string) (TokenSet, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.VerifyRegistration")
	defer endSpan(span)

	var result TokenSet
	err := kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		claims, err := kit.jwt.verifyToken(token)
		if err != nil {
			return ErrTokenInvalid
		}
		id, _ := claims["id"].(string)
		email, _ := claims["email"].(string)
		exp, _ := claims["exp"].(float64)
		if id == "" || email == "" {
			return ErrTokenInvalid
		}
		if time.Now().Unix() > int64(exp) {
			return ErrTokenExpired
		}

		name := nameFromEmail(email)
		user, err := kit.users.SetVerified(ctx, id, name, "")
		if err != nil {
			return err
		}

		if err := kit.hooks.callAfterEmailVerified(ctx, user.ID, user.ProfileID, claims); err != nil {
			return err
		}

		result, err = kit.createTokenAndSession(ctx, user)
		return err
	})
	return result, err
}

// SendPasswordReset sends a password reset email. Returns nil even if
// the user is not found (prevents email enumeration).
func (kit *AuthKit) SendPasswordReset(ctx context.Context, email string) error {
	ctx, span := kit.startSpan(ctx, "AuthKit.SendPasswordReset")
	defer endSpan(span)

	return kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		user, err := kit.users.FindByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				return nil
			}
			return err
		}
		if !user.Verified {
			return nil
		}

		selector, err := generateRandomHex()
		if err != nil {
			return err
		}
		verifier, err := generateRandomHex()
		if err != nil {
			return err
		}
		verifierHash := hashSHA256(verifier)
		expiresAt := time.Now().Add(1 * time.Hour)

		if err := kit.resets.Create(ctx, user.ID, selector, verifierHash, expiresAt); err != nil {
			return err
		}

		return kit.sendResetPasswordMail(ctx, user, selector, verifier)
	})
}

func (kit *AuthKit) sendResetPasswordMail(ctx context.Context, user User, selector, verifier string) error {
	claims := map[string]any{
		"id":       user.ID,
		"email":    user.Email,
		"selector": selector,
		"verifier": verifier,
	}

	token, err := kit.jwt.createToken(claims)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s?token=%s", kit.cfg.ResetPasswordURL, token)
	name := nameFromEmail(user.Email)
	return kit.mail.SendPasswordReset(ctx, user.Email, name, url)
}

// ResetPassword validates the reset token and sets a new password.
func (kit *AuthKit) ResetPassword(ctx context.Context, token, newPassword string) (TokenSet, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.ResetPassword")
	defer endSpan(span)

	var result TokenSet
	err := kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		claims, err := kit.jwt.verifyToken(token)
		if err != nil {
			return ErrTokenInvalid
		}
		id, _ := claims["id"].(string)
		email, _ := claims["email"].(string)
		selector, _ := claims["selector"].(string)
		verifier, _ := claims["verifier"].(string)
		if id == "" || email == "" || selector == "" || verifier == "" {
			return ErrTokenInvalid
		}

		resetToken, err := kit.resets.FindBySelector(ctx, selector)
		if err != nil {
			if errors.Is(err, ErrTokenNotFound) {
				return ErrTokenInvalid
			}
			return err
		}
		if resetToken.ExpiresAt.Before(time.Now()) {
			return ErrTokenExpired
		}

		verifierHash := hashSHA256(verifier)
		if subtle.ConstantTimeCompare([]byte(resetToken.VerifierHash), []byte(verifierHash)) != 1 {
			return ErrTokenInvalid
		}

		hashedPassword, err := kit.hash.hash(newPassword)
		if err != nil {
			return err
		}

		if err := kit.users.UpdatePassword(ctx, id, hashedPassword); err != nil {
			return err
		}

		if err := kit.resets.DeleteByUser(ctx, id); err != nil {
			return err
		}

		user := User{ID: id, Email: email}
		result, err = kit.createTokenAndSession(ctx, user)
		return err
	})
	return result, err
}

// Logout revokes the current session and all its refresh tokens.
func (kit *AuthKit) Logout(ctx context.Context, sessionID string) error {
	ctx, span := kit.startSpan(ctx, "AuthKit.Logout")
	defer endSpan(span)

	// Non-blocking hook — errors are logged by caller.
	_ = kit.hooks.callBeforeLogout(ctx, sessionID)

	kit.cache.Delete(sessionID)
	return kit.revokeSession(ctx, sessionID)
}

// --- helpers ---

func generateRandomHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
