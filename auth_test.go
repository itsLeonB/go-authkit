package authkit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister_Success_WithVerification(t *testing.T) {
	kit := newTestKit()
	mail := kit.mail.(*mockMailService)

	verified, err := kit.Register(context.Background(), "user@test.com", "password123", "")
	require.NoError(t, err)
	assert.False(t, verified)
	assert.Equal(t, 1, mail.verificationsSent)
}

func TestRegister_Success_NoVerificationURL(t *testing.T) {
	kit := newTestKit(func(k *AuthKit) {
		k.cfg.VerificationURL = ""
	})
	mail := kit.mail.(*mockMailService)

	verified, err := kit.Register(context.Background(), "user@test.com", "password123", "")
	require.NoError(t, err)
	assert.True(t, verified)
	assert.Equal(t, 0, mail.verificationsSent)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com"})

	_, err := kit.Register(context.Background(), "user@test.com", "password123", "")
	assert.ErrorIs(t, err, ErrUserExists)
}

func TestLogin_Success(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("password123")
	users.addUser(User{ID: "1", Email: "user@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "user@test.com", "password123")
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.NotEmpty(t, tokens.Fingerprint)
}

func TestLogin_WrongPassword(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("password123")
	users.addUser(User{ID: "1", Email: "user@test.com", PasswordHash: hash, Verified: true})

	_, err := kit.Login(context.Background(), "user@test.com", "wrongpassword")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestLogin_UserNotFound(t *testing.T) {
	kit := newTestKit()

	_, err := kit.Login(context.Background(), "nonexist@test.com", "password123")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestLogin_NotVerified(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("password123")
	users.addUser(User{ID: "1", Email: "user@test.com", PasswordHash: hash, Verified: false})

	_, err := kit.Login(context.Background(), "user@test.com", "password123")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestVerifyRegistration_Success(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com"})

	hookCalled := false
	kit.hooks.AfterEmailVerified = func(_ context.Context, uid, pid string, _ map[string]any) error {
		hookCalled = true
		assert.Equal(t, "1", uid)
		return nil
	}

	// Create a verification token
	token, err := kit.jwt.createToken(map[string]any{
		"id":    "1",
		"email": "user@test.com",
		"exp":   float64(9999999999),
	})
	require.NoError(t, err)

	tokens, err := kit.VerifyRegistration(context.Background(), token)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.True(t, hookCalled)
}

func TestVerifyRegistration_ExpiredToken(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com"})

	token, _ := kit.jwt.createToken(map[string]any{
		"id":    "1",
		"email": "user@test.com",
		"exp":   float64(1), // expired
	})

	_, err := kit.VerifyRegistration(context.Background(), token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestSendPasswordReset_UserNotFound(t *testing.T) {
	kit := newTestKit()
	mail := kit.mail.(*mockMailService)

	err := kit.SendPasswordReset(context.Background(), "nobody@test.com")
	require.NoError(t, err)
	assert.Equal(t, 0, mail.passwordResetsSent)
}

func TestSendPasswordReset_Success(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com", Verified: true})
	mail := kit.mail.(*mockMailService)

	err := kit.SendPasswordReset(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Equal(t, 1, mail.passwordResetsSent)
}

func TestResetPassword_Success(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com", Verified: true})
	resets := kit.resets.(*mockResetTokenStore)

	selector := "sel123"
	verifier := "ver456"
	resets.tokens[selector] = ResetToken{
		UserID:       "1",
		Selector:     selector,
		VerifierHash: hashSHA256(verifier),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	token, _ := kit.jwt.createToken(map[string]any{
		"id":       "1",
		"email":    "user@test.com",
		"selector": selector,
		"verifier": verifier,
	})

	tokens, err := kit.ResetPassword(context.Background(), token, "newpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com", Verified: true})
	resets := kit.resets.(*mockResetTokenStore)

	selector := "sel123"
	verifier := "ver456"
	resets.tokens[selector] = ResetToken{
		UserID:       "1",
		Selector:     selector,
		VerifierHash: hashSHA256(verifier),
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
	}

	token, _ := kit.jwt.createToken(map[string]any{
		"id":       "1",
		"email":    "user@test.com",
		"selector": selector,
		"verifier": verifier,
	})

	_, err := kit.ResetPassword(context.Background(), token, "newpassword")
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestResetPassword_InvalidVerifier(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "1", Email: "user@test.com", Verified: true})
	resets := kit.resets.(*mockResetTokenStore)

	selector := "sel123"
	resets.tokens[selector] = ResetToken{
		UserID:       "1",
		Selector:     selector,
		VerifierHash: hashSHA256("correct-verifier"),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	token, _ := kit.jwt.createToken(map[string]any{
		"id":       "1",
		"email":    "user@test.com",
		"selector": selector,
		"verifier": "wrong-verifier",
	})

	_, err := kit.ResetPassword(context.Background(), token, "newpassword")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestLogout_Success(t *testing.T) {
	kit := newTestKit()
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}

	err := kit.Logout(context.Background(), "s1")
	require.NoError(t, err)
	assert.Empty(t, sessions.sessions)
}
