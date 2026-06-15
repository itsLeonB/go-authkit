package authkit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshToken_ReplayDetection(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("pass")
	users.addUser(User{ID: "u1", Email: "test@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "test@test.com", "pass")
	require.NoError(t, err)

	_, err = kit.RefreshToken(context.Background(), tokens.RefreshToken)
	require.NoError(t, err)

	// Old token should be invalid after rotation
	_, err = kit.RefreshToken(context.Background(), tokens.RefreshToken)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestRefreshToken_ConcurrentRotation(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("pass")
	users.addUser(User{ID: "u1", Email: "test@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "test@test.com", "pass")
	require.NoError(t, err)

	var wg sync.WaitGroup
	results := make([]error, 2)
	wg.Add(2)
	for i := range 2 {
		go func(idx int) {
			defer wg.Done()
			_, results[idx] = kit.RefreshToken(context.Background(), tokens.RefreshToken)
		}(i)
	}
	wg.Wait()

	successes := 0
	failures := 0
	for _, err := range results {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	// At most one succeeds
	assert.LessOrEqual(t, successes, 1)
	assert.GreaterOrEqual(t, failures, 1)
}

func TestVerifyToken_SessionRevoked(t *testing.T) {
	kit := newTestKit()
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}

	fgp := "raw-fgp"
	token, err := kit.jwt.createToken(map[string]any{
		ClaimUserID:      "u1",
		ClaimSessionID:   "s1",
		ClaimFingerprint: hashSHA256(fgp),
	})
	require.NoError(t, err)

	// Revoke session
	delete(sessions.sessions, "s1")

	_, err = kit.VerifyToken(context.Background(), token, fgp)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestResetPassword_SelectorReuse(t *testing.T) {
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
		"id": "1", "email": "user@test.com",
		"selector": selector, "verifier": verifier,
	})

	_, err := kit.ResetPassword(context.Background(), token, "newpass")
	require.NoError(t, err)

	// Reuse same token — selector deleted
	_, err = kit.ResetPassword(context.Background(), token, "anotherpass")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestResetPassword_WrongVerifier(t *testing.T) {
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
		"id": "1", "email": "user@test.com",
		"selector": selector, "verifier": "wrong-verifier",
	})

	_, err := kit.ResetPassword(context.Background(), token, "newpass")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}
