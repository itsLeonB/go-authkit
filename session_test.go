package authkit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTokenAndSession(t *testing.T) {
	kit := newTestKit()

	user := User{ID: "u1", Email: "test@test.com", Verified: true}
	kit.users.(*mockUserStore).addUser(user)

	tokens, err := kit.createTokenAndSession(context.Background(), user)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.NotEmpty(t, tokens.Fingerprint)
}

func TestRefreshToken_Success(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("pass")
	users.addUser(User{ID: "u1", Email: "test@test.com", PasswordHash: hash, Verified: true})

	// Login first to get tokens
	tokens, err := kit.Login(context.Background(), "test@test.com", "pass")
	require.NoError(t, err)

	// Refresh
	newTokens, err := kit.RefreshToken(context.Background(), tokens.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newTokens.AccessToken)
	assert.NotEmpty(t, newTokens.RefreshToken)
	assert.NotEqual(t, tokens.RefreshToken, newTokens.RefreshToken)
}

func TestRefreshToken_NotFound(t *testing.T) {
	kit := newTestKit()

	_, err := kit.RefreshToken(context.Background(), "nonexistent-token")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestRefreshToken_Expired(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "u1", Email: "test@test.com", Verified: true})
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}
	refresh := kit.refresh.(*mockRefreshTokenStore)

	// Manually insert an expired refresh token
	rawToken := "expired-raw-token"
	tokenHash := hashToken(rawToken)
	refresh.tokens[tokenHash] = RefreshToken{
		ID:        tokenHash,
		SessionID: "s1",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	_, err := kit.RefreshToken(context.Background(), rawToken)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestRevokeSession(t *testing.T) {
	kit := newTestKit()
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}
	refresh := kit.refresh.(*mockRefreshTokenStore)
	refresh.tokens["hash1"] = RefreshToken{SessionID: "s1", TokenHash: "hash1"}

	err := kit.revokeSession(context.Background(), "s1")
	require.NoError(t, err)
	assert.Empty(t, sessions.sessions)
	assert.Empty(t, refresh.tokens)
}
