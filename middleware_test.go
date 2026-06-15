package authkit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyToken_Valid(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "u1", Email: "test@test.com", Verified: true})
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}

	fgp := "raw-fingerprint"
	fgpHash := hashSHA256(fgp)

	token, err := kit.jwt.createToken(map[string]any{
		ClaimUserID:      "u1",
		ClaimSessionID:   "s1",
		ClaimFingerprint: fgpHash,
	})
	require.NoError(t, err)

	claims, err := kit.VerifyToken(context.Background(), token, fgp)
	require.NoError(t, err)
	assert.Equal(t, "u1", claims[ClaimUserID])
	assert.Equal(t, "s1", claims[ClaimSessionID])
}

func TestVerifyToken_InvalidSignature(t *testing.T) {
	kit := newTestKit()

	_, err := kit.VerifyToken(context.Background(), "invalid.token.here", "fgp")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyToken_WrongFingerprint(t *testing.T) {
	kit := newTestKit()
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}

	fgpHash := hashSHA256("correct-fgp")
	token, _ := kit.jwt.createToken(map[string]any{
		ClaimUserID:      "u1",
		ClaimSessionID:   "s1",
		ClaimFingerprint: fgpHash,
	})

	_, err := kit.VerifyToken(context.Background(), token, "wrong-fgp")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyToken_SessionNotFound(t *testing.T) {
	kit := newTestKit()

	fgp := "raw-fingerprint"
	fgpHash := hashSHA256(fgp)
	token, _ := kit.jwt.createToken(map[string]any{
		ClaimUserID:      "u1",
		ClaimSessionID:   "nonexistent",
		ClaimFingerprint: fgpHash,
	})

	_, err := kit.VerifyToken(context.Background(), token, fgp)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestVerifyToken_SessionUserMismatch(t *testing.T) {
	kit := newTestKit()
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u2"} // different user

	fgp := "raw-fingerprint"
	fgpHash := hashSHA256(fgp)
	token, _ := kit.jwt.createToken(map[string]any{
		ClaimUserID:      "u1",
		ClaimSessionID:   "s1",
		ClaimFingerprint: fgpHash,
	})

	_, err := kit.VerifyToken(context.Background(), token, fgp)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}
