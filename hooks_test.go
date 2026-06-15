package authkit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBeforeRegister_Rejected(t *testing.T) {
	errForbidden := errors.New("forbidden")
	kit := newTestKit(func(k *AuthKit) {
		k.hooks.BeforeRegister = func(_ context.Context, _ string) error {
			return errForbidden
		}
	})

	_, err := kit.Register(context.Background(), "new@test.com", "password123", "")
	assert.ErrorIs(t, err, errForbidden)
}

func TestClaimsBuilder_AugmentsClaims(t *testing.T) {
	kit := newTestKit(func(k *AuthKit) {
		k.hooks.ClaimsBuilder = func(_ context.Context, userID string, claims map[string]any) (map[string]any, error) {
			claims["role"] = "admin"
			return claims, nil
		}
	})
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("pass")
	users.addUser(User{ID: "u1", Email: "test@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "test@test.com", "pass")
	require.NoError(t, err)

	claims, err := kit.jwt.verifyToken(tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims["role"])
}

func TestAfterEmailVerified_Called(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "u1", Email: "user@test.com"})

	var gotUserID, gotProfileID string
	kit.hooks.AfterEmailVerified = func(_ context.Context, userID, profileID string, _ map[string]any) error {
		gotUserID = userID
		gotProfileID = profileID
		return nil
	}

	token, err := kit.jwt.createToken(map[string]any{
		"id": "u1", "email": "user@test.com", "exp": float64(9999999999),
	})
	require.NoError(t, err)

	_, err = kit.VerifyRegistration(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "u1", gotUserID)
	assert.Equal(t, "profile-u1", gotProfileID)
}

func TestBeforeLogout_ErrorNonBlocking(t *testing.T) {
	kit := newTestKit(func(k *AuthKit) {
		k.hooks.BeforeLogout = func(_ context.Context, _ string) error {
			return errors.New("hook error")
		}
	})
	sessions := kit.sessions.(*mockSessionStore)
	sessions.sessions["s1"] = Session{ID: "s1", UserID: "u1"}

	err := kit.Logout(context.Background(), "s1")
	require.NoError(t, err)
	assert.Empty(t, sessions.sessions)
}
