package authkit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStatelessTestKit(opts ...func(*AuthKit)) *AuthKit {
	kit, err := New(Config{
		Stateless:   true,
		JWTIssuer:   "test",
		JWTSecret:   "test-secret-that-is-long-enough-for-hs256-signing",
		JWTDuration: 15 * time.Minute,
	}, Deps{
		Tx:    &mockTransactor{},
		Users: newMockUserStore(),
	}, Hooks{})
	if err != nil {
		panic(err)
	}
	for _, o := range opts {
		o(kit)
	}
	return kit
}

func TestStateless_Login_ReturnsOnlyAccessToken(t *testing.T) {
	kit := newStatelessTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("password123")
	users.addUser(User{ID: "u1", Email: "admin@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "admin@test.com", "password123")
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.Empty(t, tokens.RefreshToken)
	assert.Empty(t, tokens.Fingerprint)
}

func TestStateless_VerifyToken_JWTOnly(t *testing.T) {
	kit := newStatelessTestKit()
	users := kit.users.(*mockUserStore)
	hash, _ := kit.hash.hash("password123")
	users.addUser(User{ID: "u1", Email: "admin@test.com", PasswordHash: hash, Verified: true})

	tokens, err := kit.Login(context.Background(), "admin@test.com", "password123")
	require.NoError(t, err)

	claims, err := kit.VerifyToken(context.Background(), tokens.AccessToken, "")
	require.NoError(t, err)
	assert.Equal(t, "u1", claims[ClaimUserID])
}

func TestStateless_RefreshToken_ReturnsErrNotSupported(t *testing.T) {
	kit := newStatelessTestKit()

	_, err := kit.RefreshToken(context.Background(), "some-token")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestStateless_Logout_ReturnsErrNotSupported(t *testing.T) {
	kit := newStatelessTestKit()

	err := kit.Logout(context.Background(), "some-session")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestStateless_SendPasswordReset_ReturnsErrNotSupported(t *testing.T) {
	kit := newStatelessTestKit()

	err := kit.SendPasswordReset(context.Background(), "admin@test.com")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestStateless_ResetPassword_ReturnsErrNotSupported(t *testing.T) {
	kit := newStatelessTestKit()

	_, err := kit.ResetPassword(context.Background(), "token", "newpass")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestStateless_Register_WithBeforeRegisterHook(t *testing.T) {
	errForbidden := errors.New("forbidden")
	kit := newStatelessTestKit(func(k *AuthKit) {
		k.hooks.BeforeRegister = func(_ context.Context, _ string) error {
			return errForbidden
		}
	})

	_, err := kit.Register(context.Background(), "new@test.com", "password123", "")
	assert.ErrorIs(t, err, errForbidden)
}

func TestStateless_Register_Success(t *testing.T) {
	kit := newStatelessTestKit()

	verified, err := kit.Register(context.Background(), "new@test.com", "password123", "")
	require.NoError(t, err)
	assert.True(t, verified) // no VerificationURL → auto-verified
}

func TestStateless_Shutdown_NilCache(t *testing.T) {
	kit := newStatelessTestKit()
	err := kit.Shutdown()
	assert.NoError(t, err)
}
