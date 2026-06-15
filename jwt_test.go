package authkit

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHS256_CreateAndVerify(t *testing.T) {
	svc := newJWTServiceHS256("test-issuer", "my-secret-key", 15*time.Minute)
	data := map[string]any{"userID": "u1"}

	token, err := svc.createToken(data)
	require.NoError(t, err)

	got, err := svc.verifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "u1", got["userID"])
}

func TestHS256_ExpiredToken(t *testing.T) {
	svc := newJWTServiceHS256("test-issuer", "my-secret-key", -1*time.Second)
	data := map[string]any{"userID": "u1"}

	token, err := svc.createToken(data)
	require.NoError(t, err)

	got, err := svc.verifyToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)
	assert.Equal(t, "u1", got["userID"])
}

func TestHS256_WrongSecret(t *testing.T) {
	svc := newJWTServiceHS256("test-issuer", "secret-a", 15*time.Minute)
	token, err := svc.createToken(map[string]any{"userID": "u1"})
	require.NoError(t, err)

	other := newJWTServiceHS256("test-issuer", "secret-b", 15*time.Minute)
	_, err = other.verifyToken(token)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestHS256_WrongIssuer(t *testing.T) {
	svc := newJWTServiceHS256("issuer-a", "secret", 15*time.Minute)
	token, err := svc.createToken(map[string]any{"userID": "u1"})
	require.NoError(t, err)

	other := newJWTServiceHS256("issuer-b", "secret", 15*time.Minute)
	_, err = other.verifyToken(token)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestRS256_CreateAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	svc := newJWTServiceRS256("test-issuer", key, 15*time.Minute)
	data := map[string]any{"userID": "u1"}

	token, err := svc.createToken(data)
	require.NoError(t, err)

	got, err := svc.verifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "u1", got["userID"])
}

func TestRS256_ExpiredToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	svc := newJWTServiceRS256("test-issuer", key, -1*time.Second)
	token, err := svc.createToken(map[string]any{"userID": "u1"})
	require.NoError(t, err)

	_, err = svc.verifyToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestRS256_WrongKey(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	svc := newJWTServiceRS256("test-issuer", key1, 15*time.Minute)
	token, err := svc.createToken(map[string]any{"userID": "u1"})
	require.NoError(t, err)

	other := newJWTServiceRS256("test-issuer", key2, 15*time.Minute)
	_, err = other.verifyToken(token)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}
