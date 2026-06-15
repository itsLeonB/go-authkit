package authkit

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_HS256_NoSecret(t *testing.T) {
	_, err := New(Config{
		JWTAlgorithm: AlgorithmHS256,
		JWTIssuer:    "test",
		JWTDuration:  15 * time.Minute,
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	assert.ErrorContains(t, err, "JWTSecret required")
}

func TestValidate_RS256_NoKey(t *testing.T) {
	_, err := New(Config{
		JWTAlgorithm: AlgorithmRS256,
		JWTIssuer:    "test",
		JWTSecret:    "unused",
		JWTDuration:  15 * time.Minute,
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	assert.ErrorContains(t, err, "JWTPrivateKey required")
}

func TestValidate_NoIssuer(t *testing.T) {
	_, err := New(Config{
		JWTSecret:   "secret",
		JWTDuration: 15 * time.Minute,
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	assert.ErrorContains(t, err, "JWTIssuer required")
}

func TestValidate_NoDuration(t *testing.T) {
	_, err := New(Config{
		JWTSecret: "secret",
		JWTIssuer: "test",
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	assert.ErrorContains(t, err, "JWTDuration must be positive")
}

func TestValidate_Stateless_MinimalConfig(t *testing.T) {
	kit, err := New(Config{
		Stateless:   true,
		JWTSecret:   "secret",
		JWTIssuer:   "test",
		JWTDuration: 15 * time.Minute,
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	require.NoError(t, err)
	assert.NotNil(t, kit)
}

func TestValidate_RS256_ValidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kit, err := New(Config{
		Stateless:     true,
		JWTAlgorithm:  AlgorithmRS256,
		JWTPrivateKey: key,
		JWTIssuer:     "test",
		JWTDuration:   15 * time.Minute,
	}, Deps{Tx: &mockTransactor{}, Users: newMockUserStore()}, Hooks{})
	require.NoError(t, err)
	assert.NotNil(t, kit)
}
