package authkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHash_RoundTrip(t *testing.T) {
	svc := newHashService(bcrypt.MinCost)
	hashed, err := svc.hash("password123")
	require.NoError(t, err)

	ok, err := svc.verify(hashed, "password123")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestHash_WrongPassword(t *testing.T) {
	svc := newHashService(bcrypt.MinCost)
	hashed, err := svc.hash("password123")
	require.NoError(t, err)

	ok, err := svc.verify(hashed, "wrongpassword")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHash_InvalidHash(t *testing.T) {
	svc := newHashService(bcrypt.MinCost)
	ok, err := svc.verify("not-a-valid-bcrypt-hash", "password123")
	assert.False(t, ok)
	assert.Error(t, err)
}

func TestHash_DefaultCost(t *testing.T) {
	svc := newHashService(0)
	assert.Equal(t, defaultBcryptCost, svc.cost)
}
