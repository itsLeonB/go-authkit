package authkit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOAuthURL(t *testing.T) {
	// OAuth tests require a mock goth.Provider which is complex to set up.
	// Instead test the state store interaction.
	kit := newTestKit()
	state := kit.state.(*mockStateStore)

	// Without providers configured, should return provider disabled
	_, err := kit.GetOAuthURL(context.Background(), "google")
	assert.ErrorIs(t, err, ErrProviderDisabled)
	assert.Empty(t, state.states)
}

func TestHandleOAuthCallback_InvalidState(t *testing.T) {
	kit := newTestKit()

	_, err := kit.HandleOAuthCallback(context.Background(), "google", "code", "invalid-state")
	assert.Error(t, err)
}

func TestGetOrCreateOAuthUser_ExistingOAuth(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	oauth := kit.oauth.(*mockOAuthAccountStore)

	users.addUser(User{ID: "u1", Email: "test@test.com", Verified: true})
	oauth.accounts["google:gid1"] = OAuthAccount{UserID: "u1", Provider: "google", ProviderID: "gid1"}

	user, isNew, err := kit.getOrCreateOAuthUser(context.Background(), OAuthUserInfo{
		Provider:   "google",
		ProviderID: "gid1",
		Email:      "test@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "u1", user.ID)
	assert.False(t, isNew)
}

func TestGetOrCreateOAuthUser_ExistingEmail(t *testing.T) {
	kit := newTestKit()
	users := kit.users.(*mockUserStore)
	users.addUser(User{ID: "u1", Email: "test@test.com", Verified: true})
	// Configure provider service with a trusted provider
	kit.providers = &providerService{providers: map[string]providerEntry{
		"google": {trusted: true},
	}}

	user, isNew, err := kit.getOrCreateOAuthUser(context.Background(), OAuthUserInfo{
		Provider:   "google",
		ProviderID: "new-gid",
		Email:      "test@test.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "u1", user.ID)
	assert.False(t, isNew)
}

func TestGetOrCreateOAuthUser_NewUser(t *testing.T) {
	kit := newTestKit()
	kit.providers = &providerService{providers: map[string]providerEntry{
		"google": {trusted: true},
	}}

	user, isNew, err := kit.getOrCreateOAuthUser(context.Background(), OAuthUserInfo{
		Provider:   "google",
		ProviderID: "gid1",
		Email:      "new@test.com",
		Name:       "New User",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.True(t, isNew)
}

func TestGetOrCreateOAuthUser_UntrustedProvider(t *testing.T) {
	kit := newTestKit()
	kit.providers = &providerService{providers: map[string]providerEntry{
		"github": {trusted: false},
	}}

	_, _, err := kit.getOrCreateOAuthUser(context.Background(), OAuthUserInfo{
		Provider:   "github",
		ProviderID: "gid1",
		Email:      "new@test.com",
	})
	assert.ErrorIs(t, err, ErrProviderDisabled)
}
