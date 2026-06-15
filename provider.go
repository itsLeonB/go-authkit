package authkit

import (
	"context"
	"net/url"

	"github.com/markbates/goth"
)

type providerService struct {
	providers map[string]providerEntry
}

type providerEntry struct {
	provider goth.Provider
	trusted  bool
}

func newProviderService(providers []ProviderConfig) *providerService {
	m := make(map[string]providerEntry, len(providers))
	for _, p := range providers {
		m[p.Provider.Name()] = providerEntry{provider: p.Provider, trusted: p.Trusted}
	}
	return &providerService{providers: m}
}

func (ps *providerService) get(provider string) (providerEntry, error) {
	entry, ok := ps.providers[provider]
	if !ok {
		return providerEntry{}, ErrProviderDisabled
	}
	return entry, nil
}

func (ps *providerService) isTrusted(provider string) (bool, error) {
	entry, err := ps.get(provider)
	if err != nil {
		return false, err
	}
	return entry.trusted, nil
}

func (ps *providerService) getAuthCodeURL(provider, state string) (string, string, error) {
	entry, err := ps.get(provider)
	if err != nil {
		return "", "", err
	}

	session, err := entry.provider.BeginAuth(state)
	if err != nil {
		return "", "", err
	}
	authURL, err := session.GetAuthURL()
	if err != nil {
		return "", "", err
	}
	return authURL, session.Marshal(), nil
}

func (ps *providerService) handleCallback(_ context.Context, provider, code, sessionStr string) (OAuthUserInfo, error) {
	entry, err := ps.get(provider)
	if err != nil {
		return OAuthUserInfo{}, err
	}

	session, err := entry.provider.UnmarshalSession(sessionStr)
	if err != nil {
		return OAuthUserInfo{}, err
	}

	_, err = session.Authorize(entry.provider, url.Values{"code": {code}})
	if err != nil {
		return OAuthUserInfo{}, err
	}

	user, err := entry.provider.FetchUser(session)
	if err != nil {
		return OAuthUserInfo{}, err
	}

	return OAuthUserInfo{
		Provider:    user.Provider,
		ProviderID:  user.UserID,
		Email:       user.Email,
		Name:        user.Name,
		Avatar:      user.AvatarURL,
		AccessToken: user.AccessToken,
	}, nil
}
