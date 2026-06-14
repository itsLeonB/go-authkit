package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// GetOAuthURL generates an OAuth provider authorization URL.
func (kit *AuthKit) GetOAuthURL(ctx context.Context, provider string) (string, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.GetOAuthURL")
	defer endSpan(span)

	state, err := generateState()
	if err != nil {
		return "", err
	}

	url, sessionStr, err := kit.providers.getAuthCodeURL(provider, state)
	if err != nil {
		return "", err
	}

	if err = kit.state.Store(ctx, state, sessionStr, 5*time.Minute); err != nil {
		return "", err
	}

	return url, nil
}

// HandleOAuthCallback processes the OAuth provider callback.
func (kit *AuthKit) HandleOAuthCallback(ctx context.Context, provider, code, state string) (TokenSet, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.HandleOAuthCallback")
	defer endSpan(span)

	parentCtx := ctx

	var (
		result TokenSet
		user   User
		isNew  bool
	)
	err := kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		sessionStr, err := kit.state.VerifyAndDelete(ctx, state)
		if err != nil {
			return err
		}

		userInfo, err := kit.providers.handleCallback(ctx, provider, code, sessionStr)
		if err != nil {
			return err
		}

		user, isNew, err = kit.getOrCreateOAuthUser(ctx, userInfo)
		if err != nil {
			return err
		}

		if !user.Verified {
			user, err = kit.users.SetVerified(ctx, user.ID, userInfo.Name, userInfo.Avatar)
			if err != nil {
				return err
			}
		}

		result, err = kit.createTokenAndSession(ctx, user)
		return err
	})
	if err != nil {
		return TokenSet{}, err
	}

	// Non-blocking hook
	_ = kit.hooks.callAfterOAuthLogin(parentCtx, user.ID, provider, isNew)

	return result, nil
}

func (kit *AuthKit) getOrCreateOAuthUser(ctx context.Context, info OAuthUserInfo) (User, bool, error) {
	existing, err := kit.oauth.FindByProvider(ctx, info.Provider, info.ProviderID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return User{}, false, err
	}
	if !existing.IsZero() {
		user, err := kit.users.FindByID(ctx, existing.UserID)
		if err != nil {
			return User{}, false, err
		}
		return user, false, nil
	}
	return kit.createNewOAuthUser(ctx, info)
}

func (kit *AuthKit) createNewOAuthUser(ctx context.Context, info OAuthUserInfo) (User, bool, error) {
	trusted, err := kit.providers.isTrusted(info.Provider)
	if err != nil {
		return User{}, false, err
	}
	if !trusted {
		return User{}, false, ErrProviderDisabled
	}

	user, err := kit.users.FindByEmail(ctx, info.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return User{}, false, err
	}
	created := false
	if user.IsZero() {
		user, err = kit.users.CreateOAuth(ctx, info.Email, info.Name, info.Avatar)
		if err != nil {
			return User{}, false, err
		}
		created = true
	}

	if err = kit.oauth.Link(ctx, user.ID, info.Provider, info.ProviderID, info.Email); err != nil {
		return User{}, false, err
	}

	return user, created, nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
