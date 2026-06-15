package authkit

import "context"

// Hooks holds optional callbacks for injecting application-specific logic.
type Hooks struct {
	// BeforeLogout runs before session revocation. Errors are non-blocking.
	BeforeLogout func(ctx context.Context, sessionID string) error

	// AfterEmailVerified runs after email verification succeeds.
	// Receives raw JWT claims so the hook can extract app-specific data.
	// Errors are blocking and abort the verification flow.
	AfterEmailVerified func(ctx context.Context, userID, profileID string, claims map[string]any) error

	// AfterOAuthLogin runs after successful OAuth authentication.
	// Errors are non-blocking.
	AfterOAuthLogin func(ctx context.Context, userID string, provider string, isNewUser bool) error

	// ClaimsBuilder is called when issuing a JWT access token.
	// It receives base claims and returns augmented claims for the token.
	// Errors abort token issuance.
	ClaimsBuilder func(ctx context.Context, userID string, baseClaims map[string]any) (map[string]any, error)
}

func (h Hooks) callBeforeLogout(ctx context.Context, sessionID string) error {
	if h.BeforeLogout == nil {
		return nil
	}
	return h.BeforeLogout(ctx, sessionID)
}

func (h Hooks) callAfterEmailVerified(ctx context.Context, userID, profileID string, claims map[string]any) error {
	if h.AfterEmailVerified == nil {
		return nil
	}
	return h.AfterEmailVerified(ctx, userID, profileID, claims)
}

func (h Hooks) callAfterOAuthLogin(ctx context.Context, userID string, provider string, isNewUser bool) error {
	if h.AfterOAuthLogin == nil {
		return nil
	}
	return h.AfterOAuthLogin(ctx, userID, provider, isNewUser)
}
