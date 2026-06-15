package authkit

import "context"

// MWRequirements defines composable bitflag requirements for auth middleware.
type MWRequirements uint8

const (
	// RequireAuth requires a valid access token with an active session.
	RequireAuth MWRequirements = 1 << iota
	// RequireVerified requires the user's email to be verified.
	RequireVerified
)

// Claim key constants embedded in JWT access tokens.
const (
	ClaimUserID      = "userID"
	ClaimSessionID   = "sessionID"
	ClaimFingerprint = "fgp"
	ClaimExp         = "exp"
	ClaimIat         = "iat"
)

// VerifyToken validates an access token and fingerprint, returning claims.
func (kit *AuthKit) VerifyToken(ctx context.Context, token, fingerprint string) (map[string]any, error) {
	ctx, span := kit.startSpan(ctx, "AuthKit.VerifyToken")
	defer endSpan(span)

	claims, err := kit.jwt.verifyToken(token)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if kit.cfg.Stateless {
		return claims, nil
	}

	// Verify fingerprint
	if kit.cfg.fingerprintEnabled() {
		expectedHash, ok := claims[ClaimFingerprint].(string)
		if !ok || expectedHash == "" {
			return nil, ErrTokenInvalid
		}
		if hashSHA256(fingerprint) != expectedHash {
			return nil, ErrTokenInvalid
		}
	}

	// Extract and validate session
	sessionID, ok := claims[ClaimSessionID].(string)
	if !ok || sessionID == "" {
		return nil, ErrTokenInvalid
	}
	userID, ok := claims[ClaimUserID].(string)
	if !ok || userID == "" {
		return nil, ErrTokenInvalid
	}

	var loadErr error
	cachedUserID, hit := kit.cache.Get(sessionID, func(_ string) (string, bool) {
		session, err := kit.sessions.GetByID(ctx, sessionID)
		if err != nil {
			loadErr = err
			return "", false
		}
		return session.UserID, true
	})
	if loadErr != nil {
		return nil, loadErr
	}
	if !hit {
		return nil, ErrSessionNotFound
	}
	if cachedUserID != userID {
		return nil, ErrSessionNotFound
	}

	return claims, nil
}
