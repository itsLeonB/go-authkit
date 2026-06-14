package authkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// RefreshToken validates and rotates a refresh token, issuing new tokens.
func (kit *AuthKit) RefreshToken(ctx context.Context, rawRefreshToken string) (TokenSet, error) {
	var result TokenSet
	err := kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		rt, err := kit.getRefreshToken(ctx, rawRefreshToken)
		if err != nil {
			return err
		}

		session, err := kit.sessions.GetByID(ctx, rt.SessionID)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				return ErrSessionNotFound
			}
			return err
		}

		if err := kit.users.Exists(ctx, session.UserID); err != nil {
			return err
		}

		// Rotate refresh token
		newRefreshToken, err := kit.rotateRefreshToken(ctx, rt)
		if err != nil {
			return err
		}

		rawFgp, fgpHash := generateFingerprint()
		claims := buildBaseClaims(session, fgpHash)

		if kit.hooks.ClaimsBuilder != nil {
			claims, err = kit.hooks.ClaimsBuilder(ctx, session.UserID, claims)
			if err != nil {
				return err
			}
		}

		accessToken, err := kit.jwt.createToken(claims)
		if err != nil {
			return err
		}

		result = TokenSet{AccessToken: accessToken, RefreshToken: newRefreshToken, Fingerprint: rawFgp}
		return nil
	})
	return result, err
}

func (kit *AuthKit) createTokenAndSession(ctx context.Context, user User) (TokenSet, error) {
	session, refreshToken, err := kit.createSession(ctx, user.ID)
	if err != nil {
		return TokenSet{}, err
	}

	rawFgp, fgpHash := generateFingerprint()
	claims := buildBaseClaims(session, fgpHash)

	if kit.hooks.ClaimsBuilder != nil {
		claims, err = kit.hooks.ClaimsBuilder(ctx, session.UserID, claims)
		if err != nil {
			return TokenSet{}, err
		}
	}

	accessToken, err := kit.jwt.createToken(claims)
	if err != nil {
		return TokenSet{}, err
	}

	return TokenSet{AccessToken: accessToken, RefreshToken: refreshToken, Fingerprint: rawFgp}, nil
}

func (kit *AuthKit) revokeSession(ctx context.Context, sessionID string) error {
	return kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := kit.refresh.DeleteBySession(ctx, sessionID); err != nil {
			return err
		}
		return kit.sessions.Delete(ctx, sessionID)
	})
}

func (kit *AuthKit) createSession(ctx context.Context, userID string) (Session, string, error) {
	var session Session
	var refreshToken string
	err := kit.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		var err error
		session, err = kit.sessions.Create(ctx, userID)
		if err != nil {
			return err
		}
		expiresAt := time.Now().Add(kit.cfg.RefreshTokenTTL)
		refreshToken, err = kit.createRefreshToken(ctx, session.ID, expiresAt)
		return err
	})
	return session, refreshToken, err
}

func (kit *AuthKit) createRefreshToken(ctx context.Context, sessionID string, expiresAt time.Time) (string, error) {
	token, tokenHash := generateRefreshTokenPair()
	if err := kit.refresh.Create(ctx, sessionID, tokenHash, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func (kit *AuthKit) rotateRefreshToken(ctx context.Context, old RefreshToken) (string, error) {
	if time.Now().After(old.ExpiresAt) {
		return "", ErrTokenExpired
	}

	if err := kit.refresh.Delete(ctx, old.SessionID, old.TokenHash); err != nil {
		return "", err
	}

	if err := kit.sessions.Touch(ctx, old.SessionID); err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(kit.cfg.RefreshTokenTTL)
	return kit.createRefreshToken(ctx, old.SessionID, expiresAt)
}

func (kit *AuthKit) getRefreshToken(ctx context.Context, rawToken string) (RefreshToken, error) {
	rt, err := kit.refresh.FindByHash(ctx, hashToken(rawToken))
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return RefreshToken{}, ErrTokenInvalid
		}
		return RefreshToken{}, err
	}
	return rt, nil
}

func buildBaseClaims(session Session, fgpHash string) map[string]any {
	return map[string]any{
		ClaimUserID:      session.UserID,
		ClaimSessionID:   session.ID,
		ClaimFingerprint: fgpHash,
	}
}

func generateFingerprint() (raw, hash string) {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	raw = hex.EncodeToString(b)
	hash = hashSHA256(raw)
	return
}

func generateRefreshTokenPair() (token, tokenHash string) {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	token = hex.EncodeToString(b)
	tokenHash = hashToken(token)
	return
}

func hashToken(token string) string {
	return hashSHA256(token)
}
