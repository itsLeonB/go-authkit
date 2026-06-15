package authkit

import (
	"time"

	"github.com/itsLeonB/sekure"
)

type jwtService struct {
	inner sekure.JWTService
}

func newJWTService(issuer, key string, duration time.Duration) *jwtService {
	return &jwtService{inner: sekure.NewJwtService(issuer, key, duration)}
}

func (j *jwtService) createToken(claims map[string]any) (string, error) {
	return j.inner.CreateToken(claims)
}

func (j *jwtService) verifyToken(token string) (map[string]any, error) {
	claims, err := j.inner.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	return claims.Data, nil
}
