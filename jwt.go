package authkit

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type jwtClaims struct {
	jwt.RegisteredClaims
	Data map[string]any `json:"data"`
}

type jwtService struct {
	issuer   string
	duration time.Duration
	sign     func(token *jwt.Token) (string, error)
	keyFunc  jwt.Keyfunc
	methods  []string
}

func newJWTServiceHS256(issuer, secret string, duration time.Duration) *jwtService {
	return &jwtService{
		issuer:   issuer,
		duration: duration,
		sign: func(token *jwt.Token) (string, error) {
			return token.SignedString([]byte(secret))
		},
		keyFunc: func(_ *jwt.Token) (any, error) {
			return []byte(secret), nil
		},
		methods: []string{jwt.SigningMethodHS256.Name},
	}
}

func newJWTServiceRS256(issuer string, privateKey *rsa.PrivateKey, duration time.Duration) *jwtService {
	return &jwtService{
		issuer:   issuer,
		duration: duration,
		sign: func(token *jwt.Token) (string, error) {
			return token.SignedString(privateKey)
		},
		keyFunc: func(_ *jwt.Token) (any, error) {
			return &privateKey.PublicKey, nil
		},
		methods: []string{jwt.SigningMethodRS256.Name},
	}
}

func (j *jwtService) createToken(data map[string]any) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.GetSigningMethod(j.methods[0]), jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(j.duration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Data: data,
	})
	return j.sign(token)
}

// verifyToken validates tokenStr and returns the embedded data claims.
// On expiry, returns the data along with ErrTokenExpired (useful for refresh flows).
// On all other errors, returns nil data with ErrTokenInvalid.
func (j *jwtService) verifyToken(tokenStr string) (map[string]any, error) {
	var claims jwtClaims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, j.keyFunc,
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods(j.methods),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
			errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrTokenInvalid
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims.Data, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}
	return claims.Data, nil
}
