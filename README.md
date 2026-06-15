# go-authkit

A batteries-included auth library for Go web apps.

## Features

- Email/password registration with email verification
- Login with session management and refresh token rotation
- OAuth login (any [goth](https://github.com/markbates/goth) provider)
- Password reset using selector/verifier pattern
- Token fingerprinting (cookie-bound JWTs prevent token theft)
- RS256 / HS256 configurable JWT signing
- Stateless mode for simple Bearer-token flows
- Bring-your-own storage (implement store interfaces)
- Framework-agnostic core + Gin adapter (`authgin`)
- Lifecycle hooks (BeforeRegister, ClaimsBuilder, AfterEmailVerified, etc.)

## Installation

```bash
go get github.com/itsLeonB/go-authkit
```

## Quick Start (stateful)

```go
package main

import (
    "time"
    "github.com/itsLeonB/go-authkit"
    "github.com/itsLeonB/go-authkit/authgin"
)

func main() {
    kit, _ := authkit.New(authkit.Config{
        JWTIssuer:        "myapp",
        JWTSecret:        "your-256-bit-secret",
        JWTDuration:      15 * time.Minute,
        RefreshTokenTTL:  7 * 24 * time.Hour,
        VerificationURL:  "https://myapp.com/verify",
        ResetPasswordURL: "https://myapp.com/reset",
    }, authkit.Deps{
        Tx:       yourTransactor,
        Users:    yourUserStore,
        Sessions: yourSessionStore,
        Refresh:  yourRefreshStore,
        Resets:   yourResetStore,
        OAuth:    yourOAuthStore,
        Mail:     yourMailService,
        Cache:    yourSessionCache,
        State:    yourStateStore,
    }, authkit.Hooks{})
    defer kit.Shutdown()

    // Wire with Gin using authgin.NewHandler(kit, transport, cfg)
}
```

## Quick Start (stateless)

```go
kit, _ := authkit.New(authkit.Config{
    Stateless:   true,
    JWTIssuer:   "myapp",
    JWTSecret:   "your-256-bit-secret",
    JWTDuration: 1 * time.Hour,
}, authkit.Deps{
    Tx:    yourTransactor,
    Users: yourUserStore,
}, authkit.Hooks{})
```

In stateless mode, `Login` returns only an access token. `RefreshToken`, `Logout`, and password reset operations return `ErrNotSupported`.

## Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `JWTAlgorithm` | No | `HS256` (default) or `RS256` |
| `JWTSecret` | HS256 | HMAC signing key |
| `JWTPrivateKey` | RS256 | `*rsa.PrivateKey` for signing |
| `JWTIssuer` | Yes | `iss` claim value |
| `JWTDuration` | Yes | Access token TTL |
| `RefreshTokenTTL` | Stateful | Refresh token lifetime |
| `Stateless` | No | Disables sessions/refresh/fingerprinting |
| `RequireFingerprint` | No | `*bool`, defaults to `true` in stateful mode |
| `VerificationURL` | No | Base URL for email verification links |
| `ResetPasswordURL` | No | Base URL for password reset links |
| `Tracer` | No | OpenTelemetry `trace.Tracer` |

## Store Interfaces

Implement these interfaces to connect authkit to your database:

- `UserStore` — user CRUD
- `SessionStore` — session lifecycle
- `RefreshTokenStore` — hashed refresh tokens
- `ResetTokenStore` — selector/verifier reset tokens
- `OAuthAccountStore` — OAuth identity linking
- `Transactor` — database transactions
- `MailService` — email delivery
- `SessionCache` — fast session lookup cache
- `StateStore` — OAuth CSRF state management

## Hooks

```go
authkit.Hooks{
    BeforeRegister:     func(ctx, email) error { ... },
    ClaimsBuilder:      func(ctx, userID, baseClaims) (map[string]any, error) { ... },
    AfterEmailVerified: func(ctx, userID, profileID, claims) error { ... },
    AfterOAuthLogin:    func(ctx, userID, provider, isNewUser) error { ... },
    BeforeLogout:       func(ctx, sessionID) error { ... },  // non-blocking
}
```

## Testing (authkittest)

The `authkittest` package provides in-memory mock stores for integration testing:

```go
import "github.com/itsLeonB/go-authkit/authkittest"

kit := authkittest.NewKit()  // fully wired with mock stores
// or
kit := authkittest.NewKit(authkittest.WithStateless())
```

Individual mock stores are also exported for fine-grained control:

```go
users := authkittest.NewUserStore()
sessions := authkittest.NewSessionStore()
// etc.
```

## authgin (Gin integration)

The `authgin` sub-package provides:

- `CookieTransport` — httpOnly cookie-based token transport
- `AuthMiddleware` — validates access tokens and populates gin.Context
- `CSRFMiddleware` — double-submit cookie CSRF protection
- `Handler` — ready-to-use route handlers (register, login, logout, refresh, OAuth, reset)
- `StatelessHandler` — Bearer token handlers for stateless mode

## Security

- **Timing-safe comparisons** — `subtle.ConstantTimeCompare` for verifier validation; bcrypt for passwords
- **Error masking** — `ErrInvalidCredentials` for both "user not found" and "wrong password" (prevents enumeration)
- **Token rotation** — refresh tokens are deleted before new ones are issued (no replay window)
- **Fingerprint binding** — access tokens are bound to an httpOnly fingerprint cookie
- **CSRF protection** — double-submit cookie pattern for state-changing requests
- **httpOnly cookies** — all auth cookies are httpOnly (no JavaScript access)
- **SHA-256 hashing** — refresh tokens and fingerprints are stored as hashes only
- **Secure cookies** — enforced when SameSite=None

## License

MIT
