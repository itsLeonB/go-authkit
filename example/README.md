# Examples

Runnable examples demonstrating go-authkit usage.

## Stateful (cookie-based sessions)

Full auth flow with sessions, refresh tokens, fingerprinting, and CSRF protection.

```bash
go run ./example/stateful
```

Endpoints:
- `POST /api/v1/auth/register` — register with email/password
- `POST /api/v1/auth/login` — login, sets cookies
- `GET /api/v1/auth/verify?token=...` — verify email
- `POST /api/v1/auth/password/forgot` — send reset email
- `POST /api/v1/auth/password/reset` — reset password
- `POST /api/v1/auth/refresh` — rotate refresh token
- `POST /api/v1/auth/logout` — revoke session (requires auth + CSRF)
- `GET /api/v1/me` — get current user (requires auth)

## Stateless (Bearer token)

Simple JWT flow for admin tools or APIs without session management.

```bash
go run ./example/stateless
```

Endpoints:
- `POST /api/v1/auth/register` — register
- `POST /api/v1/auth/login` — returns `{"type": "Bearer", "token": "..."}`
- `GET /api/v1/me` — requires `Authorization: Bearer <token>` header
