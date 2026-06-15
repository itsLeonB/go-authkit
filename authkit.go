package authkit

// AuthKit is the main entry point for all auth operations.
type AuthKit struct {
	cfg       Config
	hash      *hashService
	jwt       *jwtService
	tx        Transactor
	users     UserStore
	sessions  SessionStore
	refresh   RefreshTokenStore
	resets    ResetTokenStore
	oauth     OAuthAccountStore
	mail      MailService
	cache     SessionCache
	state     StateStore
	providers *providerService
	hooks     Hooks
}

// Deps holds all external dependencies for AuthKit.
type Deps struct {
	Tx        Transactor
	Users     UserStore
	Sessions  SessionStore
	Refresh   RefreshTokenStore
	Resets    ResetTokenStore
	OAuth     OAuthAccountStore
	Mail      MailService
	Cache     SessionCache
	State     StateStore
	Providers []ProviderConfig
}

// New creates a new AuthKit instance.
func New(cfg Config, deps Deps, hooks Hooks) *AuthKit {
	kit := &AuthKit{
		cfg:   cfg,
		hash:  newHashService(10),
		jwt:   newJWTService(cfg.JWTIssuer, cfg.JWTSecret, cfg.JWTDuration),
		tx:    deps.Tx,
		users: deps.Users,
		hooks: hooks,
	}

	if !cfg.Stateless {
		kit.sessions = deps.Sessions
		kit.refresh = deps.Refresh
		kit.resets = deps.Resets
		kit.oauth = deps.OAuth
		kit.mail = deps.Mail
		kit.cache = deps.Cache
		kit.state = deps.State
		kit.providers = newProviderService(deps.Providers)
	}

	return kit
}

// Shutdown releases resources held by AuthKit.
func (kit *AuthKit) Shutdown() error {
	if kit.cfg.Stateless || kit.cache == nil {
		return nil
	}
	return kit.cache.Shutdown()
}
}
