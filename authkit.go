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
	return &AuthKit{
		cfg:       cfg,
		hash:      newHashService(10),
		jwt:       newJWTService(cfg.JWTIssuer, cfg.JWTSecret, cfg.JWTDuration),
		tx:        deps.Tx,
		users:     deps.Users,
		sessions:  deps.Sessions,
		refresh:   deps.Refresh,
		resets:    deps.Resets,
		oauth:     deps.OAuth,
		mail:      deps.Mail,
		cache:     deps.Cache,
		state:     deps.State,
		providers: newProviderService(deps.Providers),
		hooks:     hooks,
	}
}

// Shutdown releases resources held by AuthKit.
func (kit *AuthKit) Shutdown() error {
	return kit.cache.Shutdown()
}
