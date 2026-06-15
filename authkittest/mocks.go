// Package authkittest provides mock implementations of authkit store interfaces
// for use in consumer integration tests.
package authkittest

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/itsLeonB/go-authkit"
)

// UserStore is a thread-safe in-memory implementation of authkit.UserStore.
type UserStore struct {
	mu      sync.Mutex
	users   map[string]authkit.User
	byEmail map[string]authkit.User
	nextID  int
}

// NewUserStore creates an empty UserStore.
func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]authkit.User), byEmail: make(map[string]authkit.User)}
}

func (m *UserStore) FindByID(_ context.Context, userID string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return authkit.User{}, authkit.ErrUserNotFound
	}
	return u, nil
}

func (m *UserStore) FindByEmail(_ context.Context, email string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byEmail[email]
	if !ok {
		return authkit.User{}, authkit.ErrUserNotFound
	}
	return u, nil
}

func (m *UserStore) Create(_ context.Context, email, passwordHash string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u := authkit.User{ID: "id-" + strconv.Itoa(m.nextID), Email: email, PasswordHash: passwordHash}
	m.users[u.ID] = u
	m.byEmail[email] = u
	return u, nil
}

func (m *UserStore) CreateOAuth(_ context.Context, email, _, _ string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u := authkit.User{ID: "id-" + strconv.Itoa(m.nextID), Email: email, Verified: true}
	m.users[u.ID] = u
	m.byEmail[email] = u
	return u, nil
}

func (m *UserStore) SetVerified(_ context.Context, userID string, _, _ string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return authkit.User{}, authkit.ErrUserNotFound
	}
	u.Verified = true
	u.ProfileID = "profile-" + userID
	m.users[userID] = u
	m.byEmail[u.Email] = u
	return u, nil
}

func (m *UserStore) UpdatePassword(_ context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return authkit.ErrUserNotFound
	}
	u.PasswordHash = passwordHash
	m.users[userID] = u
	m.byEmail[u.Email] = u
	return nil
}

func (m *UserStore) Exists(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return authkit.ErrUserNotFound
	}
	return nil
}

// AddUser inserts a user directly for test setup.
func (m *UserStore) AddUser(u authkit.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = u
	m.byEmail[u.Email] = u
}

// SessionStore is a thread-safe in-memory implementation of authkit.SessionStore.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]authkit.Session
	nextID   int
}

// NewSessionStore creates an empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]authkit.Session)}
}

func (m *SessionStore) Create(_ context.Context, userID string) (authkit.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s := authkit.Session{ID: "id-" + strconv.Itoa(m.nextID), UserID: userID}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *SessionStore) GetByID(_ context.Context, id string) (authkit.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return authkit.Session{}, authkit.ErrSessionNotFound
	}
	return s, nil
}

func (m *SessionStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *SessionStore) Touch(_ context.Context, _ string) error { return nil }

// RefreshTokenStore is a thread-safe in-memory implementation of authkit.RefreshTokenStore.
type RefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]authkit.RefreshToken
}

// NewRefreshTokenStore creates an empty RefreshTokenStore.
func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{tokens: make(map[string]authkit.RefreshToken)}
}

func (m *RefreshTokenStore) Create(_ context.Context, sessionID, tokenHash string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenHash] = authkit.RefreshToken{ID: tokenHash, SessionID: sessionID, TokenHash: tokenHash, ExpiresAt: expiresAt, CreatedAt: time.Now()}
	return nil
}

func (m *RefreshTokenStore) FindByHash(_ context.Context, hash string) (authkit.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.tokens[hash]
	if !ok {
		return authkit.RefreshToken{}, authkit.ErrTokenNotFound
	}
	return rt, nil
}

func (m *RefreshTokenStore) Delete(_ context.Context, _ string, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, tokenHash)
	return nil
}

func (m *RefreshTokenStore) DeleteBySession(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.tokens {
		if v.SessionID == sessionID {
			delete(m.tokens, k)
		}
	}
	return nil
}

// ResetTokenStore is a thread-safe in-memory implementation of authkit.ResetTokenStore.
type ResetTokenStore struct {
	mu     sync.Mutex
	tokens map[string]authkit.ResetToken
}

// NewResetTokenStore creates an empty ResetTokenStore.
func NewResetTokenStore() *ResetTokenStore {
	return &ResetTokenStore{tokens: make(map[string]authkit.ResetToken)}
}

func (m *ResetTokenStore) Create(_ context.Context, userID, selector, verifierHash string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[selector] = authkit.ResetToken{UserID: userID, Selector: selector, VerifierHash: verifierHash, ExpiresAt: expiresAt}
	return nil
}

func (m *ResetTokenStore) FindBySelector(_ context.Context, selector string) (authkit.ResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.tokens[selector]
	if !ok {
		return authkit.ResetToken{}, authkit.ErrTokenNotFound
	}
	return rt, nil
}

func (m *ResetTokenStore) DeleteByUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.tokens {
		if v.UserID == userID {
			delete(m.tokens, k)
		}
	}
	return nil
}

// OAuthAccountStore is a thread-safe in-memory implementation of authkit.OAuthAccountStore.
type OAuthAccountStore struct {
	mu       sync.Mutex
	accounts map[string]authkit.OAuthAccount
}

// NewOAuthAccountStore creates an empty OAuthAccountStore.
func NewOAuthAccountStore() *OAuthAccountStore {
	return &OAuthAccountStore{accounts: make(map[string]authkit.OAuthAccount)}
}

func (m *OAuthAccountStore) FindByProvider(_ context.Context, provider, providerID string) (authkit.OAuthAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oa, ok := m.accounts[provider+":"+providerID]
	if !ok {
		return authkit.OAuthAccount{}, authkit.ErrUserNotFound
	}
	return oa, nil
}

func (m *OAuthAccountStore) Link(_ context.Context, userID, provider, providerID, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[provider+":"+providerID] = authkit.OAuthAccount{UserID: userID, Provider: provider, ProviderID: providerID, Email: email}
	return nil
}

// MailService is a no-op implementation of authkit.MailService.
type MailService struct {
	mu                 sync.Mutex
	VerificationsSent  int
	PasswordResetsSent int
}

// NewMailService creates a new MailService.
func NewMailService() *MailService { return &MailService{} }

func (m *MailService) SendVerification(_ context.Context, _, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VerificationsSent++
	return nil
}

func (m *MailService) SendPasswordReset(_ context.Context, _, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PasswordResetsSent++
	return nil
}

// SessionCache is an in-memory implementation of authkit.SessionCache.
type SessionCache struct {
	mu    sync.Mutex
	store map[string]string
}

// NewSessionCache creates a new SessionCache.
func NewSessionCache() *SessionCache {
	return &SessionCache{store: make(map[string]string)}
}

func (m *SessionCache) Get(sessionID string, loader func(string) (string, bool)) (string, bool) {
	m.mu.Lock()
	v, ok := m.store[sessionID]
	m.mu.Unlock()
	if ok {
		return v, true
	}
	val, loaded := loader(sessionID)
	if loaded {
		m.mu.Lock()
		m.store[sessionID] = val
		m.mu.Unlock()
		return val, true
	}
	return "", false
}

func (m *SessionCache) Delete(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, sessionID)
}

func (m *SessionCache) Shutdown() error { return nil }

// StateStore is an in-memory implementation of authkit.StateStore.
type StateStore struct {
	mu     sync.Mutex
	states map[string]string
}

// NewStateStore creates a new StateStore.
func NewStateStore() *StateStore {
	return &StateStore{states: make(map[string]string)}
}

func (m *StateStore) Store(_ context.Context, state, value string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[state] = value
	return nil
}

func (m *StateStore) VerifyAndDelete(_ context.Context, state string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.states[state]
	if !ok {
		return "", authkit.ErrTokenInvalid
	}
	delete(m.states, state)
	return v, nil
}

// Transactor is a no-op implementation of authkit.Transactor (executes fn directly).
type Transactor struct{}

// NewTransactor creates a new Transactor.
func NewTransactor() *Transactor { return &Transactor{} }

func (m *Transactor) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
