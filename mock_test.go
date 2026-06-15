package authkit

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// --- Mock Stores ---

type mockUserStore struct {
	mu      sync.Mutex
	users   map[string]User
	byEmail map[string]User
	nextID  int
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]User), byEmail: make(map[string]User)}
}

func (m *mockUserStore) FindByID(_ context.Context, userID string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserStore) FindByEmail(_ context.Context, email string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byEmail[email]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserStore) Create(_ context.Context, email, passwordHash string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u := User{ID: idStr(m.nextID), Email: email, PasswordHash: passwordHash}
	m.users[u.ID] = u
	m.byEmail[email] = u
	return u, nil
}

func (m *mockUserStore) CreateOAuth(_ context.Context, email, name, avatar string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	u := User{ID: idStr(m.nextID), Email: email, Verified: true}
	m.users[u.ID] = u
	m.byEmail[email] = u
	return u, nil
}

func (m *mockUserStore) SetVerified(_ context.Context, userID string, name, avatar string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Verified = true
	u.ProfileID = "profile-" + userID
	m.users[userID] = u
	m.byEmail[u.Email] = u
	return u, nil
}

func (m *mockUserStore) UpdatePassword(_ context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	u.PasswordHash = passwordHash
	m.users[userID] = u
	m.byEmail[u.Email] = u
	return nil
}

func (m *mockUserStore) Exists(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return ErrUserNotFound
	}
	return nil
}

// addUser is a test helper.
func (m *mockUserStore) addUser(u User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = u
	m.byEmail[u.Email] = u
}

type mockSessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	nextID   int
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]Session)}
}

func (m *mockSessionStore) Create(_ context.Context, userID string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s := Session{ID: idStr(m.nextID), UserID: userID}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockSessionStore) GetByID(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) Touch(_ context.Context, _ string) error { return nil }

type mockRefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]RefreshToken
}

func newMockRefreshTokenStore() *mockRefreshTokenStore {
	return &mockRefreshTokenStore{tokens: make(map[string]RefreshToken)}
}

func (m *mockRefreshTokenStore) Create(_ context.Context, sessionID, tokenHash string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenHash] = RefreshToken{ID: tokenHash, SessionID: sessionID, TokenHash: tokenHash, ExpiresAt: expiresAt, CreatedAt: time.Now()}
	return nil
}

func (m *mockRefreshTokenStore) FindByHash(_ context.Context, hash string) (RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.tokens[hash]
	if !ok {
		return RefreshToken{}, ErrTokenNotFound
	}
	return rt, nil
}

func (m *mockRefreshTokenStore) Delete(_ context.Context, _ string, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, tokenHash)
	return nil
}

func (m *mockRefreshTokenStore) DeleteBySession(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.tokens {
		if v.SessionID == sessionID {
			delete(m.tokens, k)
		}
	}
	return nil
}

type mockResetTokenStore struct {
	mu     sync.Mutex
	tokens map[string]ResetToken
}

func newMockResetTokenStore() *mockResetTokenStore {
	return &mockResetTokenStore{tokens: make(map[string]ResetToken)}
}

func (m *mockResetTokenStore) Create(_ context.Context, userID, selector, verifierHash string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[selector] = ResetToken{UserID: userID, Selector: selector, VerifierHash: verifierHash, ExpiresAt: expiresAt}
	return nil
}

func (m *mockResetTokenStore) FindBySelector(_ context.Context, selector string) (ResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.tokens[selector]
	if !ok {
		return ResetToken{}, ErrTokenNotFound
	}
	return rt, nil
}

func (m *mockResetTokenStore) DeleteByUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.tokens {
		if v.UserID == userID {
			delete(m.tokens, k)
		}
	}
	return nil
}

type mockOAuthAccountStore struct {
	mu       sync.Mutex
	accounts map[string]OAuthAccount // key: provider+providerID
}

func newMockOAuthAccountStore() *mockOAuthAccountStore {
	return &mockOAuthAccountStore{accounts: make(map[string]OAuthAccount)}
}

func (m *mockOAuthAccountStore) FindByProvider(_ context.Context, provider, providerID string) (OAuthAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oa, ok := m.accounts[provider+":"+providerID]
	if !ok {
		return OAuthAccount{}, ErrUserNotFound
	}
	return oa, nil
}

func (m *mockOAuthAccountStore) Link(_ context.Context, userID, provider, providerID, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[provider+":"+providerID] = OAuthAccount{UserID: userID, Provider: provider, ProviderID: providerID, Email: email}
	return nil
}

type mockMailService struct {
	mu                 sync.Mutex
	verificationsSent  int
	passwordResetsSent int
}

func (m *mockMailService) SendVerification(_ context.Context, _, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationsSent++
	return nil
}

func (m *mockMailService) SendPasswordReset(_ context.Context, _, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passwordResetsSent++
	return nil
}

type mockSessionCache struct {
	mu    sync.Mutex
	store map[string]string
}

func newMockSessionCache() *mockSessionCache {
	return &mockSessionCache{store: make(map[string]string)}
}

func (m *mockSessionCache) Get(sessionID string, loader func(string) (string, bool)) (string, bool) {
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

func (m *mockSessionCache) Delete(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, sessionID)
}

func (m *mockSessionCache) Shutdown() error { return nil }

type mockStateStore struct {
	mu     sync.Mutex
	states map[string]string
}

func newMockStateStore() *mockStateStore {
	return &mockStateStore{states: make(map[string]string)}
}

func (m *mockStateStore) Store(_ context.Context, state, value string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[state] = value
	return nil
}

func (m *mockStateStore) VerifyAndDelete(_ context.Context, state string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.states[state]
	if !ok {
		return "", ErrTokenInvalid
	}
	delete(m.states, state)
	return v, nil
}

type mockTransactor struct{}

func (m *mockTransactor) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// --- Test helpers ---

func idStr(n int) string {
	return "id-" + strconv.Itoa(n)
}

func newTestKit(opts ...func(*AuthKit)) *AuthKit {
	kit, err := New(Config{
		JWTIssuer:        "test",
		JWTSecret:        "test-secret-that-is-long-enough-for-hs256-signing",
		JWTDuration:      15 * time.Minute,
		RefreshTokenTTL:  24 * time.Hour,
		VerificationURL:  "http://localhost/verify",
		ResetPasswordURL: "http://localhost/reset",
	}, Deps{
		Tx:       &mockTransactor{},
		Users:    newMockUserStore(),
		Sessions: newMockSessionStore(),
		Refresh:  newMockRefreshTokenStore(),
		Resets:   newMockResetTokenStore(),
		OAuth:    newMockOAuthAccountStore(),
		Mail:     &mockMailService{},
		Cache:    newMockSessionCache(),
		State:    newMockStateStore(),
	}, Hooks{})
	if err != nil {
		panic(err)
	}
	for _, o := range opts {
		o(kit)
	}
	return kit
}
