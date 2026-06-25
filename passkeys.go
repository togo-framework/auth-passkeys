// Package passkeys adds WebAuthn / passkey (FIDO2) authentication to the togo
// auth family — passwordless registration and login ceremonies, with the issued
// session coming from the togo auth plugin.
//
//	PASSKEYS_RP_ID=localhost PASSKEYS_RP_NAME="Fort" PASSKEYS_RP_ORIGINS=http://localhost:3000
//
// Endpoints (mounted on the kernel router):
//
//	POST /api/auth/passkeys/register/begin   POST /api/auth/passkeys/register/finish
//	POST /api/auth/passkeys/login/begin      POST /api/auth/passkeys/login/finish
package passkeys

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/togo-framework/togo"
)

// Credential is a stored passkey for a user.
type Credential struct {
	ID        string    `json:"id"`         // base64url credential id
	UserID    string    `json:"user_id"`    // the owning user (email/id)
	Name      string    `json:"name"`       // display label
	cred      webauthn.Credential
	SignCount uint32    `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

// Store is the credential persistence seam (swap for a DB-backed store).
type Store interface {
	Add(c *Credential)
	ByUser(userID string) []*Credential
	Get(id string) (*Credential, bool)
	UpdateSignCount(id string, count uint32)
	Delete(id string) bool
}

// Service is the passkeys runtime stored on the kernel (k.Get("passkeys")).
type Service struct {
	k     *togo.Kernel
	wa    *webauthn.WebAuthn
	store Store
	mu    sync.Mutex
	// in-flight ceremony sessions keyed by user id (challenge state).
	sessions map[string]*webauthn.SessionData
}

func init() {
	togo.RegisterProviderFunc("auth-passkeys", togo.PriorityLate+10, func(k *togo.Kernel) error {
		s, err := newService(k)
		if err != nil {
			return err
		}
		k.Set("passkeys", s)
		if k.Router != nil {
			s.mountRoutes(k.Router)
		}
		return nil
	})
}

func newService(k *togo.Kernel) (*Service, error) {
	rpID := env("PASSKEYS_RP_ID", "localhost")
	rpName := env("PASSKEYS_RP_NAME", "togo")
	origins := splitCSV(env("PASSKEYS_RP_ORIGINS", "http://localhost:3000,http://localhost:8080"))
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		k:        k,
		wa:       wa,
		store:    newMemStore(),
		sessions: map[string]*webauthn.SessionData{},
	}, nil
}

// FromKernel returns the passkeys Service.
func FromKernel(k *togo.Kernel) (*Service, bool) {
	v, ok := k.Get("passkeys")
	if !ok {
		return nil, false
	}
	s, ok := v.(*Service)
	return s, ok
}

// WithStore swaps the credential store (e.g. a DB-backed implementation).
func (s *Service) WithStore(store Store) *Service {
	s.store = store
	return s
}

// CredentialsFor returns the stored passkeys for a user.
func (s *Service) CredentialsFor(userID string) []*Credential { return s.store.ByUser(userID) }

// putSession / takeSession track the per-user ceremony challenge.
func (s *Service) putSession(userID string, sd *webauthn.SessionData) {
	s.mu.Lock()
	s.sessions[userID] = sd
	s.mu.Unlock()
}

func (s *Service) takeSession(userID string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sd, ok := s.sessions[userID]
	delete(s.sessions, userID)
	return sd, ok
}

// waUser adapts a user + their credentials to the go-webauthn User interface.
type waUser struct {
	id    string
	name  string
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *waUser) WebAuthnIcon() string                       { return "" }

// userFor builds the WebAuthn user view for a user id from the store.
func (s *Service) userFor(userID string) *waUser {
	var creds []webauthn.Credential
	for _, c := range s.store.ByUser(userID) {
		creds = append(creds, c.cred)
	}
	return &waUser{id: userID, name: userID, creds: creds}
}

// --- in-memory store ---

type memStore struct {
	mu   sync.RWMutex
	byID map[string]*Credential
}

func newMemStore() *memStore { return &memStore{byID: map[string]*Credential{}} }

func (m *memStore) Add(c *Credential) {
	m.mu.Lock()
	m.byID[c.ID] = c
	m.mu.Unlock()
}

func (m *memStore) ByUser(userID string) []*Credential {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Credential
	for _, c := range m.byID {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out
}

func (m *memStore) Get(id string) (*Credential, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.byID[id]
	return c, ok
}

func (m *memStore) UpdateSignCount(id string, count uint32) {
	m.mu.Lock()
	if c, ok := m.byID[id]; ok {
		c.SignCount = count
		c.cred.Authenticator.SignCount = count
	}
	m.mu.Unlock()
}

func (m *memStore) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return false
	}
	delete(m.byID, id)
	return true
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
