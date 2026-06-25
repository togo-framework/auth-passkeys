package passkeys

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func newCred(id, user string) *Credential {
	return &Credential{ID: id, UserID: user, Name: "passkey", CreatedAt: time.Now()}
}

func TestMemStoreAddGetByUser(t *testing.T) {
	s := newMemStore()
	s.Add(newCred("c1", "alice"))
	s.Add(newCred("c2", "alice"))
	s.Add(newCred("c3", "bob"))

	if got := s.ByUser("alice"); len(got) != 2 {
		t.Fatalf("alice should have 2 credentials, got %d", len(got))
	}
	if got := s.ByUser("bob"); len(got) != 1 || got[0].ID != "c3" {
		t.Fatalf("bob = %+v", got)
	}
	if _, ok := s.Get("c1"); !ok {
		t.Fatal("Get(c1) should exist")
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("Get(nope) should be false")
	}
	// isolation: bob never sees alice's
	for _, c := range s.ByUser("bob") {
		if c.UserID != "bob" {
			t.Fatalf("isolation leak: %+v", c)
		}
	}
}

func TestUpdateSignCount(t *testing.T) {
	s := newMemStore()
	s.Add(newCred("c1", "alice"))
	s.UpdateSignCount("c1", 42)
	c, _ := s.Get("c1")
	if c.SignCount != 42 || c.cred.Authenticator.SignCount != 42 {
		t.Fatalf("sign count not updated: %+v", c)
	}
	// unknown id is a no-op (no panic)
	s.UpdateSignCount("nope", 1)
}

func TestDelete(t *testing.T) {
	s := newMemStore()
	s.Add(newCred("c1", "alice"))
	if !s.Delete("c1") {
		t.Fatal("Delete(c1) should be true")
	}
	if s.Delete("c1") {
		t.Fatal("second Delete should be false")
	}
	if len(s.ByUser("alice")) != 0 {
		t.Fatal("credential not removed")
	}
}

func TestWebAuthnUserAdapter(t *testing.T) {
	s := &Service{store: newMemStore()}
	c := newCred("c1", "alice@example.com")
	c.cred = webauthn.Credential{ID: []byte("rawid")}
	s.store.Add(c)

	u := s.userFor("alice@example.com")
	if string(u.WebAuthnID()) != "alice@example.com" {
		t.Errorf("WebAuthnID = %q", u.WebAuthnID())
	}
	if u.WebAuthnName() != "alice@example.com" || u.WebAuthnDisplayName() != "alice@example.com" {
		t.Errorf("name/display = %q/%q", u.WebAuthnName(), u.WebAuthnDisplayName())
	}
	if len(u.WebAuthnCredentials()) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(u.WebAuthnCredentials()))
	}
}

func TestNewServiceConfig(t *testing.T) {
	t.Setenv("PASSKEYS_RP_ID", "localhost")
	t.Setenv("PASSKEYS_RP_NAME", "Fort")
	t.Setenv("PASSKEYS_RP_ORIGINS", "http://localhost:3000, http://localhost:8080")
	s, err := newService(nil)
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	if s.wa == nil {
		t.Fatal("webauthn not initialized")
	}
	// the in-flight session map + default store are ready
	if s.store == nil || s.sessions == nil {
		t.Fatal("service not fully initialized")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := &Service{sessions: map[string]*webauthn.SessionData{}}
	sd := &webauthn.SessionData{Challenge: "abc"}
	s.putSession("alice", sd)
	got, ok := s.takeSession("alice")
	if !ok || got.Challenge != "abc" {
		t.Fatalf("takeSession = %+v, %v", got, ok)
	}
	// taken once — second take is empty (challenge can't be replayed)
	if _, ok := s.takeSession("alice"); ok {
		t.Fatal("session should be consumed after take")
	}
}

func TestWithStore(t *testing.T) {
	s := &Service{store: newMemStore()}
	custom := newMemStore()
	if s.WithStore(custom) != s {
		t.Fatal("WithStore should return the service")
	}
	if s.store != custom {
		t.Fatal("store not swapped")
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a , b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("splitCSV = %#v", got)
	}
}
