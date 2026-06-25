package passkeys

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"

	auth "github.com/togo-framework/auth"
)

func (s *Service) mountRoutes(r chi.Router) {
	r.Route("/api/auth/passkeys", func(r chi.Router) {
		r.Post("/register/begin", s.registerBegin)
		r.Post("/register/finish", s.registerFinish)
		r.Post("/login/begin", s.loginBegin)
		r.Post("/login/finish", s.loginFinish)
		r.Get("/credentials", s.listCredentials)
	})
}

// userID resolves the ceremony subject — body {"user_id"} or query/header, else
// the authenticated user.
func (s *Service) userID(r *http.Request, fallbackBody string) string {
	if fallbackBody != "" {
		return fallbackBody
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		return v
	}
	if v := r.Header.Get("X-User-Id"); v != "" {
		return v
	}
	return ""
}

type beginBody struct {
	UserID string `json:"user_id"`
}

// POST /register/begin → PublicKeyCredentialCreationOptions
func (s *Service) registerBegin(w http.ResponseWriter, r *http.Request) {
	var b beginBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	uid := s.userID(r, b.UserID)
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	user := s.userFor(uid)
	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.putSession(uid, session)
	writeJSON(w, 200, options)
}

// POST /register/finish → verify attestation + store the credential
func (s *Service) registerFinish(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(r, "")
	if uid == "" {
		writeErr(w, 400, "user_id required (X-User-Id or ?user_id)")
		return
	}
	session, ok := s.takeSession(uid)
	if !ok {
		writeErr(w, 400, "no registration in progress")
		return
	}
	user := s.userFor(uid)
	cred, err := s.wa.FinishRegistration(user, *session, r)
	if err != nil {
		writeErr(w, 400, "registration failed: "+err.Error())
		return
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	s.store.Add(&Credential{
		ID:        id,
		UserID:    uid,
		Name:      "passkey",
		cred:      *cred,
		SignCount: cred.Authenticator.SignCount,
		CreatedAt: time.Now(),
	})
	writeJSON(w, 201, map[string]any{"id": id, "registered": true})
}

// POST /login/begin → PublicKeyCredentialRequestOptions
func (s *Service) loginBegin(w http.ResponseWriter, r *http.Request) {
	var b beginBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	uid := s.userID(r, b.UserID)
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	user := s.userFor(uid)
	if len(user.creds) == 0 {
		writeErr(w, 404, "no passkeys registered for this user")
		return
	}
	options, session, err := s.wa.BeginLogin(user)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.putSession(uid, session)
	writeJSON(w, 200, options)
}

// POST /login/finish → verify assertion + issue an auth session
func (s *Service) loginFinish(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(r, "")
	if uid == "" {
		writeErr(w, 400, "user_id required (X-User-Id or ?user_id)")
		return
	}
	session, ok := s.takeSession(uid)
	if !ok {
		writeErr(w, 400, "no login in progress")
		return
	}
	user := s.userFor(uid)
	cred, err := s.wa.FinishLogin(user, *session, r)
	if err != nil {
		writeErr(w, 401, "login failed: "+err.Error())
		return
	}
	// update the stored sign count (clone/replay detection).
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	s.store.UpdateSignCount(id, cred.Authenticator.SignCount)

	// issue an auth session via the togo auth plugin, if present.
	if a, ok := auth.FromKernel(s.k); ok {
		id := auth.Identity{ID: uid, Email: uid, Guard: "passkeys"}
		if tok, err := a.IssueSession(w, id); err == nil {
			writeJSON(w, 200, map[string]any{"authenticated": true, "token": tok})
			return
		}
		if tok, err := a.IssueToken(id); err == nil {
			writeJSON(w, 200, map[string]any{"authenticated": true, "token": tok})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"authenticated": true})
}

// GET /credentials → list a user's passkeys
func (s *Service) listCredentials(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(r, "")
	if uid == "" {
		writeErr(w, 400, "user_id required")
		return
	}
	writeJSON(w, 200, s.CredentialsFor(uid))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var _ = webauthn.Credential{}
