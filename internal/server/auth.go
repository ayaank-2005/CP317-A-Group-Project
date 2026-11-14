package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"scamshield/internal/reportstatus"
)

const (
	sessionCookie = "ss_session"
	sessionTTL    = 7 * 24 * time.Hour
)

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (u *User) role() reportstatus.Role {
	role, ok := reportstatus.ParseRole(u.Role)
	if !ok {
		return reportstatus.RoleUser
	}
	return role
}

// sessionStore keeps sessions in memory: signing in again is required
// after a server restart, and it only works with a single server process.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	userID  string
	expires time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]session{}}
}

func (s *sessionStore) create(userID string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for t, sess := range s.sessions {
		if now.After(sess.expires) {
			delete(s.sessions, t)
		}
	}
	s.sessions[token] = session{userID: userID, expires: now.Add(sessionTTL)}
	return token, nil
}

func (s *sessionStore) lookup(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, token)
		return "", false
	}
	return sess.userID, true
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// currentUser returns the signed-in user, or nil. The role is re-read from
// the users table on every request so a demotion takes effect immediately.
func (a *App) currentUser(ctx context.Context, r *http.Request) (*User, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil
	}
	userID, ok := a.sessions.lookup(cookie.Value)
	if !ok {
		return nil, nil
	}

	var u User
	err = a.db.QueryRow(ctx,
		`SELECT id::text, email, role FROM users WHERE id = $1`, userID,
	).Scan(&u.ID, &u.Email, &u.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		a.sessions.remove(cookie.Value)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// requireUser writes a 401 and returns nil when nobody is signed in.
func (a *App) requireUser(w http.ResponseWriter, r *http.Request) *User {
	u, err := a.currentUser(r.Context(), r)
	if err != nil {
		serverError(w, err)
		return nil
	}
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Please sign in to continue.")
		return nil
	}
	return u
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := a.currentUser(r.Context(), r)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]*User{"user": u})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "Enter your email and password.")
		return
	}

	// Passwords are bcrypt hashes checked by pgcrypto's crypt().
	var u User
	err := a.db.QueryRow(r.Context(), `
		SELECT id::text, email, role
		FROM users
		WHERE lower(email) = lower($1)
		  AND password_hash = crypt($2, password_hash)`,
		email, body.Password,
	).Scan(&u.ID, &u.Email, &u.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusUnauthorized, "That email and password don't match an account.")
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}

	token, err := a.sessions.create(u.ID)
	if err != nil {
		serverError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]*User{"user": &u})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.remove(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}
