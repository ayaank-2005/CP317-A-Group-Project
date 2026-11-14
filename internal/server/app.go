package server

import (
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Only top-level page assets are served, so the schema, Go and C sources
// in the repository root never become downloadable.
var staticFile = regexp.MustCompile(`^/[A-Za-z0-9_-]+\.(html|css|js)$`)

type App struct {
	db        *pgxpool.Pool
	sessions  *sessionStore
	staticDir string
	// SecureCookies sets the Secure flag; enable it when served over HTTPS.
	SecureCookies bool
}

func New(db *pgxpool.Pool, staticDir string) *App {
	return &App{db: db, sessions: newSessionStore(), staticDir: staticDir}
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/auth/me", a.handleMe)
	mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", a.handleLogout)

	mux.HandleFunc("GET /api/categories", a.handleCategories)
	mux.HandleFunc("GET /api/reports", a.handleSearchReports)
	mux.HandleFunc("GET /api/reports/{id}", a.handlePublicReport)
	mux.HandleFunc("POST /api/reports", a.handleSubmitReport)
	mux.HandleFunc("GET /api/my-reports", a.handleMyReports)

	mux.HandleFunc("GET /api/moderation/queue", a.handleModerationQueue)
	mux.HandleFunc("POST /api/moderation/reports/{id}/decision", a.handleDecision)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Not found.")
	})
	mux.HandleFunc("/", a.handleStatic)

	return mux
}

func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	if !staticFile.MatchString(path) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(a.staticDir, filepath.FromSlash(path)))
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, apiError{Error: message})
}

func serverError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeError(w, http.StatusInternalServerError, "The server had a problem. Please try again in a moment.")
}

// readJSON also rejects non-JSON bodies, which stops plain HTML forms on
// other sites from posting to the API with the user's cookie.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Expected a JSON request body.")
		return false
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "The request is too large.")
		} else {
			writeError(w, http.StatusBadRequest, "The request body is not valid JSON.")
		}
		return false
	}
	return true
}
