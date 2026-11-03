// api/index.go  (Vercel serverless entrypoint)
// Scan code is unchanged from before. New: the router at the bottom, and the two database endpoints 
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"scamshield/internal/reports"
	"scamshield/internal/rules"
	"scamshield/internal/store"
)

// ---- database: /api/reports and /api/categories use it ----
var (
	mu sync.Mutex
	db *store.Store
)

func openStore(_ context.Context) (reports.Searcher, error) {
	mu.Lock()
	defer mu.Unlock()
	if db == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second) // the pool outlives one request
		defer cancel()
		s, err := store.New(ctx)
		if err != nil {
			return nil, err
		}
		db = s
	}
	return db, nil
}

var (
	searchHandler     = reports.Search(openStore)
	categoriesHandler = reports.Categories(openStore)
)

// ---- scanner (unchanged) ----

var (
	once sync.Once
	eng  *rules.Engine
)

func setup() {
	once.Do(func() { eng = rules.NewEngine(rules.Defaults(), nil) }) // pass a reputation client here later
}

var (
	urlRe       = regexp.MustCompile(`https?://[^\s]+`)
	phoneOnlyRe = regexp.MustCompile(`^[+\d\s().-]+$`)
	ipHostRe    = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/|$)`)
	bareURLRe   = regexp.MustCompile(`(?i)^(www\.|[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(/|$))`)
)

const (
	maxInputRunes = 10000
	minTextRunes  = 10
)

func problem(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "error", "message": msg})
}

func classify(s string) string {
	switch {
	case ipHostRe.MatchString(s):
		return "url"
	case phoneOnlyRe.MatchString(s):
		return "phone"
	case urlRe.MatchString(s) && strings.HasPrefix(strings.ToLower(s), "http"), bareURLRe.MatchString(s) && !strings.ContainsAny(s, " \n\t"):
		return "url"
	default:
		return "text"
	}
}

func scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "That kind of request isn't supported."})
		return
	}
	setup()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 10,000 characters can be up to ~40 KB in some languages
	var req struct {
		Input   string `json:"input"`   // field name the scanner script sends
		Content string `json:"content"` // accepted too, for older callers
		Type    string `json:"type"`    // ignored: the server classifies for itself
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, "We could not read your submission. Please try again.")
		return
	}
	text := strings.TrimSpace(req.Input)
	if text == "" {
		text = strings.TrimSpace(req.Content)
	}
	if text == "" {
		problem(w, "Please enter a message, email, phone number, or URL before scanning.")
		return
	}
	if n := len([]rune(text)); n > maxInputRunes {
		problem(w, "Your submission is too long. Please keep it under 10,000 characters.")
		return
	}
	kind := classify(text)
	if kind == "phone" {
		// UI-1: a phone number on its own is looked up in the public database, not scored
		problem(w, "A phone number on its own is checked in the public scam database. Please use the database search.")
		return
	}
	if kind == "text" && len([]rune(text)) < minTextRunes {
		problem(w, "Your message is too short. Please enter at least 10 characters.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	in := rules.Input{Type: kind, Text: text, URLs: urlRe.FindAllString(text, -1)}
	if kind == "url" && len(in.URLs) == 0 {
		in.URLs = []string{"https://" + text} // bare link such as bit.ly/abc: give the rules something to parse
	}
	res := eng.Assess(ctx, in)
	out := rules.BuildResponse(res, rules.PrimaryLanguage(r.Header.Get("Accept-Language")))
	// Never log `text`: raw submissions must not be stored (SEC-1)
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- router ----

// routeOf finds which endpoint was asked for. It uses the real path when Vercel keeps it,
// and the ?route= value added by the rewrite in vercel.json otherwise.
func routeOf(r *http.Request) string {
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api"), "/")
	if p == "" || p == "index" {
		p = strings.Trim(r.URL.Query().Get("route"), "/")
	}
	return p
}

func Handler(w http.ResponseWriter, r *http.Request) {
	switch routeOf(r) {
	case "scan":
		scan(w, r)
	case "reports":
		searchHandler(w, r)
	case "categories":
		categoriesHandler(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found."})
	}
}

