// api/index.go 
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"scamshield/internal/rules"
)

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
	maxInputRunes = 10000 // same limit as the scanner script
	minTextRunes  = 10
)

// The scanner script reads {status, message} for problems and {status:"ok", verdict, explanation, flags} for results.
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

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/scan" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	setup()

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 10,000 characters
	var req struct {
		Input   string `json:"input"`   // field name 
		Content string `json:"content"` // for older callers
		Type    string `json:"type"`    
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
		in.URLs = []string{"https://" + text} // bare link bit.ly/abc gives the rules something to parse
	}

	res := eng.Assess(ctx, in)
	out := rules.BuildResponse(res, rules.PrimaryLanguage(r.Header.Get("Accept-Language")))

	// Never log: raw submissions must not be stored (SEC-1)
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
