// internal/moderation/handlers.go
// MOD-1: reviewing reports. Wrap every handler with RequireKey (see api/index.go).
// A moderator sees redacted text only, never raw submissions.
//
//	GET  /api/mod-queue?page=&pageSize=   reports waiting for review, oldest first
//	GET  /api/mod-candidates?id=<uuid>    reports the given one could be merged into
//	POST /api/mod-decision                {reportId, decision: approve|reject|merge, moderator, mergeIntoId?, reason?}
//	GET  /api/mod-history?limit=          the record of recent decisions
package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---- data the front end receives ----

type Category struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type Sender struct {
	Type  string `json:"type"` // phone | domain | email
	Value string `json:"value"`
}

// Item is one report waiting in the queue.
type Item struct {
	ID              string    `json:"id"`
	Category        Category  `json:"category"`
	Sender          *Sender   `json:"sender"` // null when the report has no sender
	Content         string    `json:"content"`
	SubmissionCount int       `json:"submissionCount"`
	Language        string    `json:"language"`
	CreatedAt       time.Time `json:"createdAt"`
}

type Queue struct {
	Results  []Item `json:"results"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"pageSize"`
}

// Candidate is a report a duplicate could be merged into.
type Candidate struct {
	ID              string  `json:"id"`
	Sender          *Sender `json:"sender"`
	Content         string  `json:"content"`
	SubmissionCount int     `json:"submissionCount"`
	Status          string  `json:"status"`
}

// Logged is one row of the decision record.
type Logged struct {
	ID           int64     `json:"id"`
	ReportID     string    `json:"reportId"`
	Category     string    `json:"category"` // category name of the report that was decided
	Sender       *Sender   `json:"sender"`   // null when that report had no sender
	Moderator    string    `json:"moderator"`
	Decision     string    `json:"decision"` // approved | rejected | merged
	MergedIntoID *string   `json:"mergedIntoId"`
	Reason       *string   `json:"reason"`
	DecidedAt    time.Time `json:"decidedAt"`
}

// ---- what the handlers need from the database layer (implemented by internal/store) ----

type Kind string

const (
	Approved Kind = "approved"
	Rejected Kind = "rejected"
	Merged   Kind = "merged"
)

type Decision struct {
	ReportID    string
	Moderator   string // the name the moderator typed in; recorded with the decision
	Kind        Kind
	MergeIntoID string // only for Merged
	Reason      string
}

// ErrNotApplicable means nothing was changed: the report was already decided, is no longer
// in the queue, or the merge target is not usable.
var ErrNotApplicable = errors.New("decision not applicable")

type Store interface {
	ModQueue(ctx context.Context, page, pageSize int) (Queue, error)
	ModCandidates(ctx context.Context, reportID string) ([]Candidate, error)
	Decide(ctx context.Context, d Decision) error
	ModHistory(ctx context.Context, limit int) ([]Logged, error)
}

// Provider returns the Store, connecting on first use (same pattern as the other handlers).
type Provider func(ctx context.Context) (Store, error)

// ---- settings ----

const (
	timeout        = 10 * time.Second
	maxBody        = 8 << 10
	maxReasonRunes = 500
	minRejectRunes = 3
	minNameRunes   = 2
	maxNameRunes   = 60

	unavailableMsg = "The review queue is temporarily unavailable. Please try again in a moment."
	failedMsg      = "Something went wrong on our side. Please try again."
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	writeError(w, http.StatusMethodNotAllowed, "That kind of request isn't supported.")
	return false
}

// postJSON checks the method and content type, then decodes the body into v.
func postJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "That kind of request isn't supported.")
		return false
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "That kind of request isn't supported.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "We could not read that. Please try again.")
		return false
	}
	return true
}

func open(w http.ResponseWriter, r *http.Request, get Provider) (Store, context.Context, context.CancelFunc, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	st, err := get(ctx)
	if err != nil {
		cancel()
		log.Printf("moderation: database unavailable: %v", err)
		writeError(w, http.StatusServiceUnavailable, unavailableMsg)
		return nil, nil, nil, false
	}
	return st, ctx, cancel, true
}

func intParam(r *http.Request, name string, def, min, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n < min {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func normalizeID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	return s, uuidRe.MatchString(s)
}

// cleanName accepts a person's name: letters, digits, spaces and . ' ’ - only.
func cleanName(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	n := utf8.RuneCountInString(s)
	if n < minNameRunes || n > maxNameRunes {
		return "", false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(" .'’-", r) {
			return "", false
		}
	}
	return s, true
}

// ---- handlers ----

// ReviewQueue lists the reports waiting for a decision.
func ReviewQueue(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		page := intParam(r, "page", 1, 1, 10000)
		size := intParam(r, "pageSize", 10, 1, 50)

		st, ctx, cancel, ok := open(w, r, get)
		if !ok {
			return
		}
		defer cancel()

		q, err := st.ModQueue(ctx, page, size)
		if err != nil {
			log.Printf("moderation: queue failed: %v", err)
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}
		if q.Results == nil {
			q.Results = []Item{}
		}
		writeJSON(w, http.StatusOK, q)
	}
}

// Candidates lists reports the given report could be merged into.
func Candidates(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		id, ok := normalizeID(r.URL.Query().Get("id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "That report could not be found.")
			return
		}

		st, ctx, cancel, ok := open(w, r, get)
		if !ok {
			return
		}
		defer cancel()

		list, err := st.ModCandidates(ctx, id)
		if err != nil {
			log.Printf("moderation: candidates failed: %v", err)
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}
		if list == nil {
			list = []Candidate{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": list})
	}
}

type decisionRequest struct {
	ReportID    string `json:"reportId"`
	Decision    string `json:"decision"`
	Moderator   string `json:"moderator"`
	MergeIntoID string `json:"mergeIntoId"`
	Reason      string `json:"reason"`
}

// Decide approves, rejects or merges one report and records the decision.
func Decide(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req decisionRequest
		if !postJSON(w, r, &req) {
			return
		}

		var ok bool
		d := Decision{Reason: strings.TrimSpace(req.Reason)}

		if d.Moderator, ok = cleanName(req.Moderator); !ok {
			writeError(w, http.StatusBadRequest, "Please enter your name (2 to 60 letters) so the decision can be recorded.")
			return
		}
		if d.ReportID, ok = normalizeID(req.ReportID); !ok {
			writeError(w, http.StatusBadRequest, "That report could not be found.")
			return
		}
		if utf8.RuneCountInString(d.Reason) > maxReasonRunes {
			writeError(w, http.StatusBadRequest, "Please keep the reason under 500 characters.")
			return
		}

		switch req.Decision {
		case "approve":
			d.Kind = Approved
		case "reject":
			d.Kind = Rejected
			if utf8.RuneCountInString(d.Reason) < minRejectRunes {
				writeError(w, http.StatusBadRequest, "Please give a short reason for rejecting this report.")
				return
			}
		case "merge":
			d.Kind = Merged
			if d.MergeIntoID, ok = normalizeID(req.MergeIntoID); !ok {
				writeError(w, http.StatusBadRequest, "Please choose the report to merge this into.")
				return
			}
			if d.MergeIntoID == d.ReportID {
				writeError(w, http.StatusBadRequest, "A report can't be merged into itself.")
				return
			}
		default:
			writeError(w, http.StatusBadRequest, "Please choose approve, reject or merge.")
			return
		}

		st, ctx, cancel, ok := open(w, r, get)
		if !ok {
			return
		}
		defer cancel()

		err := st.Decide(ctx, d)
		if errors.Is(err, ErrNotApplicable) {
			writeError(w, http.StatusConflict,
				"That report is no longer waiting for review, or the merge target can't be used. Refresh the queue and try again.")
			return
		}
		if err != nil {
			log.Printf("moderation: decision failed: %v", err) // never log the reason, name or report text
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "decision": string(d.Kind)})
	}
}

// History lists the most recent decisions (the record of who decided what, and why).
func History(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		limit := intParam(r, "limit", 25, 1, 100)

		st, ctx, cancel, ok := open(w, r, get)
		if !ok {
			return
		}
		defer cancel()

		list, err := st.ModHistory(ctx, limit)
		if err != nil {
			log.Printf("moderation: history failed: %v", err)
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}
		if list == nil {
			list = []Logged{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": list})
	}
}
