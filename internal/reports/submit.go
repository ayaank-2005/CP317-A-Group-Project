
package reports

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type Submission struct {
	Category   string `json:"category"`
	SenderType string `json:"senderType"`
	Sender     string `json:"sender"`
	Content    string `json:"content"`
	Language   string `json:"language"`
}

type SubmissionResult struct {
	ReportID        string `json:"reportId"`
	Status          string `json:"status"`
	SubmissionCount int    `json:"submissionCount"`
	RedactionCount  int    `json:"redactionCount"`
}

type Submitter interface {
	SubmitReport(context.Context, Submission) (SubmissionResult, error)
}

type SubmitProvider func(context.Context) (Submitter, error)

// Handles report submissions by validating the request and saving it through the database.
func Submit(get SubmitProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "That kind of request isn't supported.")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

		var req Submission
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Please check your submission and try again.")
			return
		}

		// Cleans up the submitted values before validation.
		req.Category = strings.TrimSpace(strings.ToLower(req.Category))
		req.SenderType = strings.TrimSpace(strings.ToLower(req.SenderType))
		req.Sender = strings.TrimSpace(req.Sender)
		req.Content = strings.TrimSpace(req.Content)
		req.Language = strings.TrimSpace(strings.ToLower(req.Language))

		// Validates the required category and report description.
		if req.Category == "" {
			writeError(w, http.StatusBadRequest, "Please choose a scam category.")
			return
		}

		if req.Content == "" || utf8.RuneCountInString(req.Content) < 10 {
			writeError(w, http.StatusBadRequest, "Please provide at least 10 characters describing the scam.")
			return
		}

		if utf8.RuneCountInString(req.Content) > 10000 {
			writeError(w, http.StatusBadRequest, "Your description is too long. Please keep it under 10,000 characters.")
			return
		}

		// Validates and normalizes the optional sender information.
		if (req.SenderType == "") != (req.Sender == "") {
			writeError(w, http.StatusBadRequest, "Please provide both the sender type and sender value, or leave both empty.")
			return
		}

		switch req.SenderType {
		case "":
	
		case "phone":
			normalized, ok := NormalizePhone(req.Sender)
			if !ok {
				writeError(w, http.StatusBadRequest, "Please enter a valid North American phone number.")
				return
			}
			req.Sender = normalized
		case "domain":
			req.Sender = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(req.Sender, "https://"), "http://"))
			req.Sender = strings.TrimPrefix(req.Sender, "www.")
			if strings.ContainsAny(req.Sender, " /?#@") || !strings.Contains(req.Sender, ".") {
				writeError(w, http.StatusBadRequest, "Please enter a valid website domain.")
				return
			}
		case "email":
			req.Sender = strings.ToLower(req.Sender)
			if !strings.Contains(req.Sender, "@") || !strings.Contains(strings.SplitN(req.Sender, "@", 2)[1], ".") {
				writeError(w, http.StatusBadRequest, "Please enter a valid email address.")
				return
			}
		default:
			writeError(w, http.StatusBadRequest, "Please choose a valid sender type.")
			return
		}

		// Sets a default language and limits the accepted language value.
		if req.Language == "" {
			req.Language = "en"
		}
		if len(req.Language) > 10 {
			req.Language = "en"
		}

		// Connects to the database and saves the report.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		s, err := get(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, unavailableMsg)
			return
		}

		result, err := s.SubmitReport(ctx, req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "We couldn't submit your report. Please try again.")
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, result)
	}
}

