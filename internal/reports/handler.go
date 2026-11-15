// internal/reports/handlers.go
package reports

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// What the handlers need from the database layer
type Searcher interface {
	SearchReports(ctx context.Context, p Params) (Page, error)
	ListCategories(ctx context.Context) ([]Category, error)
}

type Provider func(ctx context.Context) (Searcher, error)

const (
	unavailableMsg = "The database is temporarily unavailable. Please try again in a moment."
	failedMsg      = "We couldn't complete that search. Please try again."
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
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

func Search(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		p, err := ParseParams(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, "That type of scam isn't recognised. Please choose one from the list.")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		s, err := get(ctx)
		if err != nil {
			log.Printf("reports: database unavailable: %v", err) 
			writeError(w, http.StatusServiceUnavailable, unavailableMsg)
			return
		}
		page, err := s.SearchReports(ctx, p)
		if err != nil {
			log.Printf("reports: search failed: %v", err)
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}

		if page.Results == nil {
			page.Results = []Report{}
		}
		page.Page, page.PageSize = p.Page, p.PageSize
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, page)
	}
}

// Categories handles GET /api/categories
func Categories(get Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		s, err := get(ctx)
		if err != nil {
			log.Printf("reports: database unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, unavailableMsg)
			return
		}
		cats, err := s.ListCategories(ctx)
		if err != nil {
			log.Printf("reports: categories failed: %v", err)
			writeError(w, http.StatusInternalServerError, failedMsg)
			return
		}
		if cats == nil {
			cats = []Category{}
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, cats)
	}
}
