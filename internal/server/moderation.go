package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"scamshield/internal/reportstatus"
)

const (
	queueLimit        = 100
	mergeTargetsLimit = 50
)

var decisions = map[string]reportstatus.Status{
	"approve": reportstatus.Approved,
	"reject":  reportstatus.Rejected,
	"merge":   reportstatus.Merged,
}

// requireModerator writes a 401/403 and returns nil unless a moderator is
// signed in.
func (a *App) requireModerator(w http.ResponseWriter, r *http.Request) *User {
	user := a.requireUser(w, r)
	if user == nil {
		return nil
	}
	if user.role() != reportstatus.RoleModerator {
		writeError(w, http.StatusForbidden, reportstatus.ErrForbidden.Error())
		return nil
	}
	return user
}

type queueItem struct {
	ID              string    `json:"id"`
	Content         string    `json:"content"`
	Category        category  `json:"category"`
	SubmissionCount int       `json:"submissionCount"`
	CreatedAt       time.Time `json:"createdAt"`
}

func (a *App) collectQueue(r *http.Request, status string, order string, limit int) ([]queueItem, error) {
	rows, err := a.db.Query(r.Context(), `
		SELECT r.id::text, r.redacted_content, c.code, c.name, r.submission_count, r.created_at
		FROM scam_reports r
		JOIN scam_categories c ON c.id = r.category_id
		WHERE r.status = $1
		ORDER BY `+order+`
		LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (queueItem, error) {
		var q queueItem
		return q, row.Scan(&q.ID, &q.Content, &q.Category.Code, &q.Category.Name,
			&q.SubmissionCount, &q.CreatedAt)
	})
}

// handleModerationQueue lists reports awaiting review, oldest first, plus
// recently approved reports that pending ones can be merged into.
func (a *App) handleModerationQueue(w http.ResponseWriter, r *http.Request) {
	if a.requireModerator(w, r) == nil {
		return
	}
	queue, err := a.collectQueue(r, "pending_review", "r.created_at, r.id", queueLimit)
	if err != nil {
		serverError(w, err)
		return
	}
	targets, err := a.collectQueue(r, reportstatus.Approved.DB(), "r.approved_at DESC NULLS LAST, r.id", mergeTargetsLimit)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"queue": queue, "mergeTargets": targets})
}

func decisionErrorStatus(err error) int {
	switch {
	case errors.Is(err, reportstatus.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, reportstatus.ErrTransition):
		return http.StatusConflict
	case errors.Is(err, reportstatus.ErrMergeTarget):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}

func (a *App) handleDecision(w http.ResponseWriter, r *http.Request) {
	user := a.requireModerator(w, r)
	if user == nil {
		return
	}
	var body struct {
		Decision  string `json:"decision"`
		MergeInto string `json:"mergeInto"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	decision, ok := decisions[body.Decision]
	if !ok {
		writeError(w, http.StatusBadRequest, `Decision must be "approve", "reject" or "merge".`)
		return
	}
	id := r.PathValue("id")
	if !reportstatus.IsValidID(id) {
		writeError(w, http.StatusNotFound, reportstatus.ErrNotFound.Error())
		return
	}

	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		serverError(w, err)
		return
	}
	defer tx.Rollback(ctx)

	var dbStatus string
	var submissions int
	err = tx.QueryRow(ctx,
		`SELECT status, submission_count FROM scam_reports WHERE id = $1 FOR UPDATE`, id,
	).Scan(&dbStatus, &submissions)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, reportstatus.ErrNotFound.Error())
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	current, ok := reportstatus.FromDB(dbStatus)
	if !ok {
		serverError(w, errors.New("unknown report status "+dbStatus))
		return
	}

	var target reportstatus.MergeTarget
	var mergeInto *string
	if decision == reportstatus.Merged && reportstatus.IsValidID(body.MergeInto) {
		target.IsSelf = body.MergeInto == id
		var targetStatus string
		// FOR SHARE keeps the target Approved until this merge commits.
		err := tx.QueryRow(ctx,
			`SELECT status FROM scam_reports WHERE id = $1 FOR SHARE`, body.MergeInto,
		).Scan(&targetStatus)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			serverError(w, err)
			return
		}
		if err == nil {
			target.Found = true
			target.Status, _ = reportstatus.FromDB(targetStatus)
		}
		mergeInto = &body.MergeInto
	}

	if err := reportstatus.ValidateDecision(current, user.role(), decision, target); err != nil {
		writeError(w, decisionErrorStatus(err), err.Error())
		return
	}

	if _, err := tx.Exec(ctx, `
		UPDATE scam_reports
		SET status = $2,
		    merged_into_id = $3,
		    reviewed_by = $4,
		    reviewed_at = now(),
		    approved_at = CASE WHEN $2 = 'approved' THEN now() ELSE approved_at END
		WHERE id = $1`,
		id, decision.DB(), mergeInto, user.ID); err != nil {
		serverError(w, err)
		return
	}
	if mergeInto != nil {
		// The public report now speaks for the merged submissions too.
		if _, err := tx.Exec(ctx,
			`UPDATE scam_reports SET submission_count = submission_count + $2 WHERE id = $1`,
			*mergeInto, submissions); err != nil {
			serverError(w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		serverError(w, err)
		return
	}

	resp := map[string]any{"id": id, "status": decision.String()}
	if mergeInto != nil {
		resp["mergedInto"] = *mergeInto
	}
	writeJSON(w, http.StatusOK, resp)
}
