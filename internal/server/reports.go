package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"scamshield/internal/redact"
	"scamshield/internal/reportstatus"
)

const (
	defaultPageSize = 10
	maxPageSize     = 50
	maxQueryLength  = 200
	myReportsLimit  = 200
)

type category struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type sender struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// publicReport is the card shape database.js renders.
type publicReport struct {
	ID          string     `json:"id"`
	Content     string     `json:"content"`
	Category    category   `json:"category"`
	Sender      *sender    `json:"sender"`
	ReportCount int        `json:"reportCount"`
	ApprovedAt  *time.Time `json:"approvedAt"`
	Language    string     `json:"language"`
}

const publicReportColumns = `
	r.id::text, r.redacted_content, c.code, c.name, s.sender_type, s.value,
	r.submission_count, r.approved_at, r.language`

const publicReportJoins = `
	FROM scam_reports r
	JOIN scam_categories c ON c.id = r.category_id
	LEFT JOIN senders s ON s.id = r.sender_id`

func scanPublicReport(row pgx.Row, extra ...any) (publicReport, error) {
	var p publicReport
	var senderType, senderValue *string
	dest := append([]any{
		&p.ID, &p.Content, &p.Category.Code, &p.Category.Name, &senderType, &senderValue,
		&p.ReportCount, &p.ApprovedAt, &p.Language,
	}, extra...)
	if err := row.Scan(dest...); err != nil {
		return p, err
	}
	if senderType != nil && senderValue != nil {
		p.Sender = &sender{Type: *senderType, Value: *senderValue}
	}
	return p, nil
}

func (a *App) handleCategories(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT code, name FROM scam_categories ORDER BY id`)
	if err != nil {
		serverError(w, err)
		return
	}
	cats, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (category, error) {
		var c category
		return c, row.Scan(&c.Code, &c.Name)
	})
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cats)
}

func positiveInt(value string, fallback, max int) int {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return fallback
	}
	if max > 0 && n > max {
		return max
	}
	return n
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (a *App) handleSearchReports(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	q := strings.TrimSpace(query.Get("q"))
	if len(q) > maxQueryLength {
		q = q[:maxQueryLength]
	}
	cat := query.Get("category")
	page := positiveInt(query.Get("page"), 1, 0)
	pageSize := positiveInt(query.Get("pageSize"), defaultPageSize, maxPageSize)

	rows, err := a.db.Query(r.Context(), `
		SELECT `+publicReportColumns+`, count(*) OVER ()
		`+publicReportJoins+`
		WHERE r.status = 'approved'
		  AND ($1 = '' OR c.code = $1)
		  AND ($2 = ''
		       OR r.search_vector @@ plainto_tsquery('english', $2)
		       OR s.value ILIKE '%' || $3 || '%'
		       OR r.redacted_content ILIKE '%' || $3 || '%')
		ORDER BY r.approved_at DESC NULLS LAST, r.id
		LIMIT $4 OFFSET $5`,
		cat, q, escapeLike(q), pageSize, (page-1)*pageSize)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	results := []publicReport{}
	total := 0
	for rows.Next() {
		p, err := scanPublicReport(rows, &total)
		if err != nil {
			serverError(w, err)
			return
		}
		results = append(results, p)
	}
	if err := rows.Err(); err != nil {
		serverError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results":  results,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// handlePublicReport returns an Approved report, or for a Merged report
// the ID of the report it was merged into so the page can follow it.
func (a *App) handlePublicReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reportstatus.IsValidID(id) {
		writeError(w, http.StatusNotFound, "We couldn't find that report.")
		return
	}

	var dbStatus, mergedInto string
	p, err := scanPublicReport(a.db.QueryRow(r.Context(), `
		SELECT `+publicReportColumns+`, r.status, coalesce(r.merged_into_id::text, '')
		`+publicReportJoins+`
		WHERE r.id = $1`, id), &dbStatus, &mergedInto)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "We couldn't find that report.")
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}

	status, _ := reportstatus.FromDB(dbStatus)
	switch public := reportstatus.PublicReportID(status, p.ID, mergedInto); {
	case public == "":
		writeError(w, http.StatusNotFound, "This report isn't public.")
	case public != p.ID:
		writeJSON(w, http.StatusOK, map[string]string{"mergedInto": public})
	default:
		writeJSON(w, http.StatusOK, map[string]publicReport{"report": p})
	}
}

func (a *App) handleSubmitReport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Category string  `json:"category"`
		Content  string  `json:"content"`
		Sender   *sender `json:"sender"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	var senderValue string
	if body.Sender != nil && strings.TrimSpace(body.Sender.Value) != "" {
		v, err := normalizeSender(body.Sender.Type, body.Sender.Value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		senderValue = v
	}
	user, err := a.currentUser(r.Context(), r)
	if err != nil {
		serverError(w, err)
		return
	}

	content := strings.TrimSpace(body.Content)
	if content == "" {
		writeError(w, http.StatusBadRequest, "Please paste the scam message you received.")
		return
	}
	masked := redact.Mask(content)
	if len(masked.Content) > reportstatus.MaxContent {
		writeError(w, http.StatusBadRequest, "Your report is too long. Please keep it under "+
			strconv.Itoa(reportstatus.MaxContent)+" characters.")
		return
	}

	reportID, err := reportstatus.NewID()
	if err != nil {
		serverError(w, err)
		return
	}
	submissionID, err := reportstatus.NewID()
	if err != nil {
		serverError(w, err)
		return
	}
	var submitter *string
	if user != nil {
		submitter = &user.ID
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	var categoryID int
	err = tx.QueryRow(r.Context(), `SELECT id FROM scam_categories WHERE code = $1`, body.Category).Scan(&categoryID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusBadRequest, "Please choose what type of scam this is.")
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}

	var senderID *int64
	if senderValue != "" {
		var id int64
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO senders (sender_type, value) VALUES ($1, $2)
			ON CONFLICT (sender_type, value) DO UPDATE SET value = EXCLUDED.value
			RETURNING id`, body.Sender.Type, senderValue).Scan(&id); err != nil {
			serverError(w, err)
			return
		}
		senderID = &id
	}

	// The schema allows one open report per sender and category, so a
	// submission about a known sender joins it. The 'collecting' threshold
	// (UI-3) is not implemented: new reports go straight to review.
	for attempt := 0; attempt < 3; attempt++ {
		if senderID != nil {
			var existing string
			err := tx.QueryRow(r.Context(), `
				SELECT id::text FROM scam_reports
				WHERE sender_id = $1 AND category_id = $2
				  AND status IN ('collecting', 'pending_review')
				FOR UPDATE`, *senderID, categoryID).Scan(&existing)
			if err == nil {
				if _, err := tx.Exec(r.Context(),
					`UPDATE scam_reports SET submission_count = submission_count + 1 WHERE id = $1`,
					existing); err != nil {
					serverError(w, err)
					return
				}
				reportID = existing
				break
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				serverError(w, err)
				return
			}
		}
		tag, err := tx.Exec(r.Context(), `
			INSERT INTO scam_reports (id, category_id, sender_id, redacted_content, status, submission_count)
			VALUES ($1, $2, $3, $4, $5, 1)
			ON CONFLICT (sender_id, category_id)
			    WHERE sender_id IS NOT NULL AND status IN ('collecting', 'pending_review')
			DO NOTHING`,
			reportID, categoryID, senderID, masked.Content, reportstatus.Pending.DB())
		if err != nil {
			serverError(w, err)
			return
		}
		if tag.RowsAffected() == 1 {
			break
		}
		// Another request opened the report first; join it on the next pass.
	}
	if _, err := tx.Exec(r.Context(), `
		INSERT INTO report_submissions (id, report_id, submitter_id, redacted_content, redaction_count)
		VALUES ($1, $2, $3, $4, $5)`,
		submissionID, reportID, submitter, masked.Content, masked.Count); err != nil {
		serverError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             submissionID,
		"status":         reportstatus.Pending.String(),
		"redactionCount": masked.Count,
		"tracked":        user != nil,
	})
}

type myReport struct {
	ID             string     `json:"id"`
	ReportID       string     `json:"reportId"`
	Status         string     `json:"status"`
	Content        string     `json:"content"`
	RedactionCount int        `json:"redactionCount"`
	Category       category   `json:"category"`
	SubmittedAt    time.Time  `json:"submittedAt"`
	DecidedAt      *time.Time `json:"decidedAt"`
	PublicReportID *string    `json:"publicReportId"`
}

func (a *App) handleMyReports(w http.ResponseWriter, r *http.Request) {
	user := a.requireUser(w, r)
	if user == nil {
		return
	}

	rows, err := a.db.Query(r.Context(), `
		SELECT s.id::text, r.id::text, r.status, coalesce(r.merged_into_id::text, ''),
		       s.redacted_content, s.redaction_count, c.code, c.name,
		       s.created_at, r.reviewed_at
		FROM report_submissions s
		JOIN scam_reports r ON r.id = s.report_id
		JOIN scam_categories c ON c.id = r.category_id
		WHERE s.submitter_id = $1
		ORDER BY s.created_at DESC, s.id
		LIMIT $2`, user.ID, myReportsLimit)
	if err != nil {
		serverError(w, err)
		return
	}

	reports, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (myReport, error) {
		var m myReport
		var dbStatus, mergedInto string
		if err := row.Scan(&m.ID, &m.ReportID, &dbStatus, &mergedInto, &m.Content,
			&m.RedactionCount, &m.Category.Code, &m.Category.Name,
			&m.SubmittedAt, &m.DecidedAt); err != nil {
			return m, err
		}
		status, ok := reportstatus.FromDB(dbStatus)
		if !ok {
			return m, errors.New("unknown report status " + dbStatus)
		}
		m.Status = status.String()
		if public := reportstatus.PublicReportID(status, m.ReportID, mergedInto); public != "" {
			m.PublicReportID = &public
		}
		return m, nil
	})
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}
