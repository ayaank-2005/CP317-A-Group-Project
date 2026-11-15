// internal/store/moderation.go
// Database side of report review (MOD-1). Implements moderation.Store using the same pool.
// Decisions record the moderator's typed name (no user accounts yet); see db/moderation.sql.
//
// Each decision is ONE SQL statement (data-modifying CTEs), so the report change and the log row
// either both happen or neither does, and a report can only be decided once: the UPDATE only
// matches while status = 'pending_review'. Every value is a parameter ($1, $2 ...).
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"scamshield/internal/moderation"
)

var _ moderation.Store = (*Store)(nil)

const (
	// Oldest first, so nothing waits forever. Only redacted text is ever selected.
	sqlModQueue = `SELECT r.id::text, c.code, c.name, s.sender_type, s.value,
			r.redacted_content, r.submission_count, r.language, r.created_at
		FROM scam_reports r
		JOIN scam_categories c ON c.id = r.category_id
		LEFT JOIN senders s ON s.id = r.sender_id
		WHERE r.status = 'pending_review'
		ORDER BY r.created_at, r.id
		LIMIT $1::bigint OFFSET $2::bigint`

	sqlModQueueCount = `SELECT count(*) FROM scam_reports WHERE status = 'pending_review'`

	// Possible merge targets: same category, not the report itself, still alive.
	// Reports from the same sender come first, then the busiest.
	sqlModCandidates = `SELECT r.id::text, s.sender_type, s.value, r.redacted_content, r.submission_count, r.status
		FROM scam_reports r
		LEFT JOIN senders s ON s.id = r.sender_id
		WHERE r.id <> $1::uuid
		  AND r.status IN ('collecting', 'pending_review', 'approved')
		  AND r.category_id = (SELECT category_id FROM scam_reports WHERE id = $1::uuid)
		ORDER BY (r.sender_id IS NOT DISTINCT FROM (SELECT sender_id FROM scam_reports WHERE id = $1::uuid)) DESC,
		         r.submission_count DESC, r.created_at
		LIMIT 20`

	sqlApprove = `WITH upd AS (
			UPDATE scam_reports
			SET status = 'approved', approved_at = now()
			WHERE id = $1::uuid AND status = 'pending_review'
			RETURNING id)
		INSERT INTO moderation_decisions (report_id, moderator, decision, reason)
		SELECT id, $2::text, 'approved', NULLIF($3::text, '') FROM upd
		RETURNING id`

	sqlReject = `WITH upd AS (
			UPDATE scam_reports
			SET status = 'rejected'
			WHERE id = $1::uuid AND status = 'pending_review'
			RETURNING id)
		INSERT INTO moderation_decisions (report_id, moderator, decision, reason)
		SELECT id, $2::text, 'rejected', NULLIF($3::text, '') FROM upd
		RETURNING id`

	// Merge: the duplicate ($1) becomes 'merged' and points at the target ($3); the target gains the
	// duplicate's submission count. The target must be alive, in the same category, and not the
	// duplicate itself. If anything does not hold, nothing changes and no row is returned.
	sqlMerge = `WITH src AS (
			SELECT id, category_id, submission_count FROM scam_reports
			WHERE id = $1::uuid AND status = 'pending_review' FOR UPDATE),
		tgt AS (
			SELECT t.id FROM scam_reports t, src
			WHERE t.id = $3::uuid AND t.id <> src.id
			  AND t.category_id = src.category_id
			  AND t.status IN ('collecting', 'pending_review', 'approved')
			FOR UPDATE OF t),
		merged AS (
			UPDATE scam_reports
			SET status = 'merged', merged_into_id = (SELECT id FROM tgt)
			WHERE id = (SELECT id FROM src) AND EXISTS (SELECT 1 FROM tgt)
			RETURNING id),
		bumped AS (
			UPDATE scam_reports
			SET submission_count = submission_count + (SELECT submission_count FROM src)
			WHERE id = (SELECT id FROM tgt) AND EXISTS (SELECT 1 FROM merged)
			RETURNING id)
		INSERT INTO moderation_decisions (report_id, moderator, decision, merged_into_id, reason)
		SELECT id, $2::text, 'merged', $3::uuid, NULLIF($4::text, '') FROM merged
		RETURNING id`

	sqlModHistory = `SELECT d.id, d.report_id::text, c.name, s.sender_type, s.value,
			d.moderator, d.decision, d.merged_into_id::text, d.reason, d.decided_at
		FROM moderation_decisions d
		JOIN scam_reports r ON r.id = d.report_id
		JOIN scam_categories c ON c.id = r.category_id
		LEFT JOIN senders s ON s.id = r.sender_id
		ORDER BY d.decided_at DESC, d.id DESC
		LIMIT $1::bigint`
)

func (s *Store) ModQueue(ctx context.Context, page, pageSize int) (moderation.Queue, error) {
	q := moderation.Queue{Results: []moderation.Item{}, Page: page, PageSize: pageSize}

	if err := s.pool.QueryRow(ctx, sqlModQueueCount).Scan(&q.Total); err != nil {
		return q, err
	}
	if q.Total == 0 {
		return q, nil
	}

	rows, err := s.pool.Query(ctx, sqlModQueue, pageSize, (page-1)*pageSize)
	if err != nil {
		return q, err
	}
	defer rows.Close()

	for rows.Next() {
		var it moderation.Item
		var sType, sValue *string // a report can have no sender
		if err := rows.Scan(&it.ID, &it.Category.Code, &it.Category.Name, &sType, &sValue,
			&it.Content, &it.SubmissionCount, &it.Language, &it.CreatedAt); err != nil {
			return q, err
		}
		if sType != nil && sValue != nil {
			it.Sender = &moderation.Sender{Type: *sType, Value: *sValue}
		}
		q.Results = append(q.Results, it)
	}
	return q, rows.Err()
}

func (s *Store) ModCandidates(ctx context.Context, reportID string) ([]moderation.Candidate, error) {
	rows, err := s.pool.Query(ctx, sqlModCandidates, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []moderation.Candidate{}
	for rows.Next() {
		var c moderation.Candidate
		var sType, sValue *string
		if err := rows.Scan(&c.ID, &sType, &sValue, &c.Content, &c.SubmissionCount, &c.Status); err != nil {
			return nil, err
		}
		if sType != nil && sValue != nil {
			c.Sender = &moderation.Sender{Type: *sType, Value: *sValue}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Decide applies one decision. It returns moderation.ErrNotApplicable when nothing changed
// (already decided, no longer in the queue, or an unusable merge target).
func (s *Store) Decide(ctx context.Context, d moderation.Decision) error {
	var logID int64
	var err error

	switch d.Kind {
	case moderation.Approved:
		err = s.pool.QueryRow(ctx, sqlApprove, d.ReportID, d.Moderator, d.Reason).Scan(&logID)
	case moderation.Rejected:
		err = s.pool.QueryRow(ctx, sqlReject, d.ReportID, d.Moderator, d.Reason).Scan(&logID)
	case moderation.Merged:
		err = s.pool.QueryRow(ctx, sqlMerge, d.ReportID, d.Moderator, d.MergeIntoID, d.Reason).Scan(&logID)
	default:
		return moderation.ErrNotApplicable
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return moderation.ErrNotApplicable
	}
	return err
}

func (s *Store) ModHistory(ctx context.Context, limit int) ([]moderation.Logged, error) {
	rows, err := s.pool.Query(ctx, sqlModHistory, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []moderation.Logged{}
	for rows.Next() {
		var l moderation.Logged
		var sType, sValue *string
		if err := rows.Scan(&l.ID, &l.ReportID, &l.Category, &sType, &sValue,
			&l.Moderator, &l.Decision, &l.MergedIntoID, &l.Reason, &l.DecidedAt); err != nil {
			return nil, err
		}
		if sType != nil && sValue != nil {
			l.Sender = &moderation.Sender{Type: *sType, Value: *sValue}
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
