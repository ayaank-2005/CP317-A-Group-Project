
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"scamshield/internal/redact"
	"scamshield/internal/reports"
)

// Saves a report, groups similar submissions, and updates its review status.
func (s *Store) SubmitReport(ctx context.Context, submission reports.Submission) (reports.SubmissionResult, error) {
	var result reports.SubmissionResult

	// Masks personal information and generates a fingerprint for grouping reports.
	masked := redact.Mask(submission.Content)
	fingerprintInput := strings.ToLower(strings.Join(strings.Fields(masked.Content), " "))
	hash := sha256.Sum256([]byte(fingerprintInput))
	fingerprint := hex.EncodeToString(hash[:])

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)

	var categoryID int16
	err = tx.QueryRow(ctx,
		`SELECT id FROM scam_categories WHERE code = $1`,
		submission.Category,
	).Scan(&categoryID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return result, errors.New("unknown scam category")
		}
		return result, err
	}

	var senderID *int64

	// Finds or creates a sender record when sender information is provided.
	if submission.SenderType != "" {
		var id int64

		err = tx.QueryRow(ctx, `
			INSERT INTO senders (sender_type, value)
			VALUES ($1, $2)
			ON CONFLICT (sender_type, value)
			DO UPDATE SET value = EXCLUDED.value
			RETURNING id
		`, submission.SenderType, submission.Sender).Scan(&id)

		if err != nil {
			return result, err
		}

		senderID = &id
	}

	// Locks submissions in the same sender/category or content/category group.
	lockKey := submission.Category + ":" + fingerprint
	if senderID != nil {
		lockKey = submission.Category + ":" + submission.SenderType + ":" + submission.Sender
	}

	_, err = tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`,
		lockKey,
	)
	if err != nil {
		return result, err
	}

	var reportID string

	// Looks for an existing open report before creating a new group.
	if senderID != nil {
		err = tx.QueryRow(ctx, `
			SELECT id
			FROM scam_reports
			WHERE sender_id = $1
			  AND category_id = $2
			  AND status IN ('collecting', 'pending_review')
			FOR UPDATE
		`, *senderID, categoryID).Scan(&reportID)
	} else {
		err = tx.QueryRow(ctx, `
			SELECT id
			FROM scam_reports
			WHERE sender_id IS NULL
			  AND category_id = $1
			  AND fingerprint = $2
			  AND status IN ('collecting', 'pending_review')
			FOR UPDATE
		`, categoryID, fingerprint).Scan(&reportID)
	}

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			INSERT INTO scam_reports (
				category_id,
				sender_id,
				fingerprint,
				redacted_content,
				language,
				status
			)
			VALUES ($1, $2, $3, $4, $5, 'collecting')
			RETURNING id
		`,
			categoryID,
			senderID,
			fingerprint,
			masked.Content,
			submission.Language,
		).Scan(&reportID)

		if err != nil {
			return result, err
		}
	}

	// Stores the individual submission and its redaction count.
	_, err = tx.Exec(ctx, `
		INSERT INTO report_submissions (
			report_id,
			redacted_content,
			redaction_count
		)
		VALUES ($1, $2, $3)
	`,
		reportID,
		masked.Content,
		masked.Count,
	)

	if err != nil {
		return result, err
	}

	// Increments the submission count and moves eligible reports to review.
	err = tx.QueryRow(ctx, `
		UPDATE scam_reports
		SET
			submission_count = submission_count + 1,
			status = CASE
				WHEN status = 'collecting'
				 AND submission_count + 1 >= review_threshold
				THEN 'pending_review'
				ELSE status
			END
		WHERE id = $1
		RETURNING status, submission_count
	`, reportID).Scan(&result.Status, &result.SubmissionCount)

	if err != nil {
		return result, err
	}

	if err := tx.Commit(ctx); err != nil {
		return result, err
	}

	result.ReportID = reportID
	result.RedactionCount = masked.Count

	return result, nil
}
