-- db/moderation.sql
-- 
-- The report side already exists: scam_reports has status ('pending_review', 'approved',
-- 'rejected', 'merged') and merged_into_id, and the public_reports view only shows
-- status = 'approved'. This adds the record of every decision ("decisions must be documented").
--

BEGIN;

CREATE TABLE IF NOT EXISTS moderation_decisions (
    id             BIGSERIAL PRIMARY KEY,
    report_id      UUID        NOT NULL REFERENCES scam_reports (id),
    moderator      TEXT        NOT NULL CHECK (char_length(moderator) BETWEEN 2 AND 60),
    decision       TEXT        NOT NULL CHECK (decision IN ('approved', 'rejected', 'merged')),
    merged_into_id UUID        REFERENCES scam_reports (id),
    reason         TEXT,
    decided_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (decision <> 'merged' OR merged_into_id IS NOT NULL),
    CHECK (decision = 'merged' OR merged_into_id IS NULL),
    CHECK (reason IS NULL OR char_length(reason) <= 500)
);

CREATE INDEX IF NOT EXISTS idx_decisions_report ON moderation_decisions (report_id);
CREATE INDEX IF NOT EXISTS idx_decisions_time   ON moderation_decisions (decided_at DESC, id DESC);

-- The record is append-only: a row can never be edited or removed, not even by the application.
CREATE OR REPLACE FUNCTION moderation_decisions_readonly() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'moderation_decisions is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_decisions_readonly ON moderation_decisions;
CREATE TRIGGER trg_decisions_readonly
    BEFORE UPDATE OR DELETE ON moderation_decisions
    FOR EACH ROW EXECUTE FUNCTION moderation_decisions_readonly();

COMMIT;
