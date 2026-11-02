-- ScamShield schema (PostgreSQL 14+)

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- fuzzy sender / keyword search / helps users search for with typos

-- ---------------------------------------------------------------
-- Accounts and roles (public visitors are anonymous and have no row)
-- ---------------------------------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL, -- argon2id or bcrypt, never plaintext
    role TEXT NOT NULL DEFAULT 'user' CHECK (
        role IN (
            'user',
            'moderator',
            'analyst'
        )
    ),
    preferred_language TEXT NOT NULL DEFAULT 'en', -- UI-2: explanations in user's language
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_users_email ON users (lower(email));

REATE TABLE scam_categories (
    id SMALLSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

INSERT INTO
    scam_categories (code, name)
VALUES ('bank', 'Bank impersonation'),
    ('delivery', 'Fake delivery notice'),
    ('job', 'Job scam'),
    ('government', 'Government / CRA impersonation'),
    ('phishing', 'Phishing'),
    ('romance', 'Romance scam'),
    ('investment', 'Investment scam'),
    ('other', 'Other');

CREATE TABLE report_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    report_id UUID NOT NULL REFERENCES scam_reports (id) ON DELETE CASCADE,
    submitter_id UUID REFERENCES users (id), -- NULL = anonymous
    redacted_content TEXT NOT NULL,
    redaction_count SMALLINT NOT NULL DEFAULT 0, -- shown as "2 personal details masked"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_submissions_report ON report_submissions (report_id);

CREATE TABLE senders (
    id BIGSERIAL PRIMARY KEY,
    sender_type TEXT NOT NULL CHECK (
        sender_type IN ('phone', 'domain', 'email')
    ),
    value TEXT NOT NULL, -- normalised: E.164 phone, lowercase domain
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (sender_type, value)
);

CREATE INDEX idx_senders_value_trgm ON senders USING gin (value gin_trgm_ops);

CREATE TABLE scam_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    category_id SMALLINT NOT NULL REFERENCES scam_categories (id),
    sender_id BIGINT REFERENCES senders (id),
    fingerprint TEXT, -- content hash, groups reports with no sender
    redacted_content TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'en',
    -- collecting: waiting for enough similar submissions (UI-3)
    -- pending_review: threshold reached, visible in moderator queue
    status TEXT NOT NULL DEFAULT 'collecting' CHECK (
        status IN (
            'collecting',
            'pending_review',
            'approved',
            'rejected',
            'merged'
        )
    ),
    submission_count INT NOT NULL DEFAULT 0,
    review_threshold INT NOT NULL DEFAULT 5,
    merged_into_id UUID REFERENCES scam_reports (id),
    reviewed_by UUID REFERENCES users (id),
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_vector tsvector GENERATED ALWAYS AS (
        to_tsvector(
            'english',
            coalesce(redacted_content, '')
        )
    ) STORED,
    CHECK (
        status <> 'merged'
        OR merged_into_id IS NOT NULL
    )
);

CREATE INDEX idx_reports_search ON scam_reports USING gin (search_vector);

CREATE INDEX idx_reports_public ON scam_reports (category_id, approved_at DESC)
WHERE
    status = 'approved';

CREATE INDEX idx_reports_queue ON scam_reports (created_at)
WHERE
    status = 'pending_review';
-- Only one open group per sender+category, so new submissions attach to it
CREATE UNIQUE INDEX uq_reports_open_group ON scam_reports (sender_id, category_id)
WHERE
    sender_id IS NOT NULL
    AND status IN (
        'collecting',
        'pending_review'
    );

CREATE TABLE report_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    report_id UUID NOT NULL REFERENCES scam_reports (id) ON DELETE CASCADE,
    submitter_id UUID REFERENCES users (id), -- NULL = anonymous
    redacted_content TEXT NOT NULL,
    redaction_count SMALLINT NOT NULL DEFAULT 0, -- shown as "2 personal details masked"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_submissions_report ON report_submissions (report_id);
