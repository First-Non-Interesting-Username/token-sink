-- 0005 — Phase 6 review workflow (spec §10, §17)
-- Backing tables for the four-agent PoC review, dispute, deletion safeguards,
-- final report, and human-approval tokens for submission / active testing.
--
-- All UUID primary keys are TEXT(36) with a CHECK(length=36) constraint.

PRAGMA foreign_keys = ON;

-- ---- approvals ---------------------------------------------------------
-- Session-scoped human approval tokens. The CLI and UI mint a token
-- and capture it here. Every privileged action (active testing,
-- submission, scope change, deletion) references an approval row by
-- id so the audit log can prove the action was authorized.
CREATE TABLE approvals (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    token           TEXT NOT NULL UNIQUE,
    action          TEXT NOT NULL,         -- active_testing|submission|scope_change|deletion
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(id) ON DELETE CASCADE,
    actor           TEXT NOT NULL,         -- 'human' identity from the CLI/UI
    reason          TEXT NOT NULL DEFAULT '',
    expires_at      TEXT NOT NULL,         -- ISO-8601 UTC
    consumed_at     TEXT,                  -- first use, NULL = unused
    revoked_at      TEXT,                  -- NULL unless explicitly revoked
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_approvals_token ON approvals(token) WHERE revoked_at IS NULL;
CREATE INDEX idx_approvals_campaign ON approvals(campaign_id);

-- ---- submission manifests ---------------------------------------------
-- Records every submission attempt (manifest export or HTTP). The
-- payload is on disk under vulnerabilities/<id>/<version>/submission/.
CREATE TABLE submission_manifests (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    approval_id     TEXT NOT NULL REFERENCES approvals(id) ON DELETE RESTRICT,
    transport       TEXT NOT NULL,         -- manifest_only|http
    target          TEXT NOT NULL,         -- URL, vendor name, or "manifest-only"
    manifest_path   TEXT NOT NULL,
    response_status INTEGER,
    response_body_path TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_submission_finding ON submission_manifests(finding_id);
CREATE INDEX idx_submission_approval ON submission_manifests(approval_id);

-- ---- finding review opinions (cache) -----------------------------------
-- The 4-agent review for a given (finding, version) lives in
-- ``reviews``; this table aggregates verdicts + computed quorum
-- outcome for fast UI rendering and audit.
CREATE TABLE finding_review_summaries (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    mode            TEXT NOT NULL,         -- independent_first|discussion_first
    quorum_policy   TEXT NOT NULL,         -- all_accept | all_accept_or_3_of_4_no_blockers
    reviewer_count  INTEGER NOT NULL,
    accept_count    INTEGER NOT NULL,
    reject_count    INTEGER NOT NULL,
    request_changes_count INTEGER NOT NULL,
    blocking_issues TEXT NOT NULL DEFAULT '[]', -- JSON list
    outcome         TEXT NOT NULL,         -- advance|quarantine|request_changes|inconclusive
    has_dispute     INTEGER NOT NULL DEFAULT 0,
    dispute_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    UNIQUE (finding_id, version, mode)
);
CREATE INDEX idx_review_summaries_finding ON finding_review_summaries(finding_id);

-- ---- dispute reviews ---------------------------------------------------
-- A dispute review is a fresh review authored against a finding that
-- was already concluded (tombstoned or quarantined). The two-review
-- rule for deletion requires at least one dispute review alongside the
-- original.
ALTER TABLE reviews ADD COLUMN dispute_target_id TEXT REFERENCES reviews(id) ON DELETE SET NULL;

-- +mavr down
DROP TABLE IF EXISTS finding_review_summaries;
DROP TABLE IF EXISTS submission_manifests;
DROP TABLE IF EXISTS approvals;
