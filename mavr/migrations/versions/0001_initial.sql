-- 0001 — initial schema for MAVR
-- All UUID primary keys are TEXT(36) with a CHECK(length=36) constraint.
-- Content hashes are SHA-256 hex (64 chars).

PRAGMA foreign_keys = ON;

-- ---- shared helpers -----------------------------------------------------
-- A row-version column for optimistic concurrency is included on entities
-- that the orchestrator mutates; default 0 is fine because writes go
-- through SQL helpers that bump it.

-- ---- campaigns ----------------------------------------------------------
CREATE TABLE campaigns (
    id            TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    target_spec   TEXT NOT NULL,           -- JSON: allowed targets
    state         TEXT NOT NULL,           -- draft|active|paused|completed|cancelled
    created_at    TEXT NOT NULL,           -- ISO-8601 UTC
    updated_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    human_approved INTEGER NOT NULL DEFAULT 0,
    duration_hours INTEGER NOT NULL DEFAULT 24,
    token_budget  INTEGER NOT NULL DEFAULT 0,
    tool_budget   INTEGER NOT NULL DEFAULT 0,
    config_snapshot TEXT NOT NULL DEFAULT '{}' -- JSON
);
CREATE INDEX idx_campaigns_state ON campaigns(state);

-- ---- scope policies -----------------------------------------------------
CREATE TABLE scope_policies (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    allowed_targets TEXT NOT NULL,         -- JSON: list of host/url patterns
    allowed_methods TEXT NOT NULL,         -- JSON: list of HTTP methods
    action_allowlist TEXT NOT NULL,        -- JSON: list of action classes
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    active_testing  INTEGER NOT NULL DEFAULT 0,
    explicit_unsafe_networking INTEGER NOT NULL DEFAULT 0,
    human_approved  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_scope_policies_campaign ON scope_policies(campaign_id);

-- ---- agents -------------------------------------------------------------
CREATE TABLE agents (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    parent_id       TEXT REFERENCES agents(id) ON DELETE SET NULL,
    role            TEXT NOT NULL,         -- discovery|research|impact|poc|reviewer|polish|final_review|search|extraction|subagent
    status          TEXT NOT NULL,         -- created|queued|assigned|running|waiting|completed|failed|cancelled|blocked
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE CASCADE,
    task_id         TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    budget_tokens   INTEGER NOT NULL DEFAULT 0,
    budget_time_seconds INTEGER NOT NULL DEFAULT 0,
    budget_tool_calls INTEGER NOT NULL DEFAULT 0,
    budget_network_requests INTEGER NOT NULL DEFAULT 0,
    tokens_used     INTEGER NOT NULL DEFAULT 0,
    time_used_seconds INTEGER NOT NULL DEFAULT 0,
    tool_calls_used INTEGER NOT NULL DEFAULT 0,
    network_requests_used INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_agents_parent ON agents(parent_id);
CREATE INDEX idx_agents_campaign ON agents(campaign_id);
CREATE INDEX idx_agents_status ON agents(status);

-- ---- tasks --------------------------------------------------------------
CREATE TABLE tasks (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    parent_task_id  TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,         -- search|extract|impact|poc|review|polish|submit|...
    status          TEXT NOT NULL,         -- pending|leased|running|completed|failed|cancelled|quarantined
    priority        INTEGER NOT NULL DEFAULT 0,
    payload         TEXT NOT NULL DEFAULT '{}',
    result          TEXT,
    error           TEXT,
    idempotency_key TEXT,
    attempt         INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    lease_owner     TEXT,
    lease_expires_at TEXT,
    lease_heartbeat_at TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT
);
CREATE UNIQUE INDEX idx_tasks_idem ON tasks(idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_tasks_campaign_status ON tasks(campaign_id, status);
CREATE INDEX idx_tasks_priority_created ON tasks(priority DESC, created_at);

-- ---- providers ----------------------------------------------------------
CREATE TABLE providers (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    provider_id     TEXT NOT NULL UNIQUE,   -- stable external id (e.g. "huggingface")
    display_name    TEXT NOT NULL,
    kind            TEXT NOT NULL,          -- native|gateway|custom
    free            INTEGER NOT NULL,       -- 1|0
    free_status     TEXT NOT NULL,          -- confirmed|unknown|paid
    base_url        TEXT,
    auth_status     TEXT NOT NULL,          -- ok|missing|invalid
    capabilities    TEXT NOT NULL DEFAULT '{}',
    context_limit   INTEGER,
    rate_limit_rpm  INTEGER,
    streaming       INTEGER NOT NULL DEFAULT 0,
    tool_support    INTEGER NOT NULL DEFAULT 0,
    structured_output INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_providers_kind ON providers(kind);

-- ---- models -------------------------------------------------------------
CREATE TABLE models (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    provider_id     TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model_key       TEXT NOT NULL,          -- provider-specific id
    display_name    TEXT NOT NULL,
    free            INTEGER NOT NULL,       -- 1|0
    free_status     TEXT NOT NULL,          -- confirmed|unknown|paid
    context_limit   INTEGER,
    tool_support    INTEGER NOT NULL DEFAULT 0,
    structured_output INTEGER NOT NULL DEFAULT 0,
    streaming       INTEGER NOT NULL DEFAULT 0,
    pricing_input_per_mtok REAL,
    pricing_output_per_mtok REAL,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (provider_id, model_key)
);
CREATE INDEX idx_models_free ON models(free);

-- ---- router decisions ---------------------------------------------------
CREATE TABLE router_decisions (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    task_id         TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    router_id       TEXT NOT NULL,
    candidates      TEXT NOT NULL,          -- JSON list
    chosen_model_id TEXT,
    rationale       TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0,
    expected_cost   REAL NOT NULL DEFAULT 0,
    fallback_chain  TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_router_decisions_task ON router_decisions(task_id);

-- ---- search results -----------------------------------------------------
CREATE TABLE search_results (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    task_id         TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    query           TEXT NOT NULL,
    engine          TEXT NOT NULL,
    rank            INTEGER NOT NULL,
    url             TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    snippet         TEXT NOT NULL DEFAULT '',
    source_status   TEXT NOT NULL DEFAULT 'ok',  -- ok|filtered|error
    in_scope        INTEGER NOT NULL DEFAULT 1,
    retrieved_at    TEXT NOT NULL
);
CREATE INDEX idx_search_results_campaign ON search_results(campaign_id);
CREATE INDEX idx_search_results_query ON search_results(query);

-- ---- extracted sources --------------------------------------------------
CREATE TABLE extracted_sources (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    task_id         TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    source_url      TEXT NOT NULL,
    final_url       TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    byte_length     INTEGER NOT NULL,
    content_hash    TEXT NOT NULL CHECK (length(content_hash) = 64),
    raw_artifact_id TEXT NOT NULL,
    extracted_artifact_id TEXT,
    http_status     INTEGER,
    redirect_count  INTEGER NOT NULL DEFAULT 0,
    fetched_at      TEXT NOT NULL,
    extractor       TEXT NOT NULL,          -- curl|jina
    metadata        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_extracted_sources_campaign ON extracted_sources(campaign_id);
CREATE INDEX idx_extracted_sources_hash ON extracted_sources(content_hash);

-- ---- evidence items -----------------------------------------------------
CREATE TABLE evidence_items (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    source_url      TEXT NOT NULL,
    retrieved_at    TEXT NOT NULL,
    content_hash    TEXT NOT NULL CHECK (length(content_hash) = 64),
    byte_length     INTEGER NOT NULL,
    content_type    TEXT NOT NULL,
    raw_artifact_id TEXT NOT NULL,
    extracted_artifact_id TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_evidence_campaign ON evidence_items(campaign_id);
CREATE INDEX idx_evidence_hash ON evidence_items(content_hash);

-- ---- findings -----------------------------------------------------------
CREATE TABLE findings (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    state           TEXT NOT NULL,          -- spec §10 lifecycle state
    severity        TEXT,
    confidence      TEXT,
    current_version INTEGER NOT NULL DEFAULT 1,
    tombstoned      INTEGER NOT NULL DEFAULT 0,
    tombstone_reason TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_findings_campaign ON findings(campaign_id);
CREATE INDEX idx_findings_state ON findings(state);

-- ---- finding_versions ---------------------------------------------------
CREATE TABLE finding_versions (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    state           TEXT NOT NULL,
    author_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
    summary         TEXT NOT NULL,
    body_markdown   TEXT NOT NULL,
    evidence_refs   TEXT NOT NULL DEFAULT '[]',  -- JSON list of EvidenceItem UUIDs
    created_at      TEXT NOT NULL,
    UNIQUE (finding_id, version)
);
CREATE INDEX idx_finding_versions_finding ON finding_versions(finding_id);

-- ---- reviews ------------------------------------------------------------
CREATE TABLE reviews (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    reviewer_agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    verdict         TEXT NOT NULL,         -- accept|reject|request_changes
    validity        TEXT NOT NULL,         -- valid|invalid|inconclusive
    reproduction_quality TEXT NOT NULL,
    scope_safety    TEXT NOT NULL,         -- safe|unsafe|unknown
    severity_consistency TEXT NOT NULL,     -- consistent|inconsistent
    missing_evidence TEXT NOT NULL DEFAULT '[]',
    requested_changes TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0,
    provider_id     TEXT,
    model_id        TEXT,
    rationale       TEXT NOT NULL DEFAULT '',
    is_dispute      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    UNIQUE (finding_id, version, reviewer_agent_id)
);
CREATE INDEX idx_reviews_finding ON reviews(finding_id);

-- ---- PoCs ---------------------------------------------------------------
CREATE TABLE pocs (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    setup           TEXT NOT NULL,
    commands        TEXT NOT NULL,         -- JSON list
    expected_output TEXT NOT NULL DEFAULT '',
    cleanup         TEXT NOT NULL DEFAULT '',
    safety_notes    TEXT NOT NULL DEFAULT '',
    redacted_fields TEXT NOT NULL DEFAULT '[]',
    target_kind     TEXT NOT NULL,         -- local_mock|staging|live
    requires_human_approval INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    UNIQUE (finding_id, version)
);

-- ---- final reports ------------------------------------------------------
CREATE TABLE final_reports (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    report_path     TEXT NOT NULL,
    evidence_manifest_path TEXT NOT NULL,
    redaction_manifest_path TEXT NOT NULL,
    hash_manifest   TEXT NOT NULL,
    approved_by     TEXT,
    submitted_at    TEXT,
    submission_target TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (finding_id, version)
);

-- ---- usage events -------------------------------------------------------
CREATE TABLE usage_events (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    event_id        TEXT NOT NULL UNIQUE,   -- idempotency key from provider
    schema_version  TEXT NOT NULL,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    agent_id        TEXT REFERENCES agents(id) ON DELETE SET NULL,
    task_id         TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    provider_id     TEXT NOT NULL,
    model_key       TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    is_free         INTEGER NOT NULL DEFAULT 1,
    is_paid         INTEGER NOT NULL DEFAULT 0,
    estimated_cost  REAL NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_usage_campaign ON usage_events(campaign_id);
CREATE INDEX idx_usage_provider_model ON usage_events(provider_id, model_key);

-- ---- audit events -------------------------------------------------------
CREATE TABLE audit_events (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    event_id        TEXT NOT NULL UNIQUE,
    schema_version  TEXT NOT NULL,
    actor_id        TEXT,
    actor_kind      TEXT NOT NULL,          -- system|agent|human|policy
    category        TEXT NOT NULL,          -- state_transition|policy_decision|approval|config|error
    subject_kind    TEXT,
    subject_id      TEXT,
    prior_state     TEXT,
    new_state       TEXT,
    reason          TEXT NOT NULL DEFAULT '',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_audit_subject ON audit_events(subject_kind, subject_id);
CREATE INDEX idx_audit_created ON audit_events(created_at);

-- schema_migrations tracking is created by the runner itself.
-- (intentionally not part of this migration's up SQL)

-- +mavr down
-- (no down-DDL needed for the runner-managed table)
DROP TABLE IF EXISTS usage_events;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS final_reports;
DROP TABLE IF EXISTS pocs;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS finding_versions;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS evidence_items;
DROP TABLE IF EXISTS extracted_sources;
DROP TABLE IF EXISTS search_results;
DROP TABLE IF EXISTS router_decisions;
DROP TABLE IF EXISTS models;
DROP TABLE IF EXISTS providers;
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS scope_policies;
DROP TABLE IF EXISTS campaigns;
