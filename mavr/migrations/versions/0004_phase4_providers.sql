-- 0004 — provider / router / usage tables for Phase 4 (spec §7, §8)
-- Adds the persistence backing for:
--   * model score records (per (model_key, category) with recency weighting)
--   * benchmark run history (offline benchmark suite)
--   * circuit-breaker state per (provider, model)
--   * dead-letter queue entries for unroutable tasks
--   * usage events (already declared in 0001; this migration adds the
--     dedup-friendly unique index for event_idempotency, which is
--     enforced separately to make the writer idempotent across retries)
--
-- All UUID primary keys are TEXT(36) with a CHECK(length=36) constraint.
PRAGMA foreign_keys = ON;

-- ---- model scores -------------------------------------------------------
CREATE TABLE model_scores (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    model_key       TEXT NOT NULL,
    category        TEXT NOT NULL,           -- spec §8.3 category id
    score           REAL NOT NULL,           -- 0.0 .. 1.0
    sample_count    INTEGER NOT NULL DEFAULT 0,
    confidence_low  REAL NOT NULL DEFAULT 0,
    confidence_high REAL NOT NULL DEFAULT 0,
    recency_weight  REAL NOT NULL DEFAULT 1.0,
    source          TEXT NOT NULL DEFAULT 'benchmark',  -- benchmark|live
    last_updated    TEXT NOT NULL,
    UNIQUE (provider_id, model_key, category)
);
CREATE INDEX idx_model_scores_category ON model_scores(category);
CREATE INDEX idx_model_scores_model ON model_scores(provider_id, model_key);

-- ---- benchmark runs -----------------------------------------------------
CREATE TABLE benchmark_runs (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    suite_version   TEXT NOT NULL,           -- the version of the prompt set
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    actor_kind      TEXT NOT NULL DEFAULT 'human',  -- human|system|agent
    actor_id        TEXT,
    config_snapshot TEXT NOT NULL DEFAULT '{}',
    summary         TEXT NOT NULL DEFAULT '{}',      -- JSON aggregate stats
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_benchmark_runs_started ON benchmark_runs(started_at);

-- ---- benchmark results --------------------------------------------------
CREATE TABLE benchmark_results (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    run_id          TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
    provider_id     TEXT NOT NULL,
    model_key       TEXT NOT NULL,
    category        TEXT NOT NULL,
    prompt_id       TEXT NOT NULL,
    passed          INTEGER NOT NULL,         -- 1|0
    score           REAL NOT NULL DEFAULT 0, -- 0.0 .. 1.0
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    raw_output_path TEXT,                    -- optional path to raw output
    error           TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_benchmark_results_run ON benchmark_results(run_id);
CREATE INDEX idx_benchmark_results_model ON benchmark_results(provider_id, model_key);

-- ---- circuit breakers ---------------------------------------------------
CREATE TABLE circuit_breakers (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    model_key       TEXT NOT NULL,            -- '*' means provider-level
    state           TEXT NOT NULL,            -- closed|open|half_open
    failures        INTEGER NOT NULL DEFAULT 0,
    successes       INTEGER NOT NULL DEFAULT 0,
    opened_at       TEXT,
    cooldown_until  TEXT,
    last_failure_at TEXT,
    last_error      TEXT NOT NULL DEFAULT '',
    UNIQUE (provider_id, model_key)
);
CREATE INDEX idx_circuit_breakers_state ON circuit_breakers(state);

-- ---- dead-letter queue --------------------------------------------------
CREATE TABLE dead_letter (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    schema_version  TEXT NOT NULL,
    task_id         TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    reason          TEXT NOT NULL,            -- no_candidates|policy_violation|circuit_open|timeout|error
    detail          TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_dead_letter_campaign ON dead_letter(campaign_id);
CREATE INDEX idx_dead_letter_task ON dead_letter(task_id);

-- +mavr down
DROP TABLE IF EXISTS dead_letter;
DROP TABLE IF EXISTS circuit_breakers;
DROP TABLE IF EXISTS benchmark_results;
DROP TABLE IF EXISTS benchmark_runs;
DROP TABLE IF EXISTS model_scores;
