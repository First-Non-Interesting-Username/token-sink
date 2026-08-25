-- 0006 — Phase 7 observability (spec §14)
-- Backing tables for in-process metrics, the SSE event ring buffer,
-- and persisted approval center state. All UUID primary keys are
-- TEXT(36) with a CHECK(length=36) constraint.

PRAGMA foreign_keys = ON;

-- ---- system events (SSE) ----------------------------------------------
-- The orchestrator + subsystems publish structured events here. The SSE
-- endpoint tails this table in order; on reconnect the client passes
-- the last event id (rowid) and the server replays from after it.
-- We do not enforce a foreign key on campaign_id/agent_id/task_id
-- because events are best-effort and must not block writers if rows
-- are deleted under us.
CREATE TABLE system_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version  TEXT NOT NULL,
    event_type      TEXT NOT NULL,         -- campaign.*, agent.*, task.*, finding.*, approval.*, metric.*, system.*
    severity        TEXT NOT NULL DEFAULT 'info',  -- debug|info|warning|error
    campaign_id     TEXT,
    agent_id        TEXT,
    task_id         TEXT,
    finding_id      TEXT,
    correlation_id  TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '{}',    -- JSON
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_system_events_created ON system_events(created_at);
CREATE INDEX idx_system_events_type ON system_events(event_type);
CREATE INDEX idx_system_events_campaign ON system_events(campaign_id);

-- ---- metrics (counters, gauges, histograms) ----------------------------
-- Generic key/value metric rows with dimensions. Histograms are stored
-- as multiple rows sharing a (name, dim_hash) with explicit bucket
-- labels so the UI can render p50/p90/p99 without an external service.
CREATE TABLE metric_points (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version  TEXT NOT NULL,
    name            TEXT NOT NULL,         -- e.g. router.requests, provider.latency_ms
    kind            TEXT NOT NULL,         -- counter|gauge|histogram
    value           REAL NOT NULL,
    count           INTEGER NOT NULL DEFAULT 0,    -- for histogram bucket
    bucket          TEXT,                  -- for histogram buckets
    dimensions      TEXT NOT NULL DEFAULT '{}',    -- JSON dict
    is_free         INTEGER NOT NULL DEFAULT 1,    -- 0|1, NULL allowed for system metrics
    is_paid         INTEGER NOT NULL DEFAULT 0,
    campaign_id     TEXT,
    agent_id        TEXT,
    task_id         TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_metric_points_name ON metric_points(name);
CREATE INDEX idx_metric_points_name_dims ON metric_points(name, dimensions);
CREATE INDEX idx_metric_points_created ON metric_points(created_at);
CREATE INDEX idx_metric_points_campaign ON metric_points(campaign_id);

-- +mavr down
DROP TABLE IF EXISTS metric_points;
DROP TABLE IF EXISTS system_events;
