-- Usage accounting attribution columns (issue #204, PLAN §13.5).
--
-- Migration 002 created a minimal usage_events table (provider/model/tokens).
-- This extends it with the full attribution dimensions from
-- schemas/usage_event.schema.json so every recorded request can be attributed
-- per campaign/agent/task and split free vs paid. Additive only: existing
-- rows keep working with NULL attribution.
ALTER TABLE usage_events ADD COLUMN event_uuid TEXT;
ALTER TABLE usage_events ADD COLUMN campaign_uuid TEXT;
ALTER TABLE usage_events ADD COLUMN agent_uuid TEXT;
ALTER TABLE usage_events ADD COLUMN task_uuid TEXT;
ALTER TABLE usage_events ADD COLUMN is_free_tier INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_events ADD COLUMN request_status TEXT NOT NULL DEFAULT 'success';
ALTER TABLE usage_events ADD COLUMN estimated_cost_usd REAL;
ALTER TABLE usage_events ADD COLUMN latency_ms INTEGER;
ALTER TABLE usage_events ADD COLUMN cache_read_tokens INTEGER;
ALTER TABLE usage_events ADD COLUMN cache_write_tokens INTEGER;
ALTER TABLE usage_events ADD COLUMN occurred_at TEXT;
CREATE UNIQUE INDEX idx_usage_events_uuid ON usage_events(event_uuid);
CREATE INDEX idx_usage_events_campaign ON usage_events(campaign_uuid);
CREATE INDEX idx_usage_events_agent ON usage_events(agent_uuid);
CREATE INDEX idx_usage_events_occurred ON usage_events(occurred_at);
