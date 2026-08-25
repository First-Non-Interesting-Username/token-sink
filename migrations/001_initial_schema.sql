-- Initial schema (extracted from the original in-code MIGRATIONS list in
-- storage/sqlite.py so all migrations live in one forward-only sequence).
CREATE TABLE records (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'created',
    data TEXT NOT NULL,               -- JSON payload
    idempotency_key TEXT UNIQUE,      -- enables idempotent task execution
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (kind, id)
);
CREATE TABLE transitions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,  -- append-only history ordering
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE artifacts (
    sha256 TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    suggested_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_records_kind ON records(kind);
CREATE INDEX idx_transitions_record ON transitions(kind, record_id);
