-- 0003 — finding state-machine leases (spec §10)
-- A dedicated table for finding leases. The previous implementation
-- stored the lease in the most-recent finding_transitions row's
-- metadata, which meant any concurrent transition() between lease()
-- and release_lease() would clobber the lease (or vice versa). A
-- dedicated row per lease keeps ownership independent of the
-- append-only transition log.

PRAGMA foreign_keys = ON;

CREATE TABLE finding_leases (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    owner           TEXT NOT NULL,
    token           TEXT NOT NULL,
    acquired_at     TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    released_at     TEXT,
    UNIQUE (finding_id, token)
);
CREATE INDEX idx_finding_leases_finding ON finding_leases(finding_id) WHERE released_at IS NULL;
CREATE INDEX idx_finding_leases_expires ON finding_leases(expires_at) WHERE released_at IS NULL;

-- +mavr down
DROP TABLE IF EXISTS finding_leases;
