-- 0002 — runtime tables and indexes for the orchestrator (spec §6, §10, §12)
-- Builds on 0001. Adds:
--   * task dependencies (DAG edges)
--   * task attempts history
--   * audit event correlation indexes
--   * finding state transition history
--   * kill-switch state
--   * quarantine log

PRAGMA foreign_keys = ON;

-- ---- task dependencies (DAG) --------------------------------------------
CREATE TABLE task_dependencies (
    task_id          TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_id    TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on_id),
    CHECK (task_id <> depends_on_id)
);
CREATE INDEX idx_task_deps_depends ON task_dependencies(depends_on_id);

-- ---- task attempt history ----------------------------------------------
CREATE TABLE task_attempts (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    task_id         TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt_number  INTEGER NOT NULL,
    agent_id        TEXT REFERENCES agents(id) ON DELETE SET NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    outcome         TEXT NOT NULL,         -- success|transient|permanent|policy|model_quality|cancelled
    error_class     TEXT,
    error_message   TEXT,
    tokens_used     INTEGER NOT NULL DEFAULT 0,
    tool_calls      INTEGER NOT NULL DEFAULT 0,
    network_requests INTEGER NOT NULL DEFAULT 0,
    wall_time_ms    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_task_attempts_task ON task_attempts(task_id, attempt_number);

-- ---- finding transition history ----------------------------------------
CREATE TABLE finding_transitions (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    prior_state     TEXT,
    new_state       TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    actor_id        TEXT,
    actor_kind      TEXT NOT NULL,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_finding_transitions_finding ON finding_transitions(finding_id, created_at);

-- ---- kill switch -------------------------------------------------------
CREATE TABLE kill_switch (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    is_active       INTEGER NOT NULL DEFAULT 0,
    reason          TEXT NOT NULL DEFAULT '',
    activated_by    TEXT,
    activated_at    TEXT
);

-- ---- quarantine log (poison tasks, rejected subagent outputs) ----------
CREATE TABLE quarantine_log (
    id              TEXT PRIMARY KEY CHECK (length(id) = 36),
    subject_kind    TEXT NOT NULL,         -- task|subagent|review
    subject_id      TEXT NOT NULL,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE CASCADE,
    classification  TEXT NOT NULL,         -- poison|policy_violation|permanent_failure|adversarial
    reason          TEXT NOT NULL,
    inputs_redacted TEXT NOT NULL,         -- JSON: inputs with secrets stripped
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_quarantine_subject ON quarantine_log(subject_kind, subject_id);
CREATE INDEX idx_quarantine_campaign ON quarantine_log(campaign_id);

-- +mavr down
DROP TABLE IF EXISTS quarantine_log;
DROP TABLE IF EXISTS kill_switch;
DROP TABLE IF EXISTS finding_transitions;
DROP TABLE IF EXISTS task_attempts;
DROP TABLE IF EXISTS task_dependencies;
