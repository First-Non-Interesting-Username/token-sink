# Storage layer (PLAN.md §12)

Implementation lives in `storage/base.py` (interface + errors) and
`storage/sqlite.py` (Phase-1 engine). Key decisions and why:

## Interface-first

Agents code against `Storage` (ABC) only. Swapping engines later must not
touch agent code — that is the PLAN §12 abstraction requirement. Errors are
typed (`RecordExistsError`, `ConflictError`, `ArtifactNotFoundError`) so
callers can implement idempotent retry semantics.

## SQLite specifics

- **WAL journal mode**: readers never block the writer, and a crashed process
  leaves a recoverable WAL instead of a torn main DB file (crash recovery).
- Each migration runs in a single transaction with its version recorded in
  `schema_migrations`; a crash mid-migration rolls back and retries on next
  startup. Migrations are append-only — never edit one already applied.
- `isolation_level=None` (autocommit) with explicit `with self.conn:` blocks:
  each block is exactly one transaction.

## Identity & safety rules

- Record identity = `(kind, id)`; artifact identity = sha256 of contents.
  Filenames are metadata only — PLAN §12's "never filenames alone" rule.
- Idempotency: `insert_record(..., idempotency_key=...)` has a UNIQUE
  constraint; a repeated task execution raises `RecordExistsError`, which the
  runtime treats as "already done" (PLAN §12 idempotent task execution).
- Optimistic concurrency: every record carries a `version`; updates fail with
  `ConflictError` unless `expected_version` matches — this is what makes
  conflicting finding edits detectable (§18).
- Transitions are atomic compare-and-set: the UPDATE itself checks
  `state = from_state`, so there is no check/write race, and every transition
  appends to the `transitions` table (append-only history per PLAN §10/§12).
- Artifact paths derive purely from the hex digest (two-level fanout), so path
  traversal via user-supplied names is structurally impossible; reads verify
  the checksum to detect corruption/tampering.

## Export/import

`export_all()` dumps every table as JSON — the seed of the backup/export
feature; import lands when the schema set stabilizes (#9/#10).
