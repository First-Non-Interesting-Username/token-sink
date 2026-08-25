# Migrations (`migrations/` + `storage/migrations.py`)

Forward-only schema migrations for the transactional storage layer
(PLAN §12, issue #130).

## How it works

- Each migration is a plain `.sql` file: `NNN_short_name.sql` where `NNN` is
  the sequential version (001, 002, …). The runner rejects gaps, duplicate
  versions, and unrecognized filenames — a missing middle migration usually
  means a bad merge or partial copy.
- `schema_migrations` records every applied version **with the sha256 of the
  file content**. At startup (and before each migrate), the runner verifies:
  - applied hash == current file hash → editing an already-applied migration
    fails loudly instead of silently diverging from what ran;
  - no versions in the DB newer than the code ships → an old binary refuses
    to operate on a future schema (**downgrade protection**: downgrades are
    deliberately unsupported because they risk data loss);
  - no applied version whose file has disappeared.
- Application is strictly forward-only. Each migration runs in one explicit
  transaction together with its history row, so the marker can never exist
  without the schema change and a crash mid-migration rolls back completely.
  Note: `sqlite3.executescript()` issues an implicit COMMIT, which would break
  atomicity — the runner splits statements itself and executes them inside
  `BEGIN`/`COMMIT` (see `_split_statements`; files are repo-controlled, so a
  minimal splitter is sufficient).
- Upgrades are **explicit**, not automatic at import: call `migrate()` on the
  storage or `MigrationRunner` directly (wired to the planned
  `system migrate`). Dry-run via `runner.pending()`.
- Re-running a fully-applied set is a no-op.

## Conventions for adding a migration

1. Append `00N_description.sql`. Never edit an existing file after it has
   shipped — add a new migration instead.
2. Keep each file small and additive where possible; destructive changes need
   a note in the PR explaining data handling.
3. Add/extend tests in `tests/unit/test_migrations.py`, including a round-trip
   check that data written pre-migration survives (§21: restart must not lose
   state).
