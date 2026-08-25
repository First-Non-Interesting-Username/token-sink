# Install, Upgrade & Packaging (Linux)

Primary install path: **PyPI wheel** (`pip install token-sink`). A container
image is a possible future addition; the wheel is the supported path for now.

## Prerequisites

- Linux (the app is Linux-only by design — PLAN.md).
- Python **3.11+** (3.11 or 3.12 are what CI tests).
- `pip` (or `pipx`, recommended for CLI isolation) — no compiler needed; the
  only runtime dependency is PyYAML, which ships wheels for common platforms.
- Optional: `curl` on PATH. Some search/extraction features shell out to it;
  without it those features degrade with a clear error while everything else
  works.

## Install

```sh
# from a built wheel (see "Building" below until the project is on PyPI)
python -m pip install dist/token_sink-*.whl
```

This installs the `token-sink` console script plus all subsystem packages.

## Verify (environment check)

The packaging-side environment check runs at launch and is available as a
command:

```sh
token-sink doctor
```

It verifies the Python version, runtime dependencies, optional binaries
(warnings only), and that the data directory (`~/.local/share/token-sink`)
is writable. Exit code 0 = environment OK; 1 = at least one failure with an
actionable message. Note this is the lightweight *install* check — the full
`system doctor` diagnostics command is tracked separately in PLAN §17.

## Upgrades & DB migrations

Upgrading is the same command as installing — pip replaces the old version:

```sh
python -m pip install --upgrade dist/token_sink-<newer>.whl
```

Schema state lives in SQLite (`schema_migrations` table, see
`storage/sqlite.py`). Migrations are **forward-only and append-only**: each
runs in its own transaction on first startup after an upgrade, so a crash
mid-migration rolls back cleanly and retries on next start. Applied versions
are recorded, so re-running against an already-migrated database is a no-op.
Downgrades across schema versions are not supported — restore from a backup
(`system campaign export` / storage bundle export) if you must go back.

## Building

```sh
uv build            # or: python -m pip install build && python -m build
# → dist/token_sink-<version>-py3-none-any.whl
```

## CI

`.github/workflows/package.yml` builds the wheel on every PR touching
packaging-relevant files, installs it into a fresh venv on a clean runner,
and smoke-tests `token-sink doctor` + import of every subsystem package.
