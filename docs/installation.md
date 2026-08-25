# Installation (Linux)

> **Authorized security testing only.** MAVR is a tool for conducting
> security testing against systems you are explicitly authorized to
> test. It has no default target. Use of this tool against systems
> without authorization is unlawful and unethical.

This page covers the supported installation paths for MAVR on
Linux. macOS and Windows are not officially supported; the code
should run on macOS with the same Python toolchain but you may need
to adjust paths.

## Supported Python versions

MAVR targets CPython 3.11 and 3.12. It is tested on 3.11 in CI; the
package's `requires-python` is `">=3.11"`. Newer 3.x releases
typically work but are not part of the release matrix.

Check your version:

```bash
python3 --version   # should print 3.11.x or 3.12.x
```

If your distribution only ships 3.10 or older, install a newer
interpreter. On Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
```

On Fedora / RHEL:

```bash
sudo dnf install -y python3.11 python3.11-devel
```

## Dependencies

System packages required:

* `python3.11` (or `python3.12`) and the matching `python*-venv`
* `libsqlite3` (already present on most distributions)
* `build-essential` (for `pip install` of any wheels that need to
  compile; most dependencies are pre-built)

MAVR also has Python dependencies pinned in `pyproject.toml`. They
are installed automatically by `pip`.

## Installation paths

You have three supported install paths. Pick the one that matches
how isolated you want the environment to be.

### Option 1 — `pipx install mavr` (recommended for end users)

`pipx` installs the `system` CLI into an isolated virtualenv and
exposes the entry point on your `$PATH`. This is the cleanest
choice if you only want to run MAVR as a CLI.

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install mavr
system --version   # mavr 0.1.0
```

To upgrade later:

```bash
pipx upgrade mavr
```

To uninstall:

```bash
pipx uninstall mavr
```

### Option 2 — `pip install --user` (manual, fast iteration)

```bash
python3 -m pip install --user mavr
# add ~/.local/bin to PATH if it isn't already
export PATH="$HOME/.local/bin:$PATH"
system --version
```

### Option 3 — editable install (developers)

Clone the repository and install in editable mode:

```bash
git clone https://github.com/your-org/mavr.git
cd mavr
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
system --version
```

The `[dev]` extra pulls in `pytest`, `pytest-asyncio`, `ruff`, and
`mypy`.

## First-run setup

After installing, initialize the local data directory:

```bash
system init run
```

This creates `~/.local/share/mavr/` (or the platform equivalent
under `$XDG_DATA_HOME`) with the SQLite database, artifact
directory, and a default `config.yaml`. The first run also applies
all versioned migrations.

Verify the install:

```bash
system doctor run
```

You should see green checks for:

* Python version
* Database reachable
* Artifact directory writable
* (Optional) at least one provider configured

## Upgrading

The data directory and migrations are forward-compatible within a
major version. To upgrade from 0.1.x to 0.1.y:

```bash
pipx upgrade mavr           # or `pip install --user --upgrade mavr`
system init run --upgrade   # apply any new migrations
```

`system init run` is idempotent: it will only apply migrations that
have not been applied yet. A migration's checksum is recorded at
apply time; if a SQL file is modified after it has been applied,
the next `init run` will refuse to start.

## Reproducible install

A `make install` target is shipped at the repository root for
developers:

```bash
make install          # editable install with dev extras
make install-user     # user-site install
make wheel            # build a wheel into dist/
make sdist            # build an sdist into dist/
```

`scripts/install.sh` is the non-make equivalent; both call the
same `pip` invocations.

## Optional: PyInstaller single-file binary

If you need a self-contained, offline-laptop binary that does not
require a Python toolchain at run time:

```bash
pip install pyinstaller
pyinstaller --onefile --name mavr mavr/__main__.py
./dist/mavr/mavr --version
```

The resulting binary bundles the whole `mavr` package. It does
*not* bundle the SQLite native extension (SQLite is in the Python
standard library on supported versions) and it does not bundle the
OpenSSL trust store; if you need HTTPS to a private CA, ship the CA
bundle alongside the binary.

## Troubleshooting

* `system: command not found` — the user-site `bin` is not on your
  `$PATH`. Add `~/.local/bin` (or the output of
  `python3 -m site --user-base)/bin`) to your shell rc.
* `externally-managed-environment` (PEP 668) — use `pipx install
  mavr` or `python3 -m venv .venv` instead of a system-wide
  `pip install`.
* `sqlite3.OperationalError: no such table: schema_migrations` —
  the database file was created against an older schema. Run
  `system init run` to re-apply migrations.
* `ImportError: cannot import name 'X' from 'mavr.Y'` — you have
  an older MAVR install on `sys.path` shadowing the new one. Use
  `pipx` or a venv to isolate.
