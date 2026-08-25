"""`system doctor`: environment/config diagnostics (PLAN §17, §16; issue #93).

Runs every check and reports ALL results — never aborts at the first
failure — then exits 0 (pass), 1 (fail), or 2 (warn) so scripts and CI can
consume the outcome. Output is human-readable by default, JSON with --json.

Check list per issue #93:
- Python version + required system deps (`ddgs` importable, `curl` on PATH)
- Config file parses + passes §16 validation (all errors reported)
- DB path writable; artifact dir writable (created if missing); disk space
- OS credential store accessible (keyring, optional/soft)
- Network egress sanity to provider endpoints only — never any target
- Local UI port availability
- Storage schema version/migration state

Design note: checks are pure functions returning CheckResult records so they
are individually unit-testable without spawning subprocesses where avoidable.
"""

from __future__ import annotations

import json
import shutil
import shutil as _shutil
import socket
import sqlite3
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# Status levels. Exit codes: pass=0, warn-only=2, any fail=1.
PASS = "pass"
WARN = "warn"
FAIL = "fail"

EXIT_CODES = {PASS: 0, WARN: 2, FAIL: 1}


@dataclass
class CheckResult:
    """One diagnostic check's outcome."""

    name: str
    status: str  # PASS | WARN | FAIL
    detail: str
    # Machine-readable extras surfaced under `data` in --json output.
    data: dict = field(default_factory=dict)


@dataclass
class DoctorReport:
    """Aggregated result of a full doctor run."""

    results: list[CheckResult] = field(default_factory=list)

    @property
    def worst(self) -> str:
        order = {PASS: 0, WARN: 1, FAIL: 2}
        if not self.results:
            return PASS
        return max(self.results, key=lambda r: order[r.status]).status

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.worst]

    def to_json(self) -> str:
        return json.dumps(
            {
                "status": self.worst,
                "exit_code": self.exit_code,
                "checks": [
                    {"name": r.name, "status": r.status, "detail": r.detail, "data": r.data}
                    for r in self.results
                ],
            },
            indent=2,
        )

    def to_human(self) -> str:
        icon = {PASS: "OK  ", WARN: "WARN", FAIL: "FAIL"}
        lines = [f"token-sink system doctor — overall: {self.worst.upper()}", ""]
        for r in self.results:
            lines.append(f"[{icon[r.status]}] {r.name}: {r.detail}")
            if r.data:
                for k, v in sorted(r.data.items()):
                    lines.append(f"       {k}: {v}")
        return "\n".join(lines)


def check_python_version(min_version: tuple[int, int] = (3, 11)) -> CheckResult:
    """Required interpreter version (pyproject requires >=3.11)."""
    cur = sys.version_info[:2]
    if cur >= min_version:
        return CheckResult(
            "python-version",
            PASS,
            f"Python {cur[0]}.{cur[1]} >= required {min_version[0]}.{min_version[1]}",
            {"version": f"{cur[0]}.{cur[1]}"},
        )
    return CheckResult(
        "python-version",
        FAIL,
        f"Python {cur[0]}.{cur[1]} is below required {min_version[0]}.{min_version[1]}",
        {"version": f"{cur[0]}.{cur[1]}"},
    )


def check_module_import(module: str, required: bool = True) -> CheckResult:
    """Whether a Python dependency imports (e.g. ddgs for search, PLAN §9)."""
    import importlib.util

    spec = importlib.util.find_spec(module)
    if spec is not None:
        return CheckResult(f"module:{module}", PASS, f"{module} available")
    level = FAIL if required else WARN
    return CheckResult(
        f"module:{module}",
        level,
        f"{module} not installed"
        + ("" if required else " (optional until its subsystem is enabled)"),
    )


def check_command_on_path(cmd: str, required: bool = True) -> CheckResult:
    """Whether a system command exists (e.g. curl used for extraction, §9)."""
    path = shutil.which(cmd)
    if path:
        return CheckResult(f"command:{cmd}", PASS, f"found at {path}", {"path": path})
    level = FAIL if required else WARN
    return CheckResult(f"command:{cmd}", level, f"'{cmd}' not found on PATH")


def check_config(config_path: str | Path | None) -> CheckResult:
    """Parse + validate the config file, reporting ALL errors (never just the first).

    A missing config is a warning, not a failure: first-run users may not have
    one yet; doctor tells them how to proceed.
    """
    from config.loader import ConfigError, load_config_collect

    p = Path(config_path) if config_path else _default_config_path()
    if p is None or not p.is_file():
        return CheckResult(
            "config",
            WARN,
            f"no config file found at {p or '<default>'}",
            {"path": str(p) if p else "", "hint": "create one from examples/config.example.yaml"},
        )
    try:
        _, errors = load_config_collect(p)
    except ConfigError as exc:
        # Defensive: loaders that raise instead of collecting still get all
        # their collected errors surfaced here.
        return CheckResult("config", FAIL, f"config invalid: {exc}", {"errors": [str(exc)]})
    except Exception as exc:  # parse-level crash — still collect-and-report style
        return CheckResult("config", FAIL, f"config failed to load: {exc}")
    if errors:
        return CheckResult(
            "config",
            FAIL,
            f"config has {len(errors)} validation error(s)",
            {"path": str(p), "errors": errors},
        )
    return CheckResult("config", PASS, "config valid", {"path": str(p)})


def check_writable_dir(path_str: str, label: str, create: bool = True) -> CheckResult:
    """A configured directory exists (or can be created) and is writable."""
    p = Path(path_str)
    try:
        if not p.exists():
            if not create:
                return CheckResult(label, WARN, f"{p} does not exist")
            p.mkdir(parents=True, exist_ok=True)
        probe = p / ".doctor-write-probe"
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
        return CheckResult(label, PASS, f"{p} writable")
    except OSError as exc:
        return CheckResult(label, FAIL, f"{p} not writable: {exc}")


def check_db_writable(db_path: str) -> CheckResult:
    """DB path's parent is writable and a SQLite handle opens there."""
    parent = Path(db_path).parent
    if not parent.is_dir():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return CheckResult("db-path", FAIL, f"cannot create {parent}: {exc}")
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.close()
        return CheckResult("db-path", PASS, f"sqlite usable at {db_path}")
    except sqlite3.Error as exc:
        return CheckResult("db-path", FAIL, f"sqlite unusable at {db_path}: {exc}")


def check_disk_space(path: str, min_free_bytes: int = 1 << 30) -> CheckResult:
    """At least ~1 GiB free where storage lives (warn below, fail near-zero)."""
    p = Path(path)
    root = p if p.is_dir() else p.parent
    try:
        usage = _shutil.disk_usage(root)
    except OSError as exc:
        return CheckResult("disk-space", FAIL, f"cannot stat {root}: {exc}")
    free = usage.free
    gb = free / (1 << 30)
    if free >= min_free_bytes:
        return CheckResult("disk-space", PASS, f"{gb:.1f} GiB free", {"free_bytes": free})
    if free > min_free_bytes // 10:
        return CheckResult(
            "disk-space",
            WARN,
            f"only {gb:.2f} GiB free (<1 GiB threshold)",
            {"free_bytes": free},
        )
    return CheckResult(
        "disk-space", FAIL, f"critically low: {gb:.2f} GiB free", {"free_bytes": free}
    )


def check_keyring() -> CheckResult:
    """OS credential store accessibility (#29). Soft: keyring may be absent."""
    try:
        import keyring  # type: ignore

        backend = keyring.get_keyring()
        name = getattr(backend, "priority", None)
        # A fail-priority backend means no usable store was found.
        if name == 0:
            return CheckResult(
                "keyring",
                WARN,
                "no usable OS credential store backend found",
                {"backend": type(backend).__name__},
            )
        return CheckResult(
            "keyring",
            PASS,
            "credential store accessible",
            {"backend": type(backend).__name__},
        )
    except Exception as exc:
        return CheckResult(
            "keyring",
            WARN,
            f"keyring unavailable ({exc}); env-var credential references still work",
        )


def check_provider_endpoints(urls: list[str], timeout_s: float = 5.0) -> CheckResult:
    """Network egress sanity against provider endpoints ONLY.

    Never probes campaign targets — this check runs before any campaign
    exists. Failures are warnings: offline dev boxes are a legitimate setup.
    """
    if not urls:
        return CheckResult("provider-endpoints", PASS, "no provider endpoints configured")
    reachable, unreachable = [], []
    for url in urls:
        try:
            req = urllib.request.Request(url, method="GET")
            urllib.request.urlopen(req, timeout=timeout_s)
            reachable.append(url)
        except urllib.error.HTTPError:
            # Any HTTP response (even 4xx) proves DNS+TCP+TLS egress works.
            reachable.append(url)
        except Exception as exc:
            unreachable.append(f"{url} ({type(exc).__name__})")
    data = {"reachable": reachable, "unreachable": unreachable}
    if not unreachable:
        return CheckResult(
            "provider-endpoints", PASS, f"{len(reachable)} endpoint(s) reachable", data
        )
    return CheckResult(
        "provider-endpoints", WARN, f"{len(unreachable)}/{len(urls)} endpoint(s) unreachable", data
    )


def check_port_available(host: str, port: int) -> CheckResult:
    """Local UI/API port bindability."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return CheckResult("ui-port", PASS, f"{host}:{port} available")
    except OSError as exc:
        return CheckResult("ui-port", FAIL, f"{host}:{port} not bindable: {exc}")
    finally:
        s.close()


def check_schema_version(db_path: str, expected_version: int = 1) -> CheckResult:
    """Storage schema migration state (#7): reads user_version, never mutates it.

    A fresh/absent DB is fine (version 0 = uninitialized); a version newer
    than this build understands is a hard fail (downgrade would corrupt).
    """
    if not Path(db_path).exists():
        return CheckResult(
            "schema-version",
            WARN,
            "no database yet; will initialize on first run",
            {"current": 0, "expected": expected_version},
        )
    try:
        conn = sqlite3.connect(db_path)
        (ver,) = conn.execute("PRAGMA user_version;").fetchone()
        conn.close()
    except sqlite3.Error as exc:
        return CheckResult("schema-version", FAIL, f"cannot read schema version: {exc}")
    data = {"current": ver, "expected": expected_version}
    if ver == expected_version:
        return CheckResult("schema-version", PASS, f"schema v{ver} up to date", data)
    if ver > expected_version:
        return CheckResult(
            "schema-version",
            FAIL,
            f"DB schema v{ver} is NEWER than supported v{expected_version} (older build?)",
            data,
        )
    return CheckResult(
        "schema-version",
        WARN,
        f"schema v{ver} pending migration to v{expected_version}",
        data,
    )


DEFAULT_PROVIDER_ENDPOINTS = [
    "https://api.openai.com/v1/models",
    "https://api.anthropic.com/v1/messages",
]


def run_doctor(
    config_path: str | Path | None = None,
    provider_endpoints: list[str] | None = None,
    skip_network: bool = False,
) -> DoctorReport:
    """Run every check and collect all results (issue #93: report-all semantics)."""
    from config.loader import ConfigError, load_config_collect

    report = DoctorReport()
    report.results.append(check_python_version())
    report.results.append(check_module_import("ddgs", required=False))
    report.results.append(check_command_on_path("curl"))

    # --- config + everything derived from it ---
    cfg_result = check_config(config_path)
    report.results.append(cfg_result)
    cfg = None
    db_path = "/var/lib/token-sink/tokensink.db"
    artifact_dir = "/var/lib/token-sink/artifacts"
    host, port = "127.0.0.1", 8080
    endpoints = DEFAULT_PROVIDER_ENDPOINTS if provider_endpoints is None else provider_endpoints
    if cfg_result.status != FAIL:
        try:
            p = Path(config_path) if config_path else _default_config_path()
            if p and p.is_file():
                cfg, errs = load_config_collect(p)
                if not errs:
                    db_path = cfg.storage.db_path
                    artifact_dir = cfg.storage.artifact_path
                    host, port = cfg.server.host, cfg.server.port
                    # Provider endpoint probing stays conservative: only probe
                    # well-known defaults; config stores env-var refs, not URLs.
        except (ConfigError, Exception):
            # Already reported by check_config; fall back to defaults above.
            pass

    report.results.append(check_db_writable(db_path))
    report.results.append(check_writable_dir(artifact_dir, "artifact-dir"))
    report.results.append(check_disk_space(artifact_dir))
    report.results.append(check_keyring())
    if not skip_network:
        report.results.append(check_provider_endpoints(endpoints))
    report.results.append(check_port_available(host, port))
    report.results.append(check_schema_version(db_path))
    return report


def _default_config_path() -> Path | None:
    """Search order mirrors docs/configuration.md: ./token-sink.yaml then ~/.config."""
    for candidate in (
        Path("token-sink.yaml"),
        Path("token-sink.toml"),
        Path.home() / ".config" / "token-sink" / "config.yaml",
    ):
        if candidate.is_file():
            return candidate
    return Path("token-sink.yaml")


def format_exit_hint(report: DoctorReport) -> str:
    return f"exit code: {report.exit_code} ({report.worst})"
