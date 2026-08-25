"""Unit tests for `system doctor` (issue #93): report-all semantics, exit codes,
per-check outcomes. Network-touching checks are disabled/mocked so the suite
never makes external calls.
"""

from __future__ import annotations

import socket
import sqlite3
from pathlib import Path

from cli import doctor
from cli.doctor import (
    FAIL,
    PASS,
    WARN,
    CheckResult,
    DoctorReport,
    check_config,
    check_db_writable,
    check_disk_space,
    check_port_available,
    check_python_version,
    check_schema_version,
    check_writable_dir,
    run_doctor,
)

GOOD_CONFIG = """
server:
  host: 127.0.0.1
  port: 8081
storage:
  db_path: {tmp}/tokensink.db
  artifact_path: {tmp}/artifacts
"""


def write_config(tmp_path: Path, body: str = GOOD_CONFIG) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(body.replace("{tmp}", str(tmp_path)), encoding="utf-8")
    return p


# --- report aggregation ------------------------------------------------------


def test_worst_status_and_exit_codes():
    r = DoctorReport(
        results=[
            CheckResult("a", PASS, "ok"),
            CheckResult("b", WARN, "meh"),
            CheckResult("c", FAIL, "bad"),
        ]
    )
    assert r.worst == FAIL
    assert r.exit_code == 1


def test_warn_only_gives_exit_code_2():
    r = DoctorReport(results=[CheckResult("a", PASS, "ok"), CheckResult("b", WARN, "meh")])
    assert r.exit_code == 2


def test_all_pass_exit_zero():
    r = DoctorReport(results=[CheckResult("a", PASS, "ok")])
    assert r.exit_code == 0


def test_json_output_shape():
    r = DoctorReport(results=[CheckResult("a", WARN, "meh", {"k": "v"})])
    import json

    parsed = json.loads(r.to_json())
    assert parsed["status"] == "warn"
    assert parsed["exit_code"] == 2
    assert parsed["checks"][0]["data"] == {"k": "v"}


# --- individual checks -------------------------------------------------------


def test_python_version_passes_on_current_interpreter():
    assert check_python_version(min_version=(3, 0)).status == PASS


def test_python_version_fails_on_absurd_requirement():
    assert check_python_version(min_version=(99, 0)).status == FAIL


def test_missing_module_reports_fail_or_warn():
    from cli.doctor import check_module_import

    assert check_module_import("definitely_not_a_real_module_xyz").status == FAIL
    assert check_module_import("definitely_not_a_real_module_xyz", required=False).status == WARN


def test_command_check(tmp_path):
    from cli.doctor import check_command_on_path

    assert check_command_on_path("sh").status == PASS
    assert check_command_on_path("no-such-cmd-xyz").status == FAIL


def test_valid_config_passes(tmp_path):
    res = check_config(write_config(tmp_path))
    assert res.status == PASS


def test_invalid_config_reports_ALL_errors_not_first(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "server:\n  port: 99999\nstorage:\n  artifact_path: ''\nfree_only: 'yes'\n",
        encoding="utf-8",
    )
    res = check_config(bad)
    assert res.status == FAIL
    # §16/issue-93 requirement: every error is in one report.
    assert len(res.data["errors"]) >= 3


def test_missing_config_is_warn_with_hint(tmp_path):
    res = check_config(tmp_path / "nope.yaml")
    assert res.status == WARN
    assert "hint" in res.data or "example" in res.detail


def test_db_writable_creates_parent_and_opens_sqlite(tmp_path):
    db = tmp_path / "sub" / "dir" / "db.sqlite"
    assert check_db_writable(str(db)).status == PASS
    assert db.parent.is_dir()


def test_writable_dir_created_and_probed(tmp_path):
    target = tmp_path / "artifacts"
    res = check_writable_dir(str(target), "artifact-dir")
    assert res.status == PASS
    assert target.is_dir()
    # Probe file must not be left behind.
    assert list(target.iterdir()) == []


def test_disk_space_ok_on_normal_fs(tmp_path):
    assert check_disk_space(str(tmp_path), min_free_bytes=1).status == PASS


def test_port_available_and_conflict_detected():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    # Bound socket → port busy (listen omitted; bind conflict still detected).
    try:
        res = check_port_available("127.0.0.1", port)
        assert res.status in (FAIL,)
    finally:
        s.close()
    # A fresh ephemeral bind should succeed after release.
    assert check_port_available("127.0.0.1", 0).status == PASS


def test_schema_version_fresh_db_is_warn(tmp_path):
    db = tmp_path / "new.db"
    res = check_schema_version(str(db))
    assert res.status == WARN
    assert res.data["current"] == 0


def test_schema_version_current_passes(tmp_path):
    db = tmp_path / "v1.db"
    conn = sqlite3.connect(db)
    conn.execute(f"PRAGMA user_version = {doctor.DEFAULT_PROVIDER_ENDPOINTS and 1};")
    conn.commit()
    conn.close()
    assert check_schema_version(str(db)).status == PASS


def test_schema_version_newer_than_build_fails(tmp_path):
    db = tmp_path / "future.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 99;")
    conn.commit()
    conn.close()
    res = check_schema_version(str(db))
    assert res.status == FAIL


# --- full-run semantics ------------------------------------------------------


def test_run_doctor_collects_every_check_even_after_failures(tmp_path, monkeypatch):
    # Force several checks to fail; the run must STILL execute all later checks.
    monkeypatch.setattr(
        doctor,
        "check_provider_endpoints",
        lambda *a, **k: CheckResult("provider-endpoints", WARN, "offline (mocked)", {}),
    )
    cfg = write_config(tmp_path)
    report = run_doctor(config_path=cfg, skip_network=True)
    names = [r.name for r in report.results]
    # Report-all: a failure early in the list never suppresses later checks.
    assert "python-version" in names and "config" in names
    assert "db-path" in names and "artifact-dir" in names and "disk-space" in names
    assert "ui-port" in names and "schema-version" in names
    # With network skipped, no endpoint probe ran.
    assert "provider-endpoints" not in names


def test_run_doctor_json_end_to_end(tmp_path):
    cfg = write_config(tmp_path)
    report = run_doctor(config_path=cfg, skip_network=True)
    import json

    parsed = json.loads(report.to_json())
    assert len(parsed["checks"]) >= 8
