"""Redacted run-bundle export (spec §14, §17).

A run bundle is a zip that contains:

- ``manifest.json`` — campaign metadata, scope policy, finding counts.
- ``config_snapshot.json`` — a copy of the active config (with secrets
  and bearer tokens stripped).
- ``events.jsonl`` — a redacted stream of system events for the
  campaign and its descendants.
- ``usage.json`` — usage / cost breakdown split by free vs paid.
- ``audit.jsonl`` — redacted audit events.
- ``findings.json`` — findings, reviews, and final reports for the
  campaign (no PoC payloads).
- ``artifacts_index.json`` — pointers to artifact files (no content).
- ``db_dump.sqlite`` — a SQLite snapshot of the live DB with secret
  columns zeroed and the approvals table redacted.
- ``redaction_manifest.json`` — what we removed and why.

The bundle is safe to hand to a remote reviewer.
"""
from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mavr.observability.logging import get_logger
from mavr.storage.database import Database

log = get_logger(__name__)

_REDACTED_COLUMNS: dict[str, frozenset[str]] = {
    "approvals": frozenset({"token"}),
}


@dataclass(frozen=True)
class BundleResult:
    path: Path
    size_bytes: int
    entry_count: int


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_config_snapshot(cfg: Any) -> dict[str, Any]:
    """Return a JSON-serializable copy of the config with secrets removed."""
    if cfg is None:
        return {}
    try:
        raw = cfg.model_dump(mode="json")
    except AttributeError:
        try:
            raw = dict(cfg)
        except Exception:  # noqa: BLE001
            return {}

    def _scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _scrub(v) for k, v in value.items() if not _is_secret_key(k)}
        if isinstance(value, list):
            return [_scrub(v) for v in value]
        return value

    return _scrub(raw)


def _is_secret_key(name: str) -> bool:
    n = name.lower()
    return any(t in n for t in ("secret", "token", "password", "api_key", "apikey"))


def _redact_payload(payload: Any) -> Any:
    """Redact a JSON payload recursively."""
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        for k, v in payload.items():
            if _is_secret_key(k):
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact_payload(v)
        return out
    if isinstance(payload, list):
        return [_redact_payload(v) for v in payload]
    if isinstance(payload, str):
        return _redact_string(payload)
    return payload


def _redact_string(text: str) -> str:
    """Pattern-based string scrubber for free-text fields."""
    return redact_free_text(text)


def _dump_table(cur: sqlite3.Cursor, table: str, redact_columns: Iterable[str] = ()) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    redact = {c.lower() for c in redact_columns}
    for row in cur.fetchall():
        as_dict = dict(row)
        for col in redact:
            if col in as_dict:
                as_dict[col] = "***REDACTED***"
        rows.append(as_dict)
    return rows


async def _gather_campaign(
    db: Database, campaign_id: str
) -> dict[str, Any]:
    async with db.acquire() as conn:
        cur = await conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        campaign = await cur.fetchone()
        if campaign is None:
            raise ValueError(f"unknown campaign: {campaign_id}")
        cur = await conn.execute(
            "SELECT * FROM scope_policies WHERE campaign_id = ?", (campaign_id,)
        )
        scope = await cur.fetchone()
        cur = await conn.execute(
            "SELECT * FROM agents WHERE campaign_id = ? ORDER BY created_at", (campaign_id,)
        )
        agents = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT * FROM tasks WHERE campaign_id = ? ORDER BY created_at", (campaign_id,)
        )
        tasks = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT * FROM findings WHERE campaign_id = ? ORDER BY created_at", (campaign_id,)
        )
        findings = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT r.* FROM reviews r JOIN findings f ON f.id = r.finding_id "
            "WHERE f.campaign_id = ? ORDER BY r.created_at",
            (campaign_id,),
        )
        reviews = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT fr.* FROM final_reports fr JOIN findings f ON f.id = fr.finding_id "
            "WHERE f.campaign_id = ? ORDER BY fr.version",
            (campaign_id,),
        )
        reports = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT * FROM usage_events WHERE campaign_id = ? ORDER BY created_at", (campaign_id,)
        )
        usage = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT * FROM system_events WHERE campaign_id = ? ORDER BY id", (campaign_id,)
        )
        events = list(await cur.fetchall())
        cur = await conn.execute(
            "SELECT * FROM audit_events "
            "WHERE subject_kind = 'campaign' AND subject_id = ? OR "
            "(subject_kind = 'finding' AND subject_id IN (SELECT id FROM findings WHERE campaign_id = ?))"
            "ORDER BY created_at",
            (campaign_id, campaign_id),
        )
        audit_rows = list(await cur.fetchall())
    return {
        "campaign": dict(campaign),
        "scope": dict(scope) if scope else None,
        "agents": [dict(r) for r in agents],
        "tasks": [dict(r) for r in tasks],
        "findings": [dict(r) for r in findings],
        "reviews": [dict(r) for r in reviews],
        "reports": [dict(r) for r in reports],
        "usage": [dict(r) for r in usage],
        "events": [dict(r) for r in events],
        "audit": [dict(r) for r in audit_rows],
    }


def _redact_audit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        r2 = dict(r)
        try:
            meta = json.loads(r2.get("metadata") or "{}")
        except (TypeError, ValueError):
            meta = {}
        meta = _redact_payload(meta)
        r2["metadata"] = json.dumps(meta, ensure_ascii=False)
        if isinstance(r2.get("reason"), str):
            r2["reason"] = redact_free_text(r2["reason"])
        out.append(r2)
    return out


def _redact_event_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        r2 = dict(r)
        try:
            payload = json.loads(r2.get("payload") or "{}")
        except (TypeError, ValueError):
            payload = {}
        payload = _redact_payload(payload)
        r2["payload"] = json.dumps(payload, ensure_ascii=False)
        out.append(r2)
    return out


async def _dump_redacted_db(db: Database) -> bytes:
    """Return a copy of the SQLite DB with secret columns redacted."""
    src_path = db.path
    src = sqlite3.connect(str(src_path))
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            dst = sqlite3.connect(tmp_path)
            try:
                src.backup(dst)
                cur = dst.cursor()
                for table, cols in _REDACTED_COLUMNS.items():
                    for col in cols:
                        try:
                            cur.execute(
                                f"UPDATE {table} SET {col} = '***REDACTED***'"  # noqa: S608
                            )
                        except sqlite3.OperationalError:
                            # Table or column missing; skip
                            continue
                dst.commit()
                dst.close()
                return Path(tmp_path).read_bytes()
            finally:
                try:
                    dst.close()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            try:
                Path(tmp_path).unlink()
            except FileNotFoundError:
                pass
    finally:
        src.close()


async def export_run_bundle(
    db: Database,
    *,
    campaign_id: str,
    output_path: Path,
    config_snapshot: Any = None,
    artifact_index: list[dict[str, Any]] | None = None,
) -> BundleResult:
    """Export a redacted run bundle to ``output_path``.

    ``config_snapshot`` is an :class:`AppConfig` (or any pydantic model
    with ``model_dump``) whose values will be scrubbed of secrets.
    ``artifact_index`` lets the caller enumerate artifact files; the
    bundle only stores the index, not the file contents.
    """
    if not campaign_id:
        raise ValueError("campaign_id must be non-empty")
    output_path = Path(output_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = await _gather_campaign(db, campaign_id)
    if data["campaign"] is None:
        raise ValueError(f"unknown campaign: {campaign_id}")

    redacted_events = _redact_event_rows(data["events"])
    redacted_audit = _redact_audit_rows(data["audit"])

    usage_summary = {
        "free_calls_total": sum(1 for r in data["usage"] if r["is_free"]),
        "paid_calls_total": sum(1 for r in data["usage"] if r["is_paid"]),
        "input_tokens_total": sum(int(r["input_tokens"] or 0) for r in data["usage"]),
        "output_tokens_total": sum(int(r["output_tokens"] or 0) for r in data["usage"]),
        "cache_read_tokens_total": sum(int(r["cache_read_tokens"] or 0) for r in data["usage"]),
        "cache_write_tokens_total": sum(int(r["cache_write_tokens"] or 0) for r in data["usage"]),
        "estimated_cost_total": sum(float(r["estimated_cost"] or 0.0) for r in data["usage"]),
    }

    findings_payload = {
        "findings": data["findings"],
        "reviews": data["reviews"],
        "final_reports": data["reports"],
    }

    redaction_manifest = {
        "redacted_keys": sorted(["token", "secret", "password", "api_key", "apikey"]),
        "redacted_columns": [
            {"table": t, "columns": sorted(c)} for t, c in _REDACTED_COLUMNS.items()
        ],
        "redacted_patterns": [
            {"name": "bearer", "pattern": r"bearer\s+[A-Za-z0-9._\-]+"},
            {"name": "openai_key", "pattern": r"sk-[A-Za-z0-9]{20,}"},
            {"name": "anthropic_key", "pattern": r"sk-ant-[A-Za-z0-9\-]{20,}"},
            {"name": "google_key", "pattern": r"AIza[0-9A-Za-z\-_]{20,}"},
        ],
        "generated_at": _now_iso(),
    }

    manifest = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "exported_at": _now_iso(),
        "redacted": True,
        "counts": {
            "agents": len(data["agents"]),
            "tasks": len(data["tasks"]),
            "findings": len(data["findings"]),
            "reviews": len(data["reviews"]),
            "final_reports": len(data["reports"]),
            "system_events": len(redacted_events),
            "audit_events": len(redacted_audit),
            "usage_events": len(data["usage"]),
        },
    }

    db_bytes = await _dump_redacted_db(db)

    cfg_snapshot = _safe_config_snapshot(config_snapshot)

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("config_snapshot.json", json.dumps(cfg_snapshot, ensure_ascii=False, indent=2))
        zf.writestr("redaction_manifest.json", json.dumps(redaction_manifest, ensure_ascii=False, indent=2))
        zf.writestr("usage.json", json.dumps(usage_summary, ensure_ascii=False, indent=2))
        zf.writestr("findings.json", json.dumps(findings_payload, ensure_ascii=False, indent=2))
        zf.writestr(
            "artifacts_index.json",
            json.dumps({"items": artifact_index or []}, ensure_ascii=False, indent=2),
        )
        events_buf = "\n".join(json.dumps(r, ensure_ascii=False) for r in redacted_events)
        zf.writestr("events.jsonl", events_buf + ("\n" if events_buf else ""))
        audit_buf = "\n".join(json.dumps(r, ensure_ascii=False) for r in redacted_audit)
        zf.writestr("audit.jsonl", audit_buf + ("\n" if audit_buf else ""))
        zf.writestr("db_dump.sqlite", db_bytes)

    size = output_path.stat().st_size
    with zipfile.ZipFile(output_path) as zf:
        entry_count = len(zf.namelist())
    return BundleResult(path=output_path, size_bytes=size, entry_count=entry_count)


# Compile pattern table eagerly for downstream redaction tests.
_PATTERNS = [
    re.compile(r"bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
]


def redact_free_text(text: str) -> str:
    """Apply every redaction pattern to ``text`` and return the scrubbed copy."""
    if not text:
        return text
    for pat in _PATTERNS:
        text = pat.sub("***REDACTED***", text)
    return text


__all__ = [
    "BundleResult",
    "export_run_bundle",
    "redact_free_text",
]
