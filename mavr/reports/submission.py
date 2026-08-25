"""Report submission (spec §10.6, §17).

Submission is NEVER automatic. The flow is:

1. The user runs ``system report submit <finding>`` with a freshly
   minted ``--approval-token`` (from :func:`mavr.approvals.create`).
2. The CLI calls :func:`submit` here, which:
   * re-validates the finding is in ``vulnerabilities`` state,
   * consumes the approval token (action=submission),
   * writes a manifest to disk under
     ``vulnerabilities/<id>/<version>/submission/``,
   * records a :class:`mavr.schemas.entities.FinalReport` row in
     ``submission_manifests`` and an audit event,
   * optionally performs an HTTP POST when ``transport='http'`` is
     explicitly enabled per campaign.
"""
from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr import approvals as approvals_mod
from mavr.findings import lifecycle
from mavr.findings.workflow import write_final_report
from mavr.observability.logging import get_logger
from mavr.orchestrator import audit
from mavr.schemas import entities as schema

log = get_logger(__name__)


class SubmissionError(RuntimeError):
    """Raised when a submission cannot proceed."""


@dataclass(frozen=True)
class SubmissionResult:
    finding_id: str
    version: int
    manifest_path: str
    transport: str  # manifest_only | http
    target: str
    response_status: int | None
    approval_id: str
    submitted_at: datetime


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _resolve_host_is_blocked(host: str) -> bool:
    """Heuristic SSRF guard for HTTP submission. We never POST to:
    * loopback / link-local / private ranges,
    * the cloud metadata service (169.254.169.254),
    * any hostname that does not resolve to a public IP.
    The spec's full SSRF defense is in :mod:`mavr.policy`; this is the
    submission-time belt-and-braces check.
    """
    import ipaddress

    blocked = {"localhost", "metadata.google.internal", "metadata"}
    if host.lower() in blocked:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True
    return False


async def submit(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    approval_token: str,
    output_dir: str,
    transport: str = "manifest_only",
    target: str = "manifest-only",
    human_approved: bool = False,
    extra_metadata: dict[str, Any] | None = None,
) -> SubmissionResult:
    """Submit a finalized finding.

    ``approval_token`` is consumed atomically. ``transport`` is
    ``manifest_only`` (default; safe) or ``http``. The HTTP transport
    is only allowed when ``human_approved=True`` is passed *and* the
    approval token is present.
    """
    if not human_approved:
        raise SubmissionError(
            "submission requires an explicit human_approved token; "
            "pass --human-approved to the CLI"
        )
    if transport not in {"manifest_only", "http"}:
        raise SubmissionError(f"unknown transport: {transport!r}")
    if transport == "http" and not target.startswith(("http://", "https://")):
        raise SubmissionError("http transport requires an http(s):// target URL")

    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise SubmissionError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.VULNERABILITY:
        raise SubmissionError(
            f"finding is in {finding.state.value}; only findings in "
            "vulnerabilities may be submitted"
        )

    approval = await approvals_mod.consume(
        conn, token=approval_token, expected_action="submission"
    )

    artifacts = await write_final_report(
        conn,
        finding_id=finding_id,
        version=version,
        output_dir=output_dir,
        body_markdown=await _load_latest_body(conn, finding_id, version),
        evidence_manifest={"approval_id": approval.id, "transport": transport},
        redactions=[],
    )

    submission_dir = (
        artifacts.report_path.rsplit("/", 1)[0] + "/submission"
        if "/" in artifacts.report_path
        else artifacts.report_path + "_submission"
    )
    from pathlib import Path

    sub_path = Path(submission_dir)
    sub_path.mkdir(parents=True, exist_ok=True)
    manifest_blob = {
        "finding_id": finding_id,
        "version": version,
        "approval_id": approval.id,
        "approval_actor": approval.actor,
        "transport": transport,
        "target": target,
        "submitted_at": _now_iso(),
        "report_path": artifacts.report_path,
        "evidence_manifest_path": artifacts.evidence_manifest_path,
        "redaction_manifest_path": artifacts.redaction_manifest_path,
        "hash_manifest": artifacts.hash_manifest,
        "extra_metadata": extra_metadata or {},
    }
    manifest_path = sub_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_blob, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    response_status: int | None = None
    if transport == "http":
        # Belt-and-braces SSRF check at submission time.
        from urllib.parse import urlparse

        host = urlparse(target).hostname or ""
        if _resolve_host_is_blocked(host):
            raise SubmissionError(
                f"http target {target!r} resolves to a blocked host"
            )
        # We deliberately keep this minimal: a real implementation
        # would build a signed envelope and POST. The harness is the
        # manifest on disk; the HTTP path is opt-in and only fires
        # after the SSRF guard.
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    target,
                    json=manifest_blob,
                    headers={"content-type": "application/json"},
                )
                response_status = resp.status_code
        except httpx.HTTPError as exc:
            raise SubmissionError(f"http submission failed: {exc}") from exc

    sid = str(uuid4())
    await conn.execute(
        "INSERT INTO submission_manifests("
        "id, schema_version, finding_id, version, approval_id, transport, target, "
        "manifest_path, response_status, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sid,
            schema.SCHEMA_VERSION,
            finding_id,
            version,
            approval.id,
            transport,
            target,
            str(manifest_path),
            response_status,
            _now_iso(),
        ),
    )
    await audit.record(
        conn,
        actor_id=None,
        actor_kind=schema.ActorKind.HUMAN,
        category=schema.AuditCategory.STATE_TRANSITION,
        subject_kind="finding",
        subject_id=finding_id,
        prior_state=finding.state.value,
        new_state="submitted",
        reason=f"submission transport={transport}",
        metadata={
            "transport": transport,
            "target": target,
            "manifest_path": str(manifest_path),
            "approval_id": approval.id,
            "approval_actor": approval.actor,
            "response_status": response_status,
        },
    )
    await conn.commit()
    return SubmissionResult(
        finding_id=finding_id,
        version=version,
        manifest_path=str(manifest_path),
        transport=transport,
        target=target,
        response_status=response_status,
        approval_id=approval.id,
        submitted_at=datetime.now(UTC),
    )


async def _load_latest_body(
    conn: aiosqlite.Connection, finding_id: str, version: int
) -> str:
    cur = await conn.execute(
        "SELECT body_markdown FROM finding_versions "
        "WHERE finding_id = ? AND version = ? ORDER BY created_at DESC LIMIT 1",
        (finding_id, version),
    )
    row = await cur.fetchone()
    if row is None:
        return f"# Final report for {finding_id} v{version}\n"
    return row["body_markdown"]


__all__ = [
    "SubmissionError",
    "SubmissionResult",
    "submit",
]


# Hash helper used by tests to verify the manifest.
def manifest_sha256(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
