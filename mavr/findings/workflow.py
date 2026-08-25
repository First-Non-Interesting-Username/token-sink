"""Finding workflow orchestrator (spec §10).

This module is the glue that drives a single finding from
``initial_findings`` through the full review pipeline:

* discovery (initial finding write),
* first-cycle review (research agent),
* impact analysis,
* PoC draft (smallest safe, deterministic reproduction),
* four-agent review (with quorum + dispute + safety overrides),
* polishing (no new technical facts),
* final review (claim↔evidence traceability check),
* tombstone safeguards (dual confirmation),
* quarantine (all-reject).

The orchestrator exposes one :func:`advance_finding` function that
takes a finding id and the latest artifact payload and walks the state
machine. Individual steps can also be called directly (e.g. for
testing or a UI that wants fine-grained control).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr.findings import lifecycle
from mavr.findings.reviews import (
    KNOWN_QUORUM_POLICIES,
    OUTCOME_ADVANCE,
    OUTCOME_QUARANTINE,
    OUTCOME_REQUEST_CHANGES,
    ReviewError,
    ReviewSummary,
    compute_summary,
    evaluate_deletion,
)
from mavr.observability.logging import get_logger
from mavr.orchestrator import audit
from mavr.schemas import entities as schema

log = get_logger(__name__)


# Patterns we never want surfaced in evidence summaries, findings
# bodies, or final reports. A finding body that smuggles one of these
# must be flagged for redaction and never allowed to override scope.
_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore (?:all )?previous instructions", re.IGNORECASE),
    re.compile(r"override\s+scope", re.IGNORECASE),
    re.compile(r"disable\s+(?:the\s+)?kill\s*switch", re.IGNORECASE),
    re.compile(r"\bbypass\s+sandbox", re.IGNORECASE),
    re.compile(r"exfiltrat(?:e|ion)", re.IGNORECASE),
    re.compile(r"rm\s+-rf\s+/", re.IGNORECASE),
    re.compile(r"curl\s+[^\s|;&]+\s*\|\s*sh", re.IGNORECASE),
)


def detect_prompt_injection(text: str) -> list[str]:
    """Return the list of injection patterns detected in ``text``."""
    found: list[str] = []
    for pat in _PROMPT_INJECTION_PATTERNS:
        if pat.search(text):
            found.append(pat.pattern)
    return found


# ---- inputs -------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryPayload:
    """Spec §10.1 — required fields for an initial finding."""

    title: str
    description: str
    severity: schema.Severity
    confidence: str  # confirmed|likely|inconclusive|incorrect
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    target: str = ""
    attack_vector: str = ""
    observed_on: str = ""
    requested_by: str = "discovery_agent"

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.description.strip():
            raise ValueError("description must not be empty")
        if not self.evidence_refs:
            raise ValueError("at least one evidence_ref is required (spec §10.1)")
        if self.confidence not in {"confirmed", "likely", "inconclusive", "incorrect"}:
            raise ValueError(f"invalid confidence: {self.confidence!r}")


@dataclass(frozen=True)
class ImpactPayload:
    """Spec §10.3 — impact analysis output."""

    root_cause: str
    preconditions: str
    affected_versions: str
    security_boundary: str
    cia_impact: dict[str, str]
    exploitability: str
    mitigations: str
    evidence_gaps: list[str] = field(default_factory=list)
    severity: schema.Severity | None = None

    def __post_init__(self) -> None:
        if not self.root_cause.strip():
            raise ValueError("root_cause must not be empty")
        if not self.security_boundary.strip():
            raise ValueError("security_boundary must not be empty")
        for k in ("confidentiality", "integrity", "availability"):
            if k not in self.cia_impact:
                raise ValueError(f"cia_impact.{k} is required")


@dataclass(frozen=True)
class PoCPayload:
    """Spec §10.4 — smallest, deterministic PoC."""

    setup: str
    commands: tuple[str, ...]
    expected_output: str
    cleanup: str
    safety_notes: str
    target_kind: str  # local_mock|staging|live
    requires_human_approval: bool = True
    redacted_fields: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.setup.strip():
            raise ValueError("setup must not be empty")
        if not self.commands:
            raise ValueError("commands must not be empty")
        if self.target_kind not in {"local_mock", "staging", "live"}:
            raise ValueError(f"invalid target_kind: {self.target_kind!r}")
        # Any attempt to escalate to live must be flagged for human
        # approval. We always set requires_human_approval=True; a
        # caller that knows they have one can pass False explicitly
        # (used in tests and dry-runs).
        if self.target_kind == "live" and not self.requires_human_approval:
            raise ValueError("live-target PoCs require human_approved=true")


@dataclass(frozen=True)
class ReviewInput:
    """Spec §10.4 — single reviewer's verdict for a PoC."""

    reviewer_agent_id: str
    verdict: schema.ReviewVerdict
    validity: str
    reproduction_quality: str
    scope_safety: str
    severity_consistency: str
    missing_evidence: list[str] = field(default_factory=list)
    requested_changes: str = ""
    confidence: float = 0.0
    provider_id: str | None = None
    model_id: str | None = None
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.validity not in {"valid", "invalid", "inconclusive"}:
            raise ValueError(f"invalid validity: {self.validity!r}")
        if self.reproduction_quality not in {"high", "medium", "low", "n/a"}:
            raise ValueError(f"invalid reproduction_quality: {self.reproduction_quality!r}")
        if self.scope_safety not in {"safe", "unsafe", "unknown"}:
            raise ValueError(f"invalid scope_safety: {self.scope_safety!r}")
        if self.severity_consistency not in {"consistent", "inconsistent", "unknown"}:
            raise ValueError(f"invalid severity_consistency: {self.severity_consistency!r}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be in [0, 1]")


# ---- discovery ----------------------------------------------------------


async def create_initial_finding(
    conn: aiosqlite.Connection,
    *,
    campaign_id: str,
    payload: DiscoveryPayload,
    evidence_hashes: dict[str, str] | None = None,
) -> schema.Finding:
    """Spec §10.1 — insert a new finding in ``initial_findings``.

    Every required field is validated; prompt-injection attempts in
    the description cause the finding to be rejected at the door.
    """
    if detect_prompt_injection(payload.description):
        raise ValueError("description contains prompt-injection markers")
    for ref in payload.evidence_refs:
        if not _is_uuid(ref):
            raise ValueError(f"invalid evidence_ref uuid: {ref!r}")
    finding = await lifecycle.insert(
        conn,
        campaign_id=campaign_id,
        title=payload.title,
        severity=payload.severity,
        confidence=payload.confidence,
    )
    body = json.dumps(
        {
            "title": payload.title,
            "description": payload.description,
            "severity": payload.severity.value,
            "confidence": payload.confidence,
            "evidence_refs": list(payload.evidence_refs),
            "target": payload.target,
            "attack_vector": payload.attack_vector,
            "observed_on": payload.observed_on,
            "evidence_hashes": evidence_hashes or {},
        },
        ensure_ascii=False,
        indent=2,
    )
    await _write_finding_version(
        conn,
        finding_id=finding.id,
        version=1,
        state=schema.FindingState.INITIAL,
        body=body,
        evidence_refs=list(payload.evidence_refs),
        summary=payload.title,
    )
    return finding


# ---- first-cycle review (research_agent) ---------------------------------


async def run_first_cycle_review(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    reviewer_agent_id: str,
    conclusion: str,
    rationale: str,
    supporting_evidence: list[str],
) -> schema.Finding:
    """Lease, decide, and transition the finding to ``validated`` or ``disputed``.

    ``conclusion`` must be one of ``confirmed | likely | inconclusive
    | incorrect`` (spec §10.2). The function refuses to record a
    ``disputed`` outcome without at least one supporting evidence
    reference.
    """
    if conclusion not in {"confirmed", "likely", "inconclusive", "incorrect"}:
        raise ReviewError(f"invalid first-cycle conclusion: {conclusion!r}")
    if not supporting_evidence:
        raise ReviewError("first-cycle review must cite at least one evidence_ref")

    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.INITIAL:
        raise ReviewError(
            f"finding is in {finding.state.value}, expected initial_findings"
        )

    lease = await lifecycle.lease(
        conn, finding_id=finding_id, owner=reviewer_agent_id, ttl_seconds=300
    )
    if lease is None:
        raise ReviewError("could not acquire finding lease for first-cycle review")

    try:
        # Mark the finding as under review first.
        if finding.state == schema.FindingState.INITIAL:
            finding = await lifecycle.transition(
                conn,
                finding_id=finding_id,
                new_state=schema.FindingState.REVIEW_CYCLE_1,
                actor_id=reviewer_agent_id,
                reason="first-cycle review claimed",
            )
        if conclusion in {"confirmed", "likely"}:
            new_state = schema.FindingState.VALIDATED
        else:
            new_state = schema.FindingState.DISPUTED
        # The first-cycle review is captured in the audit log only —
        # the versioned body is written by subsequent impact / PoC /
        # polish steps. This keeps the version chain monotonic with
        # the lifecycle bump set (impact, poc_draft, polished).
        await audit.record(
            conn,
            actor_id=reviewer_agent_id,
            actor_kind=schema.ActorKind.AGENT,
            category=schema.AuditCategory.POLICY_DECISION,
            subject_kind="finding",
            subject_id=finding_id,
            prior_state=finding.state.value,
            new_state=schema.FindingState.REVIEW_CYCLE_1.value,
            reason=f"first_cycle:{conclusion}",
            metadata={
                "conclusion": conclusion,
                "rationale": rationale,
                "supporting_evidence": list(supporting_evidence),
            },
        )
        finding = await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=new_state,
            actor_id=reviewer_agent_id,
            reason=f"first_cycle:{conclusion}",
            metadata={"conclusion": conclusion, "evidence_count": len(supporting_evidence)},
        )
    finally:
        await lifecycle.release_lease(conn, finding_id=finding_id, owner=reviewer_agent_id)
    return finding


# ---- impact analysis ----------------------------------------------------


async def record_impact(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    agent_id: str,
    impact: ImpactPayload,
) -> schema.Finding:
    """Move a validated finding to ``impact_analysis`` and persist the body."""
    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.VALIDATED:
        raise ReviewError(
            f"finding is in {finding.state.value}, expected validated"
        )
    lease = await lifecycle.lease(conn, finding_id=finding_id, owner=agent_id)
    if lease is None:
        raise ReviewError("could not acquire finding lease for impact")
    try:
        body = json.dumps(
            {
                "root_cause": impact.root_cause,
                "preconditions": impact.preconditions,
                "affected_versions": impact.affected_versions,
                "security_boundary": impact.security_boundary,
                "cia_impact": dict(impact.cia_impact),
                "exploitability": impact.exploitability,
                "mitigations": impact.mitigations,
                "evidence_gaps": list(impact.evidence_gaps),
                "severity": impact.severity.value if impact.severity else None,
            },
            ensure_ascii=False,
            indent=2,
        )
        severity = impact.severity or finding.severity
        # Persist impact_version so we have a clean diff chain.
        # The transition to IMPACT will bump current_version; write
        # the body at the post-bump version.
        next_version = finding.current_version + 1
        await _write_finding_version(
            conn,
            finding_id=finding_id,
            version=next_version,
            state=schema.FindingState.IMPACT,
            body=body,
            evidence_refs=[],
            summary=f"impact:{impact.root_cause[:60]}",
        )
        finding = await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.IMPACT,
            actor_id=agent_id,
            reason="impact analysis recorded",
            metadata={"severity": severity.value if severity else None},
        )
        if severity is not None and severity != finding.severity:
            await conn.execute(
                "UPDATE findings SET severity = ? WHERE id = ?",
                (severity.value, finding_id),
            )
            await conn.commit()
            finding.severity = severity
    finally:
        await lifecycle.release_lease(conn, finding_id=finding_id, owner=agent_id)
    return finding


# ---- PoC draft ----------------------------------------------------------


async def record_poc_draft(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    agent_id: str,
    poc: PoCPayload,
) -> schema.Finding:
    """Persist the smallest, safe, deterministic PoC.

    Rejects prompt-injection attempts in setup / commands / safety
    notes — the PoC content is *untrusted* once stored and may not
    contain instructions that could override scope.
    """
    for field_name in ("setup", "safety_notes", "expected_output", "cleanup"):
        text = getattr(poc, field_name)
        if detect_prompt_injection(text):
            raise ReviewError(
                f"PoC.{field_name} contains prompt-injection markers — refusing to record"
            )
    for cmd in poc.commands:
        if detect_prompt_injection(cmd):
            raise ReviewError(
                f"PoC.commands contains prompt-injection markers: {cmd!r}"
            )
    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.IMPACT:
        raise ReviewError(f"finding is in {finding.state.value}, expected impact_analysis")
    lease = await lifecycle.lease(conn, finding_id=finding_id, owner=agent_id)
    if lease is None:
        raise ReviewError("could not acquire finding lease for PoC draft")
    try:
        # Write at the post-bump version (POC_DRAFT auto-bumps).
        next_version = finding.current_version + 1
        body = json.dumps(
            {
                "setup": poc.setup,
                "commands": list(poc.commands),
                "expected_output": poc.expected_output,
                "cleanup": poc.cleanup,
                "safety_notes": poc.safety_notes,
                "target_kind": poc.target_kind,
                "requires_human_approval": poc.requires_human_approval,
                "redacted_fields": list(poc.redacted_fields),
            },
            ensure_ascii=False,
            indent=2,
        )
        await _write_finding_version(
            conn,
            finding_id=finding_id,
            version=next_version,
            state=schema.FindingState.POC_DRAFT,
            body=body,
            evidence_refs=[],
            summary=f"poc_draft:{poc.target_kind}",
        )
        # Persist the PoC row
        await conn.execute(
            "INSERT INTO pocs("
            "id, schema_version, finding_id, version, setup, commands, expected_output, "
            "cleanup, safety_notes, redacted_fields, target_kind, requires_human_approval, "
            "created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                schema.SCHEMA_VERSION,
                finding_id,
                next_version,
                poc.setup,
                json.dumps(list(poc.commands)),
                poc.expected_output,
                poc.cleanup,
                poc.safety_notes,
                json.dumps(list(poc.redacted_fields)),
                poc.target_kind,
                1 if poc.requires_human_approval else 0,
                _now_iso(),
            ),
        )
        finding = await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.POC_DRAFT,
            actor_id=agent_id,
            reason="PoC draft recorded",
            metadata={
                "target_kind": poc.target_kind,
                "requires_human_approval": poc.requires_human_approval,
            },
        )
    finally:
        await lifecycle.release_lease(conn, finding_id=finding_id, owner=agent_id)
    return finding


# ---- four-agent review --------------------------------------------------


async def record_review(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    review: ReviewInput,
) -> schema.Review:
    """Insert a single reviewer's verdict (idempotent per reviewer)."""
    from mavr.findings import reviews as reviews_mod

    if not _is_uuid(review.reviewer_agent_id):
        raise ReviewError("reviewer_agent_id must be a UUID")
    return await reviews_mod.insert(
        conn,
        finding_id=finding_id,
        version=version,
        reviewer_agent_id=review.reviewer_agent_id,
        verdict=review.verdict,
        validity=review.validity,
        reproduction_quality=review.reproduction_quality,
        scope_safety=review.scope_safety,
        severity_consistency=review.severity_consistency,
        missing_evidence=review.missing_evidence,
        requested_changes=review.requested_changes,
        confidence=review.confidence,
        provider_id=review.provider_id,
        model_id=review.model_id,
        rationale=review.rationale,
    )


async def fold_reviews(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    mode: str = "independent_first",
    quorum_policy: str = "all_accept_or_3_of_4_no_blockers",
    reviewer_count: int = 4,
) -> ReviewSummary:
    """Collect all reviews for ``(finding, version)`` and persist a summary.

    The finding is transitioned based on the summary:

    * ``advance`` → ``poc_review`` → ready for polish (or directly to
      ``polished_report`` once a PoC was the focus).
    * ``quarantine`` → ``quarantined``.
    * ``request_changes`` → revert to ``poc_draft`` for rework.
    * ``inconclusive`` → stays in ``poc_review``.
    """
    from mavr.findings import reviews as reviews_mod

    if quorum_policy not in KNOWN_QUORUM_POLICIES:
        raise ReviewError(f"unknown quorum policy: {quorum_policy!r}")
    if mode not in {"independent_first", "discussion_first"}:
        raise ReviewError(f"unknown review mode: {mode!r}")

    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.POC_REVIEW:
        raise ReviewError(
            f"finding is in {finding.state.value}, expected poc_review"
        )

    reviews = await reviews_mod.list_for_finding_version(
        conn, finding_id=finding_id, version=version
    )
    summary = compute_summary(
        reviews,
        finding_id=finding_id,
        version=version,
        mode=mode,
        quorum_policy=quorum_policy,
    )
    await reviews_mod.record_summary(conn, summary)
    if summary.outcome == OUTCOME_ADVANCE:
        await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.POLISHED,
            actor_id=None,
            reason="quorum advance",
            metadata={
                "accept": summary.accept_count,
                "reject": summary.reject_count,
                "mode": mode,
                "quorum": quorum_policy,
            },
        )
    elif summary.outcome == OUTCOME_QUARANTINE:
        await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.QUARANTINED,
            actor_id=None,
            reason="quorum quarantine",
            metadata={
                "blocking_issues": summary.blocking_issues,
                "mode": mode,
            },
        )
    elif summary.outcome == OUTCOME_REQUEST_CHANGES:
        await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.POC_DRAFT,
            actor_id=None,
            reason="request_changes → rework",
            metadata={"mode": mode},
        )
    return summary


# ---- final review (claim ↔ evidence traceability) ----------------------


@dataclass(frozen=True)
class TraceabilityReport:
    passed: bool
    missing_evidence_claims: list[str]
    altered_claims: list[str]
    notes: str


def check_traceability(
    *,
    polished_body: str,
    source_evidence: dict[str, dict[str, Any]],
) -> TraceabilityReport:
    """Ensure every claim in ``polished_body`` links to an EvidenceItem.

    A claim is any ``[evidence:<uuid>]`` reference in the body. Each
    referenced uuid must exist in ``source_evidence``. An evidence row
    may also set ``"claim": "value"`` to assert that the verbatim text
    must appear in the body; the report flags mismatches as
    ``altered_claims``. Rows that omit the ``claim`` key only require
    existence, not verbatim match (so common references like an
    advisory link don't need the advisory title spelled out in the
    report).
    """
    if detect_prompt_injection(polished_body):
        return TraceabilityReport(
            passed=False,
            missing_evidence_claims=[],
            altered_claims=[],
            notes="polished body contains prompt-injection markers",
        )
    missing: list[str] = []
    altered: list[str] = []
    pattern = re.compile(r"\[evidence:([0-9a-f-]{36})\]")
    referenced = pattern.findall(polished_body)
    for ref in referenced:
        if ref not in source_evidence:
            missing.append(ref)
            continue
        ev = source_evidence[ref]
        # Only enforce verbatim match when the evidence asserts a claim.
        claim = ev.get("claim") or ev.get("must_contain")
        if claim and isinstance(claim, str) and claim not in polished_body:
            altered.append(ref)
    return TraceabilityReport(
        passed=not missing and not altered,
        missing_evidence_claims=missing,
        altered_claims=altered,
        notes=("all claims traced" if not missing and not altered else "see findings"),
    )


async def run_final_review(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    agent_id: str,
    polished_body: str,
    source_evidence: dict[str, dict[str, Any]],
    auto_advance: bool = True,
) -> tuple[schema.Finding, TraceabilityReport]:
    """Spec §10.6 — final review: claim↔evidence traceability.

    When ``auto_advance`` is true and the traceability check passes,
    the finding is moved to ``vulnerabilities``. If the check fails
    the finding is reverted to ``polished_report`` for rework.
    """
    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state not in {schema.FindingState.POLISHED, schema.FindingState.FINAL_REVIEW}:
        raise ReviewError(
            f"finding is in {finding.state.value}, expected polished_report or final_review"
        )

    report = check_traceability(
        polished_body=polished_body, source_evidence=source_evidence
    )
    await audit.record(
        conn,
        actor_id=agent_id,
        actor_kind=schema.ActorKind.AGENT,
        category=schema.AuditCategory.POLICY_DECISION,
        subject_kind="finding",
        subject_id=finding_id,
        prior_state=finding.state.value,
        new_state=finding.state.value,
        reason="final_review traceability",
        metadata={
            "passed": report.passed,
            "missing": report.missing_evidence_claims,
            "altered": report.altered_claims,
        },
    )
    if not report.passed:
        if auto_advance:
            await lifecycle.transition(
                conn,
                finding_id=finding_id,
                new_state=schema.FindingState.POLISHED,
                actor_id=agent_id,
                reason="final_review failed traceability → rework",
                metadata={"report": report.notes},
            )
        return finding, report

    if auto_advance:
        # The state machine requires POLISHED → FINAL_REVIEW → VULNERABILITY.
        if finding.state == schema.FindingState.POLISHED:
            finding = await lifecycle.transition(
                conn,
                finding_id=finding_id,
                new_state=schema.FindingState.FINAL_REVIEW,
                actor_id=agent_id,
                reason="final review started",
                metadata={"notes": report.notes},
            )
        finding = await lifecycle.transition(
            conn,
            finding_id=finding_id,
            new_state=schema.FindingState.VULNERABILITY,
            actor_id=agent_id,
            reason="final_review passed",
            metadata={"notes": report.notes},
        )
    return finding, report


# ---- deletion safeguard -------------------------------------------------


@dataclass(frozen=True)
class TombstoneRequest:
    finding_id: str
    requested_by: str  # human actor
    reason: str
    approval_id: str  # approval token, must be for 'deletion'


async def tombstone(
    conn: aiosqlite.Connection,
    *,
    request: TombstoneRequest,
) -> schema.Finding:
    """Dual-confirmation tombstone (spec §10.5).

    Requires:

    1. a human approval token (action=deletion) consumed by the caller
       *before* invoking this function;
    2. both the original review and a dispute review concluded
       ``incorrect`` (validity=invalid, verdict=reject).
    """
    from mavr import approvals as approvals_mod

    # 1. Verify approval.
    approval = await approvals_mod.get_by_token(conn, request.approval_id)
    if approval is None and _is_uuid(request.approval_id):
        # The CLI passes the *token*; allow lookup by id by canonical
        # conversion. We do this by scanning (id is unique).
        cur = await conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (request.approval_id,)
        )
        row = await cur.fetchone()
        approval = (
            approvals_mod._row_to_approval(row) if row else None
        )  # type: ignore[attr-defined]
    if approval is None:
        raise ReviewError("deletion requires an approval token (action=deletion)")
    if approval.action != "deletion":
        raise ReviewError(
            f"approval action mismatch: expected 'deletion', got {approval.action!r}"
        )
    if approval.consumed_at is None:
        raise ReviewError("approval token must be consumed before tombstone")
    if approval.finding_id not in (None, request.finding_id):
        raise ReviewError("approval was issued for a different finding")

    # 2. Verify dual confirmation.
    reviews = await list_all_reviews(conn, request.finding_id)
    verdict = evaluate_deletion(reviews, original_conclusion="incorrect")
    if not verdict.eligible:
        raise ReviewError(f"tombstone refused: {verdict.reason}")

    finding = await lifecycle.get(conn, request.finding_id)
    if finding is None:
        raise ReviewError(f"finding {request.finding_id} not found")
    if finding.state == schema.FindingState.TOMBSTONED:
        return finding

    lease = await lifecycle.lease(
        conn, finding_id=request.finding_id, owner=request.requested_by
    )
    if lease is None:
        raise ReviewError("could not acquire finding lease for tombstone")
    try:
        await lifecycle.transition(
            conn,
            finding_id=request.finding_id,
            new_state=schema.FindingState.TOMBSTONED,
            actor_id=None,
            actor_kind=schema.ActorKind.HUMAN,
            reason=request.reason,
            metadata={
                "approval_id": approval.id,
                "requested_by": request.requested_by,
                "original_review_id": verdict.original_review_id,
                "dispute_review_id": verdict.dispute_review_id,
            },
        )
    finally:
        await lifecycle.release_lease(
            conn, finding_id=request.finding_id, owner=request.requested_by
        )
    result = await lifecycle.get(conn, request.finding_id)
    assert result is not None
    return result


# ---- helpers ------------------------------------------------------------


async def _write_finding_version(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    state: schema.FindingState,
    body: str,
    evidence_refs: list[str],
    summary: str,
) -> None:
    await conn.execute(
        "INSERT INTO finding_versions("
        "id, schema_version, finding_id, version, state, author_agent_id, "
        "summary, body_markdown, evidence_refs, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()),
            schema.SCHEMA_VERSION,
            finding_id,
            version,
            state.value,
            None,
            summary,
            body,
            json.dumps(evidence_refs, ensure_ascii=False),
            _now_iso(),
        ),
    )


async def list_all_reviews(
    conn: aiosqlite.Connection, finding_id: str
) -> list[schema.Review]:
    from mavr.findings import reviews as reviews_mod

    return await reviews_mod.list_all_for_finding(conn, finding_id)


def _is_uuid(value: str) -> bool:
    return bool(
        re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            value,
        )
    )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---- final-report writer ------------------------------------------------


@dataclass(frozen=True)
class FinalReportArtifacts:
    finding_id: str
    version: int
    report_path: str
    evidence_manifest_path: str
    redaction_manifest_path: str
    hash_manifest: str
    bytes: dict[str, int]
    files: list[str]


async def write_final_report(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    output_dir: str,
    body_markdown: str,
    evidence_manifest: dict[str, Any],
    redactions: list[dict[str, str]],
) -> FinalReportArtifacts:
    """Persist the final report under ``<output_dir>/<finding>/<version>/``.

    Layout::

        <output_dir>/<finding>/<version>/report.md
        <output_dir>/<finding>/<version>/evidence.json
        <output_dir>/<finding>/<version>/redaction.json
        <output_dir>/<finding>/<version>/hashes.txt

    Returns a :class:`FinalReportArtifacts` with all paths and the
    hash manifest. The function refuses to write if the finding is
    not in the ``vulnerabilities`` state — the final report is only
    valid after :func:`run_final_review` has passed.
    """
    from pathlib import Path

    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise ReviewError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.VULNERABILITY:
        raise ReviewError(
            f"cannot write final report in state {finding.state.value}; "
            "final review must pass first"
        )

    target = Path(output_dir).expanduser().resolve() / finding_id / str(version)
    target.mkdir(parents=True, exist_ok=True)
    report_path = target / "report.md"
    evidence_path = target / "evidence.json"
    redaction_path = target / "redaction.json"
    hashes_path = target / "hashes.txt"

    report_path.write_text(body_markdown, encoding="utf-8")
    evidence_path.write_text(
        json.dumps(evidence_manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    redaction_path.write_text(
        json.dumps(redactions, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # Hash every file we just wrote.
    digest_lines: list[str] = []
    file_bytes: dict[str, int] = {}
    for path in (report_path, evidence_path, redaction_path):
        h = hashlib.sha256()
        data = path.read_bytes()
        h.update(data)
        digest_lines.append(f"{h.hexdigest()}  {path.relative_to(target)}")
        file_bytes[path.name] = len(data)
    # Hash of the hash manifest itself for the DB column.
    manifest_blob = "\n".join(digest_lines).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_blob).hexdigest()
    hashes_path.write_text(
        "\n".join(digest_lines) + f"\n{manifest_hash}  hashes.txt.signed\n",
        encoding="utf-8",
    )
    file_bytes[hashes_path.name] = len(manifest_blob) + 1

    # Persist the final_reports row.
    rid = str(uuid4())
    await conn.execute(
        "INSERT INTO final_reports("
        "id, schema_version, finding_id, version, report_path, "
        "evidence_manifest_path, redaction_manifest_path, hash_manifest, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            rid,
            schema.SCHEMA_VERSION,
            finding_id,
            version,
            str(report_path),
            str(evidence_path),
            str(redaction_path),
            manifest_hash,
            _now_iso(),
        ),
    )
    await conn.commit()

    return FinalReportArtifacts(
        finding_id=finding_id,
        version=version,
        report_path=str(report_path),
        evidence_manifest_path=str(evidence_path),
        redaction_manifest_path=str(redaction_path),
        hash_manifest=manifest_hash,
        bytes=file_bytes,
        files=[
            str(report_path),
            str(evidence_path),
            str(redaction_path),
            str(hashes_path),
        ],
    )


__all__ = [
    "DiscoveryPayload",
    "FinalReportArtifacts",
    "ImpactPayload",
    "PoCPayload",
    "ReviewInput",
    "TombstoneRequest",
    "TraceabilityReport",
    "check_traceability",
    "create_initial_finding",
    "detect_prompt_injection",
    "fold_reviews",
    "record_impact",
    "record_poc_draft",
    "record_review",
    "run_final_review",
    "run_first_cycle_review",
    "tombstone",
    "write_final_report",
]
