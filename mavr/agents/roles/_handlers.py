"""Phase 6 agent role handlers (spec §10).

Each role is a thin async function with the same signature as
:class:`mavr.orchestrator.runtime.AgentHandler`. Roles do not call
LLMs themselves; they read the task payload (which already contains
the upstream output) and return the next structured payload. The
runtime, audit, and the workflow module handle state transitions.

Why a "function" rather than a class? Spec §6 calls them agent
roles; the runtime dispatches by ``Task.kind`` so any callable
matching the handler protocol works. A function makes the
deterministic / test-only path obvious.

The role list:

* :func:`discovery_agent` — turns a search/extract result into a
  :class:`workflow.DiscoveryPayload`.
* :func:`research_agent` — runs the first-cycle review (conclusion
  + supporting evidence) on an initial finding.
* :func:`impact_agent` — produces an :class:`workflow.ImpactPayload`
  for a validated finding.
* :func:`poc_agent` — produces a :class:`workflow.PoCPayload` for an
  impact-analyzed finding.
* :func:`reviewer_agent` — produces a :class:`workflow.ReviewInput`
  for a PoC draft (called 4× per finding with diversity).
* :func:`polish_agent` — converts the validated state into the final
  report body, without changing technical facts.
* :func:`final_review_agent` — runs traceability and either advances
  the finding or sends it back for rework.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mavr.findings import workflow
from mavr.findings.workflow import (
    DiscoveryPayload,
    ImpactPayload,
    PoCPayload,
    ReviewInput,
)
from mavr.orchestrator.runtime import RuntimeContext
from mavr.schemas import entities as schema

# A role is a coroutine function taking (task, ctx) and returning a
# dict (the task's ``result``).
RoleHandler = Callable[[schema.Task, RuntimeContext], "Any"]


# ---- discovery ----------------------------------------------------------


async def discovery_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Create the initial finding from upstream search/extract data.

    The task payload MUST include::

        {
            "campaign_id": "...",
            "payload": {
                "title": "...",
                "description": "...",
                "severity": "low|medium|high|critical|info",
                "confidence": "confirmed|likely|inconclusive|incorrect",
                "evidence_refs": ["<uuid>", ...],
                "target": "...",
                "attack_vector": "...",
                "observed_on": "ISO-8601",
                "evidence_hashes": {"<uuid>": "<sha256hex>"},
            }
        }

    The handler is deterministic and offline: it does NOT call any
    LLM. A future implementation may swap in a real provider; the
    structured-output contract is the same.
    """
    from mavr.findings import workflow as wf

    payload = task.payload.get("payload", {})
    discovery = DiscoveryPayload(
        title=str(payload.get("title", "")).strip(),
        description=str(payload.get("description", "")).strip(),
        severity=schema.Severity(str(payload.get("severity", "info"))),
        confidence=str(payload.get("confidence", "inconclusive")),  # type: ignore[arg-type]
        evidence_refs=tuple(payload.get("evidence_refs", []) or []),
        target=str(payload.get("target", "")),
        attack_vector=str(payload.get("attack_vector", "")),
        observed_on=str(payload.get("observed_on", "")),
        requested_by=task.payload.get("requested_by", "discovery_agent"),
    )
    evidence_hashes = payload.get("evidence_hashes") or {}
    finding = await wf.create_initial_finding(
        ctx.db,
        campaign_id=task.campaign_id,
        payload=discovery,
        evidence_hashes=evidence_hashes,
    )
    ctx.charge_tool_call()
    return {
        "finding_id": finding.id,
        "state": finding.state.value,
        "severity": finding.severity.value if finding.severity else None,
        "confidence": finding.confidence,
    }


# ---- research (first-cycle review) --------------------------------------


async def research_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """First-cycle review: claim a lease and decide confirmed/likely/etc.

    Payload contract::

        {
            "finding_id": "...",
            "conclusion": "confirmed|likely|inconclusive|incorrect",
            "rationale": "...",
            "supporting_evidence": ["<uuid>", ...]
        }
    """
    finding_id = task.payload["finding_id"]
    conclusion = task.payload["conclusion"]
    rationale = task.payload.get("rationale", "")
    evidence = list(task.payload.get("supporting_evidence", []))
    finding = await workflow.run_first_cycle_review(
        ctx.db,
        finding_id=finding_id,
        reviewer_agent_id=ctx.agent.id,
        conclusion=conclusion,
        rationale=rationale,
        supporting_evidence=evidence,
    )
    ctx.charge_tool_call()
    return {
        "finding_id": finding.id,
        "new_state": finding.state.value,
        "conclusion": conclusion,
    }


# ---- impact -------------------------------------------------------------


async def impact_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Spec §10.3 impact analysis.

    Payload contract::

        {
            "finding_id": "...",
            "root_cause": "...",
            "preconditions": "...",
            "affected_versions": "...",
            "security_boundary": "...",
            "cia_impact": {"confidentiality": "...", "integrity": "...", "availability": "..."},
            "exploitability": "...",
            "mitigations": "...",
            "evidence_gaps": [...],
            "severity": "..."  # optional override
        }
    """
    p = task.payload
    impact = ImpactPayload(
        root_cause=p["root_cause"],
        preconditions=p.get("preconditions", ""),
        affected_versions=p.get("affected_versions", ""),
        security_boundary=p["security_boundary"],
        cia_impact=dict(p.get("cia_impact", {})),
        exploitability=p.get("exploitability", ""),
        mitigations=p.get("mitigations", ""),
        evidence_gaps=list(p.get("evidence_gaps", []) or []),
        severity=schema.Severity(p["severity"]) if p.get("severity") else None,
    )
    finding = await workflow.record_impact(
        ctx.db,
        finding_id=p["finding_id"],
        agent_id=ctx.agent.id,
        impact=impact,
    )
    ctx.charge_tool_call()
    return {
        "finding_id": finding.id,
        "new_state": finding.state.value,
        "severity": finding.severity.value if finding.severity else None,
    }


# ---- PoC ---------------------------------------------------------------


async def poc_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Spec §10.4 PoC draft.

    Payload contract::

        {
            "finding_id": "...",
            "setup": "...",
            "commands": ["...", "..."],
            "expected_output": "...",
            "cleanup": "...",
            "safety_notes": "...",
            "target_kind": "local_mock|staging|live",
            "redacted_fields": [...]
        }
    """
    p = task.payload
    poc = PoCPayload(
        setup=p["setup"],
        commands=tuple(p.get("commands", []) or []),
        expected_output=p.get("expected_output", ""),
        cleanup=p.get("cleanup", ""),
        safety_notes=p.get("safety_notes", ""),
        target_kind=p.get("target_kind", "local_mock"),
        requires_human_approval=bool(p.get("requires_human_approval", True)),
        redacted_fields=tuple(p.get("redacted_fields", []) or []),
    )
    finding = await workflow.record_poc_draft(
        ctx.db,
        finding_id=p["finding_id"],
        agent_id=ctx.agent.id,
        poc=poc,
    )
    ctx.charge_tool_call()
    return {
        "finding_id": finding.id,
        "new_state": finding.state.value,
        "target_kind": poc.target_kind,
    }


# ---- reviewer (4× per PoC) ----------------------------------------------


async def reviewer_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Record one reviewer's verdict against a (finding, version) pair.

    Payload contract::

        {
            "finding_id": "...",
            "version": <int>,
            "verdict": "accept|reject|request_changes",
            "validity": "valid|invalid|inconclusive",
            "reproduction_quality": "high|medium|low|n/a",
            "scope_safety": "safe|unsafe|unknown",
            "severity_consistency": "consistent|inconsistent|unknown",
            "missing_evidence": [...],
            "requested_changes": "...",
            "confidence": 0.0,
            "provider_id": "...",
            "model_id": "...",
            "rationale": "..."
        }
    """
    p = task.payload
    review = ReviewInput(
        reviewer_agent_id=ctx.agent.id,
        verdict=schema.ReviewVerdict(p["verdict"]),
        validity=p["validity"],
        reproduction_quality=p["reproduction_quality"],
        scope_safety=p["scope_safety"],
        severity_consistency=p["severity_consistency"],
        missing_evidence=list(p.get("missing_evidence", []) or []),
        requested_changes=p.get("requested_changes", ""),
        confidence=float(p.get("confidence", 0.0)),
        provider_id=p.get("provider_id"),
        model_id=p.get("model_id"),
        rationale=p.get("rationale", ""),
    )
    saved = await workflow.record_review(
        ctx.db,
        finding_id=p["finding_id"],
        version=int(p["version"]),
        review=review,
    )
    ctx.charge_tool_call()
    return {
        "review_id": saved.id,
        "verdict": saved.verdict.value,
        "scope_safety": saved.scope_safety,
        "validity": saved.validity,
    }


# ---- polish -------------------------------------------------------------


async def polish_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Convert the validated state to a final-report-shaped body.

    The polish agent NEVER introduces new technical facts. Its job is
    to render the validated state (``impact_analysis`` +
    ``poc_draft``) into a polished body that the final review can
    audit for claim↔evidence traceability.

    Payload contract::

        {
            "finding_id": "...",
            "version": <int>,
            "body_markdown": "...",
            "evidence_refs": ["<uuid>", ...]
        }
    """
    from mavr.findings import lifecycle

    p = task.payload
    finding_id = p["finding_id"]
    version = int(p["version"])
    body = p["body_markdown"]
    evidence_refs = list(p.get("evidence_refs", []) or [])

    finding = await lifecycle.get(ctx.db, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")
    if finding.state not in {
        schema.FindingState.POC_REVIEW,
        schema.FindingState.POC_DRAFT,
        schema.FindingState.IMPACT,
    }:
        raise ValueError(
            f"cannot polish in state {finding.state.value}; need impact/poc state"
        )

    lease = await lifecycle.lease(ctx.db, finding_id=finding_id, owner=ctx.agent.id)
    if lease is None:
        raise ValueError("could not acquire finding lease for polish")
    try:
        # The POLISHED transition bumps; write the body at the post-bump
        # version so the unique (finding_id, version) constraint holds.
        next_version = finding.current_version + 1
        await workflow._write_finding_version(  # type: ignore[attr-defined]
            ctx.db,
            finding_id=finding_id,
            version=next_version,
            state=schema.FindingState.POLISHED,
            body=body,
            evidence_refs=evidence_refs,
            summary=f"polished v{version}",
        )
        await lifecycle.transition(
            ctx.db,
            finding_id=finding_id,
            new_state=schema.FindingState.POLISHED,
            actor_id=ctx.agent.id,
            reason="polished report",
            metadata={"version": next_version},
        )
    finally:
        await lifecycle.release_lease(
            ctx.db, finding_id=finding_id, owner=ctx.agent.id
        )
    ctx.charge_tool_call()
    return {"finding_id": finding_id, "new_state": "polished_report"}


# ---- final review -------------------------------------------------------


async def final_review_agent(
    task: schema.Task, ctx: RuntimeContext
) -> dict[str, Any]:
    """Run claim↔evidence traceability and advance or revert.

    Payload contract::

        {
            "finding_id": "...",
            "version": <int>,
            "polished_body": "...",
            "source_evidence": {"<uuid>": {...}, ...},
            "auto_advance": <bool>
        }
    """
    p = task.payload
    finding, report = await workflow.run_final_review(
        ctx.db,
        finding_id=p["finding_id"],
        agent_id=ctx.agent.id,
        polished_body=p["polished_body"],
        source_evidence=dict(p.get("source_evidence", {}) or {}),
        auto_advance=bool(p.get("auto_advance", True)),
    )
    ctx.charge_tool_call()
    return {
        "finding_id": finding.id,
        "new_state": finding.state.value,
        "traceability_passed": report.passed,
        "missing_evidence_claims": list(report.missing_evidence_claims),
        "altered_claims": list(report.altered_claims),
    }


# ---- registry -----------------------------------------------------------


@dataclass(frozen=True)
class RoleBinding:
    role: schema.AgentRole
    handler: RoleHandler
    kind: schema.TaskKind


ROLE_BINDINGS: tuple[RoleBinding, ...] = (
    RoleBinding(schema.AgentRole.DISCOVERY, discovery_agent, schema.TaskKind.GENERIC),
    RoleBinding(schema.AgentRole.RESEARCH, research_agent, schema.TaskKind.GENERIC),
    RoleBinding(schema.AgentRole.IMPACT, impact_agent, schema.TaskKind.IMPACT),
    RoleBinding(schema.AgentRole.POC, poc_agent, schema.TaskKind.POC),
    RoleBinding(schema.AgentRole.REVIEWER, reviewer_agent, schema.TaskKind.REVIEW),
    RoleBinding(schema.AgentRole.POLISH, polish_agent, schema.TaskKind.POLISH),
    RoleBinding(schema.AgentRole.FINAL_REVIEW, final_review_agent, schema.TaskKind.REVIEW),
)


def handler_for(kind: schema.TaskKind, role: schema.AgentRole) -> RoleHandler:
    """Return the handler for ``(kind, role)`` or raise ``KeyError``."""
    for binding in ROLE_BINDINGS:
        if binding.role == role and binding.kind == kind:
            return binding.handler
    raise KeyError(f"no binding for role={role.value} kind={kind.value}")


__all__ = [
    "ROLE_BINDINGS",
    "RoleBinding",
    "RoleHandler",
    "discovery_agent",
    "final_review_agent",
    "handler_for",
    "impact_agent",
    "poc_agent",
    "polish_agent",
    "research_agent",
    "reviewer_agent",
]
