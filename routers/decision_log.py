"""Router decision log (PLAN §7.2).

Every router invocation produces a `DecisionRecord`: what the routers saw
(task snapshot, model catalog version, input signals), what each router
proposed (candidate plans, including failed routers recorded as failed
partials), and how the coordinator merged them (policy + final selection).

Decisions are reproducible: given a stored record, `replay()` re-runs the
merge deterministically from the recorded candidates and flags drift between
the recomputed and recorded selection. Records are JSON-serializable so any
storage layer (PLAN §12) can persist them, and every payload passes through a
redaction hook before persistence because decision payloads may contain
target data (PLAN §16; same pipeline shape as issue #29).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

# Type of the pluggable redaction function. Takes a JSON-compatible object,
# returns the same shape with sensitive values masked.
Redactor = Callable[[Any], Any]

RedactionError = RuntimeError


def default_redactor(payload: Any) -> Any:
    """Identity redactor.

    The real redaction pipeline (issue #29) is injected via
    ``redactor=``; until it lands we fail closed only if explicitly asked
    to enforce redaction (see DecisionLog.enforce_redaction).
    """
    return payload


def snapshot_hash(task_snapshot: Any) -> str:
    """Stable content hash for a task snapshot (or any input blob)."""
    canonical = json.dumps(task_snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class CandidatePlan:
    """One router's structured proposal (PLAN §7.2)."""

    router_id: str
    provider: str
    model: str
    rationale: str
    confidence: float
    expected_cost: float
    fallbacks: list[dict[str, Any]] = field(default_factory=list)
    # Routers that crash mid-pool still leave a complete record: their plan
    # slot is marked failed with the error captured, never silently dropped.
    failed: bool = False
    error: str | None = None


@dataclass
class DecisionRecord:
    """Full reproducibility record for one routing decision."""

    decision_id: str
    task_ref: str  # reference/link to the full task payload in storage
    task_snapshot_hash: str
    model_catalog_version: str
    # Input signals at decision time: load, quotas, historical stats, budgets…
    input_signals: dict[str, Any]
    candidates: list[CandidatePlan]
    merge_policy: str  # consensus | fastest | best_score | diversity
    final_selection: dict[str, Any]  # chosen candidate summary + merge details
    created_at: str = ""
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionRecord:
        data = dict(data)
        data["candidates"] = [CandidatePlan(**c) for c in data.get("candidates", [])]
        return cls(**data)


class MergePolicyError(ValueError):
    """Unknown or non-deterministic merge policy requested."""


# Deterministic merge policies keyed by name. Each takes the list of
# successful candidate plans plus policy options and returns (selection,
# merge_details). Ordering ties are broken by router_id so replay is stable
# regardless of pool completion order.
def _merge_consensus(
    plans: list[CandidatePlan], options: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    # Group by (provider, model); highest agreement wins, then confidence.
    groups: dict[tuple[str, str], list[CandidatePlan]] = {}
    for p in plans:
        groups.setdefault((p.provider, p.model), []).append(p)
    best_key = max(
        groups,
        key=lambda k: (
            len(groups[k]),
            max(p.confidence for p in groups[k]),
            k[0],
            k[1],
        ),
    )
    winner = max(groups[best_key], key=lambda p: (p.confidence, p.router_id))
    details = {
        "agreement": len(groups[best_key]),
        "distinct_candidates": len(groups),
    }
    return _selection(winner), {"policy": "consensus", **details}


def _merge_fastest(
    plans: list[CandidatePlan], options: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_latency = options.get("expected_latency", {})
    winner = min(
        plans,
        key=lambda p: (
            expected_latency.get(f"{p.provider}/{p.model}", float("inf")),
            p.router_id,
        ),
    )
    return _selection(winner), {
        "policy": "fastest",
        "expected_latency": expected_latency,
    }


def _merge_best_score(
    plans: list[CandidatePlan], options: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    budget = options.get("budget")
    eligible = [p for p in plans if budget is None or p.expected_cost <= budget]
    if not eligible:
        raise MergePolicyError("no candidate within budget")
    scores = options.get("scores", {})
    winner = max(
        eligible,
        key=lambda p: (scores.get(f"{p.provider}/{p.model}", 0.0), p.confidence, p.router_id),
    )
    return _selection(winner), {"policy": "best_score", "budget": budget}


def _merge_diversity(
    plans: list[CandidatePlan], options: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    # Independent review must not collapse onto one model family: pick the
    # top candidate per distinct family, then the best-scoring family head.
    families = options.get("families", {})
    seen_families: set[str] = set()
    heads: list[CandidatePlan] = []
    ordered = sorted(plans, key=lambda p: (-p.confidence, p.router_id))
    for p in ordered:
        fam = families.get(f"{p.provider}/{p.model}", p.model)
        if fam not in seen_families:
            seen_families.add(fam)
            heads.append(p)
    return _selection(heads[0]), {
        "policy": "diversity",
        "distinct_families": len(seen_families),
        "family_heads": [p.model for p in heads],
    }


MERGE_POLICIES = {
    "consensus": _merge_consensus,
    "fastest": _merge_fastest,
    "best_score": _merge_best_score,
    "diversity": _merge_diversity,
}


def _selection(winner: CandidatePlan) -> dict[str, Any]:
    return {
        "router_id": winner.router_id,
        "provider": winner.provider,
        "model": winner.model,
    }


class DecisionLog:
    """Records routing decisions and replays them deterministically."""

    def __init__(
        self,
        redactor: Redactor = default_redactor,
        enforce_redaction: bool = False,
    ):
        self._redactor = redactor
        # Fail-closed option: refuse to persist if the redactor changed nothing.
        self.enforce_redaction = enforce_redaction

    def record(
        self,
        *,
        task_snapshot: Any,
        task_ref: str,
        model_catalog_version: str,
        input_signals: dict[str, Any],
        candidate_plans: list[CandidatePlan],
        merge_policy: str,
        final_selection: dict[str, Any],
        merge_options: dict[str, Any] | None = None,
        created_at: str = "",
    ) -> dict[str, Any]:
        """Build + redact a decision record and return its persisted form.

        ``merge_options`` carries the policy inputs used at decision time
        (budget, expected latencies, capability scores, family map) — replay
        needs them to be deterministic, so they are stored inside the record.
        """
        stored_selection = dict(final_selection)
        if merge_options:
            # Nested under a reserved key so it can't collide with the
            # selection fields themselves.
            stored_selection["options"] = dict(merge_options)
        record = DecisionRecord(
            decision_id=str(uuid.uuid4()),
            task_ref=task_ref,
            task_snapshot_hash=snapshot_hash(task_snapshot),
            model_catalog_version=model_catalog_version,
            input_signals=dict(input_signals),
            candidates=list(candidate_plans),
            merge_policy=merge_policy,
            final_selection=stored_selection,
            created_at=created_at,
        )
        payload = record.to_dict()
        redacted = self._redact(payload)
        redacted["decision_id"] = record.decision_id  # IDs survive redaction
        return redacted

    def _redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            out = self._redactor(json.loads(json.dumps(payload)))
        except Exception as exc:  # redaction failure must never leak raw data
            raise RedactionError(f"redaction pipeline failed: {exc}") from exc
        if not isinstance(out, dict):
            raise RedactionError("redactor returned a non-mapping payload")
        if self.enforce_redaction and out == payload:
            raise RedactionError("redactor made no changes while enforcement enabled")
        out["redacted"] = True
        return out

    def replay(self, persisted_record: dict[str, Any]) -> dict[str, Any]:
        """Deterministically re-run the merge from a stored record.

        Returns a report with the recomputed selection and a `drift` flag
        comparing it against the recorded one. Failed partial plans are
        excluded exactly as they were during the original merge.
        """
        rec = DecisionRecord.from_dict(persisted_record)
        try:
            merge_fn = MERGE_POLICIES[rec.merge_policy]
        except KeyError:
            raise MergePolicyError(f"unknown merge policy: {rec.merge_policy!r}") from None
        live = [c for c in rec.candidates if not c.failed]
        if not live:
            raise MergePolicyError("no successful candidates to merge")
        options = rec.final_selection.get("options", {})
        selection, details = merge_fn(live, options)
        keys = ("router_id", "provider", "model")
        # Compare only on the canonical selection keys so extra merge metadata
        # stored alongside the selection never causes false drift.
        recorded_sel = {k: rec.final_selection.get(k) for k in keys}
        return {
            "decision_id": rec.decision_id,
            "recomputed_selection": selection,
            "recorded_selection": recorded_sel,
            "drift": selection != recorded_sel,
            "merge_details": details,
        }
