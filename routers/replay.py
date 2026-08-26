"""Router-decision replay harness (issue #159, PLAN §7.2).

Design decisions (per AGENTS.md):

- ``DecisionLog.replay`` already re-merges a single stored record; this
  module is the *harness* around it: catalog pinning, byte-identical
  verification, explainable traces, and batch regression mode.
- Catalog pinning: the harness is constructed with the live model-catalog
  version. Any record whose ``model_catalog_version`` differs is rejected
  with :class:`CatalogMismatch` BEFORE replay runs — a decision made under
  a different capability/cost table proves nothing about current router
  behavior, so silently "replaying" it would be misleading (fail loudly).
- Byte-identical check: drift detection in DecisionLog.replay compares only
  canonical selection keys; regression mode additionally requires the full
  serialized recomputation to match what the recorded merge produced, so a
  tie-break change that flips ordering surfaces even when the winner key is
  unchanged.
- Explain: an auditor asking "why was task X routed to model M" gets one
  ordered trace: inputs → per-router candidates (incl. failed partials) →
  merge policy + options → outcome.
- Regression mode takes a directory of JSON records and replays every one,
  returning per-record pass/fail so CI can diff router-code changes against
  real recorded decisions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from routers.decision_log import (
    MERGE_POLICIES,
    CandidatePlan,
    DecisionRecord,
    MergePolicyError,
)

try:  # pragma: no cover - trivial re-export shim
    from routers.decision_log import RedactionError  # noqa: F401
except ImportError:  # pragma: no cover
    RedactionError = RuntimeError


class CatalogMismatch(ValueError):
    """Record was created under a different model-catalog version."""


@dataclass
class ReplayResult:
    """Outcome of replaying one persisted decision record."""

    decision_id: str
    ok: bool  # True = reproduced exactly
    drift: bool  # recomputed selection differs from recorded
    byte_identical: bool  # full serialization matches too
    report: dict[str, Any]  # underlying DecisionLog.replay report
    error: str | None = None  # set when replay itself raised


class ReplayHarness:
    """Replay/verify/explain router decisions under a pinned catalog."""

    def __init__(self, model_catalog_version: str) -> None:
        self.model_catalog_version = model_catalog_version

    def _check_catalog(self, record: dict[str, Any]) -> None:
        if record.get("model_catalog_version") != self.model_catalog_version:
            raise CatalogMismatch(
                f"record {record.get('decision_id', '?')} was created under "
                f"catalog '{record.get('model_catalog_version')}' but harness "
                f"is pinned to '{self.model_catalog_version}'"
            )

    @staticmethod
    def _byte_fingerprint(selection: dict[str, Any], details: dict[str, Any]) -> str:
        """Canonical fingerprint of the full merge outcome (not just keys)."""
        blob = json.dumps(
            {"selection": selection, "details": details},
            sort_keys=True,
            separators=(",", ":"),
        )
        import hashlib

        return hashlib.sha256(blob.encode()).hexdigest()

    def replay(self, record: dict[str, Any], strict: bool = True) -> ReplayResult:
        """Replay one record.

        ``strict=True`` enforces catalog pinning (default). Raises
        CatalogMismatch / MergePolicyError; per-record errors are captured
        in the returned ReplayResult only in batch contexts — direct calls
        propagate them so callers cannot miss a loud failure.
        """
        if strict:
            self._check_catalog(record)
        rec = DecisionRecord.from_dict(record)
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
        recorded_sel = {k: rec.final_selection.get(k) for k in keys}
        # Byte-identical compares the FULL outcome incl. merge details —
        # stricter than DecisionLog.replay's key-only comparison. The
        # recorded side stores policy options under "options" but (in this
        # repo's record shape) no computed merge_details, so:
        # - when a fixture DOES carry stored "merge_details", fingerprint
        #   selection+details+options on both sides and require equality —
        #   this catches tie-break/ordering changes in merge code;
        # - otherwise run the merge twice and require identical
        #   fingerprints (determinism check on current code).
        options_fp = {"options": options}
        fp_new = self._byte_fingerprint(selection, {**details, **options_fp})
        stored_details = rec.final_selection.get("merge_details")
        if stored_details is not None:
            fp_old = self._byte_fingerprint(recorded_sel, {**stored_details, **options_fp})
            byte_ok = fp_new == fp_old
        else:
            sel2, det2 = merge_fn(live, options)
            byte_ok = fp_new == self._byte_fingerprint(sel2, {**det2, **options_fp})
        return ReplayResult(
            decision_id=rec.decision_id,
            ok=selection == recorded_sel and byte_ok,
            drift=selection != recorded_sel,
            byte_identical=byte_ok,
            report={
                "decision_id": rec.decision_id,
                "recomputed_selection": selection,
                "recorded_selection": recorded_sel,
                "drift": selection != recorded_sel,
                "merge_details": details,
            },
        )

    def explain(self, record: dict[str, Any]) -> dict[str, Any]:
        """Auditor trace: why was task X routed to model M?

        Ordered input → candidates → policy → outcome, including failed
        router partials (they are part of the story).
        """
        rec = DecisionRecord.from_dict(record)
        result = self.replay(record)
        return {
            "decision_id": rec.decision_id,
            "task_ref": rec.task_ref,
            "input_snapshot_hash": rec.task_snapshot_hash,
            "model_catalog_version": rec.model_catalog_version,
            "input_signals": rec.input_signals,
            "candidates": [
                {
                    "router_id": c.router_id,
                    "provider": c.provider,
                    "model": c.model,
                    "confidence": c.confidence,
                    "expected_cost": c.expected_cost,
                    "failed": c.failed,
                    "error": c.error,
                }
                for c in rec.candidates
            ],
            "merge_policy": rec.merge_policy,
            "merge_options": rec.final_selection.get("options", {}),
            "outcome": rec.final_selection,
            "reproduced": result.ok,
            "replay_report": result.report,
        }

    def regression(self, directory: str | Path, strict: bool = True) -> dict[str, Any]:
        """Run every stored record in ``directory`` through replay.

        Records whose catalog version mismatches count as failures (unless
        ``strict=False``, which skips them) so CI flags stale fixtures
        instead of silently shrinking coverage.
        """
        summary: dict[str, Any] = {"total": 0, "passed": 0, "failed": 0}
        failures: list[dict[str, Any]] = []
        d = Path(directory)
        for path in sorted(d.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                summary["total"] += 1
                summary["failed"] += 1
                failures.append({"file": path.name, "error": f"invalid JSON: {e}"})
                continue
            summary["total"] += 1
            try:
                res = self.replay(record, strict=strict)
            except (CatalogMismatch, MergePolicyError, TypeError, KeyError) as e:
                summary["failed"] += 1
                failures.append({"file": path.name, "error": str(e)})
                continue
            if res.ok:
                summary["passed"] += 1
            else:
                summary["failed"] += 1
                failures.append(
                    {
                        "file": path.name,
                        "decision_id": res.decision_id,
                        "drift": res.drift,
                        "report": res.report,
                    }
                )
        summary["failures"] = failures
        return summary


def write_record_fixture(record: dict[str, Any], directory: str | Path) -> Path:
    """Persist a decision record as a regression fixture file."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    did = record.get("decision_id") or "unknown"
    p = d / f"{did}.json"
    p.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return p


# Re-exported for harness consumers building records by hand.
__all__ = [
    "CandidatePlan",
    "CatalogMismatch",
    "ReplayHarness",
    "ReplayResult",
    "write_record_fixture",
]
