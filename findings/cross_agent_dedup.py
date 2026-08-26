"""Cross-agent duplicate detection and adjudication (issue #246, PLAN §10).

`findings/dedup.py` detects duplicate *records*. This module adds the
cross-agent dimension the issue requires: when two DIFFERENT discovering
agents surface the same vulnerability, the duplicates must be linked — never
silently dropped — and an explicit adjudication step either merges them with
full provenance from both sides or rejects the link.

Rules:

- Detection at intake records WHICH agent found each copy; a same-agent
  resubmission and a cross-agent collision are distinguished.
- Candidate links start as ``proposed``; only ``confirm_duplicate`` moves
  them to ``confirmed`` (and enables merge), only ``reject_duplicate``
  closes them. Adjudicator must be distinct from both discovering agents.
- Merging goes through dedup.merge_duplicates so append-only merge history
  and evidence/review union are preserved, then stamps cross-agent
  attribution onto the canonical record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from findings.dedup import (
    DuplicateLink,
    MergeResult,
    find_duplicates,
    merge_duplicates,
)


class AdjudicationError(Exception):
    """Invalid adjudication: bad state transition or independence violation."""


@dataclass
class DuplicateCase:
    """One adjudication case over a proposed cross-agent duplicate pair."""

    case_uuid: str
    finding_uuid: str
    duplicate_of_uuid: str
    discovering_agents: dict[str, str] = field(default_factory=dict)
    # proposed | confirmed | rejected | merged
    status: str = "proposed"
    score: float = 0.0
    reason: str = ""
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def _record(self, action: str, actor: str, notes: str) -> None:
        # Append-only decision log: entries are added, never edited.
        self.decisions.append({"action": action, "actor": actor, "notes": notes})

    def confirm(self, adjudicator_id: str, notes: str = "") -> None:
        if self.status != "proposed":
            raise AdjudicationError(f"cannot confirm a case in status {self.status!r}")
        self._require_independent(adjudicator_id)
        self.status = "confirmed"
        self._record("confirmed", adjudicator_id, notes)

    def reject(self, adjudicator_id: str, notes: str = "") -> None:
        if self.status != "proposed":
            raise AdjudicationError(f"cannot reject a case in status {self.status!r}")
        self._require_independent(adjudicator_id)
        self.status = "rejected"
        self._record("rejected", adjudicator_id, notes)

    def _require_independent(self, adjudicator_id: str) -> None:
        # The adjudicator must not be one of the two discovering agents:
        # an agent can never confirm its own finding's duplicate status.
        agents = set(self.discovering_agents.values())
        if adjudicator_id in agents:
            raise AdjudicationError("adjudicator must be independent of both discovering agents")


def open_cases(candidate: dict, existing: list[dict]) -> list[DuplicateCase]:
    """Screen a candidate at intake and open cases for every match.

    Exact fingerprint matches open cases directly; heuristic candidates at
    or above SIMILARITY_THRESHOLD open lower-confidence cases. Look-alikes
    below the threshold produce nothing — they must not be linked (#139).
    """
    links: list[DuplicateLink] = find_duplicates(candidate, existing)
    by_uuid = {str(f.get("finding_uuid")): f for f in [*existing, candidate]}
    cases: list[DuplicateCase] = []
    for link in links:
        dup_of = by_uuid[str(link.duplicate_of_uuid)]
        cand = by_uuid[str(link.finding_uuid)]
        case = DuplicateCase(
            case_uuid=f"{link.finding_uuid[:8]}-{link.duplicate_of_uuid[:8]}",
            finding_uuid=link.finding_uuid,
            duplicate_of_uuid=link.duplicate_of_uuid,
            discovering_agents={
                "candidate": str(cand.get("discovered_by", "unknown")),
                "existing": str(dup_of.get("discovered_by", "unknown")),
            },
            score=link.score,
            reason=link.reason,
        )
        # Same agent re-submitting its own finding still opens a case, but
        # the attribution makes the distinction visible to the adjudicator.
        cases.append(case)
    return cases


def adjudicate_merge(
    case: DuplicateCase, canonical: dict, duplicate: dict, adjudicator_id: str
) -> MergeResult:
    """Confirm a case and merge into ``canonical`` with provenance kept."""
    if case.status == "merged":
        raise AdjudicationError("case already merged")
    case.confirm(adjudicator_id, notes="confirmed via adjudicate_merge")
    pair = {canonical.get("finding_uuid"), duplicate.get("finding_uuid")}
    expected = {case.finding_uuid, case.duplicate_of_uuid}
    if pair != expected:
        raise AdjudicationError("case pair does not match canonical/duplicate pair")
    result = merge_duplicates(canonical, [duplicate], adjudicator_id)
    canonical.setdefault("cross_agent_attribution", []).append(
        {
            "absorbed_from": duplicate.get("discovered_by", "unknown"),
            "canonical_by": canonical.get("discovered_by", "unknown"),
            "case_uuid": case.case_uuid,
        }
    )
    case.status = "merged"
    case._record("merged", adjudicator_id, f"canonical={canonical['finding_uuid']}")
    return result
