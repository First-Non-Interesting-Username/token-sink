"""Evidence-gap workflow for reverted findings (issue #158, PLAN §10.5).

When all four PoC reviewers reject and the finding is reverted to
post-first-review instead of quarantined, it needs a bounded path to acquire
"additional evidence". This module implements that loop:

1. **Gap extraction** — each reviewer's ``missing_evidence`` free text is
   normalized into a structured ``EvidenceGap`` keyed by content hash, so
   paraphrased duplicates across reviewers collapse into one gap.
2. **Task generation** — one re-investigation task per unresolved gap. Tasks
   are validated against the campaign's :class:`ScopePolicy`: any task whose
   target URL falls outside scope is rejected, never silently rewritten — no
   scope expansion without human approval.
3. **Loop bound** — evidence-gathering cycles are capped (configurable,
   default 2). When the cap is exhausted the finding must be force-quarantined
   with reason ``unresolvable-evidence-gaps``, preventing infinite
   discover/review/revert loops and wasted budget.
4. **Reviewer context** — newly gathered evidence records which gap(s) it
   addresses, so re-review shows what's new vs. re-litigated.

Pure functions + an in-memory tracker over the existing lifecycle types;
no storage backend assumptions.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from findings.lifecycle import Finding
from policy.scope import ScopePolicy


class EvidenceGapError(ValueError):
    """Invalid gap workflow operation."""


DEFAULT_MAX_CYCLES = 2

# Normalize whitespace/punctuation so "add PoC for XSS!" and "Add PoC for XSS"
# produce the same gap key.
_NORMALIZE_RE = re.compile(r"[^a-z0-9 ]+")


def gap_key(text: str) -> str:
    """Deterministic content-hash key for a missing-evidence description."""
    norm = _NORMALIZE_RE.sub(" ", text.lower()).strip()
    norm = re.sub(r"\s+", " ", norm)
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


@dataclass
class EvidenceGap:
    """One aggregated reviewer-identified evidence deficiency."""

    key: str  # content hash; stable across paraphrases
    description: str  # first-seen wording (provenance preserved)
    sources: list[str] = field(default_factory=list)  # reviewer agent UUIDs
    addressed_by: list[str] = field(default_factory=list)  # evidence item UUIDs

    @property
    def resolved(self) -> bool:
        return bool(self.addressed_by)


def extract_gaps(finding: Finding) -> list[EvidenceGap]:
    """Aggregate every PoC reviewer's ``missing_evidence`` into unique gaps.

    Empty/blank entries are skipped. Paraphrases collapse by content hash;
    the first-seen wording is kept and later reviewers are recorded as
    additional sources.
    """
    order: list[str] = []
    by_key: dict[str, EvidenceGap] = {}
    for review in finding.poc_reviews:
        text = (review.get("missing_evidence") or "").strip()
        if not text:
            continue
        k = gap_key(text)
        if k in by_key:
            src = review.get("reviewer_uuid", "")
            if src and src not in by_key[k].sources:
                by_key[k].sources.append(src)
            continue
        gap = EvidenceGap(
            key=k,
            description=text,
            sources=[review.get("reviewer_uuid", "") or ""],
        )
        by_key[k] = gap
        order.append(k)
    return [by_key[k] for k in order]


@dataclass
class ReinvestigationTask:
    """One targeted follow-up task derived from a single gap."""

    gap_key: str
    finding_uuid: str
    campaign_uuid: str
    instruction: str
    target_url: str | None = None  # optional; None = analysis on known material
    status: str = "pending"  # pending | completed | rejected_out_of_scope
    rejection_reason: str = ""


def generate_tasks(
    finding: Finding,
    gaps: list[EvidenceGap],
    *,
    scope: ScopePolicy | None = None,
) -> tuple[list[ReinvestigationTask], list[ReinvestigationTask]]:
    """Create one re-investigation task per unresolved gap.

    Returns ``(tasks, rejected)``. Tasks whose declared target URL does not
    classify as in-scope under the campaign's policy are REJECTED, not
    silently trimmed: silent rewriting could turn an out-of-scope probe into
    an in-scope one without anyone noticing. With no scope given, tasks with
    a target URL are still produced but flagged for human approval upstream
    (the orchestrator refuses unapproved targets).
    """
    tasks: list[ReinvestigationTask] = []
    rejected: list[ReinvestigationTask] = []
    for gap in gaps:
        if gap.resolved:
            continue
        task = ReinvestigationTask(
            gap_key=gap.key,
            finding_uuid=finding.finding_uuid,
            campaign_uuid=finding.campaign_uuid,
            instruction=(
                f"Re-investigate ({finding.title}): gather evidence addressing "
                f"reviewer gap '{gap.description}'"
            ),
            target_url=finding.location or None,
        )
        if scope is not None and task.target_url:
            classification, _spec = scope.classify_target(task.target_url)
            if classification != "in":
                task.status = "rejected_out_of_scope"
                task.rejection_reason = (
                    f"target '{task.target_url}' classifies '{classification}' under "
                    "campaign scope; scope expansion requires human approval"
                )
                rejected.append(task)
                continue
        tasks.append(task)
    return tasks, rejected


@dataclass
class GapWorkflowState:
    """Per-finding tracker: gaps, cycles used, cap enforcement."""

    max_cycles: int = DEFAULT_MAX_CYCLES
    cycles_used: int = 0
    gaps: dict[str, EvidenceGap] = field(default_factory=dict)
    force_quarantine_reason: str = ""

    def record_revert(
        self,
        finding: Finding,
        *,
        max_cycles: int | None = None,
    ) -> bool:
        """Register a revert-to-post-first-review; returns True if allowed.

        Increments the cycle counter. When the configured cap is already
        exhausted, sets ``force_quarantine_reason`` and returns False — the
        caller MUST quarantine instead of reverting.
        """
        self.max_cycles = self.max_cycles if max_cycles is None else max_cycles
        if max_cycles is not None:
            self.max_cycles = max_cycles
        if self.cycles_used >= self.max_cycles:
            self.force_quarantine_reason = "unresolvable-evidence-gaps"
            return False
        self.cycles_used += 1
        for gap in extract_gaps(finding):
            existing = self.gaps.get(gap.key)
            if existing is None:
                self.gaps[gap.key] = gap
            else:
                for s in gap.sources:
                    if s not in existing.sources:
                        existing.sources.append(s)
        return True

    def attach_evidence(self, gap_key: str, evidence_uuid: str) -> None:
        """Mark a gap addressed by newly gathered evidence (#150 pipeline)."""
        gap = self.gaps.get(gap_key)
        if gap is None:
            raise EvidenceGapError(f"unknown gap key '{gap_key}'")
        if evidence_uuid not in gap.addressed_by:
            gap.addressed_by.append(evidence_uuid)

    @property
    def open_gaps(self) -> list[EvidenceGap]:
        return [g for g in self.gaps.values() if not g.resolved]

    def can_advance_to_review(self) -> bool:
        """Re-review requires every known gap to have addressing evidence."""
        return not self.open_gaps

    def reviewer_context(self) -> dict[str, list[str]]:
        """What re-reviewers must be shown: which evidence addresses which gap."""
        return {g.description: list(g.addressed_by) for g in self.gaps.values()}

    def to_dict(self) -> dict[str, object]:
        return json.loads(
            json.dumps(
                {
                    "max_cycles": self.max_cycles,
                    "cycles_used": self.cycles_used,
                    "force_quarantine_reason": self.force_quarantine_reason,
                    "gaps": [
                        {
                            "key": g.key,
                            "description": g.description,
                            "sources": g.sources,
                            "addressed_by": g.addressed_by,
                        }
                        for g in self.gaps.values()
                    ],
                }
            )
        )
