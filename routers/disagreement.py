"""Parallel-router disagreement recording & resolution (PLAN §7.2, issue #281).

When several routers run on the same task, they may propose different
(provider, model) selections. PLAN requires that:

- the disagreement itself is *recorded* (who proposed what),
- the coordinator's resolution carries an explicit rationale — never a
  silent pick,
- decisions remain queryable by task/agent.

This module is a small, deterministic layer over ``DecisionLog``: it does
not re-implement merging (the merge policies in ``decision_log`` stay the
single source of truth for selection); it captures disagreement metadata
around whatever policy ran and produces auditable resolution records.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from routers.decision_log import CandidatePlan


@dataclass
class Resolution:
    """Coordinator resolution of one disagreement."""

    decision_id: str
    disagreed: bool
    groups: list[dict[str, Any]] = field(default_factory=list)
    winner_group: str = ""
    rationale: str = ""
    resolved_by: str = "coordinator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "disagreed": self.disagreed,
            "groups": self.groups,
            "winner_group": self.winner_group,
            "rationale": self.rationale,
            "resolved_by": self.resolved_by,
        }


def _group_key(plan: CandidatePlan) -> tuple[str, str]:
    return (plan.provider, plan.model)


def detect(plans: list[CandidatePlan]) -> bool:
    """True when live plans propose more than one distinct selection."""
    live = [p for p in plans if not p.failed]
    return len({_group_key(p) for p in live}) > 1


def resolve(
    plans: list[CandidatePlan],
    merge_fn: Callable[
        [list[CandidatePlan], dict[str, Any]],
        tuple[dict[str, Any], dict[str, Any]],
    ],
    merge_options: dict[str, Any] | None = None,
    decision_id: str = "",
    coordinator_note: str = "",
    resolved_by: str = "coordinator",
) -> Resolution:
    """Record disagreement structure + run the policy merge with rationale.

    The rationale is always explicit: either the coordinator's own note or
    a deterministic description of why the policy picked the winner. A
    silent resolution (no rationale possible) is a bug and raises.
    """
    options = dict(merge_options or {})
    groups: dict[tuple[str, str], list[CandidatePlan]] = {}
    for p in plans:
        if not p.failed:
            groups.setdefault(_group_key(p), []).append(p)

    ordered_groups = sorted(
        groups.items(),
        key=lambda kv: (-len(kv[1]), -max(p.confidence for p in kv[1]), kv[0]),
    )
    group_summaries = [
        {
            "provider": key[0],
            "model": key[1],
            "routers": sorted(p.router_id for p in members),
            "max_confidence": max(p.confidence for p in members),
        }
        for key, members in ordered_groups
    ]

    selection, details = merge_fn([p for p in plans if not p.failed], options)
    winner_group = f"{selection.get('provider', '?')}/{selection.get('model', '?')}"

    if not detect(plans):
        rationale = coordinator_note or "no disagreement: all routers proposed the same selection"
    elif coordinator_note:
        rationale = coordinator_note
    else:
        agree_count = len(groups[_group_key_by_label(groups, winner_group)])
        runner_up = max((len(members) for _, members in ordered_groups[1:]), default=0)
        rationale = (
            f"policy '{details.get('policy', 'unknown')}' selected {winner_group}: "
            f"{agree_count} router(s) agreed; runner-up had at most {runner_up}"
        )
    if not rationale.strip():
        raise ValueError("coordinator resolution produced an empty rationale")

    return Resolution(
        decision_id=decision_id,
        disagreed=len(group_summaries) > 1,
        groups=group_summaries,
        winner_group=winner_group,
        rationale=rationale,
        resolved_by=resolved_by,
    )


def _group_key_by_label(groups: dict, label: str) -> tuple[str, str]:
    provider, model = label.split("/", 1)
    return (provider, model)


class DisagreementIndex:
    """In-memory query surface: decisions by task / by agent.

    Storage-backed deployments can persist the same dicts; this index is
    the shape other subsystems query (UI/CLI read models).
    """

    def __init__(self) -> None:
        self._by_task: dict[str, list[dict[str, Any]]] = {}
        self._by_agent: dict[str, list[dict[str, Any]]] = {}

    def add(self, task_ref: str, record: dict[str, Any]) -> None:
        self._by_task.setdefault(task_ref, []).append(record)
        for c in record.get("candidates", []):
            rid = c.get("router_id") if isinstance(c, dict) else getattr(c, "router_id", None)
            if rid:
                self._by_agent.setdefault(rid, []).append(record)

    def by_task(self, task_ref: str) -> list[dict[str, Any]]:
        return list(self._by_task.get(task_ref, []))

    def by_agent(self, agent_uuid: str) -> list[dict[str, Any]]:
        return list(self._by_agent.get(agent_uuid, []))
