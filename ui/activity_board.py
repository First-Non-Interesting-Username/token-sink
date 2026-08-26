"""Agent activity board — queryable state snapshot for the live grid (issue #169).

The orchestrator's event handlers call ``upsert`` / ``record_task`` /
``mark_blocked`` etc.; the UI/API reads ``snapshot`` / ``drilldown``. The board
owns no agent behavior: it is a read-model that renders what events report,
so the view can never disagree with the §6 state machine for long (events are
the single source of truth).

Per-agent card fields (PLAN §13.2): uuid, role, parent uuid, current task,
model/provider, elapsed time, status, latest event. Blocked agents carry a
link to the blocking approval or policy event; stale heartbeats are flagged
inline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class AgentCard:
    """Mutable per-agent record maintained from lifecycle events."""

    agent_uuid: str
    role: str = ""
    parent_uuid: str | None = None
    campaign_uuid: str | None = None
    model: str = ""
    provider: str = ""
    status: str = "idle"  # idle | running | blocked | done | failed
    current_task_id: str | None = None
    latest_event: str = ""
    started_at: datetime | None = None  # start of the current task
    last_heartbeat: datetime = field(default_factory=_now)
    # When status == "blocked": what is blocking (approval id / policy event id).
    blocked_by: dict | None = None
    subagent_uuids: list[str] = field(default_factory=list)
    task_history: list[dict] = field(default_factory=list)  # {task_id, status, ts}


class AgentActivityBoard:
    """In-memory read-model backing the live agent activity grid."""

    def __init__(self, stale_threshold_s: float = 120.0):
        self.stale_threshold_s = stale_threshold_s
        self._agents: dict[str, AgentCard] = {}

    # -- writes (from orchestrator event handlers) ----------------------------

    def upsert(
        self,
        agent_uuid: str,
        *,
        role: str = "",
        parent_uuid: str | None = None,
        campaign_uuid: str | None = None,
        model: str = "",
        provider: str = "",
        event: str = "",
    ) -> None:
        card = self._agents.setdefault(agent_uuid, AgentCard(agent_uuid))
        if role:
            card.role = role
        if parent_uuid:
            card.parent_uuid = parent_uuid
            self._agents.setdefault(parent_uuid, AgentCard(parent_uuid)).subagent_uuids.append(
                agent_uuid
            )
        if campaign_uuid:
            card.campaign_uuid = campaign_uuid
        if model:
            card.model = model
        if provider:
            card.provider = provider
        if event:
            card.latest_event = event
        card.last_heartbeat = _now()

    def mark_task(self, agent_uuid: str, task_id: str, *, started: bool) -> None:
        card = self._agents[agent_uuid]
        card.last_heartbeat = _now()
        if started:
            card.status = "running"
            card.current_task_id = task_id
            card.started_at = _now()
            card.task_history.append(
                {"task_id": task_id, "status": "running", "ts": _now().isoformat()}
            )
        else:
            # Find the matching history row and close it out.
            for entry in reversed(card.task_history):
                if entry["task_id"] == task_id and entry["status"] == "running":
                    entry["status"] = "finished"
                    break
            if card.current_task_id == task_id:
                card.current_task_id = None
                card.started_at = None
                card.status = "idle"

    def mark_status(self, agent_uuid: str, status: str, *, event: str = "") -> None:
        if status not in {"idle", "running", "blocked", "done", "failed"}:
            raise ValueError(f"unknown agent status: {status!r}")
        card = self._agents[agent_uuid]
        card.status = status
        card.last_heartbeat = _now()
        if event:
            card.latest_event = event

    def mark_blocked(self, agent_uuid: str, *, kind: str, ref: str, reason: str = "") -> None:
        """Flag an agent as blocked by an approval or policy decision."""
        card = self._agents[agent_uuid]
        card.status = "blocked"
        card.blocked_by = {"kind": kind, "ref": ref, "reason": reason}
        card.latest_event = f"blocked by {kind}:{ref}"
        card.last_heartbeat = _now()

    def heartbeat(self, agent_uuid: str) -> None:
        self._agents[agent_uuid].last_heartbeat = _now()

    # -- reads ----------------------------------------------------------------

    @property
    def stale_threshold(self) -> timedelta:
        return timedelta(seconds=self.stale_threshold_s)

    def _is_stale(self, card: AgentCard, now: datetime | None = None) -> bool:
        now = now or _now()
        return (now - card.last_heartbeat) > self.stale_threshold

    def snapshot(
        self,
        *,
        campaign: str | None = None,
        role: str | None = None,
        status: str | None = None,
    ) -> list[AgentCard]:
        cards = [
            c
            for c in self._agents.values()
            if (campaign is None or c.campaign_uuid == campaign)
            and (role is None or c.role == role)
            and (status is None or c.status == status)
        ]
        return sorted(cards, key=lambda c: c.agent_uuid)

    def card(self, card: AgentCard) -> dict:
        """Serialize one card, adding derived fields (elapsed, stale)."""
        elapsed_s = None
        if card.started_at is not None:
            elapsed_s = (_now() - card.started_at).total_seconds()
        return {
            "agent_uuid": card.agent_uuid,
            "role": card.role,
            "parent_uuid": card.parent_uuid,
            "campaign_uuid": card.campaign_uuid,
            "model": card.model,
            "provider": card.provider,
            "status": card.status,
            "current_task_id": card.current_task_id,
            "elapsed_s": round(elapsed_s, 3) if elapsed_s is not None else None,
            "latest_event": card.latest_event,
            "stale": self._is_stale(card),
            "blocked_by": card.blocked_by,
        }

    def drilldown(self, agent_uuid: str) -> dict | None:
        card = self._agents.get(agent_uuid)
        if card is None:
            return None
        base = self.card(card)
        base["task_history"] = card.task_history
        base["subagent_uuids"] = card.subagent_uuids
        return base

    def now_iso(self) -> str:
        return _now().isoformat()
