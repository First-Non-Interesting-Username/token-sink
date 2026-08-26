"""Pause/resume semantics at multiple scopes (issue #115, PLAN §2.5/§6/§12).

Design decisions (per AGENTS.md "document everything"):

- **Scoped pause registry over the existing campaign lifecycle.**
  ``orchestrator/campaign_lifecycle.py`` already implements graceful drain +
  resumable snapshots for a single campaign. This module adds the missing
  *scope* dimension: pause can target one agent, one campaign, or the whole
  system — and dispatchers consult ``is_paused()`` before handing out work.

- **Graceful by construction.** Pausing never kills in-flight work; it only
  stops *new* dispatch. In-flight completion is the lifecycle's drain
  callback's job (unchanged). A paused scope simply reports "do not start
  more tasks".

- **Distinct from the kill switch.** The kill switch is immediate and blocks
  network actions; pause is cooperative scheduling control. Paused scopes
  still allow approvals (#131) to be listed and decided — approving work is
  not new work dispatch.

- **Restart-while-paused stays paused.** The registry serializes to JSON;
  on restore, previously paused scopes resume as paused (no auto-resume),
  satisfying §12's state-survives-restart requirement.

- **Expiry safety valve**: an optional TTL prevents an orphaned pause from
  silently starving the fleet forever; expired pauses report as lifted but
  are recorded for audit.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PauseScope(StrEnum):
    AGENT = "agent"
    CAMPAIGN = "campaign"
    GLOBAL = "global"


class PauseError(ValueError):
    """Invalid pause request."""


@dataclass
class PauseRecord:
    scope: PauseScope
    target: str | None  # None only for global
    actor: str
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope.value,
            "target": self.target,
            "actor": self.actor,
            "reason": self.reason,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PauseRecord:
        return cls(
            scope=PauseScope(d["scope"]),
            target=d["target"],
            actor=d["actor"],
            reason=d.get("reason", ""),
            created_at=d["created_at"],
            expires_at=d.get("expires_at"),
        )


class PauseRegistry:
    """Tracks active pauses across the three scopes; consulted pre-dispatch."""

    def __init__(self, *, now: Any = time.time) -> None:
        self._pauses: dict[tuple[str, str | None], PauseRecord] = {}
        self._expired_log: list[dict[str, Any]] = []
        self._now = now

    @staticmethod
    def _key(scope: PauseScope, target: str | None) -> tuple[str, str | None]:
        if scope is PauseScope.GLOBAL:
            return ("global", None)
        if not target:
            raise PauseError(f"{scope.value} pause requires a target id")
        return (scope.value, target)

    # -- mutation -----------------------------------------------------------
    def pause(
        self,
        scope: PauseScope,
        target: str | None,
        *,
        actor: str,
        reason: str = "",
        ttl_seconds: float | None = None,
    ) -> PauseRecord:
        rec = PauseRecord(
            scope=scope,
            target=None if scope is PauseScope.GLOBAL else target,
            actor=actor,
            reason=reason,
            expires_at=(self._now() + ttl_seconds) if ttl_seconds else None,
        )
        self._pauses[self._key(scope, target)] = rec
        return rec

    def lift(self, scope: PauseScope, target: str | None) -> bool:
        """Lift a pause; returns False when none was active."""
        return self._pauses.pop(self._key(scope, target), None) is not None

    # -- queries ------------------------------------------------------------
    def _active(self, key: tuple[str, str | None]) -> PauseRecord | None:
        rec = self._pauses.get(key)
        if rec and rec.expires_at is not None and self._now() >= rec.expires_at:
            del self._pauses[key]
            self._expired_log.append(rec.to_dict())
            return None
        return rec

    def is_paused(self, *, campaign_id: str | None = None, agent_id: str | None = None) -> bool:
        """True when dispatch into this context must stop.

        Global pause dominates; then campaign; then agent.
        """
        if self._active(("global", None)):
            return True
        if campaign_id and self._active(("campaign", campaign_id)):
            return True
        if agent_id and self._active(("agent", agent_id)):
            return True
        return False

    def blocking_pause(
        self, *, campaign_id: str | None = None, agent_id: str | None = None
    ) -> PauseRecord | None:
        """The most specific active pause explaining a block (for UI/audit)."""
        for key in (
            ("agent", agent_id) if agent_id else None,
            ("campaign", campaign_id) if campaign_id else None,
            ("global", None),
        ):
            if key and (rec := self._active(key)):  # type: ignore[has-type]
                return rec
        return None

    def active_pauses(self) -> list[PauseRecord]:
        out = []
        for key in list(self._pauses):
            if rec := self._active(key):
                out.append(rec)
        return sorted(out, key=lambda r: r.created_at)

    @property
    def expired_for_audit(self) -> list[dict[str, Any]]:
        return list(self._expired_log)

    # -- persistence (restart-while-paused stays paused, §12) -----------------
    def to_json(self) -> str:
        return json.dumps([r.to_dict() for r in self.active_pauses()])

    @classmethod
    def from_json(cls, s: str, **kw: Any) -> PauseRegistry:
        reg = cls(**kw)
        for d in json.loads(s):
            reg._pauses[reg._key(PauseScope(d["scope"]), d["target"])] = PauseRecord.from_dict(d)
        return reg
