"""Dispatch gate + violation circuit breaker for tool calls (issue #155).

The only way a tool call may execute is through :meth:`ToolGate.dispatch`,
which validates against the registry first. A rejected call never reaches
execution — the model receives the structured rejection as bounded feedback
instead. Repeated malformed calls trip a per-agent/model circuit breaker that
pauses the offender, with audit events emitted via ``policy.audit``.

Malformed-call counters are keyed by (model, provider) so the §8.3 score
system can query tool-use reliability.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from policy.audit import AuditLog
from tools.registry import Rejection, ToolRegistry


@dataclass
class BreakerConfig:
    """Repeated-violation breaker thresholds (issue #155)."""

    max_violations: int = 5
    window_s: float = 300.0
    cooldown_s: float = 600.0


@dataclass
class _ViolationWindow:
    timestamps: list[float] = field(default_factory=list)
    tripped_until: float = 0.0


class ToolGate:
    """Validating dispatcher: the single path from a model's tool call to
    actual execution."""

    def __init__(
        self,
        registry: ToolRegistry,
        audit_log: AuditLog | None = None,
        breaker_config: BreakerConfig | None = None,
        max_retries: int = 3,
        clock=time.monotonic,
    ) -> None:
        self.registry = registry
        self._audit = audit_log
        self._config = breaker_config or BreakerConfig()
        self.max_retries = max_retries
        # injectable clock keeps breaker tests deterministic
        self._clock = clock
        self._violations: dict[str, _ViolationWindow] = {}
        # per (model, provider) malformed-call counters → §8.3 scores
        self.malformed_by_model: Counter[tuple[str, str]] = Counter()
        self.total_by_model: Counter[tuple[str, str]] = Counter()

    def _identity_key(self, agent_uuid: str, model_id: str) -> str:
        return f"{agent_uuid}:{model_id}"

    def breaker_state(self, agent_uuid: str, model_id: str) -> dict[str, float | bool]:
        key = self._identity_key(agent_uuid, model_id)
        win = self._violations.get(key)
        now = self._clock()
        return {
            "tripped": bool(win and win.tripped_until > now),
            "cooldown_remaining_s": max(0.0, (win.tripped_until - now)) if win else 0.0,
            "recent_violations": len(
                [t for t in win.timestamps if now - t <= self._config.window_s]
            )
            if win
            else 0,
        }

    def _record_violation(self, agent_uuid: str, model_id: str) -> bool:
        """Record one malformed call; returns True when the breaker trips."""
        key = self._identity_key(agent_uuid, model_id)
        now = self._clock()
        win = self._violations.setdefault(key, _ViolationWindow())
        if win.tripped_until > now:
            return True  # already paused; do not extend on further attempts
        win.timestamps = [t for t in win.timestamps if now - t <= self._config.window_s]
        win.timestamps.append(now)
        if len(win.timestamps) >= self._config.max_violations:
            win.tripped_until = now + self._config.cooldown_s
            win.timestamps.clear()
            if self._audit:
                self._audit.append(
                    "tool_breaker_tripped",
                    {
                        "agent_uuid": agent_uuid,
                        "model_id": model_id,
                        "cooldown_s": self._config.cooldown_s,
                    },
                    actor="tools.gate",
                )
            return True
        return False

    def dispatch(
        self,
        fn: Any,
        name: str,
        arguments: dict[str, Any],
        *,
        agent_uuid: str = "",
        model_id: str = "",
        provider_id: str = "",
    ) -> tuple[Any | None, Rejection | None]:
        """Validate then execute *fn(normalized_arguments)*.

        Returns ``(result, None)`` on success or ``(None, rejection)`` when
        validation fails or the breaker is open — in both cases *fn* is never
        invoked, which the safety tests assert directly.
        """
        identity = (model_id, provider_id)
        self.total_by_model[identity] += 1

        state = self.breaker_state(agent_uuid, model_id)
        if state["tripped"]:
            self.malformed_by_model[identity] += 1
            return None, Rejection(
                "breaker_open",
                "agent/model paused for repeated malformed tool calls; "
                f"cooldown {state['cooldown_remaining_s']:.0f}s remaining",
            )

        normalized, rejection = self.registry.validate_call(name, arguments)
        if rejection is not None:
            self.malformed_by_model[identity] += 1
            tripped = self._record_violation(agent_uuid, model_id)
            if tripped:
                return None, Rejection(
                    "breaker_open",
                    "paused after repeated malformed tool calls",
                    [rejection.code],
                )
            if self._audit:
                self._audit.append(
                    "tool_call_rejected",
                    {"tool": name, "code": rejection.code, "message": rejection.message},
                    actor="tools.gate",
                )
            return None, rejection

        result = fn(**(normalized or {}))
        return result, None

    def retry_budget_left(self, rejections_seen: int) -> int:
        """Bounded-retry helper: how many more feedback rounds the caller may
        spend on this call before escalating to the failure matrix (#91,
        MALFORMED_OUTPUT dead-letter path)."""
        return max(0, self.max_retries - rejections_seen)
