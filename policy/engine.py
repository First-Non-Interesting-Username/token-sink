"""Policy engine (PLAN §2.1, §5, §15): evaluate every tool call against the
campaign scope BEFORE execution. A failed check produces a blocked decision
with an actionable explanation; enforcement lives here in code, never as
prompt discouragement.

Missing or ambiguous scope is a defined refusal state (`ScopeStatus.AMBIGUOUS`
/ `MISSING`), not an error to guess around.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from policy.scope import ACTIVE_TEST_CLASSES, HARD_PROHIBITED_ACTIONS, ScopePolicy
from policy.ssrf import SSRFGuard


class ScopeStatus(enum.Enum):
    """Defined states for how well a campaign's scope is known (§5)."""

    DEFINED = "defined"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"


@dataclass(frozen=True)
class BlockedAction:
    """A denied action plus an actionable explanation (§5)."""

    reason: str
    violations: list[str] = field(default_factory=list)
    blocked_event_id: str = ""


@dataclass(frozen=True)
class AllowedAction:
    decision: str = "allowed"


@dataclass
class ToolCallRequest:
    """The unit the engine evaluates: one attempted tool invocation."""

    tool: str
    agent_uuid: str
    campaign_uuid: str
    # What the tool would touch — a URL for network tools, an identifier for
    # repos/packages/APIs.
    target: str = ""
    method: str = ""
    test_class: str = ""
    action: str = ""  # named action class, e.g. "denial_of_service"
    shell_command: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    allowed: bool
    status: ScopeStatus
    explanation: str
    blocked_event_id: str = ""
    violations: list[str] = field(default_factory=list)


def assess_scope(scope: ScopePolicy | None) -> ScopeStatus:
    """Classify how defined a campaign's scope is.

    - MISSING: no scope object at all, no authorization reference, or zero
      in-scope targets — agents must refuse/pause.
    - AMBIGUOUS: authorization reference present but the target surface is
      empty, or vice versa — pause for human clarification.
    """
    if scope is None:
        return ScopeStatus.MISSING
    has_auth = bool(scope.authorization_reference)
    has_targets = bool(scope.in_scope)
    if not has_auth and not has_targets:
        return ScopeStatus.MISSING
    if not (has_auth and has_targets):
        return ScopeStatus.AMBIGUOUS
    return ScopeStatus.DEFINED


class PolicyEngine:
    """Evaluates tool calls against a campaign's ScopePolicy (§5)."""

    def __init__(self, scope: ScopePolicy | None, ssrf_guard: SSRFGuard | None = None):
        self.scope = scope
        self._scope_status = assess_scope(scope)
        self._ssrf = ssrf_guard or SSRFGuard()
        self._blocked_events: dict[str, BlockedAction] = {}

    @property
    def scope_status(self) -> ScopeStatus:
        return self._scope_status

    def blocked_events(self) -> dict[str, BlockedAction]:
        return dict(self._blocked_events)

    def _block(
        self, request: ToolCallRequest, reason: str, violations: list[str]
    ) -> PolicyDecision:
        # Every block emits a durable event with an ID so observability (#23)
        # and audit (#15) can reference exactly what was refused and why.
        event_id = str(uuid.uuid4())
        self._blocked_events[event_id] = BlockedAction(
            reason=reason, violations=list(violations), blocked_event_id=event_id
        )
        actionable = f"{reason} (tool={request.tool!r}"
        if request.target:
            actionable += f", target={request.target!r}"
        if violations:
            actionable += ", violations=" + ", ".join(violations)
        actionable += ")"
        return PolicyDecision(
            False,
            self._scope_status,
            actionable,
            blocked_event_id=event_id,
            violations=list(violations),
        )

    def evaluate(self, request: ToolCallRequest) -> PolicyDecision:
        # 1. Missing/ambiguous scope is itself a refusal state (§5): agents
        # must pause rather than guess at what is permitted.
        if self._scope_status is ScopeStatus.MISSING:
            return self._block(
                request,
                "campaign scope is MISSING — define authorization + in-scope "
                "targets before any tool runs",
                ["scope_missing"],
            )
        if self._scope_status is ScopeStatus.AMBIGUOUS:
            return self._block(
                request,
                "campaign scope is AMBIGUOUS — authorization and target list "
                "must both be present; pausing for human clarification",
                ["scope_ambiguous"],
            )
        assert self.scope is not None

        # 2. Kill switch interplay is handled upstream; here we enforce the
        # per-action rules in a fixed order so blocks are deterministic.

        # 3. Named prohibited actions — including the hard-prohibited set
        # that no campaign configuration can re-enable.
        prohibited = self.scope.prohibited_actions | HARD_PROHIBITED_ACTIONS
        if request.action and request.action in prohibited:
            return self._block(
                request,
                f"action {request.action!r} is prohibited by campaign policy",
                [f"prohibited_action:{request.action}"],
            )

        # 4. Shell execution is disabled by default (§15) and requires the
        # explicit 'shell' test class to have been granted.
        if request.tool == "shell" or request.shell_command:
            if "shell" not in self.scope.allowed_test_classes:
                return self._block(
                    request,
                    "shell execution is disabled by default; grant the "
                    "'shell' test class explicitly to enable it",
                    ["shell_not_approved"],
                )

        # 5. Active testing requires both the flag and the test class being
        # allowed; read-only reconnaissance stays available without it.
        effective_class = request.test_class or (
            "reconnaissance" if request.tool != "shell" else "shell"
        )
        if effective_class in ACTIVE_TEST_CLASSES:
            if not self.scope.active_testing_enabled:
                return self._block(
                    request,
                    "active testing is disabled for this campaign",
                    ["active_testing_disabled"],
                )
            if effective_class not in self.scope.allowed_test_classes:
                return self._block(
                    request,
                    f"test class {effective_class!r} is not allowed by this campaign",
                    [f"test_class_denied:{effective_class}"],
                )

        # 6. HTTP method allowlist for anything that speaks HTTP.
        if request.method:
            method = request.method.upper()
            if method not in {m.upper() for m in self.scope.allowed_methods}:
                return self._block(
                    request,
                    f"HTTP method {method} is not in the campaign allowlist "
                    f"{sorted(self.scope.allowed_methods)}",
                    [f"method_denied:{method}"],
                )

        # 7. Target checks: scope classification FIRST (cheap, offline, and
        # gives the most actionable explanation), then the SSRF guard for
        # http(s) destinations — a hard safety layer independent of campaign
        # config that stays in effect even when the host IS in scope.
        if request.target:
            classification, match = self.scope.classify_target(request.target)
            if classification == "out":
                return self._block(
                    request,
                    "target is explicitly out of scope",
                    ["target_out_of_scope"],
                )
            if classification == "unlisted":
                return self._block(
                    request,
                    "target is not listed in campaign scope (default-deny)",
                    ["target_unlisted"],
                )
            del match  # matched spec kept for future rate-limit keying

            if request.target.lower().startswith(("http://", "https://")):
                verdict = self._ssrf.check(request.target)
                if not verdict.allowed:
                    return self._block(
                        request,
                        f"SSRF protection: {verdict.reason}",
                        ["ssrf_blocked"],
                    )

        return PolicyDecision(True, self._scope_status, "allowed by campaign policy")

    def evaluate_or_raise(self, request: ToolCallRequest) -> PolicyDecision:
        """Convenience wrapper for call sites that treat denial as fatal."""
        decision = self.evaluate(request)
        if not decision.allowed:
            raise PermissionError(decision.explanation)
        time.sleep(0)  # keep import used; evaluation itself is side-effect free
        return decision
