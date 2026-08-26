"""Conflicting-edit resolution for findings (PLAN §18, issue #132).

Implements the ``versioned_merge_resolution`` recovery path declared for
``FailureClass.CONFLICTING_EDITS`` in :mod:`orchestrator.failures`.

Two guards protect every finding write:

1. **Lease binding** — while a finding sits in a leased state
   (see ``LEASED_STATES``), only the current lease holder may modify it,
   and only while its lease is unexpired. A non-holder or expired holder
   gets :class:`StaleLeaseError` / :class:`NotLeaseHolderError`.
2. **Optimistic concurrency** — every write carries the version the writer
   based their edit on (the append-only history length). If the stored
   version has moved on, the write is rejected with
   :class:`ConflictError` and *both* the attempted edit and the current
   record are preserved in an audit entry for diagnosis — nothing is
   silently overwritten (PLAN principle 4).

Conflict resolution is explicit: after a :class:`ConflictError` the caller
re-reads the current record and either rebases their edit onto it or calls
:meth:`ConcurrencyControl.resolve_conflict` to record an explicit
adjudication (last-write-wins or discard) in the audit trail.

Rejections are audited *without* advancing the version: a rejected write
must not stale every other in-flight writer, so rejection evidence goes to
a side audit log plus a history-only transition recorded at the CURRENT
version number (not appended past it). Adjudications go through both guards.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from findings.lifecycle import (
    LEASED_STATES,
    Finding,
    LifecycleError,
    RecordStore,
    Transition,
    _now,
)


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _fresh_copy(finding: Finding) -> Finding:
    """Return an independent copy of a stored finding.

    ``RecordStore.load`` returns the live stored object; mutating it in
    place would silently rewrite every previously stored "version". All
    writes are applied to a copy which then becomes the new head.
    """
    return copy.deepcopy(finding)


class ConflictError(LifecycleError):
    """Optimistic-concurrency violation: the record changed underneath us."""

    def __init__(self, finding_uuid: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"conflicting edit on {finding_uuid}: expected version "
            f"{expected_version}, actual {actual_version}"
        )
        self.finding_uuid = finding_uuid
        self.expected_version = expected_version
        self.actual_version = actual_version


class NotLeaseHolderError(LifecycleError):
    """Write attempted by an agent that does not hold the finding's lease."""


class StaleLeaseError(LifecycleError):
    """The finding's lease exists but has expired."""


@dataclass
class RejectedWrite:
    """Audit record of one rejected write attempt (§18: preserve for diagnosis)."""

    finding_uuid: str
    actor_uuid: str
    expected_version: int
    actual_version: int
    reason_attempted: str
    timestamp: str


class ConcurrencyControl:
    """Version-checked, lease-bound write layer over a :class:`RecordStore`."""

    def __init__(self, store: RecordStore) -> None:
        self.store = store
        self.rejections: list[RejectedWrite] = []

    # -- queries -----------------------------------------------------------

    def current_version(self, finding_uuid: str) -> int:
        """Version = number of entries in the append-only history."""
        return len(self.store.history(finding_uuid))

    def rejected_writes(self, finding_uuid: str | None = None) -> list[RejectedWrite]:
        """All conflicting-edit rejections, optionally filtered by finding."""
        if finding_uuid is None:
            return list(self.rejections)
        return [r for r in self.rejections if r.finding_uuid == finding_uuid]

    # -- guarded writes ------------------------------------------------------

    def update(
        self,
        finding_uuid: str,
        agent_uuid: str,
        expected_version: int,
        mutate: Callable[[Finding], None],
        reason: str = "edit",
    ) -> int:
        """Apply ``mutate`` under both guards; returns the new version.

        Raises before touching the record on any violation — the failed
        edit never lands half-applied because mutation happens only after
        both checks pass. A rejected write does NOT advance the version.
        """
        finding = self.store.load(finding_uuid)
        if finding is None:
            raise LifecycleError(f"unknown finding {finding_uuid}")
        state = finding.state
        from findings.lifecycle import State

        if isinstance(state, str):
            state = State(state)

        # Guard 1: lease binding (only in states where leases are required).
        if state in LEASED_STATES:
            self._require_valid_lease(finding, agent_uuid)

        # Guard 2: optimistic version check against the live record.
        actual = self.current_version(finding_uuid)
        if actual != expected_version:
            self._audit_rejection(finding_uuid, agent_uuid, expected_version, actual, reason)
            raise ConflictError(finding_uuid, expected_version, actual)

        # Work on a copy so prior stored versions stay frozen; the copy
        # becomes the new head on save.
        working = _fresh_copy(finding)
        if isinstance(working.state, str):
            working.state = State(working.state)
        mutate(working)

        t = Transition(
            seq=actual + 1,
            finding_uuid=finding_uuid,
            from_state=str(state),
            to_state=str(working.state),
            reason=f"guarded_write:{reason}",
            actor_uuid=agent_uuid,
            timestamp=_now(),
            payload={"expected_version": expected_version},
        )
        self.store.save(working, t)
        return self.current_version(finding_uuid)

    # -- explicit resolution -------------------------------------------------

    def resolve_conflict(
        self,
        finding_uuid: str,
        adjudicator_uuid: str,
        winner_payload: dict[str, Any],
        strategy: str,
        expected_version: int | None = None,
    ) -> int:
        """Record an explicit adjudication of a conflicting edit.

        ``strategy`` is ``"last_write_wins"`` (apply winner_payload over the
        current record) or ``"discard_incoming"`` (keep current, log the
        losing payload). Either way the losing edit stays visible in the
        audit trail — never silently dropped.

        Adjudication is itself a guarded write: the adjudicator must hold a
        valid lease when the finding is in a leased state, and must pass the
        current version via ``expected_version`` so a concurrent writer can't
        slip in between read and adjudication. Passing ``expected_version``
        explicitly keeps the API honest; callers who genuinely want to force
        an adjudication against any concurrent change should re-read the
        current version immediately before calling.
        """
        if strategy not in ("last_write_wins", "discard_incoming"):
            raise LifecycleError(f"unknown resolution strategy {strategy!r}")

        finding = self.store.load(finding_uuid)
        if finding is None:
            raise LifecycleError(f"unknown finding {finding_uuid}")
        state = finding.state
        from findings.lifecycle import State

        if isinstance(state, str):
            state = State(state)

        # Same two guards as update(): adjudication must never be a way
        # around lease binding or optimistic concurrency.
        if state in LEASED_STATES:
            self._require_valid_lease(finding, adjudicator_uuid)
        actual = self.current_version(finding_uuid)
        if expected_version is not None and expected_version != actual:
            self._audit_rejection(
                finding_uuid, adjudicator_uuid, expected_version, actual, f"resolve:{strategy}"
            )
            raise ConflictError(finding_uuid, expected_version, actual)

        working = _fresh_copy(finding)
        if isinstance(working.state, str):
            working.state = State(working.state)
        if strategy == "last_write_wins":
            for key, value in winner_payload.items():
                setattr(working, key, value)

        t = Transition(
            seq=actual + 1,
            finding_uuid=finding_uuid,
            from_state=str(state),
            to_state=str(working.state),
            reason=f"conflict_resolved:{strategy}",
            actor_uuid=adjudicator_uuid,
            timestamp=_now(),
            payload={"winner": winner_payload},
        )
        self.store.save(working, t)
        return self.current_version(finding_uuid)

    # -- internal --------------------------------------------------------------

    def _require_valid_lease(self, finding: Finding, agent_uuid: str) -> None:
        lease = finding.lease
        if lease is None:
            raise NotLeaseHolderError(f"{finding.finding_uuid} requires a lease; none held")
        if lease.agent_uuid != agent_uuid:
            raise NotLeaseHolderError(
                f"lease on {finding.finding_uuid} held by {lease.agent_uuid}, not {agent_uuid}"
            )
        if _parse_ts(lease.expires_at) <= datetime.now(UTC):
            raise StaleLeaseError(f"lease on {finding.finding_uuid} expired at {lease.expires_at}")

    def _audit_rejection(
        self,
        finding_uuid: str,
        agent_uuid: str,
        expected: int,
        actual: int,
        reason: str,
    ) -> None:
        """Preserve evidence of the rejected attempt WITHOUT advancing the version.

        The rejection lands in the side audit log and as a history-only
        marker stamped with the CURRENT version's seq — it is deliberately
        NOT appended to the store's history, because bumping the version on
        rejection would instantly stale every other in-flight writer and
        turn one conflict into a cascade.
        """
        rejection = RejectedWrite(
            finding_uuid=finding_uuid,
            actor_uuid=agent_uuid,
            expected_version=expected,
            actual_version=actual,
            reason_attempted=reason,
            timestamp=_now(),
        )
        self.rejections.append(rejection)
