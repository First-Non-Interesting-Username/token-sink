"""Free-only enforcement for routing.

A task is free-only if ``task.free_only`` is true. In that case, only
models whose free status is ``confirmed`` are eligible. A per-campaign
override (carried on the routing task) can downgrade a free-only
restriction to "allow paid" but only when the task carries an
explicit ``human_approved`` flag. This satisfies spec §7.3 ("never
route to paid when free-only").
"""
from __future__ import annotations

from mavr.schemas.routing import ModelCatalogEntry


class FreeOnlyViolation(RuntimeError):
    """Raised when a free-only task is asked to consider a non-free model."""


def eligible_candidates(
    entry: ModelCatalogEntry,
    *,
    free_only: bool,
    allow_paid_override: bool = False,
    human_approved: bool = False,
) -> ModelCatalogEntry:
    """Return the entry if it is eligible for the task. Raise otherwise.

    The override is honored only if both ``allow_paid_override`` and
    ``human_approved`` are set. A paid model with free_status=paid is
    only ever returned when the override path is taken.
    """
    if entry.free and entry.free_status == "confirmed":
        return entry
    if not free_only:
        return entry
    if allow_paid_override and human_approved:
        return entry
    raise FreeOnlyViolation(
        f"model {entry.provider_id}/{entry.model_key} is "
        f"free={entry.free} free_status={entry.free_status!r}; "
        "free-only routing rejects it"
    )


def require_paid_override(task) -> bool:
    """Return True iff a free-only task is allowed to consider a paid model."""
    if not task.free_only:
        return True
    if task.allow_paid_override and task.human_approved:
        return True
    return False
