"""§10.2/§10.5 deletion & quarantine safeguards (issue #48).

Shared helpers used by FindingLifecycle to enforce the safety rules that
keep deletion rare, deliberate and auditable:

- Reviewer independence: the dispute reviewer must be a distinct agent UUID
  from every earlier reviewer on the record (PLAN §10.2 "a separate
  reviewer"; §7.2 diversity principle).
- Exactly-once deletion: a tombstone transition is only applied once; a
  second attempt raises instead of double-deleting or silently succeeding.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - type hints only
    pass  # (Finding / LifecycleError referenced lazily to avoid circular import)


def reviewer_uuids(finding) -> set[str]:
    """All agent UUIDs that have already reviewed this finding.

    Covers both cycle-1 review entries (`reviewer`) and dispute entries,
    which also use `reviewer` as their key.
    """
    out: set[str] = set()
    for r in getattr(finding, "reviews", []):
        ru = r.get("reviewer")
        if ru:
            out.add(ru)
    return out


def require_distinct_reviewer(finding, new_reviewer_uuid: str) -> None:
    """Raise unless `new_reviewer_uuid` differs from all prior reviewers.

    PLAN §10.2: the dispute evaluation must be independent — the same agent
    confirming its own 'incorrect' conclusion can never satisfy dual
    confirmation.
    """
    prior = reviewer_uuids(finding)
    if new_reviewer_uuid in prior:
        raise _lifecycle_error(
            "reviewer independence violated: dispute reviewer must differ "
            f"from prior reviewers {sorted(prior)}"
        )


def assert_not_deleted(finding) -> None:
    """Guard against any post-tombstone action (tombstones are terminal)."""
    if str(getattr(finding, "state", "")).endswith("deleted"):
        raise _lifecycle_error("finding is deleted: tombstone is terminal")


def _lifecycle_error(msg: str):
    # Imported lazily so the guard module can be imported from lifecycle.py
    # without a circular import at module-load time.
    from findings.lifecycle import LifecycleError

    return LifecycleError(msg)


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return True
