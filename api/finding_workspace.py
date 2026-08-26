"""Finding workspace read-model: timeline, version diff, review assembly.

Implements the read-only API behind the finding-workspace UI view
(PLAN §13 view 3, issue #162). Sits on top of the versioned records and
append-only transition history maintained by :mod:`findings.lifecycle`
(#11/#50) — it performs NO state mutation; every endpoint is a query.

Pieces:

- **Timeline** (:meth:`FindingWorkspace.timeline`): ordered lifecycle
  events for one finding. Ordering is stable by ``(seq, timestamp)`` so a
  store that received events out of order still yields a deterministic,
  causally correct sequence (seq is assigned by the lifecycle at transition
  time and is authoritative).
- **Version diff** (:meth:`FindingWorkspace.diff_versions`): structured
  comparison of two finding versions — scalar field changes, list-field
  membership changes (added/removed preserving order), and nested-dict
  changes. This is NOT a text diff: consumers get typed field-level data
  they can render.
- **Review assembly** (:meth:`FindingWorkspace.reviews`): reviewer verdicts
  including PoC reviews, dissent flags, and mode metadata (§10.5).

Safety: every serialized response is passed through the redaction pipeline
(:mod:`src.tokensink.redaction`) before leaving this module (issue #29
pipeline), so secrets never reach the UI layer even if a finding snapshot
captured one.
"""

from __future__ import annotations

from typing import Any

from findings.lifecycle import RecordStore
from src.tokensink import redaction

__all__ = ["VersionDiff", "FindingWorkspace", "UnknownFindingError", "UnknownVersionError"]


class UnknownFindingError(KeyError):
    pass


class UnknownVersionError(KeyError):
    pass


def _redact(value: Any) -> Any:
    """Recursively redact strings inside JSON-shaped *value*."""
    if isinstance(value, str):
        return redaction.redact(value).text
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


# Fields compared as ordered lists (membership + order matter); everything
# else non-dict is compared by equality.
_LIST_FIELDS = frozenset({"evidence_refs", "repro_outline"})


class VersionDiff:
    """Structured diff between two finding versions."""

    def __init__(self) -> None:
        self.changed: dict[str, dict[str, Any]] = {}
        self.added: dict[str, Any] = {}
        self.removed: dict[str, Any] = {}

    def to_dict(self) -> dict[str, Any]:
        return {"changed": self.changed, "added": self.added, "removed": self.removed}

    @property
    def empty(self) -> bool:
        return not self.changed and not self.added and not self.removed


def _diff_lists(old: list, new: list) -> dict[str, Any] | None:
    """Ordered-membership diff for claim/evidence-style list fields."""
    old_set, new_set = set(old), set(new)
    added = [x for x in new if x not in old_set]
    removed = [x for x in old if x not in new_set]
    reordered = added == [] and removed == [] and old != new
    if added or removed or reordered:
        result: dict[str, Any] = {"added": added, "removed": removed}
        # Pure reorder carries meaning for repro outlines (step order).
        if reordered:
            result["reordered"] = True
            result["old"] = list(old)
            result["new"] = list(new)
        return result
    return None


def _diff_dicts(old: dict, new: dict, into: VersionDiff, prefix: str = "") -> None:
    for key in sorted(set(old) | set(new)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in old:
            into.added[path] = new[key]
        elif key not in new:
            into.removed[path] = old[key]
        else:
            a, b = old[key], new[key]
            if isinstance(a, dict) and isinstance(b, dict):
                _diff_dicts(a, b, into, prefix=path)
            elif isinstance(a, list) and isinstance(b, list):
                d = _diff_lists(a, b)
                if d is not None:
                    into.changed[path] = {"kind": "list", **d}
            elif a != b:
                into.changed[path] = {"kind": "scalar", "old": a, "new": b}


class FindingWorkspace:
    """Read-only queries backing the finding-workspace UI (#22 view 3)."""

    def __init__(self, store: RecordStore):
        self.store = store

    # -- internal ------------------------------------------------------------

    def _require(self, finding_uuid: str) -> str:
        history = self.store.history(finding_uuid)
        if not history and self.store.load(finding_uuid) is None:
            raise UnknownFindingError(finding_uuid)
        return finding_uuid

    def _version(self, finding_uuid: str, version: int) -> dict[str, Any]:
        """Fetch one version snapshot. Versions are 1-indexed in arrival order.

        The in-memory store keeps references, so we deep-copy and freeze the
        snapshot the moment it is requested — but that alone cannot recover
        historical state if a caller mutated a record in place. Real store
        implementations (#12) must persist immutable copies; this read model
        additionally snapshots defensively via to_dict() copies taken at
        query time.
        """
        import copy

        versions = getattr(self.store, "_versions", {}).get(finding_uuid, [])
        if not 1 <= version <= len(versions):
            raise UnknownVersionError(
                f"finding {finding_uuid} has no version {version} (has {len(versions)})"
            )
        return copy.deepcopy(versions[version - 1].to_dict())

    # -- endpoints -------------------------------------------------------------

    def timeline(self, finding_uuid: str) -> dict[str, Any]:
        """All lifecycle events for a finding, deterministically ordered."""
        self._require(finding_uuid)
        events = [
            {
                "seq": t.seq,
                "from_state": t.from_state,
                "to_state": t.to_state,
                "reason": t.reason,
                "actor_uuid": t.actor_uuid,
                "timestamp": t.timestamp,
                "payload": t.payload,
            }
            for t in self.store.history(finding_uuid)
        ]
        # Stable sort keyed on seq (assigned at transition time — the causal
        # order), timestamp as tiebreak. Out-of-order event arrival therefore
        # cannot scramble the displayed sequence.
        events.sort(key=lambda e: (e["seq"], e["timestamp"]))
        current = self.store.load(finding_uuid)
        return {
            "finding_uuid": finding_uuid,
            "current_state": current.state.value if current is not None else None,
            "version_count": len(getattr(self.store, "_versions", {}).get(finding_uuid, [])),
            "events": _redact(events),
        }

    def diff_versions(
        self, finding_uuid: str, from_version: int, to_version: int
    ) -> dict[str, Any]:
        """Structured field-level diff between two versions of a finding."""
        self._require(finding_uuid)
        old = self._version(finding_uuid, from_version)
        new = self._version(finding_uuid, to_version)
        diff = VersionDiff()
        for key in sorted(set(old) | set(new)):
            if key not in old:
                diff.added[key] = new[key]
            elif key not in new:
                diff.removed[key] = old[key]
            elif key in ("reviews", "poc_reviews"):
                continue  # assembled separately via .reviews()
            elif isinstance(old[key], dict) and isinstance(new[key], dict):
                _diff_dicts(old[key], new[key], diff, prefix=key)
            elif isinstance(old[key], list) and isinstance(new[key], list):
                d = _diff_lists(old[key], new[key])
                if d is not None:
                    diff.changed[key] = {"kind": "list", **d}
            elif old[key] != new[key]:
                diff.changed[key] = {"kind": "scalar", "old": old[key], "new": new[key]}
        return _redact(
            {
                "finding_uuid": finding_uuid,
                "from_version": from_version,
                "to_version": to_version,
                **diff.to_dict(),
            }
        )

    def reviews(self, finding_uuid: str) -> dict[str, Any]:
        """Reviewer verdicts incl. dissent and PoC verdicts (§10.5 metadata)."""
        self._require(finding_uuid)
        current = self.store.load(finding_uuid)
        if current is None:
            raise UnknownFindingError(finding_uuid)
        record = current.to_dict()
        poc = []
        for r in record.get("poc_reviews", []):
            poc.append(
                {
                    "reviewer": r.get("reviewer") or r.get("agent_uuid", ""),
                    "verdict": r.get("verdict", ""),
                    "dissent": bool(r.get("dissent")),
                    "mode": r.get("mode", ""),  # independent-first / discussion-first
                    "comment": r.get("comment", ""),
                }
            )
        return _redact(
            {
                "finding_uuid": finding_uuid,
                "reviews": record.get("reviews", []),
                "poc_reviews": poc,
            }
        )
