"""Finding version store: per-transition authorship, semantic diffs, CLI (issue #291).

PLAN §13 view 3 requires reviewers to answer "what changed since the first
review cycle and who changed it" from the UI alone. The pieces already exist
but are disconnected:

- ``findings.lifecycle.RecordStore`` keeps every version snapshot +
  append-only transition history (with actor + reason per transition).
- ``findings.version_diff.diff_findings`` produces the structured semantic
  diff (claim changes, evidence-link deltas, drift flags).
- ``findings.concurrency.ConcurrencyControl`` rejects conflicting concurrent
  edits and audits the rejections.

This module is the *version-store view* that ties them together:

- :meth:`VersionStore.versions` — ordered version metadata (version number,
  author, reason, timestamp, state) derived from history; no duplicate
  bookkeeping, single source of truth.
- :meth:`VersionStore.diff` — semantic diff between any two versions with a
  unified prose fallback for free-text fields.
- :meth:`VersionStore.conflicts` — surfaced conflicting-edit rejections
  per §18 so a reviewer sees who collided with whom.
- :func:`render_unified_diff` — difflib-based prose rendering used by the
  ``finding inspect --diff vN vM`` CLI surface (:mod:`cli.finding_inspect`).

Read-only over the store: nothing here mutates finding records.
"""

from __future__ import annotations

import difflib
from typing import Any

from findings import version_diff as vd
from findings.concurrency import ConcurrencyControl
from findings.lifecycle import RecordStore

__all__ = ["VersionInfo", "VersionStore", "UnknownVersionError"]


class UnknownVersionError(KeyError):
    pass


def _as_state_value(state: Any) -> str:
    return getattr(state, "value", state)


class VersionInfo:
    """Metadata about one stored version of a finding."""

    __slots__ = ("version", "author", "reason", "timestamp", "state")

    def __init__(self, version: int, author: str, reason: str, timestamp: str, state: str):
        self.version = version
        self.author = author
        self.reason = reason
        self.timestamp = timestamp
        self.state = state

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "author": self.author,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "state": self.state,
        }


class VersionStore:
    """Read-only view over a RecordStore answering version/diff/conflict queries."""

    def __init__(self, store: RecordStore, concurrency: ConcurrencyControl | None = None):
        self.store = store
        # Optional concurrency control; only needed for conflict surfacing.
        self._concurrency = concurrency

    # -- internals -------------------------------------------------------------

    def _versions_list(self, finding_uuid: str) -> list[Any]:
        versions = list(getattr(self.store, "_versions", {}).get(finding_uuid, []))
        if not versions:
            raise UnknownVersionError(f"finding {finding_uuid} has no stored versions")
        return versions

    def _snapshot(self, finding_uuid: str, version: int):
        versions = self._versions_list(finding_uuid)
        if not 1 <= version <= len(versions):
            raise UnknownVersionError(
                f"finding {finding_uuid} has no version {version} (has {len(versions)})"
            )
        return versions[version - 1]

    def _history(self, finding_uuid: str) -> list[Any]:
        return list(self.store.history(finding_uuid))

    # -- queries ---------------------------------------------------------------

    def versions(self, finding_uuid: str) -> list[dict[str, Any]]:
        """Ordered version metadata: who made each change, why, when.

        Version N corresponds to the Nth stored snapshot; its author/reason/
        timestamp come from the transition saved alongside it (same index in
        the append-only history — RecordStore.save appends to both).
        """
        history = self._history(finding_uuid)
        out = []
        for i, t in enumerate(history, start=1):
            record = None
            versions = getattr(self.store, "_versions", {}).get(finding_uuid, [])
            if i <= len(versions):
                record = versions[i - 1]
            out.append(
                {
                    "version": i,
                    "author": t.actor_uuid,
                    "reason": t.reason,
                    "timestamp": t.timestamp,
                    "state": _as_state_value(record.state) if record is not None else t.to_state,
                }
            )
        return out

    def diff(self, finding_uuid: str, from_version: int, to_version: int) -> dict[str, Any]:
        """Semantic diff between two versions (see findings.version_diff)."""
        old = self._snapshot(finding_uuid, from_version)
        new = self._snapshot(finding_uuid, to_version)
        result = vd.diff_findings(old, new)
        result["from_version"] = from_version
        result["to_version"] = to_version
        result["changed_by"] = {
            "from_author": self._author_of(finding_uuid, from_version),
            "to_author": self._author_of(finding_uuid, to_version),
        }
        return result

    def _author_of(self, finding_uuid: str, version: int) -> str:
        history = self._history(finding_uuid)
        if 1 <= version <= len(history):
            return history[version - 1].actor_uuid
        return ""

    def conflicts(self, finding_uuid: str | None = None) -> list[dict[str, Any]]:
        """Conflicting-edit rejections surfaced per PLAN §18."""
        if self._concurrency is None:
            return []
        rejections = self._concurrency.rejected_writes(finding_uuid)
        return [
            {
                "finding_uuid": r.finding_uuid,
                "agent_uuid": r.actor_uuid,
                "expected_version": r.expected_version,
                "actual_version": r.actual_version,
                "reason": r.reason_attempted,
            }
            for r in rejections
        ]


def render_unified_diff(
    old_text: str, new_text: str, from_label: str = "v-old", to_label: str = "v-new"
) -> str:
    """Unified prose diff for free-text fields (CLI fallback rendering).

    Semantic structure lives in :meth:`VersionStore.diff`; this renders one
    field's before/after as a standard unified diff for terminal display.
    """
    lines = difflib.unified_diff(
        old_text.splitlines(keepends=True) or [""],
        new_text.splitlines(keepends=True) or [""],
        fromfile=from_label,
        tofile=to_label,
    )
    return "".join(lines)


def format_diff_report(result: dict[str, Any]) -> str:
    """Render a full VersionStore.diff result for `finding inspect --diff`."""
    lines = [
        f"finding {result['finding_uuid']}: v{result['from_version']} -> v{result['to_version']}",
        f"authors: {result['changed_by']['from_author']} -> {result['changed_by']['to_author']}",
        "",
    ]
    for c in result["changed"]:
        lines.append(f"~ {c['field']}:")
        lines.append(render_unified_diff(str(c["old"]), str(c["new"]), "-old", "+new"))
    if result["evidence_added"]:
        lines.append(f"+ evidence: {', '.join(result['evidence_added'])}")
    if result["evidence_removed"]:
        lines.append(f"- evidence removed: {', '.join(result['evidence_removed'])}")
    if result["has_unlinked_drift"]:
        fields = ", ".join(u["field"] for u in result["unlinked_claims"])
        lines.append(f"! UNLINKED CLAIM DRIFT: {fields}")
    return "\n".join(lines)
