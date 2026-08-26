"""Versioned finding snapshots + diff-by-version service (issue #291, PLAN §13 view 3).

Issue #119's :mod:`findings.version_diff` diffs two in-memory ``Finding``
records; the RecordStore already keeps every prior version. This module is
the reviewer-facing layer between the two:

- **Addressable versions**: ``v1..vN`` with the actor, timestamp and
  transition reason that produced each one — a reviewer can answer *"what
  changed since the first review cycle and who changed it"* from this
  timeline alone.
- **Diff by version numbers**: :meth:`VersionSnapshotStore.diff` loads the
  two stored records and reuses the structured diff from #119, adding
  version metadata plus **semantic highlights** (severity changes, claim
  changes, evidence-link add/remove) so UI/CLI can render meaning rather
  than prose noise.
- **§18 conflict surfacing**: rejected concurrent edits never advance the
  version (that's ConcurrencyControl's contract), so the snapshot timeline
  shows only real edits; callers combine it with
  ``ConcurrencyControl.rejected_writes()`` for conflict display.

Read-only over the store except for loading — no mutation of stored state.
"""

from __future__ import annotations

from typing import Any

from findings.concurrency import ConcurrencyControl
from findings.lifecycle import Finding, RecordStore
from findings.version_diff import CLAIM_FIELDS, diff_findings

__all__ = [
    "SEVERITY_FIELDS",
    "VersionNotFoundError",
    "VersionSnapshotStore",
    "render_side_by_side",
]

# Fields whose change counts as a severity/impact escalation in highlights.
# PLAN §10.3 severity rubric maps impact+evidence → level; suspected_impact
# is the free-text impact surface findings carry today.
SEVERITY_FIELDS = ("suspected_impact",)


class VersionNotFoundError(KeyError):
    """A requested snapshot version does not exist for the finding."""

    def __init__(self, finding_uuid: str, version: int) -> None:
        super().__init__(f"finding {finding_uuid} has no version v{version}")
        self.finding_uuid = finding_uuid
        self.version = version


class VersionSnapshotStore:
    """Version-numbered access + diffing over a :class:`RecordStore`.

    Version N is the Nth entry of the append-only history (same numbering
    ConcurrencyControl uses as its optimistic-concurrency token), so
    versions here, in conflict errors, and in lifecycle results all agree.
    """

    def __init__(
        self,
        store: RecordStore,
        concurrency: ConcurrencyControl | None = None,
    ) -> None:
        self.store = store
        self._cc = concurrency if concurrency is not None else ConcurrencyControl(store)

    # -- timeline -------------------------------------------------------------

    def versions(self, finding_uuid: str) -> list[dict[str, Any]]:
        """The full version timeline: number, actor, reason, timestamp.

        Rejected writes are absent by construction — they don't advance the
        history (see findings/concurrency.py), which keeps this list the
        truth about what actually landed.
        """
        out: list[dict[str, Any]] = []
        for i, t in enumerate(self.store.history(finding_uuid), start=1):
            out.append(
                {
                    "version": i,
                    "actor_uuid": t.actor_uuid,
                    "reason": t.reason,
                    "timestamp": t.timestamp,
                    "from_state": t.from_state,
                    "to_state": t.to_state,
                }
            )
        return out

    def snapshot(self, finding_uuid: str, version: int) -> Finding:
        """The stored record as of ``version`` (1-based)."""
        versions = self.store.history(finding_uuid)
        if version < 1 or version > len(versions):
            raise VersionNotFoundError(finding_uuid, version)
        found = self.store.load(finding_uuid)
        assert found is not None
        # load() returns only the head; walk the store's internal version
        # list through the public save order instead of reaching into privates:
        # RecordStore persists every saved Finding, so we re-fetch via the
        # same sequence the base class exposes. The base implementation keeps
        # them in _versions; expose through history-aligned replay below.
        return self._snapshot_at(finding_uuid, version)

    def _snapshot_at(self, finding_uuid: str, version: int) -> Finding:
        # RecordStore.save appends each Finding; the version list parallels
        # the history list. Access goes through the store's public-ish
        # attribute to avoid duplicating storage; subclasses that persist
        # differently override load-all behavior anyway.
        versions_list = getattr(self.store, "_versions", {}).get(finding_uuid, [])
        try:
            return versions_list[version - 1]
        except IndexError:
            raise VersionNotFoundError(finding_uuid, version) from None

    def head_version(self, finding_uuid: str) -> int:
        return self._cc.current_version(finding_uuid)

    # -- diffing ----------------------------------------------------------------

    def diff(self, finding_uuid: str, from_version: int, to_version: int) -> dict[str, Any]:
        """Structured diff between any two versions with semantic highlights."""
        old = self.snapshot(finding_uuid, from_version)
        new = self.snapshot(finding_uuid, to_version)
        d = diff_findings(old, new)

        highlights: list[dict[str, Any]] = []
        for c in d["changed"]:
            field = c["field"]
            if field in SEVERITY_FIELDS:
                highlights.append({"kind": "severity_change", "field": field, **c})
            elif field in CLAIM_FIELDS:
                highlights.append({"kind": "claim_change", "field": field, **c})
            else:
                highlights.append({"kind": "metadata_change", "field": field, **c})
        for ref in d["evidence_added"]:
            highlights.append({"kind": "evidence_added", "ref": ref})
        for ref in d["evidence_removed"]:
            highlights.append({"kind": "evidence_removed", "ref": ref})

        d.update(
            {
                "finding_uuid": finding_uuid,
                "from_version": from_version,
                "to_version": to_version,
                # Actor of the edit that produced to_version (the transition
                # at seq == to_version - 1 in the 0-indexed history).
                "changed_by": (
                    t.actor_uuid
                    if (t := _history_entry(self.store, finding_uuid, to_version))
                    else None
                ),
                "highlights": highlights,
            }
        )
        return d

    def changes_since(self, finding_uuid: str, since_version: int) -> dict[str, Any]:
        """Acceptance-shaped summary: everything from v(N+1)..head in one call."""
        head = self.head_version(finding_uuid)
        d = self.diff(finding_uuid, since_version, head)
        actors: list[str] = []
        for entry in self.versions(finding_uuid)[since_version:]:
            if entry["actor_uuid"] not in actors:
                actors.append(entry["actor_uuid"])
        return {"diff": d, "actors": actors, "from_version": since_version, "to_version": head}

    def conflicts(self, finding_uuid: str) -> list[dict[str, Any]]:
        """§18 conflicting-edit evidence for this finding (rejected writes)."""
        return [
            {
                "actor_uuid": r.actor_uuid,
                "expected_version": r.expected_version,
                "actual_version": r.actual_version,
                "reason_attempted": r.reason_attempted,
                "timestamp": r.timestamp,
            }
            for r in self._cc.rejected_writes(finding_uuid)
        ]


def render_side_by_side(d: dict[str, Any]) -> str:
    """Plain-text side-by-side-style rendering for the CLI.

    ``finding inspect --diff v3 v5`` prints this: version header, actor,
    then per-field old/new pairs plus semantic highlight markers.
    """
    lines = [
        f"{d.get('finding_uuid', '?')}  v{d['from_version']} -> v{d['to_version']}"
        f"  (by {d.get('changed_by') or 'unknown'})"
    ]
    if d["changed"]:
        width = max(len(c["field"]) for c in d["changed"]) + 2
        for c in d["changed"]:
            marker = ""
            for h in d.get("highlights", []):
                if h.get("field") == c["field"] and h["kind"] != "metadata_change":
                    marker = f" [{h['kind']}]"
                    break
            lines.append(f"  {c['field'] + ':':<{width}}{marker}")
            lines.append(f"    v{d['from_version']}: {c['old']!r}")
            lines.append(f"    v{d['to_version']}: {c['new']!r}")
    else:
        lines.append("  no scalar fields changed")
    for h in d.get("highlights", []):
        if h["kind"].startswith("evidence"):
            lines.append(f"  evidence {h['kind'].split('_', 1)[1]}: {h['ref']}")
    if d.get("has_unlinked_drift"):
        lines.append("  ⚠ unlinked claim drift present (PLAN §10.6)")
    return "\n".join(lines)


def _history_entry(store: RecordStore, finding_uuid: str, version: int):
    hist = store.history(finding_uuid)
    idx = version - 1
    if 0 <= idx < len(hist):
        return hist[idx]
    return None
