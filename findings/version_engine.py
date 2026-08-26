"""Finding version diff engine for the workspace (PLAN §13 view 3 — #291).

``findings/version_diff.py`` (#119) diffs two in-memory ``Finding``
records. This module is the workspace-facing engine the issue asks for:

- **Version lookup from history** (:func:`load_versions`): the
  ``RecordStore`` keeps every prior version (append-only). Versions are
  addressed v1..vN in transition order, so a reviewer can ask for any two.
- **Workspace diff** (:func:`workspace_diff`): wraps
  :func:`findings.version_diff.diff_findings` and adds the semantic
  layers the issue requires beyond prose diffs:
    * claim-field changes flagged explicitly (CLAIM_FIELDS),
    * severity change detection (from the severity rubric's append-only
      history, issue #266/#239),
    * evidence link additions/removals surfaced as first-class entries.
- **Unified text rendering** (:func:`render_unified`): a compact
  ``field: old -> new`` view suitable for CLI
  (``finding inspect --diff v3 v5``) and the UI side-by-side pane.
- **Conflicting concurrent edits** (:func:`detect_conflict`, §18): two
  branches derived from the same base version that both changed the same
  field is a conflict; the caller surfaces it instead of last-write-wins.

Read-only pure functions over stored records — safe to call from API/UI.
"""

from __future__ import annotations

from typing import Any

from findings.version_diff import CLAIM_FIELDS, METADATA_FIELDS, diff_findings


class VersionError(ValueError):
    """Unknown version number or malformed history."""


def load_versions(history_entries: list[Any]) -> list[Any]:
    """Ordered finding snapshots v1..vN from a RecordStore history.

    Each history entry carries the post-transition finding record; v1 is
    the initial submission.
    """
    if not history_entries:
        raise VersionError("no versions recorded for finding")
    return [getattr(e, "finding", None) or e["finding"] for e in history_entries]


def severity_changes(new: Any) -> list[dict[str, Any]]:
    """Severity history entries recorded on the newer version, if any.

    Reads the rubric's ``SeverityHistory`` (issue #266/#239); entries are
    rendered as dicts so the workspace diff stays JSON-serializable.
    """
    hist = getattr(new, "severity_history", None)
    if hist is None:
        return []
    return [
        {
            "from_severity": str(e.from_level.value),
            "to_severity": str(e.to_level.value),
            "rationale": e.rationale,
            "stage": e.stage,
        }
        for e in getattr(hist, "entries", [])
    ]


def workspace_diff(old: Any, new: Any) -> dict[str, Any]:
    """Structured diff with semantic flags for the finding workspace."""
    base = diff_findings(old, new)
    # diff_findings (#119) scopes to claim fields; metadata deltas
    # (state, owner_agent_uuid, redaction_status) are computed here so the
    # workspace view shows every change, marked as non-claim (".").
    seen_fields = {c["field"] for c in base["changed"]}
    metadata_changes = []
    for f in METADATA_FIELDS:
        if f in seen_fields:
            continue
        ov, nv = getattr(old, f, None), getattr(new, f, None)
        if ov != nv:
            metadata_changes.append({"field": f, "old": ov, "new": nv})
    changed = base["changed"] + metadata_changes
    claim_changed = [c for c in changed if c["field"] in CLAIM_FIELDS]
    return {
        **base,
        "changed": changed,
        "claim_changes": claim_changed,
        "metadata_changes": metadata_changes,
        "severity_changes": severity_changes(new),
        "summary": {
            "fields_changed": len(changed),
            "claims_changed": len(claim_changed),
            "evidence_added": len(base["evidence_added"]),
            "evidence_removed": len(base["evidence_removed"]),
            "unlinked_drift": base["has_unlinked_drift"],
        },
    }


def render_unified(d: dict[str, Any]) -> str:
    """Compact unified text view: 'field: old -> new' lines + deltas."""
    out = []
    for c in d["changed"]:
        marker = "!" if c["field"] in CLAIM_FIELDS else "."
        out.append(f"{marker} {c['field']}: {c['old']!r} -> {c['new']!r}")
    for r in d["evidence_added"]:
        out.append(f"+ evidence {r}")
    for r in d["evidence_removed"]:
        out.append(f"- evidence {r}")
    for s in d.get("severity_changes", []):
        out.append(
            f"! severity: {s.get('from_severity')} -> {s.get('to_severity')}"
            f" ({s.get('rationale', '')})"
        )
    if not out:
        out.append("(no changes)")
    return "\n".join(out)


def detect_conflict(base: Any, ours: Any, theirs: Any) -> dict[str, Any]:
    """Detect conflicting concurrent edits from a common ancestor (§18).

    Both branches changed the same scalar claim/metadata field ⇒ conflict;
    disjoint field sets merge cleanly. Returns a machine-readable report.
    """
    ours_d = diff_findings(base, ours)
    theirs_d = diff_findings(base, theirs)
    ours_fields = {c["field"] for c in ours_d["changed"]}
    theirs_fields = {c["field"] for c in theirs_d["changed"]}
    conflicts = sorted(ours_fields & theirs_fields)
    return {
        "conflicts": conflicts,
        "has_conflict": bool(conflicts),
        "cleanly_mergeable": not conflicts,
        "detail": [
            {
                "field": f,
                "base": getattr(base, f, None),
                "ours": getattr(ours, f, None),
                "theirs": getattr(theirs, f, None),
            }
            for f in conflicts
        ],
    }
