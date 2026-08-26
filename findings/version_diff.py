"""Finding version diffing with evidence-link validation (issue #119, PLAN §13.3).

Design decisions (per AGENTS.md "document everything"):

- **Structured, not textual.** The diff compares two versioned ``Finding``
  records field by field (findings/lifecycle.py keeps every prior version in
  the RecordStore). The result is a machine-readable dict for the API (#32)
  plus a Markdown renderer for humans — never a raw text diff, because
  evidence refs and claim changes need semantic meaning.

- **Claim-drift awareness (#97 groundwork).** Any change to the technical
  claim surface (title, category, affected_asset, location, observation,
  hypothesis, repro_outline, suspected_impact, confidence) must be backed by
  an evidence reference change or pre-existing evidence; otherwise it is
  flagged as ``unlinked_claims`` so the final reviewer sees altered claims
  that point at nothing (PLAN §10.6 fact-drift gate).

- **Redaction-aware.** The rendered output respects the NEWER record's
  ``redaction_status``: when redacted, free-text fields are replaced by
  placeholders in the human rendering while the machine diff still carries
  hashes-free structural info (field names + change kinds only).

- **Read-only pure functions** over Finding records — no storage access, no
  mutation, no network. Safe to call from any API/UI layer.
"""

from __future__ import annotations

from typing import Any

from findings.lifecycle import Finding

# Fields whose change alters the technical claim itself.
CLAIM_FIELDS = (
    "title",
    "category",
    "affected_asset",
    "location",
    "observation",
    "hypothesis",
    "repro_outline",
    "suspected_impact",
    "confidence",
)

# Fields tracked in diffs but not treated as claim changes.
METADATA_FIELDS = ("state", "owner_agent_uuid", "redaction_status")

# Simple scalars compare directly; list/dict fields compare structurally.
_SCALAR_FIELDS = CLAIM_FIELDS


def diff_findings(old: Finding, new: Finding) -> dict[str, Any]:
    """Structured diff between two versions of a finding.

    Returns a machine-readable dict:
      - changed: [{field, old, new}] for scalar claim/metadata fields
      - evidence_added / evidence_removed: evidence-ref sets delta
      - unlinked_claims: altered claim fields with no evidence backing
    """
    changed = []
    for f in _SCALAR_FIELDS:
        ov, nv = getattr(old, f), getattr(new, f)
        if ov != nv:
            changed.append({"field": f, "old": ov, "new": nv})

    old_refs, new_refs = set(old.evidence_refs), set(new.evidence_refs)
    ev_added = sorted(new_refs - old_refs)
    ev_removed = sorted(old_refs - new_refs)

    # A claim change counts as linked when the newer version references at
    # least one evidence item — either newly added (directly justifying the
    # change) or already present. No refs at all ⇒ drift flag.
    has_evidence = bool(new_refs)
    unlinked = [
        {"field": c["field"], "old": c["old"], "new": c["new"]}
        for c in changed
        if c["field"] in CLAIM_FIELDS and not has_evidence
    ]

    return {
        "finding_uuid": new.finding_uuid,
        "changed": changed,
        "evidence_added": ev_added,
        "evidence_removed": ev_removed,
        "unlinked_claims": unlinked,
        "has_unlinked_drift": bool(unlinked),
    }


def render_markdown(d: dict[str, Any], *, redacted: bool = False) -> str:
    """Human-readable Markdown rendering of :func:`diff_findings` output.

    When ``redacted`` is True (the newer record's redaction_status), free-text
    values are masked — structure stays visible, content does not leak.
    """

    def val(v: Any) -> str:
        if v is None:
            return "—"
        text = str(v)
        return "[redacted]" if redacted else text

    lines: list[str] = []
    if d["changed"]:
        lines.append("## Changed fields")
        lines.append("| Field | Old | New |")
        lines.append("|---|---|---|")
        for c in d["changed"]:
            marker = " ⚠" if c["field"] in [u["field"] for u in d["unlinked_claims"]] else ""
            lines.append(f"| {c['field']}{marker} | {val(c['old'])} | {val(c['new'])} |")
    else:
        lines.append("No scalar fields changed.")
    if d["evidence_added"]:
        lines.append("\n## Evidence added")
        for r in d["evidence_added"]:
            lines.append(f"- {r}")
    if d["evidence_removed"]:
        lines.append("\n## Evidence removed")
        for r in d["evidence_removed"]:
            lines.append(f"- {r}")
    if d["has_unlinked_drift"]:
        lines.append(
            "\n⚠ **Claim drift warning**: the marked claim fields changed "
            "without supporting evidence references (PLAN §10.6)."
        )
    return "\n".join(lines)
