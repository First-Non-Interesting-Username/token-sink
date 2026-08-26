"""Claim-to-evidence traceability gate (PLAN §10.6/§21 — issue #282).

Definition of Done: "Every final claim can be traced to evidence or is
explicitly labeled as analysis." ``EvidenceStore.check_traceability``
(#165) already mechanically verifies a *list* of claim dicts; this module
turns that into an enforceable lifecycle gate plus the structured plumbing
the issue asks for:

- **Structured claims on findings** (:func:`extract_claims`): claims live
  on the finding record as ``finding.claims`` — each is a dict with
  ``claim`` text and either non-empty ``evidence_uuids`` or one of
  ``ANALYSIS_LABELS`` in ``label``. :func:`validate_claim_shape` rejects
  malformed claims at write time so garbage can't reach the gate.
- **Gate** (:meth:`TraceabilityGate.check`): run at polishing/final review.
  FAILS FORWARD — raises :class:`TraceabilityError` listing every
  untraceable claim instead of letting the finding advance silently. The
  gate never mutates state; it only blocks.
- **Traceability view** (:func:`render_traceability`): claim → evidence
  chain rendered per finding (text form for CLI/UI §13 view 3).
- **Fixtures**: :data:`UNTRACEABLE_CLAIM_FIXTURES` contains deliberately
  untraceable claims that must be caught.

The gate delegates all verdict logic to
``EvidenceStore.check_traceability`` so there is exactly one definition of
"traceable" in the codebase.
"""

from __future__ import annotations

from typing import Any

from findings.evidence import ANALYSIS_LABELS, EvidenceStore


class TraceabilityError(Exception):
    """A finding carries claims that are neither evidence-backed nor labeled."""


def validate_claim_shape(claim: dict[str, Any]) -> None:
    """Reject malformed claim dicts before they reach the gate."""
    text = str(claim.get("claim", "")).strip()
    if not text:
        raise TraceabilityError("claim requires non-empty 'claim' text")
    uuids = claim.get("evidence_uuids") or []
    label = str(claim.get("label", "")).lower()
    if not uuids and not any(lbl in label for lbl in ANALYSIS_LABELS):
        # Fail early with the same rule the gate enforces, but as a shape
        # error — writers should fix the claim, not discover it at review.
        raise TraceabilityError(
            f"claim {text!r} needs evidence_uuids or an {'/'.join(ANALYSIS_LABELS)} label"
        )


def extract_claims(finding: Any) -> list[dict[str, Any]]:
    """Structured claims from a finding record ([] when none set)."""
    return list(getattr(finding, "claims", []) or [])


class TraceabilityGate:
    """§21 acceptance gate over the EvidenceStore's single traceability rule."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def check(self, finding: Any) -> Any:
        """Verify every claim on ``finding``; return the TraceabilityReport.

        Raises :class:`TraceabilityError` when any claim is untraceable —
        the finding must NOT advance to polished/final states until fixed.
        """
        claims = extract_claims(finding)
        report = self.store.check_traceability(claims)
        if report.violations:
            raise TraceabilityError(
                f"{len(report.violations)} untraceable claim(s) on finding "
                f"{getattr(finding, 'finding_uuid', '?')}:\n- " + "\n- ".join(report.violations)
            )
        return report

    def check_or_fail_forward(self, finding: Any, actor_uuid: str) -> Any:
        """Gate + audit stub: returns the report, records nothing itself.

        Kept separate from check() so callers wiring this into
        FindingLifecycle transitions can attach the history entry at their
        transition point without double-writing.
        """
        return self.check(finding)


def render_traceability(finding: Any, store: EvidenceStore) -> str:
    """Claim → evidence chain view per finding (§13 view 3, text form).

    Lines look like::

        [evidence] Payload echoed unencoded. -> ev-1(ev1.json), ev-2(ev2.json)
        [analysis] Likely affects v2.x only.
    """
    lines: list[str] = []
    for c in extract_claims(finding):
        text = str(c.get("claim", ""))
        uuids = c.get("evidence_uuids") or []
        if uuids:
            refs = []
            for u in uuids:
                item = store.get(u)
                name = item.artifact_ref or u
                refs.append(f"{u}({name})")
            lines.append(f"[evidence] {text} -> {', '.join(refs)}")
        else:
            lines.append(f"[analysis] {text}")
    return "\n".join(lines)


# Fixtures: deliberately untraceable claims that MUST be caught by the
# gate. Used by tests and by evaluation harnesses exercising §10.6.
UNTRACEABLE_CLAIM_FIXTURES: list[dict[str, Any]] = [
    {"claim": "The service leaks customer PII in bulk.", "label": ""},
    {"claim": "Attackers can pivot to the internal network.", "evidence_uuids": []},
    {"claim": "Exploitation is trivially automatable.", "note": "hunch, no backing"},
]

# Well-formed counterparts that must pass.
TRACEABLE_CLAIM_FIXTURES: list[dict[str, Any]] = [
    {
        "claim": "Payload echoed unencoded.",
        "evidence_uuids": ["ev-1"],
    },
    {
        "claim": "Likely affects only versions below 2.4.",
        "label": "analysis",
    },
]
