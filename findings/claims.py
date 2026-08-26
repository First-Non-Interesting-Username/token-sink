"""Claim-to-evidence traceability gate (issue #282, PLAN §10.6/§13 view 3).

The definition of done requires that every final claim in a report can be
traced to an evidence artifact or is explicitly labeled as analysis. This
module makes that checkable:

- Structured claim objects: each claim carries its text, a kind
  (``evidence`` | ``analysis``), and — for evidence-backed claims — one or
  more evidence artifact references.
- ``check_traceability()`` is the lifecycle gate used at polishing/final
  review: it FAILS (raises) when any claim has no evidence refs and no
  explicit analysis label. Untraceable claims never pass silently.
- ``render_chain()`` produces the claim → evidence chain view for the UI/CLI
  (PLAN §13 view 3).

Evidence refs are opaque strings matching the finding's ``evidence_refs``
convention; the gate verifies each referenced artifact actually appears in
the finding's evidence set so dangling links are caught too.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CLAIM_KIND_EVIDENCE = "evidence"
CLAIM_KIND_ANALYSIS = "analysis"
CLAIM_KINDS = (CLAIM_KIND_EVIDENCE, CLAIM_KIND_ANALYSIS)


class TraceabilityError(Exception):
    """A claim fails traceability; message names every offending claim."""


@dataclass
class Claim:
    """One structured reportable claim."""

    text: str
    kind: str = CLAIM_KIND_EVIDENCE  # evidence | analysis
    evidence_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in CLAIM_KINDS:
            raise ValueError(f"claim kind must be one of {CLAIM_KINDS}, got {self.kind!r}")

    @property
    def is_traceable(self) -> bool:
        """Analysis claims are traceable by label; others need evidence."""
        return self.kind == CLAIM_KIND_ANALYSIS or bool(self.evidence_refs)


def check_traceability(claims: list[Claim], evidence_registry: set[str] | None = None) -> list[str]:
    """Gate: raise unless EVERY claim traces to evidence or is labeled.

    When ``evidence_registry`` is given (the finding's known evidence ids),
    evidence-backed claims must reference artifacts that exist there — a
    dangling ref is treated as untraceable, not as proof.
    Returns the list of claim indexes that passed (for the render step).
    """
    problems: list[str] = []
    passing: list[str] = []
    registry = evidence_registry if evidence_registry is not None else None
    for i, claim in enumerate(claims):
        where = f"claim[{i}]"
        if not claim.text.strip():
            problems.append(f"{where}: empty claim text")
            continue
        if not claim.is_traceable:
            problems.append(
                f"{where}: untraceable — no evidence refs and not labeled "
                f"'{CLAIM_KIND_ANALYSIS}': {claim.text[:60]!r}"
            )
            continue
        if claim.kind == CLAIM_KIND_EVIDENCE and registry is not None:
            missing = [r for r in claim.evidence_refs if r not in registry]
            if missing:
                problems.append(f"{where}: references unknown evidence artifacts {missing}")
                continue
        passing.append(where)
    if problems:
        raise TraceabilityError(
            "traceability gate failed:\n" + "\n".join(f"  - {p}" for p in problems)
        )
    return passing


def render_chain(claims: list[Claim]) -> str:
    """Claim → evidence chain view (PLAN §13 view 3), plain-text rendering."""
    lines: list[str] = []
    for i, claim in enumerate(claims):
        if claim.kind == CLAIM_KIND_ANALYSIS:
            lines.append(f"[{i}] ANALYSIS: {claim.text}")
        else:
            refs = ", ".join(claim.evidence_refs) if claim.evidence_refs else "(none)"
            lines.append(f"[{i}] CLAIM: {claim.text}\n     evidence: {refs}")
    return "\n".join(lines)
