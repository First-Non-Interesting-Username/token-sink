"""Claim-level fact-drift gate (issue #97, PLAN §10.6 / §21).

Design decisions (per AGENTS.md "document everything"):

- **Atomic claims.** A finding's claim surface is decomposed into one atomic
  claim per technical field (title, category, affected_asset, location,
  observation sentence, repro step, suspected_impact, numeric values found in
  any field). Atomicity matters because the gate must name *which* fact moved
  ("CVSS 7.5 -> 9.8"), not just "the report changed".

- **Diff at claim granularity, not text granularity.** The polished report is
  compared against the validated finding version claim by claim. A polished
  report may *rephrase* a claim freely — paraphrase is allowed as long as the
  atomic facts (numbers, identifiers, severity words) survive. What is never
  allowed silently:
    - **numeric drift**: any number present in the validated claim that is
      missing or altered in the polished claim (CVSS 7.5 -> 9.8, port counts,
      CVE ids, versions);
    - **dropped claims**: every validated claim must appear in the polished
      report; polishing may rephrase, not remove facts;
    - **unlinked new claims**: a polished-report claim that has no counterpart
      in the validated finding is new information and must carry an evidence
      reference (``evidence_uuids``) or be explicitly labeled analysis.

- **Hard gate semantics.** :func:`evaluate_gate` returns a pass/fail verdict.
  A failing verdict blocks advancement to ``vulnerabilities/<finding-id>/``
  until the diff is resolved (fix the report or obtain human sign-off via
  ``signed_off=True``, which is recorded in the stored diff for audit).

- **Pure functions + serializable results.** No I/O, no storage access; the
  returned dict can be stored next to the report version for audit (#89).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Words that express severity/impact strength; changing them changes the claim.
_SEVERITY_WORDS = (
    "critical",
    "high",
    "medium",
    "low",
    "severe",
    "moderate",
    "minor",
    "trivial",
)

_NUM_RE = re.compile(r"\d+(?:\.\d+)?")

# Spelled-out small numbers are treated as numbers too ("three extra rows"
# is the same fact as "3 extra rows"); polishing must not alter the count.
_WORD_NUMS = {
    w: str(i)
    for i, w in enumerate(
        ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"],
    )
}
_WORDNUM_RE = re.compile(rf"\b({'|'.join(_WORD_NUMS)})\b")


def _numbers(text: str) -> list[str]:
    found = _NUM_RE.findall(text)
    found += [_WORD_NUMS[w] for w in _WORDNUM_RE.findall(text.lower())]
    return found


def _severity_words(text: str) -> set[str]:
    t = text.lower()
    return {w for w in _SEVERITY_WORDS if re.search(rf"\b{w}\b", t)}


def extract_claims(finding: dict[str, Any]) -> dict[str, str]:
    """Decompose a finding record into atomic claims keyed by stable IDs.

    The keys are ``<field>``, ``<field>#<n>`` (for per-sentence/per-step
    decomposition of long fields) and ``num:<value>@<field>#<n>`` for numeric
    facts extracted from free text so they can be tracked individually.
    """
    claims: dict[str, str] = {}
    for f in ("title", "category", "affected_asset", "location"):
        v = str(finding.get(f, "")).strip()
        if v:
            claims[f] = v
    for f in ("observation", "hypothesis", "suspected_impact"):
        v = str(finding.get(f, "")).strip()
        if not v:
            continue
        parts = [s.strip() for s in re.split(r"(?<=[.!?\n])\s+", v) if s.strip()]
        if len(parts) <= 1:
            claims[f] = v
        else:
            for i, p in enumerate(parts):
                claims[f"{f}#{i}"] = p
    steps = finding.get("repro_outline") or []
    for i, s in enumerate(steps):
        claims[f"repro_outline#{i}"] = str(s).strip()
    return claims


@dataclass
class GateVerdict:
    """Outcome of the fact-drift gate for one polished report."""

    passed: bool
    violations: list[str] = field(default_factory=list)
    # machine-readable per-category findings for the final-review agent
    modified_claims: list[dict[str, Any]] = field(default_factory=list)
    dropped_claims: list[str] = field(default_factory=list)
    added_claims: list[dict[str, Any]] = field(default_factory=list)
    allowed_paraphrases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "record_type": "fact_drift_verdict",
            "passed": self.passed,
            "violations": list(self.violations),
            "modified_claims": list(self.modified_claims),
            "dropped_claims": list(self.dropped_claims),
            "added_claims": list(self.added_claims),
            "allowed_paraphrases": list(self.allowed_paraphrases),
        }


def _tokens(text: str) -> set[str]:
    """Lowercase alphanumeric fragments (splits sql_injection, /api/users)."""
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3}


def _token_hits(vtext: str, ptokens: set[str]) -> int:
    """Count validated tokens present in polished tokens (prefix-tolerant)."""
    hits = 0
    for t in _tokens(vtext):
        if t in ptokens or any(p.startswith(t[:4]) and p[:1] == t[:1] for p in ptokens):
            hits += 1
    return hits


def _is_match(validated_text: str, polished_claim: str) -> bool:
    """A polished claim still carries a validated claim when its key facts do.

    Key facts = numbers and severity words. If the validated claim has none,
    fall back to token-overlap >= half of the validated tokens (paraphrase
    tolerance); otherwise require all numbers/severity words to survive.
    """
    vn, pn = _numbers(validated_text), _numbers(polished_claim)
    vs, ps = _severity_words(validated_text), _severity_words(polished_claim)
    pt = _tokens(polished_claim)
    if vn or vs:
        if not all(n in pn for n in vn):
            return False
        if not vs.issubset(ps):
            return False
        return _token_hits(validated_text, pt) >= 1
    vt_len = len(_tokens(validated_text))
    hits = _token_hits(validated_text, pt)
    return vt_len > 0 and hits >= max(1, vt_len // 2)


def evaluate_gate(
    validated_finding: dict[str, Any],
    polished_report: dict[str, Any],
    *,
    evidence_store_lookup=None,
    signed_off: bool = False,
) -> GateVerdict:
    """Compare a polished report against its validated source at claim level.

    ``polished_report`` maps section names to content; recognized shapes:

    - ``{"claims": [{"claim": "...", "evidence_uuids": [...], "label": "..."}]}`
      — explicit claim list from the polishing agent;
    - ``{"report": "<markdown/text>", ...}`` — free text, decomposed with
      :func:`extract_claims`-style sentence splitting.

    ``evidence_store_lookup(uuids) -> list[str]`` may verify that cited
    evidence UUIDs actually exist; unknown UUIDs count as unlinked.

    ``signed_off=True`` records human sign-off: violations are reported but
    the verdict passes, and the sign-off travels inside the stored diff.
    """
    v = GateVerdict(passed=True)
    validated_claims = extract_claims(validated_finding)

    polished_claims: dict[str, str] = {}
    evidence_by_claim: dict[str, list[str]] = {}
    labels_by_claim: dict[str, str] = {}
    pr = polished_report.get("claims")
    if isinstance(pr, list):
        for i, c in enumerate(pr):
            text = str(c.get("claim", "")).strip()
            if not text:
                continue
            key = f"polished#{i}"
            polished_claims[key] = text
            evidence_by_claim[key] = list(c.get("evidence_uuids") or [])
            labels_by_claim[key] = str(c.get("label", ""))
    else:
        text = str(polished_report.get("report", "")).strip()
        parts = [s.strip() for s in re.split(r"(?<=[.!?\n])\s+", text) if s.strip()]
        for i, p in enumerate(parts):
            polished_claims[f"polished#{i}"] = p

    consumed: set[str] = set()
    # A polished claim may carry several atomic facts at once (e.g. the whole
    # observation paragraph); allow it to satisfy multiple validated claims.
    multi: dict[str, list[str]] = {}

    def _find_counterpart(vtext: str) -> str | None:
        for pk, ptext in polished_claims.items():
            if _is_match(vtext, ptext):
                return pk
        return None

    # 1. every validated claim must survive (rephrase ok, drop not)
    for vk, vtext in validated_claims.items():
        pk = _find_counterpart(vtext)
        if pk is None:
            v.dropped_claims.append(vk)
            v.violations.append(f"dropped claim {vk}: polishing may rephrase but not remove facts")
        else:
            multi.setdefault(pk, []).append(vk)
            if polished_claims[pk] != vtext:
                v.allowed_paraphrases.append(vk)

    # 2. new claims need evidence or an analysis label. A claim that already
    # carried at least one validated fact is not "new information".
    for pk, ptext in sorted(polished_claims.items()):
        if pk in consumed or pk in multi:
            continue
        uuids = evidence_by_claim.get(pk, [])
        known = uuids
        if uuids and evidence_store_lookup is not None:
            known = evidence_store_lookup(uuids)
        label = labels_by_claim.get(pk, "").lower()
        if known:
            v.allowed_paraphrases.append(pk)
            continue
        if any(lb in label for lb in ("analysis", "inference", "opinion")):
            continue
        v.added_claims.append({"claim_key": pk, "text": ptext})
        v.violations.append(
            f"unlinked added claim {pk}: no evidence reference and not labeled analysis"
        )

    v.passed = not v.violations
    if signed_off and not v.passed:
        v.passed = True
        v.violations = [f"{m} [human-signed-off]" for m in v.violations]
    return v


def store_diff_for_audit(verdict: GateVerdict, finding_uuid: str) -> dict[str, Any]:
    """Serialize the verdict for persistence beside the report version (#89)."""
    d = verdict.to_dict()
    d["finding_uuid"] = finding_uuid
    return d
