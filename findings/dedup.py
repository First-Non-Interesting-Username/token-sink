"""Duplicate-finding detection and provenance-preserving merge (issue #139, PLAN §10).

Parallel routers and agents independently surface the same vulnerability.
This module detects likely duplicates at finding-intake time and supports an
explicit, auditable merge into one canonical finding.

Design rules:

- Detection is conservative. Only an exact fingerprint match auto-flags as a
  duplicate; heuristic similarity merely proposes a candidate pair for
  adjudication. Look-alikes below the threshold are never merged.
- Candidates are LINKED (via `duplicate_of` links), never silently dropped.
- A merge produces ONE canonical finding; both source records remain with an
  append-only merge decision recorded on each, preserving full provenance
  from both sides (evidence UUIDs, reviews, agents).
- No network, no dependencies — pure functions over finding dicts so it can
  run at intake in any storage backend.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# Heuristic threshold: token-Jaccard similarity at or above this flags a
# candidate pair for human/agent adjudication. Deliberately high — a false
# "merge" destroys information, while a missed dedup only costs review time.
SIMILARITY_THRESHOLD = 0.72

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
# Words too generic to help distinguish findings.
_STOPWORDS = frozenset(
    """the and for with that this from into when where what which allow allows
    attacker user users via using may can could would should might also been
    being have has had its their there these those then than thus because
    parameter parameters request response server client page endpoint input
    value values field fields data without any all not but are was were will""".split()
)


@dataclass(frozen=True)
class DuplicateLink:
    """A proposed/confirmed duplicate relationship between two findings."""

    finding_uuid: str
    duplicate_of_uuid: str
    # exact | similar | confirmed | rejected
    status: str
    score: float = 1.0  # similarity score (exact matches: 1.0)
    reason: str = ""


@dataclass
class MergeResult:
    """Outcome of an adjudicated merge."""

    canonical_finding: dict
    absorbed_uuids: list[str] = field(default_factory=list)
    merge_notes: str = ""


def _normalize_asset(affected_asset: str) -> str:
    """Reduce an asset reference to its comparable core (host or path)."""
    asset = (affected_asset or "").strip().lower()
    asset = re.sub(r"^https?://", "", asset)
    # Strip query strings and fragments: same resource, different params is
    # usually the SAME vulnerability surface for dedup purposes.
    asset = asset.split("?")[0].split("#")[0]
    return asset.rstrip("/")


def _normalize_location(location: str) -> str:
    loc = (location or "").strip().lower()
    # Normalize volatile bits: numeric ids, uuids, long hex tokens.
    loc = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<id>", loc)
    loc = re.sub(r"\b\d+\b", "<n>", loc)
    return loc


def root_cause_fingerprint(finding: dict) -> str:
    """Deterministic fingerprint over target + vuln class + root cause.

    Two findings with identical fingerprints are treated as exact duplicates.
    The fingerprint deliberately EXCLUDES free-text observation wording so
    that two agents describing the same flaw differently still collide.
    """
    parts = [
        _normalize_asset(str(finding.get("affected_asset", ""))),
        # category carries the vuln class when present (e.g. xss-reflected);
        # fall back to title tokens if the producer omitted it.
        str(finding.get("category") or "").strip().lower(),
        _normalize_location(str(finding.get("location", ""))),
        str(finding.get("root_cause") or "").strip().lower(),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
    return digest


def _tokens(finding: dict) -> set[str]:
    text = " ".join(
        str(finding.get(k) or "") for k in ("title", "observation", "root_cause", "hypothesis")
    ).lower()
    return {t for t in _TOKEN_RE.findall(text) if t not in _STOPWORDS}


def similarity(a: dict, b: dict) -> float:
    """Token-Jaccard similarity over descriptive fields of two findings."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def find_duplicates(candidate: dict, existing: list[dict]) -> list[DuplicateLink]:
    """Screen a new candidate against existing findings of the campaign.

    Returns links sorted by confidence: exact fingerprint matches first,
    then heuristic candidates at/above SIMILARITY_THRESHOLD. Never returns
    look-alikes below the threshold — they must NOT be linked or merged.
    """
    links: list[DuplicateLink] = []
    cand_fp = root_cause_fingerprint(candidate)
    for other in existing:
        if other.get("finding_uuid") == candidate.get("finding_uuid"):
            continue
        if root_cause_fingerprint(other) == cand_fp:
            links.append(
                DuplicateLink(
                    finding_uuid=str(candidate["finding_uuid"]),
                    duplicate_of_uuid=str(other["finding_uuid"]),
                    status="exact",
                    score=1.0,
                    reason="identical target+vuln-class+root-cause fingerprint",
                )
            )
            continue
        score = similarity(candidate, other)
        if score >= SIMILARITY_THRESHOLD:
            links.append(
                DuplicateLink(
                    finding_uuid=str(candidate["finding_uuid"]),
                    duplicate_of_uuid=str(other["finding_uuid"]),
                    status="similar",
                    score=round(score, 3),
                    reason="high token similarity — adjudicate manually",
                )
            )
    return sorted(links, key=lambda link: -link.score)


def merge_duplicates(canonical: dict, duplicates: list[dict], adjudicator_id: str) -> MergeResult:
    """Merge duplicate findings INTO the canonical one, preserving provenance.

    Both sides stay intact in history: the canonical record gains the
    duplicates' evidence/review/provenance references plus an append-only
    `merge_history` entry naming every absorbed record and the adjudicator;
    each absorbed record is marked superseded via `merge_history` too (the
    caller transitions it to the tombstone/superseded state per lifecycle).
    """
    if not duplicates:
        raise ValueError("merge_duplicates requires at least one duplicate")

    absorbed: list[str] = []
    notes: list[str] = []
    seen_evidence = set(canonical.get("evidence_uuids") or [])
    seen_reviews = set(canonical.get("review_uuids") or [])

    for dup in duplicates:
        du = dup.get("finding_uuid")
        if not du or du == canonical.get("finding_uuid"):
            continue
        absorbed.append(str(du))
        # Provenance preservation: union evidence + reviews, never overwrite.
        for ev in dup.get("evidence_uuids") or []:
            if ev not in seen_evidence:
                seen_evidence.add(ev)
                canonical.setdefault("evidence_uuids", []).append(ev)
        for rv in dup.get("review_uuids") or []:
            if rv not in seen_reviews:
                seen_reviews.add(rv)
                canonical.setdefault("review_uuids", []).append(rv)
        # Keep richer severity/confidence if the duplicate asserted one and
        # the canonical record lacks it entirely.
        if not canonical.get("category") and dup.get("category"):
            canonical["category"] = dup["category"]
        notes.append(f"absorbed {du} ({dup.get('title', 'untitled')})")

    canonical.setdefault("merge_history", []).append(
        {
            "action": "merge",
            "canonical_uuid": canonical["finding_uuid"],
            "absorbed_uuids": absorbed,
            "adjudicator": adjudicator_id,
            "notes": "; ".join(notes),
            # Append-only convention: entries are added, never edited/removed,
            # matching transition_history semantics in the finding schema.
        }
    )

    for dup in duplicates:
        du = dup.get("finding_uuid")
        if du and du != canonical["finding_uuid"]:
            dup.setdefault("merge_history", []).append(
                {
                    "action": "superseded_by_merge",
                    "canonical_uuid": canonical["finding_uuid"],
                    "adjudicator": adjudicator_id,
                }
            )

    return MergeResult(
        canonical_finding=canonical,
        absorbed_uuids=absorbed,
        merge_notes="; ".join(notes),
    )
