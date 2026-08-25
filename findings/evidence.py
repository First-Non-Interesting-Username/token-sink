"""Immutable evidence store + claim-to-evidence traceability (issue #84).

Implements the evidence substrate behind PLAN §2.3 / §9 / §10.6 / §21:

- **Write-once records.** An evidence item can be created but never mutated
  or deleted through this API. Raw observation bytes live in the content-
  addressed ArtifactStore (identity = SHA-256, see storage/artifacts.py);
  interpretation lives *alongside* the record, never merged into the raw
  payload (§2.3 "store raw observations separately from agent
  interpretations").
- **Provenance per §9.** Every item records source URL, tool/extraction
  method, retrieval timestamp, and the capturing agent/task UUID.
- **Traceability API.** ``resolve_claims`` maps a report's claim lists to
  their cited evidence chain, and ``check_traceability`` mechanically
  verifies the §21 acceptance rule: every claim is traceable to existing
  evidence or explicitly labeled as analysis.

Deletion semantics: findings may be tombstoned (#48) but evidence referenced
by audit history must survive — this store exposes no delete at all, and
``retain_for_audit`` marks items that a tombstone sweep must skip.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Claim classes from schemas/evidence_item.schema.json — the §9 requirement
# that raw facts are never conflated with agent inference.
CLAIM_TYPES = frozenset(
    {"source_fact", "agent_inference", "unverified_claim", "requires_active_confirmation"}
)

# Labels accepted by check_traceability for claims with no evidence: they
# must say outright that they are analysis/opinion, not observed fact.
ANALYSIS_LABELS = ("analysis", "inference", "opinion")


class EvidenceExistsError(RuntimeError):
    """An evidence UUID was reused. UUIDs are identity; reuse is a bug."""


class EvidenceNotFoundError(KeyError):
    """A claim cites an evidence UUID this store has never seen."""


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class EvidenceItem:
    """One immutable evidence record (mirrors schemas/evidence_item.schema.json v1).

    ``raw_digest`` points into the ArtifactStore and is the identity of the
    raw bytes; ``content_hash`` covers the record itself so any post-hoc
    mutation of a persisted item is detectable.
    """

    evidence_uuid: str
    campaign_uuid: str
    kind: str  # observation | http_exchange | file_diff | log_excerpt | ...
    claim_type: str  # one of CLAIM_TYPES
    artifact_ref: str
    raw_digest: str  # sha256 of the raw observation bytes
    provenance_agent_uuid: str
    task_uuid: str | None = None
    source_url: str | None = None
    source_tool: str | None = None  # e.g. ddgs, curl, jina
    extraction_method: str | None = None
    retrieved_at: str | None = None  # when the source was fetched
    created_at: str = field(default_factory=_utcnow_iso)
    interpretation: str | None = None  # agent reading, kept OUT of raw bytes
    # Captured at creation time. Stored, never recomputed on demand — a
    # recomputed hash would "verify" a tampered record against itself.
    recorded_hash: str = ""

    def __post_init__(self) -> None:
        if self.claim_type not in CLAIM_TYPES:
            raise ValueError(
                f"claim_type must be one of {sorted(CLAIM_TYPES)}, got {self.claim_type!r}"
            )
        if len(self.raw_digest) != 64:
            raise ValueError("raw_digest must be a full sha256 hex digest")
        if not self.provenance_agent_uuid:
            raise ValueError("provenance requires the capturing agent's UUID")
        if not self.recorded_hash:
            # First freeze of the record's identity; later field changes do
            # NOT update it, which is exactly what verify_integrity detects.
            object.__setattr__(self, "recorded_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "evidence_uuid": self.evidence_uuid,
            "campaign_uuid": self.campaign_uuid,
            "kind": self.kind,
            "claim_type": self.claim_type,
            "artifact_ref": self.artifact_ref,
            "raw_digest": self.raw_digest,
            "provenance_agent_uuid": self.provenance_agent_uuid,
            "task_uuid": self.task_uuid,
            "source_url": self.source_url,
            "source_tool": self.source_tool,
            "extraction_method": self.extraction_method,
            "retrieved_at": self.retrieved_at,
            "created_at": self.created_at,
            "interpretation": self.interpretation,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = {
            "schema_version": 1,
            "record_type": "evidence_item",
            "evidence_uuid": self.evidence_uuid,
            "campaign_uuid": self.campaign_uuid,
            "kind": self.kind,
            "claim_type": self.claim_type,
            "artifact_ref": self.artifact_ref,
            "content_hash": self.recorded_hash,
            "raw_digest": self.raw_digest,
            "provenance": {"agent_uuid": self.provenance_agent_uuid},
            "created_at": self.created_at,
        }
        for k in (
            "task_uuid",
            "source_url",
            "source_tool",
            "extraction_method",
            "retrieved_at",
            "interpretation",
        ):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        if self.task_uuid:
            d["provenance"]["task_uuid"] = self.task_uuid
        return d


@dataclass(frozen=True)
class TraceabilityReport:
    """Result of the mechanical §21 acceptance check on a set of claims."""

    traceable: tuple[str, ...]  # claims fully backed by known evidence
    labeled_analysis: tuple[str, ...]  # explicitly labeled analysis/inference
    violations: tuple[str, ...]  # neither traceable nor labeled → FAIL


class EvidenceStore:
    """In-memory reference implementation of the write-once evidence store.

    Deliberately backend-agnostic like observability.event_store: the SQLite
    backend (#53) should implement the same operations inside transactions.
    There is no update() and no delete() — that IS the feature (§2.3).
    """

    def __init__(self):
        self._items: dict[str, EvidenceItem] = {}
        # audit-pinned items must survive finding tombstoning sweeps
        self._audit_pinned: set[str] = set()

    def add(self, item: EvidenceItem) -> EvidenceItem:
        """Register an item. Write-once: re-adding any UUID raises."""
        if item.evidence_uuid in self._items:
            raise EvidenceExistsError(
                f"evidence {item.evidence_uuid} already exists; evidence is write-once"
            )
        self._items[item.evidence_uuid] = item
        return item

    def get(self, evidence_uuid: str) -> EvidenceItem:
        try:
            return self._items[evidence_uuid]
        except KeyError:
            raise EvidenceNotFoundError(evidence_uuid) from None

    def exists(self, evidence_uuid: str) -> bool:
        return evidence_uuid in self._items

    def for_campaign(self, campaign_uuid: str) -> list[EvidenceItem]:
        return [i for i in self._items.values() if i.campaign_uuid == campaign_uuid]

    def verify_integrity(self) -> list[str]:
        """Compare each record's frozen creation hash against a fresh compute.

        A non-empty result means the record's fields were mutated after
        creation (or the persisted hash was altered) — tamper detection per
        §13/§15 audit expectations.
        """
        return [u for u, i in self._items.items() if i._compute_hash() != i.recorded_hash]

    def retain_for_audit(self, evidence_uuids: list[str]) -> None:
        """Pin evidence so finding deletion/tombstoning cannot remove it."""
        for u in evidence_uuids:
            self.get(u)  # fail loudly on unknown IDs rather than silently no-op
            self._audit_pinned.add(u)

    @property
    def audit_pinned(self) -> frozenset[str]:
        return frozenset(self._audit_pinned)

    def deletable_after_tombstone(self, candidate_uuids: list[str]) -> set[str]:
        """What a tombstone sweep may actually remove.

        Evidence referenced by audit history (pinned here) survives even when
        its finding is deleted — issue #84 requirement.
        """
        return {u for u in candidate_uuids if u not in self._audit_pinned}

    # ------------------------------------------------------------------
    # Claim → evidence traceability (§10.6 final review, §21 acceptance)
    # ------------------------------------------------------------------

    def resolve_claim(self, evidence_uuids: list[str]) -> list[EvidenceItem]:
        """Resolve one claim's citation list to its evidence chain.

        Raises EvidenceNotFoundError listing ALL missing IDs — partial
        resolution would let an unbacked claim slip through review.
        """
        missing = [u for u in evidence_uuids if u not in self._items]
        if missing:
            raise EvidenceNotFoundError(", ".join(missing))
        return [self._items[u] for u in evidence_uuids]

    def check_traceability(
        self,
        claims: list[dict[str, Any]],
    ) -> TraceabilityReport:
        """Mechanically verify §21: every claim traceable or labeled as analysis.

        Each claim dict needs either:
          - ``evidence_uuids``: non-empty list of known evidence IDs → traceable
          - ``label`` containing one of ANALYSIS_LABELS → explicitly analysis
        Anything else is a violation and blocks final review.
        """
        traceable: list[str] = []
        labeled: list[str] = []
        violations: list[str] = []

        for i, claim in enumerate(claims):
            text = str(claim.get("claim", f"<claim {i}>"))
            uuids = claim.get("evidence_uuids") or []
            label = str(claim.get("label", "")).lower()

            if uuids:
                missing = [u for u in uuids if u not in self._items]
                if missing:
                    violations.append(f"{text}: cites unknown evidence {', '.join(missing)}")
                else:
                    traceable.append(text)
                continue

            if any(lbl in label for lbl in ANALYSIS_LABELS):
                labeled.append(text)
                continue

            violations.append(
                f"{text}: no evidence cited and not labeled as {'/'.join(ANALYSIS_LABELS)}"
            )

        return TraceabilityReport(
            traceable=tuple(traceable),
            labeled_analysis=tuple(labeled),
            violations=tuple(violations),
        )
