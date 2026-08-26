"""Provenance records: acquisition metadata, hash integrity, trust decay
(issue #150, PLAN §9, §10.1, §11).

A first-class, versioned record describing HOW a piece of evidence was
obtained and whether it can still be trusted. Used by evidence items,
extracted sources, search results, and PoC outputs.

Design rules:

- Hash integrity: the content hash covers the PRE-REDACTION raw bytes.
  Redaction applies to display copies only, so verification survives it.
  A mismatch against the stored artifact flags the evidence stale/untrusted —
  never silently consumed downstream.
- Trust decay: freshness classes derived from fetch age; consumers must
  distinguish fresh from stale. Re-verification is a POLICY decision; this
  module never refetches (rate limits).
- Queryable: audit views list findings with no provenance or stale-only
  provenance for report reviewers before final review (#97).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

SCHEMA_VERSION = 1

# Acquisition methods (§9 / #150). Unknown values are rejected at construction
# so an unclassifiable source forces an explicit taxonomy decision.
ACQUISITION_METHODS = (
    "direct_fetch",
    "jina",
    "ddgs_snippet",
    "agent_observation",
    "local_fixture",
)

# Freshness classes (trust decay). Ordered oldest → newest; a record's class
# is derived from fetch age against these thresholds unless pinned otherwise.
FRESHNESS_CLASSES = ("stale", "aging", "fresh")

# Default decay thresholds. Configurable per policy; conservative defaults
# because security findings age as soon as targets change.
FRESH_AFTER_H = 24
AGING_AFTER_DAYS = 14


@dataclass(frozen=True)
class RedirectHop:
    """One hop in a redirect chain: requested URL → response URL + status."""

    url: str
    status: int


@dataclass
class ProvenanceRecord:
    """How a piece of evidence was acquired, and whether it is still trustworthy."""

    acquisition_method: str
    fetched_at: str  # RFC 3339 UTC
    content_hash: str  # sha256 hex of PRE-REDACTION raw bytes
    campaign_uuid: str
    agent_uuid: str
    source_url: str | None = None
    final_url: str | None = None  # after redirects
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    http_status: int | None = None
    extraction_pipeline_version: str = "unknown"
    tool_name: str | None = None
    tool_version: str | None = None
    task_uuid: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.acquisition_method not in ACQUISITION_METHODS:
            raise ValueError(
                f"unknown acquisition method {self.acquisition_method!r}; "
                f"expected one of {ACQUISITION_METHODS}"
            )
        if not _is_sha256(self.content_hash):
            raise ValueError("content_hash must be a lowercase sha256 hex digest")
        if not self.campaign_uuid or not self.agent_uuid:
            raise ValueError("provenance requires campaign_uuid and agent_uuid")
        if self.acquisition_method in ("direct_fetch", "jina", "ddgs_snippet"):
            # Network-sourced evidence must carry its retrieval outcome.
            if not self.source_url or self.http_status is None:
                raise ValueError("network-sourced provenance requires source_url and http_status")

    # --- integrity -----------------------------------------------------

    def verify_content_hash(self, raw_bytes: bytes) -> bool:
        """True iff raw_bytes hash to the recorded (pre-redaction) hash."""
        return hashlib.sha256(raw_bytes).hexdigest() == self.content_hash

    @staticmethod
    def hash_bytes(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    # --- trust decay ----------------------------------------------------

    def freshness_class(self, now: datetime | None = None) -> str:
        """Classify staleness from fetch age. Pure function of time — no I/O."""
        now = now or datetime.now(UTC)
        fetched = datetime.fromisoformat(self.fetched_at)
        age = now - fetched
        if age <= timedelta(hours=FRESH_AFTER_H):
            return "fresh"
        if age <= timedelta(days=AGING_AFTER_DAYS):
            return "aging"
        return "stale"

    def is_trusted(
        self,
        raw_bytes: bytes | None = None,
        now: datetime | None = None,
        *,
        require_fresh: bool = False,
    ) -> tuple[bool, str]:
        """Trust verdict with reason.

        Untrusted when: hash mismatch (if bytes supplied), stale freshness,
        or (require_fresh) anything below 'fresh'. Re-verification is left to
        policy; we only report.
        """
        cls = self.freshness_class(now)
        if raw_bytes is not None and not self.verify_content_hash(raw_bytes):
            return False, "content-hash-mismatch"
        if cls == "stale":
            return False, f"provenance-stale (fetched {self.fetched_at})"
        if require_fresh and cls != "fresh":
            return False, f"provenance-not-fresh ({cls})"
        return True, f"ok ({cls})"

    # --- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        d = {
            "schema_version": self.schema_version,
            "record_type": "provenance",
            "acquisition_method": self.acquisition_method,
            "fetched_at": self.fetched_at,
            "content_hash": self.content_hash,
            "campaign_uuid": self.campaign_uuid,
            "agent_uuid": self.agent_uuid,
            "final_url": self.final_url,
            "redirect_chain": [{"url": h.url, "status": h.status} for h in self.redirect_chain],
            "http_status": self.http_status,
            "extraction_pipeline_version": self.extraction_pipeline_version,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "task_uuid": self.task_uuid,
        }
        if self.source_url is not None:
            d["source_url"] = self.source_url
        return d

    @classmethod
    def from_dict(cls, d: dict) -> ProvenanceRecord:
        hops = [RedirectHop(url=h["url"], status=h["status"]) for h in d.get("redirect_chain", [])]
        return cls(
            acquisition_method=d["acquisition_method"],
            fetched_at=d["fetched_at"],
            content_hash=d["content_hash"],
            campaign_uuid=d["campaign_uuid"],
            agent_uuid=d["agent_uuid"],
            source_url=d.get("source_url"),
            final_url=d.get("final_url"),
            redirect_chain=hops,
            http_status=d.get("http_status"),
            extraction_pipeline_version=d.get("extraction_pipeline_version", "unknown"),
            tool_name=d.get("tool_name"),
            tool_version=d.get("tool_version"),
            task_uuid=d.get("task_uuid"),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )


def _is_sha256(value: str) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


# --- audit views (#97 pre-final-review checks) ------------------------------


def findings_without_provenance(findings: list[dict]) -> list[str]:
    """Finding UUIDs that reference evidence but have no provenance attached."""
    return [
        f["finding_uuid"]
        for f in findings
        if f.get("evidence_uuids") and not f.get("provenance_records")
    ]


def findings_with_stale_only_provenance(
    findings: list[dict], now: datetime | None = None
) -> list[str]:
    """Finding UUIDs whose every provenance record is stale/untrusted."""
    result: list[str] = []
    for f in findings:
        recs = f.get("provenance_records") or []
        if not recs or not f.get("evidence_uuids"):
            continue
        parsed = [
            r if isinstance(r, ProvenanceRecord) else ProvenanceRecord.from_dict(r) for r in recs
        ]
        if all(not p.is_trusted(now=now)[0] for p in parsed):
            result.append(f["finding_uuid"])
    return result


def capture_redirect_chain(hops: list[tuple[str, int]]) -> list[RedirectHop]:
    """Build a redirect chain from (url, status) pairs, recording the FINAL
    url on the record's final_url by convention: last hop wins."""
    chain = [RedirectHop(url=u, status=s) for u, s in hops]
    return chain
