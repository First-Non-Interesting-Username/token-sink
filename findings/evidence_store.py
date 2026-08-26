"""Content-addressed evidence & provenance store (issue #165, PLAN §9/§10.1/§21).

Design decisions (per AGENTS.md "document everything"):

- **Content-addressed raw captures.** Raw observation bytes are stored by
  their sha256 digest — identical captures are stored once, and any claim
  citing a digest is verifiable against the exact bytes that were observed.
  The store keeps raw bytes in memory (reference implementation) behind the
  same interface a filesystem/artifact-store backend would implement (#53).

- **Source metadata travels with every capture**: source URL, retrieval
  timestamp, capturing agent, extraction method, and optional redirect-hop
  provenance. This makes each piece of evidence independently re-checkable
  for freshness/trust without trusting the capturing agent's word.

- **Claim-to-evidence traceability API (§21).** Claims link to evidence via
  digests; ``trace_claim`` returns the full chain (claim → capture → source),
  and ``verify`` re-hashes stored bytes to detect tampering or truncation.

- **Append-only + privacy-preserving.** Captures are never mutated once
  written; redaction happens before storage (caller's responsibility, same
  gate as agents/capture.py) so this store only ever holds what the caller
  decided was safe to persist.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


class EvidenceStoreError(ValueError):
    """Invalid capture or unknown digest."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class RedirectHop:
    """One hop of a redirect chain observed while fetching the source."""

    url: str
    status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "status": self.status}


@dataclass
class RawCapture:
    """A content-addressed raw observation plus its source metadata."""

    raw_bytes: bytes
    digest: str = ""  # sha256 hex of raw_bytes — the capture's identity
    campaign_uuid: str | None = None
    task_uuid: str | None = None
    agent_uuid: str | None = None
    source_url: str | None = None
    source_tool: str | None = None  # e.g. "curl", "ddgs", "browser"
    extraction_method: str | None = None
    content_type: str | None = None
    retrieved_at: float = field(default_factory=time.time)
    redirect_hops: list[RedirectHop] = field(default_factory=list)

    def verify(self) -> bool:
        """Re-hash the stored bytes; detects tampering/truncation."""
        return sha256_hex(self.raw_bytes) == self.digest

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        d = {
            "schema_version": 1,
            "record_type": "raw_capture",
            "digest": self.digest,
            "size": len(self.raw_bytes),
            "campaign_uuid": self.campaign_uuid,
            "task_uuid": self.task_uuid,
            "agent_uuid": self.agent_uuid,
            "source_url": self.source_url,
            "source_tool": self.source_tool,
            "extraction_method": self.extraction_method,
            "content_type": self.content_type,
            "retrieved_at": self.retrieved_at,
            "redirect_hops": [h.to_dict() for h in self.redirect_hops],
        }
        if include_raw:
            d["raw_base64"] = __import__("base64").b64encode(self.raw_bytes).decode()
        return d


class EvidenceStore:
    """Content-addressed store with claim→evidence traceability."""

    def __init__(self) -> None:
        # digest → capture; identical bytes dedupe naturally.
        self._captures: dict[str, RawCapture] = {}
        # claim_id → ordered list of digests backing it.
        self._claims: dict[str, list[str]] = {}

    # --- ingestion ---
    def put_capture(self, cap: RawCapture) -> str:
        if not cap.raw_bytes and not cap.digest:
            raise EvidenceStoreError("empty capture")
        expected = sha256_hex(cap.raw_bytes)
        if cap.digest and cap.digest != expected:
            raise EvidenceStoreError(
                f"digest mismatch: declared {cap.digest[:12]}… but content hashes to "
                f"{expected[:12]}…"
            )
        cap.digest = expected
        self._captures.setdefault(expected, cap)  # first writer wins (append-only)
        return expected

    def put_raw(
        self,
        raw: bytes,
        *,
        campaign_uuid: str | None = None,
        **meta: Any,
    ) -> str:
        return self.put_capture(RawCapture(raw_bytes=raw, campaign_uuid=campaign_uuid, **meta))

    # --- lookup ---
    def get_capture(self, digest: str) -> RawCapture | None:
        return self._captures.get(digest)

    def has(self, digest: str) -> bool:
        return digest in self._captures

    # --- claims ---
    def link_claim(self, claim_id: str, digests: list[str]) -> None:
        """Bind a claim to its supporting evidence digests."""
        missing = [d for d in digests if d not in self._captures]
        if missing:
            raise EvidenceStoreError(f"unknown evidence digest(s): {missing}")
        cur = self._claims.setdefault(claim_id, [])
        for d in digests:
            if d not in cur:
                cur.append(d)

    def trace_claim(self, claim_id: str) -> list[dict[str, Any]]:
        """Full §21 chain for one claim: claim → capture → source metadata."""
        return [
            self.get_capture(d).to_dict()  # type: ignore[union-attr]
            for d in self._claims.get(claim_id, [])
            if d in self._captures
        ]

    def claims_for_digest(self, digest: str) -> list[str]:
        """Reverse index: which claims cite this capture."""
        return sorted(c for c, ds in self._claims.items() if digest in ds)

    # --- integrity ---
    def verify_all(self) -> list[str]:
        """Re-hash every capture; returns digests that fail verification."""
        return [d for d, c in self._captures.items() if not c.verify()]

    def __len__(self) -> int:
        return len(self._captures)
