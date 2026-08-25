"""Free-status verification workflow for gateway models (PLAN §8.2, issue #87).

Partly-free gateways (§8.2) must never be assumed free because the gateway is
partly free. When free-status metadata is unavailable, a model is marked
``unknown`` and stays excluded from free-only routing (the hard block lives in
the router / issue #66). This module implements the *confirmation* side:

- Catalog entries carry :class:`FreeStatus` plus source-of-truth and
  verification timestamp (:class:`ModelFreeStatus`).
- A verification flow: an operator (or approved agent task) submits evidence
  of free status; a human approves the transition unknown → free/paid.
  Transitions are NEVER auto-promoted from model output alone —
  :meth:`VerificationStore.submit` only records a pending request and
  :meth:`VerificationStore.approve` requires an explicit human approver.
- Re-verification: a status entry carries the hash of the upstream pricing
  page it was verified against; when that hash changes the entry is stale and
  reverts to ``unknown`` (:func:`effective_status` /
  :meth:`VerificationStore.refresh_pricing_hashes`).
- Every transition is appended to a tamper-evident audit trail
  (:class:`AuditEntry`, chained hashes like the §13/§14 event store).
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class FreeStatus(enum.Enum):
    """Free-status classification of a model (PLAN §8.2)."""

    FREE = "free"
    PAID = "paid"
    UNKNOWN = "unknown"


# Statuses eligible for free-only routing. Anything else — notably UNKNOWN —
# is excluded until confirmed (PLAN §8.2: "unknown ⇒ excluded until confirmed").
FREE_ROUTABLE = frozenset({FreeStatus.FREE})


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    """Provenance-tagged evidence backing a verification request.

    ``kind`` describes what kind of proof this is (e.g. ``pricing_page``,
    ``provider_docs``); ``content_hash`` pins the exact bytes that were seen,
    so later re-verification can detect drift.
    """

    kind: str  # e.g. "pricing_page", "provider_docs"
    reference: str  # URL or other provenance pointer
    content_hash: str = ""  # sha256 of the referenced content snapshot
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "reference": self.reference,
            "content_hash": self.content_hash,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        return cls(
            kind=str(d["kind"]),
            reference=str(d["reference"]),
            content_hash=str(d.get("content_hash", "")),
            notes=str(d.get("notes", "")),
        )


@dataclass(frozen=True)
class VerificationRequest:
    """A pending unknown → free/paid confirmation request."""

    request_id: str
    provider: str
    model_id: str
    proposed_status: FreeStatus  # target status (FREE or PAID)
    submitted_by: str  # operator name or approved agent-task id
    evidence: list[Evidence]
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "provider": self.model_provider_key(self.provider, self.model_id)[0],
            "model_id": self.model_provider_key(self.provider, self.model_id)[1],
            "proposed_status": self.proposed_status.value,
            "submitted_by": self.submitted_by,
            "evidence": [e.to_dict() for e in self.evidence],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VerificationRequest:
        return cls(
            request_id=str(d["request_id"]),
            provider=str(d["provider"]),
            model_id=str(d["model_id"]),
            proposed_status=FreeStatus(d["proposed_status"]),
            submitted_by=str(d["submitted_by"]),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            created_at=float(d["created_at"]),
        )

    @staticmethod
    def model_provider_key(provider: str, model_id: str) -> tuple[str, str]:
        return provider, model_id


@dataclass
class ModelFreeStatus:
    """Catalog entry: free status + provenance for one (provider, model)."""

    provider: str
    model_id: str
    status: FreeStatus = FreeStatus.UNKNOWN
    # Source of truth for the current status ("operator", "verification:<id>").
    source: str = ""
    verified_at: float | None = None
    # sha256 of the upstream pricing page at verification time; used to detect
    # staleness (a changed hash invalidates the verified status).
    pricing_page_hash: str | None = None
    expires_at: float | None = None  # optional TTL on the verification

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.model_id}"

    def is_stale(self, now: float) -> bool:
        if self.expires_at is not None and now >= self.expires_at:
            return True
        return False

    def effective_status(self, now: float, current_pricing_hash: str | None = None) -> FreeStatus:
        """Status after applying expiry/pricing-drift rules.

        A verified entry reverts to UNKNOWN when it expires or when the
        upstream pricing-page hash no longer matches what was verified.
        """
        if self.status is FreeStatus.UNKNOWN:
            return FreeStatus.UNKNOWN
        if self.is_stale(now):
            return FreeStatus.UNKNOWN
        if (
            self.pricing_page_hash is not None
            and current_pricing_hash is not None
            and current_pricing_hash != self.pricing_page_hash
        ):
            return FreeStatus.UNKNOWN
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "status": self.status.value,
            "source": self.source,
            "verified_at": self.verified_at,
            "pricing_page_hash": self.pricing_page_hash,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ModelFreeStatus:
        return cls(
            provider=str(d["provider"]),
            model_id=str(d["model_id"]),
            status=FreeStatus(d["status"]),
            source=str(d.get("source", "")),
            verified_at=d.get("verified_at"),
            pricing_page_hash=d.get("pricing_page_hash"),
            expires_at=d.get("expires_at"),
        )


@dataclass(frozen=True)
class AuditEntry:
    """Append-only audit record for a status transition (chained hash).

    ``prev_hash`` links to the previous entry so any tampering with history
    breaks the chain — same tamper-evidence approach as the §13 event store.
    """

    seq: int
    ts: float
    action: str  # "submit" | "approve" | "deny" | "expire" | "invalidate"
    provider: str
    model_id: str
    actor: str
    from_status: FreeStatus
    to_status: FreeStatus
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "action": self.action,
                "provider": self.provider,
                "model_id": self.model_id,
                "actor": self.actor,
                "from_status": self.from_status.value,
                "to_status": self.to_status.value,
                "detail": self.detail,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        )
        return _sha256(payload)


class VerificationError(ValueError):
    """Raised for invalid verification operations."""


class VerificationStore:
    """In-memory catalog of model free statuses + verification workflow.

    Storage-agnostic by design (matches the rest of the codebase until §12
    storage lands); callers can serialize via :meth:`export_statuses`.
    """

    def __init__(self) -> None:
        self._statuses: dict[str, ModelFreeStatus] = {}
        self._requests: dict[str, VerificationRequest] = {}
        self._audit: list[AuditEntry] = []
        self._pricing_hashes: dict[str, str] = {}

    # --- catalog ---------------------------------------------------------

    @staticmethod
    def _key(provider: str, model_id: str) -> str:
        return f"{provider}/{model_id}"

    def get(self, provider: str, model_id: str) -> ModelFreeStatus:
        key = self._key(provider, model_id)
        if key not in self._statuses:
            # Unknown models are materialized lazily as UNKNOWN — the default
            # posture per §8.2 (never assume free).
            self._statuses[key] = ModelFreeStatus(provider=provider, model_id=model_id)
        return self._statuses[key]

    def set_pricing_hash(self, provider: str, model_id: str, content: str) -> None:
        """Record the current hash of the upstream pricing page for a model."""
        self._pricing_hashes[self._key(provider, model_id)] = _sha256(content)

    def refresh_pricing_hashes(self, now: float | None = None) -> list[AuditEntry]:
        """Invalidate entries whose pricing page changed; revert them to unknown."""
        now = time.time() if now is None else now
        invalidated: list[AuditEntry] = []
        for key, entry in list(self._statuses.items()):
            if entry.status is FreeStatus.UNKNOWN or entry.pricing_page_hash is None:
                continue
            current = self._pricing_hashes.get(key)
            if current is not None and current != entry.pricing_page_hash:
                old = entry.status
                entry.status = FreeStatus.UNKNOWN
                entry.source = f"invalidated:{entry.source}"
                invalidated.append(
                    self._append_audit(
                        action="invalidate",
                        provider=entry.provider,
                        model_id=entry.model_id,
                        actor="system",
                        from_status=old,
                        to_status=FreeStatus.UNKNOWN,
                        detail={"reason": "pricing_page_hash_changed"},
                    )
                )
        return invalidated

    # --- verification flow -----------------------------------------------

    def submit(
        self,
        provider: str,
        model_id: str,
        proposed_status: FreeStatus,
        submitted_by: str,
        evidence: list[Evidence],
        now: float | None = None,
    ) -> VerificationRequest:
        """Operator/approved-agent submits evidence. Does NOT change status.

        The transition itself requires a separate human approval — model
        output alone can never promote a status (§8.2 safety rule).
        """
        if proposed_status is FreeStatus.UNKNOWN:
            raise VerificationError("proposed_status must be free or paid")
        now = time.time() if now is None else now
        req = VerificationRequest(
            request_id=f"vfq_{uuid.uuid4().hex[:12]}",
            provider=provider,
            model_id=model_id,
            proposed_status=proposed_status,
            submitted_by=submitted_by,
            evidence=list(evidence),
            created_at=now,
        )
        self._requests[req.request_id] = req
        self._append_audit(
            action="submit",
            provider=provider,
            model_id=model_id,
            actor=submitted_by,
            from_status=self.get(provider, model_id).status,
            to_status=proposed_status,
            detail={"request_id": req.request_id},
        )
        return req

    def approve(
        self,
        request_id: str,
        approved_by: str,
        ttl_seconds: float | None = None,
        now: float | None = None,
    ) -> ModelFreeStatus:
        """Human approves the transition; catalog entry updates atomically."""
        now = time.time() if now is None else now
        req = self._requests.get(request_id)
        if req is None:
            raise VerificationError(f"unknown request {request_id!r}")
        entry = self.get(req.provider, req.model_id)
        old = entry.status
        entry.status = req.proposed_status
        entry.source = f"verification:{request_id}"
        entry.verified_at = now
        entry.pricing_page_hash = self._pricing_hashes.get(self._key(req.provider, req.model_id))
        entry.expires_at = now + ttl_seconds if ttl_seconds else None
        del self._requests[request_id]
        self._append_audit(
            action="approve",
            provider=req.provider,
            model_id=req.model_id,
            actor=approved_by,
            from_status=old,
            to_status=req.proposed_status,
            detail={"request_id": request_id, "evidence": [e.to_dict() for e in req.evidence]},
        )
        return entry

    def deny(self, request_id: str, denied_by: str, reason: str = "") -> None:
        req = self._requests.pop(request_id, None)
        if req is None:
            raise VerificationError(f"unknown request {request_id!r}")
        self._append_audit(
            action="deny",
            provider=req.provider,
            model_id=req.model_id,
            actor=denied_by,
            from_status=self.get(req.provider, req.model_id).status,
            to_status=self.get(req.provider, req.model_id).status,
            detail={"request_id": request_id, "reason": reason},
        )

    def expire_stale(self, now: float | None = None) -> list[ModelFreeStatus]:
        """Revert expired verified entries to unknown (re-verification needed)."""
        now = time.time() if now is None else now
        reverted: list[ModelFreeStatus] = []
        for entry in self._statuses.values():
            if entry.status is not FreeStatus.UNKNOWN and entry.is_stale(now):
                old = entry.status
                entry.status = FreeStatus.UNKNOWN
                entry.source = f"expired:{entry.source}"
                self._append_audit(
                    action="expire",
                    provider=entry.provider,
                    model_id=entry.model_id,
                    actor="system",
                    from_status=old,
                    to_status=FreeStatus.UNKNOWN,
                    detail={"expired_at": entry.expires_at},
                )
                reverted.append(entry)
        return reverted

    # --- queries -----------------------------------------------------------

    def pending_requests(self) -> list[VerificationRequest]:
        return sorted(self._requests.values(), key=lambda r: r.created_at)

    def effective_status(
        self, provider: str, model_id: str, now: float | None = None
    ) -> FreeStatus:
        now = time.time() if now is None else now
        entry = self.get(provider, model_id)
        current = self._pricing_hashes.get(self._key(provider, model_id))
        return entry.effective_status(now=now, current_pricing_hash=current)

    def routable_free(self, now: float | None = None) -> list[tuple[str, str]]:
        """Models currently eligible for free-only routing (FREE only)."""
        out = []
        for key in sorted(self._statuses):
            p, m = key.split("/", 1)
            if self.effective_status(p, m, now=now) is FreeStatus.FREE:
                out.append((p, m))
        return out

    # --- audit -------------------------------------------------------------

    def _append_audit(
        self,
        action: str,
        provider: str,
        model_id: str,
        actor: str,
        from_status: FreeStatus,
        to_status: FreeStatus,
        detail: dict[str, Any],
    ) -> AuditEntry:
        prev_hash = self._audit[-1].entry_hash if self._audit else ""
        entry = AuditEntry(
            seq=len(self._audit),
            ts=time.time(),
            action=action,
            provider=provider,
            model_id=model_id,
            actor=actor,
            from_status=from_status,
            to_status=to_status,
            detail=detail,
            prev_hash=prev_hash,
        )
        # Hash includes prev_hash so any tampering with earlier entries breaks
        # the chain (same approach as the §13 event store).
        entry = AuditEntry(**{**entry.__dict__, "entry_hash": entry.compute_hash()})
        self._audit.append(entry)
        return entry

    def audit_trail(self) -> list[AuditEntry]:
        return list(self._audit)

    def verify_audit_chain(self) -> bool:
        prev = ""
        for i, e in enumerate(self._audit):
            if e.seq != i or e.prev_hash != prev or e.entry_hash != e.compute_hash():
                return False
            prev = e.entry_hash
        return True

    # --- persistence helpers -------------------------------------------------

    def export_statuses(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._statuses.values()]
