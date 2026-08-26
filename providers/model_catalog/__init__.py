"""Model catalog service: discovery refresh, capability/context metadata,
staleness handling, and versioned snapshots (PLAN §8.1-§8.2, issue #118).

Routers need a live catalog of models with capabilities, context limits,
free status, rate limits, and trust level. Free-status classification is
NOT decided here — it delegates to ``providers.free_status`` (the merged
#87 verification workflow): unknown models are excluded from free-only
routing until a human confirms them.

Design rules:

- **Discovery never silently drops models mid-campaign** (issue requirement):
  a refresh that no longer sees a model marks it :attr:`CatalogEntry.deprecated`
  instead of removing it, so in-flight campaigns keep resolving their entries.
- **Staleness**: every entry carries ``last_verified``; stale entries stay
  queryable but report ``is_stale=True`` so routers can treat them
  conservatively (lower confidence + log warning — see
  :meth:`ModelCatalog.candidates`).
- **Versioned snapshots**: each refresh appends an immutable snapshot id so
  router decision replay (#55) can reconstruct the exact catalog state a
  decision used (:meth:`ModelCatalog.snapshot`, :meth:`ModelCatalog.restore`).
- Storage-agnostic (in-memory dict), matching the rest of ``providers/``.
"""

from __future__ import annotations

import copy
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# Re-export so router code has one import site for free-status semantics.
from providers.free_status import FreeStatus

__all__ = [
    "Capability",
    "TrustLevel",
    "CatalogEntry",
    "CatalogSnapshot",
    "ModelCatalog",
]


class Capability(StrEnum):
    """Task capabilities a model can advertise (PLAN §8.1/§8.3)."""

    CODING = "coding"
    SEARCH = "search"
    REASONING = "reasoning"
    REVIEW = "review"
    SECURITY_ANALYSIS = "security_analysis"
    REPORT_WRITING = "report_writing"


class TrustLevel(StrEnum):
    """How much a provider/model endpoint is trusted (PLAN §8.2 custom endpoints)."""

    NATIVE = "native"  # first-party provider adapter
    GATEWAY = "gateway"  # partly-free gateway (strict allowlist required)
    CUSTOM = "custom"  # user-supplied endpoint


@dataclass
class CatalogEntry:
    """One model's authoritative metadata in the catalog."""

    provider: str
    model_id: str
    capabilities: set[Capability] = field(default_factory=set)
    context_window: int = 0  # tokens; 0 = unknown
    max_output_tokens: int = 0  # tokens; 0 = unknown
    supports_streaming: bool = False
    supports_tool_calling: bool = False
    supports_structured_output: bool = False
    # Requests/tokens per minute budgets; None = no locally-known limit.
    request_rate_limit: int | None = None
    token_rate_limit: int | None = None
    # Pricing per million tokens (input/output); None = unknown/not applicable.
    # Currency is REQUIRED whenever any price is set (issue #210).
    price_input_per_mtok: float | None = None
    price_output_per_mtok: float | None = None
    price_currency: str | None = None
    # Free-tier constraints, e.g. {"requests_per_day": 50,
    # "context_cap_tokens": 16000}; keys validated by
    # providers.model_catalog.seed.validate_entry.
    free_tier_constraints: dict[str, Any] = field(default_factory=dict)
    trust_level: TrustLevel = TrustLevel.GATEWAY
    free_status: FreeStatus = FreeStatus.UNKNOWN
    deprecated: bool = False
    last_verified: float = 0.0  # epoch seconds of last successful refresh

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.model_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "capabilities": sorted(c.value for c in self.capabilities),
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "supports_streaming": self.supports_streaming,
            "supports_tool_calling": self.supports_tool_calling,
            "supports_structured_output": self.supports_structured_output,
            "request_rate_limit": self.request_rate_limit,
            "token_rate_limit": self.token_rate_limit,
            "price_input_per_mtok": self.price_input_per_mtok,
            "price_output_per_mtok": self.price_output_per_mtok,
            "price_currency": self.price_currency,
            "free_tier_constraints": dict(self.free_tier_constraints),
            "trust_level": self.trust_level.value,
            "free_status": self.free_status.value,
            "deprecated": self.deprecated,
            "last_verified": self.last_verified,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CatalogEntry:
        return cls(
            provider=str(d["provider"]),
            model_id=str(d["model_id"]),
            capabilities={Capability(c) for c in d.get("capabilities", [])},
            context_window=int(d.get("context_window", 0)),
            max_output_tokens=int(d.get("max_output_tokens", 0)),
            supports_streaming=bool(d.get("supports_streaming", False)),
            supports_tool_calling=bool(d.get("supports_tool_calling", False)),
            supports_structured_output=bool(d.get("supports_structured_output", False)),
            request_rate_limit=d.get("request_rate_limit"),
            token_rate_limit=d.get("token_rate_limit"),
            price_input_per_mtok=d.get("price_input_per_mtok"),
            price_output_per_mtok=d.get("price_output_per_mtok"),
            price_currency=d.get("price_currency"),
            free_tier_constraints=dict(d.get("free_tier_constraints", {})),
            trust_level=TrustLevel(d.get("trust_level", "gateway")),
            free_status=FreeStatus(d.get("free_status", "unknown")),
            deprecated=bool(d.get("deprecated", False)),
            last_verified=float(d.get("last_verified", 0.0)),
        )


@dataclass(frozen=True)
class CatalogSnapshot:
    """Immutable point-in-time copy of the whole catalog.

    Snapshots exist so decision replay (#55) can reconstruct exactly what the
    router saw; they are never mutated by later refreshes.
    """

    snapshot_id: str
    ts: float
    entries: dict[str, CatalogEntry]

    @classmethod
    def take(cls, entries: dict[str, CatalogEntry]) -> CatalogSnapshot:
        return cls(
            snapshot_id=f"cat_{uuid.uuid4().hex[:12]}",
            ts=time.time(),
            # Deep-copy so later in-place edits can't leak into the snapshot.
            entries=copy.deepcopy(entries),
        )


class ModelCatalog:
    """Shared registry backing the router pool (#16) and UI provider page."""

    STALE_AFTER_SECONDS = 24 * 3600.0  # default staleness horizon

    def __init__(self, stale_after_seconds: float = STALE_AFTER_SECONDS) -> None:
        self._entries: dict[str, CatalogEntry] = {}
        self._snapshots: dict[str, CatalogSnapshot] = {}
        self.stale_after_seconds = stale_after_seconds

    # --- basic access ------------------------------------------------------

    @staticmethod
    def _key(provider: str, model_id: str) -> str:
        return f"{provider}/{model_id}"

    def get(self, provider: str, model_id: str) -> CatalogEntry | None:
        return self._entries.get(self._key(provider, model_id))

    def upsert(self, entry: CatalogEntry, now: float | None = None) -> CatalogEntry:
        entry.last_verified = time.time() if now is None else now
        self._entries[entry.key] = entry
        return entry

    def all_entries(self, include_deprecated: bool = True) -> list[CatalogEntry]:
        out = list(self._entries.values())
        if not include_deprecated:
            out = [e for e in out if not e.deprecated]
        return out

    # --- discovery refresh ---------------------------------------------------

    def apply_discovery(
        self,
        provider: str,
        discovered: list[dict[str, Any]],
        now: float | None = None,
    ) -> tuple[list[CatalogEntry], list[CatalogEntry]]:
        """Apply a discovery result for one provider.

        Returns ``(updated, deprecated)``. Models that disappeared from the
        discovery response are marked deprecated — NEVER removed — so running
        campaigns keep resolving their catalog entries.
        """
        now = time.time() if now is None else now
        updated: list[CatalogEntry] = []
        seen_keys: set[str] = set()
        for raw in discovered:
            entry = CatalogEntry.from_dict({**raw, "provider": provider})
            old = self._entries.get(entry.key)
            # Preserve deprecation state across refreshes unless rediscovered
            # below; a rediscovered model is un-deprecated automatically.
            entry.deprecated = False
            _ = old
            self._entries[entry.key] = entry
            seen_keys.add(entry.key)
            updated.append(entry)

        # Anything of this provider NOT in the discovery result → deprecated.
        newly_deprecated: list[CatalogEntry] = []
        for key, existing in self._entries.items():
            if key.startswith(f"{provider}/") and key not in seen_keys:
                if not existing.deprecated:
                    existing.deprecated = True
                    newly_deprecated.append(existing)
        return updated, newly_deprecated

    # --- staleness -----------------------------------------------------------

    def is_stale(self, entry: CatalogEntry, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (now - entry.last_verified) > self.stale_after_seconds or entry.last_verified <= 0

    def candidates(
        self,
        capability: Capability | None = None,
        require_structured_output: bool = False,
        now: float | None = None,
    ) -> list[tuple[CatalogEntry, bool]]:
        """Query API for the router pool (#16).

        Returns ``(entry, stale)`` pairs. Deprecated entries are excluded;
        stale entries are included but flagged so callers can lower
        confidence and log a warning (conservative treatment per issue #118).
        """
        out = []
        for entry in self.all_entries(include_deprecated=False):
            if capability is not None and capability not in entry.capabilities:
                continue
            if require_structured_output and not entry.supports_structured_output:
                continue
            out.append((entry, self.is_stale(entry, now)))
        return sorted(out, key=lambda pair: pair[0].key)

    # --- snapshots -------------------------------------------------------------

    def snapshot(self) -> CatalogSnapshot:
        snap = CatalogSnapshot.take(self._entries)
        self._snapshots[snap.snapshot_id] = snap
        return snap

    def restore(self, snapshot_id: str) -> dict[str, CatalogEntry]:
        """Return the exact entry state a past decision used (#55 replay)."""
        snap = self._snapshots.get(snapshot_id)
        if snap is None:
            raise KeyError(f"unknown catalog snapshot {snapshot_id!r}")
        return copy.deepcopy(snap.entries)
