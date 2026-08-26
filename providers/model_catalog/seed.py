"""Seed model catalog: maintained baseline entries for PLAN §8.2 (issue #210).

The catalog service (:mod:`providers.model_catalog`) is storage-agnostic and
starts empty. Routers and operators need a *maintained* starting point, so
this module ships a small, documentation-only seed set covering the three
provider classes of PLAN §8.2 (native-free, partly-free gateway, custom
endpoint) with identity, capabilities, context limits, pricing / free-tier
constraints, rate limits, and streaming / tool-calling / structured-output
support flags.

Rules:

- **Documentation only**: every seeded entry uses ``example`` providers and
  placeholder values; nothing here is live provider data and nothing is
  enabled by default. Free status stays ``unknown`` unless the merged #87
  verification workflow has confirmed it — seeds never pre-approve freeness.
- **Validated at load**: :func:`load_seed_catalog` runs every entry through
  :func:`validate_entry` so a malformed seed fails loudly instead of
  poisoning the router pool.
- **Maintained by hand**: seeds are reviewed like code. Discovery refreshes
  (:meth:`ModelCatalog.apply_discovery`) update/deprecate on top of them but
  never silently re-enable free routing.
"""

from __future__ import annotations

from typing import Any

from providers.free_status import FreeStatus
from providers.model_catalog import (
    Capability,
    CatalogEntry,
    ModelCatalog,
    TrustLevel,
)

__all__ = ["CatalogValidationError", "validate_entry", "SEED_ENTRIES", "load_seed_catalog"]


class CatalogValidationError(ValueError):
    """A catalog entry violates the PLAN §8.2 metadata invariants."""


def validate_entry(entry: CatalogEntry) -> None:
    """Raise :class:`CatalogValidationError` if *entry* breaks an invariant.

    Invariants (PLAN §8.2):

    - identity is non-empty and key-shaped (no whitespace, non-empty parts);
    - limits, when known, are positive;
    - pricing, when known, is non-negative and paired with a currency;
    - a model advertising paid pricing must not simultaneously be marked
      FREE without going through the human verification workflow — the seed
      data therefore must never claim both.
    """
    for part in (entry.provider, entry.model_id):
        if not part or part.strip() != part or any(c.isspace() for c in part):
            raise CatalogValidationError(f"invalid identity component {part!r}")
    if entry.context_window < 0 or entry.max_output_tokens < 0:
        raise CatalogValidationError(f"{entry.key}: negative token limit")
    if entry.request_rate_limit is not None and entry.request_rate_limit <= 0:
        raise CatalogValidationError(f"{entry.key}: request_rate_limit must be positive")
    if entry.token_rate_limit is not None and entry.token_rate_limit <= 0:
        raise CatalogValidationError(f"{entry.key}: token_rate_limit must be positive")
    if entry.price_input_per_mtok is not None or entry.price_output_per_mtok is not None:
        for name in ("price_input_per_mtok", "price_output_per_mtok"):
            value = getattr(entry, name)
            if value is not None and value < 0:
                raise CatalogValidationError(f"{entry.key}: {name} must be >= 0")
        if entry.price_currency is None:
            raise CatalogValidationError(f"{entry.key}: pricing present without price_currency")
        if (
            entry.price_input_per_mtok is not None
            and entry.price_input_per_mtok > 0
            and entry.free_status is FreeStatus.FREE
        ):
            # Paid pricing + FREE would bypass the #87 human verification gate.
            raise CatalogValidationError(
                f"{entry.key}: positive input pricing contradicts free_status=free"
            )
    unknown_keys = set(entry.free_tier_constraints) - {
        "requests_per_day",
        "tokens_per_day",
        "context_cap_tokens",
        "requires_registration",
        "notes",
    }
    if unknown_keys:
        raise CatalogValidationError(
            f"{entry.key}: unknown free-tier constraint keys {sorted(unknown_keys)}"
        )


def _seed(**kw: Any) -> CatalogEntry:
    entry = CatalogEntry(**kw)
    validate_entry(entry)
    return entry


# Documentation-only seed entries. Placeholder numbers illustrate the shape of
# the metadata; they are NOT live provider facts and must never be treated as
# verified free-status evidence (that is the #87 workflow's job).
SEED_ENTRIES: list[CatalogEntry] = [
    _seed(
        provider="example-native-free",
        model_id="example-small",
        capabilities={Capability.CODING, Capability.REASONING},
        context_window=32_000,
        max_output_tokens=4_096,
        supports_streaming=True,
        supports_tool_calling=False,
        supports_structured_output=True,
        request_rate_limit=15,
        token_rate_limit=100_000,
        trust_level=TrustLevel.NATIVE,
        free_status=FreeStatus.UNKNOWN,
        price_input_per_mtok=None,
        price_output_per_mtok=None,
        free_tier_constraints={
            "requests_per_day": 200,
            "requires_registration": True,
            "notes": "documentation-only example; verify before enabling",
        },
    ),
    _seed(
        provider="example-gateway",
        model_id="example-medium",
        capabilities={Capability.CODING, Capability.REASONING, Capability.REVIEW},
        context_window=128_000,
        max_output_tokens=8_192,
        supports_streaming=True,
        supports_tool_calling=True,
        supports_structured_output=True,
        request_rate_limit=60,
        token_rate_limit=250_000,
        trust_level=TrustLevel.GATEWAY,
        free_status=FreeStatus.UNKNOWN,
        price_input_per_mtok=0.0,
        price_output_per_mtok=0.0,
        price_currency="USD",
        free_tier_constraints={
            "requests_per_day": 50,
            "context_cap_tokens": 16_000,
            "requires_registration": True,
            "notes": "gateway free tier; allowlist required per PLAN §8.2",
        },
    ),
    _seed(
        provider="example-custom-endpoint",
        model_id="example-selfhosted",
        capabilities={Capability.SECURITY_ANALYSIS},
        context_window=64_000,
        max_output_tokens=8_192,
        supports_streaming=False,
        supports_tool_calling=True,
        supports_structured_output=False,
        trust_level=TrustLevel.CUSTOM,
        free_status=FreeStatus.UNKNOWN,
        price_input_per_mtok=0.5,
        price_output_per_mtok=1.5,
        price_currency="USD",
        free_tier_constraints={},
    ),
]


def load_seed_catalog(
    catalog: ModelCatalog | None = None, now: float | None = None
) -> ModelCatalog:
    """Return *catalog* (a fresh one by default) populated with the seeds.

    Every entry is re-validated at load time; a malformed seed raises
    :class:`CatalogValidationError` rather than entering the router pool.
    Seeded entries keep ``free_status=UNKNOWN``, so none of them are
    routable under free-only policies until a human confirms them via the
    #87 verification workflow.
    """
    catalog = catalog if catalog is not None else ModelCatalog()
    for entry in SEED_ENTRIES:
        validate_entry(entry)
        catalog.upsert(CatalogEntry.from_dict(entry.to_dict()), now=now)
    return catalog
