"""Provider capability matrix + conformance verification (spec §8.1).

Every adapter *declares* streaming / tool / structured-output support
via :class:`AdapterCapabilities`. This module makes those declarations
trustworthy:

* :func:`build_matrix` — derives the support matrix from registered
  adapters for the provider/model UI.
* :func:`verify_adapter` — runs live conformance probes against an
  adapter and returns which declared capabilities it actually
  honours. A declared capability that fails its probe is reported as
  ``verified=False`` so the router can stop trusting it.
* :func:`eligible_for_structured` — routing-side enforcement: a task
  that requires structured output only considers adapters with a
  verified ``structured_output`` capability, unless the caller allows
  the prompt-based JSON fallback (send ``json_object`` anyway and
  validate — safe only when the caller validates).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from mavr.observability.logging import get_logger
from mavr.providers.adapters.base import ProviderAdapter
from mavr.schemas.routing import ChatMessage, ChatRequest

log = get_logger(__name__)


@dataclass(frozen=True)
class CapabilityRow:
    provider_id: str
    model_key: str
    streaming: bool
    tool_support: bool
    structured_output: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "model_key": self.model_key,
            "streaming": self.streaming,
            "tool_support": self.tool_support,
            "structured_output": self.structured_output,
        }


def build_matrix(adapters: list[ProviderAdapter]) -> list[CapabilityRow]:
    """One row per (adapter, model) from declared capabilities."""
    rows: list[CapabilityRow] = []
    for a in adapters:
        caps = a.capabilities
        for m in a.models():
            rows.append(
                CapabilityRow(
                    provider_id=a.provider_id,
                    model_key=m.model_key,
                    streaming=caps.streaming,
                    tool_support=caps.tool_support,
                    structured_output=caps.structured_output,
                )
            )
    return rows


# ---- conformance verification ----------------------------------------------


def _probe_request(response_format: str = "text") -> ChatRequest:
    return ChatRequest(
        messages=[ChatMessage(role="user", content="Reply with the word ok.")],
        max_tokens=16,
        response_format=response_format,  # type: ignore[arg-type]
    )


async def verify_adapter(adapter: ProviderAdapter) -> dict[str, Any]:
    """Probe an adapter and check its declared capabilities actually work.

    Returns ``{"declared": {...}, "verified": {...}, "notes": [...]}``.
    Each probe failure is recorded in ``notes``; nothing raises — a
    broken capability is data, not an error.
    """
    caps = adapter.capabilities
    declared = {
        "streaming": caps.streaming,
        "tool_support": caps.tool_support,
        "structured_output": caps.structured_output,
    }
    verified: dict[str, bool] = {}
    notes: list[str] = []
    model_keys = adapter.list_model_keys()
    if not model_keys:
        return {
            "declared": declared,
            "verified": {k: False for k in declared},
            "notes": ["no models registered"],
        }
    key = model_keys[0]

    # Streaming probe: declared streaming must yield at least one chunk.
    if caps.streaming:
        try:
            got_chunk = False
            async for _chunk in adapter.stream(key, _probe_request()):
                got_chunk = True
                break
            verified["streaming"] = got_chunk
            if not got_chunk:
                notes.append("declared streaming produced no chunks")
        except Exception as exc:  # noqa: BLE001 — probe must never raise
            verified["streaming"] = False
            notes.append(f"streaming probe failed: {exc}")
    else:
        verified["streaming"] = False

    # Structured-output probe: json_object response_format must come
    # back parseable as JSON (best effort — providers differ).
    if caps.structured_output:
        try:
            resp = await adapter.chat(key, _probe_request("json_object"))
            try:
                json.loads(resp.content)
                verified["structured_output"] = True
            except ValueError:
                verified["structured_output"] = False
                notes.append("structured_output probe returned non-JSON content")
        except Exception as exc:  # noqa: BLE001
            verified["structured_output"] = False
            notes.append(f"structured_output probe failed: {exc}")
    else:
        verified["structured_output"] = False

    # Tool support is declared-only here: a faithful probe requires a
    # model round-trip executing tools, which belongs to the benchmark
    # harness. We mark it unverified rather than pretending.
    verified["tool_support"] = False
    if caps.tool_support:
        notes.append("tool_support declared; verification requires benchmark run")

    return {"declared": declared, "verified": verified, "notes": notes}


# ---- routing enforcement ----------------------------------------------------


@dataclass(frozen=True)
class StructuredEligibility:
    eligible: bool
    fallback: bool  # True when prompt-based JSON fallback was applied
    reason: str = ""


def eligible_for_structured(
    *,
    capabilities_verified: dict[str, bool],
    allow_json_fallback: bool = False,
) -> StructuredEligibility:
    """May this adapter serve a structured-output-required task?"""
    if capabilities_verified.get("structured_output"):
        return StructuredEligibility(True, False)
    if allow_json_fallback:
        return StructuredEligibility(
            True,
            True,
            "adapter lacks verified structured output; using prompt-based "
            "JSON + validation fallback",
        )
    return StructuredEligibility(
        False, False, "no verified structured-output capability"
    )


__all__ = [
    "CapabilityRow",
    "StructuredEligibility",
    "build_matrix",
    "eligible_for_structured",
    "verify_adapter",
]
