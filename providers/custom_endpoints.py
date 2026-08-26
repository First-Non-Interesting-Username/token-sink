"""User-defined OpenAI-compatible endpoints (PLAN Phase 3, §8.2 — issue #250).

Custom endpoints let an operator point the system at any OpenAI-compatible
base URL (self-hosted gateways, proxies, alternate providers) with:

- A validated config schema: endpoint id, base URL, api-key *reference*
  (env var name, §15 — never a literal secret), model list, and per-endpoint
  rate limits.
- Free/paid classification that is **user-declared** for custom endpoints and
  defaults to ``unknown``. Under free-only routing, models with status
  ``unknown`` are hard-blocked — consistent with #66/#87 semantics.
- Startup validation with actionable, key-path-addressed error messages.
- Redaction-safe rendering: endpoints never leak API keys into logs; only
  the env var *name* is ever stored or displayed (coordinate with the
  redaction pipeline via ``safe_repr``).
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from providers.free_status import FREE_ROUTABLE, FreeStatus

# http(s) base URLs only — no file://, no bare host without scheme.
_ALLOWED_SCHEMES = {"http", "https"}


class EndpointConfigError(Exception):
    """Invalid custom-endpoint configuration; message names the offending key."""


class UnclassifiedModelError(EndpointConfigError):
    """A model with unknown free-status was selected under free-only mode."""


class ModelStatus(enum.StrEnum):
    """User-declared free/paid classification for custom-endpoint models."""

    FREE = "free"
    PAID = "paid"
    UNKNOWN = "unknown"  # the default — and blocked under free-only


@dataclass(frozen=True)
class CustomEndpoint:
    """One OpenAI-compatible endpoint declared by the operator."""

    endpoint_id: str
    base_url: str
    api_key_env_var: str  # reference only — never the secret itself
    models: dict[str, ModelStatus] = field(default_factory=dict)
    max_concurrent_requests: int = 4

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", self.endpoint_id):
            raise EndpointConfigError(
                f"providers.custom_endpoints.{self.endpoint_id}: id must match [a-z0-9][a-z0-9_-]*"
            )
        parsed = urlparse(self.base_url)
        if parsed.scheme not in _ALLOWED_SCHEMES or not parsed.netloc:
            raise EndpointConfigError(
                f"providers.custom_endpoints.{self.endpoint_id}.base_url: "
                f"{self.base_url!r} is not a valid http(s) URL"
            )
        if not self.api_key_env_var.isidentifier() or self.api_key_env_var.islower():
            raise EndpointConfigError(
                f"providers.custom_endpoints.{self.endpoint_id}.api_key_env_var: "
                f"{self.api_key_env_var!r} does not look like an env var name "
                "(credentials are references, never literal values — PLAN §15)"
            )
        if self.max_concurrent_requests < 1:
            raise EndpointConfigError(
                f"providers.custom_endpoints.{self.endpoint_id}."
                "max_concurrent_requests: must be >= 1"
            )

    @classmethod
    def from_config(cls, endpoint_id: str, raw: object) -> CustomEndpoint:
        """Build from the raw YAML section with actionable errors."""
        prefix = f"providers.custom_endpoints.{endpoint_id}"
        if not isinstance(raw, dict):
            raise EndpointConfigError(f"{prefix}: must be a mapping")
        missing = [k for k in ("base_url", "api_key_env_var") if k not in raw]
        if missing:
            raise EndpointConfigError(f"{prefix}: missing required keys {missing}")
        raw_models = raw.get("models", {})
        if not isinstance(raw_models, dict):
            raise EndpointConfigError(f"{prefix}.models: must map model name -> status")
        models: dict[str, ModelStatus] = {}
        for name, status in raw_models.items():
            try:
                models[str(name)] = ModelStatus(str(status).lower())
            except ValueError:
                raise EndpointConfigError(
                    f"{prefix}.models.{name}: status must be one of "
                    f"{[s.value for s in ModelStatus]}"
                ) from None
        mcr = raw.get("max_concurrent_requests", 4)
        if isinstance(mcr, bool) or not isinstance(mcr, int) or mcr < 1:
            raise EndpointConfigError(f"{prefix}.max_concurrent_requests: must be an integer >= 1")
        return cls(
            endpoint_id=endpoint_id,
            base_url=str(raw["base_url"]),
            api_key_env_var=str(raw["api_key_env_var"]),
            models=models,
            max_concurrent_requests=mcr,
        )

    def safe_repr(self) -> str:
        """Log-safe rendering: shows the env-var NAME, never a key value."""
        return (
            f"CustomEndpoint(id={self.endpoint_id!r}, base_url={self.base_url!r}, "
            f"api_key=<$'{self.api_key_env_var}'>)"
        )


def check_free_only(endpoint: CustomEndpoint, model: str) -> None:
    """Hard block for free-only routing (#66): unknown ⇒ excluded.

    Only explicitly-declared ``free`` models on custom endpoints are
    routable under free-only mode; ``paid`` and undeclared/``unknown``
    models both fail with an actionable message.
    """
    status = endpoint.models.get(model, ModelStatus.UNKNOWN)
    if status == ModelStatus.FREE and FreeStatus.FREE in FREE_ROUTABLE:
        return
    raise UnclassifiedModelError(
        f"model {model!r} on endpoint {endpoint.endpoint_id!r} has free "
        f"status {status.value!r}; free-only mode requires an explicit "
        "'free' classification in the endpoint's models list"
    )


def parse_custom_endpoints(raw: object) -> dict[str, CustomEndpoint]:
    """Validate the whole ``providers.custom_endpoints`` mapping.

    Collects every endpoint's errors so an operator fixes all of them in a
    single startup round-trip (§16 convention shared with config/loader).
    """
    errors: list[str] = []
    endpoints: dict[str, CustomEndpoint] = {}
    if raw is None:
        return endpoints
    if not isinstance(raw, dict):
        raise EndpointConfigError("providers.custom_endpoints: must be a mapping")
    for raw_id, body in raw.items():
        endpoint_id = str(raw_id).lower()
        try:
            ep = CustomEndpoint.from_config(endpoint_id, body)
        except EndpointConfigError as e:
            errors.append(str(e))
            continue
        if ep.endpoint_id in endpoints:
            errors.append(f"providers.custom_endpoints.{endpoint_id}: duplicate id")
            continue
        endpoints[ep.endpoint_id] = ep
    if errors:
        raise EndpointConfigError(
            "invalid custom endpoint configuration:\n" + "\n".join(f"  - {e}" for e in errors)
        )
    return endpoints
