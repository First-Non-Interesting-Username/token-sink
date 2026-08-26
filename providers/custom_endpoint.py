"""Custom provider endpoint configuration (issue #250, PLAN Phase 3, §8.2).

Phase 3 requires "custom endpoint configuration": operators can point the
system at arbitrary OpenAI-compatible base URLs (self-hosted gateways,
aggregators, internal proxies) alongside the built-in providers.

Design decisions (per AGENTS.md documentation rules):

- Config-shaped and validation-first like ``config/loader.py``: all errors
  are collected with key paths, never raised one at a time.
- Credentials are *references* (env var names, PLAN §16/§15), never
  literal values — same rule as the main credentials map.
- Free/paid classification of a custom endpoint's models is **declared by
  the operator** (they know their gateway's pricing) but defaults to
  ``unknown``. Per PLAN §8.2 "unknown ⇒ excluded until confirmed":
  under free-only mode an unknown-status custom model is blocked from
  routing exactly like an unknown catalog model (:mod:`routers.free_only`
  performs that gate; this module supplies the declared status resolver).
- Per-endpoint rate limits reuse the shape of ``policy.scope.RateLimit``
  (requests + per_seconds) so the shared limiter can consume them as-is.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "CustomEndpoint",
    "CustomEndpointError",
    "CustomEndpointRegistry",
    "EndpointClassification",
    "validate_custom_endpoints",
]

# https scheme is required; host must be present. Localhost endpoints are
# allowed (local gateways are a primary use case) but must still be https
# in production configs — plain http is accepted only for explicit
# loopback hosts, mirroring §15's local-first posture.
_HTTP_OK_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}

_URL_RE = re.compile(r"^https?://[^/\s]+(/[^\s]*)?$")

_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")


class EndpointClassification(enum.StrEnum):
    """Operator-declared pricing classification for a custom endpoint."""

    UNKNOWN = "unknown"
    FREE = "free"
    PAID = "paid"


@dataclass(frozen=True)
class _RateLimitShape:
    """Minimal mirror of policy.scope.RateLimit (avoids import cycle)."""

    max_requests: int
    per_seconds: float


@dataclass(frozen=True)
class CustomEndpoint:
    """One user-defined OpenAI-compatible endpoint."""

    name: str
    base_url: str
    # §16 credential reference: env var NAME holding the API key (optional —
    # some local gateways need no auth).
    api_key_env_var: str | None = None
    models: tuple[str, ...] = ()
    classification: EndpointClassification = EndpointClassification.UNKNOWN
    max_requests_per_min: int | None = None

    def status_for(self, model_id: str) -> EndpointClassification:
        """Declared classification for a model on this endpoint."""
        if model_id not in self.models:
            return EndpointClassification.UNKNOWN
        return self.classification

    def rate_limit(self) -> _RateLimitShape | None:
        if self.max_requests_per_min is None:
            return None
        return _RateLimitShape(max_requests=self.max_requests_per_min, per_seconds=60.0)


def validate_custom_endpoints(raw: object) -> tuple[list[CustomEndpoint], list[str]]:
    """Validate the ``providers.custom_endpoints`` YAML section.

    Returns ``(endpoints, errors)`` — errors carry ``custom_endpoints.<key>``
    paths so they merge cleanly into the loader's aggregated report.
    """
    errors: list[str] = []
    endpoints: list[CustomEndpoint] = []

    if raw is None:
        return endpoints, errors
    if not isinstance(raw, list):
        return endpoints, ["providers.custom_endpoints: must be a list of endpoint mappings"]

    seen_names: set[str] = set()
    for i, item in enumerate(raw):
        p = f"custom_endpoints[{i}]"
        if not isinstance(item, dict):
            errors.append(f"providers.{p}: must be a mapping")
            continue

        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"providers.{p}.name: must be a non-empty string")
            continue
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
            errors.append(
                f"providers.{p}.name: '{name}' must be lowercase alphanumeric "
                "(dashes/underscores allowed) — it becomes the provider id"
            )
            continue
        if name in seen_names:
            errors.append(f"providers.{p}.name: duplicate endpoint name '{name}'")
            continue
        seen_names.add(name)

        base_url = item.get("base_url")
        if not isinstance(base_url, str) or not _URL_RE.match(base_url):
            errors.append(f"providers.{p}.base_url: must be an absolute http(s) URL")
            continue
        lower_host = base_url.split("://", 1)[1].split("/", 1)[0].split(":")[0].lower()
        if base_url.startswith("http://") and lower_host not in _HTTP_OK_HOSTS:
            errors.append(
                f"providers.{p}.base_url: plain http is only allowed for loopback/"
                f"local hosts ({', '.join(sorted(_HTTP_OK_HOSTS))}); use https"
            )

        env_var = item.get("api_key_env_var")
        if env_var is not None:
            if not isinstance(env_var, str) or not env_var.isidentifier() or env_var.islower():
                errors.append(
                    f"providers.{p}.api_key_env_var: value '{env_var}' does not look "
                    "like an env var name (credentials are references, never literal "
                    "values — PLAN §15)"
                )
                continue

        models_raw = item.get("models", [])
        if not isinstance(models_raw, list) or not all(isinstance(m, str) for m in models_raw):
            errors.append(f"providers.{p}.models: must be a list of model-id strings")
            continue
        models: list[str] = []
        bad_models = [m for m in models_raw if not _MODEL_ID_RE.match(m)]
        if bad_models:
            errors.append(
                f"providers.{p}.models: invalid model ids {bad_models!r} "
                "(allowed: alphanumerics, . _ : / -)"
            )
            continue
        if len(set(models_raw)) != len(models_raw):
            errors.append(f"providers.{p}.models: duplicate model ids")
            continue
        models = list(models_raw)

        cls_raw = item.get("classification", EndpointClassification.UNKNOWN.value)
        try:
            classification = EndpointClassification(cls_raw)
        except ValueError:
            errors.append(
                f"providers.{p}.classification: must be one of "
                f"{', '.join(c.value for c in EndpointClassification)} "
                "(defaults to unknown; unknown models are blocked under free-only mode)"
            )
            continue

        rpm = item.get("max_requests_per_min")
        if rpm is not None and (not isinstance(rpm, int) or isinstance(rpm, bool) or rpm <= 0):
            errors.append(f"providers.{p}.max_requests_per_min: must be a positive integer")
            continue

        endpoints.append(
            CustomEndpoint(
                name=name,
                base_url=base_url,
                api_key_env_var=env_var,
                models=tuple(models),
                classification=classification,
                max_requests_per_min=rpm,
            )
        )

    return endpoints, errors


class CustomEndpointError(ValueError):
    """Raised when a lookup references an unknown endpoint/model."""


class CustomEndpointRegistry:
    """Runtime lookup over validated custom endpoints.

    Provides the status resolver surface the free-only gate expects:
    ``status_for(provider, model) -> FreeStatus-compatible value``, where
    custom endpoints default to UNKNOWN and never claim FREE without an
    explicit operator declaration.
    """

    def __init__(self, endpoints: list[CustomEndpoint] | None = None) -> None:
        self._by_name: dict[str, CustomEndpoint] = {}
        for ep in endpoints or []:
            if ep.name in self._by_name:
                raise CustomEndpointError(f"duplicate endpoint name '{ep.name}'")
            self._by_name[ep.name] = ep

    def get(self, name: str) -> CustomEndpoint:
        try:
            return self._by_name[name]
        except KeyError:
            raise CustomEndpointError(f"unknown custom endpoint '{name}'") from None

    @property
    def names(self) -> list[str]:
        return sorted(self._by_name)

    def status_for(self, provider: str, model_id: str) -> EndpointClassification:
        """Status resolver compatible with the free-only gate.

        Unknown providers resolve UNKNOWN rather than raising — the free-only
        gate blocks UNKNOWN, which is the safe direction (fail closed).
        """
        ep = self._by_name.get(provider)
        if ep is None:
            return EndpointClassification.UNKNOWN
        return ep.status_for(model_id)

    def free_only_violations(self, provider: str, model_id: str) -> bool:
        """True when free-only mode must block this (provider, model)."""
        return self.status_for(provider, model_id) is not EndpointClassification.FREE

    def rate_limit_for(self, provider: str) -> _RateLimitShape | None:
        ep = self._by_name.get(provider)
        return ep.rate_limit() if ep else None


def make_status_resolver(
    registry: CustomEndpointRegistry,
    fallback: Callable[[str, str], enum.Enum],
) -> Callable[[str, str], enum.Enum]:
    """Compose a routing status resolver: custom declarations first,
    catalog fallback second. A model listed on a custom endpoint NEVER
    falls through to the catalog fallback — an undeclared custom model
    stays UNKNOWN (blocked under free-only), it does not inherit some
    other provider's free status.
    """
    cache: dict[tuple[str, str], enum.Enum] = {}

    def resolve(provider: str, model_id: str) -> enum.Enum:
        key = (provider, model_id)
        if key not in cache:
            ep = registry._by_name.get(provider)
            if ep is not None and ep.models:
                # Custom endpoint owns its models' classification entirely.
                cache[key] = ep.status_for(model_id)
            else:
                cache[key] = fallback(provider, model_id)
        return cache[key]

    return resolve
