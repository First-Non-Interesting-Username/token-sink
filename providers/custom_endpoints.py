"""Custom OpenAI-compatible endpoints (issue #250, PLAN Phase 3 §8.2 / §16).

Operators can point token-sink at arbitrary OpenAI-compatible base URLs:

```yaml
providers:
  free_only: true
  custom_endpoints:
    - id: my-relay
      base_url: https://relay.example.com/v1
      credential_ref: MY_RELAY_API_KEY      # env var NAME — never a literal key
      models: [model-a, model-b]
      status: unknown                        # unknown | free | paid
      max_concurrent: 4
      timeout_s: 60
```

Rules:

- **Credential refs only.** Like ``providers.credentials``, values must look
  like env var names; a literal-looking key is a config error (§15).
- **Free/paid classification is user-declared and defaults to ``unknown``.**
  Unknown-status endpoints are BLOCKED under ``free_only`` mode — fail
  closed, mirroring the model-catalog rule ("unknown ⇒ excluded until
  confirmed").
- **Startup validation with actionable errors** via the standard
  ``ConfigError`` path; every problem is collected, not just the first.
- **Keys never leak into logs**: the only place a resolved key exists is
  inside :func:`resolve_endpoint_key`, which callers pass straight into an
  HTTP client; all reporting paths carry the endpoint *id*, never the key.
- ``provider test <id>`` CLI exercises connectivity + model listing and
  reports health (:class:`EndpointTestResult`), using the same probe shape
  as ``providers/health.py`` so results feed the monitor unchanged.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from src.tokensink.redaction import redact

# User-declared statuses for a custom endpoint's models. Anything outside
# this set is a config error; anything but "free" is blocked under free_only.
VALID_STATUSES = ("unknown", "free", "paid")
DEFAULT_STATUS = "unknown"


class EndpointConfigError(ValueError):
    """A single custom-endpoint definition is invalid."""


@dataclass
class CustomEndpoint:
    """One user-defined OpenAI-compatible endpoint."""

    id: str
    base_url: str
    credential_ref: str | None = None  # env var NAME holding the API key
    models: list[str] = field(default_factory=list)
    status: str = DEFAULT_STATUS
    max_concurrent: int = 2
    timeout_s: int = 60

    def to_dict(self) -> dict:
        # Never includes any secret material — only the REF name.
        return {
            "id": self.id,
            "base_url": self.base_url,
            "credential_ref": self.credential_ref,
            "models": list(self.models),
            "status": self.status,
            "max_concurrent": self.max_concurrent,
            "timeout_s": self.timeout_s,
        }


def parse_custom_endpoints(raw: object) -> tuple[list[CustomEndpoint], list[str]]:
    """Validate the raw ``providers.custom_endpoints`` YAML section.

    Returns ``(endpoints, errors)`` where each error string is prefixed with
    its config path so startup messages point at the offending field.
    """
    errors: list[str] = []
    if raw is None:
        return [], errors
    if not isinstance(raw, list):
        return [], ["providers.custom_endpoints: must be a list of endpoint mappings"]

    endpoints: list[CustomEndpoint] = []
    seen_ids: set[str] = set()

    for i, item in enumerate(raw):
        prefix = f"providers.custom_endpoints[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue

        ep_id = item.get("id")
        if not isinstance(ep_id, str) or not ep_id.strip():
            errors.append(f"{prefix}.id: required, must be a non-empty string")
            continue
        if not ep_id.replace("-", "_").isidentifier():
            errors.append(f"{prefix}.id ('{ep_id}'): use letters, digits, hyphens/underscores")
            continue
        if ep_id in seen_ids:
            errors.append(f"{prefix}.id ('{ep_id}'): duplicate endpoint id")
            continue
        seen_ids.add(ep_id)

        base_url = item.get("base_url")
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            errors.append(
                f"{prefix}.base_url: must be an http(s) URL (e.g. https://host.example.com/v1)"
            )
            continue

        cred = item.get("credential_ref")
        if cred is not None:
            if not isinstance(cred, str) or not cred.isidentifier() or cred.islower():
                errors.append(
                    f"{prefix}.credential_ref ('{cred}'): does not look like an env "
                    "var name — credentials are references, never literal values"
                )
                continue
            if cred not in os.environ:
                errors.append(f"{prefix}.credential_ref: referenced env var '{cred}' is not set")
                continue

        models = item.get("models", [])
        if not isinstance(models, list) or not all(isinstance(m, str) and m for m in models):
            errors.append(f"{prefix}.models: must be a list of non-empty strings")
            continue

        status = item.get("status", DEFAULT_STATUS)
        if status not in VALID_STATUSES:
            errors.append(
                f"{prefix}.status ('{status}'): must be one of {', '.join(VALID_STATUSES)} "
                "(classification is user-declared; 'unknown' is blocked under free_only)"
            )
            continue

        max_concurrent = item.get("max_concurrent", 2)
        timeout_s = item.get("timeout_s", 60)
        if (
            not isinstance(max_concurrent, int)
            or isinstance(max_concurrent, bool)
            or max_concurrent < 1
        ):
            errors.append(f"{prefix}.max_concurrent: must be a positive integer")
            continue
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s < 1:
            errors.append(f"{prefix}.timeout_s: must be a positive integer")
            continue

        endpoints.append(
            CustomEndpoint(
                id=ep_id,
                base_url=base_url.rstrip("/"),
                credential_ref=cred,
                models=list(models),
                status=status,
                max_concurrent=max_concurrent,
                timeout_s=timeout_s,
            )
        )

    return endpoints, errors


def blocked_under_free_only(endpoints: list[CustomEndpoint], free_only: bool) -> list[str]:
    """IDs of endpoints whose status excludes them under free-only mode.

    Fail closed: everything not explicitly declared ``free`` is blocked.
    """
    if not free_only:
        return []
    return [e.id for e in endpoints if e.status != "free"]


def resolve_endpoint_key(endpoint: CustomEndpoint) -> str | None:
    """Resolve the credential ref to the actual key at use time.

    The returned value must go straight into an HTTP client and never be
    logged or serialized. Returns None when the endpoint declares no ref.
    """
    if endpoint.credential_ref is None:
        return None
    return os.environ.get(endpoint.credential_ref)


@dataclass
class EndpointTestResult:
    """Outcome of `provider test <id>` for one custom endpoint."""

    endpoint_id: str
    reachable: bool
    latency_ms: float | None = None
    models: list[str] = field(default_factory=list)
    error: str | None = None

    def to_human(self) -> str:
        # Redact defensively even here: error bodies sometimes echo headers.
        err = ""
        if self.error:
            err = f" — {redact(self.error).text}"
        if not self.reachable:
            return f"[{self.endpoint_id}] FAIL{err}"
        models = ", ".join(self.models) if self.models else "(no models listed)"
        return f"[{self.endpoint_id}] OK ({self.latency_ms:.0f} ms) models: {models}{err}"


def test_endpoint(
    endpoint: CustomEndpoint,
    timeout_s: float | None = None,
    opener=None,
) -> EndpointTestResult:
    """Exercise connectivity + model listing against a custom endpoint.

    Performs a GET on ``{base_url}/models`` (the one cheap authenticated
    route every OpenAI-compatible server implements). Network calls go
    through ``opener`` when given so tests inject fakes without sockets.
    """
    timeout = timeout_s if timeout_s is not None else endpoint.timeout_s
    url = f"{endpoint.base_url}/models"
    req = urllib.request.Request(url, method="GET")
    key = resolve_endpoint_key(endpoint)
    if key is not None:
        req.add_header("Authorization", f"Bearer {key}")

    start = time.monotonic()
    try:
        open_fn = opener.open if opener is not None else urllib.request.urlopen
        with open_fn(req, timeout=timeout) as resp:  # type: ignore[operator]
            body = json.loads(resp.read().decode("utf-8"))
        latency_ms = (time.monotonic() - start) * 1000.0
    except urllib.error.HTTPError as exc:
        return EndpointTestResult(
            endpoint_id=endpoint.id,
            reachable=False,
            error=f"HTTP {exc.code} from {url}",
        )
    except Exception as exc:  # noqa: BLE001 — report, don't crash the CLI
        return EndpointTestResult(endpoint_id=endpoint.id, reachable=False, error=str(exc))

    models: list[str] = []
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, list):
        models = [m.get("id") for m in data if isinstance(m, dict) and isinstance(m.get("id"), str)]
    models = [m for m in models if m is not None]

    return EndpointTestResult(
        endpoint_id=endpoint.id,
        reachable=True,
        latency_ms=latency_ms,
        models=models,
    )
