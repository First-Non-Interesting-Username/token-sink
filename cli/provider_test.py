"""``token-sink provider test <id>`` (PLAN Phase 3, §8.2, issue #250).

Exercises connectivity + model listing against a configured custom endpoint
and reports health. Safety properties:

- The API key is read from the referenced env var at call time and sent only
  in the Authorization header — it is NEVER printed, logged, or included in
  any error message. Errors surface only status codes and exception *types*.
- Only the configured provider endpoint is contacted; this command never
  touches campaign targets.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from config.loader import Config, CustomEndpoint


class EndpointResult:
    """Outcome of one probe; ``key_leaked`` stays False by construction."""

    def __init__(
        self,
        name: str,
        ok: bool,
        status: str,
        models: list[str] | None = None,
        latency_ms: int | None = None,
    ) -> None:
        self.name = name
        self.ok = ok
        self.status = status  # human-safe: no headers, no key material
        self.models = models or []
        self.latency_ms = latency_ms

    def render(self) -> str:
        lines = [f"{self.name}: {'PASS' if self.ok else 'FAIL'} — {self.status}"]
        if self.models:
            shown = ", ".join(self.models[:10])
            more = f" (+{len(self.models) - 10} more)" if len(self.models) > 10 else ""
            lines.append(f"  models: {shown}{more}")
        return "\n".join(lines)


def _auth_headers(ep: CustomEndpoint) -> dict[str, str]:
    # Key goes from env straight into the header; never into logs/exceptions.
    if ep.api_key_env_var:
        key = os.environ.get(ep.api_key_env_var, "")
        if key:
            return {"Authorization": f"Bearer {key}"}
    return {}


def test_endpoint(
    ep: CustomEndpoint,
    *,
    timeout_s: float | None = None,
    urlopen=None,
) -> EndpointResult:
    """Probe ``GET {base_url}/models`` and report connectivity + model list.

    ``urlopen`` is injectable for tests.
    """
    opener = urlopen or urllib.request.urlopen
    url = ep.base_url.rstrip("/") + "/models"
    import time

    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers=_auth_headers(ep), method="GET")
        with opener(req, timeout=timeout_s or ep.timeout_s) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        latency = int((time.monotonic() - start) * 1000)
        # OpenAI-compatible shape: {"data": [{"id": "..."}, ...]}
        data = body.get("data") if isinstance(body, dict) else None
        models = (
            [m.get("id", "") for m in data if isinstance(m, dict)] if isinstance(data, list) else []
        )
        return EndpointResult(
            ep.name, True, "reachable, model list OK", models=models, latency_ms=latency
        )
    except urllib.error.HTTPError as e:
        # e.headers/e.read() may echo request info; report ONLY the code.
        return EndpointResult(ep.name, False, f"HTTP {e.code}")
    except Exception as exc:  # noqa: BLE001 — type name only, never contents
        return EndpointResult(ep.name, False, type(exc).__name__)


def run_provider_test(cfg: Config, endpoint_id: str) -> int:
    """CLI entrypoint. Returns process exit code."""
    eps = [e for e in cfg.custom_endpoints if e.name == endpoint_id]
    if not eps:
        known = ", ".join(e.name for e in cfg.custom_endpoints) or "(none configured)"
        print(f"unknown endpoint '{endpoint_id}'. configured: {known}")
        return 2
    res = test_endpoint(eps[0])
    print(res.render())
    return 0 if res.ok else 1


def collect_all(cfg: Config) -> list[EndpointResult]:
    """Probe every configured custom endpoint (used by doctor/tests)."""
    results: list[EndpointResult] = []
    for ep in cfg.custom_endpoints:
        r: EndpointResult = test_endpoint(ep)
        results.append(r)
    return results
