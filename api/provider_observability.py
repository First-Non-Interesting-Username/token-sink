"""Provider & model observability API + view model (issue #240, PLAN §13
view 4, §8.1–§8.4, §14).

Design decisions (per AGENTS.md):

- **Aggregation only — no parallel source of truth.** Every number rendered
  here comes from an existing subsystem: ``providers.health`` for probe state,
  latency and quota; ``observability.metrics`` for request/error/timeout and
  rate-limit counters (model/provider family); ``evaluation.scores`` for the
  per-category score WITH its Wilson confidence interval and sample count;
  ``storage.usage`` for token/cost totals and free-vs-paid split;
  ``providers.free_status`` for the routing-relevant free/paid classification.
- **Confidence is mandatory in output.** §8.3 requires exposing score
  confidence: a model with 2 observations must visibly show a wide interval.
  The view carries both interval bounds and sample count so the UI can never
  render a bare point estimate as if it were certain.
- **Unknown free-status means excluded.** Per PLAN §8.2 ("unknown ⇒ excluded
  until confirmed"), models whose effective free status is unknown are
  flagged ``excluded_from_free_routing=True`` so the UI renders them as such
  rather than optimistically free-eligible.
- **Redaction posture**: error drill-down surfaces provider-side error codes
  and timestamps only — never target data or prompts (PLAN §13.7).
- Same stdlib HTTP-server shape as api/approvals.py (loopback default), plus
  a pure ``ProviderObservabilityView`` core that tests exercise directly.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from observability.event_store import EventStore


def _pct(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile; None when no data."""
    if not values:
        return None
    s = sorted(values)
    idx = max(0, min(len(s) - 1, round(p / 100 * (len(s) - 1))))
    return s[idx]


@dataclass
class ViewDeps:
    """Existing stores the view aggregates from (all optional individually)."""

    health_monitor: Any = None  # providers.health.ProviderHealthMonitor
    metrics: Any = None  # observability.metrics.MetricsStore
    scores: Any = None  # evaluation.scores.ScoreStore
    usage: Any = None  # storage.usage.UsageStore
    free_status: Any = None  # providers.free_status.VerificationStore
    events: EventStore | None = None


@dataclass
class ProviderObservabilityView:
    """Builds the PLAN §13 view-4 payload from existing subsystems."""

    deps: ViewDeps
    _emitted_event_ids: set[int] = field(default_factory=set)

    # -- aggregation --------------------------------------------------------

    def provider_summary(self) -> list[dict[str, Any]]:
        monitor = self.deps.health_monitor
        rows = list(monitor.status_page()) if monitor else []
        for row in rows:
            prov = row["provider"]
            lat = self._latency_samples(prov)
            row["latency_p50_ms"] = _pct(lat, 50)
            row["latency_p95_ms"] = _pct(lat, 95)
            row["requests"], row["errors"], row["timeouts"], row["rate_limited"] = self._counters(
                prov
            )
        return rows

    def model_rows(
        self, *, since: float | None = None, until: float | None = None
    ) -> list[dict[str, Any]]:
        """Per-model rows: scores+CI, usage split, free-status eligibility."""
        out: dict[tuple[str, str], dict[str, Any]] = {}

        scores = self.deps.scores
        if scores:
            for entry in scores.entries():
                key = (entry.provider, entry.model)
                row = out.setdefault(key, {"provider": entry.provider, "model": entry.model})
                lo, hi = entry.wilson_interval
                row.setdefault("scores", {})[entry.category] = {
                    "score": round(entry.score, 4),
                    "ci_low": round(lo, 4),
                    "ci_high": round(hi, 4),
                    "n_observations": entry.n_observations,
                }

        usage = self.deps.usage
        if usage:
            for dim_row in usage.breakdown("model_id", since=since, until=until):
                # breakdown keys by model id; attach tokens/cost to any
                # matching model row regardless of provider spelling.
                mid = dim_row.get("model_id")
                for key, row in out.items():
                    if key[1] == mid:
                        row["tokens_total"] = dim_row.get("total_tokens")
                        row["cost_usd"] = dim_row.get("total_cost_usd")

        fs = self.deps.free_status
        for (prov, model), row in out.items():
            row["free_status"] = (
                "unknown" if fs is None else self._effective_status(fs, prov, model)
            )
            row["excluded_from_free_routing"] = row["free_status"] != "free"
        return sorted(out.values(), key=lambda r: (r["provider"], r["model"]))

    def recent_errors(self, provider: str, limit: int = 10) -> list[dict[str, Any]]:
        """Display-safe error drill-down: codes/timestamps only (§13.7)."""
        metrics = self.deps.metrics
        if not metrics:
            return []
        errs = metrics.raw(family="provider", name="request_error", tags={"provider": provider})
        return [
            {
                "ts": s.ts,
                "error_code": s.tags.get("error_code", "unknown"),
                "model": s.tags.get("model"),
            }
            for s in errs[-limit:]
        ]

    def health_events_since(self, last_event_id: int):
        """Reconnect support: replay health-delta events after an ID (#256)."""
        if self.deps.events is None:
            return []
        result = self.deps.events.replay_after(last_event_id)
        return [e for e in result.events if e.type == "provider_health"]

    # -- helpers ------------------------------------------------------------

    def _effective_status(self, fs: Any, provider: str, model: str) -> str:
        try:
            store_map = getattr(fs, "_records", None) or {}
            for rec in store_map.values():
                if rec.provider == provider and rec.model_id == model:
                    st = rec.effective_status(now=float("inf"), current_pricing_hash=None)
                    return st.value
        except Exception:
            pass
        return "unknown"

    def _latency_samples(self, provider: str) -> list[float]:
        if not self.deps.metrics:
            return []
        return [
            s.value
            for s in self.deps.metrics.raw(
                family="provider", name="request_latency_ms", tags={"provider": provider}
            )
        ]

    def _counters(self, provider: str) -> tuple[int, int, int, int]:
        m = self.deps.metrics
        if not m:
            return 0, 0, 0, 0

        def count(name: str) -> int:
            return len(m.raw(family="provider", name=name, tags={"provider": provider}))

        return (
            count("request_ok") + count("request_error") + count("request_timeout"),
            count("request_error"),
            count("request_timeout"),
            count("rate_limited"),
        )


class ProviderObservabilityApiServer:
    """Loopback HTTP surface over the view (same shape as approvals API)."""

    def __init__(self, view: ProviderObservabilityView, host: str = "127.0.0.1", port: int = 0):
        self.view = view
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def handle(
        self, method: str, path: str, query: dict[str, str] | None = None
    ) -> tuple[int, dict]:
        parts = [p for p in path.strip("/").split("/") if p]
        q = query or {}
        if method == "GET" and parts == ["providers"]:
            return 200, {"providers": self.view.provider_summary()}
        if method == "GET" and parts == ["models"]:
            since = float(q["since"]) if "since" in q else None
            until = float(q["until"]) if "until" in q else None
            return 200, {"models": self.view.model_rows(since=since, until=until)}
        if method == "GET" and len(parts) == 3 and parts[0] == "providers" and parts[2] == "errors":
            return 200, {"errors": self.view.recent_errors(parts[1])}
        return 404, {"error": f"no route for {method} {path}"}

    def start(self) -> str:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _dispatch(self) -> None:
                from urllib.parse import parse_qs, urlparse

                parsed = urlparse(self.path)
                query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                status, payload = (
                    server.handle(self.command, parsed.path, query)
                    if not body
                    else (500, {"error": "GET-only API"})
                )
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _dispatch

            def log_message(self, format: str, *args: Any) -> None:  # silence test noise
                pass

        self._httpd = ThreadingHTTPServer((self._host, self._port), Handler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://{self._host}:{self._port}"

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
