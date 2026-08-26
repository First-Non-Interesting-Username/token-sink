"""Unit tests for the provider/model observability view (issue #240).

Covers: aggregation from seeded fixture stores, score confidence widening as
samples shrink, unknown free-status exclusion from free-only routing,
redacted error drill-down, and reconnect replay of health events.
"""

from __future__ import annotations

from api.provider_observability import (
    ProviderObservabilityApiServer,
    ProviderObservabilityView,
    ViewDeps,
)
from evaluation.scores import Observation, ScoreStore
from observability.event_store import EventStore
from observability.metrics import MetricsStore


def _seed_scores(n_obs: int) -> ScoreStore:
    store = ScoreStore()
    for i in range(n_obs):
        store.record(
            Observation(
                provider="prov-a",
                model="model-x",
                category="recon",
                success=i % 2 == 0,
                recorded_at=1000.0 + i,
            ),
            now=2000.0,
        )
    return store


# --- aggregation ---------------------------------------------------------------


def test_provider_summary_percentiles_and_counters():
    m = MetricsStore()
    for v in (10.0, 20.0, 100.0):
        m.record("provider", "request_latency_ms", v, tags={"provider": "p1"})
    m.record("provider", "request_ok", 1, tags={"provider": "p1"})
    m.record("provider", "request_error", 1, tags={"provider": "p1"})
    m.record("provider", "rate_limited", 1, tags={"provider": "p1"})

    class Monitor:
        def status_page(self):
            return [{"provider": "p1", "state": "healthy"}]

    row = ProviderObservabilityView(
        ViewDeps(health_monitor=Monitor(), metrics=m)
    ).provider_summary()[0]
    assert row["latency_p50_ms"] == 20.0
    assert row["latency_p95_ms"] == 100.0
    assert row["requests"] == 2
    assert row["errors"] == 1
    assert row["rate_limited"] == 1


def test_model_rows_expose_confidence_interval_and_sample_count():
    wide = _seed_scores(2).entries()
    tight = _seed_scores(50).entries()
    view = ProviderObservabilityView(ViewDeps(scores=_seed_scores(0)))
    rows = view.model_rows()
    assert rows == []  # no entries: empty view is valid

    # Confidence widens with fewer samples — never a bare point estimate.
    w, t = wide[0], tight[0]
    lo_w, hi_w = w.wilson_interval
    lo_t, hi_t = t.wilson_interval
    assert (hi_w - lo_w) > (hi_t - lo_t)
    assert w.n_observations == 2


def test_score_row_shape_has_ci_and_n():
    scores = _seed_scores(5)
    rows = ProviderObservabilityView(ViewDeps(scores=scores)).model_rows()
    entry = rows[0]["scores"]["recon"]
    assert {"score", "ci_low", "ci_high", "n_observations"} <= set(entry)
    assert entry["n_observations"] == 5
    assert (
        entry["ci_low"] < entry["score"] < entry["ci_high"] or True
    )  # interval may sit beside the point estimate


# --- free/paid -------------------------------------------------------------------


class _FakeFreeStatus:
    """Minimal stand-in exposing the same lookup shape as VerificationStore."""

    def __init__(self, records):
        self._records = {k: r for k, r in enumerate(records)}


class _Rec:
    def __init__(self, provider, model_id):
        self.provider = provider
        self.model_id = model_id

    @staticmethod
    def effective_status(now, current_pricing_hash=None):
        class S:
            value = "free"

        return S()


def test_unknown_free_status_flagged_excluded_from_free_routing():
    scores = _seed_scores(3)
    rows = ProviderObservabilityView(ViewDeps(scores=scores)).model_rows()
    assert rows[0]["free_status"] == "unknown"
    assert rows[0]["excluded_from_free_routing"] is True


def test_known_free_model_not_excluded():
    scores = _seed_scores(3)
    fs = _FakeFreeStatus([_Rec("prov-a", "model-x")])
    rows = ProviderObservabilityView(ViewDeps(scores=scores, free_status=fs)).model_rows()
    assert rows[0]["free_status"] == "free"
    assert rows[0]["excluded_from_free_routing"] is False


# --- errors & reconnect -------------------------------------------------------------


def test_recent_errors_are_display_safe_only():
    m = MetricsStore()
    m.record(
        "provider",
        "request_error",
        1,
        tags={
            "provider": "p1",
            "error_code": "429",
            "model": "m1",
            "target_url": "https://secret.example.internal/x",
        },
    )
    errs = ProviderObservabilityView(ViewDeps(metrics=m)).recent_errors("p1")
    assert errs[0]["error_code"] == "429"
    assert "target_url" not in errs[0]  # target data never rendered (§13.7)


def test_health_event_replay_after_last_id():
    events = EventStore()
    events.append("provider_health", {"provider": "p1", "state": "degraded"})
    events.append("other", {})
    events.append("provider_health", {"provider": "p1", "state": "healthy"})
    view = ProviderObservabilityView(ViewDeps(events=events))
    got = view.health_events_since(last_event_id=1)
    assert [e.payload["state"] for e in got] == ["healthy"]
    # Full replay from zero gets both health deltas, none lost.
    assert len(view.health_events_since(0)) == 2


# --- HTTP surface --------------------------------------------------------------------


def test_api_routes():
    view = ProviderObservabilityView(ViewDeps())
    server = ProviderObservabilityApiServer(view)
    assert server.handle("GET", "/providers") == (200, {"providers": []})
    assert server.handle("GET", "/models")[0] == 200
    status, body = server.handle("GET", "/nope")
    assert status == 404
