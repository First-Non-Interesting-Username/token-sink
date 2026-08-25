"""Safety tests: NO routing path may escape free-only mode (issue #66, §19.1).

These are the §19.1 "safety-style" negative-path tests: even adversarial
shapes — fallback chains, retries/failovers, unknown catalog entries — must
be blocked in code, not merely discouraged.
"""

from __future__ import annotations

import pytest

from providers.free_status import FreeStatus
from routers.free_only import FreeOnlyGate, FreeOnlyViolation


def make_gate(table: dict[tuple[str, str], FreeStatus] | None = None) -> FreeOnlyGate:
    table = table or {}
    return FreeOnlyGate(lambda p, m: table.get((p, m), FreeStatus.UNKNOWN))


@pytest.mark.safety
def test_retry_path_cannot_select_paid_model():
    """Failover after a free model fails must re-check the next pick."""
    gate = make_gate({("p", "free"): FreeStatus.FREE})
    # Simulate: primary failed mid-flight, router retries with a paid model.
    with pytest.raises(FreeOnlyViolation):
        gate.enforce_selection("p", "paid", origin="retry")


@pytest.mark.safety
def test_fallback_chain_cannot_hide_paid_model_behind_free_primary():
    gate = make_gate(
        {
            ("p", "free"): FreeStatus.FREE,
            ("p", "paid"): FreeStatus.PAID,
        }
    )
    routable, _ = gate.filter(
        [
            type(
                "C",
                (),
                {
                    "provider": "p",
                    "model": "free",
                    "fallbacks": [{"provider": "p", "model": "paid"}],
                },
            )()
        ]
    )
    assert routable == []


@pytest.mark.safety
def test_deeply_nested_fallback_chain_fully_validated():
    gate = make_gate(
        {
            ("p", "f1"): FreeStatus.FREE,
            ("p", "f2"): FreeStatus.FREE,
            ("p", "paid3"): FreeStatus.PAID,
        }
    )
    cand = type(
        "C",
        (),
        {
            "provider": "p",
            "model": "f1",
            "fallbacks": [
                {"provider": "p", "model": "f2"},
                {"provider": "p", "model": "paid3"},
            ],
        },
    )()
    routable, blocked = gate.filter([cand])
    assert not routable
    assert any(b.model == "paid3" and b.origin.startswith("fallback") for b in blocked)


@pytest.mark.safety
def test_unknown_catalog_entry_never_routable():
    gate = make_gate()  # empty table: everything UNKNOWN
    routable, blocked = gate.filter(
        [
            type(
                "C",
                (),
                {
                    "provider": "any",
                    "model": "thing",
                    "fallbacks": [],
                },
            )()
        ]
    )
    assert not routable and blocked[0].status == "unknown"


@pytest.mark.safety
def test_no_resolver_bypass_via_missing_provider():
    # Empty provider/model strings still resolve (to UNKNOWN) and are blocked.
    gate = make_gate()
    routable, blocked = gate.filter(
        [
            type(
                "C",
                (),
                {
                    "provider": "",
                    "model": "",
                    "fallbacks": [],
                },
            )()
        ]
    )
    assert not routable and len(blocked) == 1
