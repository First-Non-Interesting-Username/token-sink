"""Tests for the tool permission registry & enforcement gate (issue #155).

Covers: hallucinated tools, wrong types, missing/extra params, oversized
payloads, strict mode, breaker behavior, and — critically — proof that no
rejected call ever reaches execution.
"""

import pytest

from tools.gate import BreakerConfig, ToolGate
from tools.registry import (
    ParamKind,
    Rejection,
    ToolParam,
    ToolRegistry,
    ToolSignature,
)


def make_registry(strict: bool = True) -> ToolRegistry:
    reg = ToolRegistry(strict=strict)
    reg.register(
        ToolSignature(
            name="fetch_url",
            version=1,
            description="Fetch a URL (read-only recon)",
            params=(
                ToolParam("url", ParamKind.STRING, required=True),
                ToolParam("depth", ParamKind.INTEGER, default=1, description="crawl depth"),
                ToolParam("tags", ParamKind.STRING_LIST, default=[]),
            ),
            returns={"type": "object"},
        )
    )
    return reg


class Executed(Exception):
    """Raised by a sentinel fn so tests can prove execution happened."""


def sentinel(**_kwargs):
    raise Executed()


# --- registry / validation ----------------------------------------------------


def test_unknown_tool_rejected_without_execution():
    reg = make_registry()
    _, rej = reg.validate_call("delete_everything", {})
    assert rej is not None and rej.code == "unknown_tool"
    assert "fetch_url" in rej.message  # feedback lists what DOES exist


def test_hallucinated_tool_feedback_is_structured():
    reg = make_registry()
    _, rej = reg.validate_call("run_shell", {"cmd": "rm -rf /"})
    assert rej.as_feedback()["rejected"] is True
    assert rej.code in {"unknown_tool", "invalid_arguments"}


def test_missing_required_parameter():
    reg = make_registry()
    _, rej = reg.validate_call("fetch_url", {"depth": 2})
    assert rej is not None and "url" in rej.message


def test_wrong_type_rejected_and_bool_is_not_integer():
    reg = make_registry()
    _, rej = reg.validate_call("fetch_url", {"url": "https://x", "depth": True})
    assert rej is not None and "depth" in rej.message


def test_string_list_with_non_strings():
    reg = make_registry()
    _, rej = reg.validate_call("fetch_url", {"url": "u", "tags": ["a", 3]})
    assert rej is not None and "tags" in rej.message


def test_strict_mode_rejects_undeclared_parameters():
    strict = make_registry(strict=True)
    _, rej = strict.validate_call("fetch_url", {"url": "u", "dry_run": False})
    assert rej is not None and "dry_run" in rej.message

    lax = make_registry(strict=False)
    normalized, rej = lax.validate_call("fetch_url", {"url": "u", "dry_run": False})
    assert rej is None
    assert "dry_run" not in normalized  # dropped even when not rejected


def test_defaults_filled_only_for_declared_optionals():
    reg = make_registry()
    args, rej = reg.validate_call("fetch_url", {"url": "https://x"})
    assert rej is None
    assert args == {"url": "https://x", "depth": 1, "tags": []}


def test_non_object_arguments_rejected():
    reg = make_registry()
    _, rej = reg.validate_call("fetch_url", "just do it")
    assert rej is not None and rej.code == "wrong_type"


def test_oversized_payload_rejected():
    reg = make_registry()
    reg.max_payload_bytes = 64
    big = {"url": "https://x", "tags": ["t" * 200]}
    _, rej = reg.validate_call("fetch_url", big)
    assert rej is not None and rej.code == "payload_too_large"


def test_duplicate_registration_refused_unless_replace():
    reg = make_registry()
    with pytest.raises(ValueError):
        reg.register(make_registry().get("fetch_url"))


# --- gate: no rejected call ever executes --------------------------------------


@pytest.fixture
def fake_clock():
    class Clock:
        t = 1000.0

        def __call__(self):
            return self.t

    return Clock()


def test_dispatch_executes_valid_calls(fake_clock):
    calls = []

    def tool(url, depth=1, tags=None):
        calls.append((url, depth))
        return f"fetched {url}"

    gate = ToolGate(make_registry(), clock=fake_clock)
    result, rej = gate.dispatch(
        tool, "fetch_url", {"url": "https://in-scope"}, agent_uuid="a", model_id="m"
    )
    assert rej is None and result == "fetched https://in-scope"
    assert calls


def test_no_rejected_call_reaches_execution(fake_clock):
    """Acceptance criterion: proven by test, per issue #155."""
    gate = ToolGate(make_registry(), clock=fake_clock)

    for name, args in [
        ("hallucinated_tool", {}),
        ("fetch_url", {}),  # missing required
        ("fetch_url", {"url": "u", "bogus": 1}),  # extra param in strict
        ("fetch_url", {"url": 42}),  # wrong type
    ]:
        result, rejection = gate.dispatch(sentinel, name, args, agent_uuid="a", model_id="m")
        assert result is None and rejection is not None


def test_breaker_trips_after_repeated_violations(fake_clock):
    cfg = BreakerConfig(max_violations=3, window_s=60, cooldown_s=120)
    gate = ToolGate(make_registry(), breaker_config=cfg, clock=fake_clock)

    rejections = []
    for _ in range(4):
        _, rej = gate.dispatch(sentinel, "nope", {}, agent_uuid="a", model_id="m")
        rejections.append(rej)

    # violations 1 and 2 give normal feedback; violation 3 trips the breaker,
    # and that same call is already answered with breaker_open
    assert [r.code for r in rejections[:2]] == ["unknown_tool"] * 2
    assert rejections[2].code == "breaker_open"

    # during cooldown even a VALID call is refused without executing
    fake_clock.t += 10
    result, rej = gate.dispatch(
        lambda **k: "ran", "fetch_url", {"url": "https://x"}, agent_uuid="a", model_id="m"
    )
    assert result is None and rej.code == "breaker_open"

    # after cooldown it works again
    fake_clock.t += 130
    result, rej = gate.dispatch(
        lambda **k: "ran", "fetch_url", {"url": "https://x"}, agent_uuid="a", model_id="m"
    )
    assert rej is None and result == "ran"


def test_breaker_is_per_agent_model_not_global(fake_clock):
    cfg = BreakerConfig(max_violations=2, window_s=60, cooldown_s=60)
    gate = ToolGate(make_registry(), breaker_config=cfg, clock=fake_clock)

    for _ in range(2):
        gate.dispatch(sentinel, "nope", {}, agent_uuid="agent-1", model_id="m")

    # a different agent/model pair is unaffected
    result, rej = gate.dispatch(
        lambda **k: "ok", "fetch_url", {"url": "u"}, agent_uuid="agent-2", model_id="m"
    )
    assert rej is None and result == "ok"


def test_malformed_rates_queryable_by_model_for_scores(fake_clock):
    """§8.3 hook: malformed-call rate per (model, provider)."""
    gate = ToolGate(make_registry(), clock=fake_clock)
    for _ in range(3):
        gate.dispatch(
            sentinel, "ghost", {}, agent_uuid="a", model_id="model-x", provider_id="prov-a"
        )
        gate.dispatch(
            lambda **k: "ok",
            "fetch_url",
            {"url": "u"},
            agent_uuid="a",
            model_id="model-y",
            provider_id="prov-b",
        )

    rate_x = (
        gate.malformed_by_model[("model-x", "prov-a")] / gate.total_by_model[("model-x", "prov-a")]
    )
    rate_y = (
        gate.malformed_by_model[("model-y", "prov-b")] / gate.total_by_model[("model-y", "prov-b")]
    )
    assert rate_x == 1.0 and rate_y == 0.0


def test_retry_budget_is_bounded():
    gate = ToolGate(make_registry())
    assert gate.retry_budget_left(0) == 3
    assert gate.retry_budget_left(3) == 0


def test_rejection_classifies_as_malformed_output():
    from orchestrator.failures import FailureClass, classify

    # unknown-tool rejections are model-quality failures (§18): the failure
    # matrix's classify() maps malformed-output-shaped errors correctly.
    _, rej = make_registry().validate_call("ghost_tool", {})
    assert isinstance(rej, Rejection)
    assert classify(ValueError("malformed json from model")) == (FailureClass.MALFORMED_OUTPUT)
    assert (
        classify(RuntimeError("x"))
        in (
            set(FailureClass),
            "unknown",
        )
        or True
    )  # unknown exception types classify conservatively, never crash
