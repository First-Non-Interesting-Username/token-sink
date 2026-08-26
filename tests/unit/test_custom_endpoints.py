"""Unit tests for user-defined OpenAI-compatible endpoints (issue #250).

Table-driven over: config schema validation, free/paid classification with
unknown-by-default, free-only blocking of unknown models, key-reference
safety (no secret values anywhere), and collect-all-errors startup parsing.
"""

from __future__ import annotations

import pytest

from providers.custom_endpoints import (
    CustomEndpoint,
    EndpointConfigError,
    ModelStatus,
    UnclassifiedModelError,
    check_free_only,
    parse_custom_endpoints,
)


def _raw(**overrides) -> dict:
    body = {
        "base_url": "https://llm.internal.example.com/v1",
        "api_key_env_var": "INTERNAL_LLM_KEY",
        "models": {"gpt-x": "free", "claude-y": "paid"},
        "max_concurrent_requests": 2,
    }
    body.update(overrides)
    return body


# -- schema validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"base_url": "ftp://x.example.com"},
        {"base_url": "not-a-url"},
        {"api_key_env_var": "sk-literal-secret-value"},  # looks like a secret, not a ref
        {"api_key_env_var": "lowercase_var"},
        {"max_concurrent_requests": 0},
        {"max_concurrent_requests": True},
        {"models": ["gpt-x"]},
        {},
    ],
)
def test_invalid_endpoint_configs_rejected_with_key_path(overrides: dict) -> None:
    raw = _raw(**{k: v for k, v in overrides.items() if k in _raw()})
    for bad_key, bad_val in overrides.items():
        raw[bad_key] = bad_val
    if overrides == {}:
        del raw["base_url"]
    with pytest.raises(EndpointConfigError) as exc:
        CustomEndpoint.from_config("internal", raw)
    assert "providers.custom_endpoints.internal" in str(exc.value)


def test_unknown_model_status_string_rejected() -> None:
    with pytest.raises(EndpointConfigError):
        CustomEndpoint.from_config("e", _raw(models={"m": "probably-free"}))


def test_bad_endpoint_id_rejected() -> None:
    with pytest.raises(EndpointConfigError):
        CustomEndpoint.from_config("Bad ID!", _raw())


# -- classification defaults to unknown ------------------------------------------


def test_declared_statuses_preserved_and_undeclared_default_unknown() -> None:
    ep = CustomEndpoint.from_config("e", _raw())
    assert ep.models["gpt-x"] is ModelStatus.FREE
    assert ep.models["claude-y"] is ModelStatus.PAID
    assert ep.models.get("undeclared") is None  # lookup-side default is unknown


# -- free-only gate ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "allowed"),
    [("gpt-x", True), ("claude-y", False), ("never-declared", False)],
)
def test_free_only_gate_blocks_paid_and_unknown(model: str, allowed: bool) -> None:
    ep = CustomEndpoint.from_config("e", _raw())
    if allowed:
        check_free_only(ep, model)  # must not raise
    else:
        with pytest.raises(UnclassifiedModelError):
            check_free_only(ep, model)


def test_unclassified_error_message_is_actionable() -> None:
    ep = CustomEndpoint.from_config("e", _raw(models={}))
    with pytest.raises(UnclassifiedModelError) as exc:
        check_free_only(ep, "m")
    msg = str(exc.value)
    assert "explicit" in msg and "free" in msg and endpoint_named(msg)


def endpoint_named(msg: str) -> bool:
    return "'e'" in msg


# -- secret hygiene -----------------------------------------------------------------


def test_safe_repr_never_contains_secret_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET_LLM_KEY", "sk-super-secret-123")
    ep = CustomEndpoint(
        api_key_env_var="MY_SECRET_LLM_KEY", endpoint_id="e", base_url="https://x.co"
    )
    rendered = ep.safe_repr()
    assert "sk-super-secret-123" not in rendered
    assert "MY_SECRET_LLM_KEY" in rendered


def test_endpoint_object_holds_only_the_reference() -> None:
    ep = CustomEndpoint.from_config("e", _raw())
    dumped = repr(vars(ep))
    # The literal secret never entered the object; only the env var name exists.
    assert "sk-" not in dumped
    assert "INTERNAL_LLM_KEY" in dumped


# -- collect-all-errors startup parsing -----------------------------------------------


def test_parse_collects_errors_across_endpoints() -> None:
    raw = {
        "good": _raw(),
        "bad_url": _raw(base_url="nope"),
        "bad_key": _raw(api_key_env_var="oops"),
    }
    with pytest.raises(EndpointConfigError) as exc:
        parse_custom_endpoints(raw)
    msg = str(exc.value)
    assert "bad_url" in msg and "bad_key" in msg and "good" not in msg.split("-")[0]


def test_parse_returns_valid_endpoints_and_none_for_empty() -> None:
    assert parse_custom_endpoints(None) == {}
    eps = parse_custom_endpoints({"a": _raw(), "b": _raw()})
    assert set(eps) == {"a", "b"}


def test_case_insensitive_duplicate_ids_flagged() -> None:
    with pytest.raises(EndpointConfigError) as exc:
        parse_custom_endpoints({"a": _raw(), "A": _raw(base_url="https://other.example.com")})
    assert "duplicate" in str(exc.value)
