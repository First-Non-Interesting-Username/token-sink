"""Tests for custom OpenAI-compatible endpoint configuration (#250).

Covers: config validation (all error classes with key paths), credential
reference rules, classification defaulting to unknown, free-only blocking
of unknown custom models, per-endpoint rate limits, and resolver
composition where a custom endpoint owns its models' status.
"""

from __future__ import annotations

import enum

import pytest

from providers.custom_endpoint import (
    CustomEndpoint,
    CustomEndpointError,
    CustomEndpointRegistry,
    EndpointClassification,
    make_status_resolver,
    validate_custom_endpoints,
)


def ep(**kw) -> dict:
    base = {
        "name": "mygateway",
        "base_url": "https://gw.example.com/v1",
        "models": ["m1", "m2"],
        "api_key_env_var": "MYGATEWAY_API_KEY",
    }
    base.update(kw)
    return base


# --- validation ----------------------------------------------------------------


def test_valid_endpoint_parses():
    endpoints, errors = validate_custom_endpoints([ep()])
    assert not errors
    e = endpoints[0]
    assert e.name == "mygateway"
    assert e.base_url == "https://gw.example.com/v1"
    assert e.models == ("m1", "m2")
    assert e.classification is EndpointClassification.UNKNOWN  # default!
    assert e.api_key_env_var == "MYGATEWAY_API_KEY"


def test_none_section_is_noop():
    endpoints, errors = validate_custom_endpoints(None)
    assert endpoints == [] and errors == []


@pytest.mark.parametrize(
    "raw,expected_error",
    [
        ("nope", "must be a list"),
        ([{"base_url": "https://x"}], "name"),
        ([{"name": "x"}], "base_url"),
        ([ep(name="BadName")], "lowercase"),
        ([ep(), ep()], "duplicate endpoint name"),
        ([ep(base_url="http://gw.example.com")], "plain http"),
        ([ep(api_key_env_var="sk-literal123")], "env var name"),
        ([ep(models=["m1", 3])], "list of model-id strings"),
        ([ep(models=["bad model id!"])], "invalid model ids"),
        ([ep(classification="complimentary")], "classification"),
        ([ep(max_requests_per_min=-5)], "positive integer"),
        ([{"name": "ok", "base_url": 42}], "absolute http(s) URL"),
    ],
)
def test_validation_errors_carry_paths(raw, expected_error):
    _, errors = validate_custom_endpoints(raw)
    assert errors, f"expected an error mentioning {expected_error!r}"
    assert any(expected_error in e for e in errors), errors
    # every error points at the section path
    assert all(e.startswith("providers.") for e in errors)


def test_http_allowed_for_loopback():
    for url in ["http://localhost:8000/v1", "http://127.0.0.1:11434"]:
        endpoints, errors = validate_custom_endpoints([ep(base_url=url)])
        assert not errors, (url, errors)


def test_classification_free_and_paid_accepted():
    f, e1 = validate_custom_endpoints([ep(name="a", classification="free")])
    p, e2 = validate_custom_endpoints([ep(name="b", classification="paid")])
    assert not e1 and not e2
    assert f[0].classification is EndpointClassification.FREE
    assert p[0].classification is EndpointClassification.PAID


# --- registry / free-only enforcement --------------------------------------------


def build_registry() -> CustomEndpointRegistry:
    eps, errors = validate_custom_endpoints(
        [
            ep(classification="free"),  # mygateway: m1,m2 declared free
            ep(
                name="paid_gw",
                base_url="https://p.example.com",
                models=["pm"],
                classification="paid",
            ),  # noqa: E501
            ep(name="silent_gw", base_url="https://s.example.com", models=["sm"]),  # unknown
        ]
    )
    assert not errors
    return CustomEndpointRegistry(eps)


def test_unknown_model_on_endpoint_blocked_under_free_only():
    r = build_registry()
    # undeclared model on a custom endpoint -> UNKNOWN -> blocked
    assert r.free_only_violations("mygateway", "undeclared")
    assert r.status_for("mygateway", "undeclared") is EndpointClassification.UNKNOWN


def test_declared_free_passes_and_paid_blocks():
    r = build_registry()
    assert not r.free_only_violations("mygateway", "m1")
    assert r.free_only_violations("paid_gw", "pm")


def test_default_unknown_status_blocks_even_on_free_endpoint_models_list():
    """Undeclared model never inherits the endpoint's declared class."""
    eps, _ = validate_custom_endpoints([ep(classification="free")])
    r = CustomEndpointRegistry(eps)
    assert r.status_for("mygateway", "m1") is EndpointClassification.FREE
    assert r.status_for("mygateway", "other") is EndpointClassification.UNKNOWN


def test_unknown_provider_fails_closed():
    r = build_registry()
    assert r.free_only_violations("nosuchprovider", "any")


def test_get_unknown_endpoint_raises():
    with pytest.raises(CustomEndpointError):
        build_registry().get("nope")


def test_duplicate_names_rejected_at_runtime():
    with pytest.raises(CustomEndpointError):
        CustomEndpointRegistry(
            [
                CustomEndpoint(name="x", base_url="https://x"),
                CustomEndpoint(name="x", base_url="https://y"),
            ]
        )


# --- rate limits ---------------------------------------------------------------


def test_per_endpoint_rate_limit_shape():
    eps, errors = validate_custom_endpoints([ep(max_requests_per_min=30)])
    assert not errors
    rl = eps[0].rate_limit()
    assert rl is not None and rl.max_requests == 30 and rl.per_seconds == 60.0


def test_no_rate_limit_when_unset():
    eps, _ = validate_custom_endpoints([ep()])
    assert eps[0].rate_limit() is None
    assert build_registry().rate_limit_for("mygateway") is None


def test_registry_rate_limit_lookup():
    eps, _ = validate_custom_endpoints([ep(max_requests_per_min=10)])
    r = CustomEndpointRegistry(eps)
    assert r.rate_limit_for("mygateway").max_requests == 10
    assert r.rate_limit_for("unknown") is None


# --- resolver composition ---------------------------------------------------------


class FakeStatus(enum.Enum):
    FREE = "free"
    PAID = "paid"
    UNKNOWN = "unknown"


def test_resolver_custom_endpoint_owns_its_status():
    r = build_registry()
    catalog_calls = []

    def catalog(p, m):
        catalog_calls.append((p, m))
        return FakeStatus.FREE  # would wrongly bless everything

    resolve = make_status_resolver(r, catalog)
    assert resolve("mygateway", "m1") is EndpointClassification.FREE
    assert resolve("paid_gw", "pm") is EndpointClassification.PAID
    # undeclared custom model must NOT inherit the catalog's FREE
    assert resolve("mygateway", "undeclared") is EndpointClassification.UNKNOWN
    assert catalog_calls == []  # custom endpoints never consult fallback


def test_resolver_builtin_providers_fall_through_to_catalog():
    r = build_registry()

    def catalog(p, m):
        return FakeStatus.PAID

    resolve = make_status_resolver(r, catalog)
    assert resolve("openai", "gpt-x") is FakeStatus.PAID
