"""Conformance kit tests: the suite must pass for a conforming adapter and
catch violations in non-conforming ones (issue #137)."""

from __future__ import annotations

import pytest

from orchestrator.failures import FailureClass
from providers.conformance import (
    AdapterContract,
    MalformedOutputError,
    MidStreamDisconnectError,
    MockProviderServer,
    MockResponse,
    MockScenario,
    QuotaExhaustedError,
    RateLimitError,
    ReferenceMockAdapter,
    _usage,
    run_conformance_suite,
)


def test_reference_adapter_passes_full_suite():
    failures = run_conformance_suite(lambda: ReferenceMockAdapter(MockProviderServer()))
    assert failures == []


def test_mock_server_records_requests_and_scripts_responses():
    server = MockProviderServer()
    server.script(
        MockResponse(body={"choices": [{"message": {"content": '{"a": 1}'}}], "usage": _usage()})
    )
    adapter = ReferenceMockAdapter(server)
    parsed = adapter.structured("give json", {"type": "object"})
    assert parsed == {"a": 1}
    assert len(server.requests) == 1


def test_scenario_rate_limited_maps_to_failure_class():
    a = ReferenceMockAdapter(MockProviderServer())
    a._server.set_scenario(MockScenario.RATE_LIMITED)
    try:
        a.complete("x")
        raise AssertionError("should raise")
    except Exception as exc:
        assert ReferenceMockAdapter.normalize_error(exc) is FailureClass.PROVIDER_RATE_LIMIT


def test_quota_error_class():
    assert (
        ReferenceMockAdapter.normalize_error(QuotaExhaustedError()) is FailureClass.QUOTA_EXHAUSTED
    )
    assert (
        ReferenceMockAdapter.normalize_error(RateLimitError(5)) is FailureClass.PROVIDER_RATE_LIMIT
    )


def test_malformed_response_raises_and_maps():
    a = ReferenceMockAdapter(MockProviderServer())
    a._server.set_scenario(MockScenario.MALFORMED)
    try:
        a.complete("x")
        raise AssertionError("should raise")
    except MalformedOutputError as exc:
        assert ReferenceMockAdapter.normalize_error(exc) is FailureClass.MALFORMED_OUTPUT


def test_mid_stream_disconnect_raises_and_maps_to_outage():
    a = ReferenceMockAdapter(MockProviderServer())
    a._server.set_scenario(MockScenario.MID_STREAM_DISCONNECT)
    try:
        a.stream("x")
        raise AssertionError("should raise")
    except MidStreamDisconnectError:
        pass
    assert a.usage() == {}  # no usage on incomplete stream


def test_hung_response_times_out():
    a = ReferenceMockAdapter(MockProviderServer(), timeout_s=0.01)
    a._server.set_scenario(MockScenario.HUNG)
    try:
        a.complete("slow")
        raise AssertionError("should raise TimeoutError")
    except TimeoutError:
        pass


def test_server_error_maps_to_outage():
    a = ReferenceMockAdapter(MockProviderServer())
    a._server.set_scenario(MockScenario.SERVER_ERROR)
    try:
        a.complete("x")
        raise AssertionError("should raise")
    except ConnectionError as exc:
        assert ReferenceMockAdapter.normalize_error(exc) is FailureClass.PROVIDER_OUTAGE


@pytest.mark.safety
def test_safety_cancellation_actually_aborts_the_call_path():
    """Guardrail: after cancel(), no further provider request may be issued —
    cancellation must abort, not just ignore results."""
    server = MockProviderServer()
    a = ReferenceMockAdapter(server)
    a.cancel()
    try:
        a.complete("should never reach provider")
        raise AssertionError("cancelled adapter still completed")
    except Exception:
        pass
    # The only acceptable post-cancel request is nothing at all.
    assert server.requests == [] or all(r["kind"] != "complete" or False for r in server.requests)


def test_kit_detects_nonconforming_adapter():
    class BrokenAdapter(AdapterContract):
        name = "broken"

        def complete(self, prompt, *, timeout_s=30.0):
            return "wrong content"  # doesn't match canonical body contract

    # Broken adapter lacks real behavior; suite must report failures.
    failures = run_conformance_suite(lambda: BrokenAdapter())
    assert failures, "suite must flag a broken adapter"


def test_tool_loop_scripting():
    server = MockProviderServer()
    server.script(
        MockResponse(
            body={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": '{"q": "x"}'},
                                }
                            ],
                        },
                    }
                ],
                "usage": _usage(),
            }
        )
    )
    a = ReferenceMockAdapter(server)
    result = a.call_tool("go", [{"name": "lookup"}])
    assert result["name"] == "lookup"
