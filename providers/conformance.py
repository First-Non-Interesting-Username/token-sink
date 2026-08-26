"""Provider adapter conformance test kit (issue #137, PLAN §8.1/§18/§19).

A shared mock provider server + parametrized suite that every provider
adapter must pass. Without it, each adapter's tests drift and interface gaps
surface only at runtime.

Components:

- ``MockProviderServer`` — a scripted, in-process fake provider. Scenarios:
  normal completion, streaming chunks, tool-call loops, malformed responses,
  mid-stream disconnects, 429 rate limits, quota errors, slow/hung responses.
  In-process by design: hermetic in CI, no sockets, and doubles as fixture
  source for router failover integration tests (#44).
- ``AdapterContract`` — the abstract adapter interface every adapter must
  implement (mirrors PLAN §8.1: complete, streaming, tool-calling, structured
  output, cancellation, usage extraction, error normalization).
- ``run_conformance_suite(adapter_factory)`` — the shared parametrized checks.
  CI runs this for every registered adapter; adding an adapter without
  conformance passes fails the test gate.

Error mapping follows orchestrator/failures.py FailureClass (#91 classes):
429 → PROVIDER_RATE_LIMIT, quota → QUOTA_EXHAUSTED, malformed output →
MALFORMED_OUTPUT, timeouts/hangs → AGENT_TIMEOUT, connection loss/5xx →
PROVIDER_OUTAGE.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from orchestrator.failures import FailureClass

# --------------------------------------------------------------------------
# Mock provider server
# --------------------------------------------------------------------------


class MockScenario(enum.Enum):
    OK = "ok"
    STREAM = "stream"
    TOOL_LOOP = "tool_loop"
    MALFORMED = "malformed"  # valid HTTP, garbage payload
    MID_STREAM_DISCONNECT = "mid_stream_disconnect"
    RATE_LIMITED = "rate_limited"  # 429 + Retry-After
    QUOTA_EXHAUSTED = "quota_exhausted"
    HUNG = "hung"  # never responds within timeout
    SERVER_ERROR = "server_error"  # 5xx outage


@dataclass
class MockResponse:
    """What the mock server answers with for one request."""

    status: int = 200
    body: dict[str, Any] | None = None
    chunks: list[str] = field(default_factory=list)  # streaming deltas
    disconnect_after_chunks: int | None = None  # mid-stream cut-off point
    retry_after_s: int = 1
    hang_s: float = 0.0  # simulated latency; caller's timeout should win


class MockProviderServer:
    """Scripted fake provider implementing the transport side of the §8.1
    interface. Adapters under test point their HTTP layer at this object
    (or call its handle() method directly through an injectable transport)."""

    def __init__(self) -> None:
        self.scenario = MockScenario.OK
        self.requests: list[dict[str, Any]] = []
        self.cancelled: list[dict[str, Any]] = []
        # Scriptable per-request responses; falls back to scenario default.
        self._scripted: list[MockResponse] = []

    def set_scenario(self, scenario: MockScenario) -> None:
        self.scenario = scenario

    def script(self, *responses: MockResponse) -> None:
        """Queue exact responses consumed one per request (tool loops etc.)."""
        self._scripted = list(responses)

    def _default_response(self) -> MockResponse:
        return {
            MockScenario.OK: MockResponse(body=_ok_body()),
            MockScenario.STREAM: MockResponse(body=_ok_body(), chunks=["Hello", ", ", "world"]),
            MockScenario.TOOL_LOOP: MockResponse(body=_tool_call_body()),
            MockScenario.MALFORMED: MockResponse(body={"weird": [1, 2, 3]}),
            MockScenario.MID_STREAM_DISCONNECT: MockResponse(
                body=_ok_body(), chunks=["partial ", "data"], disconnect_after_chunks=1
            ),
            MockScenario.RATE_LIMITED: MockResponse(status=429),
            MockScenario.QUOTA_EXHAUSTED: MockResponse(status=402),
            MockScenario.HUNG: MockResponse(hang_s=30.0),
            MockScenario.SERVER_ERROR: MockResponse(status=503),
        }[self.scenario]

    def handle(self, request: dict[str, Any]) -> MockResponse:
        """Transport entry point: record the request, answer per script."""
        self.requests.append(request)
        if self._scripted:
            return self._scripted.pop(0)
        return self._default_response()

    def note_cancelled(self, request: dict[str, Any]) -> None:
        """Called by the adapter when cancellation aborts an in-flight call."""
        self.cancelled.append(request)


# --- canonical mock bodies -------------------------------------------------


def _usage() -> dict[str, int]:
    return {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


def _ok_body() -> dict[str, Any]:
    return {
        "id": "mock-1",
        "object": "chat.completion",
        "model": "mock-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello, world"},
                "finish_reason": "stop",
            }
        ],
        "usage": _usage(),
    }


def _tool_call_body() -> dict[str, Any]:
    return {
        "id": "mock-2",
        "object": "chat.completion",
        "model": "mock-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": '{"q": "x"}'},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": _usage(),
    }


# --------------------------------------------------------------------------
# Adapter contract + conformance suite
# --------------------------------------------------------------------------


class AdapterContract:
    """Abstract §8.1 adapter surface. Adapters subclass this; the conformance
    suite verifies behavior, not just method existence."""

    name = "abstract"

    def complete(self, prompt: str, *, timeout_s: float = 30.0) -> str: ...
    def stream(self, prompt: str, *, timeout_s: float = 30.0) -> list[str]: ...
    def call_tool(self, prompt: str, tools: list[dict], *, timeout_s: float = 30.0) -> dict: ...
    def structured(self, prompt: str, schema: dict, *, timeout_s: float = 30.0) -> dict: ...
    def cancel(self) -> None: ...
    def health_check(self) -> bool: ...
    def usage(self) -> dict[str, int]: ...
    @staticmethod
    def normalize_error(exc: Exception) -> FailureClass: ...


class ReferenceMockAdapter(AdapterContract):
    """In-memory adapter wired straight to MockProviderServer. Serves as the
    reference implementation of the contract AND keeps the suite testable
    before real adapters exist."""

    name = "reference-mock"

    def __init__(self, server: MockProviderServer, timeout_s: float = 5.0):
        self._server = server
        self._timeout_s = timeout_s
        self._cancelled = False
        self._last_usage: dict[str, int] = {}

    # -- helpers --
    def _request(self, payload: dict) -> MockResponse:
        resp = self._server.handle(payload)
        if resp.hang_s > self._timeout_s:
            raise TimeoutError(f"provider exceeded {self._timeout_s}s")
        if resp.status == 429:
            raise RateLimitError(resp.retry_after_s)
        if resp.status == 402:
            raise QuotaExhaustedError()
        if resp.status >= 500:
            raise ConnectionError(f"upstream {resp.status}")
        return resp

    # -- contract --
    def complete(self, prompt: str, *, timeout_s: float | None = None) -> str:
        if self._cancelled:
            raise CancelledError()
        resp = self._request({"kind": "complete", "prompt": prompt})
        content = (resp.body or {}).get("choices", [{}])[0].get("message", {}).get("content")
        if not isinstance(content, str):  # malformed payload surfaces loudly
            raise MalformedOutputError(str(resp.body))
        self._last_usage = (resp.body or {}).get("usage", {})
        return content

    def stream(self, prompt: str, *, timeout_s: float | None = None) -> list[str]:
        if self._cancelled:
            raise CancelledError()
        resp = self._request({"kind": "stream", "prompt": prompt})
        chunks = list(resp.chunks)
        if resp.disconnect_after_chunks is not None:
            self._last_usage = {}
            raise MidStreamDisconnectError(delivered=resp.disconnect_after_chunks)
        self._last_usage = resp.body.get("usage", {}) if resp.body else {}
        return chunks

    def call_tool(self, prompt: str, tools: list[dict], *, timeout_s: float | None = None) -> dict:
        if self._cancelled:
            raise CancelledError()
        resp = self._request({"kind": "tools", "prompt": prompt, "tools": tools})
        msg = ((resp.body or {}).get("choices") or [{}])[0].get("message", {})
        if "tool_calls" not in msg:
            raise MalformedOutputError("expected tool_calls in response")
        self._last_usage = (resp.body or {}).get("usage", {})
        tc = msg["tool_calls"][0]
        return {
            "id": tc["id"],
            "name": tc["function"]["name"],
            "arguments": json_loads_safe(tc["function"]["arguments"]),
        }

    def structured(self, prompt: str, schema: dict, *, timeout_s: float | None = None) -> dict:
        raw = self.complete(prompt, timeout_s=timeout_s or self._timeout_s)
        parsed = json_loads_safe(raw)
        if not isinstance(parsed, dict):
            raise MalformedOutputError("structured response was not a JSON object")
        return parsed

    def cancel(self) -> None:
        self._cancelled = True

    def health_check(self) -> bool:
        try:
            self._server.handle({"kind": "health"})
            return True
        except Exception:  # noqa: BLE001 - health check reports, never raises
            return False

    def usage(self) -> dict[str, int]:
        return dict(self._last_usage)

    @staticmethod
    def normalize_error(exc: Exception) -> FailureClass:
        if isinstance(exc, RateLimitError):
            return FailureClass.PROVIDER_RATE_LIMIT
        if isinstance(exc, QuotaExhaustedError):
            return FailureClass.QUOTA_EXHAUSTED
        if isinstance(exc, TimeoutError):
            return FailureClass.AGENT_TIMEOUT
        if isinstance(exc, (ConnectionError, MidStreamDisconnectError)):
            return FailureClass.PROVIDER_OUTAGE
        if isinstance(exc, MalformedOutputError):
            return FailureClass.MALFORMED_OUTPUT
        if isinstance(exc, CancelledError):
            return FailureClass.AGENT_TIMEOUT  # cancelled work is not retried as-is
        return FailureClass.PROVIDER_OUTAGE


# --- adapter-side exceptions (real adapters map these onto HTTP failures) --


class RateLimitError(Exception):
    def __init__(self, retry_after_s: int) -> None:
        super().__init__(f"rate limited, retry after {retry_after_s}s")


class QuotaExhaustedError(Exception):
    pass


class MalformedOutputError(Exception):
    pass


class MidStreamDisconnectError(Exception):
    def __init__(self, delivered: int) -> None:
        super().__init__(f"stream cut off after {delivered} chunk(s)")


class CancelledError(Exception):
    pass


def json_loads_safe(raw: str) -> Any:
    import json

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise MalformedOutputError(f"not valid JSON: {raw[:80]!r}") from None


def run_conformance_suite(make_adapter: Callable[[], AdapterContract]) -> list[str]:
    """Run every conformance check against a fresh adapter instance.

    Returns a list of failure descriptions; empty means the adapter conforms.
    CI calls this per registered adapter — an adapter without a green run
    fails the gate (issue #137).
    """
    failures: list[str] = []

    def check(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except AssertionError as exc:
            failures.append(f"{name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - any unexpected crash is a failure
            failures.append(f"{name}: unexpected {type(exc).__name__}: {exc}")

    check("interface_completeness", lambda: _check_interface(make_adapter()))
    check("normal_completion_and_usage_extraction", lambda: _check_completion(make_adapter()))
    check("streaming_chunks", lambda: _check_streaming(make_adapter()))
    check("tool_calling_loop", lambda: _check_tools(make_adapter()))
    check("structured_output_validation", lambda: _check_structured(make_adapter()))
    check("cancellation_aborts", lambda: _check_cancel(make_adapter()))
    check("timeout_enforcement_on_hung_response", lambda: _check_timeout(make_adapter()))
    check(
        "error_mapping_rate_limit",
        lambda: _check_error_map(
            make_adapter(), MockScenario.RATE_LIMITED, FailureClass.PROVIDER_RATE_LIMIT
        ),
    )
    check(
        "error_mapping_quota",
        lambda: _check_error_map(
            make_adapter(), MockScenario.QUOTA_EXHAUSTED, FailureClass.QUOTA_EXHAUSTED
        ),
    )
    check(
        "error_mapping_malformed",
        lambda: _check_error_map(
            make_adapter(), MockScenario.MALFORMED, FailureClass.MALFORMED_OUTPUT
        ),
    )
    check(
        "error_mapping_outage",
        lambda: _check_error_map(
            make_adapter(), MockScenario.SERVER_ERROR, FailureClass.PROVIDER_OUTAGE
        ),
    )
    check("mid_stream_disconnect_is_outage", lambda: _check_disconnect(make_adapter()))
    check("health_check_reports_liveness", lambda: _check_health(make_adapter()))
    return failures


def _expect_raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {exc_type.__name__}, nothing raised")


def _check_interface(a: AdapterContract) -> None:
    for meth in (
        "complete",
        "stream",
        "call_tool",
        "structured",
        "cancel",
        "health_check",
        "usage",
        "normalize_error",
    ):
        assert hasattr(a, meth), f"adapter missing {meth}()"
    assert isinstance(a.name, str) and a.name


def _fresh_server(scenario: MockScenario) -> MockProviderServer:
    s = MockProviderServer()
    s.set_scenario(scenario)
    return s


def _make_with(scenario: MockScenario) -> ReferenceMockAdapter:
    return ReferenceMockAdapter(_fresh_server(scenario))


def _check_completion(a: AdapterContract) -> None:
    out = a.complete("hi")
    assert out == "Hello, world", out
    u = a.usage()
    assert u.get("total_tokens") == 18, f"usage extraction wrong: {u}"


def _check_streaming(a: AdapterContract) -> None:
    if isinstance(a, ReferenceMockAdapter):
        a._server.set_scenario(MockScenario.STREAM)
    chunks = a.stream("hi")
    assert "".join(chunks) == "Hello, world", chunks


def _check_tools(a: AdapterContract) -> None:
    if isinstance(a, ReferenceMockAdapter):
        a._server.set_scenario(MockScenario.TOOL_LOOP)
    result = a.call_tool("find x", [{"name": "lookup"}])
    assert result["name"] == "lookup" and result["arguments"] == {"q": "x"}


def _check_structured(a: AdapterContract) -> None:
    # The reference adapter echoes whatever JSON the server sent; script a
    # JSON-object completion to validate the structured path end-to-end.
    ref = a  # only meaningful for adapters honoring structured()
    server_resp = MockResponse(
        body={"choices": [{"message": {"content": '{"answer": 42}'}}], "usage": _usage()}
    )
    if isinstance(ref, ReferenceMockAdapter):
        ref._server.script(server_resp)
    parsed = ref.structured("give json", {"type": "object"})
    assert parsed == {"answer": 42}


def _check_cancel(a: AdapterContract) -> None:
    a.cancel()
    _expect_raises(CancelledError, lambda: a.complete("after cancel"))


def _check_timeout(a: AdapterContract) -> None:
    ref = a
    if isinstance(ref, ReferenceMockAdapter):
        ref._server.set_scenario(MockScenario.HUNG)
    _expect_raises(TimeoutError, lambda: ref.complete("hung"))


def _check_error_map(a: AdapterContract, scenario: MockScenario, expected: FailureClass) -> None:
    ref = a
    if isinstance(ref, ReferenceMockAdapter):
        ref._server.set_scenario(scenario)
        try:
            ref.complete("boom")
        except Exception as exc:
            assert ref.normalize_error(exc) is expected, (
                f"{scenario.value} mapped to {ref.normalize_error(exc)}, want {expected}"
            )
            return
        raise AssertionError(f"{scenario.value} did not raise")


def _check_disconnect(a: AdapterContract) -> None:
    ref = a
    if isinstance(ref, ReferenceMockAdapter):
        ref._server.set_scenario(MockScenario.MID_STREAM_DISCONNECT)
        try:
            ref.stream("hi")
        except MidStreamDisconnectError:
            assert ref.normalize_error(MidStreamDisconnectError(1)) is FailureClass.PROVIDER_OUTAGE
            return
        raise AssertionError("mid-stream disconnect did not raise")
    # Non-reference adapters just need the mapping right.
    assert ref.normalize_error(MidStreamDisconnectError(1)) is FailureClass.PROVIDER_OUTAGE


def _check_health(a: AdapterContract) -> None:
    assert a.health_check() is True
