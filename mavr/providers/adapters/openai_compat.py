"""Generic OpenAI-compatible adapter.

Used for:

* Custom endpoints the user supplies (a local llama.cpp server, a
  vLLM box, a paid-tier OpenAI base URL with their own key, etc.).
* Partly-free gateways (OpenCode Zen, Kilo Gateway). The gateway
  adapter subclasses this and overrides the model list with the
  strict per-model free metadata from the catalog.

The base adapter never assumes a model is free; it relies on the
:class:`ModelCatalogEntry` list provided by the subclass.
"""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from typing import Any, Literal

import httpx

from mavr.providers.adapters.base import (
    AdapterAuth,
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
    normalize_http_error,
    normalize_timeout_error,
)
from mavr.schemas.routing import (
    AdapterCapabilities,
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    UsageInfo,
)


class OpenAICompatibleAdapter(ProviderAdapter):
    """OpenAI-compatible Chat Completions adapter.

    Subclasses supply a unique ``provider_id`` and a model list. The
    free filter at the router layer decides which of those models are
    actually routable in free-only mode.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        display_name: str,
        kind: str,
        base_url: str,
        auth_secret_name: str | None,
        models: list[ModelCatalogEntry],
        capabilities: AdapterCapabilities | None = None,
        auth_required: bool = True,
        client: httpx.AsyncClient | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            AdapterMetadata(
                provider_id=provider_id,
                display_name=display_name,
                kind=kind,
                base_url=base_url.rstrip("/"),
                capabilities=capabilities
                or AdapterCapabilities(
                    streaming=True,
                    tool_support=True,
                    structured_output=True,
                    rate_limit_rpm=30,
                    request_timeout_seconds=60.0,
                ),
                auth=AdapterAuth(secret_name=auth_secret_name, required=auth_required),
            )
        )
        self._models = list(models)
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        self._extra_headers = dict(extra_headers or {})

    def models(self) -> list[ModelCatalogEntry]:
        return list(self._models)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._metadata.auth.required:
            token = self.get_secret()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        headers.update(self._extra_headers)
        return headers

    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        body = _build_request_body(model_key, request)
        try:
            resp = await self._client.post(
                f"{self._metadata.base_url}/chat/completions",
                headers=self._headers(),
                json=body,
                timeout=self._metadata.capabilities.request_timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise normalize_timeout_error(self.provider_id, str(exc)) from exc
        except httpx.HTTPError as exc:
            raise normalize_http_error(
                provider_id=self.provider_id, http_status=None, message=str(exc)
            ) from exc

        if resp.status_code >= 400:
            raise normalize_http_error(
                provider_id=self.provider_id,
                http_status=resp.status_code,
                message=resp.text[:500],
            )
        data = _safe_json(resp)
        content, usage, tool_calls, finish = _extract_response(data)
        return ChatResponse(
            content=content,
            finish_reason=_coerce_finish_reason(finish),
            tool_calls=tool_calls,
            usage=usage,
            raw=data,
        )

    async def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        body = _build_request_body(model_key, request, stream=True)
        try:
            async with self._client.stream(
                "POST",
                f"{self._metadata.base_url}/chat/completions",
                headers=self._headers(),
                json=body,
                timeout=self._metadata.capabilities.request_timeout_seconds,
            ) as resp:
                if resp.status_code >= 400:
                    text = (await resp.aread()).decode("utf-8", errors="replace")[:500]
                    raise normalize_http_error(
                        provider_id=self.provider_id,
                        http_status=resp.status_code,
                        message=text,
                    )
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        import json as _json

                        data = _json.loads(payload)
                    except Exception:  # noqa: BLE001
                        continue
                    content, usage, tool_calls, finish = _extract_response(data)
                    if content or tool_calls:
                        yield ChatStream(
                            content=content,
                            finish_reason=finish,
                            usage=usage,
                            tool_calls=tool_calls,
                        )
        except httpx.TimeoutException as exc:
            raise normalize_timeout_error(self.provider_id, str(exc)) from exc
        except httpx.HTTPError as exc:
            raise normalize_http_error(
                provider_id=self.provider_id, http_status=None, message=str(exc)
            ) from exc

    async def health(self) -> HealthReport:
        if self._metadata.auth.required and not self.get_secret():
            return HealthReport(ok=False, auth_status="missing", detail="no API key configured")
        url = self._models_endpoint()
        start = time.monotonic()
        try:
            resp = await self._client.get(url, headers=self._headers(), timeout=10.0)
        except httpx.TimeoutException as exc:
            return HealthReport(ok=False, auth_status=self.auth_status(), detail=f"timeout: {exc}")
        except httpx.HTTPError as exc:
            return HealthReport(ok=False, auth_status=self.auth_status(), detail=f"network: {exc}")
        latency = int((time.monotonic() - start) * 1000)
        ok = 200 <= resp.status_code < 400
        return HealthReport(
            ok=ok,
            auth_status=self.auth_status(),
            latency_ms=latency,
            detail=f"http {resp.status_code}",
        )

    def _models_endpoint(self) -> str:
        # most OpenAI-compatible gateways expose /v1/models; the user can
        # override ``base_url`` to point at a variant.
        return f"{self._metadata.base_url}/models"


# ---- helpers ------------------------------------------------------------


def _build_request_body(
    model_key: str, request: ChatRequest, *, stream: bool = False
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model_key,
        "messages": [m.model_dump() for m in request.messages],
        "temperature": float(request.temperature),
        "stream": bool(stream),
    }
    if request.max_tokens:
        body["max_tokens"] = int(request.max_tokens)
    if request.stop:
        body["stop"] = list(request.stop)
    if request.response_format == "json_object":
        body["response_format"] = {"type": "json_object"}
    if request.tools:
        body["tools"] = [
            {"type": "function", "function": t.model_dump()} for t in request.tools
        ]
    return body


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {"error": resp.text}


def _coerce_finish_reason(
    value: str,
) -> Literal['stop', 'length', 'tool_call', 'error', 'cancelled']:
    """Coerce an OpenAI-style finish_reason into the ChatResponse Literal set."""
    allowed = {"stop", "length", "tool_call", "error", "cancelled"}
    if value in allowed:
        return value  # type: ignore[return-value]
    return "stop"


def _extract_response(data: Any) -> tuple[str, UsageInfo, list[dict[str, Any]], str]:
    content = ""
    finish = "stop"
    tool_calls: list[dict[str, Any]] = []
    usage = UsageInfo(is_free=True)
    if not isinstance(data, dict):
        return content, usage, tool_calls, "error"
    choices = data.get("choices") or []
    if choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message") or {}
            # Streaming chunks carry their content under "delta" instead
            # of "message" — read whichever is present.
            content = str(message.get("content") or first.get("delta", {}).get("content") or "")
            tool_calls = list(message.get("tool_calls") or [])
            finish = str(first.get("finish_reason") or finish)
    usage_meta = data.get("usage") or {}
    if isinstance(usage_meta, dict):
        usage = UsageInfo(
            input_tokens=int(usage_meta.get("prompt_tokens") or 0),
            output_tokens=int(usage_meta.get("completion_tokens") or 0),
            cache_read_tokens=int(
                (usage_meta.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
            ),
            is_free=True,
        )
    return content, usage, tool_calls, finish or "stop"
