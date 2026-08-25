"""Adapter for Google Gemini (free tier, spec §7).

Speaks the ``generativelanguage.googleapis.com`` REST API. Uses the
``x-goog-api-key`` header (instead of a query string) so the secret
never appears in URLs. The free tier is keyed on the
``GOOGLE_API_KEY`` (or ``GEMINI_API_KEY``) environment variable /
keyring secret.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import Any

import httpx

from mavr.providers.adapters.base import (
    AdapterAuth,
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
    normalize_http_error,
    normalize_timeout_error,
)
from mavr.providers.model_catalog.catalog import GEMINI_FREE_MODELS
from mavr.schemas.routing import (
    AdapterCapabilities,
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    ProviderError,
    ProviderErrorReason,
    UsageInfo,
)

PROVIDER_ID = "gemini"
DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiAdapter(ProviderAdapter):
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE,
        auth_secret_name: str | None = "GEMINI_API_KEY",
        env_fallbacks: tuple[str, ...] = ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            AdapterMetadata(
                provider_id=PROVIDER_ID,
                display_name="Google Gemini (free tier)",
                kind="native",
                base_url=base_url,
                capabilities=AdapterCapabilities(
                    streaming=True,
                    tool_support=True,
                    structured_output=True,
                    context_limit=1_048_576,
                    rate_limit_rpm=15,
                    request_timeout_seconds=60.0,
                ),
                auth=AdapterAuth(secret_name=auth_secret_name, required=True),
            )
        )
        self._env_fallbacks = env_fallbacks
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    def models(self) -> list[ModelCatalogEntry]:
        return list(GEMINI_FREE_MODELS)

    def get_secret(self) -> str | None:
        val = super().get_secret()
        if val:
            return val
        for env in self._env_fallbacks:
            v = os.environ.get(env)
            if v and v.strip():
                return v
        return None

    def _url(self, model_key: str, suffix: str) -> str:
        return f"{self._metadata.base_url}/models/{model_key}:{suffix}"

    def _headers(self) -> dict[str, str]:
        token = self.get_secret()
        if not token:
            raise ProviderError(
                ProviderErrorReason.AUTH,
                f"{self.provider_id}: missing API key (set GEMINI_API_KEY env or store "
                f"'{self._metadata.auth.secret_name}' in keyring)",
                retryable=False,
                provider_id=self.provider_id,
            )
        return {
            "Content-Type": "application/json",
            "x-goog-api-key": token,
        }

    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        body = _build_body(request)
        try:
            resp = await self._client.post(
                self._url(model_key, "generateContent"),
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
        content, usage = _extract_response(data)
        return ChatResponse(
            content=content,
            finish_reason="stop" if content else "error",
            usage=usage,
            raw=data,
        )

    async def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        body = _build_body(request)
        try:
            async with self._client.stream(
                "POST",
                self._url(model_key, "streamGenerateContent"),
                params={"alt": "sse"},
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
                    content, usage = _extract_response(data)
                    if content:
                        yield ChatStream(content=content, usage=usage)
        except httpx.TimeoutException as exc:
            raise normalize_timeout_error(self.provider_id, str(exc)) from exc
        except httpx.HTTPError as exc:
            raise normalize_http_error(
                provider_id=self.provider_id, http_status=None, message=str(exc)
            ) from exc

    async def health(self) -> HealthReport:
        if not self.get_secret():
            return HealthReport(ok=False, auth_status="missing", detail="no GEMINI_API_KEY")
        try:
            resp = await self._client.get(
                f"{self._metadata.base_url}/models",
                headers=self._headers(),
                timeout=10.0,
            )
        except httpx.TimeoutException as exc:
            return HealthReport(ok=False, auth_status=self.auth_status(), detail=f"timeout: {exc}")
        except httpx.HTTPError as exc:
            return HealthReport(ok=False, auth_status=self.auth_status(), detail=f"network: {exc}")
        return HealthReport(
            ok=200 <= resp.status_code < 400,
            auth_status=self.auth_status(),
            detail=f"http {resp.status_code}",
        )


# ---- helpers ------------------------------------------------------------


def _build_body(request: ChatRequest) -> dict[str, Any]:
    contents: list[dict[str, Any]] = []
    system_parts: list[str] = []
    for m in request.messages:
        if m.role == "system":
            system_parts.append(m.content)
            continue
        role = "user" if m.role == "user" else "model"
        contents.append({"role": role, "parts": [{"text": m.content}]})
    body: dict[str, Any] = {"contents": contents}
    if system_parts:
        body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
    gen: dict[str, Any] = {"temperature": request.temperature}
    if request.max_tokens:
        gen["maxOutputTokens"] = int(request.max_tokens)
    if request.stop:
        gen["stopSequences"] = list(request.stop)
    if request.response_format == "json_object":
        gen["responseMimeType"] = "application/json"
    body["generationConfig"] = gen
    if request.tools:
        body["tools"] = [
            {
                "functionDeclarations": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters or {"type": "object"},
                    }
                    for t in request.tools
                ]
            }
        ]
    return body


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {"error": resp.text}


def _extract_response(data: Any) -> tuple[str, UsageInfo]:
    text_parts: list[str] = []
    usage = UsageInfo(is_free=True)
    if not isinstance(data, dict):
        return "", usage
    for cand in data.get("candidates") or []:
        content = cand.get("content") or {}
        for part in content.get("parts") or []:
            txt = part.get("text")
            if txt:
                text_parts.append(str(txt))
    meta = data.get("usageMetadata") or {}
    if isinstance(meta, dict):
        usage = UsageInfo(
            input_tokens=int(meta.get("promptTokenCount") or 0),
            output_tokens=int(meta.get("candidatesTokenCount") or 0),
            cache_read_tokens=int(meta.get("cachedContentTokenCount") or 0),
            is_free=True,
        )
    return "".join(text_parts), usage
