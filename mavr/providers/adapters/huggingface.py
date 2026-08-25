"""Adapter for the Hugging Face Inference free tier (spec §7).

The free tier exposes a serverless inference API for a small set of
small/medium models. This adapter speaks the
``https://api-inference.huggingface.co/models/{model}`` endpoint and
maps the per-model free status from the model catalog — it does NOT
assume every hosted model is free.

If the user's keyring does not contain an ``HF_TOKEN`` secret, the
adapter falls back to the rate-limited anonymous tier. This is the
expected behavior for a free-tier native provider.
"""
from __future__ import annotations

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
from mavr.providers.model_catalog.catalog import HUGGINGFACE_FREE_MODELS
from mavr.schemas.routing import (
    AdapterCapabilities,
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    UsageInfo,
)

PROVIDER_ID = "huggingface"
HF_BASE = "https://api-inference.huggingface.co"


class HuggingFaceAdapter(ProviderAdapter):
    def __init__(
        self,
        *,
        auth_secret_name: str | None = "HF_TOKEN",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            AdapterMetadata(
                provider_id=PROVIDER_ID,
                display_name="Hugging Face Inference (free tier)",
                kind="native",
                base_url=HF_BASE,
                capabilities=AdapterCapabilities(
                    streaming=True,
                    tool_support=False,
                    structured_output=False,
                    context_limit=8192,
                    rate_limit_rpm=10,
                    request_timeout_seconds=60.0,
                ),
                auth=AdapterAuth(secret_name=auth_secret_name, required=False),
            )
        )
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    def models(self) -> list[ModelCatalogEntry]:
        return list(HUGGINGFACE_FREE_MODELS)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = self.get_secret()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        prompt = _messages_to_prompt(request.messages)
        parameters: dict[str, Any] = {
            "max_new_tokens": int(request.max_tokens or 256),
            "temperature": float(request.temperature),
            "return_full_text": False,
        }
        if request.stop:
            parameters["stop"] = list(request.stop)
        payload: dict[str, Any] = {
            "inputs": prompt,
            "parameters": parameters,
        }
        try:
            resp = await self._client.post(
                f"{self._metadata.base_url}/models/{model_key}",
                headers=self._headers(),
                json=payload,
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
        content = _extract_text(data)
        return ChatResponse(
            content=content,
            finish_reason="stop",
            usage=UsageInfo(is_free=True),
        )

    async def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        # HF free tier doesn't expose a streaming endpoint; we fall back
        # to a single chunk that contains the full response.
        response = await self.chat(model_key, request)
        yield ChatStream(content=response.content, finish_reason=response.finish_reason, usage=response.usage)

    async def health(self) -> HealthReport:
        try:
            # The HF "models" endpoint is a cheap connectivity probe.
            resp = await self._client.get(
                f"{self._metadata.base_url}/models",
                headers=self._headers(),
                timeout=10.0,
            )
        except httpx.TimeoutException as exc:
            return HealthReport(ok=False, auth_status=self.auth_status(), detail=f"timeout: {exc}")
        except httpx.HTTPError as exc:
            return HealthReport(
                ok=False,
                auth_status=self.auth_status(),
                detail=f"network: {exc}",
            )
        return HealthReport(
            ok=200 <= resp.status_code < 400 or resp.status_code == 404,
            auth_status=self.auth_status(),
            detail=f"http {resp.status_code}",
        )


# ---- helpers ------------------------------------------------------------


def _messages_to_prompt(messages: list) -> str:
    """Concatenate chat messages into a single prompt blob.

    HF Inference free tier doesn't speak OpenAI-style chat; the
    native text-generation endpoint takes a single ``inputs`` string.
    """
    parts: list[str] = []
    for m in messages:
        role = m.role
        content = m.content
        if role == "system":
            parts.append(f"<|system|>\n{content}")
        elif role == "user":
            parts.append(f"<|user|>\n{content}")
        elif role == "assistant":
            parts.append(f"<|assistant|>\n{content}")
        else:
            parts.append(f"<|{role}|>\n{content}")
    parts.append("<|assistant|>")
    return "\n\n".join(parts)


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {"error": resp.text}


def _extract_text(data: Any) -> str:
    if isinstance(data, list) and data:
        item = data[0]
        if isinstance(item, dict):
            return str(item.get("generated_text") or item.get("text") or "")
        return str(item)
    if isinstance(data, dict):
        if "error" in data:
            raise normalize_http_error(
                provider_id=PROVIDER_ID,
                http_status=None,
                message=str(data.get("error")),
            )
        if "generated_text" in data:
            return str(data["generated_text"])
    return ""
