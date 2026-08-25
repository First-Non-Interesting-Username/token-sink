"""Provider adapter package.

Adapters are responsible for the wire-level integration with one or more
LLM providers. They expose a small, uniform surface (see
``mavr.providers.adapters.base.ProviderAdapter``) and translate the
provider-specific quirks into the types defined in
``mavr.schemas.routing``.

Concrete adapters live in submodules:

* :mod:`mavr.providers.adapters.huggingface` — native free tier
* :mod:`mavr.providers.adapters.gemini` — native free tier
* :mod:`mavr.providers.adapters.opencode_zen` — partly-free gateway
* :mod:`mavr.providers.adapters.kilo_gateway` — partly-free gateway
* :mod:`mavr.providers.adapters.openai_compat` — user-supplied OpenAI-compatible endpoint
"""
from __future__ import annotations

from mavr.providers.adapters.base import (
    AdapterAuth,
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
)

__all__ = [
    "AdapterAuth",
    "AdapterMetadata",
    "ChatStream",
    "ProviderAdapter",
]
