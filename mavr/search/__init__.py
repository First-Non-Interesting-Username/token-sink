"""Search + extraction subsystem (spec §9).

Public API:

* :class:`SearchEngine` — the ddgs wrapper.
* :func:`extract.fetch` — primary URL fetcher.
* :func:`extract.store_extraction` — persist raw + sanitized + evidence.
* :func:`evidence.record_evidence` — durable evidence-item row.
* :func:`agents.SearchAgentHandler` / :class:`ExtractionAgentHandler`
  — runtime handlers that wire the subsystem into a task.
* :func:`agents.search_subagent` / :func:`extraction_subagent` —
  spawn a child agent for the runtime.
* :mod:`safety` — SSRF denylist, path-traversal protection.
* :mod:`sanitize` — HTML stripping + UNTRUSTED_INPUT labeling.
"""
from __future__ import annotations

from mavr.search import agents, engine, evidence, extract, safety, sanitize

__all__ = [
    "agents",
    "engine",
    "evidence",
    "extract",
    "safety",
    "sanitize",
    "SearchEngine",
]


def __getattr__(name: str) -> object:
    """Lazy attribute access so importing this package doesn't pay for
    loading ddgs until something actually needs the search engine.
    """
    if name == "SearchEngine":
        return engine.SearchEngine
    raise AttributeError(f"module 'mavr.search' has no attribute {name!r}")
