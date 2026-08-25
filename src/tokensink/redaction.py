"""Redaction pipeline (PLAN §15, issue #29).

Every piece of persisted output — logs, reports, exports, failed
inputs/outputs preserved for diagnosis — passes through :func:`redact` before
it is written anywhere. The pipeline is pattern-based and dependency-free so
it can be applied everywhere without pulling in extra runtime requirements.

Design notes:
- Patterns are ordered; more specific patterns (key=value pairs) run before
  generic token-shaped strings to avoid mangling surrounding text.
- Replacement keeps a short type hint (``[REDACTED:<kind>]``) so redacted
  output stays diagnosable without leaking the secret itself.
- ``RedactionResult`` reports whether anything was found so callers can set
  the per-finding redaction status required by PLAN §15/§11.
- This module never receives or stores actual credentials: it only scrubs
  text that might contain them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Each entry: (kind, compiled regex). Order matters — see module docstring.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Authorization headers (case-insensitive scheme + value).
    (
        "authorization_header",
        re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic|token|digest)?\s*\S+"),
    ),
    # Cookie / Set-Cookie headers.
    ("cookie", re.compile(r"(?i)\b(set-cookie|cookie)\s*[:=]\s*\S[^\s;]*")),
    # Common credential key=value shapes: password=..., api_key: ..., secret="..."
    (
        "key_value_secret",
        re.compile(
            r"(?i)\b((?:api[_-]?key|apikey|secret|password|passwd|pwd|token"
            r"|access[_-]?token|refresh[_-]?token|client[_-]?secret)"
            r"(?:\s*[:=]\s*))(\"[^\"]{4,}\"|'[^']{4,}'|[^\s,;}]{4,})"
        ),
    ),
    # Bearer tokens appearing bare in text.
    ("bearer_token", re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]{8,}")),
    # Provider API key shapes.
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # Private keys in PEM form (multi-line).
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
    ),
    # Generic high-entropy-ish long tokens (last resort).
    (
        "generic_token",
        re.compile(r"\b[A-Za-z0-9_-]{32,64}\b(?<![A-Fa-f0-9]{32})(?![0-9a-f]{7}-[0-9a-f]{4})"),
    ),
]

# SHA/commit hashes and UUIDs are common non-secret long strings; exclude the
# obvious hex forms from the generic-token catch-all instead of redacting them.
_HEXISH = re.compile(r"^[0-9a-f]{32}$|^[0-9A-F]{32}$")


@dataclass
class RedactionResult:
    """Outcome of running the pipeline over one piece of content."""

    text: str
    matches: list[tuple[str, int]] = field(default_factory=list)  # (kind, count)

    @property
    def found_sensitive_content(self) -> bool:
        return bool(self.matches)

    @property
    def status(self) -> str:
        """Maps onto the schemas' redaction_status enum."""
        if self.matches:
            return "redacted"
        return "no_sensitive_content_found"


def _guard(m: re.Match, kind_hint: str = "") -> str:
    """Replacement callback. Generic-token hits that are plain hex digests or
    UUID-like strings are kept — they carry provenance, not secrets."""
    if m.re.pattern == _PATTERNS[-1][1].pattern:
        candidate = m.group(0)
        if _HEXISH.match(candidate) or candidate.count("-") == 4:
            return candidate
    return f"[REDACTED:{kind_hint}]"


def redact(content: str) -> RedactionResult:
    """Return *content* with every recognized secret replaced.

    Non-string input is coerced with ``str()`` so callers can pass structured
    objects they intend to serialize later.
    """
    if not isinstance(content, str):
        content = str(content)

    result_text = content
    counts: dict[str, int] = {}

    for kind, pattern in _PATTERNS:
        result_text, n = pattern.subn(lambda m, k=kind: _guard(m, k), result_text)
        if n:
            counts[kind] = counts.get(kind, 0) + n

    return RedactionResult(text=result_text, matches=[(k, c) for k, c in counts.items()])


def redact_mapping(data: dict) -> tuple[dict, bool]:
    """Redact every string value in a flat mapping. Returns (new_dict, changed)."""
    changed = False
    out = {}
    for key, value in data.items():
        res = redact(value)
        out[key] = res.text
        if res.found_sensitive_content:
            changed = True
    return out, changed
