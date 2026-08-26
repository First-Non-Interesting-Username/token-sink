"""PoC safety validator (issue #164, PLAN §10.4/§10.5/§15).

A mechanical, static gate that runs on a PoC draft record *before* it may
advance from ``poc_draft`` to ``poc_review``. The goal: reviewer attention is
never wasted on non-conforming drafts and unsafe content never propagates.

Checks (all offline — nothing here executes PoC commands or touches a
network):

1. Completeness — required §10.4 sections present and non-empty.
2. Target scope — every URL/host mentioned anywhere in the record must
   classify as in-scope via :class:`policy.scope.ScopePolicy`, or be a local
   fixture (loopback) reference when ``uses_local_fixture`` is true.
3. Destructive patterns — denylisted commands/methods/payloads (configurable).
4. Secret/PII scan — built-in detector set applied to command strings,
   payloads and prose alike.
5. Fixture-preference nudge — warn when the finding looks demonstrable with a
   local mock instead of a live target (§10.4 "prefer a local fixture").

The result is a JSON-serializable verdict dict meant to be stored alongside
the PoC version; any FAIL verdict blocks advancement to review.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Severity levels for individual findings.
LEVEL_FAIL = "fail"
LEVEL_WARN = "warn"

# Loopback hosts accepted as local-fixture targets (mirrors PLAN §10.4's
# "local fixtures preferred" and fixtures/target's loopback-only binding).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Built-in detector sets (issue #164 asks to reuse the #29 detector set; the
# full redaction pipeline is injectable upstream, so these are conservative,
# high-precision patterns that catch obvious leaks without excessive FPs)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{25,}\b", re.IGNORECASE)),
    (
        "generic_api_key_param",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|passwd|token)\s*[=:]\s*['\"]?[A-Za-z0-9+/_\-]{12,}"
        ),
    ),
)

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn_like", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card_like", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
)

# Default destructive-pattern denylist (§10.4: no destructive actions).
# Policy configs may extend or replace these via DestructivePatterns.
_DEFAULT_DESTRUCTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("rm_rf_variant", r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+"),
    ("mkfs", r"\bmkfs(\.\w+)?\b"),
    ("dd_to_device", r"\bdd\b[^|]*\bof=/dev/"),
    ("drop_table", r"(?i)\bDROP\s+(TABLE|DATABASE)\b"),
    ("truncate_table", r"(?i)\bTRUNCATE\s+TABLE\b"),
    ("shutdown_reboot", r"\b(shutdown|reboot|halt)(\s|$)"),
    ("fork_bomb", r":\(\)\s*\{\s*:\|\:&\s*\};:"),
    ("mass_request_loop", r"(?i)\bfor\b.*\bin\b.*\b(curl|wget|httpx|requests)\b"),
    ("credential_stuffing", r"(?i)credential[_ ]?stuffing|\bhydra\b|\bpatator\b"),
    ("chmod_777_root", r"\bchmod\s+-R?\s*777\s+/\b"),
)


@dataclass
class DestructivePatterns:
    """Configurable denylist; each entry is (name, regex source)."""

    patterns: tuple[tuple[str, str], ...] = _DEFAULT_DESTRUCTIVE_PATTERNS

    def compiled(self) -> list[tuple[str, re.Pattern[str]]]:
        return [(name, re.compile(src)) for name, src in self.patterns]


@dataclass
class ValidatorVerdict:
    """Stored verdict for one PoC draft version."""

    poc_uuid: str
    passed: bool
    checks: list[dict[str, Any]] = field(default_factory=list)

    def add(self, level: str, code: str, message: str, detail: dict | None = None) -> None:
        self.checks.append(
            {"level": level, "code": code, "message": message, "detail": detail or {}}
        )
        if level == LEVEL_FAIL:
            self.passed = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "poc_uuid": self.poc_uuid,
            "passed": self.passed,
            "checks": self.checks,
        }


class PoCSafetyValidator:
    """Static validator over PoC draft records (poc.schema.json shape)."""

    def __init__(
        self,
        scope_policy: Any = None,
        destructive: DestructivePatterns | None = None,
        extra_secret_patterns: tuple[tuple[str, str], ...] = (),
    ) -> None:
        # scope_policy is a policy.scope.ScopePolicy or None (no-scope mode:
        # only loopback fixture references are then acceptable).
        self.scope = scope_policy
        self.destructive = destructive or DestructivePatterns()
        self._secret_patterns = _SECRET_PATTERNS + tuple(
            (name, re.compile(src)) for name, src in extra_secret_patterns
        )

    # -- public API --------------------------------------------------------
    def validate(self, poc: dict[str, Any]) -> ValidatorVerdict:
        verdict = ValidatorVerdict(poc_uuid=str(poc.get("poc_uuid", "")), passed=True)
        self._check_completeness(poc, verdict)
        self._check_scope(poc, verdict)
        self._check_destructive(poc, verdict)
        self._check_secrets_pii(poc, verdict)
        self._check_fixture_preference(poc, verdict)
        return verdict

    # -- checks ------------------------------------------------------------
    def _check_completeness(self, poc: dict, v: ValidatorVerdict) -> None:
        # §10.4 required sections; schema enforces presence of keys but the
        # validator catches empty-string stubs that would waste review time.
        required_text = {
            "setup": poc.get("setup"),
            "expected_output": poc.get("expected_output"),
            "safety_notes": poc.get("safety_notes"),
        }
        for name, value in required_text.items():
            if not isinstance(value, str) or not value.strip():
                v.add(
                    LEVEL_FAIL,
                    f"missing_section:{name}",
                    f"required section '{name}' is missing or empty",
                )
        for name in ("commands", "cleanup_steps"):
            value = poc.get(name)
            if not isinstance(value, list) or not value:
                v.add(
                    LEVEL_FAIL,
                    f"missing_section:{name}",
                    f"required section '{name}' must be a non-empty list",
                )

    def _check_scope(self, poc: dict, v: ValidatorVerdict) -> None:
        uses_fixture = bool(poc.get("uses_local_fixture"))
        text_blob = "\n".join(
            str(x)
            for x in [poc.get("setup"), *poc.get("commands", []), poc.get("expected_output")]
            if x
        )
        urls = _URL_RE.findall(text_blob)
        if poc.get("target"):
            urls.append(json_target_url(poc["target"]))
        for url in urls:
            host = _host_of(url)
            if host in _LOOPBACK_HOSTS:
                continue  # local fixture target — always fine
            if self.scope is None:
                v.add(
                    LEVEL_FAIL,
                    "out_of_scope_target",
                    f"{url} referenced without approved campaign scope"
                    " (no-scope mode allows only local fixtures)",
                    {"url": url},
                )
            else:
                status, _ = self.scope.classify_target(url)
                if status != "in":
                    v.add(
                        LEVEL_FAIL,
                        "out_of_scope_target",
                        f"{url} is not in approved campaign scope",
                        {"url": url, "status": status},
                    )
        # A PoC claiming fixture use should actually point at loopback.
        if uses_fixture and not urls:
            v.add(
                LEVEL_WARN,
                "fixture_unreferenced",
                "uses_local_fixture=true but no URL appears in setup/commands",
            )
        if uses_fixture:
            non_loopback = [u for u in urls if _host_of(u) not in _LOOPBACK_HOSTS]
            if non_loopback:
                v.add(
                    LEVEL_WARN,
                    "fixture_mixed_with_live",
                    "fixture-preferred PoC also references live targets",
                    {"urls": non_loopback},
                )

    def _check_destructive(self, poc: dict, v: ValidatorVerdict) -> None:
        blob = "\n".join(str(x) for x in [poc.get("setup"), *poc.get("commands", [])] if x)
        for name, pattern in self.destructive.compiled():
            m = pattern.search(blob)
            if m:
                v.add(
                    LEVEL_FAIL,
                    f"destructive_pattern:{name}",
                    f"denylisted destructive pattern matched: {name}",
                    {"snippet": _clip(m.group(0))},
                )

    def _check_secrets_pii(self, poc: dict, v: ValidatorVerdict) -> None:
        # Scan EVERYTHING textual — commands and embedded payloads included,
        # per issue requirement ("not just prose").
        blob = "\n".join(
            str(x)
            for x in [
                poc.get("setup"),
                poc.get("expected_output"),
                poc.get("safety_notes"),
                json.dumps(poc.get("target") or ""),
                *poc.get("commands", []),
                *poc.get("cleanup_steps", []),
            ]
            if x
        )
        for name, pattern in self._secret_patterns:
            for m in pattern.finditer(blob):
                v.add(
                    LEVEL_FAIL,
                    f"secret_detected:{name}",
                    f"possible secret ({name}) present — redact before review",
                    {"snippet": _clip(m.group(0))},
                )
        for name, pattern in _PII_PATTERNS:
            for m in pattern.finditer(blob):
                v.add(
                    LEVEL_FAIL,
                    f"pii_detected:{name}",
                    f"possible PII ({name}) present — redact before review",
                    {"snippet": _clip(m.group(0))},
                )

    def _check_fixture_preference(self, poc: dict, v: ValidatorVerdict) -> None:
        # §10.4 bullet: prefer a local mock when it demonstrates the issue.
        if not poc.get("uses_local_fixture") and poc.get("target"):
            target = poc.get("target") or {}
            url = json_target_url(target) if not isinstance(target, str) else target
            if url and _host_of(url) not in _LOOPBACK_HOSTS:
                v.add(
                    LEVEL_WARN,
                    "prefer_local_fixture",
                    "live target used where a local fixture may demonstrate "
                    "the issue — confirm necessity",
                    {"url": url},
                )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _host_of(url: str) -> str:
    m = re.match(r"[a-z]+://([^/:?#]+)", url, re.IGNORECASE)
    return (m.group(1) if m else "").lower().rstrip(".")


def _clip(text: str, limit: int = 60) -> str:
    # Snippets stored in verdicts are clipped so no full secret ever lands
    # in the verdict record itself.
    return text[:limit]


def json_target_url(target: Any) -> str:
    """Best-effort URL extraction from a schema `target` object."""
    if isinstance(target, str):
        return target
    if isinstance(target, dict):
        for key in ("url", "base_url", "host", "hostname", "domain"):
            val = target.get(key)
            if isinstance(val, str) and val:
                return val if "//" in val else f"https://{val}"
    return ""
