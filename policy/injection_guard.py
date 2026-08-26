"""Prompt-injection defense pipeline (issue #258, PLAN §15, §19).

PLAN §15: content fetched from targets — and model output — is untrusted
input and can never override system policy or campaign scope. §19 makes
"prompt-injection content cannot override system policy" an explicit
safety test. This module is the enforcement pipeline:

- :func:`delimit` — structurally wraps untrusted content in a labeled,
  non-spoofable frame before it enters agent context. The frame carries a
  random nonce so a page cannot forge its own closing delimiter.
- :class:`InjectionScanner` — flags instruction-like constructs in target
  content aimed at tool use / policy change (``ignore previous
  instructions``, fake system prompts, tool-call syntax, scope/approval/
  budget directives). Flagged spans are neutralized: wrapped in visible
  ``[NEUTRALIZED]`` markers so downstream agents see that text was
  removed, not silently truncated.
- :func:`sanitize_model_output` — model output attempting to invoke tools
  or policy directly is rejected. Tools are only callable via the
  sanctioned runtime path; output is *data*, never a command channel.

Design notes:

- Detection is deliberately conservative (high precision on imperative
  patterns); the goal is defense-in-depth, not perfect recall — the
  delimiter + runtime path separation carry the real guarantee.
- Neutralization never deletes silently: every transformation is counted
  and reported, per the repo-wide "blocked events with actionable
  explanations" convention.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

__all__ = [
    "DelimitedContent",
    "InjectionFinding",
    "InjectionScanner",
    "SanitizeResult",
    "sanitize_model_output",
]


# ---------------------------------------------------------------------------
# Structural delimiting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelimitedContent:
    """Untrusted content inside a nonce-guarded frame."""

    framed: str
    nonce: str
    source_label: str


def delimit(content: str, source_label: str) -> DelimitedContent:
    """Wrap untrusted content in a labeled frame agents are taught to treat as data."""
    nonce = secrets.token_hex(8)
    begin = f"<<UNTRUSTED:{source_label}:{nonce}>>"
    end = f"<<END_UNTRUSTED:{nonce}>>"
    framed = f"{begin}\n{content}\n{end}"
    return DelimitedContent(framed=framed, nonce=nonce, source_label=source_label)


# ---------------------------------------------------------------------------
# Instruction-pattern scanning / neutralization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InjectionFinding:
    """One flagged instruction-like span."""

    pattern_name: str
    matched_text: str
    start: int
    end: int


@dataclass
class ScanReport:
    """Outcome of scanning one piece of untrusted content."""

    sanitized: str = ""
    findings: list[InjectionFinding] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.findings)


# Patterns aim at the actual attack surface: overriding instructions,
# forging authority, invoking tools/policy directly from content.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "instruction_override",
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    ),
    (
        "fake_system_prompt",
        re.compile(r"\b(?:system|developer)\s*(?:prompt|message)\s*:", re.I),
    ),
    (
        "policy_override",
        re.compile(
            r"(?:you\s+are\s+now|new\s+rules?|disregard\s+(?:the\s+)?)"
            r"\s*[^\n]{0,20}?(?:policy|scope|guidelines)",
            re.I,
        ),
    ),
    (
        "tool_invocation",
        re.compile(r"\b(?:call|run|execute|invoke)\s+(?:the\s+)?tool[:\s]+\w+", re.I),
    ),
    (
        "shell_directive",
        re.compile(r"(?:^|\n)\s*\$\s+\S|```(?:bash|sh|shell)\b", re.I),
    ),
    (
        "approval_forge",
        re.compile(
            r"\b(?:approval|approvals)\s+(?:is\s+)?(?:granted|approved|required\s*:\s*none)", re.I
        ),
    ),
    (
        "budget_change",
        re.compile(
            r"\b(?:raise|increase|set)\s+(?:the\s+)?(?:token|request|spend)\s+budget\b", re.I
        ),
    ),
    (
        "scope_change",
        re.compile(
            r"\b(?:add|expand|include)\s+[^\n]{0,40}\b"
            r"(?:to\s+|in\s+)?(?:scope|in[-\s]?scope targets)\b",
            re.I,
        ),
    ),
]


class InjectionScanner:
    """Flags and neutralizes instruction-like constructs in untrusted text."""

    def __init__(self, extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None) -> None:
        self._patterns = list(_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def scan(self, content: str) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []
        for name, pattern in self._patterns:
            for m in pattern.finditer(content):
                findings.append(
                    InjectionFinding(
                        pattern_name=name, matched_text=m.group(0), start=m.start(), end=m.end()
                    )  # noqa: E501
                )
        return sorted(findings, key=lambda f: f.start)

    def sanitize(self, content: str) -> ScanReport:
        """Neutralize flagged spans (kept, but visibly marked as removed)."""
        report = ScanReport()
        findings = self.scan(content)
        out: list[str] = []
        cursor = 0
        for f in findings:
            if f.start < cursor:
                continue  # overlapping earlier match already covered
            out.append(content[cursor : f.start])
            out.append(f"[NEUTRALIZED:{f.pattern_name}]")
            cursor = f.end
        out.append(content[cursor:])
        report.sanitized = "".join(out)
        report.findings = findings
        return report


# ---------------------------------------------------------------------------
# Model-output gate
# ---------------------------------------------------------------------------

_OUTPUT_TOOL_PATTERNS = [
    (
        "output_tool_call",
        re.compile(r"\b(?:I(?:'ll| will)? now|let me)\s+(?:call|invoke|run|execute)\b", re.I),
    ),
    (
        "output_tool_syntax",
        re.compile(r'<(?:tool|function)_call>|"\s*name\s*"\s*:\s*"(?:run_|execute_|call_)'),
    ),
    (
        "output_policy_claim",
        re.compile(
            r"\b(?:I\s+have\s+)?(?:granted|approved)\s+(?:myself|the campaign)"
            r"|scope\s+now\s+includes",
            re.I,
        ),
    ),
]


@dataclass(frozen=True)
class SanitizeResult:
    """Verdict on model output treated strictly as data."""

    accepted: bool
    violations: list[str] = field(default_factory=list)


def sanitize_model_output(output: str) -> SanitizeResult:
    """Reject model output that attempts direct tool/policy invocation.

    Model output is a *data* channel only. Anything resembling a tool call,
    self-granted approval, or scope change is refused with named violations;
    it never reaches the tool layer because tools are dispatched exclusively
    by the sanctioned runtime path, which never parses model prose.
    """
    violations: list[str] = []
    for name, pattern in _OUTPUT_TOOL_PATTERNS:
        m = pattern.search(output)
        if m:
            violations.append(name)
    return SanitizeResult(accepted=not violations, violations=violations)
