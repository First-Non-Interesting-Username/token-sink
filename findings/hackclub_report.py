"""Hack Club Security report format (issue #123, PLAN §10.6, §15).

The system's end target is authorized submission to
https://security.hackclub.com/ — but submission stays a separate,
human-approved action forever (§15). This module covers the *format* half:

- :data:`TEMPLATE_VERSION` / :data:`REQUIRED_SECTIONS` — a versioned report
  template mapped from validated finding data, so old exports stay
  reproducible against the template version that produced them.
- :func:`map_finding_to_report` — builds a draft report dict from a
  validated finding record.
- :class:`ReportValidator` — completeness gate run before a report becomes
  submission-eligible: every required section present, every factual claim
  traceable to evidence (delegates to ``EvidenceStore.check_traceability``,
  issue #84), PoC reproducibility checklist satisfied (#94), and redaction
  confirmed (#29). Violations are returned as specific, actionable failures.
- :func:`export_markdown` / :func:`export_json` — clean render bundles for
  manual paste/submission by the human operator.
- :func:`dry_run` — reports exactly which gates would block and why,
  without producing an export.

There is deliberately NO network code in this module: nothing here submits
anything anywhere.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

TEMPLATE_VERSION = 1

# Required sections in presentation order (Hack Club Security fields).
# Kept data-level so the validator and renderers share one source of truth.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "title",
    "affected_asset",
    "vulnerability_class",  # CWE mapping
    "severity_assessment",  # severity + rationale
    "reproduction_steps",
    "poc_reference",
    "impact_analysis",
    "remediation_suggestion",
    "evidence_links",
)

# Common secret shapes; presence anywhere in the export blocks it. Deliberately
# conservative patterns tuned for false positives over misses (a blocked export
# costs the operator seconds; a leaked token costs far more).
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),  # OpenAI-style keys
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),  # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access keys
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|api[_-]?key|secret)\s*[:=]\s*\S+"),
)

# A CWE id looks like "CWE-79". Free text is rejected by the validator so
# vulnerability_class stays machine-comparable across reports.
_CWE_RE = re.compile(r"^CWE-\d{1,4}$")


class ReportError(Exception):
    """Raised for structurally invalid report inputs."""


@dataclass
class ValidationFailure:
    """One specific, operator-actionable reason a report is not submittable."""

    gate: str  # sections | traceability | poc_checklist | redaction | cwe
    message: str


@dataclass
class GateReport:
    """Result of running all gates (validation or dry-run)."""

    template_version: int
    failures: list[ValidationFailure] = field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return not self.failures

    def summary(self) -> str:
        if self.eligible:
            return f"submission-eligible (template v{self.template_version})"
        lines = [f"blocked by {len(self.failures)} failure(s) (template v{self.template_version}):"]
        lines += [f"  - [{f.gate}] {f.message}" for f in self.failures]
        return "\n".join(lines)


def map_finding_to_report(finding: dict[str, Any]) -> dict[str, Any]:
    """Draft a Hack Club report dict from a validated finding record.

    Field names follow the finding lifecycle schema (findings/lifecycle.py);
    missing optional inputs become empty placeholders the validator will
    silently dropping the section.
    """
    return {
        "template_version": TEMPLATE_VERSION,
        "title": finding.get("title", ""),
        "affected_asset": finding.get("affected_asset", ""),
        "vulnerability_class": finding.get("cwe", ""),  # must be set explicitly
        "severity_assessment": {
            "severity": finding.get("severity", ""),
            "rationale": finding.get("severity_rationale", ""),
        },
        "reproduction_steps": list(finding.get("repro_outline") or []),
        "poc_reference": finding.get("poc_ref", ""),
        "impact_analysis": finding.get("impact_analysis", ""),
        "remediation_suggestion": finding.get("remediation", ""),
        "evidence_links": list(finding.get("evidence_refs") or []),
        "claims": list(finding.get("claims") or []),
        "poc_checklist": list(finding.get("poc_checklist") or []),
    }


class ReportValidator:
    """Completeness + safety gate for submission eligibility."""

    def __init__(self, evidence_store: Any | None = None):
        # evidence_store: findings.evidence.EvidenceStore (or duck-typed);
        # None disables claim traceability checking (unit-test convenience).
        self.evidence_store = evidence_store

    def validate(self, report: dict[str, Any]) -> GateReport:
        gr = GateReport(template_version=int(report.get("template_version", TEMPLATE_VERSION)))
        self._check_sections(report, gr)
        self._check_cwe(report, gr)
        self._check_traceability(report, gr)
        self._check_poc_checklist(report, gr)
        self._check_redaction(report, gr)
        return gr

    # -- gates ---------------------------------------------------------------

    def _check_sections(self, report: dict[str, Any], gr: GateReport) -> None:
        for section in REQUIRED_SECTIONS:
            value = report.get(section)
            if value is None or value == "" or value == []:
                gr.failures.append(
                    ValidationFailure("sections", f"required section missing/empty: {section}")
                )
        sev = report.get("severity_assessment")
        if isinstance(sev, dict):
            if not sev.get("severity"):
                gr.failures.append(
                    ValidationFailure("sections", "severity_assessment.severity is empty")
                )
            if not str(sev.get("rationale", "")).strip():
                gr.failures.append(
                    ValidationFailure("sections", "severity_assessment.rationale is empty")
                )

    def _check_cwe(self, report: dict[str, Any], gr: GateReport) -> None:
        vc = str(report.get("vulnerability_class", ""))
        if vc and not _CWE_RE.match(vc):
            gr.failures.append(
                ValidationFailure(
                    "cwe", f"vulnerability_class {vc!r} is not a CWE id (expected 'CWE-<number>')"
                )
            )

    def _check_traceability(self, report: dict[str, Any], gr: GateReport) -> None:
        claims = report.get("claims") or []
        if not claims:
            return  # no claims made → nothing to trace (sections gate still applies)
        if self.evidence_store is None:
            return  # checker unavailable; traceability enforced downstream
        result = self.evidence_store.check_traceability(claims)
        for v in result.violations:
            gr.failures.append(ValidationFailure("traceability", v))

    def _check_poc_checklist(self, report: dict[str, Any], gr: GateReport) -> None:
        checklist = report.get("poc_checklist")
        if checklist is None:
            return  # no PoC attached at all — poc_reference section gate covers it
        unsatisfied = [
            item for item in checklist if not (isinstance(item, dict) and item.get("satisfied"))
        ]
        for item in unsatisfied:
            gr.failures.append(
                ValidationFailure(
                    "poc_checklist",
                    f"PoC reproducibility item not satisfied: {item.get('item', '<unlabeled>')}",
                )
            )

    def _check_redaction(self, report: dict[str, Any], gr: GateReport) -> None:
        blob = json.dumps(report, default=str)
        for pattern in SECRET_PATTERNS:
            m = pattern.search(blob)
            if m:
                # Never echo the secret itself into the failure message.
                gr.failures.append(
                    ValidationFailure(
                        "redaction",
                        f"possible unredacted secret matching {pattern.pattern!r} "
                        f"in report content",
                    )
                )


# --- exports ------------------------------------------------------------------


def export_markdown(report: dict[str, Any]) -> str:
    """Render a submission-ready Markdown bundle (manual paste target)."""
    sev = report.get("severity_assessment") or {}
    lines = [
        f"# {report.get('title', '')}".rstrip(),
        "",
        f"- **Affected asset**: {report.get('affected_asset', '')}",
        f"- **Vulnerability class**: {report.get('vulnerability_class', '')}",
        f"- **Severity**: {sev.get('severity', '')}",
    ]
    rationale = str(sev.get("rationale", "")).strip()
    if rationale:
        lines.append(f"  - Rationale: {rationale}")
    lines += ["", "## Reproduction steps", ""]
    steps = report.get("reproduction_steps") or []
    if not steps:
        lines.append("_(none provided)_")
    for i, step in enumerate(steps, 1):
        lines.append(f"{i}. {step}")
    lines += [
        "",
        "## Proof of concept",
        "",
        str(report.get("poc_reference", "") or "_(none)_"),
        "",
        "## Impact analysis",
        "",
        str(report.get("impact_analysis", "") or "_(none)_"),
        "",
        "## Remediation suggestion",
        "",
        str(report.get("remediation_suggestion", "") or "_(none)_"),
        "",
        "## Supporting evidence",
        "",
    ]
    links = report.get("evidence_links") or []
    if not links:
        lines.append("_(none)_")
    for ref in links:
        lines.append(f"- `{ref}`")
    lines.append("")
    return "\n".join(lines)


def export_json(report: dict[str, Any]) -> str:
    """Stable JSON bundle (sorted keys so exports are byte-reproducible)."""
    return json.dumps(report, sort_keys=True, indent=2)


# --- dry-run --------------------------------------------------------------------


def dry_run(report: dict[str, Any], validator: ReportValidator) -> GateReport:
    """Report exactly which gates would block submission and why, exporting
    nothing."""
    return validator.validate(report)


__all__ = [
    "GateReport",
    "REQUIRED_SECTIONS",
    "ReportError",
    "ReportValidator",
    "TEMPLATE_VERSION",
    "ValidationFailure",
    "dry_run",
    "export_json",
    "export_markdown",
    "map_finding_to_report",
]
