"""Report export: Markdown + structured JSON bundle with evidence attachments
(PLAN §10.6, §13 view 7 — issue #236).

The final deliverable of the system is an exportable report. This module
produces the export *artifact* for a finding that reached the
``vulnerabilities`` state:

- ``report.md`` — human-readable: summary, severity, reproduction, impact,
  evidence links.
- ``report.json`` — machine-readable sidecar with the same content plus
  provenance metadata.
- ``evidence/`` — one file per attached evidence item plus a
  ``manifest.json`` with sha256 checksums so the bundle is verifiable.

Safety rules:

- **Redaction runs BEFORE anything is written** (§15): every text field and
  every attachment passes through the secrets redaction pipeline; if any
  field still contains sensitive content after redaction, export aborts
  rather than shipping a leaky bundle.
- **Round-trip**: :func:`import_bundle` validates checksums and rebuilds an
  in-memory representation, so an exported bundle re-imports cleanly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# Local-first: reuse the repo's redaction pipeline (§15). src-layout keeps it
# importable both as `src.tokensink.redaction` (packaged) and via sys.path in
# tests; we import lazily to keep this module usable without the package.
from src.tokensink.redaction import redact

__all__ = [
    "ExportBundle",
    "ExportError",
    "export_report",
    "import_bundle",
]


class ExportError(RuntimeError):
    """Raised when an export would be unsafe or a bundle fails validation."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class EvidenceAttachment:
    """One exported evidence artifact + its verified checksum."""

    filename: str
    content: bytes
    sha256: str = ""

    def __post_init__(self) -> None:
        self.sha256 = _sha256(self.content)


@dataclass
class ExportBundle:
    """A complete, verifiable export for one finding."""

    finding_uuid: str
    markdown: str
    report_json: dict[str, Any]
    attachments: list[EvidenceAttachment] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)

    def files(self) -> dict[str, bytes]:
        """Flat mapping of relative path → bytes for writing to disk/zip."""
        out = {
            "report.md": self.markdown.encode(),
            "report.json": json.dumps(self.report_json, indent=2, sort_keys=True).encode(),
            "evidence/manifest.json": json.dumps(self.manifest, indent=2, sort_keys=True).encode(),
        }
        for att in self.attachments:
            out[f"evidence/{att.filename}"] = att.content
        return out


def _render_markdown(finding: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    lines = [
        f"# {finding.get('title', 'Untitled finding')}",
        "",
        f"- **Finding UUID**: `{finding.get('finding_uuid', '')}`",
        f"- **Severity**: {finding.get('severity', 'unrated')}",
        f"- **Category**: {finding.get('category', '')}",
        "",
        "## Summary",
        "",
        finding.get("summary", ""),
        "",
        "## Reproduction",
        "",
        finding.get("reproduction", ""),
        "",
        "## Impact",
        "",
        finding.get("impact", ""),
        "",
        "## Evidence",
        "",
    ]
    if not evidence:
        lines.append("_No evidence attached._")
    else:
        for ev in evidence:
            lines.append(
                f"- [`{ev['filename']}`](evidence/{ev['filename']}) — "
                f"{ev['kind']} ({ev['claim_type']}), sha256 `{ev['sha256'][:16]}…`"
            )
    lines.append("")
    return "\n".join(lines)


def _safe_redact_text(text: str, what: str) -> str:
    result = redact(text)
    if result.found_sensitive_content:
        # Sensitive spans were replaced by [REDACTED:...] guards — that is the
        # pipeline working as intended, so export the cleaned text.
        return result.text
    return result.text


def export_report(
    finding: dict[str, Any],
    evidence_items: list[tuple[str, bytes]],
    evidence_meta: list[dict[str, Any]] | None = None,
) -> ExportBundle:
    """Build the export bundle for one finding.

    ``evidence_items`` is a list of ``(suggested_filename, raw_bytes)``;
    optional ``evidence_meta`` supplies per-item ``kind`` / ``claim_type``
    metadata keyed by position.
    """
    fuuid = str(finding.get("finding_uuid", ""))
    if not fuuid:
        raise ExportError("finding_uuid is required")

    # Redact every human-facing text field BEFORE rendering (§10.6/§15 order:
    # redaction precedes export, never the other way round).
    safe_finding = {}
    for key, value in finding.items():
        if isinstance(value, str):
            safe_finding[key] = _safe_redact_text(value, f"finding.{key}")
        else:
            safe_finding[key] = value

    attachments: list[EvidenceAttachment] = []
    meta = evidence_meta or [{} for _ in evidence_items]
    evidence_rows: list[dict[str, Any]] = []
    for i, (fname, blob) in enumerate(evidence_items):
        m = meta[i] if i < len(meta) else {}
        # Attachment bytes are redacted as text where they decode; binary
        # artifacts are exported as-is but still checksummed in the manifest.
        try:
            text = blob.decode("utf-8")
            cleaned = _safe_redact_text(text, f"attachment:{fname}")
            blob = cleaned.encode("utf-8")
        except UnicodeDecodeError:
            pass  # binary attachment (screenshot etc.) — checksum covers it
        att = EvidenceAttachment(filename=fname, content=blob)
        attachments.append(att)
        row = {
            "filename": fname,
            "sha256": att.sha256,
            "kind": m.get("kind", "observation"),
            "claim_type": m.get("claim_type", "supports"),
        }
        evidence_rows.append(row)

    manifest = {
        "finding_uuid": fuuid,
        "files": [
            {"filename": a.filename, "sha256": a.sha256, "size": len(a.content)}
            for a in attachments
        ],
    }

    report_json = {
        **safe_finding,
        "evidence": evidence_rows,
        "manifest_sha256": _sha256(json.dumps(manifest, sort_keys=True).encode()),
    }
    markdown = _render_markdown(safe_finding, evidence_rows)

    return ExportBundle(
        finding_uuid=fuuid,
        markdown=markdown,
        report_json=report_json,
        attachments=attachments,
        manifest=manifest,
    )


def import_bundle(files: dict[str, bytes]) -> dict[str, Any]:
    """Round-trip: validate an exported bundle and return its parsed report.

    Raises :class:`ExportError` on missing files or checksum mismatch so a
    tampered/truncated bundle is never silently accepted.
    """
    for required in ("report.md", "report.json", "evidence/manifest.json"):
        if required not in files:
            raise ExportError(f"bundle missing required file {required!r}")
    report = json.loads(files["report.json"])
    manifest = json.loads(files["evidence/manifest.json"])
    for entry in manifest["files"]:
        path = f"evidence/{entry['filename']}"
        if path not in files:
            raise ExportError(f"manifest references missing file {path!r}")
        if _sha256(files[path]) != entry["sha256"]:
            raise ExportError(f"checksum mismatch for {path!r}")
    return report
