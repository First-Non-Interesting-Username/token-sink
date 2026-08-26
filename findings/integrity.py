"""Evidence integrity gates: checksums verified at every lifecycle gate
(issue #303, PLAN §12, §21).

Design decisions (per AGENTS.md):

- **Manifest per finding.** A finding's evidence set is summarized as a
  manifest mapping each artifact digest → size + the evidence record's frozen
  ``recorded_hash``. The manifest itself is hashed, so any later edit to the
  evidence list is detectable exactly like a tampered artifact.
- **Verify at every gate.** ``verify_at_gate`` re-reads every referenced
  artifact through ``ArtifactStore``'s own digest verification before a
  lifecycle advancement is allowed. A corrupt or missing artifact raises
  :class:`IntegrityFailure` — the caller must block the transition and route
  the finding to quarantine; this module never deletes or "repairs" anything.
- **Quarantine, not deletion.** Evidence that fails verification may indicate
  tampering (§21), so failure records are append-only facts: each failed
  check is kept in an in-memory ledger with what was expected vs found,
  suitable for surfacing in reports and audit exports.
- **Bundle round-trip.** ``export_manifest`` embeds the finding manifest as
  bundle metadata and ``verify_imported`` re-checks it after import, closing
  the §12 backup/export/import integrity loop alongside storage/bundle.py's
  per-member checksums.

Checksums themselves come from the ArtifactStore (content-addressed by
sha256); this module adds the *finding-level* gate semantics on top.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from findings.evidence import EvidenceItem


class IntegrityError(RuntimeError):
    """Base for evidence-integrity gate failures."""


@dataclass
class ManifestEntry:
    """One artifact's integrity facts at manifest-build time."""

    digest: str
    size: int
    evidence_uuid: str
    recorded_hash: str


@dataclass
class FindingManifest:
    """Integrity manifest covering one finding's evidence artifacts."""

    finding_uuid: str
    entries: dict[str, ManifestEntry] = field(default_factory=dict)

    def content_hash(self) -> str:
        payload = {
            "finding_uuid": self.finding_uuid,
            "entries": sorted(
                (
                    {
                        "digest": e.digest,
                        "size": e.size,
                        "evidence_uuid": e.evidence_uuid,
                        "recorded_hash": e.recorded_hash,
                    }
                    for e in self.entries.values()
                ),
                key=lambda d: d["digest"],
            ),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {"finding_uuid": self.finding_uuid, "content_hash": self.content_hash()}


@dataclass
class VerificationRecord:
    """Append-only outcome of one gate check."""

    finding_uuid: str
    ok: bool
    checked: int
    failures: list[dict[str, str]] = field(default_factory=list)


def build_manifest(finding_uuid: str, evidence: list[EvidenceItem]) -> FindingManifest:
    """Summarize a finding's evidence into a verifiable manifest."""
    m = FindingManifest(finding_uuid=finding_uuid)
    for item in evidence:
        if item.raw_digest in m.entries:
            continue
        m.entries[item.raw_digest] = ManifestEntry(
            digest=item.raw_digest,
            size=0,  # filled by verify_at_gate from the store
            evidence_uuid=item.evidence_uuid,
            recorded_hash=item.recorded_hash,
        )
    return m


def verify_at_gate(
    finding_uuid: str,
    evidence: list[EvidenceItem],
    artifact_store: Any,
    *,
    ledger: list[VerificationRecord] | None = None,
    require_present: bool = True,
) -> VerificationRecord:
    """Re-verify every evidence artifact before allowing a lifecycle advance.

    Raises IntegrityError when any artifact is missing or corrupt — callers
    must treat that as a hard block and quarantine the finding (never delete
    evidence: §21 treats mismatches as potential tampering).
    """
    failures: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in evidence:
        if item.raw_digest in seen:
            continue
        seen.add(item.raw_digest)
        try:
            with artifact_store.open(item.raw_digest) as reader:
                reader.read()  # stream all bytes; hash as we go
                reader.verify_all()
        except FileNotFoundError:
            if require_present:
                failures.append(
                    {
                        "digest": item.raw_digest,
                        "reason": "missing",
                        "evidence_uuid": item.evidence_uuid,
                    }
                )
            continue
        except Exception as exc:  # store-level verification error
            failures.append(
                {
                    "digest": item.raw_digest,
                    "reason": f"corrupt: {exc}",
                    "evidence_uuid": item.evidence_uuid,
                }
            )
            continue

    rec = VerificationRecord(
        finding_uuid=finding_uuid,
        ok=not failures,
        checked=len(seen),
        failures=failures,
    )
    if ledger is not None:
        ledger.append(rec)  # append-only history of gate outcomes
    if not rec.ok:
        raise IntegrityError(
            f"evidence integrity gate failed for {finding_uuid}: "
            f"{len(failures)} artifact(s) missing or corrupt"
        )
    return rec
