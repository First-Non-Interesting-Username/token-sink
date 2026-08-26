"""Campaign authorization manifest (PLAN §5, §21 — issue #160).

The machine-checkable document that proves a campaign is authorized. PLAN §5
requires every campaign to carry an 'authorization source' and 'program
name'; §21 makes campaign scope and authorization mandatory and enforced at
runtime. This module defines the authorization *artifact* itself:

- A versioned manifest format: program identifier, in/out scope lists,
  allowed/prohibited actions, rate ceilings, a human sign-off record, and
  issue/expiration timestamps.
- Integrity: the content hash is recorded at creation; any post-hoc edit of
  the scope without regenerating the manifest is detected by ``verify()`` and
  blocks startup/campaign start.
- Import/export round-trip consistent with the campaign bundle so a run can
  later prove its authorization provenance (audit/submission evidence).
- Validity enforcement: expired or revoked manifests block active testing but
  allow read-only review of existing findings, with clear operator messaging.
- The manifest — not free-form config — is the runtime source of truth for
  §5 policy evaluation: a mismatch between the manifest and the campaign's
  ScopePolicy fails validation loudly rather than coercing silently.

Deterministic clock injection (``now`` callables) keeps expiry tests
table-driven without sleeping.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from policy.scope import ScopePolicy

MANIFEST_SCHEMA_VERSION = "1"


class ManifestError(Exception):
    """Invalid manifest structure or missing required fields."""


class TamperedManifestError(ManifestError):
    """Content hash mismatch: the manifest was edited after issuance."""


class ManifestExpiredError(ManifestError):
    """The manifest is past its expiration timestamp."""


class ManifestRevokedError(ManifestError):
    """The manifest was explicitly revoked."""


class ManifestMismatchError(ManifestError):
    """The campaign's live scope config disagrees with the manifest."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass
class SignOff:
    """Human sign-off record (§5: authorization must be human-granted)."""

    approver: str
    approved_at: str
    reference: str = ""


@dataclass
class AuthorizationManifest:
    """Versioned, integrity-checked proof that a campaign is authorized."""

    program_id: str
    issued_at: str
    expires_at: str
    sign_off: SignOff
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    rate_ceilings: dict[str, dict[str, float]] = field(default_factory=dict)
    revoked_at: str | None = None
    schema_version: str = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.program_id:
            raise ManifestError("program_id is required")
        if not self.sign_off.approver:
            raise ManifestError("human sign-off with an approver is required")
        try:
            if _parse_ts(self.expires_at) <= _parse_ts(self.issued_at):
                raise ManifestError("expires_at must be after issued_at")
        except ValueError as e:
            raise ManifestError(f"invalid timestamp: {e}") from e

    # -- serialization / integrity ----------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = {
            "schema_version": self.schema_version,
            "program_id": self.program_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "sign_off": vars(self.sign_off),
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "allowed_actions": list(self.allowed_actions),
            "prohibited_actions": list(self.prohibited_actions),
            "rate_ceilings": {k: dict(v) for k, v in self.rate_ceilings.items()},
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuthorizationManifest:
        try:
            return cls(
                schema_version=d["schema_version"],
                program_id=d["program_id"],
                issued_at=d["issued_at"],
                expires_at=d["expires_at"],
                revoked_at=d.get("revoked_at"),
                sign_off=SignOff(**d["sign_off"]),
                in_scope=list(d["in_scope"]),
                out_of_scope=list(d["out_of_scope"]),
                allowed_actions=list(d["allowed_actions"]),
                prohibited_actions=list(d["prohibited_actions"]),
                rate_ceilings={k: dict(v) for k, v in d["rate_ceilings"].items()},
            )
        except KeyError as e:
            raise ManifestError(f"missing manifest field: {e}") from e
        except TypeError as e:
            raise ManifestError(f"malformed manifest field: {e}") from e

    def export(self) -> dict[str, Any]:
        """Bundle with the recorded content hash for tamper detection."""
        body = self.to_dict()
        return {"content_hash": content_hash(body), **body}

    @classmethod
    def issue(
        cls,
        program_id: str,
        validity: Any,
        sign_off: SignOff,
        now: Callable[[], str] = _now,
        **kwargs: Any,
    ) -> AuthorizationManifest:
        """Create a manifest valid for ``validity`` seconds from now."""
        issued = _parse_ts(now())
        expires = issued + __import__("datetime").timedelta(seconds=validity)
        return cls(
            program_id=program_id,
            issued_at=issued.isoformat(),
            expires_at=expires.isoformat(),
            sign_off=sign_off,
            **kwargs,
        )

    # -- verification -------------------------------------------------------

    def verify_hash(self, recorded_hash: str) -> None:
        """Detect any post-hoc edit: recompute and compare."""
        actual = content_hash(self.to_dict())
        if actual != recorded_hash:
            raise TamperedManifestError(
                "manifest content hash mismatch — scope was edited after issuance"
            )

    def check_validity(self, now: Callable[[], str] = _now) -> None:
        """Expired or revoked manifests fail loudly, never silently pass."""
        if self.revoked_at is not None:
            raise ManifestRevokedError(
                f"manifest revoked at {self.revoked_at} — renew with the program "
                "before resuming active testing"
            )
        if _parse_ts(now()) >= _parse_ts(self.expires_at):
            raise ManifestExpiredError(
                f"manifest expired at {self.expires_at} — request renewal "
                "from the program owner to resume active testing"
            )


def content_hash(body: dict[str, Any]) -> str:
    """Stable canonical hash of a manifest body."""
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_exported(bundle: dict[str, Any], now: Callable[[], str] = _now) -> AuthorizationManifest:
    """Import an exported bundle: round-trip + tamper + validity checks."""
    bundle = dict(bundle)
    recorded = bundle.pop("content_hash", None)
    if recorded is None:
        raise ManifestError("exported manifest bundle lacks a content hash")
    manifest = AuthorizationManifest.from_dict(bundle)
    manifest.verify_hash(recorded)
    return manifest


def validate_against_scope(manifest: AuthorizationManifest, scope: ScopePolicy) -> None:
    """Fail LOUDLY on any mismatch between the manifest and live config.

    §21: the manifest, not free-form config, is the runtime source of truth.
    A discrepancy produces an error that blocks startup — never silent
    coercion of one side to match the other.
    """
    problems: list[str] = []

    def _norm(items: list[str]) -> set[str]:
        return {i.strip().lower() for i in items}

    if manifest.program_id and scope.program_name and manifest.program_id != scope.program_name:
        problems.append(
            f"program mismatch: manifest={manifest.program_id!r} config={scope.program_name!r}"
        )
    manifest_in, config_in = _norm(manifest.in_scope), {t.value for t in scope.in_scope}
    if manifest_in != config_in:
        problems.append(
            f"in-scope targets differ: manifest-only={sorted(manifest_in - config_in)} "
            f"config-only={sorted(config_in - manifest_in)}"
        )
    manifest_out = _norm(manifest.out_of_scope)
    config_out = {t.value for t in scope.out_of_scope}
    if manifest_out != config_out:
        problems.append(
            f"out-of-scope targets differ: manifest-only={sorted(manifest_out - config_out)} "
            f"config-only={sorted(config_out - manifest_out)}"
        )
    if _norm(manifest.prohibited_actions) != {a for a in scope.prohibited_actions}:
        problems.append("prohibited actions differ between manifest and campaign config")

    # Active testing may never be enabled under a manifest that prohibits it.
    if scope.active_testing_enabled and "active_testing" not in _norm(manifest.allowed_actions):
        problems.append("active testing enabled in config but not granted by manifest")

    if problems:
        raise ManifestMismatchError("; ".join(problems))


def active_testing_allowed(manifest: AuthorizationManifest, now: Callable[[], str] = _now) -> bool:
    """Gate for entering/continuing ACTIVE testing state.

    Expired/revoked manifests block active testing. Read-only review of
    existing findings remains possible — callers catch ManifestError and
    degrade to read-only mode instead.
    """
    try:
        manifest.check_validity(now)
    except ManifestError:
        return False
    return True
