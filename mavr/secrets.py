"""Secrets via the OS keyring.

All API keys (and any other sensitive values) are stored in the OS
keyring under the service name ``"mavr"`` and referenced by name from
configuration. The keyring is never logged; values are only returned
when explicitly requested by trusted code.
"""
from __future__ import annotations

import os
from typing import Final

import keyring
import keyring.errors

from mavr.observability.logging import get_logger

log = get_logger(__name__)

SERVICE_NAME: Final[str] = "mavr"


class SecretError(RuntimeError):
    """Raised when a secret cannot be resolved."""


def _coerce_name(name: str) -> str:
    if not name or not name.strip():
        raise SecretError("secret name must not be empty")
    return name.strip()


def set_secret(name: str, value: str) -> None:
    """Store a secret under ``name`` in the OS keyring."""
    n = _coerce_name(name)
    if not value:
        raise SecretError("secret value must not be empty")
    try:
        keyring.set_password(SERVICE_NAME, n, value)
        log.info("secret_set", name=n)
    except keyring.errors.KeyringError as exc:
        raise SecretError(f"failed to store secret {n!r}: {exc}") from exc


def get_secret(name: str) -> str | None:
    """Return a secret by name, or ``None`` if not present."""
    n = _coerce_name(name)
    try:
        return keyring.get_password(SERVICE_NAME, n)
    except keyring.errors.KeyringError as exc:
        raise SecretError(f"failed to read secret {n!r}: {exc}") from exc


def require_secret(name: str) -> str:
    """Return a secret, raising if missing."""
    val = get_secret(name)
    if val is None:
        raise SecretError(f"required secret {name!r} is not set in the keyring")
    return val


def delete_secret(name: str) -> None:
    """Delete a secret. Missing entries are ignored."""
    n = _coerce_name(name)
    try:
        keyring.delete_password(SERVICE_NAME, n)
        log.info("secret_deleted", name=n)
    except keyring.errors.PasswordDeleteError:
        return
    except keyring.errors.KeyringError as exc:
        raise SecretError(f"failed to delete secret {n!r}: {exc}") from exc


def list_secret_names() -> list[str]:
    """Best-effort list of secret names stored under the MAVR service.

    Returns an empty list if the keyring backend does not support listing
    (e.g. macOS Keychain on some versions).
    """
    try:
        items = keyring.get_credential(SERVICE_NAME, None)  # may raise NotImplementedError
    except (keyring.errors.KeyringError, NotImplementedError, AttributeError):
        return []
    if items is None:
        return []
    name = getattr(items, "username", None)
    return [name] if name else []


def keyring_reachable() -> tuple[bool, str]:
    """Probe the keyring backend.

    Returns ``(ok, message)``; the message is safe to display to the user.
    Never returns the secret value.
    """
    try:
        # round-trip a sentinel that we discard
        sentinel_name = "__mavr_probe__"
        keyring.set_password(SERVICE_NAME, sentinel_name, "ok")
        val = keyring.get_password(SERVICE_NAME, sentinel_name)
        try:
            keyring.delete_password(SERVICE_NAME, sentinel_name)
        except keyring.errors.PasswordDeleteError:
            pass
        if val != "ok":
            return False, "keyring round-trip mismatch"
        backend = os.environ.get("MAVR_KEYRING_BACKEND") or type(keyring.get_keyring()).__name__
        return True, f"keyring backend reachable: {backend}"
    except (keyring.errors.KeyringError, NotImplementedError) as exc:
        return False, f"keyring error: {exc}"
