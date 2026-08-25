"""Safe artifact/file naming for the storage layer (PLAN §12).

Filenames are never identity — content digests are (see artifacts.py). But
user- and model-supplied names still end up in paths (finding IDs, PoC
files, export bundles), so every name is validated before it ever touches
the filesystem. Rules are deliberately strict: anything ambiguous is
rejected rather than sanitized, because silent rewriting hides bugs and
can mask an attack.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

# Printable ASCII minus path/hostile metacharacters; keeps names portable
# across filesystems and safe to embed in URLs/tar members.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

# Windows-reserved device names (case-insensitive) — rejected so exports
# can't create files that shadow devices on Windows-mounted shares.
_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

MAX_NAME_LEN = 255


class UnsafeNameError(ValueError):
    """Raised when a candidate artifact name fails validation."""


def validate_name(name: str) -> str:
    """Return *name* unchanged if safe, else raise UnsafeNameError.

    Checks, in order: type/emptiness, length, traversal segments, absolute
    or drive-qualified paths, control characters, reserved device names,
    and the overall character allowlist.
    """
    if not isinstance(name, str) or not name:
        raise UnsafeNameError("artifact name must be a non-empty string")
    if len(name.encode("utf-8")) > MAX_NAME_LEN:
        raise UnsafeNameError(f"name longer than {MAX_NAME_LEN} bytes")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise UnsafeNameError(f"control characters in name: {name!r}")
    if name in {".", ".."}:
        raise UnsafeNameError(f"path-traversal segment in name: {name!r}")
    # Reject anything that *parses* as a path with structure (separators,
    # drive letters, UNC prefixes) rather than trying to normalize it.
    if "/" in name or "\\" in name or ":" in name:
        if _looks_like_traversal(name):
            raise UnsafeNameError(f"path traversal in name: {name!r}")
        raise UnsafeNameError(
            f"path separators/drive letters not allowed in artifact names: {name!r}"
        )
    stem = name.split(".")[0].upper()
    if stem in _RESERVED:
        raise UnsafeNameError(f"reserved device name: {name!r}")
    if not _SAFE_NAME.match(name):
        raise UnsafeNameError(f"unsafe characters in artifact name: {name!r}")
    return name


def _looks_like_traversal(name: str) -> bool:
    """Detect ../, ..\\, absolute POSIX, drive-letter, or UNC-style paths."""
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        return True
    w = PureWindowsPath(name)
    return w.is_absolute() or w.drive != "" or ".." in w.parts


def validate_rel_path(rel: str) -> PurePosixPath:
    """Validate a relative multi-segment path (e.g. inside export bundles).

    Returns the normalized PurePosixPath. Rejects absolute paths,
    backslashes-as-separators ambiguity, and any '..' segment.
    """
    if not isinstance(rel, str) or not rel:
        raise UnsafeNameError("path must be a non-empty string")
    if "\\" in rel:
        raise UnsafeNameError(f"backslash in path: {rel!r}")
    if rel.startswith("./") or rel.startswith("../"):
        raise UnsafeNameError(f"unsafe relative path: {rel!r}")
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts or "." in p.parts or not p.parts:
        raise UnsafeNameError(f"unsafe relative path: {rel!r}")
    for part in p.parts:
        validate_name(part)
    return p
