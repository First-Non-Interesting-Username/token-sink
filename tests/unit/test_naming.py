"""Unit tests for safe artifact naming (PLAN §12 + §19.1)."""

import pytest

from storage.naming import UnsafeNameError, validate_name, validate_rel_path


@pytest.mark.parametrize(
    "name",
    [
        "report.md",
        "finding_2026-08-25.json",
        "poc.sh",
        "A" * 255,
        "9lives.txt",
    ],
)
def test_accepts_safe_names(name):
    assert validate_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "..\\windows",
        "/etc/passwd",
        "C:\\temp\\x",
        "sub/dir.md",  # separators are never allowed in a single name
        ".",
        "..",
        "",
        "  ",
        "nul",
        "COM1",
        "com1.txt",
        "name\x00hidden",
        "bell\x07",
        "weird$name",
        'quote"name',
        "x" * 256,
        None,
    ],
)
def test_rejects_unsafe_names(name):
    with pytest.raises(UnsafeNameError):
        validate_name(name)


def test_rel_path_ok():
    p = validate_rel_path("findings/2026/report.md")
    assert str(p) == "findings/2026/report.md"


@pytest.mark.parametrize(
    "rel",
    ["../up.md", "/abs/path", "a/../../b", "back\\slash.md", "", "./here"],
)
def test_rel_path_rejects(rel):
    with pytest.raises(UnsafeNameError):
        validate_rel_path(rel)
