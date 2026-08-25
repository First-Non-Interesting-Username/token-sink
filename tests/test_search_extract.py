"""Tests for mavr.search.extract.

We patch :mod:`subprocess.run` to drive the curl path so the tests
stay offline and deterministic. The Jina fallback is exercised via
a separate path with a local URL that's in the allowlist.
"""
from __future__ import annotations

import subprocess
from typing import Any

import pytest

from mavr.search import extract, safety
from mavr.search.extract import (
    ALLOWED_CONTENT_TYPES,
    ContentTypeRejected,
    ExtractionOptions,
    FetchFailed,
    RedirectLimitExceeded,
    fetch,
    filter_forwarded_headers,
    store_extraction,
)
from mavr.storage.artifacts import ArtifactStore

# ---- helpers --------------------------------------------------------------


def _make_curl_result(
    *,
    body: bytes,
    status: int = 200,
    content_type: str = "text/html; charset=utf-8",
    redirects: int = 0,
) -> subprocess.CompletedProcess:
    """Build a fake CompletedProcess whose stdout is curl's combined
    header + body output.
    """
    head_lines = [f"HTTP/1.1 {status} OK"]
    for _ in range(redirects):
        head_lines.append("HTTP/1.1 302 Found")
    head_lines.append(f"Content-Type: {content_type}")
    head_lines.append(f"Content-Length: {len(body)}")
    headers_block = ("\r\n".join(head_lines) + "\r\n\r\n").encode("ascii")
    stdout = headers_block + body
    return subprocess.CompletedProcess(
        args=["curl"],
        returncode=0,
        stdout=stdout,
        stderr=b"",
    )


def _patch_curl(monkeypatch, *, result: subprocess.CompletedProcess) -> None:
    monkeypatch.setattr(
        "mavr.search.extract.subprocess.run", lambda *a, **kw: result
    )


# ---- public API -----------------------------------------------------------


def test_filter_forwarded_headers_drops_dangerous() -> None:
    headers = {
        "Authorization": "Bearer secret",
        "Cookie": "session=abc",
        "X-API-Key": "k",
        "User-Agent": "mavr",
    }
    out = filter_forwarded_headers(headers)
    assert "Authorization" not in out
    assert "Cookie" not in out
    assert "X-API-Key" not in out
    assert "User-Agent" in out


def test_allowed_content_types_frozen() -> None:
    assert "text/html" in ALLOWED_CONTENT_TYPES
    assert "application/xhtml+xml" in ALLOWED_CONTENT_TYPES
    assert "text/markdown" in ALLOWED_CONTENT_TYPES
    assert "application/pdf" not in ALLOWED_CONTENT_TYPES


# ---- fetch via curl ------------------------------------------------------


def test_fetch_success(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"<html><body><h1>hi</h1></body></html>"
    _patch_curl(monkeypatch, result=_make_curl_result(body=body))
    out = fetch(
        "https://example.com/x",
        options=ExtractionOptions(),
        pre_resolved=("93.184.216.34",),
    )
    assert out.byte_length == len(body)
    assert out.content_type.startswith("text/html")
    assert out.extractor == "curl"
    assert out.http_status == 200


def test_fetch_rejects_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_curl(
        monkeypatch,
        result=_make_curl_result(body=b"secret"),
    )
    with pytest.raises(safety.SSRFBlocked):
        fetch(
            "http://127.0.0.1/admin",
            pre_resolved=("127.0.0.1",),
        )


def test_fetch_rejects_metadata_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_curl(
        monkeypatch,
        result=_make_curl_result(body=b"{}"),
    )
    with pytest.raises(safety.SSRFBlocked):
        fetch(
            "http://169.254.169.254/latest/meta-data",
            pre_resolved=("169.254.169.254",),
        )


def test_fetch_rejects_bad_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_curl(
        monkeypatch,
        result=_make_curl_result(body=b"x"),
    )
    with pytest.raises(safety.UnsafeScheme):
        fetch("file:///etc/passwd")


def test_fetch_rejects_bad_content_type(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_curl(
        monkeypatch,
        result=_make_curl_result(body=b"%PDF-fake", content_type="application/pdf"),
    )
    with pytest.raises(ContentTypeRejected):
        fetch(
            "https://example.com/file.pdf",
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_rejects_oversize(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"x" * 10_000
    _patch_curl(
        monkeypatch,
        result=_make_curl_result(body=body),
    )
    with pytest.raises(FetchFailed):
        fetch(
            "https://example.com/big",
            options=ExtractionOptions(max_bytes=100),
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_4xx_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # We force curl to fail by giving it a non-zero return code and a
    # stderr message that the parser will surface.
    cp = subprocess.CompletedProcess(
        args=["curl"], returncode=22, stdout=b"", stderr=b"HTTP 404"
    )
    _patch_curl(monkeypatch, result=cp)
    with pytest.raises(FetchFailed):
        fetch(
            "https://example.com/missing",
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_too_many_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    cp = subprocess.CompletedProcess(
        args=["curl"],
        returncode=47,
        stdout=b"",
        stderr=b"Too many redirects",
    )
    _patch_curl(monkeypatch, result=cp)
    with pytest.raises(RedirectLimitExceeded):
        fetch(
            "https://example.com/loop",
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_max_filesize(monkeypatch: pytest.MonkeyPatch) -> None:
    cp = subprocess.CompletedProcess(
        args=["curl"],
        returncode=63,
        stdout=b"",
        stderr=b"max filesize exceeded",
    )
    _patch_curl(monkeypatch, result=cp)
    with pytest.raises(FetchFailed):
        fetch(
            "https://example.com/big",
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **kw: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="curl", timeout=1)

    monkeypatch.setattr("mavr.search.extract.subprocess.run", boom)
    with pytest.raises(FetchFailed):
        fetch(
            "https://example.com/slow",
            options=ExtractionOptions(timeout_seconds=1),
            pre_resolved=("93.184.216.34",),
        )


def test_fetch_curl_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without curl on PATH, the helper should refuse to even start."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(extract.BackendUnavailable):
        fetch("https://example.com/x", pre_resolved=("93.184.216.34",))


# ---- store_extraction -----------------------------------------------------


def test_store_extraction_round_trip(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b"<html><body><h1>Hello</h1><script>alert(1)</script></body></html>"
    _patch_curl(monkeypatch, result=_make_curl_result(body=body))
    artifacts = ArtifactStore(tmp_path / "artifacts")
    fetched = fetch(
        "https://example.com/x",
        pre_resolved=("93.184.216.34",),
    )
    extracted, evidence, sanitized = store_extraction(
        fetched,
        campaign_id="33333333-3333-4333-8333-333333333333",
        task_id="44444444-4444-4444-8444-444444444444",
        artifacts=artifacts,
    )
    assert extracted.byte_length == len(body)
    assert evidence.content_hash == fetched.content_hash
    assert evidence.raw_artifact_id == extracted.raw_artifact_id
    assert evidence.extracted_artifact_id == extracted.extracted_artifact_id
    # Raw bytes are recoverable byte-for-byte.
    assert artifacts.read(evidence.raw_artifact_id) == body
    # Sanitized text has the script removed.
    assert "Hello" in sanitized.text
    assert "alert(1)" not in sanitized.text
    # Evidence fields tie back to the source URL.
    assert evidence.source_url == "https://example.com/x"
    assert extracted.extractor == "curl"
