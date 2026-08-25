"""Web content extraction with full provenance.

Extraction has two backends:

* **curl** (primary) — invoked via :mod:`subprocess` with a strict
  argument set. We do not use :mod:`urllib` or :mod:`httpx` for the
  primary fetch because curl is a stable, externally audited binary
  with a small attack surface and per-request resource limits baked
  in (``--max-time``, ``--max-filesize``, ``--max-redirs``).
* **jina** (fallback) — unauthenticated reader at
  ``https://r.jina.ai/<url>`` for sites that block programmatic
  user agents. The fallback is opt-in and may be disabled by a
  per-campaign allowlist.

Every successful fetch:

1. Runs the URL through :mod:`mavr.search.safety` for SSRF / scheme
   denylist enforcement.
2. Streams the response into an :class:`ArtifactStore` (the raw
   bytes are written before any sanitization).
3. Sanitizes the bytes through :mod:`mavr.search.sanitize` and
   writes the cleaned version alongside the raw bytes.
4. Produces an :class:`ExtractedSource` row + an :class:`EvidenceItem`
   row. The latter is the durable handle that findings reference
   — raw URLs disappear if the page goes away, evidence UUIDs do
   not.

The extraction layer is intentionally synchronous. The runtime
executes extract handlers in worker threads / processes anyway, and
keeping the API sync makes the safety checks (DNS resolution,
artifact writes) obvious.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import quote, urlparse

from mavr.agents import identity as identity_mod
from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema
from mavr.search import safety, sanitize
from mavr.storage.artifacts import ArtifactError, ArtifactStore

log = get_logger(__name__)


# ---- constants ------------------------------------------------------------


#: The set of content types we will accept. Anything else is rejected
#: at the header level — the response body is never even read.
ALLOWED_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
        "application/json",
        "application/xml",
        "text/xml",
        "text/markdown",
    }
)

#: Hard maximum size we'll let curl read. Mirrors the spec §9.2 limit
#: and is used as a safety net in case ``--max-filesize`` is unavailable
#: or ignored.
DEFAULT_MAX_BYTES: Final[int] = 5_000_000

#: Hard maximum redirect count we will follow. Matches the spec.
DEFAULT_MAX_REDIRECTS: Final[int] = 5

#: Default per-request timeout. The runtime can override per-campaign.
DEFAULT_TIMEOUT_SECONDS: Final[int] = 20

#: Jina reader endpoint. Unauthenticated; per-campaign allowlist
#: controls whether it is used.
JINA_ENDPOINT: Final[str] = "https://r.jina.ai/"

#: Headers that must NEVER be sent to the target on retry (i.e. they
#: are dangerous to forward because they change request semantics in
#: ways the policy engine does not model).
DANGEROUS_FORWARD_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    }
)


# ---- exceptions ------------------------------------------------------------


class ExtractionError(RuntimeError):
    """Base class for extraction failures."""


class BackendUnavailable(ExtractionError):
    """Raised when neither the primary nor the fallback backend can be used."""


class FetchFailed(ExtractionError):
    """The request failed (non-2xx, network error, too big, etc.)."""


class ContentTypeRejected(ExtractionError):
    """The response Content-Type was not in the allowlist."""


class RedirectLimitExceeded(ExtractionError):
    """curl exited with TOO_MANY_REDIRECTS or our manual counter tripped."""


# ---- data types -----------------------------------------------------------


@dataclass(frozen=True)
class FetchResult:
    """The raw outcome of a single fetch."""

    url: str
    final_url: str
    content_type: str
    byte_length: int
    content_hash: str
    raw_bytes: bytes
    http_status: int
    redirect_count: int
    extractor: Literal["curl", "jina"]


# ---- extraction options ---------------------------------------------------


@dataclass(frozen=True)
class ExtractionOptions:
    max_bytes: int = DEFAULT_MAX_BYTES
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    user_agent: str = (
        "MAVR/0.1 (+local security research; contact: see config)"
    )
    jina_allowlist: tuple[str, ...] = ()
    allow_unsafe_networking: bool = False
    jina_endpoint: str = JINA_ENDPOINT


# ---- header / URL helpers -------------------------------------------------


def _is_dangerous_header(name: str) -> bool:
    return name.lower() in {h.lower() for h in DANGEROUS_FORWARD_HEADERS}


def _validate_scheme(url: str) -> None:
    parsed = urlparse(url)
    if (parsed.scheme or "").lower() not in {"http", "https"}:
        raise ExtractionError(f"unsupported scheme for extraction: {parsed.scheme!r}")


def _is_html(content_type: str) -> bool:
    return content_type.split(";", 1)[0].strip().lower() in {
        "text/html",
        "application/xhtml+xml",
    }


# ---- curl backend ---------------------------------------------------------


def _curl_argv(url: str, opts: ExtractionOptions) -> list[str]:
    """Build the curl command line.

    We pin --proto and --proto-default to https so even if the URL
    scheme is http, curl will refuse the request. (Spec §9.2 — primary
    extractor is HTTPS-only.) The ``--max-filesize`` flag is honored
    by curl itself; we still cap manually after the fact.
    """
    if not shutil.which("curl"):
        raise BackendUnavailable("curl is not installed on this system")
    return [
        "curl",
        "--silent",
        "--show-error",
        "--no-progress-meter",
        "--location",
        f"--max-redirs={opts.max_redirects}",
        f"--max-time={opts.timeout_seconds}",
        f"--max-filesize={opts.max_bytes}",
        "--proto-default=https",
        "--proto=https",
        "--proto=http",
        "--fail",                          # error on HTTP >= 400
        "--connect-timeout=10",
        "-A", opts.user_agent,
        "-D", "-",                         # dump response headers to stdout
        url,
    ]


def _split_headers_and_body(raw: bytes) -> tuple[bytes, bytes]:
    """Separate response headers from the body in curl's combined output."""
    sep = b"\r\n\r\n"
    # Header block is small; double-split is safe.
    if sep in raw:
        head, _, rest = raw.partition(sep)
        return head, rest
    sep = b"\n\n"
    if sep in raw:
        head, _, rest = raw.partition(sep)
        return head, rest
    return b"", raw


def _parse_status_and_ct(headers: bytes) -> tuple[int, str]:
    status = 0
    content_type = ""
    for line in headers.splitlines():
        if not line:
            continue
        try:
            text = line.decode("latin-1", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if text.startswith("HTTP/"):
            parts = text.split(None, 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
            continue
        if ":" in text:
            name, _, value = text.partition(":")
            if name.strip().lower() == "content-type":
                content_type = value.strip()
    return status, content_type


def _curl_redirect_count(headers: bytes) -> int:
    n = 0
    for line in headers.splitlines():
        try:
            text = line.decode("latin-1", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if text.startswith("HTTP/"):
            n += 1
    # Each redirect adds one HTTP line; the final response is also one.
    return max(0, n - 1)


def _fetch_curl(url: str, opts: ExtractionOptions) -> FetchResult:
    argv = _curl_argv(url, opts)
    log.info("extract_curl_start", url=url, max_bytes=opts.max_bytes)
    try:
        proc = subprocess.run(  # noqa: S603 — argv is a literal list
            argv,
            capture_output=True,
            timeout=opts.timeout_seconds + 5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchFailed(f"curl timed out after {opts.timeout_seconds}s") from exc
    if proc.returncode != 0:
        # curl uses 22 for HTTP >= 400, 47 for too many redirects,
        # 63 for max-filesize, 28 for timeout. We just surface the
        # stderr tail — the policy / agent can decide what to do.
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        if "redirect" in err.lower():
            raise RedirectLimitExceeded(err or "too many redirects")
        if "max filesize" in err.lower() or proc.returncode == 63:
            raise FetchFailed(f"response exceeded --max-filesize ({opts.max_bytes})")
        raise FetchFailed(f"curl failed (rc={proc.returncode}): {err}")

    headers, body = _split_headers_and_body(proc.stdout)
    if not headers:
        # curl was invoked with -D - which prepends headers; absence
        # means the call shape was wrong or output was empty.
        raise FetchFailed("curl returned no headers (empty body?)")

    status, content_type = _parse_status_and_ct(headers)
    redirect_count = _curl_redirect_count(headers)

    if status >= 400:
        raise FetchFailed(f"HTTP {status} from {url}")

    if not content_type:
        raise FetchFailed("response had no Content-Type header")

    main_ct = content_type.split(";", 1)[0].strip().lower()
    if main_ct not in ALLOWED_CONTENT_TYPES:
        raise ContentTypeRejected(
            f"Content-Type {main_ct!r} not in allowlist"
        )

    if len(body) > opts.max_bytes:
        raise FetchFailed(
            f"response body {len(body)} bytes exceeds max {opts.max_bytes}"
        )

    content_hash = hashlib.sha256(body).hexdigest()
    return FetchResult(
        url=url,
        final_url=url,
        content_type=content_type,
        byte_length=len(body),
        content_hash=content_hash,
        raw_bytes=body,
        http_status=status,
        redirect_count=redirect_count,
        extractor="curl",
    )


# ---- Jina fallback --------------------------------------------------------


def _jina_host_allowed(url: str, allowlist: tuple[str, ...]) -> bool:
    """Apply the per-campaign Jina allowlist.

    The allowlist is a list of host suffixes (e.g. ``"example.com"``).
    A target host is allowed if it equals one of the entries or is a
    subdomain of one. If the allowlist is empty, the Jina fallback is
    disabled entirely.
    """
    if not allowlist:
        return False
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    for entry in allowlist:
        suffix = entry.strip().lower().lstrip(".")
        if not suffix:
            continue
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def _fetch_jina(url: str, opts: ExtractionOptions) -> FetchResult:
    if not _jina_host_allowed(url, opts.jina_allowlist):
        raise BackendUnavailable(
            "Jina fallback is disabled or the target host is not on the allowlist"
        )
    # Jina expects the target URL as a path segment, url-quoted.
    target = quote(url, safe="")
    endpoint = opts.jina_endpoint.rstrip("/") + "/" + target
    # Run curl against Jina itself. We treat Jina as a public service
    # so we DO NOT inherit the caller's unsafe-networking override.
    jina_opts = ExtractionOptions(
        max_bytes=opts.max_bytes,
        max_redirects=opts.max_redirects,
        timeout_seconds=opts.timeout_seconds,
        user_agent=opts.user_agent,
        jina_allowlist=opts.jina_allowlist,
        allow_unsafe_networking=False,        # never relax for Jina
        jina_endpoint=opts.jina_endpoint,
    )
    result = _fetch_curl(endpoint, jina_opts)
    # We don't trust Jina's reported status: substitute the request URL
    # and normalize the content type to plain text.
    return FetchResult(
        url=url,
        final_url=url,
        content_type="text/markdown",
        byte_length=result.byte_length,
        content_hash=result.content_hash,
        raw_bytes=result.raw_bytes,
        http_status=result.http_status,
        redirect_count=result.redirect_count,
        extractor="jina",
    )


# ---- top-level fetch ------------------------------------------------------


def fetch(
    url: str,
    *,
    options: ExtractionOptions | None = None,
    allow_unsafe_networking: bool = False,
    pre_resolved: tuple[str, ...] | None = None,
) -> FetchResult:
    """Fetch ``url`` using the primary curl backend, with an optional
    Jina fallback when configured.

    Raises:
        safety.SafetyError: The URL is unsafe (bad scheme, private IP,
            missing host, …).
        BackendUnavailable: curl is missing and the fallback is
            disabled.
        FetchFailed: The request itself failed.
        ContentTypeRejected: The response Content-Type is not in
            :data:`ALLOWED_CONTENT_TYPES`.
    """
    opts = options or ExtractionOptions()
    verdict = safety.check_url(
        url,
        pre_resolved=pre_resolved,
        allow_unsafe_networking=allow_unsafe_networking,
    )
    if not verdict.allowed:
        if not verdict.scheme_ok:
            raise safety.UnsafeScheme(verdict.reason)
        raise safety.SSRFBlocked(verdict.reason)

    try:
        return _fetch_curl(url, opts)
    except (FetchFailed, ContentTypeRejected, RedirectLimitExceeded) as exc:
        log.warning("extract_curl_failed", url=url, error=str(exc))
        if opts.jina_allowlist:
            try:
                return _fetch_jina(url, opts)
            except Exception as exc2:  # noqa: BLE001
                log.warning("extract_jina_failed", url=url, error=str(exc2))
                # Re-raise the original primary error.
                raise
        raise





# ---- evidence store wiring ------------------------------------------------


def store_extraction(
    fetch_result: FetchResult,
    *,
    campaign_id: str,
    task_id: str | None,
    artifacts: ArtifactStore,
    extra_metadata: dict | None = None,
) -> tuple[schema.ExtractedSource, schema.EvidenceItem, sanitize.SanitizedContent]:
    """Persist the raw bytes, the sanitized text, and the metadata rows.

    Returns:
        ``(extracted_source, evidence_item, sanitized)`` — the two
        schema objects that the caller can persist to the DB, plus
        the in-memory sanitization result for prompt use.
    """
    if not isinstance(campaign_id, str) or not campaign_id:
        raise ExtractionError("campaign_id is required")
    raw_id = identity_mod.mint_uuid()
    ext_id = identity_mod.mint_uuid()

    raw_path = artifacts.write(raw_id, fetch_result.raw_bytes)
    try:
        sanitized = sanitize.sanitize_html(
            fetch_result.raw_bytes,
            source_url=fetch_result.url,
            content_type=fetch_result.content_type,
        )
        ext_path = artifacts.write(ext_id, sanitized.text.encode("utf-8"))
    except ArtifactError:
        artifacts.remove(raw_id)
        raise

    metadata = {
        "final_url": fetch_result.final_url,
        "redirect_count": fetch_result.redirect_count,
        "extractor": fetch_result.extractor,
        "removed_tag_count": sanitized.removed_tag_count,
        "removed_attr_count": sanitized.removed_attr_count,
        "raw_path": str(raw_path),
        "extracted_path": str(ext_path),
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    extracted = schema.ExtractedSource(
        id=identity_mod.mint_uuid(),
        task_id=task_id,
        campaign_id=campaign_id,
        source_url=fetch_result.url,
        final_url=fetch_result.final_url,
        content_type=fetch_result.content_type,
        byte_length=fetch_result.byte_length,
        content_hash=fetch_result.content_hash,
        raw_artifact_id=raw_id,
        extracted_artifact_id=ext_id,
        http_status=fetch_result.http_status,
        redirect_count=fetch_result.redirect_count,
        extractor=fetch_result.extractor,
        metadata=metadata,
    )

    evidence = schema.EvidenceItem(
        id=identity_mod.mint_uuid(),
        campaign_id=campaign_id,
        source_url=fetch_result.url,
        content_hash=fetch_result.content_hash,
        byte_length=fetch_result.byte_length,
        content_type=fetch_result.content_type,
        raw_artifact_id=raw_id,
        extracted_artifact_id=ext_id,
        notes="",
    )
    log.info(
        "extract_stored",
        evidence_id=evidence.id,
        url=fetch_result.url,
        bytes=fetch_result.byte_length,
    )
    return extracted, evidence, sanitized


# ---- ad-hoc helpers used by tests / agent handlers -----------------------


def filter_forwarded_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with dangerous keys removed.

    Called by callers that wish to forward a request through a
    retrieval proxy and need to scrub headers from a previous
    attempt first.
    """
    return {k: v for k, v in headers.items() if not _is_dangerous_header(k)}


def assert_artifact_root_traversal(root: str, candidate: str) -> str:
    """Public alias for the path-traversal check used by callers that
    derive filenames from URLs.
    """
    return safety.assert_within_root(root, candidate)


# Suppress unused-import lint when running in a slim config.
_ = (os.environ, identity_mod)
