"""Fixture catalog: the vulnerability classes the mock target exposes.

Each fixture documents its vuln class, the safe exploitation boundary, and
the evidence artifacts a reproduction should produce. Keeping the catalog as
data (not scattered strings) lets tests and the policy layer reference
fixtures by ID deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnFixture:
    """One deliberately vulnerable endpoint family on the mock target."""

    fixture_id: str
    vuln_class: str
    path: str
    description: str
    safe_boundary: str  # what must NOT be done even here
    expected_evidence: tuple[str, ...]  # artifacts a reproduction yields

    # Loopback-only by construction; recorded so tests can assert the base URL.
    requires_loopback: bool = True


FIXTURES: dict[str, VulnFixture] = {
    f.fixture_id: f
    for f in (
        VulnFixture(
            "reflected_xss",
            "xss",
            "/search",
            "Query parameter echoed into the HTML body without encoding.",
            "No destructive payload; script tags are fine, no data exfil.",
            ("request_url", "response_body_snippet"),
        ),
        VulnFixture(
            "stored_xss",
            "xss",
            "/comments",
            "Comment bodies rendered unescaped on /comments view.",
            "POST only seeded comment IDs; keep payloads small.",
            ("post_request", "rendered_page_snippet"),
        ),
        VulnFixture(
            "sqli",
            "sqli",
            "/users",
            "Numeric id concatenated into a SQLite query.",
            "Read-only extraction; never DROP/UPDATE/DELETE tables.",
            ("injected_url", "response_row"),
        ),
        VulnFixture(
            "idor",
            "access_control",
            "/invoices/<id>",
            "Invoice ids are sequential with no ownership check.",
            "Enumerate ids 1..N shipped in seed data only.",
            ("unauthorized_access_url", "response_status"),
        ),
        VulnFixture(
            "ssrf_fetcher",
            "ssrf",
            "/fetch",
            "Server-side URL fetch without destination validation.",
            "Fetch only attacker-chosen loopback URLs of THIS server.",
            ("fetch_url", "response_body"),
        ),
        VulnFixture(
            "path_traversal",
            "path_traversal",
            "/files",
            "File read joined to user input without normalization.",
            "Read only files under the fixture docroot.",
            ("traversal_path", "leaked_content"),
        ),
    )
}
