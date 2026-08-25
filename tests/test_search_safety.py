"""Tests for mavr.search.safety.

Covers the SSRF denylist (loopback, link-local, RFC1918, multicast,
metadata IP), the scheme allowlist, the slug generator, the path
traversal check, and the explicit-unsafe-networking override.
"""
from __future__ import annotations

import pytest

from mavr.search import safety


class TestCheckUrl:
    def test_allows_https_public(self) -> None:
        verdict = safety.check_url(
            "https://example.com/x",
            pre_resolved=("93.184.216.34",),
        )
        assert verdict.allowed
        assert verdict.scheme_ok
        assert verdict.host_ok
        assert verdict.ips == ("93.184.216.34",)
        assert verdict.reason == ""

    def test_allows_http_public(self) -> None:
        verdict = safety.check_url(
            "http://example.com/x",
            pre_resolved=("93.184.216.34",),
        )
        assert verdict.allowed

    @pytest.mark.parametrize(
        "url,ips,label",
        [
            ("http://127.0.0.1/", ("127.0.0.1",), "loopback v4"),
            ("http://127.5.6.7/", ("127.5.6.7",), "loopback range"),
            ("http://10.0.0.5/", ("10.0.0.5",), "RFC1918 10/8"),
            ("http://172.16.0.1/", ("172.16.0.1",), "RFC1918 172.16/12"),
            ("http://192.168.1.1/", ("192.168.1.1",), "RFC1918 192.168/16"),
            (
                "http://169.254.169.254/latest/meta-data/",
                ("169.254.169.254",),
                "cloud metadata",
            ),
            ("http://169.254.1.1/", ("169.254.1.1",), "link-local"),
            ("http://100.64.0.1/", ("100.64.0.1",), "CGNAT"),
            ("http://224.0.0.1/", ("224.0.0.1",), "multicast"),
            ("http://[::1]/", ("::1",), "IPv6 loopback"),
            ("http://[fe80::1]/", ("fe80::1",), "IPv6 link-local"),
            ("http://[fc00::1]/", ("fc00::1",), "IPv6 ULA"),
        ],
    )
    def test_denies_private_ranges(self, url: str, ips: tuple[str, ...], label: str) -> None:
        verdict = safety.check_url(url, pre_resolved=ips)
        assert not verdict.allowed, label
        assert verdict.rule == "ssrf_denylist"
        assert "denied" in verdict.reason.lower()

    def test_dns_resolution_kicks_in_when_no_preresolved(self) -> None:
        verdict = safety.check_url("http://127.0.0.1/")  # resolved internally
        assert not verdict.allowed

    def test_allow_unsafe_networking_bypass(self) -> None:
        verdict = safety.check_url(
            "http://127.0.0.1/",
            pre_resolved=("127.0.0.1",),
            allow_unsafe_networking=True,
        )
        assert verdict.allowed

    def test_rejects_file_scheme(self) -> None:
        verdict = safety.check_url("file:///etc/passwd")
        assert not verdict.allowed
        assert verdict.rule == "bad_scheme"

    def test_rejects_javascript_scheme(self) -> None:
        verdict = safety.check_url("javascript:alert(1)")
        assert not verdict.allowed
        assert verdict.rule == "bad_scheme"

    def test_rejects_no_host(self) -> None:
        verdict = safety.check_url("https:///path")
        assert not verdict.allowed
        assert verdict.rule == "no_host"

    def test_uses_preresolved_when_given(self) -> None:
        # Pretend a public DNS lookup that we know is safe.
        verdict = safety.check_url(
            "https://safe.example.com/x",
            pre_resolved=("1.1.1.1",),
        )
        assert verdict.allowed
        assert verdict.ips == ("1.1.1.1",)


class TestSafeSlug:
    def test_basic(self) -> None:
        assert safety.safe_slug("hello-world") == "hello-world"

    def test_replaces_path_separators(self) -> None:
        assert safety.safe_slug("a/b\\c") == "a_b_c"

    def test_strips_leading_dots(self) -> None:
        # Stops "..hidden" and "..." traversals.
        assert safety.safe_slug("..foo") == "foo"
        assert safety.safe_slug("...") == "_"
        assert safety.safe_slug(".hidden") == "hidden"

    def test_keeps_only_safe_chars(self) -> None:
        assert safety.safe_slug("a b$c@d!e") == "a_b_c_d_e"

    def test_empty_string_returns_underscore(self) -> None:
        assert safety.safe_slug("") == "_"
        assert safety.safe_slug("///") == "_"

    def test_caps_length(self) -> None:
        long = "a" * 500
        assert len(safety.safe_slug(long)) == 200

    def test_rejects_non_string(self) -> None:
        with pytest.raises(safety.PathTraversalError):
            safety.safe_slug(123)  # type: ignore[arg-type]


class TestPathTraversal:
    def test_within_root(self, tmp_path) -> None:
        candidate = str(tmp_path / "a.txt")
        result = safety.assert_within_root(str(tmp_path), candidate)
        assert result == str((tmp_path / "a.txt").resolve())

    def test_parent_traversal_blocked(self, tmp_path) -> None:
        bad = str(tmp_path / ".." / "etc" / "passwd")
        with pytest.raises(safety.PathTraversalError):
            safety.assert_within_root(str(tmp_path), bad)


class TestScopeAllowsUnsafe:
    def test_both_flags_required(self) -> None:
        from mavr.schemas import entities as schema

        cid = "11111111-1111-4111-8111-111111111111"
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        base_kwargs = dict(
            id="22222222-2222-4222-8222-222222222222",
            campaign_id=cid,
            created_at=now,
            updated_at=now,
        )
        assert not safety.scope_allows_unsafe_networking(
            schema.ScopePolicy(
                **base_kwargs,
                explicit_unsafe_networking=True,
                human_approved=False,
            )
        )
        assert not safety.scope_allows_unsafe_networking(
            schema.ScopePolicy(
                **base_kwargs,
                explicit_unsafe_networking=False,
                human_approved=True,
            )
        )
        assert safety.scope_allows_unsafe_networking(
            schema.ScopePolicy(
                **base_kwargs,
                explicit_unsafe_networking=True,
                human_approved=True,
            )
        )


class TestResolveNow:
    def test_loopback_resolves(self) -> None:
        ips = safety.resolve_now("localhost")
        assert any(ip.startswith("127.") for ip in ips)
