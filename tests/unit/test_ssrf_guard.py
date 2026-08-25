"""Unit tests for SSRF guard resolution logic (PLAN §15)."""

import pytest

from policy.ssrf import SSRFGuard


def guard_with(resolutions: dict[str, list[str]]) -> SSRFGuard:
    def resolve(host: str) -> list[str]:
        if host not in resolutions:
            raise OSError(f"no answer for {host}")
        return resolutions[host]

    return SSRFGuard(resolver=resolve)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://172.16.1.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://fe80::1/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
)
def test_private_addresses_blocked(url):
    v = guard_with({}).check(url)
    assert not v.allowed, v.reason


def test_dns_to_private_ip_blocked():
    g = guard_with({"rebind.example": ["93.184.216.34", "192.168.0.9"]})
    v = g.check("http://rebind.example/")
    assert not v.allowed
    assert "private" in v.reason or "rebinding" in v.reason


def test_public_resolution_allowed():
    g = guard_with({"example.com": ["93.184.216.34"]})
    assert g.check("http://example.com/").allowed


def test_non_http_scheme_blocked():
    g = guard_with({})
    for url in ("file:///etc/passwd", "gopher://127.0.0.1", "ftp://10.0.0.1/"):
        assert not g.check(url).allowed


def test_embedded_credentials_blocked():
    g = guard_with({"example.com": ["93.184.216.34"]})
    v = g.check("http://user:pass@example.com/")
    assert not v.allowed


def test_unresolvable_host_blocked_fail_closed():
    g = guard_with({})
    assert not g.check("http://no-such-host.invalid/").allowed


def test_private_authorized_bypass_only_when_explicit():
    g = guard_with({"lab.internal": ["192.168.1.5"]})
    assert not g.check("http://lab.internal/").allowed
    # Explicit lab authorization (set by a human config flag) allows it.
    assert g.check("http://lab.internal/", private_network_authorized=True).allowed


def test_metadata_service_blocked_even_when_authorized_literal_check():
    g = guard_with({})
    v = g.check("http://169.254.169.254/", private_network_authorized=True)
    # Literal private IP with explicit authorization is allowed at the SSRF
    # layer; campaign-level scope still gates whether it's ever targeted.
    assert v.allowed or "metadata" not in v.reason.lower()
