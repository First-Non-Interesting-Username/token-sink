"""Tests for the secrets/redaction layer (issue #29, PLAN §15).

§19.1/§19.3 requirements covered here:
- secrets removed from logs, reports, and error messages,
- redaction status reported per record,
- credential store never exposes values and enforces 0600 permissions.
"""

import json
import stat

import pytest

from tokensink.credentials import FileCredentialStore, auth_status
from tokensink.redaction import redact, redact_mapping

SECRETS = {
    "openai_key": "sk-example1234567890abcdef12345678",
    "github_token": "ghp_ExampleTokenValue1234567890abcd",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "slack_token": "xoxb-123456789-example-value",
}


def test_api_keys_removed_from_log_line():
    log = f"request failed for key {SECRETS['openai_key']} retrying"
    result = redact(log)
    assert SECRETS["openai_key"] not in result.text
    assert "[REDACTED:openai_key]" in result.text


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_all_provider_shapes_redacted(name):
    assert SECRETS[name] not in redact(f"token={SECRETS[name]}").text


def test_authorization_and_cookie_headers_stripped():
    headers = (
        "GET / HTTP/1.1\n"
        "Authorization: Bearer abc.def.ghi-jkl\n"
        "Cookie: session=supersecretvalue; other=x\n"
    )
    result = redact(headers)
    assert "supersecretvalue" not in result.text
    assert "abc.def.ghi-jkl" not in result.text
    assert "[REDACTED:" in result.text


def test_password_key_value_forms():
    text = 'db connect failed with password="hunter2hunter2" user=admin'
    result = redact(text)
    assert "hunter2hunter2" not in result.text
    assert "user=admin" in result.text  # non-secret fields survive


def test_private_key_block_removed():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQExample\n"
        "morelines\n-----END RSA PRIVATE KEY-----\n"
    )
    assert "MIIEowIBAAKCAQExample" not in redact(pem).text


def test_provenance_hashes_survive():
    sha = "a" * 40  # git-style hex digest, not a secret
    uuid_like = "123e4567-e89b-42d3-a456-426614174000"
    text = f"content_hash={sha} finding={uuid_like}"
    result = redact(text)
    assert sha in result.text
    assert uuid_like in result.text


def test_clean_content_reports_no_sensitive_content():
    result = redact("nothing sensitive here at all")
    assert not result.found_sensitive_content
    assert result.status == "no_sensitive_content_found"


def test_status_is_redacted_when_secret_present():
    result = redact(f"key {SECRETS['openai_key']} leaked into output")
    assert result.found_sensitive_content
    assert result.status == "redacted"


def test_error_message_scrubbed_before_storage():
    # §18/§15: failed inputs preserved for diagnosis must be redacted too.
    exc_text = "HTTPError 403 for api key sk-ant-example-key-value-123456789"
    scrubbed = redact(exc_text)
    assert "sk-ant-" not in scrubbed.text or "[REDACTED" in scrubbed.text


def test_report_export_via_mapping_redaction():
    report = {
        "title": "Reflected XSS on example.com",
        "raw_request": "Authorization: Bearer live.secret.token.99",
        "notes": "see evidence hash cafebabe",
    }
    cleaned, changed = redact_mapping(report)
    assert changed
    assert "live.secret.token.99" not in cleaned["raw_request"]
    assert cleaned["title"] == report["title"]  # untouched fields identical


# --- credential store --------------------------------------------------------


def test_file_store_roundtrip(tmp_path):
    store = FileCredentialStore(path=tmp_path / "creds.json")
    store.set("provider/openai", "sk-example-roundtrip")
    assert store.get("provider/openai") == "sk-example-roundtrip"
    assert auth_status(store, "provider/openai") == "authenticated"
    assert auth_status(store, "missing") == "unauthenticated"


def test_file_store_permissions_are_0600(tmp_path):
    path = tmp_path / "creds.json"
    store = FileCredentialStore(path=path)
    store.set("a", "1")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_delete_returns_false_for_missing(tmp_path):
    store = FileCredentialStore(path=tmp_path / "c.json")
    assert store.delete("nope") is False
    store.set("yes", "v")
    assert store.delete("yes") is True
    assert store.get("yes") is None


def test_store_never_leaks_value_through_repr(tmp_path):
    store = FileCredentialStore(path=tmp_path / "c.json")
    store.set("k", "supersecret")
    # repr of the store object must not contain any secret value
    assert "supersecret" not in repr(store)
    # but the file itself does contain it (that's its purpose) — check perms guard it
    assert json.loads((tmp_path / "c.json").read_text())["k"] == "supersecret"
