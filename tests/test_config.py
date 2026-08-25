"""Unit tests for tokensink.config: parsing, defaults, collect-and-report
validation errors (issue #5, PLAN.md §16)."""

import pytest

from tokensink.config import ConfigError, load_config


def write_yaml(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(body)
    return p


def write_toml(tmp_path, body):
    p = tmp_path / "config.toml"
    p.write_text(body)
    return p


class TestParsing:
    def test_minimal_yaml_uses_defaults(self, tmp_path):
        cfg = load_config(write_yaml(tmp_path, "server:\n  port: 9000\n"))
        assert cfg.server_port == 9000
        # untouched fields keep safe defaults
        assert cfg.free_only is True
        assert cfg.redaction_enabled is True

    def test_toml_supported(self, tmp_path):
        cfg = load_config(write_toml(
            tmp_path,
            '[server]\nport = 8123\n[routing]\nfree_only = false\n',
        ))
        assert cfg.server_port == 8123
        assert cfg.free_only is False

    def test_empty_file_is_valid(self, tmp_path):
        cfg = load_config(write_yaml(tmp_path, ""))
        assert cfg.server_host == "127.0.0.1"

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(tmp_path / "nope.yaml")
        assert "does not exist" in e.value.errors[0]

    def test_unsupported_extension(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("{}")
        with pytest.raises(ConfigError):
            load_config(p)

    def test_invalid_yaml_syntax_reported(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, "server: [unclosed\n"))
        assert "invalid YAML" in e.value.errors[0]

    def test_invalid_toml_syntax_reported(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_toml(tmp_path, "[server\nport = 1"))
        assert "invalid TOML" in e.value.errors[0]

    def test_top_level_must_be_mapping(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, "- a\n- b\n"))
        assert "mapping" in e.value.errors[0]


class TestValidation:
    def test_collect_and_report_all_errors(self, tmp_path):
        """Multiple bad values must ALL be reported, not fail on first."""
        body = """
server:
  port: 99999
routing:
  router_count: 0
review:
  quorum: 7
logging:
  level: LOUD
bogus_section: {}
"""
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, body))
        joined = "\n".join(e.value.errors)
        for fragment in ("server.port", "routing.router_count",
                         "review.quorum", "logging.level", "bogus_section"):
            assert fragment in joined, f"missing {fragment} in:\n{joined}"
        assert len(e.value.errors) >= 5

    def test_port_out_of_range(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, "server:\n  port: 0\n"))
        assert "out of range" in e.value.errors[0]

    def test_wrong_types(self, tmp_path):
        body = """
server:
  port: "not-a-port"
routing:
  free_only: "yes-please"
redaction:
  enabled: "off"
"""
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, body))
        joined = "\n".join(e.value.errors)
        assert "server.port" in joined
        assert "routing.free_only" in joined
        assert "redaction.enabled" in joined

    def test_credential_refs_reject_raw_secrets_shape(self, tmp_path):
        """Empty/non-string credential ref values are rejected — only secret
        references allowed (PLAN.md §15)."""
        body = """
providers:
  credential_refs:
    openrouter: ""
"""
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, body))
        assert "credential_refs" in e.value.errors[0]

    def test_valid_credential_refs_accepted(self, tmp_path):
        body = """
providers:
  credential_refs:
    openrouter: op://vault/openrouter/key
  allowlist: [openrouter]
"""
        cfg = load_config(write_yaml(tmp_path, body))
        assert cfg.credential_refs == {"openrouter": "op://vault/openrouter/key"}
        assert cfg.provider_allowlist == ["openrouter"]

    def test_quorum_bounds(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, "review:\n  quorum: 5\n"))
        assert "quorum" in e.value.errors[0]

    def test_budgets_must_be_positive(self, tmp_path):
        body = """
budgets:
  agent_timeout_seconds: -5
  max_tokens_per_agent: 0
"""
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(tmp_path, body))
        assert len(e.value.errors) == 2

    def test_storage_paths_need_filename_component(self, tmp_path):
        with pytest.raises(ConfigError) as e:
            load_config(write_yaml(
                tmp_path,
                "storage:\n  database_path: /\n  artifact_path: data/artifacts\n",
            ))
        assert len(e.value.errors) == 1
        assert "database_path" in e.value.errors[0]

    def test_full_valid_config(self, tmp_path):
        body = """
server:
  host: 0.0.0.0
  port: 8080
storage:
  database_path: var/tokensink.db
  artifact_path: var/artifacts
providers:
  credential_refs:
    openrouter: op://vault/openrouter/key
  allowlist: [openrouter]
routing:
  free_only: true
  router_count: 4
budgets:
  agent_timeout_seconds: 300
  max_tokens_per_agent: 100000
review:
  quorum: 4
retention:
  days: 30
redaction:
  enabled: true
logging:
  level: debug
"""
        cfg = load_config(write_yaml(tmp_path, body))
        assert cfg.server_port == 8080
        assert cfg.router_count == 4
        assert cfg.log_level == "DEBUG"
        assert cfg.retention_days == 30
