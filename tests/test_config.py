"""Tests for the config subsystem (PLAN §16)."""

from pathlib import Path

import pytest
import yaml

from config.loader import ConfigError, load_config, load_config_collect

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "config.example.yaml"


def _write(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


class TestValidConfigs:
    def test_example_config_is_valid(self, monkeypatch):
        # The documented example must always validate — it's the reference.
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-example-placeholder")
        cfg, errors = load_config_collect(EXAMPLE)
        assert errors == []
        assert cfg.server.port == 8080
        assert cfg.providers.free_only is True
        assert cfg.scope_policy.active_testing_allowed is False
        assert cfg.review.quorum == 2

    def test_empty_file_yields_all_defaults(self, tmp_path):
        cfg, errors = load_config_collect(_write(tmp_path, {}))
        assert errors == []
        assert cfg.server.host == "127.0.0.1"
        assert cfg.agents.budget_usd == 10.0

    def test_full_valid_config(self, tmp_path):
        _, errors = load_config_collect(
            _write(
                tmp_path,
                {
                    "server": {"host": "0.0.0.0", "port": 9000},
                    "storage": {"db_path": "/tmp/x.db", "artifact_path": "/tmp/art"},
                    "providers": {"allowlist": ["a"], "free_only": True},
                    "router": {"count": 3, "concurrency_per_router": 2},
                    "agents": {"budget_usd": 5.5, "request_timeout_s": 60},
                    "search": {"engine": "jina", "max_results": 5},
                    "review": {"quorum": 3},
                },
            )
        )
        assert errors == []


class TestInvalidConfigs:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError) as exc:
            load_config(tmp_path / "nope.yaml")
        assert "not found" in str(exc.value)

    def test_invalid_yaml(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("server: [unclosed")
        with pytest.raises(ConfigError) as exc:
            load_config(p)
        assert "invalid YAML" in str(exc.value)

    def test_non_mapping_top_level(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("- just\n- a\n- list\n")
        with pytest.raises(ConfigError) as exc:
            load_config(p)
        assert "mapping" in str(exc.value)


class TestCollectsAllErrors:
    """§16: report ALL errors before launching workers, not just the first."""

    def test_multiple_errors_collected_across_sections(self, tmp_path):
        _, errors = load_config_collect(
            _write(
                tmp_path,
                {
                    "server": {"port": 99999},
                    "router": {"count": 0},
                    "agents": {"budget_usd": -1},
                    "search": {"engine": "bogus"},
                    "review": {"quorum": 0},
                },
            )
        )
        keys = {e.split(":")[0] for e in errors}
        assert keys == {
            "server.port",
            "router.count",
            "agents.budget_usd",
            "search.engine",
            "review.quorum",
        }

    def test_error_messages_point_at_key_paths(self, tmp_path):
        _, errors = load_config_collect(_write(tmp_path, {"server": {"port": "http"}}))
        assert any(e.startswith("server.port:") and "integer" in e for e in errors)

    def test_unknown_section_rejected(self, tmp_path):
        _, errors = load_config_collect(_write(tmp_path, {"servor": {"host": "x"}}))
        assert any("servor" in e and "unknown section" in e for e in errors)

    def test_wrong_section_type(self, tmp_path):
        _, errors = load_config_collect(_write(tmp_path, {"server": "localhost"}))
        assert any(e == "server: must be a mapping" for e in errors)

    def test_bool_is_not_an_int(self, tmp_path):
        # YAML `true` parses to bool; must not silently pass int checks.
        _, errors = load_config_collect(_write(tmp_path, {"server": {"port": True}}))
        assert any("server.port" in e for e in errors)


class TestCredentialSafety:
    """PLAN §15: credentials are references, never literal values."""

    def test_literal_secret_value_rejected(self, tmp_path):
        _, errors = load_config_collect(
            _write(tmp_path, {"providers": {"credentials": {"openrouter": "sk-example-abc123"}}})
        )
        assert any("env var name" in e for e in errors)

    def test_lowercase_name_rejected(self, tmp_path):
        _, errors = load_config_collect(
            _write(tmp_path, {"providers": {"credentials": {"openrouter": "openrouter_key"}}})
        )
        assert any("does not look like an env var name" in e for e in errors)

    def test_unset_env_var_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DEFINITELY_NOT_SET_XYZ", raising=False)
        _, errors = load_config_collect(
            _write(tmp_path, {"providers": {"credentials": {"p": "DEFINITELY_NOT_SET_XYZ"}}})
        )
        assert any("not set" in e for e in errors)

    def test_set_env_var_passes(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_TEST_KEY", "value")
        _, errors = load_config_collect(
            _write(tmp_path, {"providers": {"credentials": {"p": "MY_TEST_KEY"}}})
        )
        assert not any("credentials" in e for e in errors)


class TestPathSafety:
    def test_traversal_in_artifact_path_rejected(self, tmp_path):
        _, errors = load_config_collect(
            _write(tmp_path, {"storage": {"artifact_path": "../escape"}})
        )
        assert any("'..'" in e for e in errors)
