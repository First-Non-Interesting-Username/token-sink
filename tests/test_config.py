"""Unit tests for config loading + validation (issue #5, PLAN.md §16)."""

from pathlib import Path

import pytest
import yaml

from config import (
    Config,
    ConfigError,
    ConfigValidationError,
    from_dict,
    load,
    load_raw,
    validate,
)

VALID = {
    "server": {"host": "127.0.0.1", "port": 8080},
    "storage": {"db_path": "data/t.db", "artifact_path": "data/artifacts"},
    "providers": {
        "credential_refs": {"openai": "OPENAI_API_KEY"},
        "allowlist": ["openrouter"],
        "free_only_mode": True,
    },
    "routers": {"count": 2, "concurrency": 4},
    "review": {"quorum": 2},
}


def write_yaml(tmp_path: Path, data) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


class TestValidConfig:
    def test_valid_yaml_loads(self, tmp_path):
        cfg = load(write_yaml(tmp_path, VALID))
        assert isinstance(cfg, Config)
        assert cfg.server_port == 8080
        assert cfg.free_only_mode is True

    def test_empty_config_gets_defaults(self, tmp_path):
        cfg = load(write_yaml(tmp_path, {}))
        assert cfg.server_host == "127.0.0.1"
        assert cfg.scope_enforcement is True
        # Safe default per §2 principle 5: active testing off unless opted in.
        assert cfg.allow_active_testing is False

    def test_toml_supported(self, tmp_path):
        p = tmp_path / "config.toml"
        p.write_text('[server]\nhost = "127.0.0.1"\nport = 9000\n')
        cfg = load(p)
        assert cfg.server_port == 9000


class TestCollectAllErrors:
    """§16: report ALL errors before launching — not fail-on-first."""

    def test_multiple_errors_all_reported(self):
        bad = {
            "server": {"port": 99999},       # out of range
            "routers": {"count": 0},          # below minimum
            "search": {"extraction_backend": "wget"},  # unknown backend
            "logging": {"level": "LOUD"},     # invalid level
        }
        errors = validate(bad)
        keys = {e.key for e in errors}
        assert {"server.port", "routers.count", "search.extraction_backend", "logging.level"} <= keys

    def test_validation_error_carries_all(self, tmp_path):
        bad = dict(VALID)
        bad["server"] = {"port": -1}
        bad["routers"] = {"count": 0}
        # exercise the real entry point, not a hand-constructed exception
        with pytest.raises(ConfigValidationError) as exc:
            load(write_yaml(tmp_path, bad))
        assert len(exc.value.errors) >= 2
        # every error message names its offending key (§16 requirement)
        assert all(": " in str(e) for e in exc.value.errors)

    def test_unknown_section_flagged(self):
        errors = validate({"providrs": {"free_only_mode": True}})
        assert any(e.key == "providrs" for e in errors)


class TestIndividualRules:
    def test_missing_file(self):
        with pytest.raises(ConfigError, match="does not exist"):
            load("/no/such/config.yaml")

    def test_bad_extension(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("{}")
        with pytest.raises(ConfigError, match="unsupported config format"):
            load(p)

    def test_invalid_yaml_syntax(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("server: [unclosed")
        with pytest.raises(ConfigError, match="parse error"):
            load_raw(p)

    def test_non_mapping_top_level(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- just\n- a list\n")
        with pytest.raises(ConfigError, match="must be a mapping"):
            load_raw(p)

    @pytest.mark.parametrize("key,val", [
        ("port", 0), ("port", 70000), ("port", "8080"),
    ])
    def test_server_port_bounds(self, key, val):
        errors = validate({"server": {key: val}})
        assert any(e.key == "server.port" for e in errors)

    def test_credential_refs_must_be_strings(self):
        errors = validate({"providers": {"credential_refs": {"openai": 12345}}})
        assert any(e.key == "providers.credential_refs.openai" for e in errors)

    def test_bool_keys_reject_strings(self):
        errors = validate({"policy": {"allow_active_testing": "yes"}})
        assert any(e.key == "policy.allow_active_testing" for e in errors)

    def test_quorum_exceeding_router_count_rejected(self):
        errors = validate({"routers": {"count": 1}, "review": {"quorum": 3}})
        assert any(e.key == "review.quorum" for e in errors)

    def test_quorum_checked_against_default_router_count(self):
        # routers section absent -> effective count is the default (2)
        errors = validate({"review": {"quorum": 50}})
        assert any(e.key == "review.quorum" for e in errors)

    def test_scalar_section_reported_not_ignored(self):
        # `server: 8080` must be a reported structural error, not silently
        # treated as "no server config".
        errors = validate({"server": 8080})
        assert any(e.key == "server" and "mapping" in e.message for e in errors)

    def test_retention_null_allowed_but_zero_not(self):
        assert not any(e.key == "retention.days" for e in validate({"retention": {"days": None}}))
        assert any(e.key == "retention.days" for e in validate({"retention": {"days": 0}}))

    def test_from_dict_maps_sections(self):
        cfg = from_dict(VALID)
        assert cfg.db_path == Path("data/t.db")
        assert cfg.provider_credential_refs == {"openai": "OPENAI_API_KEY"}
        assert cfg.provider_allowlist == ["openrouter"]
