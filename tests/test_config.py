"""Config loader tests."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from mavr.config.loader import AppConfig, load_config


def test_default_config_loads() -> None:
    cfg = load_config()
    assert isinstance(cfg, AppConfig)
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 8765
    assert cfg.providers.free_only is True
    assert cfg.routers.count >= 1
    assert cfg.logging.level == "INFO"


def test_user_overlay_overrides(tmp_dir: Path) -> None:
    overlay = tmp_dir / "user.yaml"
    overlay.write_text(
        yaml.safe_dump(
            {
                "server": {"port": 9999, "host": "127.0.0.1"},
                "logging": {"level": "DEBUG"},
            }
        ),
        encoding="utf-8",
    )
    cfg = load_config(overlay)
    assert cfg.server.port == 9999
    assert cfg.logging.level == "DEBUG"


def test_invalid_port_rejected(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text("server:\n  port: 99999\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(overlay)


def test_invalid_log_level_rejected(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text("logging:\n  level: BANANA\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(overlay)


def test_search_safe_search_enum_enforced(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text("search:\n  safe_search: nsfw\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(overlay)


def test_routers_must_be_positive(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text("routers:\n  count: 0\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(overlay)


def test_method_allowlist_uppercased() -> None:
    cfg = AppConfig.model_validate(
        {"scope_policy": {"method_allowlist": ["get", "post"]}}
    )
    assert cfg.scope_policy.method_allowlist == ["GET", "POST"]


def test_method_allowlist_empty_rejected(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text("scope_policy:\n  method_allowlist: [\"   \"]\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(overlay)


def test_allowlist_empty_string_rejected(tmp_dir: Path) -> None:
    overlay = tmp_dir / "bad.yaml"
    overlay.write_text(
        "providers:\n  allowlists:\n    foo: [\"\"]\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError):
        load_config(overlay)
