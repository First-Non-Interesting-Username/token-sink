"""Pytest fixtures shared across the test suite."""
from __future__ import annotations

import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from mavr.config.loader import AppConfig, ServerConfig, StorageConfig
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import Database


@pytest.fixture()
def tmp_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture()
def storage_paths(tmp_dir: Path) -> dict[str, Path]:
    db = tmp_dir / "mavr.db"
    artifacts = tmp_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    return {"db": db, "artifacts": artifacts}


@pytest.fixture()
def db(storage_paths: dict[str, Path]) -> Iterator[Database]:
    database = Database(storage_paths["db"])
    yield database


@pytest.fixture()
def artifact_store(storage_paths: dict[str, Path]) -> ArtifactStore:
    return ArtifactStore(storage_paths["artifacts"])


@pytest.fixture()
def base_config(storage_paths: dict[str, Path]) -> AppConfig:
    return AppConfig(
        server=ServerConfig(),
        storage=StorageConfig(db_path=str(storage_paths["db"]), artifact_dir=str(storage_paths["artifacts"])),
    )
