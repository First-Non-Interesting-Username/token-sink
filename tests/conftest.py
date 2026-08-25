"""Pytest fixtures shared across the test suite."""
from __future__ import annotations

import json
import tempfile
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import aiosqlite
import pytest
import pytest_asyncio

from mavr.config.loader import AppConfig, ServerConfig, StorageConfig
from mavr.orchestrator import Orchestrator
from mavr.schemas import entities as schema
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import Database, apply_migrations


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


# ---- Phase 3 fixtures -----------------------------------------------------


@pytest_asyncio.fixture()
async def migrated_db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "phase3.db")
    await apply_migrations(database, "up")
    yield database


@pytest_asyncio.fixture()
async def campaign_id(migrated_db: Database) -> str:
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    target_spec = json.dumps({"hosts": ["example.com"]})
    await migrated_db.execute(
        "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cid, schema.SCHEMA_VERSION, "phase3-fixture", target_spec, "active", now, now),
    )
    return cid


@pytest_asyncio.fixture()
async def orchestrator(migrated_db: Database) -> AsyncIterator[Orchestrator]:
    async def factory() -> aiosqlite.Connection:
        return await migrated_db.connect()

    orch = Orchestrator(db_factory=factory)
    await orch.start()
    yield orch
    await orch.stop()
