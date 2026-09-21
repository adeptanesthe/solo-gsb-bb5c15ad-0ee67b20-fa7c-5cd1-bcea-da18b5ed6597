"""测试夹具：文件型 SQLite（WAL，多连接真实争抢）+ fakeredis。"""

from __future__ import annotations

import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import fakeredis.aioredis
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.db import Database
from app.main import app, get_settings
from app.redis_client import DenyCache


@pytest_asyncio.fixture
async def db() -> AsyncIterator[Database]:
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    database = Database(f"sqlite+aiosqlite:///{tmp}")
    await database.create_schema()
    app.state.db = database
    yield database
    await database.close()


@pytest_asyncio.fixture
async def cache() -> DenyCache:
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    deny_cache = DenyCache(client)
    app.state.cache = deny_cache
    return deny_cache


@pytest_asyncio.fixture
async def client(db, cache) -> AsyncIterator[AsyncClient]:
    test_settings = Settings(
        database_url="sqlite://ignored",
        redis_url="redis://ignored",
        max_content_bytes=1024,
        ttl_min_seconds=1,
        ttl_max_seconds=3600,
        redis_flag_ttl_seconds=3600,
    )
    app.dependency_overrides[get_settings] = lambda: test_settings
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
