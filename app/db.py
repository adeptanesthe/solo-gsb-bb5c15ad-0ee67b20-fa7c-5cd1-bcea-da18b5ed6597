"""异步数据库引擎与会话管理。"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import insert, select

from .audit_chain import GENESIS_HASH
from .config import settings
from .models import AuditChainState, Base
from .utils import utcnow


class Database:
    def __init__(self, url: str | None = None) -> None:
        connect_args: dict = {}
        url = url or settings.database_url
        if url.startswith("sqlite"):
            if ":memory:" in url or "mode=memory" in url:
                # 内存库需要 StaticPool 共享单连接
                from sqlalchemy.pool import StaticPool

                connect_args = {"check_same_thread": False}
                self.engine: AsyncEngine = create_async_engine(
                    url,
                    connect_args=connect_args,
                    poolclass=StaticPool,
                    future=True,
                )
            else:
                # 文件库：多连接 + busy timeout，供并发测试真实争抢写锁
                connect_args = {"check_same_thread": False, "timeout": 30}
                self.engine = create_async_engine(
                    url, connect_args=connect_args, future=True
                )

                from sqlalchemy import event

                @event.listens_for(self.engine.sync_engine, "connect")
                def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA journal_mode=WAL")
                    cur.execute("PRAGMA foreign_keys=ON")
                    cur.close()
        else:
            self.engine = create_async_engine(
                url,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                future=True,
            )
        self.session_factory = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def create_schema(self) -> None:
        # 直接 create_all：表结构简单，避免引入迁移工具
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # 种子化哈希链游标（空链：last_seq=0，last_hash=创世哈希）
            state_table = AuditChainState.__table__
            exists = await conn.scalar(
                select(state_table.c.id).where(state_table.c.id == 1)
            )
            if exists is None:
                await conn.execute(
                    insert(state_table).values(
                        id=1,
                        last_seq=0,
                        last_hash=GENESIS_HASH,
                        updated_at=utcnow(),
                    )
                )

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def ping(self) -> None:
        async with self.engine.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")

    async def close(self) -> None:
        await self.engine.dispose()
