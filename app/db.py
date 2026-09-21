"""异步数据库引擎与会话管理。"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .chain import (
    GENESIS_HASH,
    build_event_payload,
    compute_entry_hash,
    compute_event_hash,
)
from .config import settings
from .models import AuditChainState, AuditLog, Base

# 旧库升级时为 audit_logs 补齐的哈希链列
_CHAIN_COLUMNS = {
    "seq": "BIGINT",
    "event_hash": "VARCHAR(64)",
    "prev_hash": "VARCHAR(64)",
    "entry_hash": "VARCHAR(64)",
}


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
            await conn.run_sync(_upgrade_audit_chain)
            await _seed_chain_state(conn)

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def ping(self) -> None:
        async with self.engine.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")

    async def close(self) -> None:
        await self.engine.dispose()


def _upgrade_audit_chain(sync_conn) -> None:  # noqa: ANN001 - SQLAlchemy 同步连接
    """旧库升级：为 audit_logs 补齐哈希链列并回填历史记录。

    - 新库：列已由 create_all 建好，无历史数据；
    - 旧库：ALTER 加列（SQLite/PostgreSQL 均支持），按 created_at, id
      排序顺序重放哈希链，再建唯一索引（IF NOT EXISTS 幂等）。
    """
    inspector = inspect(sync_conn)
    existing = {col["name"] for col in inspector.get_columns("audit_logs")}
    added = False
    for name, ddl in _CHAIN_COLUMNS.items():
        if name not in existing:
            sync_conn.execute(
                text(f"ALTER TABLE audit_logs ADD COLUMN {name} {ddl}")
            )
            added = True

    rows = sync_conn.execute(
        select(
            AuditLog.id,
            AuditLog.delivery_id,
            AuditLog.token_hash,
            AuditLog.action,
            AuditLog.result,
            AuditLog.detail,
            AuditLog.client_ip,
            AuditLog.user_agent,
            AuditLog.created_at,
        ).order_by(AuditLog.created_at, AuditLog.id)
    ).all()
    if not rows:
        # 即使没有历史行，新库也需要补一个唯一索引（create_all 已建时幂等跳过）
        if added:
            sync_conn.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_logs_seq "
                     "ON audit_logs (seq)")
            )
        return

    # 回填：按时间顺序重放链
    prev_hash = GENESIS_HASH
    for seq, row in enumerate(rows, start=1):
        payload = build_event_payload(
            id=row.id,
            delivery_id=row.delivery_id,
            token_hash=row.token_hash,
            action=row.action,
            result=row.result,
            detail=row.detail,
            client_ip=row.client_ip,
            user_agent=row.user_agent,
            created_at=row.created_at,
        )
        event_hash = compute_event_hash(payload)
        entry_hash = compute_entry_hash(prev_hash, seq, event_hash)
        sync_conn.execute(
            text(
                "UPDATE audit_logs SET seq=:seq, event_hash=:eh, "
                "prev_hash=:ph, entry_hash=:xh WHERE id=:id"
            ),
            {
                "seq": seq, "eh": event_hash, "ph": prev_hash,
                "xh": entry_hash, "id": str(row.id),
            },
        )
        prev_hash = entry_hash

    # 回填完成后补唯一索引；正常情况下 create_all 已创建，IF NOT EXISTS 幂等
    sync_conn.execute(
        text("CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_logs_seq "
             "ON audit_logs (seq)")
    )


async def _seed_chain_state(conn) -> None:  # noqa: ANN001 - SQLAlchemy 异步连接
    """保证链尖单行存在；若有回填的历史记录，链尖指向最后一条。"""
    tip = (
        await conn.execute(
            select(AuditChainState).where(AuditChainState.id == 1)
        )
    ).scalar_one_or_none()

    last = (
        await conn.execute(
            select(AuditLog.seq, AuditLog.entry_hash)
            .order_by(AuditLog.seq.desc())
            .limit(1)
        )
    ).first()

    if tip is None:
        await conn.execute(
            AuditChainState.__table__.insert().values(
                id=1,
                last_seq=last.seq if last else 0,
                last_hash=last.entry_hash if last else GENESIS_HASH,
            )
        )
    elif last is not None and (tip.last_seq < last.seq):
        # 回填历史记录后把链尖推进到链尾
        await conn.execute(
            AuditChainState.__table__.update()
            .where(AuditChainState.id == 1)
            .values(last_seq=last.seq, last_hash=last.entry_hash)
        )
