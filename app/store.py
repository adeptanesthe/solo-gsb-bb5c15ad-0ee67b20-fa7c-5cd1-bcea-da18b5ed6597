"""投递记录的数据访问层。

并发性正确性的核心：所有状态迁移都用 *单条带 WHERE 条件的 UPDATE ... RETURNING*
完成。PostgreSQL 会用行锁串行化对同一行的并发更新：
- 第一个满足条件的事务把 status 从 active 改走并返回行（赢家）；
- 其它事务的 WHERE 不再匹配，返回空（输家），随后读取当前终态给出明确结果。

审计哈希链的追加使用同样的裁决模式：对单行 ``audit_chain_state`` 做
``UPDATE ... WHERE last_seq=:expected`` 的条件更新，竞争失败的事务重试，
因此链序号的全序由数据库（而非应用层锁）决定。
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Iterable
from datetime import datetime

import sqlalchemy.exc
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .audit_chain import (
    GENESIS_HASH,
    ChainEntry,
    chain_hash,
    event_digest_for,
)
from .models import AuditChainState, AuditLog, Delivery
from .utils import utcnow

# 可能的结果状态
CONSUMED = "consumed"
REVOKED = "revoked"
EXPIRED = "expired"
ACTIVE = "active"
UNKNOWN = "unknown"

_DELIVERY_COLS = (
    Delivery.id,
    Delivery.status,
    Delivery.content,
    Delivery.kind,
    Delivery.filename,
    Delivery.content_type,
    Delivery.content_size,
    Delivery.content_sha256,
    Delivery.expires_at,
    Delivery.consumed_at,
    Delivery.revoked_at,
)

# 导出/校验链记录时的列（绝不包含 deliveries.content 等明文投递内容）
_CHAIN_COLS = (
    AuditLog.seq,
    AuditLog.created_at,
    AuditLog.action,
    AuditLog.result,
    AuditLog.delivery_id,
    AuditLog.token_hash,
    AuditLog.client_ip,
    AuditLog.user_agent,
    AuditLog.detail,
    AuditLog.event_digest,
    AuditLog.prev_hash,
    AuditLog.entry_hash,
)

# 链追加的竞争重试上限（正常竞争下通常 1~2 次即完成）
_MAX_CHAIN_ATTEMPTS = 200


class DeliveryStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        token_hash: str,
        kind: str,
        content: bytes,
        expires_at: datetime,
        filename: str | None = None,
        content_type: str | None = None,
        content_sha256: str,
    ) -> Delivery:
        delivery = Delivery(
            token_hash=token_hash,
            kind=kind,
            content=content,
            filename=filename,
            content_type=content_type,
            content_size=len(content),
            content_sha256=content_sha256,
            expires_at=expires_at,
        )
        self.session.add(delivery)
        await self.session.flush()
        return delivery

    async def _lazily_expire(self, token_hash: str, now: datetime) -> bool:
        """把 active 且已到期的行提升为 expired。

        必须在 *独立事务* 中执行：调用方的读事务可能持有旧快照
        （SQLite/REPEATABLE READ），在其中回写过期状态会覆盖
        并发赢家刚刚提交的 consumed/revoked。
        """
        result = await self.session.execute(
            update(Delivery)
            .where(
                Delivery.token_hash == token_hash,
                Delivery.status == ACTIVE,
                Delivery.expires_at <= now,
            )
            .values(status=EXPIRED, expired_at=now)
        )
        await self.session.commit()
        return (result.rowcount or 0) > 0

    async def claim(self, token_hash: str) -> tuple[bool, str, Delivery | None]:
        """原子消费。

        返回 (won, state, row)：
        - won=True  本次调用是唯一赢家，state=consumed，row 带明文内容
                    （内容仅此一次从事务中取出）。
        - won=False 本次未抢到，state 为明确的失败原因：
                    consumed（已被他人取走）/ revoked / expired / unknown，
                    row 不含内容（由上层按需读取，但不返回给调用方）。

        正确性说明：
        - 条件 UPDATE ... WHERE status='active' AND 未过期 是唯一裁决点。
          PostgreSQL（READ COMMITTED）用行锁串行化并发更新，仅一个事务命中。
        - 未命中即提交，绝不在同一事务里回写过期，避免旧快照覆盖赢家终态。
        """
        now = utcnow()
        result = await self.session.execute(
            update(Delivery)
            .where(
                Delivery.token_hash == token_hash,
                Delivery.status == ACTIVE,
                Delivery.expires_at > now,
            )
            .values(status=CONSUMED, consumed_at=now)
            .returning(*_DELIVERY_COLS)
        )
        row = result.first()
        if row is not None:
            await self.session.commit()
            return True, CONSUMED, row

        # 未命中：结束本事务后，在独立事务里幂等地推进过期，再读终态
        await self.session.commit()
        await self._lazily_expire(token_hash, now)

        current = (
            await self.session.execute(
                select(Delivery).where(Delivery.token_hash == token_hash)
            )
        ).scalar_one_or_none()
        if current is None:
            return False, UNKNOWN, None
        return False, current.status, current

    async def revoke(self, token_hash: str) -> tuple[bool, str, Delivery | None]:
        """原子撤回。返回 (won, state, row)。

        won=True 表示本次成功撤回；won=False 时 state 为
        consumed / expired / unknown（已被取走、已过期、令牌不存在）。
        """
        now = utcnow()
        result = await self.session.execute(
            update(Delivery)
            .where(
                Delivery.token_hash == token_hash,
                Delivery.status == ACTIVE,
                Delivery.expires_at > now,
            )
            .values(status=REVOKED, revoked_at=now)
            .returning(Delivery.id, Delivery.status, Delivery.expires_at, Delivery.revoked_at)
        )
        row = result.first()
        if row is not None:
            await self.session.commit()
            current = (
                await self.session.execute(
                    select(Delivery).where(Delivery.token_hash == token_hash)
                )
            ).scalar_one()
            return True, REVOKED, current

        await self.session.commit()
        await self._lazily_expire(token_hash, now)

        current = (
            await self.session.execute(
                select(Delivery).where(Delivery.token_hash == token_hash)
            )
        ).scalar_one_or_none()
        if current is None:
            return False, UNKNOWN, None
        return False, current.status, current

    async def sweep_expired(self) -> int:
        """后台批量标记过期（惰性过期之外的兜底），返回影响行数。"""
        result = await self.session.execute(
            update(Delivery)
            .where(Delivery.status == ACTIVE, Delivery.expires_at <= utcnow())
            .values(status=EXPIRED, expired_at=utcnow())
        )
        await self.session.commit()
        return result.rowcount or 0

    # ---------------- 审计哈希链 ----------------

    async def write_audit(
        self,
        *,
        action: str,
        result: str,
        delivery_id: uuid.UUID | None = None,
        token_hash: str | None = None,
        detail: dict | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        """追加一条入链审计记录，并在同一事务中推进链游标。

        未知令牌等失败请求也走这里，因此同样入链。

        步骤（顺序是正确性的关键）：

        1. 读取链游标 (last_seq, last_hash)；
        2. 用读到的游标计算新序号、事件摘要与链哈希；
        3. **先**执行条件 UPDATE 推进游标（WHERE last_seq=:read），
           这是唯一裁决点——抢占成功后才 INSERT 审计行，因此竞态时
           不会先撞 seq 唯一索引；
        4. 命中：INSERT 审计行并提交（此时仍持有链游标行锁，序号无争议）；
           未命中：重试。

        并发裁决：

        - PostgreSQL（READ COMMITTED）：条件 UPDATE 在链游标单行上排队，
          持锁者提交后 WHERE 按最新行版本重新判定，只有一个事务命中；
          未命中的事务没有产生任何写入，直接重读游标重试即可，
          同事务中的其它写入（如新建投递的 INSERT）不受影响。
        - SQLite（测试，WAL）：读快照不随提交前进，且读事务首次写入时
          若他人已提交会得到 SQLITE_BUSY_SNAPSHOT。两种失配都以
          整事务回滚 + 重读重试解决；此路径只可能发生在纯审计追加场景
          （create 路径以写 INSERT 开始，拿到写锁后快照必然最新；
          claim/revoke 的状态迁移已提前提交）。
        """
        created_at = utcnow()
        ua = (user_agent or "")[:512] or None
        ip = (client_ip or None)[:64] if client_ip else None
        th = (token_hash or None)[:64] if token_hash else None

        is_sqlite = self.session.bind.dialect.name == "sqlite"

        for _attempt in range(1, _MAX_CHAIN_ATTEMPTS + 1):
            last_seq, last_hash = await self._load_chain_state()
            seq = last_seq + 1
            digest = event_digest_for(
                seq=seq,
                created_at=created_at,
                action=action,
                result=result,
                delivery_id=delivery_id,
                token_hash=th,
                client_ip=ip,
                user_agent=ua,
                detail=detail,
            )
            entry_hash_value = chain_hash(last_hash, digest)

            try:
                # 唯一裁决点：仅当链游标仍停在本事务读到的位置时才推进
                cursor_result = await self.session.execute(
                    update(AuditChainState)
                    .where(
                        AuditChainState.id == 1,
                        AuditChainState.last_seq == last_seq,
                    )
                    .values(
                        last_seq=seq,
                        last_hash=entry_hash_value,
                        updated_at=created_at,
                    )
                )
            except sqlalchemy.exc.OperationalError:
                # SQLite/WAL：读快照过期导致的 SQLITE_BUSY_SNAPSHOT。
                # 整事务回滚以获取新快照（此路径无同事务兄弟写入，见上）。
                if not is_sqlite:
                    raise
                await self.session.rollback()
                await asyncio.sleep(0)
                continue

            if cursor_result.rowcount == 1:
                # 已独占链游标行锁：审计行的 seq 无争议，随外层事务原子提交
                entry = AuditLog(
                    delivery_id=delivery_id,
                    token_hash=th,
                    action=action,
                    result=result,
                    detail=detail,
                    client_ip=ip,
                    user_agent=ua,
                    created_at=created_at,
                    seq=seq,
                    event_digest=digest,
                    prev_hash=last_hash,
                    entry_hash=entry_hash_value,
                )
                self.session.add(entry)
                await self.session.flush()
                await self.session.commit()
                return entry

            # 游标已被他人推进：
            # - PG：本 UPDATE 未产生任何写入，重读（READ COMMITTED 可见新提交）
            #   即可重试，同事务兄弟写入原样保留；
            # - SQLite：快照不会前进，需整事务回滚后重读。
            if is_sqlite:
                await self.session.rollback()
            await asyncio.sleep(0)

        raise RuntimeError(
            f"审计链追加在 {_MAX_CHAIN_ATTEMPTS} 次尝试后仍未成功"
        )

    async def _load_chain_state(self) -> tuple[int, str]:
        """读取链游标；极端情况下（旧库未种子化）就地自愈。"""
        state_row = (
            await self.session.execute(
                select(AuditChainState.last_seq, AuditChainState.last_hash).where(
                    AuditChainState.id == 1
                )
            )
        ).first()
        if state_row is None:
            self.session.add(
                AuditChainState(id=1, last_seq=0, last_hash=GENESIS_HASH)
            )
            await self.session.flush()
            return 0, GENESIS_HASH
        return state_row.last_seq, state_row.last_hash

    async def iter_audit_range(
        self,
        *,
        start: datetime | None,
        end: datetime | None,
    ) -> AsyncIterator[ChainEntry]:
        """按链序号顺序流式迭代时间范围内的审计记录（只读）。

        时间范围约定：created_at >= start 且 created_at < end（左闭右开）。
        只选择链/元数据列，不触碰任何投递明文内容。
        """
        stmt = select(*_CHAIN_COLS)
        if start is not None:
            stmt = stmt.where(AuditLog.created_at >= start)
        if end is not None:
            stmt = stmt.where(AuditLog.created_at < end)
        stmt = stmt.order_by(AuditLog.seq.asc()).execution_options(stream_results=True)

        result = await self.session.stream(stmt)
        try:
            async for row in result:
                yield ChainEntry.from_row(row)
        finally:
            await result.close()

    async def audit_range_meta(
        self,
        *,
        start: datetime | None,
        end: datetime | None,
    ) -> tuple[int, ChainEntry | None, ChainEntry | None]:
        """返回时间范围内的 (记录数, 首条, 末条)，与流式查询共享同一快照。"""
        filters = []
        if start is not None:
            filters.append(AuditLog.created_at >= start)
        if end is not None:
            filters.append(AuditLog.created_at < end)

        count = await self.session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(*filters)
        )
        if not count:
            return 0, None, None

        first = (
            await self.session.execute(
                self._range_stmt(filters, ascending=True)
            )
        ).first()
        last = (
            await self.session.execute(
                self._range_stmt(filters, ascending=False)
            )
        ).first()
        return int(count or 0), ChainEntry.from_row(first), ChainEntry.from_row(last)

    @staticmethod
    def _range_stmt(filters: Iterable, *, ascending: bool):
        order = AuditLog.seq.asc() if ascending else AuditLog.seq.desc()
        return select(*_CHAIN_COLS).where(*filters).order_by(order).limit(1)

    async def entry_hash_before(self, first_seq: int) -> str | None:
        """供片段校验锚定：返回序号 ``first_seq - 1`` 记录的链哈希。

        库中不存在该记录（例如范围起点之前无记录）时返回 None。
        """
        if first_seq <= 1:
            return GENESIS_HASH
        row = await self.session.scalar(
            select(AuditLog.entry_hash)
            .where(AuditLog.seq == first_seq - 1)
        )
        return row
