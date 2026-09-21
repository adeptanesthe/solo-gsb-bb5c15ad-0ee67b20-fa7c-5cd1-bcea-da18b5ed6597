"""投递记录的数据访问层。

并发性正确性的核心：所有状态迁移都用 *单条带 WHERE 条件的 UPDATE ... RETURNING*
完成。PostgreSQL 会用行锁串行化对同一行的并发更新：
- 第一个满足条件的事务把 status 从 active 改走并返回行（赢家）；
- 其它事务的 WHERE 不再匹配，返回空（输家），随后读取当前终态给出明确结果。

因此不需要应用层分布式锁；Redis 仅为终态快速拒绝缓存。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditLog, Delivery
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
        entry = AuditLog(
            delivery_id=delivery_id,
            token_hash=token_hash,
            action=action,
            result=result,
            detail=detail,
            client_ip=client_ip,
            user_agent=(user_agent or "")[:512] or None,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry
