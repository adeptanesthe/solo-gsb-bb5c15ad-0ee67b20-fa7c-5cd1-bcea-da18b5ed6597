"""投递记录的数据访问层。

并发性正确性的核心：所有状态迁移都用 *单条带 WHERE 条件的 UPDATE ... RETURNING*
完成。PostgreSQL 会用行锁串行化对同一行的并发更新：
- 第一个满足条件的事务把 status 从 active 改走并返回行（赢家）；
- 其它事务的 WHERE 不再匹配，返回空（输家），随后读取当前终态给出明确结果。

因此不需要应用层分布式锁；Redis 仅为终态快速拒绝缓存。

审计哈希链的追加同样由数据库裁决：``audit_chain_state`` 单行表保存链尖，
每条审计写入时执行一次条件 UPDATE（``WHERE last_seq=:读到的序号``）推进链尖，
并发事务的条件更新被行锁串行化，输家重读新链尖并重试，保证链序号连续且唯一。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .chain import (
    build_event_payload,
    compute_entry_hash,
    compute_event_hash,
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

# 高并发下链尖条件更新的最大重试次数（正常 1~3 次即足够）
_MAX_CHAIN_ATTEMPTS = 1000


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
        """把 active 且已到期的行提升为 expired（调用方决定事务边界）。"""
        result = await self.session.execute(
            update(Delivery)
            .where(
                Delivery.token_hash == token_hash,
                Delivery.status == ACTIVE,
                Delivery.expires_at <= now,
            )
            .values(status=EXPIRED, expired_at=now)
        )
        return (result.rowcount or 0) > 0

    async def claim(self, token_hash: str) -> tuple[bool, str, Delivery | None]:
        """原子消费。

        返回 (won, state, row)：
        - won=True  本次调用是唯一赢家，state=consumed，row 带明文内容
                    （内容仅此一次从事务中取出）。状态迁移尚未提交，由调用方
                    与审计写入在同一事务中一起提交。
        - won=False 本次未抢到，state 为明确的失败原因：
                    consumed（已被他人取走）/ revoked / expired / unknown，
                    row 不含内容。终态（含惰性过期）已在本方法内提交。

        正确性说明：
        - 条件 UPDATE ... WHERE status='active' AND 未过期 是唯一裁决点。
          PostgreSQL（READ COMMITTED）用行锁串行化并发更新，仅一个事务命中。
        - 未命中分支的惰性过期与终态读取在同一事务内完成：过期提升同样带
          status='active' 的 WHERE 条件，不可能覆盖并发赢家刚写入的终态。
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
            # 不提交：与审计记录同事务提交，保证「消费成功」与「入链」原子
            return True, CONSUMED, row

        # 未命中：同事务幂等推进过期，再读终态
        await self._lazily_expire(token_hash, now)
        await self.session.commit()

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

        won=True 表示本次成功撤回（状态迁移未提交，与审计同事务提交）；
        won=False 时 state 为 consumed / expired / unknown（终态已提交）。
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
            return True, REVOKED, row

        await self._lazily_expire(token_hash, now)
        await self.session.commit()

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
        """写入一条带哈希链的审计记录（不提交，由调用方提交）。

        链顺序由 ``audit_chain_state`` 的条件 UPDATE 裁决：读到的链尖
        (last_seq, last_hash) 作为 WHERE 条件，命中才推进；并发输家重读
        新链尖并重试。审计行随后以同一事务插入，seq 唯一约束兜底，因此
        链序号连续、唯一且与链尖严格一致。
        """
        entry_id = uuid.uuid4()
        created_at = utcnow()
        ua = (user_agent or "")[:512] or None

        payload = build_event_payload(
            id=entry_id,
            delivery_id=delivery_id,
            token_hash=token_hash,
            action=action,
            result=result,
            detail=detail,
            client_ip=client_ip,
            user_agent=ua,
            created_at=created_at,
        )
        event_hash = compute_event_hash(payload)

        seq: int | None = None
        prev_hash: str | None = None
        entry_hash: str | None = None

        for attempt in range(_MAX_CHAIN_ATTEMPTS):
            tip = (
                await self.session.execute(
                    select(AuditChainState.last_seq, AuditChainState.last_hash)
                    .where(AuditChainState.id == 1)
                )
            ).one()
            next_seq = tip.last_seq + 1
            candidate = compute_entry_hash(tip.last_hash, next_seq, event_hash)

            advanced = await self.session.execute(
                update(AuditChainState)
                .where(
                    AuditChainState.id == 1,
                    AuditChainState.last_seq == tip.last_seq,
                    AuditChainState.last_hash == tip.last_hash,
                )
                .values(
                    last_seq=next_seq,
                    last_hash=candidate,
                    updated_at=created_at,
                )
            )
            if (advanced.rowcount or 0) == 1:
                seq, prev_hash, entry_hash = next_seq, tip.last_hash, candidate
                break
            # 链尖已被并发事务推进：重读新链尖后重试（无需回滚本事务，
            # 本事务尚未插入审计行；PG READ COMMITTED / SQLite WAL 下
            # SELECT 都能读到并发事务已提交的新链尖）
        else:  # pragma: no cover - 正常并发下不可能耗尽
            raise RuntimeError("审计链追加重试次数耗尽，链尖竞争异常激烈")

        entry = AuditLog(
            id=entry_id,
            delivery_id=delivery_id,
            token_hash=token_hash,
            action=action,
            result=result,
            detail=detail,
            client_ip=client_ip,
            user_agent=ua,
            created_at=created_at,
            seq=seq,
            event_hash=event_hash,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry
