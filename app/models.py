"""SQLAlchemy 2.0 模型：投递记录与审计日志。

类型使用跨方言变体：PostgreSQL 上是原生 UUID / JSONB，SQLite（测试）上回退。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import CHAR, JSON, TypeDecorator

from .utils import utcnow


class UuidType(TypeDecorator):
    """PostgreSQL 用原生 uuid，其它方言（SQLite 测试）用 CHAR(36)。"""

    impl = CHAR(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if dialect.name == "postgresql" or value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None or dialect.name == "postgresql":
            return value
        return uuid.UUID(value)


class JSONBType(TypeDecorator):
    """PostgreSQL 用 JSONB，其它方言回退通用 JSON。"""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class Base(DeclarativeBase):
    pass


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[uuid.UUID] = mapped_column(UuidType, primary_key=True, default=uuid.uuid4)
    # 取件令牌的 SHA-256；唯一索引承载并发行锁竞争
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)  # text | file
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # active | consumed | revoked | expired
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="active", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UuidType, primary_key=True, default=uuid.uuid4)
    delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UuidType,
        ForeignKey("deliveries.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # 未匹配令牌的请求也需要留痕，此时只记录哈希
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    # success | consumed | revoked | expired | unknown
    result: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    detail: Mapped[dict | None] = mapped_column(JSONBType, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    # ---- 哈希链完整性字段（见 app/chain.py）----
    # 链序号，从 1 开始连续递增；唯一索引由数据库裁决并发追加顺序
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    # 规范化事件摘要：SHA-256(规范化的事件字段 JSON)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # 前一条审计记录的链哈希；第 1 条为 64 个 0（GENESIS_HASH）
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # 本条链哈希：SHA-256(prev_hash + seq + event_hash)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditChainState(Base):
    """审计链链尖：单行表（固定 id=1），并发追加时由条件 UPDATE 裁决顺序。"""

    __tablename__ = "audit_chain_state"

    # 固定为 1，全表只允许一行
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


# 按时间倒序拉取审计记录时的组合索引
Index("ix_audit_delivery_created", AuditLog.delivery_id, AuditLog.created_at.desc())
# 后台清扫器扫描到期 active 行
Index("ix_deliveries_status_expires", Delivery.status, Delivery.expires_at)

# 审计详情中的键都很小，JSONB 仅用于存储便利
_ = text  # 保留导入，便于未来迁移脚本复用
