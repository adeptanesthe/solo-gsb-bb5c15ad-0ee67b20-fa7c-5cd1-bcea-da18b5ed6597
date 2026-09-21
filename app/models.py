"""SQLAlchemy 2.0 模型：投递记录与审计日志。

类型使用跨方言变体：PostgreSQL 上是原生 UUID / JSONB，SQLite（测试）上回退。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String, text
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


# 按时间倒序拉取审计记录时的组合索引
Index("ix_audit_delivery_created", AuditLog.delivery_id, AuditLog.created_at.desc())
# 后台清扫器扫描到期 active 行
Index("ix_deliveries_status_expires", Delivery.status, Delivery.expires_at)

# 审计详情中的键都很小，JSONB 仅用于存储便利
_ = text  # 保留导入，便于未来迁移脚本复用
