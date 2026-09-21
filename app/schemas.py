"""Pydantic 请求/响应模型。"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CreateTextRequest(BaseModel):
    text: str = Field(min_length=1, description="要投递的文本内容")
    ttl_seconds: int = Field(
        default=24 * 3600,
        ge=1,
        description="有效期（秒），服务端会再次按配置区间校验",
    )


class CreateResponse(BaseModel):
    delivery_id: uuid.UUID
    token: str = Field(description="取件令牌，仅在本次响应中返回，之后无法再查到")
    expires_at: datetime
    url: str = Field(description="取件地址（POST）")


class TextPickupResponse(BaseModel):
    result: str = "success"  # success
    delivery_id: uuid.UUID
    kind: str = "text"
    content: str
    content_sha256: str
    consumed_at: datetime


class DenyResponse(BaseModel):
    """取件/撤回未成功时的统一明确结果。"""

    result: str  # consumed | revoked | expired | unknown
    detail: str


class RevokeResponse(BaseModel):
    result: str  # revoked | already_revoked | consumed | expired | unknown
    delivery_id: uuid.UUID | None = None
    revoked_at: datetime | None = None


class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str


class AuditVerifyResponse(BaseModel):
    """哈希链完整性校验报告；ok=False 时 error 指出第一处错误类型。"""

    ok: bool
    count: int = Field(default=0, description="实际校验的记录数")
    first_seq: int | None = Field(default=None, description="首条记录序号")
    last_seq: int | None = Field(default=None, description="末条记录序号")
    start_hash: str | None = Field(default=None, description="首条记录的链哈希")
    end_hash: str | None = Field(default=None, description="末条记录的链哈希")
    # missing | out_of_order | duplicate | field_tampered | chain_break
    error: str | None = Field(default=None, description="第一处错误的类型")
    seq: int | None = Field(default=None, description="第一处错误所在记录序号")
    position: int | None = Field(default=None, description="第一处错误所在行（从 1 开始）")
    detail: str | None = Field(default=None, description="中文错误说明")
