"""审计哈希链的导出与校验接口。

- ``GET /api/v1/audit/export``：按 created_at 时间范围导出 NDJSON，
  只读事务，响应头带起止链哈希、起止序号与记录数；不包含任何投递明文。
- ``GET /api/v1/audit/verify``：在线校验库内整条链，报告第一处错误。
- ``POST /api/v1/audit/verify``：校验此前导出的 NDJSON（可按导出响应头
  中的起点序号/前链哈希锚定一个片段）。
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .chain import (
    CHAIN_VERSION,
    GENESIS_HASH,
    EventRecord,
    canonical_timestamp,
    parse_timestamp,
    verify_records,
)
from .models import AuditChainState, AuditLog

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

_BATCH = 1000
_DEFAULT_LIMIT = 10_000
_MAX_LIMIT = 100_000
_EXPOSE_HEADERS = (
    "X-Audit-Count, X-Audit-Start-Seq, X-Audit-End-Seq, "
    "X-Audit-Start-Prev-Hash, X-Audit-Start-Hash, X-Audit-End-Hash, "
    "X-Audit-Truncated"
)

# 导出列（仅审计列；绝不 join / 输出 deliveries.content 等明文投递内容）
_EXPORT_COLS = (
    AuditLog.seq,
    AuditLog.id,
    AuditLog.delivery_id,
    AuditLog.token_hash,
    AuditLog.action,
    AuditLog.result,
    AuditLog.detail,
    AuditLog.client_ip,
    AuditLog.user_agent,
    AuditLog.created_at,
    AuditLog.event_hash,
    AuditLog.prev_hash,
    AuditLog.entry_hash,
)


def _get_session(request: Request) -> AsyncSession:
    """新建一个独立于请求依赖注入的会话（导出需要跨流式响应持有）。"""
    return request.app.state.db.session_factory()


async def _set_read_only(session: AsyncSession) -> None:
    """开启只读事务：PostgreSQL 用 READ ONLY 事务，SQLite 用 query_only PRAGMA。"""
    dialect = session.bind.dialect.name
    if dialect == "postgresql":
        # 必须是事务内第一条语句；SQLAlchemy 在首次 execute 时自动开启事务
        await session.execute(text("SET TRANSACTION READ ONLY"))
    elif dialect == "sqlite":
        await session.execute(text("PRAGMA query_only=ON"))


async def _reset_read_only(session: AsyncSession) -> None:
    if session.bind.dialect.name == "sqlite":
        # 连接归还连接池前恢复，避免污染复用同一连接的写请求
        await session.execute(text("PRAGMA query_only=OFF"))


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _range_filters(stmt, start: datetime | None, end: datetime | None):
    if start is not None:
        stmt = stmt.where(AuditLog.created_at >= start)
    if end is not None:
        stmt = stmt.where(AuditLog.created_at < end)
    return stmt


def _line_from_row(row) -> str:
    return json.dumps(
        {
            "v": CHAIN_VERSION,
            "seq": row.seq,
            "id": str(row.id),
            "delivery_id": str(row.delivery_id) if row.delivery_id is not None else None,
            "token_hash": row.token_hash,
            "action": row.action,
            "result": row.result,
            "detail": row.detail,
            "client_ip": row.client_ip,
            "user_agent": row.user_agent,
            "created_at": canonical_timestamp(row.created_at),
            "event_hash": row.event_hash,
            "prev_hash": row.prev_hash,
            "entry_hash": row.entry_hash,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


@router.get(
    "/export",
    summary="按时间范围导出审计链（NDJSON 只读流）",
    responses={200: {"content": {"application/x-ndjson": {}}}},
)
async def export_audit(
    request: Request,
    start: datetime | None = Query(default=None, description="起始时间（含），ISO-8601"),
    end: datetime | None = Query(default=None, description="结束时间（不含），ISO-8601"),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT, description="最多导出条数"),
):
    start = _as_utc(start)
    end = _as_utc(end)
    if start is not None and end is not None and start >= end:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "start 必须早于 end。"},
        )

    session = _get_session(request)
    try:
        await _set_read_only(session)

        count_stmt = _range_filters(
            select(func.count()).select_from(AuditLog), start, end
        )
        total = (await session.execute(count_stmt)).scalar_one()
        effective = min(total, limit)
        truncated = 1 if total > limit else 0

        first_row = None
        last_row = None
        if effective:
            first_stmt = _range_filters(
                select(*_EXPORT_COLS).order_by(AuditLog.seq.asc()).limit(1),
                start,
                end,
            )
            first_row = (await session.execute(first_stmt)).first()

            if effective > 1:
                last_stmt = _range_filters(
                    select(*_EXPORT_COLS).order_by(AuditLog.seq.desc()).limit(1),
                    start,
                    end,
                )
                if limit < total:
                    # 截断窗口：最后一条是“窗口内”的第 effective 条，而非全量最后一条
                    window_end_seq = (
                        await session.execute(
                            _range_filters(
                                select(AuditLog.seq)
                                .order_by(AuditLog.seq.asc())
                                .limit(1)
                                .offset(effective - 1),
                                start,
                                end,
                            )
                        )
                    ).scalar_one()
                    last_stmt = _range_filters(
                        select(*_EXPORT_COLS)
                        .where(AuditLog.seq == window_end_seq),
                        start,
                        end,
                    )
                last_row = (await session.execute(last_stmt)).first()
            else:
                last_row = first_row

        start_seq = first_row.seq if first_row else None
        end_seq = last_row.seq if last_row else None

        headers = {
            "Content-Type": "application/x-ndjson; charset=utf-8",
            "X-Audit-Count": str(effective),
            "X-Audit-Truncated": str(truncated),
            "X-Audit-Start-Seq": str(start_seq) if start_seq is not None else "",
            "X-Audit-End-Seq": str(end_seq) if end_seq is not None else "",
            "X-Audit-Start-Prev-Hash": first_row.prev_hash if first_row else "",
            "X-Audit-Start-Hash": first_row.entry_hash if first_row else "",
            "X-Audit-End-Hash": last_row.entry_hash if last_row else "",
            "Access-Control-Expose-Headers": _EXPOSE_HEADERS,
        }

        async def generate() -> AsyncIterator[bytes]:
            try:
                if not effective:
                    yield b""
                    return
                cursor = start_seq - 1
                while True:
                    stmt = (
                        select(*_EXPORT_COLS)
                        .where(AuditLog.seq > cursor, AuditLog.seq <= end_seq)
                        .order_by(AuditLog.seq.asc())
                        .limit(_BATCH)
                    )
                    stmt = _range_filters(stmt, start, end)
                    batch = (await session.execute(stmt)).all()
                    if not batch:
                        break
                    for row in batch:
                        yield (_line_from_row(row) + "\n").encode("utf-8")
                    cursor = batch[-1].seq
                    if cursor >= end_seq:
                        break
            finally:
                with contextlib.suppress(Exception):
                    await _reset_read_only(session)
                await session.close()

        return StreamingResponse(generate(), headers=headers)
    except Exception:
        # 查询在流式响应开始前失败：同样要复位 SQLite query_only，
        # 否则连接归还连接池后会污染复用该连接的写请求
        with contextlib.suppress(Exception):
            await _reset_read_only(session)
        await session.close()
        raise


def _record_from_row(row) -> EventRecord:
    return EventRecord(
        seq=row.seq,
        id=str(row.id),
        delivery_id=str(row.delivery_id) if row.delivery_id is not None else None,
        token_hash=row.token_hash,
        action=row.action,
        result=row.result,
        detail=row.detail,
        client_ip=row.client_ip,
        user_agent=row.user_agent,
        created_at=canonical_timestamp(row.created_at),
        prev_hash=row.prev_hash,
        event_hash=row.event_hash,
        entry_hash=row.entry_hash,
    )


@router.get("/verify", summary="在线校验审计哈希链（库内全链）")
async def verify_online(request: Request):
    session = _get_session(request)
    try:
        await _set_read_only(session)
        tip = (
            await session.execute(
                select(AuditChainState.last_seq, AuditChainState.last_hash).where(
                    AuditChainState.id == 1
                )
            )
        ).one()

        records: list[EventRecord] = []
        cursor = 0
        while True:
            batch = (
                await session.execute(
                    select(*_EXPORT_COLS)
                    .where(AuditLog.seq > cursor)
                    .order_by(AuditLog.seq.asc())
                    .limit(_BATCH)
                )
            ).all()
            if not batch:
                break
            records.extend(_record_from_row(row) for row in batch)
            cursor = batch[-1].seq

        report = verify_records(
            records,
            expected_first_seq=1,
            expected_prev_hash=GENESIS_HASH,
            expected_last_seq=tip.last_seq,
            expected_last_hash=tip.last_hash,
            tip_seq=tip.last_seq,
            tip_hash=tip.last_hash,
        )
        return report.to_dict()
    finally:
        with contextlib.suppress(Exception):
            await _reset_read_only(session)
        await session.close()


@router.post(
    "/verify",
    summary="校验导出的 NDJSON 审计链（可锚定片段起点）",
)
async def verify_export(
    request: Request,
    start_seq: int = Query(default=1, ge=1, description="片段第一条记录的链序号"),
    start_prev_hash: str = Query(
        default=GENESIS_HASH, description="片段起点的前链哈希（导出响应头 X-Audit-Start-Prev-Hash）"
    ),
):
    body = (await request.body()).decode("utf-8")
    records: list[EventRecord] = []

    for lineno, raw in enumerate(body.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            created_at = canonical_timestamp(parse_timestamp(obj["created_at"]))
            records.append(
                EventRecord(
                    seq=int(obj["seq"]),
                    id=str(obj["id"]),
                    delivery_id=obj.get("delivery_id"),
                    token_hash=obj.get("token_hash"),
                    action=obj["action"],
                    result=obj["result"],
                    detail=obj.get("detail"),
                    client_ip=obj.get("client_ip"),
                    user_agent=obj.get("user_agent"),
                    created_at=created_at,
                    prev_hash=obj["prev_hash"],
                    event_hash=obj["event_hash"],
                    entry_hash=obj["entry_hash"],
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "ok": False,
                    "code": "invalid_format",
                    "message": f"第 {lineno} 行不是合法的审计 NDJSON 记录：{exc}",
                    "line": lineno,
                },
            )

    if len(start_prev_hash) != 64 or any(
        ch not in "0123456789abcdef" for ch in start_prev_hash
    ):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"ok": False, "code": "invalid_format",
                     "message": "start_prev_hash 必须是 64 位十六进制哈希。"},
        )

    report = verify_records(
        records,
        expected_first_seq=start_seq,
        expected_prev_hash=start_prev_hash,
    )
    return report.to_dict()
