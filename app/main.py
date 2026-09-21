"""FastAPI 应用：创建 / 取件 / 撤回 / 健康检查。

原子消费链路：
    请求 → Redis 终态标记快速拒绝（best-effort）
         → PostgreSQL 单条条件 UPDATE ... RETURNING（正确性的唯一裁决）
         → 成功后回写 Redis 终态标记
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta

import redis.exceptions
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .audit_chain import (
    GENESIS_HASH,
    ChainEntry,
    ChainFormatError,
    dumps_ndjson,
    verify_chain,
)
from .config import Settings, get_settings
from .db import Database
from .models import Delivery
from .redis_client import DenyCache, create_redis
from .schemas import (
    AuditVerifyResponse,
    CreateResponse,
    CreateTextRequest,
    DenyResponse,
    HealthResponse,
    RevokeResponse,
    TextPickupResponse,
)
from .store import CONSUMED, EXPIRED, REVOKED, UNKNOWN, DeliveryStore
from .utils import (
    client_ip,
    content_disposition,
    ensure_utc,
    hash_token,
    new_token,
    sha256_hex,
    utcnow,
)

logger = logging.getLogger("dropbox")

# 终态 -> HTTP 状态码（取件与撤回共用）
_DENY_STATUS = {
    CONSUMED: status.HTTP_410_GONE,
    EXPIRED: status.HTTP_410_GONE,
    REVOKED: status.HTTP_409_CONFLICT,
    UNKNOWN: status.HTTP_404_NOT_FOUND,
}
_DENY_DETAIL = {
    CONSUMED: "该令牌已被成功取件，内容仅可读取一次。",
    EXPIRED: "投递已过期，内容不可再读取。",
    REVOKED: "投递已被发送者撤回。",
    UNKNOWN: "取件令牌不存在。",
}


# ---------------- 依赖注入 ----------------


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    db: Database = request.app.state.db
    async with db.session_factory() as session:
        yield session


def get_store(session: AsyncSession = Depends(get_db)) -> DeliveryStore:
    return DeliveryStore(session)


async def get_cache(request: Request) -> DenyCache:
    return request.app.state.cache


# ---------------- 应用生命周期 ----------------


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = get_settings()
    app.state.db = Database()
    app.state.cache = create_redis()
    await app.state.db.create_schema()

    stop = asyncio.Event()
    sweeper_task = asyncio.create_task(_sweep_loop(app.state.db, cfg, stop))
    try:
        yield
    finally:
        stop.set()
        sweeper_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweeper_task
        await app.state.db.close()
        await app.state.cache.close()


async def _sweep_loop(db: Database, cfg: Settings, stop: asyncio.Event) -> None:
    """惰性过期之外的兜底：定时把到期 active 行批量标记为 expired。"""
    while not stop.is_set():
        try:
            async with db.session_factory() as session:
                count = await DeliveryStore(session).sweep_expired()
                if count:
                    logger.info("sweep marked %d deliveries expired", count)
        except Exception:  # noqa: BLE001 - 清扫失败不应杀死进程
            logger.exception("sweep cycle failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.sweep_interval_seconds)
        except asyncio.TimeoutError:
            pass


app = FastAPI(
    title="一次性内容投递箱 API",
    version="1.0.0",
    description="创建带过期时间的文本/小文件投递，取件令牌只能成功读取一次。",
    lifespan=lifespan,
)


# ---------------- 辅助 ----------------


def _deny(result: str, http_status: int | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=http_status or _DENY_STATUS[result],
        content=DenyResponse(result=result, detail=_DENY_DETAIL[result]).model_dump(mode="json"),
    )


async def _audit(
    store: DeliveryStore,
    *,
    action: str,
    result: str,
    request: Request,
    delivery_id=None,
    token_hash: str | None = None,
    detail: dict | None = None,
) -> None:
    await store.write_audit(
        action=action,
        result=result,
        delivery_id=delivery_id,
        token_hash=token_hash,
        detail=detail,
        client_ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


async def _fast_flag(cache: DenyCache, token_hash: str) -> str | None:
    """读 Redis 终态标记；Redis 故障时静默回落数据库。"""
    try:
        return await cache.get_flag(token_hash)
    except (redis.exceptions.RedisError, OSError):
        logger.warning("redis unavailable, falling back to database")
        return None


async def _remember_terminal(cache: DenyCache, token_hash: str, state: str, cfg: Settings) -> None:
    try:
        await cache.set_flag_if_absent(token_hash, state, cfg.redis_flag_ttl_seconds)
    except (redis.exceptions.RedisError, OSError):
        logger.warning("redis unavailable, terminal flag not cached")


def _validate_ttl(ttl_seconds: int, cfg: Settings) -> None:
    if not (cfg.ttl_min_seconds <= ttl_seconds <= cfg.ttl_max_seconds):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"ttl_seconds 必须在 {cfg.ttl_min_seconds} 与 "
                f"{cfg.ttl_max_seconds} 之间"
            ),
        )


def _check_size(size: int, cfg: Settings) -> None:
    if size > cfg.max_content_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"内容超过大小上限 {cfg.max_content_bytes} 字节",
        )


async def _delivery_id_by_hash(session: AsyncSession, token_hash: str):
    """快速拒绝路径下，用令牌哈希反查 delivery_id（仅主键，不碰内容）。"""
    return await session.scalar(
        select(Delivery.id).where(Delivery.token_hash == token_hash)
    )


# ---------------- 创建 ----------------


@app.post(
    "/api/v1/deliveries",
    response_model=CreateResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["deliveries"],
    summary="创建文本投递",
)
async def create_text(
    payload: CreateTextRequest,
    request: Request,
    store: DeliveryStore = Depends(get_store),
    cache: DenyCache = Depends(get_cache),
    cfg: Settings = Depends(get_settings),
) -> CreateResponse:
    _validate_ttl(payload.ttl_seconds, cfg)
    content = payload.text.encode("utf-8")
    _check_size(len(content), cfg)

    token, token_h = new_token()
    expires_at = utcnow() + timedelta(seconds=payload.ttl_seconds)
    digest = sha256_hex(content)

    delivery = await store.create(
        token_hash=token_h,
        kind="text",
        content=content,
        expires_at=expires_at,
        content_type="text/plain; charset=utf-8",
        content_sha256=digest,
    )
    await _audit(
        store,
        action="create",
        result="success",
        request=request,
        delivery_id=delivery.id,
        token_hash=token_h,
        detail={"kind": "text", "ttl_seconds": payload.ttl_seconds, "size": len(content)},
    )
    await store.session.commit()

    return CreateResponse(
        delivery_id=delivery.id,
        token=token,
        expires_at=expires_at,
        url=f"{str(request.base_url).rstrip('/')}/api/v1/pickup/{token}",
    )


@app.post(
    "/api/v1/deliveries/file",
    response_model=CreateResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["deliveries"],
    summary="创建小文件投递（multipart/form-data）",
)
async def create_file(
    request: Request,
    file: UploadFile = File(..., description="要投递的小文件"),
    ttl_seconds: int = Form(24 * 3600),
    store: DeliveryStore = Depends(get_store),
    cache: DenyCache = Depends(get_cache),
    cfg: Settings = Depends(get_settings),
) -> CreateResponse:
    _validate_ttl(ttl_seconds, cfg)

    # 流式读取，最多多读 1 字节以判定超限，避免把超大文件整块载入内存
    max_bytes = cfg.max_content_bytes
    chunks: list[bytes] = []
    total = 0
    oversize = False
    while chunk := await file.read(64 * 1024):
        total += len(chunk)
        if total > max_bytes:
            oversize = True
            break
        chunks.append(chunk)
    if oversize:
        _check_size(max_bytes + 1, cfg)  # 统一抛出 413

    content = b"".join(chunks)
    token, token_h = new_token()
    expires_at = utcnow() + timedelta(seconds=ttl_seconds)
    digest = sha256_hex(content)
    filename = file.filename or "file.bin"
    content_type = file.content_type or "application/octet-stream"

    delivery = await store.create(
        token_hash=token_h,
        kind="file",
        content=content,
        expires_at=expires_at,
        filename=filename[:255],
        content_type=content_type[:255],
        content_sha256=digest,
    )
    await _audit(
        store,
        action="create",
        result="success",
        request=request,
        delivery_id=delivery.id,
        token_hash=token_h,
        detail={"kind": "file", "ttl_seconds": ttl_seconds, "size": total,
                "filename": filename[:255]},
    )
    await store.session.commit()

    return CreateResponse(
        delivery_id=delivery.id,
        token=token,
        expires_at=expires_at,
        url=f"{str(request.base_url).rstrip('/')}/api/v1/pickup/{token}",
    )


# ---------------- 取件（原子消费） ----------------


@app.post(
    "/api/v1/pickup/{token}",
    tags=["deliveries"],
    summary="凭令牌取件（成功只能一次）",
    responses={
        200: {"description": "取件成功（文本返回 JSON，文件返回二进制流）"},
        409: {"model": DenyResponse, "description": "已撤回"},
        410: {"model": DenyResponse, "description": "已消费或已过期"},
        404: {"model": DenyResponse, "description": "令牌不存在"},
    },
)
async def pickup(
    token: str,
    request: Request,
    store: DeliveryStore = Depends(get_store),
    cache: DenyCache = Depends(get_cache),
    cfg: Settings = Depends(get_settings),
):
    token_h = hash_token(token)

    # 1) Redis 快速拒绝（已知终态）
    if flag := await _fast_flag(cache, token_h):
        delivery_id = await _delivery_id_by_hash(store.session, token_h)
        await _audit(
            store,
            action="pickup",
            result=flag,
            request=request,
            delivery_id=delivery_id,
            token_hash=token_h,
        )
        await store.session.commit()
        return _deny(flag)

    # 2) 数据库原子消费：并发下只有一个事务能赢得这一行
    won, state, row = await store.claim(token_h)

    if not won:
        delivery_id = getattr(row, "id", None)
        await _audit(
            store,
            action="pickup",
            result=state,
            request=request,
            delivery_id=delivery_id,
            token_hash=token_h,
        )
        await store.session.commit()
        if state != UNKNOWN:
            await _remember_terminal(cache, token_h, state, cfg)
        return _deny(state)

    # 3) 赢家：内容只在此刻从事务中取出一次
    await _audit(
        store,
        action="pickup",
        result="success",
        request=request,
        delivery_id=row.id,
        token_hash=token_h,
        detail={"kind": row.kind, "size": row.content_size},
    )
    await store.session.commit()
    await _remember_terminal(cache, token_h, CONSUMED, cfg)

    consumed_at = ensure_utc(row.consumed_at) or utcnow()
    if row.kind == "file":
        headers = {
            "X-Drop-Result": "success",
            "X-Content-SHA256": row.content_sha256,
            "Content-Disposition": content_disposition(row.filename or "file.bin"),
        }
        return Response(
            content=row.content,
            media_type=row.content_type or "application/octet-stream",
            headers=headers,
        )

    return TextPickupResponse(
        delivery_id=row.id,
        content=row.content.decode("utf-8"),
        content_sha256=row.content_sha256,
        consumed_at=consumed_at,
    )


# ---------------- 撤回 ----------------


@app.post(
    "/api/v1/revoke/{token}",
    response_model=RevokeResponse,
    tags=["deliveries"],
    summary="发送者撤回投递（凭创建时返回的令牌）",
    responses={
        200: {"description": "撤回成功，或此前已撤回（幂等）"},
        409: {"model": DenyResponse, "description": "已被取件，无法撤回"},
        410: {"model": DenyResponse, "description": "已过期"},
        404: {"model": DenyResponse, "description": "令牌不存在"},
    },
)
async def revoke(
    token: str,
    request: Request,
    store: DeliveryStore = Depends(get_store),
    cache: DenyCache = Depends(get_cache),
    cfg: Settings = Depends(get_settings),
):
    token_h = hash_token(token)

    if flag := await _fast_flag(cache, token_h):
        delivery_id = await _delivery_id_by_hash(store.session, token_h)
        await _audit(
            store,
            action="revoke",
            result=flag,
            request=request,
            delivery_id=delivery_id,
            token_hash=token_h,
        )
        await store.session.commit()
        if flag == REVOKED:
            return RevokeResponse(result="already_revoked", delivery_id=delivery_id)
        # consumed / expired / unknown 统一返回带 result 的 JSON 错误体
        return _deny(flag)

    won, state, row = await store.revoke(token_h)
    delivery_id = getattr(row, "id", None)

    if won:
        await _audit(
            store,
            action="revoke",
            result=REVOKED,
            request=request,
            delivery_id=delivery_id,
            token_hash=token_h,
        )
        await store.session.commit()
        await _remember_terminal(cache, token_h, REVOKED, cfg)
        return RevokeResponse(
            result=REVOKED,
            delivery_id=delivery_id,
            revoked_at=ensure_utc(row.revoked_at),
        )

    # 未撤回成功：记录与终态一致的审计结果，给出明确响应
    await _audit(
        store,
        action="revoke",
        result=state,
        request=request,
        delivery_id=delivery_id,
        token_hash=token_h,
    )
    await store.session.commit()
    if state != UNKNOWN:
        await _remember_terminal(cache, token_h, state, cfg)

    if state == CONSUMED or state == EXPIRED:
        return _deny(state, http_status=status.HTTP_410_GONE)
    return _deny(UNKNOWN)


# ---------------- 审计：哈希链导出 / 校验 ----------------


def _validate_range(start, end) -> None:
    if start is not None and end is not None and start >= end:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start 必须早于 end（时间范围为左闭右开）",
        )


@app.get(
    "/api/v1/audit/export",
    tags=["audit"],
    summary="按时间范围导出审计链记录（NDJSON，只读）",
    responses={
        200: {
            "description": (
                "每行一条链记录（application/x-ndjson）。响应头返回起止链哈希与"
                "记录数：X-Chain-Start-Hash / X-Chain-End-Hash / "
                "X-Chain-Record-Count / X-Chain-Genesis-Hash。"
            )
        },
        422: {"description": "时间范围非法"},
    },
)
async def export_audit(
    request: Request,
    start: datetime | None = Query(
        default=None, description="起始时间（含），ISO-8601，例如 2026-09-21T00:00:00Z"
    ),
    end: datetime | None = Query(
        default=None, description="结束时间（不含），ISO-8601"
    ),
):
    """流式导出时间范围内的审计链记录。

    - 只读：PostgreSQL 上以 READ ONLY + REPEATABLE READ 事务读取，
      计数/边界/流内容来自同一快照，且驱动层拒绝任何写操作；
    - 仅含审计字段与链哈希，**绝不包含投递明文内容**。
    """
    _validate_range(start, end)
    db: Database = request.app.state.db

    # 独立 session：其生命周期跨越流式响应（在生成器结束时关闭）
    session_cm = db.session_factory()
    session = await session_cm.__aenter__()
    try:
        conn = await session.connection()
        if conn.dialect.name == "postgresql":
            # 整个导出共享同一快照，且驱动层强制只读
            await conn.exec_driver_sql(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )

        audit_store = DeliveryStore(session)
        count, first, last = await audit_store.audit_range_meta(start=start, end=end)

        async def _stream():
            try:
                async for entry in audit_store.iter_audit_range(start=start, end=end):
                    yield dumps_ndjson(entry)
            finally:
                await session_cm.__aexit__(None, None, None)

        headers = {
            "Content-Type": "application/x-ndjson; charset=utf-8",
            "Content-Disposition": 'attachment; filename="audit-export.ndjson"',
            "X-Chain-Genesis-Hash": GENESIS_HASH,
            "X-Chain-Start-Hash": first.entry_hash if first else "",
            "X-Chain-End-Hash": last.entry_hash if last else "",
            "X-Chain-Record-Count": str(count),
        }
        return StreamingResponse(_stream(), status_code=200, headers=headers)
    except BaseException:
        await session_cm.__aexit__(None, None, None)
        raise


@app.get(
    "/api/v1/audit/verify",
    response_model=AuditVerifyResponse,
    tags=["audit"],
    summary="校验库内审计链完整性（缺行/乱序/重复/改写/断裂）",
)
async def verify_audit_db(
    start: datetime | None = Query(default=None, description="起始时间（含），ISO-8601"),
    end: datetime | None = Query(default=None, description="结束时间（不含），ISO-8601"),
    session: AsyncSession = Depends(get_db),
) -> AuditVerifyResponse:
    """全链（不带时间参数）或时间范围片段校验，返回第一处错误。

    全链校验从创世哈希锚定；片段校验自动以库中该片段首条的前一条记录
    作为链锚。只读，不产生新审计记录。
    """
    _validate_range(start, end)
    store = DeliveryStore(session)
    entries = [e async for e in store.iter_audit_range(start=start, end=end)]

    if not entries:
        return AuditVerifyResponse(ok=True)

    if start is None and end is None:
        expected_seq, anchor = 1, GENESIS_HASH
    else:
        expected_seq = entries[0].seq
        anchor = await store.entry_hash_before(expected_seq)

    report = verify_chain(entries, expected_seq=expected_seq, anchor_hash=anchor)
    return AuditVerifyResponse(**report.__dict__)


@app.post(
    "/api/v1/audit/verify",
    response_model=AuditVerifyResponse,
    tags=["audit"],
    summary="校验一份导出的 NDJSON 审计链（上传内容本身不入库）",
    responses={400: {"description": "NDJSON 格式非法"}, 413: {"description": "上传过大"}},
)
async def verify_audit_upload(
    request: Request,
    anchor_hash: str | None = Query(
        default=None,
        description="首条记录前一条的链哈希；首条为序号 1 时自动使用创世哈希",
    ),
) -> AuditVerifyResponse:
    """上传导出的 NDJSON 内容，按其 *行顺序* 校验，可检出乱序。

    与 GET 版的区别：GET 总是按库内 seq 排序，无法发现顺序颠倒；
    本接口按提交的行顺序逐行校验，因此能检出导出/传输过程中的乱序。
    """
    import json

    raw = await request.body()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="校验上传内容超过 10 MiB 上限",
        )

    entries = []
    try:
        text_body = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="请求体不是合法 UTF-8 文本",
        ) from exc

    for position, line in enumerate(text_body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"第 {position} 行不是合法 JSON：{exc.msg}",
            ) from exc
        try:
            entries.append(ChainEntry.from_dict(obj, position=position))
        except ChainFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    if not entries:
        return AuditVerifyResponse(ok=True)

    report = verify_chain(entries, anchor_hash=anchor_hash)
    return AuditVerifyResponse(**report.__dict__)


# ---------------- 健康检查 ----------------


@app.get("/health", response_model=HealthResponse, tags=["meta"], summary="健康检查")
async def health(cache: DenyCache = Depends(get_cache)) -> HealthResponse:
    db_state = redis_state = "ok"
    try:
        await app.state.db.ping()
    except Exception:  # noqa: BLE001
        db_state = "error"
    try:
        await cache.ping()
    except Exception:  # noqa: BLE001
        redis_state = "error"
    overall = "ok" if db_state == "ok" and redis_state == "ok" else "degraded"
    code = 200 if overall == "ok" else 503
    return JSONResponse(
        status_code=code,
        content=HealthResponse(
            status=overall, database=db_state, redis=redis_state
        ).model_dump(),
    )


@app.get("/", tags=["meta"], summary="服务信息")
async def root() -> dict:
    return {
        "service": "one-time-dropbox",
        "docs": "/docs",
        "endpoints": [
            "POST /api/v1/deliveries",
            "POST /api/v1/deliveries/file",
            "POST /api/v1/pickup/{token}",
            "POST /api/v1/revoke/{token}",
            "GET  /api/v1/audit/export",
            "GET  /api/v1/audit/verify",
            "POST /api/v1/audit/verify",
            "GET  /health",
        ],
    }
