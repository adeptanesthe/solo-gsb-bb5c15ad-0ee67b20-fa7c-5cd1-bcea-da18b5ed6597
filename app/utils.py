"""与框架无关的小工具：时间、令牌、哈希、HTTP 头处理。"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import Request


def utcnow() -> datetime:
    """带时区的当前 UTC 时间（唯一可信时钟）。"""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | None) -> datetime | None:
    """部分驱动（如 SQLite）会返回 naive datetime，统一按 UTC 解释。"""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def new_token() -> tuple[str, str]:
    """生成取件令牌及其 SHA-256 哈希。

    库中只存哈希：即使数据库泄露，也无法凭哈希反推出取件地址。
    返回 (明文令牌, 哈希)。
    """
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def client_ip(request: Request) -> str | None:
    # 反向代理后的真实对端（compose 直连场景下回退到 request.client）
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64] or None
    return request.client.host if request.client else None


def content_disposition(filename: str) -> str:
    """构造同时兼容 ASCII 回退与 UTF-8 文件名的 Content-Disposition。"""
    safe_ascii = filename.encode("ascii", "ignore").decode("ascii") or "download.bin"
    return f"attachment; filename=\"{safe_ascii}\"; filename*=UTF-8''{quote(filename)}"
