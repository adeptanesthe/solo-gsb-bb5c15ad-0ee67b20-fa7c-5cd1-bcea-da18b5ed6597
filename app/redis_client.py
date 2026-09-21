"""Redis 客户端封装。

Redis 在这里只做两件事，且永远不存放明文内容：
1. 终态（consumed/revoked/expired）标记：对已知失效令牌快速拒绝，保护数据库；
2. TTL 自动清理标记，不持久化任何敏感数据。

原子消费的正确性只由 PostgreSQL 的单条条件 UPDATE 保证，
Redis 宕机或标记丢失不影响正确性（会回落到数据库判定）。
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis

from .config import settings

_FLAG_PREFIX = "drop:flag:"

# Lua：仅当没有标记时写入，保证并发下终态不会被互相覆盖
_SET_IF_ABSENT = """
local v = redis.call('GET', KEYS[1])
if v == false then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return 1
end
return 0
"""


class DenyCache:
    def __init__(self, client: aioredis.Redis | Any) -> None:
        self.redis = client

    @staticmethod
    def _key(token_hash: str) -> str:
        return f"{_FLAG_PREFIX}{token_hash}"

    async def get_flag(self, token_hash: str) -> str | None:
        value = await self.redis.get(self._key(token_hash))
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else str(value)

    async def set_flag_if_absent(self, token_hash: str, flag: str, ttl_seconds: int) -> bool:
        """原子地“仅在不存在时设置”。返回是否设置成功。"""
        result = await self.redis.eval(
            _SET_IF_ABSENT, 1, self._key(token_hash), flag, int(ttl_seconds * 1000)
        )
        return int(result) == 1

    async def set_flag(self, token_hash: str, flag: str, ttl_seconds: int) -> None:
        await self.redis.set(self._key(token_hash), flag, ex=ttl_seconds)

    async def ping(self) -> None:
        await self.redis.ping()

    async def close(self) -> None:
        await self.redis.aclose()


def create_redis(url: str | None = None) -> DenyCache:
    client = aioredis.from_url(
        url or settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
        socket_connect_timeout=3,
        socket_timeout=3,
    )
    return DenyCache(client)
