"""核心行为测试：一次性消费、并发原子性、撤回、过期、文件、审计。"""

from __future__ import annotations

import asyncio

import pytest
from httpx import AsyncClient

from app.models import AuditLog, Delivery
from app.store import CONSUMED, DeliveryStore

pytestmark = pytest.mark.asyncio


async def _create_text(client: AsyncClient, text: str = "秘密内容", ttl: int = 3600) -> dict:
    resp = await client.post("/api/v1/deliveries", json={"text": text, "ttl_seconds": ttl})
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------- 创建 ----------------


async def test_create_text_returns_token_once(client: AsyncClient):
    data = await _create_text(client)
    assert data["result"] if "result" in data else True
    assert len(data["token"]) >= 40
    assert data["url"].endswith(f"/api/v1/pickup/{data['token']}")
    assert data["delivery_id"]
    assert data["expires_at"]


async def test_create_validates_ttl(client: AsyncClient):
    resp = await client.post(
        "/api/v1/deliveries", json={"text": "x", "ttl_seconds": 99999999}
    )
    assert resp.status_code == 422


async def test_create_rejects_oversize(client: AsyncClient):
    resp = await client.post(
        "/api/v1/deliveries", json={"text": "x" * 2048, "ttl_seconds": 60}
    )
    # 2048 字节 UTF-8 > 1024 上限
    assert resp.status_code == 413


# ---------------- 取件：只能成功一次 ----------------


async def test_pickup_succeeds_once_then_consumed(client: AsyncClient):
    data = await _create_text(client, text="读一次就消失")
    token = data["token"]

    first = await client.post(f"/api/v1/pickup/{token}")
    assert first.status_code == 200
    body = first.json()
    assert body["result"] == "success"
    assert body["content"] == "读一次就消失"
    assert body["content_sha256"]

    second = await client.post(f"/api/v1/pickup/{token}")
    assert second.status_code == 410
    assert second.json()["result"] == "consumed"

    third = await client.post(f"/api/v1/pickup/{token}")
    assert third.status_code == 410
    assert third.json()["result"] == "consumed"


async def test_pickup_unknown_token_is_404(client: AsyncClient):
    resp = await client.post("/api/v1/pickup/not-a-real-token")
    assert resp.status_code == 404
    assert resp.json()["result"] == "unknown"


async def test_consumed_flag_cached_in_redis(client: AsyncClient, cache, db):
    data = await _create_text(client)
    await client.post(f"/api/v1/pickup/{data['token']}")

    from app.utils import hash_token

    flag = await cache.get_flag(hash_token(data["token"]))
    assert flag == "consumed"


# ---------------- 并发：原子消费，唯一赢家 ----------------


async def test_concurrent_pickup_single_winner(client: AsyncClient, db):
    data = await _create_text(client, text="并发争抢内容")
    token = data["token"]

    async def pick():
        async with AsyncClient(transport=client._transport, base_url="http://test") as ac:
            return await ac.post(f"/api/v1/pickup/{token}")

    results = await asyncio.gather(*[pick() for _ in range(50)])
    success = [r for r in results if r.status_code == 200]
    gone = [r for r in results if r.status_code == 410]

    assert len(success) == 1
    assert success[0].json()["content"] == "并发争抢内容"
    assert len(gone) == 49
    assert all(r.json()["result"] == "consumed" for r in gone)

    # 数据库终态唯一且为 consumed
    async with db.session_factory() as session:
        row = await session.get(Delivery, data["delivery_id"])
        assert row.status == CONSUMED
        assert row.consumed_at is not None


# ---------------- 撤回 ----------------


async def test_revoke_blocks_pickup(client: AsyncClient):
    data = await _create_text(client)
    token = data["token"]

    revoked = await client.post(f"/api/v1/revoke/{token}")
    assert revoked.status_code == 200
    assert revoked.json()["result"] == "revoked"

    pickup = await client.post(f"/api/v1/pickup/{token}")
    assert pickup.status_code == 409
    assert pickup.json()["result"] == "revoked"


async def test_revoke_after_consume_is_410(client: AsyncClient):
    data = await _create_text(client)
    token = data["token"]
    await client.post(f"/api/v1/pickup/{token}")

    resp = await client.post(f"/api/v1/revoke/{token}")
    assert resp.status_code == 410
    assert resp.json()["result"] == "consumed"


async def test_concurrent_revoke_and_pickup_is_consistent(client: AsyncClient):
    """消费与撤回并发：结果必须互斥，内容要么被取走，要么撤回成功。"""
    data = await _create_text(client, text="先到先得")
    token = data["token"]

    async def post(path):
        async with AsyncClient(transport=client._transport, base_url="http://test") as ac:
            return await ac.post(path)

    pick_task = post(f"/api/v1/pickup/{token}")
    revoke_task = post(f"/api/v1/revoke/{token}")
    pickup_resp, revoke_resp = await asyncio.gather(pick_task, revoke_task)

    outcomes = {pickup_resp.status_code, revoke_resp.status_code}
    # 两种互斥结局之一：
    #  A. 取件成功(200) 且撤回失败(410 consumed)
    #  B. 撤回成功(200) 且取件被拒(409 revoked)
    if pickup_resp.status_code == 200:
        assert pickup_resp.json()["content"] == "先到先得"
        assert revoke_resp.status_code == 410
        assert revoke_resp.json()["result"] == "consumed"
    else:
        assert pickup_resp.status_code == 409
        assert pickup_resp.json()["result"] == "revoked"
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["result"] == "revoked"
    assert outcomes  # 仅用于保持可读性


# ---------------- 过期 ----------------


async def test_expired_delivery_is_lazily_marked(client: AsyncClient, db):
    data = await _create_text(client, ttl=1)
    token = data["token"]

    # 直接在数据库里把到期时间挪到过去，模拟已过期
    async with db.session_factory() as session:
        from datetime import datetime, timedelta, timezone

        row = await session.get(Delivery, data["delivery_id"])
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        await session.commit()

    resp = await client.post(f"/api/v1/pickup/{token}")
    assert resp.status_code == 410
    assert resp.json()["result"] == "expired"

    async with db.session_factory() as session:
        row = await session.get(Delivery, data["delivery_id"])
        assert row.status == "expired"
        assert row.expired_at is not None


async def test_sweep_marks_expired(db):
    from datetime import datetime, timedelta, timezone

    async with db.session_factory() as session:
        from app.utils import new_token, sha256_hex

        _token, th = new_token()
        await DeliveryStore(session).create(
            token_hash=th,
            kind="text",
            content=b"old",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            content_sha256=sha256_hex(b"old"),
        )
        await session.commit()
        count = await DeliveryStore(session).sweep_expired()
        assert count == 1


# ---------------- 文件投递 ----------------


async def test_file_roundtrip_once(client: AsyncClient):
    payload = b"\x89PNG fake-binary" * 10
    files = {"file": ("照片.png", payload, "image/png")}
    created = await client.post(
        "/api/v1/deliveries/file", data={"ttl_seconds": "600"}, files=files
    )
    assert created.status_code == 201, created.text
    token = created.json()["token"]

    first = await client.post(f"/api/v1/pickup/{token}")
    assert first.status_code == 200
    assert first.content == payload
    assert first.headers["x-drop-result"] == "success"
    assert "attachment" in first.headers["content-disposition"]
    assert "%E7%85%A7%E7%89%87" in first.headers["content-disposition"]
    assert first.headers["x-content-sha256"]

    second = await client.post(f"/api/v1/pickup/{token}")
    assert second.status_code == 410
    assert second.json()["result"] == "consumed"


# ---------------- 审计 ----------------


async def test_minimal_audit_trail(client: AsyncClient, db):
    data = await _create_text(client, text="审计我")
    token = data["token"]

    await client.post(f"/api/v1/pickup/{token}")
    await client.post(f"/api/v1/pickup/{token}")  # consumed
    await client.post("/api/v1/pickup/garbage")  # unknown

    async with db.session_factory() as session:
        from sqlalchemy import select

        rows = (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.delivery_id == data["delivery_id"])
                .order_by(AuditLog.created_at)
            )
        ).scalars().all()

        actions = [(r.action, r.result) for r in rows]
        assert ("create", "success") in actions
        assert ("pickup", "success") in actions
        assert ("pickup", "consumed") in actions
        for r in rows:
            assert r.created_at is not None

        # 未知令牌的尝试也有留痕
        unknown = (
            await session.execute(
                select(AuditLog).where(AuditLog.result == "unknown")
            )
        ).scalars().all()
        assert len(unknown) == 1
        assert unknown[0].delivery_id is None
        assert unknown[0].token_hash
