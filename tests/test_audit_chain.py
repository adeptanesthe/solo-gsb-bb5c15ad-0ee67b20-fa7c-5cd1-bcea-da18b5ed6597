"""审计哈希链测试：入链、导出、校验、五类篡改检测、并发票据。"""

from __future__ import annotations

import asyncio
import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update

from app.audit_chain import (
    GENESIS_HASH,
    ChainEntry,
    canonical_event,
    event_digest_for,
    verify_chain,
)
from app.models import AuditChainState, AuditLog, Delivery
from app.utils import utcnow

pytestmark = pytest.mark.asyncio


async def _create_text(client: AsyncClient, text: str = "秘密内容", ttl: int = 3600) -> dict:
    resp = await client.post("/api/v1/deliveries", json={"text": text, "ttl_seconds": ttl})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _all_audit(session) -> list:
    return (
        (await session.execute(select(AuditLog).order_by(AuditLog.seq.asc())))
        .scalars()
        .all()
    )


# ---------------- 基本入链 ----------------


async def test_every_audit_row_is_chained(client, db):
    data = await _create_text(client, text="入链审计")
    token = data["token"]
    await client.post(f"/api/v1/pickup/{token}")
    await client.post(f"/api/v1/pickup/{token}")  # consumed
    await client.post("/api/v1/pickup/not-a-token")  # unknown 失败请求

    async with db.session_factory() as session:
        rows = await _all_audit(session)
        assert len(rows) == 4
        prev = GENESIS_HASH
        for row in rows:
            assert row.seq is not None
            assert row.event_digest and len(row.event_digest) == 64
            assert row.prev_hash == prev
            assert row.entry_hash and len(row.entry_hash) == 64

            recomputed = event_digest_for(
                seq=row.seq,
                created_at=row.created_at,
                action=row.action,
                result=row.result,
                delivery_id=row.delivery_id,
                token_hash=row.token_hash,
                client_ip=row.client_ip,
                user_agent=row.user_agent,
                detail=row.detail,
            )
            assert recomputed == row.event_digest
            prev = row.entry_hash

        state = await session.get(AuditChainState, 1)
        assert state.last_seq == len(rows)
        assert state.last_hash == rows[-1].entry_hash


async def test_unknown_failure_requests_are_chained(client, db):
    """未知令牌等失败请求也必须入链。"""
    await client.post("/api/v1/pickup/totally-unknown")
    await client.post("/api/v1/revoke/totally-unknown")

    async with db.session_factory() as session:
        rows = (
            await session.execute(
                select(AuditLog).where(AuditLog.result == "unknown")
            )
        ).scalars().all()
        assert len(rows) == 2
        assert all(r.seq is not None for r in rows)
        assert {r.action for r in rows} == {"pickup", "revoke"}


async def test_chain_is_deterministic_canonical():
    """规范化摘要对同一事件稳定，对不同字段敏感。"""
    now = utcnow()
    common = dict(
        seq=3,
        created_at=now,
        action="pickup",
        result="success",
        delivery_id=None,
        token_hash="a" * 64,
        client_ip="127.0.0.1",
        user_agent="ua",
        detail={"size": 10, "kind": "text"},
    )
    d1 = canonical_event(**common)
    d2 = canonical_event(**common)
    assert d1 == d2  # 两次计算字节一致

    changed = dict(common, result="consumed")
    assert canonical_event(**changed) != d1


# ---------------- 导出 ----------------


async def test_export_ndjson_with_chain_headers(client, db):
    await _create_text(client, text="导出我")

    resp = await client.get("/api/v1/audit/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    count = int(resp.headers["x-chain-record-count"])
    assert count >= 1
    assert resp.headers["x-chain-genesis-hash"] == GENESIS_HASH

    lines = [json.loads(line) for line in resp.text.splitlines() if line.strip()]
    assert len(lines) == count
    assert [ln["seq"] for ln in lines] == list(range(1, count + 1))
    assert lines[0]["prev_hash"] == GENESIS_HASH
    assert resp.headers["x-chain-start-hash"] == lines[0]["entry_hash"]
    assert resp.headers["x-chain-end-hash"] == lines[-1]["entry_hash"]

    # 导出绝不包含明文投递内容
    assert "导出我" not in resp.text
    assert "content" not in lines[0]


async def test_export_range_is_left_closed_right_open(client):
    first = await _create_text(client, ttl=3600)
    # 第一条审计时间附近做粗粒度边界查询，验证左闭右开不报错且计数一致
    resp_all = await client.get("/api/v1/audit/export")
    total = int(resp_all.headers["x-chain-record-count"])

    before = await client.get(
        "/api/v1/audit/export",
        params={"end": "2000-01-01T00:00:00Z"},
    )
    assert before.status_code == 200
    assert before.headers["x-chain-record-count"] == "0"
    assert before.headers["x-chain-start-hash"] == ""
    assert before.headers["x-chain-end-hash"] == ""

    future = await client.get(
        "/api/v1/audit/export",
        params={"start": "2099-01-01T00:00:00Z"},
    )
    assert future.headers["x-chain-record-count"] == "0"

    until_now = await client.get(
        "/api/v1/audit/export",
        params={"end": "2099-01-01T00:00:00Z"},
    )
    assert int(until_now.headers["x-chain-record-count"]) == total

    await client.post(f"/api/v1/pickup/{first['token']}")
    after = await client.get(
        "/api/v1/audit/export",
        params={"start": "2099-01-01T00:00:00Z"},
    )
    assert after.headers["x-chain-record-count"] == "0"


async def test_export_rejects_inverted_range(client):
    resp = await client.get(
        "/api/v1/audit/export",
        params={
            "start": "2026-09-21T10:00:00Z",
            "end": "2026-09-21T09:00:00Z",
        },
    )
    assert resp.status_code == 422


# ---------------- 校验接口：干净链 ----------------


async def test_verify_ok_on_fresh_chain(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/not-real")

    resp = await client.get("/api/v1/audit/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 2
    assert body["first_seq"] == 1
    assert body["last_seq"] == 2
    assert body["error"] is None
    assert len(body["start_hash"]) == 64
    assert len(body["end_hash"]) == 64


async def test_verify_empty_chain(client):
    resp = await client.get("/api/v1/audit/verify")
    assert resp.json()["ok"] is True
    assert resp.json()["count"] == 0


# ---------------- 五类篡改：第一处错误 ----------------


async def _export_entries(client) -> list[dict]:
    resp = await client.get("/api/v1/audit/export")
    return [json.loads(line) for line in resp.text.splitlines() if line.strip()]


def _verify_dicts(entries: list[dict], anchor=None):
    objs = [ChainEntry.from_dict(e, position=i + 1) for i, e in enumerate(entries)]
    return verify_chain(objs, anchor_hash=anchor)


async def test_verify_detects_missing_row(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    await client.post("/api/v1/pickup/nope-2")
    entries = await _export_entries(client)
    assert len(entries) >= 3

    # 删除中间一行（seq 2）：校验在 seq 3 处发现缺少 seq 2
    tampered = [e for e in entries if e["seq"] != 2]
    report = _verify_dicts(tampered)
    assert report.ok is False
    assert report.error == "missing"
    assert report.seq == 2
    assert report.position == 2


async def test_verify_detects_out_of_order(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    await client.post("/api/v1/pickup/nope-2")
    entries = await _export_entries(client)

    # 交换第 2、3 行的位置（按提交顺序校验时发现回退）
    entries[1], entries[2] = entries[2], entries[1]
    report = _verify_dicts(entries)
    assert report.ok is False
    assert report.error == "out_of_order"
    assert report.seq == entries[1]["seq"]
    assert report.position == 2

    # POST 校验接口按上传顺序判定，同样能发现乱序
    resp = await client.post(
        "/api/v1/audit/verify",
        content="\n".join(json.dumps(e) for e in entries),
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    assert resp.json()["error"] == "out_of_order"


async def test_verify_detects_duplicate(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    entries = await _export_entries(client)

    dup = entries + [dict(entries[0])]
    report = _verify_dicts(dup)
    assert report.ok is False
    assert report.error == "duplicate"
    assert report.seq == entries[0]["seq"]
    assert report.position == len(dup)


async def test_verify_detects_field_tampering(client):
    await _create_text(client, text="字段改写测试")
    entries = await _export_entries(client)

    # 改写业务字段但保留原哈希
    entries[0]["result"] = "consumed"
    report = _verify_dicts(entries)
    assert report.ok is False
    assert report.error == "field_tampered"
    assert report.seq == 1
    assert report.position == 1

    # 改 detail 同样能发现
    entries2 = await _export_entries(client)
    entries2[0]["detail"] = {"kind": "file", "size": 99999}
    report2 = _verify_dicts(entries2)
    assert report2.error == "field_tampered"


async def test_verify_detects_chain_break(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    entries = await _export_entries(client)

    # 直接改写某行的链哈希（摘要不动，链哈希失配先报）
    entries[1]["entry_hash"] = "f" * 64
    report = _verify_dicts(entries)
    assert report.ok is False
    assert report.error == "chain_break"
    assert report.seq == 2

    # 篡改摘要（既非原摘要也非合法链哈希）→ 字段改写先报
    entries2 = await _export_entries(client)
    entries2[0]["event_digest"] = "0" * 64
    report2 = _verify_dicts(entries2)
    assert report2.error == "field_tampered"


async def test_verify_endpoint_recomputes_from_database(client, db):
    """绕过应用直接改库（模拟 DBA 落盘改写）也能被发现。"""
    await _create_text(client, text="直接改库")
    async with db.session_factory() as session:
        row = await session.scalar(select(AuditLog).where(AuditLog.seq == 1))
        row.result = "revoked"  # 只改字段，不重算哈希
        await session.commit()

    resp = await client.get("/api/v1/audit/verify")
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "field_tampered"
    assert body["seq"] == 1


async def test_verify_endpoint_detects_deleted_row_in_db(client, db):
    """直接从库里物理删除一行：GET 校验按 seq 顺序发现缺行并指出位置。"""
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    await client.post("/api/v1/pickup/nope-2")

    async with db.session_factory() as session:
        from sqlalchemy import delete

        await session.execute(delete(AuditLog).where(AuditLog.seq == 2))
        await session.commit()

    resp = await client.get("/api/v1/audit/verify")
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "missing"
    assert body["seq"] == 2
    assert body["position"] == 2


async def test_verify_endpoint_detects_broken_hash_in_db(client, db):
    """直接改库里某行的链哈希：GET 校验发现链断裂。"""
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")

    async with db.session_factory() as session:
        row = await session.scalar(select(AuditLog).where(AuditLog.seq == 2))
        row.entry_hash = "a" * 64
        await session.commit()

    resp = await client.get("/api/v1/audit/verify")
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "chain_break"
    assert body["seq"] == 2


async def test_post_verify_rejects_bad_ndjson(client):
    resp = await client.post(
        "/api/v1/audit/verify",
        content='{"seq": 1, oops}\n',
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 400

    resp2 = await client.post(
        "/api/v1/audit/verify",
        content=json.dumps({"seq": "x", "created_at": "bad", "action": "a",
                           "result": "b", "event_digest": "c",
                           "prev_hash": "d", "entry_hash": "e"}),
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp2.status_code == 400


async def test_post_verify_empty_body_is_ok(client):
    resp = await client.post(
        "/api/v1/audit/verify",
        content="",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ---------------- 范围校验的锚定 ----------------


async def test_verify_range_uses_previous_row_as_anchor(client):
    await _create_text(client)
    await client.post("/api/v1/pickup/nope-1")
    await client.post("/api/v1/pickup/nope-2")

    # 全时间范围（覆盖全部记录）应从创世锚定并通过
    resp = await client.get(
        "/api/v1/audit/verify",
        params={"start": "2000-01-01T00:00:00Z", "end": "2099-01-01T00:00:00Z"},
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 3


# ---------------- 并发：链序由数据库裁决 ----------------


async def test_concurrent_writes_preserve_total_order(client, db):
    n = 40

    async def write_audit(i: int):
        # 未知令牌取件：每个请求都失败入链，互不相关、可完全并发
        async with AsyncClient(
            transport=client._transport, base_url="http://test"
        ) as ac:
            return await ac.post(f"/api/v1/pickup/concurrent-token-{i}")

    results = await asyncio.gather(*[write_audit(i) for i in range(n)])
    assert all(r.status_code == 404 for r in results)

    async with db.session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog.seq).order_by(AuditLog.seq.asc())))
            .scalars()
            .all()
        )
        # 序号严格 1..N 连续：无缺号、无重复、无跳号
        assert rows == list(range(1, n + 1))

        state = await session.get(AuditChainState, 1)
        assert state.last_seq == n

        # 全部记录相互勾连，顺序回放即通过
        full = (
            (await session.execute(select(AuditLog).order_by(AuditLog.seq.asc())))
            .scalars()
            .all()
        )
        entries = [ChainEntry.from_row(r) for r in full]
        report = verify_chain(entries, expected_seq=1, anchor_hash=GENESIS_HASH)
        assert report.ok is True


async def test_concurrent_pickup_audit_still_contiguous(client, db):
    """50 路并发取件（既有赢家也有 consumed 失败）后，链仍完整连续。"""
    data = await _create_text(client, text="并发链校验")
    token = data["token"]

    async def pick():
        async with AsyncClient(
            transport=client._transport, base_url="http://test"
        ) as ac:
            return await ac.post(f"/api/v1/pickup/{token}")

    await asyncio.gather(*[pick() for _ in range(50)])

    resp = await client.get("/api/v1/audit/verify")
    assert resp.json()["ok"] is True
    assert resp.json()["count"] == 51  # 1 create + 50 pickup


async def test_lost_conditional_update_retries_and_recovers(db):
    """模拟链游标竞态失配（他人已把游标推进，本事务读到过期快照）：

    第一次尝试基于过期游标计算 -> 条件 UPDATE 未命中 -> 回滚并重读新
    游标重试 -> 成功。最终追加的记录序号连续、链完整。
    """
    from app.store import DeliveryStore

    async with db.session_factory() as session:
        # 先制造两条已入链记录，使真实游标停在 seq=2
        store = DeliveryStore(session)
        await store.write_audit(action="pickup", result="unknown", token_hash="b" * 64)
        await store.write_audit(action="pickup", result="unknown", token_hash="c" * 64)

        class StaleOnceStore(DeliveryStore):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.calls = 0

            async def _load_chain_state(self):
                self.calls += 1
                if self.calls == 1:
                    # 过期快照：真实 seq=2，却读到 0/创世
                    return 0, GENESIS_HASH
                return await super()._load_chain_state()

        stale_store = StaleOnceStore(session)
        entry = await stale_store.write_audit(
            action="revoke", result="unknown", token_hash="d" * 64
        )
        assert stale_store.calls == 2  # 第一次竞态失配，第二次成功
        assert entry.seq == 3
        assert entry.prev_hash != GENESIS_HASH

        state = await session.get(AuditChainState, 1)
        assert state.last_seq == 3
        assert state.last_hash == entry.entry_hash

        # 链记录 1..3 连续无缺
        seqs = (
            (await session.execute(select(AuditLog.seq).order_by(AuditLog.seq.asc())))
            .scalars()
            .all()
        )
        assert seqs == [1, 2, 3]


async def test_write_audit_is_atomic_with_delivery_create(client, db):
    """新建投递与其审计记录在同一事务提交：要么都在，要么都不在。"""
    data = await _create_text(client, text="原子性")

    async with db.session_factory() as session:
        delivery = await session.get(Delivery, data["delivery_id"])
        assert delivery is not None
        rows = (
            await session.execute(
                select(AuditLog).where(AuditLog.delivery_id == data["delivery_id"])
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].seq is not None
        assert rows[0].entry_hash is not None
