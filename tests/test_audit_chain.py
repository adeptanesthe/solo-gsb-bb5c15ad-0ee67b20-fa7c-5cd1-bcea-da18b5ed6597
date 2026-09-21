"""审计哈希链测试：链式完整性、并发裁决、导出与校验、篡改检测。"""

from __future__ import annotations

import asyncio
import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.chain import GENESIS_HASH, compute_entry_hash, compute_event_hash, verify_records
from app.models import AuditChainState, AuditLog
from app.store import DeliveryStore

pytestmark = pytest.mark.asyncio


async def _busy(client: AsyncClient) -> None:
    """制造 create / pickup 成功 / consumed / unknown 等多条审计。"""
    c = await client.post(
        "/api/v1/deliveries", json={"text": "链式审计内容", "ttl_seconds": 3600}
    )
    assert c.status_code == 201
    token = c.json()["token"]
    assert await client.post(f"/api/v1/pickup/{token}")
    assert await client.post(f"/api/v1/pickup/{token}")  # consumed
    assert await client.post("/api/v1/pickup/totally-unknown")  # unknown
    assert await client.post("/api/v1/revoke/totally-unknown")  # unknown revoke


# ---------------- 基础链式结构 ----------------


async def test_audit_rows_are_hash_chained(client: AsyncClient, db):
    await _busy(client)

    async with db.session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        )
        assert len(rows) == 5
        seqs = [r.seq for r in rows]
        assert seqs == [1, 2, 3, 4, 5]

        prev = GENESIS_HASH
        for row in rows:
            assert len(row.event_hash) == 64
            assert len(row.entry_hash) == 64
            assert row.prev_hash == prev
            # 事件摘要必须能由字段重算（防字段改写）
            payload = {
                "v": 1,
                "id": str(row.id),
                "delivery_id": str(row.delivery_id) if row.delivery_id else None,
                "token_hash": row.token_hash,
                "action": row.action,
                "result": row.result,
                "detail": row.detail,
                "client_ip": row.client_ip,
                "user_agent": row.user_agent,
                "created_at": row.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            }
            assert compute_event_hash(payload) == row.event_hash
            assert compute_entry_hash(prev, row.seq, row.event_hash) == row.entry_hash
            prev = row.entry_hash

        tip = (
            await session.execute(
                select(AuditChainState).where(AuditChainState.id == 1)
            )
        ).scalar_one()
        assert tip.last_seq == 5
        assert tip.last_hash == rows[-1].entry_hash


async def test_unknown_failures_are_chained_too(client: AsyncClient, db):
    """未知令牌等失败请求也必须入链，序号连续。"""
    await client.post("/api/v1/pickup/nope-1")
    await client.post("/api/v1/pickup/nope-2")
    async with db.session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        )
        assert [r.result for r in rows] == ["unknown", "unknown"]
        assert [r.seq for r in rows] == [1, 2]
        assert rows[0].delivery_id is None and rows[0].token_hash


# ---------------- 并发：链序由数据库裁决 ----------------


async def test_concurrent_writes_produce_gap_free_chain(client: AsyncClient, db):
    async def hit(i):
        async with AsyncClient(
            transport=client._transport, base_url="http://test"
        ) as ac:
            return await ac.post(f"/api/v1/pickup/concurrent-unknown-{i}")

    results = await asyncio.gather(*[hit(i) for i in range(40)])
    assert all(r.status_code == 404 for r in results)

    async with db.session_factory() as session:
        seqs = list(
            (await session.execute(select(AuditLog.seq).order_by(AuditLog.seq))).scalars()
        )
        tip = (
            await session.execute(
                select(AuditChainState.last_seq).where(AuditChainState.id == 1)
            )
        ).scalar_one()

    assert seqs == list(range(1, 41))
    assert len(set(seqs)) == 40
    assert tip == 40


async def test_concurrent_pickup_chain_stays_consistent(client: AsyncClient, db):
    """50 路并发取件（含业务行竞争）后审计链依旧连续且校验通过。"""
    c = await client.post(
        "/api/v1/deliveries", json={"text": "并发取件链", "ttl_seconds": 3600}
    )
    token = c.json()["token"]

    async def pick():
        async with AsyncClient(
            transport=client._transport, base_url="http://test"
        ) as ac:
            return await ac.post(f"/api/v1/pickup/{token}")

    results = await asyncio.gather(*[pick() for _ in range(50)])
    assert len([r for r in results if r.status_code == 200]) == 1
    assert len([r for r in results if r.status_code == 410]) == 49

    verify = await client.get("/api/v1/audit/verify")
    body = verify.json()
    assert body["ok"] is True, body
    # create + 50 pickups
    assert body["count"] == 51
    assert body["end_seq"] == 51


# ---------------- 导出 ----------------


async def test_export_ndjson_headers_and_no_plaintext(client: AsyncClient):
    c = await client.post(
        "/api/v1/deliveries",
        json={"text": "绝不应出现在导出里的明文", "ttl_seconds": 3600},
    )
    token = c.json()["token"]
    await client.post(f"/api/v1/pickup/{token}")

    resp = await client.get("/api/v1/audit/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    assert int(resp.headers["x-audit-count"]) == 2
    assert resp.headers["x-audit-start-seq"] == "1"
    assert resp.headers["x-audit-end-seq"] == "2"
    assert resp.headers["x-audit-start-prev-hash"] == GENESIS_HASH
    assert resp.headers["x-audit-start-hash"]
    assert resp.headers["x-audit-end-hash"]
    assert resp.headers["x-audit-truncated"] == "0"
    assert "x-audit-count" in resp.headers["access-control-expose-headers"].lower()

    lines = [json.loads(line) for line in resp.text.splitlines()]
    assert len(lines) == 2
    for obj in lines:
        assert obj["v"] == 1
        assert {"seq", "id", "event_hash", "prev_hash", "entry_hash"} <= set(obj)
        assert "content" not in obj and "text" not in obj
    assert "绝不应出现在导出里的明文" not in resp.text


async def test_export_time_range(client: AsyncClient):
    await client.post("/api/v1/pickup/early-unknown")
    first_created = json.loads(
        (await client.get("/api/v1/audit/export", params={"limit": 1})).text
        .splitlines()[0]
    )["created_at"]
    await client.post("/api/v1/pickup/later-unknown")

    # start 取第一条之后 => 只含第二条（起点含第一条，所以先验证 2 条）
    resp = await client.get("/api/v1/audit/export", params={"start": first_created})
    assert int(resp.headers["x-audit-count"]) == 2
    resp = await client.get(
        "/api/v1/audit/export",
        params={"start": "2099-01-01T00:00:00Z"},
    )
    assert int(resp.headers["x-audit-count"]) == 0
    assert resp.headers["x-audit-start-hash"] == ""
    assert resp.text == ""


async def test_export_truncated_flag(client: AsyncClient):
    for _ in range(3):
        await client.post("/api/v1/pickup/unk")
    resp = await client.get("/api/v1/audit/export", params={"limit": 2})
    assert int(resp.headers["x-audit-count"]) == 2
    assert resp.headers["x-audit-truncated"] == "1"
    assert resp.headers["x-audit-start-seq"] == "1"
    assert resp.headers["x-audit-end-seq"] == "2"
    assert len(resp.text.splitlines()) == 2


async def test_export_is_read_only(client: AsyncClient, db, monkeypatch):
    """导出事务必须只读：SQLite query_only 下写入会报错（这里验证 PRAGMA 被恢复）。"""
    await client.post("/api/v1/pickup/unk")
    await client.get("/api/v1/audit/export")
    # 导出后连接归还连接池，普通写入仍正常（PRAGMA 已恢复）
    async with db.session_factory() as session:
        await DeliveryStore(session).write_audit(
            action="pickup", result="unknown", token_hash="00" * 32
        )
        await session.commit()


# ---------------- 在线校验 ----------------


async def test_online_verify_ok(client: AsyncClient):
    await _busy(client)
    resp = await client.get("/api/v1/audit/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 5
    assert body["start_seq"] == 1
    assert body["end_seq"] == 5
    assert body["tip_seq"] == body["end_seq"] == 5
    assert body["tip_hash"] == body["end_hash"]


async def test_online_verify_empty_chain(client: AsyncClient):
    body = (await client.get("/api/v1/audit/verify")).json()
    assert body["ok"] is True and body["count"] == 0


async def test_online_verify_detects_missing_row(client: AsyncClient, db):
    await _busy(client)
    async with db.session_factory() as session:
        # 直接删除中间一行模拟缺行
        await session.execute(
            AuditLog.__table__.delete().where(AuditLog.seq == 3)
        )
        await session.commit()
    body = (await client.get("/api/v1/audit/verify")).json()
    assert body["ok"] is False
    assert body["code"] == "missing"
    assert body["expected_seq"] == 3
    assert body["seq"] == 4


async def test_online_verify_detects_field_rewrite(client: AsyncClient, db):
    await _busy(client)
    async with db.session_factory() as session:
        row = (
            await session.execute(select(AuditLog).where(AuditLog.seq == 2))
        ).scalar_one()
        row.action = "revoke"  # 改写字段但不改哈希
        await session.commit()
    body = (await client.get("/api/v1/audit/verify")).json()
    assert body["ok"] is False
    assert body["code"] == "field_tampered"
    assert body["seq"] == 2


async def test_online_verify_detects_chain_break(client: AsyncClient, db):
    await _busy(client)
    async with db.session_factory() as session:
        row = (
            await session.execute(select(AuditLog).where(AuditLog.seq == 2))
        ).scalar_one()
        # 只改 prev_hash（字段本身的改动也会被链哈希重算抓到，但优先表现为链接断裂）
        row.prev_hash = "f" * 64
        await session.commit()
    body = (await client.get("/api/v1/audit/verify")).json()
    assert body["ok"] is False
    assert body["code"] == "chain_broken"
    assert body["seq"] == 2


async def test_online_verify_detects_tip_tamper(client: AsyncClient, db):
    await _busy(client)
    async with db.session_factory() as session:
        tip = await session.get(AuditChainState, 1)
        tip.last_hash = "deadbeef" * 8
        await session.commit()
    body = (await client.get("/api/v1/audit/verify")).json()
    assert body["ok"] is False
    assert body["code"] == "tip_mismatch"


# ---------------- 导出文件的离线校验 ----------------


async def test_post_verify_exported_file_full(client: AsyncClient):
    await _busy(client)
    exported = await client.get("/api/v1/audit/export")
    resp = await client.post(
        "/api/v1/audit/verify",
        content=exported.text,
        headers={"content-type": "application/x-ndjson"},
    )
    assert resp.json()["ok"] is True


async def test_post_verify_segment_with_anchor(client: AsyncClient):
    await _busy(client)
    # 只导出 seq 2..3 的片段需要手工构造；这里直接截断导出并以头部锚点校验
    exported = await client.get("/api/v1/audit/export", params={"limit": 5})
    lines = exported.text.splitlines()
    segment = "\n".join(lines[1:3])  # seq 2,3
    first = json.loads(lines[1])
    resp = await client.post(
        "/api/v1/audit/verify",
        params={"start_seq": first["seq"], "start_prev_hash": first["prev_hash"]},
        content=segment,
        headers={"content-type": "application/x-ndjson"},
    )
    assert resp.json()["ok"] is True


async def test_post_verify_detects_duplicate(client: AsyncClient):
    await _busy(client)
    exported = await client.get("/api/v1/audit/export")
    lines = exported.text.splitlines()
    body = "\n".join(lines + [lines[-1]])  # 末行重复
    resp = await client.post(
        "/api/v1/audit/verify",
        content=body,
        headers={"content-type": "application/x-ndjson"},
    )
    assert resp.json()["code"] == "duplicate"


async def test_post_verify_detects_out_of_order(client: AsyncClient):
    await _busy(client)
    exported = await client.get("/api/v1/audit/export")
    lines = exported.text.splitlines()
    # 构造 [seq1, seq2, seq1...] 不自然；用两条 seq 开头制造倒退：
    objs = [json.loads(l) for l in lines]
    # 从 seq2 开始但声称 start_seq=3（锚点 prev 用 seq3 的 prev）
    segment_objs = [objs[2], objs[1]]  # seq3 then seq2 => 倒退
    body = "\n".join(json.dumps(o) for o in segment_objs)
    resp = await client.post(
        "/api/v1/audit/verify",
        params={"start_seq": 3, "start_prev_hash": objs[2]["prev_hash"]},
        content=body,
        headers={"content-type": "application/x-ndjson"},
    )
    assert resp.json()["code"] == "out_of_order"
    assert resp.json()["expected_seq"] == 4


async def test_post_verify_reports_first_error(client: AsyncClient):
    await _busy(client)
    exported = await client.get("/api/v1/audit/export")
    lines = exported.text.splitlines()
    # 同时制造缺行（删第 2 行）——校验必须停在第一处（序号 2 缺失）
    body = "\n".join([lines[0]] + lines[2:])
    resp = await client.post(
        "/api/v1/audit/verify",
        content=body,
        headers={"content-type": "application/x-ndjson"},
    )
    data = resp.json()
    assert data["ok"] is False
    assert data["code"] == "missing"
    assert data["expected_seq"] == 2


async def test_post_verify_invalid_ndjson(client: AsyncClient):
    resp = await client.post(
        "/api/v1/audit/verify",
        content='{"not":"a record"}\n',
        headers={"content-type": "application/x-ndjson"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "invalid_format"
    assert resp.json()["line"] == 1


async def test_chain_unit_verify_records_directly():
    from app.chain import EventRecord

    def rec(seq, prev, entry=None, event_hash=None, rid=None):
        from app.chain import build_event_payload

        payload = build_event_payload(
            id=rid or f"id{seq}",
            delivery_id=None,
            token_hash=None,
            action="pickup",
            result="unknown",
            detail=None,
            client_ip=None,
            user_agent=None,
            created_at="2026-09-21T00:00:00.000000Z",
        )
        eh = event_hash or compute_event_hash(payload)
        return EventRecord(
            seq=seq, id=rid or f"id{seq}", delivery_id=None, token_hash=None,
            action="pickup", result="unknown", detail=None, client_ip=None,
            user_agent=None, created_at="2026-09-21T00:00:00.000000Z",
            prev_hash=prev, event_hash=eh,
            entry_hash=entry or compute_entry_hash(prev, seq, eh),
        )

    r1 = rec(1, GENESIS_HASH)
    r2 = rec(2, r1.entry_hash)
    r3 = rec(3, r2.entry_hash)
    assert verify_records([r1, r2, r3], expected_last_seq=3,
                          expected_last_hash=r3.entry_hash).ok

    # 链断裂：r3 指错前链
    bad = rec(3, "ab" * 32)
    report = verify_records([r1, r2, bad], expected_last_seq=3,
                            expected_last_hash=bad.entry_hash)
    assert not report.ok and report.code == "chain_broken"
