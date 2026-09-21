"""审计链的规范化摘要、链式哈希与完整性校验。

每条审计事件按固定规则规范化后计算两级哈希：

1. ``event_hash`` = SHA-256(域分隔前缀 + 规范化事件 JSON)
   覆盖事件全部业务字段（动作、结果、关联 ID、时间、客户端信息、详情），
   任何字段被改写都会导致摘要不一致。

2. ``entry_hash`` = SHA-256(域分隔前缀 + prev_hash + seq + event_hash)
   把本条事件与前一条的链哈希、本条链序号绑定，形成哈希链。

第 1 条记录的前链哈希为全 0 的创世哈希 ``GENESIS_HASH``。

校验能力（按记录顺序逐条比对，报告第一处错误）：
- 缺行（seq 不连续）/ 乱序（seq 倒退）/ 重复（同一条记录或同一 seq 出现两次）
- 字段改写（事件摘要不一致，含链哈希字段本身被改写）
- 链断裂（前链哈希对不上）/ 链尾与数据库链尖不一致
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# 链版本号，写入每条导出记录；未来调整规范化规则时可据此区分
CHAIN_VERSION = 1
# 创世前链哈希：第 1 条（seq=1）记录的 prev_hash
GENESIS_HASH = "0" * 64

_EVENT_PREFIX = b"dropbox-audit-event-v1\n"
_ENTRY_PREFIX = b"dropbox-audit-entry-v1\n"


# ---------------- 规范化与哈希 ----------------


def canonical_timestamp(dt: datetime) -> str:
    """统一为 UTC、微秒精度、以 Z 结尾的 ISO-8601 字符串。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def parse_timestamp(value: str) -> datetime:
    """解析导出记录中的 ISO-8601 时间（兼容结尾 Z）。"""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_event_payload(
    *,
    id: uuid.UUID | str,
    delivery_id: uuid.UUID | str | None,
    token_hash: str | None,
    action: str,
    result: str,
    detail: Any,
    client_ip: str | None,
    user_agent: str | None,
    created_at: datetime | str,
) -> dict:
    """构造规范化事件摘要的载荷（不含链字段，链字段由 entry_hash 绑定）。"""
    if isinstance(created_at, datetime):
        created_at = canonical_timestamp(created_at)
    return {
        "v": CHAIN_VERSION,
        "id": str(id),
        "delivery_id": str(delivery_id) if delivery_id is not None else None,
        "token_hash": token_hash,
        "action": action,
        "result": result,
        # detail 来自 JSON 列，本身就是 JSON 兼容类型；排序键保证确定性
        "detail": detail,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": created_at,
    }


def canonical_json(payload: Any) -> bytes:
    """确定性 JSON：键排序、无多余空白、不转义非 ASCII、禁止 NaN。"""
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def compute_event_hash(payload: dict) -> str:
    return hashlib.sha256(_EVENT_PREFIX + canonical_json(payload)).hexdigest()


def compute_entry_hash(prev_hash: str, seq: int, event_hash: str) -> str:
    body = f"{prev_hash}\n{seq}\n{event_hash}".encode("ascii")
    return hashlib.sha256(_ENTRY_PREFIX + body).hexdigest()


# ---------------- 校验 ----------------


@dataclass(frozen=True)
class EventRecord:
    """校验用的一条审计记录（来自数据库行或导出的 NDJSON 行）。"""

    seq: int
    id: str
    delivery_id: str | None
    token_hash: str | None
    action: str
    result: str
    detail: Any
    client_ip: str | None
    user_agent: str | None
    created_at: str  # 已经过 canonical_timestamp 规范化
    prev_hash: str
    event_hash: str
    entry_hash: str

    def event_payload(self) -> dict:
        return build_event_payload(
            id=self.id,
            delivery_id=self.delivery_id,
            token_hash=self.token_hash,
            action=self.action,
            result=self.result,
            detail=self.detail,
            client_ip=self.client_ip,
            user_agent=self.user_agent,
            created_at=self.created_at,
        )


@dataclass
class VerifyReport:
    ok: bool
    count: int
    start_seq: int | None = None
    end_seq: int | None = None
    start_hash: str | None = None
    end_hash: str | None = None
    tip_seq: int | None = None
    tip_hash: str | None = None
    code: str | None = None
    message: str | None = None
    seq: int | None = None
    expected_seq: int | None = None
    record_id: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _error(
    code: str,
    message: str,
    *,
    records: list[EventRecord],
    seq: int | None = None,
    expected_seq: int | None = None,
    record: EventRecord | None = None,
    tip_seq: int | None = None,
    tip_hash: str | None = None,
) -> VerifyReport:
    return VerifyReport(
        ok=False,
        count=len(records),
        start_seq=records[0].seq if records else None,
        end_seq=records[-1].seq if records else None,
        start_hash=records[0].entry_hash if records else None,
        end_hash=records[-1].entry_hash if records else None,
        tip_seq=tip_seq,
        tip_hash=tip_hash,
        code=code,
        message=message,
        seq=seq,
        expected_seq=expected_seq,
        record_id=record.id if record else None,
    )


def verify_records(
    records: list[EventRecord],
    *,
    expected_first_seq: int = 1,
    expected_prev_hash: str = GENESIS_HASH,
    expected_last_seq: int | None = None,
    expected_last_hash: str | None = None,
    tip_seq: int | None = None,
    tip_hash: str | None = None,
) -> VerifyReport:
    """按给定顺序校验一段（或整条）审计链，返回第一处错误。

    records 必须按链上顺序排列；不做排序，以便发现乱序。
    expected_first_seq / expected_prev_hash 给出本段起点的锚点：
    全链校验时为 1 / GENESIS_HASH；片段校验时为导出头部的起点序号与前链哈希。
    expected_last_* 给出可信链尾（数据库链尖或调用方先前留存的端点哈希）。
    """
    expected_seq = expected_first_seq
    running_prev = expected_prev_hash
    seen_ids: set[str] = set()
    seen_seqs: set[int] = set()

    for rec in records:
        if rec.id in seen_ids:
            return _error(
                "duplicate",
                f"记录重复：同一记录 id {rec.id} 在链中出现多次。",
                records=records, seq=rec.seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )
        seen_ids.add(rec.id)

        if rec.seq in seen_seqs:
            return _error(
                "duplicate",
                f"记录重复：链序号 {rec.seq} 出现了多条记录。",
                records=records, seq=rec.seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )

        if rec.seq < expected_seq:
            return _error(
                "out_of_order",
                f"乱序：当前记录序号 {rec.seq}，而链位置应出现序号 {expected_seq}。",
                records=records, seq=rec.seq, expected_seq=expected_seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )
        if rec.seq > expected_seq:
            return _error(
                "missing",
                f"缺行：序号 {expected_seq} 的审计记录不存在（在记录 {rec.id} 之前断档）。",
                records=records, seq=rec.seq, expected_seq=expected_seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )

        # 字段完整性：重算事件摘要
        if compute_event_hash(rec.event_payload()) != rec.event_hash:
            return _error(
                "field_tampered",
                f"字段改写：序号 {rec.seq} 的事件摘要与字段内容不一致。",
                records=records, seq=rec.seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )

        # 链链接：前链哈希必须等于前一条（或创世）哈希
        if rec.prev_hash != running_prev:
            return _error(
                "chain_broken",
                f"链断裂：序号 {rec.seq} 的前链哈希与序号 {rec.seq - 1} 不匹配。",
                records=records, seq=rec.seq, expected_seq=expected_seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )

        # 本条链哈希必须与 (prev_hash, seq, event_hash) 一致
        recomputed = compute_entry_hash(running_prev, rec.seq, rec.event_hash)
        if recomputed != rec.entry_hash:
            return _error(
                "field_tampered",
                f"字段改写：序号 {rec.seq} 的链哈希被改写，无法由前链哈希与事件摘要推出。",
                records=records, seq=rec.seq, record=rec,
                tip_seq=tip_seq, tip_hash=tip_hash,
            )

        running_prev = rec.entry_hash
        seen_seqs.add(rec.seq)
        expected_seq = rec.seq + 1

    last = records[-1] if records else None

    if expected_last_seq is not None and expected_last_seq > 0 and (
        last is None or last.seq != expected_last_seq
    ):
        return _error(
            "missing",
            f"缺行：链应结束于序号 {expected_last_seq}，实际最后一条为 "
            f"{last.seq if last else '空'}。",
            records=records,
            seq=last.seq if last else None,
            expected_seq=expected_last_seq,
            record=last,
            tip_seq=tip_seq,
            tip_hash=tip_hash,
        )

    if expected_last_hash is not None and expected_last_seq and (
        last is None or last.entry_hash != expected_last_hash
    ):
        return _error(
            "tip_mismatch",
            "链尾不匹配：最后一条记录的链哈希与可信链尖不一致，链尾可能被改写或截断。",
            records=records,
            seq=last.seq if last else None,
            record=last,
            tip_seq=tip_seq,
            tip_hash=tip_hash,
        )

    return VerifyReport(
        ok=True,
        count=len(records),
        start_seq=records[0].seq if records else expected_first_seq,
        end_seq=records[-1].seq if records else expected_first_seq - 1,
        start_hash=records[0].entry_hash if records else None,
        end_hash=records[-1].entry_hash if records else None,
        tip_seq=tip_seq,
        tip_hash=tip_hash,
        message="ok" if records else "空链，无可校验记录。",
    )
