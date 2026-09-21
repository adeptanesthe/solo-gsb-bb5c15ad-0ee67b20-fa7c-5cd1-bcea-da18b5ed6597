"""审计日志哈希链：规范化事件摘要、链哈希与完整性校验。

每条审计记录都带有：

- ``seq``：全链单调递增序号（由数据库条件更新裁决分配）；
- ``event_digest``：规范化（canonical）事件摘要的 SHA-256；
- ``prev_hash``：前一条记录的链哈希（创世记录前为固定的 GENESIS_HASH）；
- ``entry_hash``：``SHA256(prev_hash | event_digest)``，本条链哈希。

规范化摘要覆盖记录的全部业务字段（序号、时间、动作、结果、关联投递、
令牌哈希、IP、UA、详情），因此任何字段改写都会导致摘要失配；
而删行、乱序、重复则通过序号连续性与前后指针发现。

注意：哈希链只能阻止/发现“非重算式”篡改。拥有数据库写权限的攻击者
理论上可以从某点起重算全部后续哈希，因此导出接口返回的末端链哈希
（end_hash）应由外部独立留存，作为校验时的信任锚。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

# 创世前缀哈希：序号 1 的 prev_hash 固定指向它
GENESIS_HASH = hashlib.sha256(
    b"one-time-dropbox/audit-chain/v1/genesis"
).hexdigest()

# 规范化事件格式版本，未来字段演进时可区分
CHAIN_VERSION = 1

# 校验可能返回的错误类别
ERR_MISSING = "missing"          # 缺行
ERR_OUT_OF_ORDER = "out_of_order"  # 乱序
ERR_DUPLICATE = "duplicate"      # 重复
ERR_FIELD_TAMPERED = "field_tampered"  # 字段改写
ERR_CHAIN_BREAK = "chain_break"  # 链断裂


class ChainFormatError(ValueError):
    """外部提交的 NDJSON 行无法解析为链记录。"""


def format_utc(value: datetime) -> str:
    """统一为 UTC、微秒精度、Z 结尾的 ISO-8601 字符串（规范化用）。"""
    if value.tzinfo is None:
        # SQLite 驱动可能返回 naive datetime，按 UTC 解释
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_event(
    *,
    seq: int,
    created_at: datetime,
    action: str,
    result: str,
    delivery_id: uuid.UUID | str | None,
    token_hash: str | None,
    client_ip: str | None,
    user_agent: str | None,
    detail: dict[str, Any] | None,
) -> bytes:
    """构造确定性的规范化事件 JSON（键排序、紧凑分隔、UTF-8 原文）。

    同一条事件在任何机器、任何 JSON 库下重新计算都必须得到相同字节，
    因此这里禁止浮点数等不确定性表示（当前 detail 中只有小整数与短字符串）。
    """
    payload = {
        "v": CHAIN_VERSION,
        "seq": seq,
        "created_at": format_utc(created_at),
        "action": action,
        "result": result,
        "delivery_id": str(delivery_id) if delivery_id is not None else None,
        "token_hash": token_hash,
        "client_ip": client_ip,
        "user_agent": user_agent,
        # 入库时 None 与 {} 等价，规范化时统一为空对象
        "detail": detail if detail is not None else {},
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def event_digest_for(
    *,
    seq: int,
    created_at: datetime,
    action: str,
    result: str,
    delivery_id: uuid.UUID | str | None,
    token_hash: str | None,
    client_ip: str | None,
    user_agent: str | None,
    detail: dict[str, Any] | None,
) -> str:
    return hashlib.sha256(
        canonical_event(
            seq=seq,
            created_at=created_at,
            action=action,
            result=result,
            delivery_id=delivery_id,
            token_hash=token_hash,
            client_ip=client_ip,
            user_agent=user_agent,
            detail=detail,
        )
    ).hexdigest()


def chain_hash(prev_hash: str, event_digest: str) -> str:
    """本条链哈希 = SHA256(前一条链哈希 | 规范化事件摘要)。"""
    return hashlib.sha256(
        prev_hash.encode("ascii") + b"|" + event_digest.encode("ascii")
    ).hexdigest()


@dataclass(frozen=True)
class ChainEntry:
    """校验所用的最小记录视图（不含任何投递明文内容）。"""

    seq: int
    created_at: datetime
    action: str
    result: str
    delivery_id: uuid.UUID | None
    token_hash: str | None
    client_ip: str | None
    user_agent: str | None
    detail: dict[str, Any] | None
    event_digest: str
    prev_hash: str
    entry_hash: str

    @classmethod
    def from_row(cls, row: Any) -> ChainEntry:
        return cls(
            seq=row.seq,
            created_at=row.created_at,
            action=row.action,
            result=row.result,
            delivery_id=row.delivery_id,
            token_hash=row.token_hash,
            client_ip=row.client_ip,
            user_agent=row.user_agent,
            detail=row.detail,
            event_digest=row.event_digest,
            prev_hash=row.prev_hash,
            entry_hash=row.entry_hash,
        )

    @classmethod
    def from_dict(cls, obj: Any, *, position: int) -> ChainEntry:
        if not isinstance(obj, dict):
            raise ChainFormatError(f"第 {position} 行不是 JSON 对象")
        try:
            seq = obj["seq"]
            created_raw = obj["created_at"]
            action = obj["action"]
            result = obj["result"]
            event_digest = obj["event_digest"]
            prev_hash = obj["prev_hash"]
            entry_hash = obj["entry_hash"]
        except KeyError as exc:
            raise ChainFormatError(f"第 {position} 行缺少字段 {exc.args[0]!s}") from None

        if isinstance(seq, bool) or not isinstance(seq, int):
            raise ChainFormatError(f"第 {position} 行 seq 必须为整数")
        try:
            created_at = datetime.fromisoformat(str(created_raw).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise ChainFormatError(
                f"第 {position} 行 created_at 不是合法 ISO-8601 时间"
            ) from None
        raw_delivery = obj.get("delivery_id")
        try:
            delivery_id = uuid.UUID(raw_delivery) if raw_delivery is not None else None
        except (TypeError, ValueError):
            raise ChainFormatError(
                f"第 {position} 行 delivery_id 不是合法 UUID"
            ) from None
        detail = obj.get("detail")
        if detail is not None and not isinstance(detail, dict):
            raise ChainFormatError(f"第 {position} 行 detail 必须为对象或 null")

        return cls(
            seq=seq,
            created_at=created_at,
            action=str(action),
            result=str(result),
            delivery_id=delivery_id,
            token_hash=obj.get("token_hash"),
            client_ip=obj.get("client_ip"),
            user_agent=obj.get("user_agent"),
            detail=detail,
            event_digest=str(event_digest),
            prev_hash=str(prev_hash),
            entry_hash=str(entry_hash),
        )

    def recomputed_digest(self) -> str:
        return event_digest_for(
            seq=self.seq,
            created_at=self.created_at,
            action=self.action,
            result=self.result,
            delivery_id=self.delivery_id,
            token_hash=self.token_hash,
            client_ip=self.client_ip,
            user_agent=self.user_agent,
            detail=self.detail,
        )

    def public_dict(self) -> dict[str, Any]:
        """导出 NDJSON 的字段白名单：永远不包含投递明文内容。"""
        return {
            "seq": self.seq,
            "created_at": format_utc(self.created_at),
            "action": self.action,
            "result": self.result,
            "delivery_id": str(self.delivery_id) if self.delivery_id else None,
            "token_hash": self.token_hash,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "detail": self.detail if self.detail is not None else {},
            "event_digest": self.event_digest,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass(frozen=True)
class ChainVerifyResult:
    ok: bool
    count: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    start_hash: str | None = None
    end_hash: str | None = None
    error: str | None = None       # 见 ERR_* 常量
    seq: int | None = None         # 第一处错误所在序号
    position: int | None = None    # 第一处错误所在行（从 1 开始）
    detail: str | None = None


def _fail(
    error: str,
    *,
    seq: int | None,
    position: int,
    detail: str,
    scanned: list[ChainEntry],
) -> ChainVerifyResult:
    return ChainVerifyResult(
        ok=False,
        count=len(scanned),
        first_seq=scanned[0].seq if scanned else None,
        last_seq=scanned[-1].seq if scanned else None,
        start_hash=scanned[0].entry_hash if scanned else None,
        end_hash=scanned[-1].entry_hash if scanned else None,
        error=error,
        seq=seq,
        position=position,
        detail=detail,
    )


def verify_chain(
    entries: Iterable[ChainEntry],
    *,
    expected_seq: int | None = None,
    anchor_hash: str | None = None,
) -> ChainVerifyResult:
    """按 *给定顺序* 逐条校验哈希链，返回第一处错误。

    - expected_seq：第一条记录应有的序号；缺省取首条自身序号（按片段校验）。
    - anchor_hash：第一条记录的 prev_hash 应指向的链哈希
      （全链校验时为 GENESIS_HASH；片段校验时为库中前一条的链哈希；
      无法取得锚点时传 None，仅校验片段内部连续性）。

    检查顺序（保证“第一处错误”的确定性）：
    重复 → 乱序 → 缺行 → 字段改写（摘要失配）→ 链断裂（哈希/前指针失配）。
    """
    entries = list(entries)
    if not entries:
        return ChainVerifyResult(ok=True)

    if expected_seq is None:
        expected_seq = entries[0].seq
    if anchor_hash is None and expected_seq == 1:
        anchor_hash = GENESIS_HASH

    seen: set[int] = set()
    prev_hash: str | None = anchor_hash
    scanned: list[ChainEntry] = []

    for position, entry in enumerate(entries, start=1):
        seq = entry.seq

        if seq in seen:
            return _fail(
                ERR_DUPLICATE,
                seq=seq,
                position=position,
                detail=f"序号 {seq} 在第 {position} 行重复出现",
                scanned=scanned,
            )
        if seq < expected_seq:
            return _fail(
                ERR_OUT_OF_ORDER,
                seq=seq,
                position=position,
                detail=(
                    f"第 {position} 行序号 {seq} 落后于期望序号 {expected_seq}，"
                    "记录乱序"
                ),
                scanned=scanned,
            )
        if seq > expected_seq:
            # 期望行可能只是被挤到了后面（乱序），也可能真的不存在（缺行）：
            # 向剩余行前瞻，期望序号还在 -> 乱序；不在 -> 缺行。
            displaced = any(
                later.seq == expected_seq for later in entries[position:]
            )
            if displaced:
                return _fail(
                    ERR_OUT_OF_ORDER,
                    seq=seq,
                    position=position,
                    detail=(
                        f"第 {position} 行序号 {seq} 提前出现于序号 "
                        f"{expected_seq} 之前，记录乱序"
                    ),
                    scanned=scanned,
                )
            return _fail(
                ERR_MISSING,
                seq=expected_seq,
                position=position,
                detail=(
                    f"缺少序号 {expected_seq}：序号 {expected_seq - 1} 之后"
                    f"直接跳到 {seq}"
                ),
                scanned=scanned,
            )

        # 重新计算规范化事件摘要：任何字段改写都会在这里失配
        digest = entry.recomputed_digest()
        if not _safe_eq(digest, entry.event_digest):
            return _fail(
                ERR_FIELD_TAMPERED,
                seq=seq,
                position=position,
                detail=(
                    f"序号 {seq} 的规范化事件摘要不匹配，记录字段被改写"
                ),
                scanned=scanned,
            )

        recomputed_entry = chain_hash(entry.prev_hash, digest)
        if not _safe_eq(recomputed_entry, entry.entry_hash):
            return _fail(
                ERR_CHAIN_BREAK,
                seq=seq,
                position=position,
                detail=f"序号 {seq} 的链哈希不匹配，链在此处断裂",
                scanned=scanned,
            )

        if prev_hash is not None and not _safe_eq(entry.prev_hash, prev_hash):
            return _fail(
                ERR_CHAIN_BREAK,
                seq=seq,
                position=position,
                detail=(
                    f"序号 {seq} 的前一条摘要哈希不匹配：期望 "
                    f"{prev_hash[:16]}…，实际 {entry.prev_hash[:16]}…"
                ),
                scanned=scanned,
            )

        seen.add(seq)
        expected_seq = seq + 1
        prev_hash = entry.entry_hash
        scanned.append(entry)

    return ChainVerifyResult(
        ok=True,
        count=len(scanned),
        first_seq=scanned[0].seq,
        last_seq=scanned[-1].seq,
        start_hash=scanned[0].entry_hash,
        end_hash=scanned[-1].entry_hash,
    )


def _safe_eq(a: str, b: str) -> bool:
    """定长比较，避免摘要比较泄露计时信息（均为 64 位十六进制）。"""
    import hmac

    return hmac.compare_digest(a, b)


def dumps_ndjson(entry: ChainEntry) -> bytes:
    """把一条链记录序列化为单行 NDJSON（导出格式即校验输入格式）。"""
    return (
        json.dumps(
            entry.public_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
