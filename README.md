# 一次性内容投递箱 API（One-Time Drop Box）

发送者创建带过期时间的 **文本** 或 **小文件** 投递，得到一个取件令牌；
收件人凭令牌取件，**内容只能被成功读取一次**。并发取件时仅有一个请求得到内容，
其余请求以及「已撤回 / 已过期 / 已消费」都会得到明确、可区分的结果。

- **FastAPI**（异步 HTTP + 自动 OpenAPI 文档）
- **PostgreSQL**：投递内容与审计的唯一可信存储，**原子消费的最终裁决者**
- **Redis**：终态快速拒绝缓存（best-effort，宕机不影响正确性）
- 令牌只存 SHA-256 哈希；明文令牌仅在创建响应中出现一次

---

## 一条命令启动

需要 Docker（含 Compose 插件）：

```bash
docker compose up --build
```

启动后：

| 服务 | 地址 |
| --- | --- |
| **API（对外端口）** | **http://localhost:8000** |
| Swagger 交互文档 | http://localhost:8000/docs |
| 健康检查 | http://localhost:8000/health |
| PostgreSQL | 仅集群内部 `db:5432`（不对宿主机暴露） |
| Redis | 仅集群内部 `redis:6379`（不对宿主机暴露） |

停止并清理数据卷：

```bash
docker compose down -v
```

> API 对外只暴露 **8000** 一个端口。数据库与 Redis 不映射到宿主机。

---

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/v1/deliveries` | 创建文本投递（JSON） |
| `POST` | `/api/v1/deliveries/file` | 创建小文件投递（multipart/form-data） |
| `POST` | `/api/v1/pickup/{token}` | 凭令牌取件（**只能成功一次**） |
| `POST` | `/api/v1/revoke/{token}` | 发送者撤回投递 |
| `GET` | `/api/v1/audit/export` | 按时间范围导出审计链（**NDJSON 只读流**） |
| `GET` | `/api/v1/audit/verify` | 在线校验库内整条审计哈希链 |
| `POST` | `/api/v1/audit/verify` | 校验此前导出的 NDJSON 审计文件 |
| `GET` | `/health` | 健康检查 |

### 取件/撤回的明确结果

取件失败时返回统一结构 `{"result": <状态>, "detail": <中文说明>}`，状态与状态码如下：

| `result` | 含义 | HTTP 状态码 |
| --- | --- | --- |
| `success` | 取件成功（文本返回 JSON，文件返回二进制流） | `200` |
| `consumed` | 令牌已被成功取件，内容已不可再读 | `410 Gone` |
| `expired` | 投递已过期 | `410 Gone` |
| `revoked` | 投递已被发送者撤回（取件）/ 无法撤回（已被取走见下） | 取件 `409 Conflict` |
| `unknown` | 令牌不存在 | `404 Not Found` |

撤回接口：成功 `200 {"result":"revoked"}`；已被取走或已过期返回 `410`
（`result` 为 `consumed` / `expired`）；令牌不存在 `404`。

---

## 使用示例

### 1) 创建文本投递

```bash
curl -s -X POST http://localhost:8000/api/v1/deliveries \
  -H 'Content-Type: application/json' \
  -d '{"text": "这是读一次就消失的秘密", "ttl_seconds": 3600}'
```

响应（`token` 仅此一次返回，请立即保存）：

```json
{
  "delivery_id": "8f1c…-…-…",
  "token": "U9rX…取件令牌…",
  "expires_at": "2026-09-21T10:00:00Z",
  "url": "http://localhost:8000/api/v1/pickup/U9rX…"
}
```

### 2) 取件（第一次成功）

```bash
curl -s -X POST "http://localhost:8000/api/v1/pickup/U9rX…"
```

```json
{
  "result": "success",
  "delivery_id": "8f1c…",
  "kind": "text",
  "content": "这是读一次就消失的秘密",
  "content_sha256": "…",
  "consumed_at": "2026-09-21T09:05:11Z"
}
```

再取一次：

```bash
curl -s -X POST "http://localhost:8000/api/v1/pickup/U9rX…" -i
# HTTP/1.1 410 Gone
# {"result":"consumed","detail":"该令牌已被成功取件，内容仅可读取一次。"}
```

### 3) 创建小文件并取件

```bash
# 创建（默认上限 1 MiB）
curl -s -X POST http://localhost:8000/api/v1/deliveries/file \
  -F 'file=@/path/to/report.pdf' \
  -F 'ttl_seconds=600'

# 取件（成功返回二进制流，响应头带校验值）
curl -X POST "http://localhost:8000/api/v1/pickup/<token>" \
  -D - -o downloaded.pdf
# X-Drop-Result: success
# X-Content-SHA256: <sha256>
# Content-Disposition: attachment; filename="report.pdf"; …
```

### 4) 撤回

```bash
curl -s -X POST "http://localhost:8000/api/v1/revoke/<token>"
# 成功：   200 {"result":"revoked", ...}
# 已取走： 410 {"result":"consumed", ...}
# 已过期： 410 {"result":"expired", ...}
```

撤回后再取件得到 `409 {"result":"revoked"}`。

---

## 并发原子消费是如何保证的

这是本服务的核心。正确性**只依赖 PostgreSQL 的单条条件更新**，不依赖应用层锁：

```sql
UPDATE deliveries
SET status = 'consumed', consumed_at = now
WHERE token_hash = :token_hash
  AND status = 'active'
  AND expires_at > now
RETURNING id, content, …;
```

- 多个并发请求执行同一条语句时，PostgreSQL 用**行锁**把对该行的更新串行化；
- 只有**第一个**事务满足 `status='active' AND 未过期`，它把状态改成 `consumed`
  并通过 `RETURNING` 拿到内容（唯一赢家）；
- 其余事务的 `WHERE` 不再匹配，返回 0 行，随后在新事务里读取当前终态，
  得到明确的 `consumed` / `revoked` / `expired`；
- 未命中的事务**不会在旧快照里回写任何状态**，因此不可能覆盖赢家刚提交的终态；
- 内容仅在赢家事务中随 `RETURNING` 取出一次，响应后不落缓存。

**Redis 的角色（非正确性依赖）**：只缓存终态标记（`consumed` / `revoked` /
`expired`），用于对已知失效令牌快速拒绝、减轻数据库压力；**绝不缓存明文内容**，
采用 Lua「仅当不存在时设置」保证终态不被互相覆盖，并设置 TTL。Redis 不可用时
请求自动回落到数据库判定，原子消费依旧成立。

**过期**：取件/撤回时惰性提升 + 后台协程每 30 秒批量兜底标记过期。

### 撤回与取件竞争

撤回使用同样的单条条件更新（目标状态 `revoked`）。它与取件互斥：
要么内容被取走（撤回得到 `consumed`），要么撤回先成功（取件得到 `revoked`），
不会出现“既取走又撤回”。

---

## 审计：可验证完整性的哈希链

所有关键动作写入 `audit_logs` 表：

- 动作：`create` / `pickup` / `revoke`
- 结果：`success` / `consumed` / `revoked` / `expired` / `unknown`
- 关联 `delivery_id`（可空）、`token_hash`、客户端 IP、User-Agent、时间与少量详情
- **未知令牌的尝试也留痕并入链**（`delivery_id` 为空、仅记录哈希），便于暴力探测审计

明文内容不写入审计；导出接口同样只输出审计列，**绝不包含投递明文**（`text` /
文件字节 / 文件名以外的内容字段均不出现；详情里只有类型、大小、文件名等元数据）。

### 每条日志的三级结构

每条审计记录除业务字段外，还带链字段：

| 字段 | 含义 |
| --- | --- |
| `seq` | 链序号，从 1 开始连续递增，数据库唯一索引 |
| `event_hash` | **规范化事件摘要**：`SHA-256("dropbox-audit-event-v1\n" + 规范化事件 JSON)` |
| `prev_hash` | **前一条摘要哈希**（上一条的 `entry_hash`）；第 1 条为 64 个 `0`（创世哈希） |
| `entry_hash` | **本条链哈希**：`SHA-256("dropbox-audit-entry-v1\n" + prev_hash + "\n" + seq + "\n" + event_hash)` |

规范化事件 JSON 固定包含 `v / id / delivery_id / token_hash / action / result /
detail / client_ip / user_agent / created_at`，按键名排序、无多余空白、不转义
非 ASCII；`created_at` 统一为 UTC 微秒精度、`Z` 结尾的 ISO-8601。任何字段被改写
都会使 `event_hash` 对不上；任何删除、重排、重放或前链篡改都会使链链接对不上。

### 并发写入：链序由数据库条件更新裁决

`audit_chain_state` 单行表保存链尖 `(last_seq, last_hash)`。写入一条审计时：

1. 读取当前链尖，算出下一个 `seq = last_seq + 1` 与候选链哈希；
2. 执行条件更新
   `UPDATE audit_chain_state SET last_seq=:next, last_hash=:candidate
    WHERE id=1 AND last_seq=:读到的 AND last_hash=:读到的`；
3. 命中（影响 1 行）才插入审计行；未命中说明并发事务已推进链尖，**重读新链尖
   并重试**。

PostgreSQL 用行锁把链尖更新串行化，SQLite（测试）靠整库写锁串行化；`seq` 上的
唯一索引作为最终兜底。审计行与投递状态变更在**同一个数据库事务**中提交（取件
赢家的 `UPDATE deliveries` 与审计插入原子可见），因此不会出现“消费成功但未入链”
或“链推进成功但无审计行”。

### 导出 NDJSON（只读）

```bash
curl -s "http://localhost:8000/api/v1/audit/export?start=2026-09-21T00:00:00Z&end=2026-09-22T00:00:00Z&limit=10000" \
  -D headers.txt -o audit.ndjson
```

- 时间过滤为 `created_at >= start AND created_at < end`（均可选，ISO-8601）；
  `limit` 1..100000，默认 10000。
- 响应为 `application/x-ndjson`（每行一条记录的 JSON，按 `seq` 升序）。
- 起止链哈希与记录数通过**响应头**返回，便于归档后离线校验：

| 响应头 | 含义 |
| --- | --- |
| `X-Audit-Count` | 实际返回的记录数 |
| `X-Audit-Start-Seq` / `X-Audit-End-Seq` | 首/末条链序号 |
| `X-Audit-Start-Prev-Hash` | 首条的 `prev_hash`（片段锚点） |
| `X-Audit-Start-Hash` / `X-Audit-End-Hash` | 首/末条链哈希 |
| `X-Audit-Truncated` | `1` 表示命中 `limit`，时间窗内还有未导出的记录 |

导出在只读事务中执行（PostgreSQL `SET TRANSACTION READ ONLY`；SQLite
`PRAGMA query_only=ON`），头部与正文取自同一快照。

### 校验

在线校验库内全链（库未被整体改写时使用，比对链尖单行）：

```bash
curl -s http://localhost:8000/api/v1/audit/verify
# {"ok":true,"count":42,"start_seq":1,"end_seq":42,"tip_seq":42,"tip_hash":"…",…}
```

离线校验导出的 NDJSON 文件（归档后随时可验）：

```bash
# 全量导出（从创世开始）
curl -s -X POST http://localhost:8000/api/v1/audit/verify \
  --data-binary @audit.ndjson -H 'Content-Type: application/x-ndjson'

# 片段导出：用导出响应头里的起点锚点
curl -s -X POST \
  "http://localhost:8000/api/v1/audit/verify?start_seq=10&start_prev_hash=<X-Audit-Start-Prev-Hash>" \
  --data-binary @segment.ndjson -H 'Content-Type: application/x-ndjson'
```

校验逐条按链顺序检查并在**第一处错误**处停止，错误码与定位信息：

| `code` | 检测到的问题 | 返回的定位字段 |
| --- | --- | --- |
| `missing` | 缺行（`seq` 断档）/ 链尾缺失 | `seq`（当前）、`expected_seq`、`record_id` |
| `out_of_order` | 乱序（`seq` 倒退） | `seq`、`expected_seq`、`record_id` |
| `duplicate` | 重复（同一记录 id 或同一 `seq` 出现两次） | `seq`、`record_id` |
| `field_tampered` | 字段改写（业务字段或链哈希字段被改） | `seq`、`record_id` |
| `chain_broken` | 链断裂（`prev_hash` 对不上） | `seq`、`record_id` |
| `tip_mismatch` | 链尾与数据库链尖不一致（截断/改写） | `tip_seq`、`tip_hash` |

> 校验接口本身不写审计、不产生新链记录（否则会污染被校验对象）。

### 数据模型要点

- 令牌为 32 字节 `secrets.token_urlsafe(32)`，库中仅存其 **SHA-256**；
- 内容存 PostgreSQL `bytea`，同时记录大小与 SHA-256；
- 状态机：`active → consumed | revoked | expired`，单向不可逆；
- `(status, expires_at)` 与 `token_hash` 建有索引，支撑并发判定与清扫；
- 审计链字段 `(seq, event_hash, prev_hash, entry_hash)` 与链尖表
  `audit_chain_state`；服务启动时自动建表，旧库会自动补列并按时间顺序回填链。

---

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://dropbox:dropbox@db:5432/dropbox` | 异步数据库 DSN |
| `REDIS_URL` | `redis://redis:6379/0` | Redis 地址 |
| `MAX_CONTENT_BYTES` | `1048576`（1 MiB） | 单条文本/文件大小上限 |
| `TTL_MIN_SECONDS` | `60` | 允许的最短有效期 |
| `TTL_MAX_SECONDS` | `604800`（7 天） | 允许的最长有效期 |
| `REDIS_FLAG_TTL_SECONDS` | `2592000`（30 天） | Redis 终态标记保留时长 |
| `SWEEP_INTERVAL_SECONDS` | `30` | 后台过期清扫间隔 |

本地裸跑（不用 Docker）可复制 `.env.example` 为 `.env` 后自行准备 PG/Redis，
再 `uvicorn app.main:app --reload`。

---

## 本地开发与测试

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

测试套件使用文件型 SQLite（WAL，多连接真实争抢写锁）+ `fakeredis`，
包含 **50 路并发取件仅有一个赢家**、**取件/撤回并发互斥**、撤回、过期、
文件一次性下载、未知令牌与审计留痕等用例；审计链部分覆盖并发 40 路纯链尖竞争
序号连续唯一、缺行/乱序/重复/字段改写/链断裂/链尖篡改的第一处错误定位、
NDJSON 导出（只读、无明文、截断标记）与离线校验、旧库自动补列回填。另在真实
PostgreSQL 上验证过 100 路并发取件恰好 1 个赢家、30 组取件/撤回互斥。

---

## 安全说明与边界

- 取件令牌是唯一的“能力凭证”：知道令牌即可取件，因此应通过私密渠道发送；
  库中不存明文令牌，泄露数据库无法反推取件地址。
- 默认内容上限 1 MiB，面向“文本或小文件”；大文件投递不在设计范围内。
- 本服务不含发送者身份认证/速率限制，生产部署建议放在鉴权网关之后并自行限流；
  `/api/v1/audit/*` 会暴露动作时间、令牌哈希与客户端信息（不含投递明文），
  同样建议在网关层限制访问。
- 表结构在启动时自动 `CREATE TABLE`（简单场景不引入迁移工具）；旧版
  `audit_logs` 表会在启动时自动补齐哈希链列并按时间顺序回填，随后追加的日志
  自动续链。
