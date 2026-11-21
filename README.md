# 跨区 DNS 变更发布顺序规划器

给内网 DNS 值班员用的 FastAPI 服务，包含两个接口：

* **`POST /plan`** — 发布顺序推演。提交最多 8 个**互不嵌套**的权威区的
  新旧 A / CNAME 记录，以及必须持续可解析的业务域名，服务按**无缓存权威记录**
  推演每一次**整区切换**后的解析状态，回答三件事：

  1. **有没有安全顺序**：有则返回逐步发布顺序，并给出每一步前后的解析结果。
  2. **现状是否已经坏了**：若按现状（所有区都还是旧记录）就查不到 IPv4 地址，
     直接返回故障链路，不再谈发布顺序。
  3. **没有安全顺序时卡在哪**：返回能安全走到的**最大前缀**，并逐个说明剩余
     每个区若紧接着发布会断在哪条解析链上，区分**缺记录**与**成环**。

* **`POST /pcap/dns-response-check`** — 离线抓包核查。客户端抓包里 DNS 查询
  等不到应答时，上传经典 PCAP（以太网 / IPv4 / UDP，≤ 5 MiB），指定 A 查询帧
  和截止帧，核查两帧之间的回包是**完整到达**、**缺片**还是**无法归属**，
  详见下文「离线抓包核查」。

## 推演模型

* 每个区只有两个状态：整区旧记录、整区新记录。一次发布 = 一个区整区切换，
  区内不存在新旧共存的中间态。
* 解析不经过缓存，不使用 TTL；记录里的 `ttl` 只做原样保留，不影响结论。
* 支持 A 与 CNAME。CNAME 链跨已提交的区追踪，最多 32 跳。
* CNAME 链**离开已提交的区**即视为无法确认（`external_target`）。需要把外部区
  纳入推演时，把它按 `records == new_records` 一并提交即可。
* 所有记录必须属于本区；同一名称不能同时有 A 与 CNAME；区顶点不允许 CNAME；
  同名 CNAME 目标必须一致；A 值必须是 IPv4。违反则返回 422。

### 为什么不是贪心

安全谓词不单调：发布一个区可能同时修好一个域名、又弄坏另一个；一个“当前会断”
的状态也可能被后发布的区修好。因此“每次挑一个当前安全的区”并不保证找到存在的
安全顺序。服务对 **2^n ≤ 256 个状态**做完整深度优先搜索（带记忆化），
一定给出正确结论；无解时在所有等长的安全前缀中挑“卡点失败域名最少”的那个。

## 启动

```bash
docker compose up --build -d
docker compose ps          # 等待 healthy
curl -s http://localhost:8000/healthz
```

OpenAPI 文档：<http://localhost:8000/docs>

镜像以非 root 用户运行，容器只读挂载根文件系统（`read_only: true`、
`no-new-privileges`），并带 `HEALTHCHECK`。

### 不用 Docker 时

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `GET /healthz`

```json
{"status": "ok", "version": "1.1.0"}
```

### `POST /plan`

请求体：

```json
{
  "zones": [
    {
      "name": "a.example.com",
      "records":     [{"name": "www.a.example.com", "type": "CNAME", "value": "svc.b.example.com", "ttl": 60}],
      "new_records": [{"name": "www.a.example.com", "type": "CNAME", "value": "svc2.b.example.com", "ttl": 60}]
    },
    {
      "name": "b.example.com",
      "records":     [{"name": "svc.b.example.com",  "type": "A", "value": "10.20.1.10"}],
      "new_records": [{"name": "svc.b.example.com",  "type": "A", "value": "10.20.1.10"},
                      {"name": "svc2.b.example.com", "type": "A", "value": "10.20.2.10"}]
    }
  ],
  "required_domains": ["www.a.example.com"]
}
```

`records` 是现状，`new_records` 是该区切换后的状态；两者相同表示“这个区不变，
但仍参与解析”。

响应 `status` 有三种：

| status | 含义 |
| --- | --- |
| `safe_order_found` | 存在安全顺序，`order` / `steps` 给出逐步操作与前后解析结果 |
| `already_broken` | 现状就解析不到 IPv4，`fault_chains` 给出故障链 |
| `no_safe_order` | 无完整安全顺序，`safe_prefix` + `blocked_zones` 给出卡点 |

每条失败链都带：

* `category`：`missing_record` / `cname_loop` / `external_target` / `chain_too_long`
* `category_label`：`缺记录` / `成环` / `链出已提交的权威区` / `CNAME 链过长`
* `detail`：缺记录时进一步区分 `nodata`（名称存在但无 A/CNAME）与
  `nxdomain`（名称不存在）
* `chain`：可读链路，例如
  `www.a.example.com --CNAME--> u.b.example.com => 无记录（NXDOMAIN）`
* `trace`：结构化的逐跳记录，便于值班员复制进工单

## 调用示例

仓库自带 4 个场景，可直接用 curl 调用：

```bash
# 1) 存在安全顺序：必须先发 b，再发 a
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/01-safe-order.json | python -m json.tool

# 2) 现状即故障：CNAME 指向一个没有记录的区
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/02-already-broken.json | python -m json.tool

# 3) 无安全顺序：a/b 互为前置，c 可安全先发
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/03-no-safe-order.json | python -m json.tool

# 4) 无安全顺序且卡点同时含“缺记录 + 成环”
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/04-blocked-mixed.json | python -m json.tool
```

场景 1 的响应节选：

```json
{
  "status": "safe_order_found",
  "order": ["b.example.com", "a.example.com"],
  "steps": [
    {"step": 1, "zone": "b.example.com",
     "addresses_before": {"www.a.example.com": ["10.20.1.10"]},
     "addresses_after":  {"www.a.example.com": ["10.20.1.10"]},
     "all_required_resolvable": true},
    {"step": 2, "zone": "a.example.com",
     "addresses_before": {"www.a.example.com": ["10.20.1.10"]},
     "addresses_after":  {"www.a.example.com": ["10.20.2.10"]},
     "all_required_resolvable": true}
  ]
}
```

场景 4 的响应节选：

```json
{
  "status": "no_safe_order",
  "safe_prefix": ["d.example.com"],
  "blocked_zones": [
    {"zone": "a.example.com",
     "categories": [{"category": "missing_record", "label": "缺记录"}],
     "failures": [{"chain": "one.a.example.com --CNAME--> gone.b.example.com => 无记录（NXDOMAIN）"}]},
    {"zone": "c.example.com",
     "categories": [{"category": "cname_loop", "label": "成环"}],
     "failures": [{"chain": "two.a.example.com --CNAME--> keep.c.example.com --CNAME--> keep.c.example.com => 回到 keep.c.example.com，成环"}]}
  ]
}
```

也可以不启动服务、直接跑同一套逻辑：

```bash
python examples/demo.py
```

## 离线抓包核查（DNS 回包缺片）

客户端抓包里 DNS 查询等不到应答时，用这个接口确认回包是否缺片。
上传**经典 PCAP**（以太网 / IPv4 / UDP，≤ 5 MiB；不支持 pcapng），用表单字段
指定 **A 查询帧**和**截止帧**（均为 1 起的抓包帧号，与 Wireshark 一致），
服务核查**查询帧之后、含截止帧**的窗口内的回包。

### 判定逻辑

1. **关联首片**：窗口内按「反向地址 + 反向端口 + DNS 事务号」匹配回包
   **首片**（分片偏移为 0 的片，只有它带 UDP 头和事务号）。
2. **汇集分片**：命中的首片按「源/目的地址 + IPv4 标识（identification）」
   把同组所有分片归拢到一个数据报。
3. **判定完整**：以首片 UDP 长度为准做字节覆盖统计，**分片乱序或重复不影响
   完整与缺片的判定**。
4. **核对问题段**：组装完整后解析 DNS，**问题段与查询一致才返回响应码**
   （同时校验 QR 位与事务号）；不一致则结论为 `question_mismatch`，不返回响应码。
5. **缺片**：有匹配首片但未收全时，按 UDP 长度给出**缺失字节区间**
   （`missing_ranges`，偏移自 UDP 头起算，半开区间）。
6. **无法归属**：窗口内只有非首片（读不到端口和事务号），或同一组地址和
   IPv4 标识下出现**内容不同的首片**时，这些分片列为 `unattributable`。

### 结论（`verdict`）

| verdict | 含义 | 对应帧号位置 |
| --- | --- | --- |
| `answered` | 收到完整应答，问题段一致，`response.rcode` 给出响应码 | `response.frames` |
| `question_mismatch` | 组装完整但问题段/QR/事务号与查询不符，不返回响应码 | `response.frames` |
| `missing_fragments` | 有匹配首片但未收全，`missing[].missing_ranges` 给出缺失区间 | `missing[].frames` |
| `unattributable` | 只有非首片 / 同组不同首片 / 首片无法核验 | `unattributable[].frames` |
| `no_response` | 窗口内未观察到任何匹配的回包分片 | — |

多种情况并存时按上表顺序取头条结论，其余在 `missing` / `unattributable`
列表里完整保留。`unattributable[].reason` 区分
`only_non_first_fragments`（只有非首片）、`conflicting_first_fragments`
（同组不同首片）、`first_fragment_unverifiable`（首片过短或长度非法）。

### 调用示例

仓库自带 8 个抓包样例（`examples/pcap/`，由 `examples/make_pcaps.py` 生成，
可重新生成），每个样例的查询帧都是第 1 帧：

```bash
# 完整应答（未分片）-> answered / NOERROR
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/01-complete-unfragmented.pcap" \
  -F "query_frame=1" -F "cutoff_frame=2" | python -m json.tool

# 分片乱序 + 重复，仍完整 -> answered（判定不受乱序/重复影响）
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/02-complete-fragments-out-of-order.pcap" \
  -F "query_frame=1" -F "cutoff_frame=5" | python -m json.tool

# 中间缺一片 -> missing_fragments，missing_ranges = [{offset: 48, length: 48}]
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/03-missing-fragment.pcap" \
  -F "query_frame=1" -F "cutoff_frame=3" | python -m json.tool

# 只有非首片 -> unattributable / only_non_first_fragments
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/04-only-non-first-fragments.pcap" \
  -F "query_frame=1" -F "cutoff_frame=3" | python -m json.tool

# 同组地址+标识出现不同首片 -> unattributable / conflicting_first_fragments
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/05-conflicting-first-fragments.pcap" \
  -F "query_frame=1" -F "cutoff_frame=5" | python -m json.tool

# 窗口内没有匹配回包 -> no_response
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/06-no-response.pcap" \
  -F "query_frame=1" -F "cutoff_frame=3" | python -m json.tool

# 问题段对不上 -> question_mismatch（不返回响应码）
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/07-question-mismatch.pcap" \
  -F "query_frame=1" -F "cutoff_frame=3" | python -m json.tool

# 完整 NXDOMAIN 应答 -> answered，rcode = 3
curl -s -X POST http://localhost:8000/pcap/dns-response-check \
  -F "file=@examples/pcap/08-nxdomain.pcap" \
  -F "query_frame=1" -F "cutoff_frame=2" | python -m json.tool
```

一键跑全部样例：

```bash
examples/check_samples.sh            # 打向 http://localhost:8000
python examples/demo_pcap.py         # 不启动服务，进程内跑同一套逻辑
```

`missing_fragments` 的响应节选（偏移自 UDP 头起算）：

```json
{
  "verdict": "missing_fragments",
  "missing": [
    {
      "frames": [2, 3],
      "identification": 20483,
      "udp_length": 105,
      "received_ranges": [{"offset": 0, "length": 48}, {"offset": 96, "length": 9}],
      "missing_ranges": [{"offset": 48, "length": 48}],
      "last_fragment_seen": true
    }
  ]
}
```

### 抓包核查的限制

* 只支持经典 PCAP、以太网链路（含 802.1Q 标签）、IPv4、UDP；IPv6、
  TCP 承载的 DNS、pcapng 不在范围内（不满足时按 422 或「非候选帧」处理）。
* 查询帧本身必须是未分片的 DNS A 查询，否则返回 422。
* 帧号 1 起，与 Wireshark `frame.number` 一致；窗口为查询帧之后、含截止帧。
* 因 snaplen 被抓包截断的帧，未捕获字节按「未收到」计入缺片，并在
  `notes` 里标明对应帧号。
* 重叠分片内容冲突时按先捕获的字节组装（判定结论不受影响），并在
  `missing[].overlap_conflict` 标明。

## 测试

```bash
pip install -r requirements-dev.txt
pytest
```

覆盖：安全顺序、必须后发/先发的依赖、现状故障（缺记录 / 成环 / 链出区 /
链过长 / NODATA vs NXDOMAIN）、无解时的最大前缀与逐区卡点、随机小规模实例与
穷举结果的等价性校验、请求校验与 HTTP 状态码；抓包核查覆盖五种结论、
分片乱序/重复不变性、缺失区间计算、IPv4 标识分组、首片冲突、snaplen 截断、
文件校验与 413/422。

## 限制

* 只支持 A / CNAME；AAAA、SRV、通配符等不参与推演。
* 最多 8 个区、每区 256 条记录、最多 64 个必保域名。
* 同一名称的多条 A 记录视为一个 RRset（多个地址任选其一即视为可解析）。
* 不校验外部区真实状态；链出已提交区一律按“无法确认”处理。
