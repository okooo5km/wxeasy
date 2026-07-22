# 慢盘 / 大账号性能优化记录

> **记录时间**：2026-07-22 15:27
> **实测数据采集**：2026-07-22（开发机，见 §5 的规模前提）
> **涉及提交**：`bc73dff`、`a3a6d96`
> **代码基线**：`wxeasy` 0.3.0，`cargo test` 191 passed
> **作者**：okooo5km(十里)

面向「机械硬盘 + 大体量微信数据」场景的两轮 daemon 性能优化的完整记录：根因、
改动、必须守住的正确性不变量、实测数据、验收步骤。

相关提交：

| 提交 | 主题 |
|------|------|
| `bc73dff` | 分片路由缓存 + mtime 门控热连接复用降低慢盘 IO |
| `a3a6d96` | 大账号多分片下的轮询 IO 与冷启动可用性优化 |

---

## 1. 背景与症状

上游用户在**低速机械硬盘**上使用时：

- 「获取消息」环节直接卡死，基本不可用；
- daemon「暖机」耗时很长，甚至撞上 CLI 的 15 秒启动超时。

该用户的微信聊天记录数据约 **120GB**。

关键前提：wxeasy 运行时**只有一条路径**——自定义只读 VFS 按需解页
（`DbCache::conn_params` → `ConnParams::open` → `vfs::open_conn`）。旧的
`full_decrypt`（整库落盘解密）在运行时已是死代码，仅 `#[cfg(test)]` 的
oracle 对拍在用。

---

## 2. 第一轮：消除「每轮打开所有分片」（`bc73dff`）

### 2.1 根因

`find_msg_shards` 为了判断「哪个分片装着这个会话的 `Msg_<md5>` 表」，会对每个
未被跳过的分片都 `open()` 一次。而每次 `open()` 都会让 SQLite 解析该分片庞大的
`sqlite_master`（一个分片里可能有成百上千张 `Msg_` 表），其 schema 页散落在整个
库文件里 —— 在机械盘上就是随机 seek 风暴。

放大点：

1. **`q_new_messages` 按会话逐个处理**，每个 changed 会话都单独调一次
   `find_msg_shards` ⇒ **O(会话数 × 活跃分片数)** 次全库 schema 解析。这是卡死主因。
2. 命中分片被 **open 两次**（`find_msg_shards` 求 `MAX(create_time)` 一次、取数
   循环再一次），连接用完即弃。
3. **零缓存**：没有结果缓存、没有跨连接的解密页缓存、没有「分片 → 会话」路由记忆，
   每轮轮询都从零冷读冷解密。
4. `shard_skippable` 的 24 小时 slack 只能跳过整天没动过的死分片，活跃分片一个不跳。

### 2.2 改动

- **分片 → 会话路由缓存**（`ShardRouteCache`）：记录每个分片里有哪些 `Msg_` 表，
  按分片 mtime 失效。命中时直接定位承载分片，不再逐个 `open()` 试探。
- **mtime 门控的热连接复用**（`HotConnPool`）：daemon 为访问过的分片保留常驻只读
  连接（含 SQLite pager 页缓存），`SourceSnapshot` 逐字段相等才复用，变了整体丢弃重建。
- **失效判定加固**：
  - 失效键除 mtime 外**并入文件长度**（`db_len` / `wal_len`），WAL 追加写必然改变长度，
    是比 mtime 更快反映「内容变了」的信号；
  - 新增 `HOT_CACHE_FRESHNESS_SLACK_SECS = 600` 新鲜度 slack：源文件「安静满 10 分钟」
    才允许信任缓存；
  - `db_mtime == 0`（metadata 读取失败）一律视为未知、永不信任；
  - 区分「**没有 `-wal` 文件**」（已 checkpoint 的休眠分片，合法可信）与
    「**`-wal` 存在但读取失败**」（未知不可信），前者可正常命中缓存。
- **焊死漏消息**（关键）：`q_new_messages` 每轮都新读 `session.db`（内容可靠、不走缓存），
  在查消息**之前**把「承载了 changed 会话的分片」强制作废，逼其现场重开读真字节，
  绕开 NTFS 跨进程 mtime 可见性滞后。定位不到承载分片的（疑似全新会话）则本轮全量作废
  重发现。
- **竞态防护**：引入作废世代号（`route_generation`），`put_shard_schema` 回写时世代号
  变了就丢弃；世代号的自增与校验都在 `shard_routes` 同一把锁的临界区内完成，两者严格串行。
- 消除 `q_stats` / `q_attachments` / `q_search` / `q_members` 降级路径上的残留双开。

---

## 3. 第二轮：面向 120GB 多分片规模（`a3a6d96`）

第一轮之后做了一次专门的规模分析，结论是**不够**——开发机账号只有 1 个分片，
以下四个瓶颈在结构上根本测不出来。

### 3.1 根因

1. **600 秒 slack 让活跃分片永远无法被信任**（最严重，且与分片数无关）。
   被监控的活跃群、5 分钟一轮 ⇒ 那个 tail 分片永远处在「最近 10 分钟被写过」状态，
   永远过不了 `trusted_as_of` 的信任窗口。而 `find_msg_shards` 与 `q_new_messages`
   查询循环**各自独立取一次热连接、各判一次 stale** ⇒ 每轮对同一活跃分片重开
   **≈2×C 次**（C = 本轮有新消息的群数），随监控群数**线性恶化**。
2. **`MAX_HOT_SHARDS = 12` 是固定常量**，与大账号的真实分片数量级不匹配，
   LRU 会把本可复用的分片提前踢出去。
3. **`find_msg_shards` 分片循环严格串行**，`since = None` 时不跳过任何分片，
   daemon 重启后路由缓存为空 ⇒ 对全部分片串行 `open()` + 扫 schema。
4. **daemon 就绪信号被 `contact.db` 全表扫描挡着**：`load_names` 排在
   `server::serve`（socket/pipe 绑定）之前，CLI 侧只有固定 15 秒
   `STARTUP_TIMEOUT_SECS`，慢盘上可能直接超时。

### 3.2 改动

- **按分片聚合**：`q_new_messages` 从「按会话逐个处理」重构为
  `aggregate_new_messages_by_shard`——先把本轮 changed 会话按承载分片分组，
  每个分片**只取一次热连接**，在**同一次 `hot.with()` 闭包内**完成 schema 发现与
  该分片上全部会话的消息查询。活跃分片每轮 open 次数 **2×C → 1**。
- **连接池容量伸缩**：容量由固定 12 改为按实际分片数 `clamp(12, 64)`；单连接 pager
  缓存反比缩放（容量 64 时降到 4MiB），内存包络维持 **≤ 256MiB**。
- **限流并发扫描**：`find_msg_shards` 与 `q_search` 的分片扫描由串行改为 `JoinSet`
  并发，并加 `MAX_CONCURRENT_SHARD_SCANS = 4` 上限。
- **冷启动可用性**：socket/pipe 绑定提前到 `contact.db` 加载之前；联系人改为后台
  异步加载；未就绪时返回 `warming_up` 状态（**不是**空联系人、**不是**错误），
  CLI 侧识别后在预算内重试。

---

## 4. 正确性不变量（改这块代码前必读）

这些是历次修复中用真实事故换来的护栏，**不得为性能放宽**：

1. **一切缓存复用严格按 mtime + 长度门控。** 微信写新消息必然 bump 对应分片
   `.db` 或 `.db-wal` 的 mtime/长度；只有 `SourceSnapshot` 逐字段相等**且**已安静满
   `HOT_CACHE_FRESHNESS_SLACK_SECS` 才允许信任。任何不确定一律重建。
2. **`mtime == 0` 永远不可信。** 它无法区分「文件不存在」与「metadata 读取瞬时失败」，
   一律当未知处理（与 `source_freshness_secs` 的既有语义对称）。
   但「**没有 `-wal` 文件**」是合法已知状态，不在此列。
3. **`session.db` 是监控路径的可靠真相源。** 它每轮新读、不走缓存。changed 会话的
   承载分片必须在查消息**之前**被强制作废；定位不到承载分片时必须全量作废兜底
   （防止全新会话首条消息因 mtime 滞后被永久漏收 —— 检查点一旦推进就不会重试）。
4. **判定段不得引入 `.await`。** `find_msg_shards` 的逐分片判定必须同步完成，
   这是世代号 TOCTOU 校验成立的前提。并发化时信号量的 `.await` 必须放在**已经
   spawn 出去的任务内部**，绝不能写在判定循环里。
5. **世代号的自增与校验必须在 `shard_routes` 同一把锁的临界区内。** 保证
   `invalidate_shard` 与 `put_shard_schema` 严格串行，任一顺序都不会留下被复活的过期条目。
6. **`HotConnHandle::with()` 只能在 `spawn_blocking` 内部调用**，不得跨 `.await`
   持有 `Connection`（`SQLITE_OPEN_NO_MUTEX` 下绕过它直接操作池化连接是 **UB**，不是 panic）。

### 已知、故意保留的取舍

- **`invalidate_shard` 清路由与逐出热连接是两把独立锁、非原子。** 合并成跨锁原子操作会
  引入锁顺序死锁风险，比它想堵的亚微秒窄缝更糟。残余窗口需「mtime 可见性持续滞后超过
  slack + 精准并发撞窗」才可能现形，且有热连接自身的实时快照双门控兜底。
- **`shards_to_force_invalidate` 的全量作废兜底**是经过论证的漏消息护栏，
  收窄它容易直接导致新会话首条消息永久漏收，**不要为性能动它**。

---

## 5. 实测数据

> 采集时间：**2026-07-22**。这些数字与当时的账号规模、硬件、OS 缓存状态强相关，
> 换机器或换账号后需重新采集，不要直接沿用做结论。

开发机账号规模：`db_storage` 354MB、**只有 1 个消息分片**（`message_0.db` 90MB）、
7493 联系人。CLI 固定开销（`daemon status`，不查库）约 **80ms**。

| 场景 | 冷（首次） | 暖（稳态） |
|------|-----------|-----------|
| SSD，OS 缓存也冷 | `history` **905ms** | ~390ms |
| SSD，OS 缓存已热 | `history` 408ms | 397ms |
| 机械盘（数据移到 D 盘后） | `history` **746ms** | ~430ms |
| 机械盘 `new-messages`（返回 200 条） | 825ms | ~650ms |

单元测试：**191 passed / 0 failed / 3 ignored**（3 个 ignored 是需要真实微信数据 +
环境变量的 oracle 对拍用例）。

### 这些数字的正确读法

- **905ms 那次是唯一的「真冷读」**（构建后文件尚未进 OS 缓存）。热连接省下的 ~515ms
  正是「解析全库 `sqlite_master` + 建 WAL 索引 + 冷页读解密」。
- **OS 缓存一旦热了，SSD 上冷暖差只剩 ~10ms** —— 因为 OS 页缓存已经把重活干了。
  这解释了为什么开发机不卡、部署机卡：**机械盘 + 内存吃紧时 OS 缓存频繁被挤掉**，
  每轮轮询都退回冷页随机读，而热连接把解密页常驻进程内 RAM，直接跳过这一整轮 IO。
- **机械盘上的 746ms 同样不是真磁盘冷读** —— 数据是刚跨盘移动过去的，移动过程
  已把文件读进了 OS 缓存。真·机械盘冷读 90MB 散落页应是**数秒级**。

### 本记录**没有**验证的部分（重要）

- **多分片规模下的真实表现**。所有实测都在 1 个分片的账号上完成，
  「开 N 个分片」的爆炸与其修复效果**只有单元测试和代码推演背书**。
- **真正的「卡死」从未被复现** —— 需要 OS 缓存冷 + 真实大账号。

---

## 6. 验收步骤（机械盘机器）

```bash
cargo build --release
```

把 `target/release/wxeasy` 部署到目标机器后：

1. **重启系统**（这是清空 OS 文件缓存最干净的办法，否则测不到真磁盘冷读）。
2. 冷读一次并看实际扫了几个分片：
   ```
   wxeasy history "<某活跃群名>" --debug-source --json
   ```
   关注 `meta.shards_scanned` —— 路由缓存生效时应只等于承载分片数（通常 1~2），
   而不是分片总数。
3. **紧接着再查一次同一个群**，对比耗时。冷暖差就是热连接省下的量；机械盘 +
   冷 OS 缓存下，这个差应远大于开发机上的数百毫秒。
4. 连续跑几轮 `wxeasy new-messages`，确认稳态耗时平稳、不随监控群数线性恶化。
5. **盯几天不要漏报**：确认 `session.db` 强制作废那条防线在真实 mtime 滞后下确实扛住了。

---

## 7. 客户现场诊断（只读，不改任何东西）

在目标机器上收集真实规模，用于判断第二轮的 ②③ 两刀吃到多少收益：

```powershell
$db=(Get-Content "$env:USERPROFILE\.wxeasy\config.json" -Raw|ConvertFrom-Json).db_dir
"db_storage : $db"
"数据库总大小: {0:N1} GB" -f ((Get-ChildItem $db -Recurse -File -EA SilentlyContinue|Measure-Object Length -Sum).Sum/1GB)
$sh=Get-ChildItem "$db\message" -Filter "message_*.db" -EA SilentlyContinue|?{$_.Name -match '^message_\d+\.db$'}
"消息分片数  : $($sh.Count)  合计 {0:N1} GB" -f (($sh|Measure-Object Length -Sum).Sum/1GB)
$sh|Sort-Object Length -Desc|Select-Object -First 8|%{ "   {0,-18}{1,8:N0} MB" -f $_.Name,($_.Length/1MB) }
"contact.db  : {0:N0} MB" -f ((Get-Item "$db\contact\contact.db" -EA 0).Length/1MB)
$w=Get-ChildItem $db -Recurse -Filter "*.db-wal" -EA SilentlyContinue
"WAL 文件    : $($w.Count) 个, 合计 {0:N0} MB, 最大 {1:N0} MB" -f (($w|Measure-Object Length -Sum).Sum/1MB),(($w|Measure-Object Length -Max).Maximum/1MB)
```

三个数字的意义：

- **分片数** —— 决定连接池伸缩与并发限流的价值。只有 3~5 个的话，真正救命的是
  「按分片聚合」那一刀；真有几十个，第二轮才是关键。
- **`db_storage` 占总量的比例** —— 微信数据的大头通常是附件图片视频，不参与解密。
  如果 120GB 里数据库只占一小部分，实际情况比预估乐观得多。
- **`contact.db` 体积** —— 直接决定冷启动可用性那一刀是否必要。

日志侧交叉验证（`[shards] xxx: 按源文件 mtime 跳过 N/M 个冷分片`）可以确认 24 小时
门槛在真实机器上是否如预期生效。

---

## 8. 已知残留与后续

- **`aggregate_new_messages_by_shard` 只覆盖 `q_new_messages`**。`q_history` 手动补查
  走的仍是 `find_msg_shards`，且没有 `session.db` 这个真相源可用，无法照搬同一套
  强制作废机制。
- **`wx history` 不带 `--since` 时仍是全量语义**（只加了 stderr 提示，未改默认值）：
  PriceKeeper 的就绪探测依赖「无时间下界返回最新一条」，改默认会让近期无消息的会话
  被误判为探测失败。
- **`warming_up` 网关目前对除 `Ping` / `ReloadConfig` 外的全部请求一刀切**，没有逐个
  查询函数做「是否真依赖 `contact.db` 派生字段」的细粒度审计。
- **`HOT_CACHE_FRESHNESS_SLACK_SECS = 600` 与 `MAX_CONCURRENT_SHARD_SCANS = 4`
  都是论证后的经验值，未经真实大账号测量标定。** 拿到现场数据后值得重新评估。
- 若未来仍在冷缓存机械盘上观察到每轮重开活跃分片的开销，可评估「为活跃分片做增量
  WAL 刷新、避免整连接重建」，但这会显著增加 VFS 复杂度，需谨慎权衡。
