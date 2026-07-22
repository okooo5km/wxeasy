# 机械盘大账号 IO 进一步优化：方案分析与路线图

> **记录时间**：2026-07-22
> **代码基线**：`a3a6d96`（第二轮 perf 之后），配套阅读
> [slow-disk-performance-optimization-2026-07-22-1527.md](slow-disk-performance-optimization-2026-07-22-1527.md)（下称「前记录」，§4 不变量编号沿用它）
> **分析方法**：15 个并行 agent——5 路子系统 IO 成本建模 → 5 个独立角度方案设计 →
> 逐方案对抗性验证（专项核对 §4 不变量、微信并发写、NTFS mtime 滞后、checkpoint 语义）
> **作者**：okooo5km(十里)

回答的问题：在 §4 六条正确性不变量一条不放宽的前提下，机械盘 + 大账号场景还能
从算法机制上砍掉多少 IO。结论：**能，且最大的一刀（§2）此前两轮完全没碰到。**

---

## 0. 结论速览

| # | 方案 | 验证结论 | 复杂度 | 梯队 |
|---|------|---------|--------|------|
| 1 | `_SORTSEQ` 索引改写全部 `create_time` 查询 | viable-with-changes | 低 | **T1 立即做** |
| 2 | `build_wal_index` 大块顺序读 | viable-with-changes | 低 | **T1 立即做** |
| 3 | WAL 帧索引增量追扫（跨重建缓存） | viable | 低 | **T1 立即做** |
| 4 | schema 页电梯预读（工作集记录 + 排序合并预读） | viable | 低-中 | T2（现场数据后） |
| 5 | ShardRouteCache 持久化 + per-table MAX 缓存 | viable-with-changes | 中 | T2（**需拍板**） |
| 6 | contact.db 派生 Names 持久化 | viable-with-changes | 低 | T2（**需拍板**） |
| 7 | 跨连接解密页 LRU 缓存（世代键控） | viable-with-changes | 极高 | T3 暂缓 |
| 8 | WAL 尾部字节探针替代 600s slack | viable-with-changes（改 §4.1） | 高 | T3 暂缓 |
| 9 | 滚动窗口热镜像（最近 N 天） | marginal | 高 | T3 暂缓 |
| — | 全量解密镜像 / WAL 帧解析消息行 / mmap 预读 / rowid 游标 CDC / 错峰、事后预热等 | rejected | — | 不做（§6） |

三场景收益汇总（冷 OS 缓存 + 机械盘口径）：

- **稳态轮询 / 单次查询**：方案 1 是主刀（查询段 1~2 个数量级），2+3+4 压重建段（合计约 3~10×）。
- **冷启动**：方案 5 是主刀（休眠分片 open 全免），1 顺带把 `MAX(create_time)` 全表扫变 3 页下潜。

---

## 1. IO 账本：钱花在哪

第二轮优化后，剩余 IO 由三项构成：

**A. 查询段（主导项）**：`Msg_<md5>` 表的 `create_time` 无索引，
`q_new_messages`（query.rs:3863）、`q_history`（query.rs:1722）、`find_msg_shards`
的 `SELECT MAX(create_time)`（query.rs:1100/1117）全部是全表扫。冷机械盘上大群表
（10⁵~10⁶ 页）单次扫描数十秒到分钟级，且每轮轮询、每次交互查询都重付。
全表扫沿叶链是半顺序读，但同时全表逐页 AES 解密的 CPU 也在白烧。

**B. 重建段（不可消除，只能变便宜）**：§4.3 强制作废护栏（不许动）决定 dirty 分片
每轮必重建连接。每次重建 = WAL 全量重扫（顺序，秒级）+ `sqlite_master` 惰性解析
（10²~10³ 次 4KB 随机读，冷盘 1~10 秒）。方案 1 落地后这就是新地板。

**C. 冷启动**：路由缓存、WAL 索引、Names 全是进程内存，daemon 重启即丢。
`find_msg_shards(since=None)`（q_history/q_search 等 5 处调用点）不跳任何分片，
全分片 open + MAX 全表扫；contact.db 几十万行全表扫挡在 warming_up 窗口里。

---

## 2. 核心发现：`Msg_` 表自带 `_SORTSEQ` 索引（真实库实测）

对本机真实账号 `message_0.db`（100MB、77 张 `Msg_` 表、98469 行）解密探查
schema 与 EQP 的结果，**推翻了此前「消息表无可用索引」的成本模型前提**：

**事实 A**：真实 DDL 为
`Msg_<md5>(local_id INTEGER PRIMARY KEY AUTOINCREMENT, …, sort_seq, create_time, …)`，
带 4 个索引：`_SENDERID` / `_SERVERID` / `_SORTSEQ(sort_seq)` / `_TYPE_SEQ(local_type, sort_seq)`。
实测 `sort_seq = create_time×1000 + 同秒序号`，偏移 `sort_seq/1000 − create_time`
全库范围 **[0, +24] 秒、恒非负**；77/77 张表 `MAX(create_time)` 所在行 == `MAX(sort_seq)` 所在行。
由此有可证包含关系：**`create_time > s ⇒ sort_seq ≥ (s+1)×1000`**。

**事实 B**：`create_time`/rowid 与时间序有真实倒挂（相对运行最大值回退的行占
0.9%~3%，最坏回退 2.1 天，历史回填/漫游补写所致）。**任何「rowid DESC 扫到边界
即停」的裁剪都会漏消息，不许做**——这同时否决了 rowid 游标 CDC 路线（§6）。

EQP 验证（SQLite 3.37；daemon 用 rusqlite 捆绑的更新版，计划只会更好）：

- `WHERE sort_seq > ? ORDER BY sort_seq ASC LIMIT n` → `SEARCH … USING INDEX _SORTSEQ`
- `SELECT MAX(sort_seq)` → covering index 最右下潜，O(树深) ≈ 3 页

**局限**：单一账号归纳。方案 1 的护栏（索引存在性检测 + NULL/0 兜底 + 回退旧 SQL）
就是为版本/账号差异准备的。

---

## 3. 第一梯队（建议立即做）

### 3.1 方案 1：`_SORTSEQ` 改写全部 `create_time` 查询（主刀）

**机制**：给现有 SQL 加索引可用的范围谓词，保留原 `create_time` 谓词做残余过滤，
输出逐行等价、协议/state 格式零改动：

1. 轮询取数（query.rs:3863）：
   `WHERE sort_seq >= (?+1)*1000 AND create_time > ? ORDER BY create_time ASC LIMIT ?`
2. `find_msg_shards` 的 MAX（query.rs:1100/1117）：
   `SELECT create_time FROM [t] ORDER BY sort_seq DESC LIMIT 1`（最右下潜 + 1 次回表）
3. `q_history`（query.rs:1722）：带 since 同 1；无 since 的「最新 N 条」用
   `ORDER BY sort_seq DESC LIMIT M`（M = 2×(limit+offset) 护栏）+ Rust 内按
   create_time 精排，结果数不足回退全扫。

**验证放行条件（必改后放行）**：

- **NULL/0 兜底**：范围谓词会静默排除 `sort_seq` 为 NULL/0/负偏移的行，而 §4.3
  「检查点一旦推进就不重试」意味着漏了就是永久漏。带 since 的改写必须加
  UNION ALL 分支 `(sort_seq IS NULL OR sort_seq <= 0) AND create_time > ?`
  （两个分支都是索引探针，近零成本）；无 since 的 top-M 同样补 NULL/0 探针。
- **按表粒度索引检测**：重扫 `sqlite_master` 时（query.rs:1092/3839，页已在
  pager cache）顺带取 `type='index'`，`_SORTSEQ` 存在性存入 `ShardRouteCache`，
  无索引回退旧 SQL。
- **逐行对拍 + 哨兵**：上线前用真实账号跑新旧 SQL 逐行对拍（不只 oracle 页级对拍）；
  生产加廉价计数器（残余谓词滤掉行数、UNION 兜底分支命中数），异常即回退。
- 可选防御：范围下界再减护栏秒数 G（如 3600），对假想负偏移账号免疫，代价是
  边界多取几行被残余谓词滤掉。

**收益**：查询段耗时 1~2 个数量级（触页数口径是 3~4 个数量级，但全表扫是半顺序读、
索引路径是随机 seek，耗时口径要打折）；冷启动每分片 MAX 从全表扫 → 3 页；
附带砍掉全表逐页 AES 解密的 CPU。大 backlog（数千新消息）时回表最坏仍数百次
随机读，但不会差于现状。

**§4 关系**：六条零触碰（纯 SQL，全部在既有 `hot.with()` 闭包内）。
新引入的风险类别（sort_seq 值语义依赖）用上述兜底分支覆盖。

**注意**：方案 2 的 `MAX(create_time)` 替换的 ≤24s 低估只影响 Meta 诊断
（derive_status 阈值 24h，meta.rs:80），new_state 检查点取自返回行 timestamp
（query.rs:4538），不受影响。

### 3.2 方案 2：`build_wal_index` 大块顺序读

**机制**：现实现每帧 `seek + read(24B)` 跳 4096B（wal_index.rs:196-216）。改为
4~8MB 缓冲循环顺序读整个 `-wal`，内存里解析帧头；salt 过滤、同 pgno 后帧覆盖、
半截尾帧判定等语义逐字不变。

**验证修正（重要）**：原始提案估的「分钟级黑洞」不成立——现行跨步读的帧步长
4120B > 4096B 页粒度，OS demand-paging 实际已把几乎全部 WAL 页按升序拖进缓存。
真实收益是 **2~5× 扫描加速 + 省 2F 次 syscall**，且与现场 WAL 实际尺寸强相关
（前记录 §7 脚本正好采这个数）。「顺序通读暖了 WAL 缓存」的附带收益 ≈ 0
（今天就已成立）。按卫生改造立项，别按救命稻草立项。

**落地要点**：

- 扫描长度必须用打开时的 metadata 快照封顶（现有 `pos + frame_size <= file_len`
  语义保留），扫描中微信追加的新帧必须忽略；
- 中途 EOF（微信 checkpoint TRUNCATE 截短 `-wal`）必须保留现有 fail-loud 报错语义，
  缓冲实现不得把中段 short read 静默当「半截尾帧」成功返回；
- `FILE_FLAG_SEQUENTIAL_SCAN` **不能**加在留存句柄上（该 File 会 move 进
  `WalSource` 被 `read_raw_page` 随机 seek 复用，SEQUENTIAL_SCAN 触发激进
  evict-behind 反伤随机读）——用独立句柄做扫描，或干脆不加 flag；
- 现有 5 个单测当回归护栏，补「长度快照封顶」「中途截断报错」两个用例。

**§4 关系**：零交集，纯实现替换。

### 3.3 方案 3：WAL 帧索引增量追扫（跨重建缓存）

**机制**：WAL 在同一 salt 世代内严格 append-only；reset/checkpoint 必改 header
salt（wal_index.rs「核心坑 1」已依赖此协议）。给 `WxVfs` 加
`Arc<Mutex<WalIndexCache>>` 字段（在 `ensure_vfs_registered` 构造时注入，与 stats
同构；**不是**挂 `VfsRegistration`——`WxVfs::open` 只能访问自身字段），缓存
`{salt1, salt2, 已扫完整帧数 n, frame_offsets, last_commit_pgcnt}`。open 时：
读 32B header → salt 一致且 `file_len ≥ 32+n×4120` ⇒ 只从上次边界继续扫 Δ 帧；
salt 不一致或文件变短 ⇒ 全量重扫（现行为）。

**收益**：dirty 分片每轮重建的 WAL 重扫从 F 帧降到 Δ 帧（通常 1~100，毫秒级）。
冷启动首扫无收益。**这是读真字节的变更检测，不是 metadata 信任**——恰好绕开
600s slack 想防的 NTFS mtime 滞后。

**落地要点**：

- 缓存边界 n 必须是「上次扫完的完整帧数」（while 循环退出时的 pos），半截尾帧
  补全后从该位置重新解析，不能用 file_len 推；
- mid-scan 并发 reset 的 TOCTOU 与现有全量扫同构（帧 salt 不匹配被丢弃），
  不引入新竞态类别，oracle 对拍显式覆盖；
- salt2 碰撞概率 ~2⁻³² 是新增的概率性假设，注释里明说；
- `frame_offsets` 用 `Arc<HashMap>` 写时替换，避免热态高频 open 深拷贝 25k 条目；
- `build_wal_index` 用句柄级 metadata 取长度（已打开 File 的 `.metadata()`），
  无 NTFS 目录项滞后问题，增量判定的 file_len 来源安全。
- 持久化索引摘要到磁盘的延伸：先不做（活跃分片落地即失效，休眠分片在方案 5
  之后根本不会被 open）。

**§4 关系**：六条全不碰，与全量扫结果逐字节等价。是方案 4/7/8 的地基。

---

## 4. 第二梯队（现场数据 / 拍板后做）

### 4.1 方案 4：schema 页电梯预读

**问题**：冷重建慢的本质是 queue depth 1 的指针追逐——SQLite 逐页串行同步读，
OS 电梯调度帮不上忙。S=1000 个 schema 页乱序串行 ≈ 10 秒。

**机制**：记录每个分片重建时实际触碰的**主库**页号集（`pages_from_main`；WAL 页
不预读——WAL 本来就是全量顺序扫）。下次重建同一分片时，在 `spawn_blocking` 的
重建任务内、`ConnParams::open` 之前：页号排序 → 相邻合并（间隙 ≤256KB 并入
同一区间）→ 按偏移升序普通带缓存 `ReadFile` 一趟（2~4 线程消费区间表），只为
暖 OS 缓存，读的字节即弃。页号提示可按 rel_key 持久化（放 daemon 状态目录），
让冷重启也吃到。

**验证修正（两条硬的）**：

- **工作集采集机制要重做**：原始提案「对 ReadStats 做快照差分」不成立——
  `ReadStats.pages_decrypted` 按物理路径**累计**只增（vfs.rs:459-468），重建后
  重解密同页是 no-op，差分近乎空集。可行做法：直接用累计集 + 预算封顶 +
  「schema 扫描窗口截止点」（open + sqlite_master 查询完成后立即快照），避免
  `q_search` 全库扫把页表污染成整库；per-connection 统计需给 VFS 加可换槽位，
  复杂度更高，二期再说。
- **禁用 mmap + `PrefetchVirtualMemory` 整条路线**（原始提案的「快路径」砍掉）：
  文件存在活跃 section object 时 `SetEndOfFile` 失败（`ERROR_USER_MAPPED_FILE`）。
  微信 checkpoint TRUNCATE 截 `-wal`、「存储空间清理」VACUUM 截主库，撞上映射
  窗口会让**微信侧**报 IO 错误。「只读不干扰微信写入」是生存前提，「短窗口」只是
  降概率不是消除。普通带缓存 ReadFile（默认 `FILE_SHARE_READ|WRITE|DELETE`，
  全项目已验证的无干扰路径）配排序区间就能拿到绝大部分电梯收益。

**收益**：机械盘上散布页排序访问典型 2~5×（3~10× 只在局部性强、可合并成大读时）。
纯 advisory：提示过期最坏白读几页，**正确性表面积为零**——真实读取仍走原路径、
仍受快照门控。SSD 上 ≈0，正好目标就是 HDD。加自适应开关：上次重建实测
「毫秒/页 > 阈值（~2ms）」才启用，配 `prefetch = auto|on|off`。

**注意**：预读在 `HotConnHandle::with()` 持 slot 锁期间执行，同分片并发查询会
多等 1~2 秒，可接受但写明。预读预算要小且自适应（目标机器内存本来就紧）。

**§4 关系**：零交集（不参与信任判定、不喂数据进查询路径、`spawn_blocking` 内同步）。

### 4.2 方案 5：ShardRouteCache 持久化 + per-table MAX 缓存 ⚠️ 决策点 1

**机制**：

- `ShardSchemaEntry`（rel_key → `{SourceSnapshot, msg_tables}`）序列化到
  `cache_dir/route_cache.json`（版本号 + db_dir 身份字段，不匹配整体丢弃）。
  加载时机：`DbCache::with_dirs`（cache.rs:112）、server accept 之前直接灌入
  `shard_routes`——此刻无并发，§4.4/§4.5 不被触碰。写回 write-behind
  （put 后 debounce flush，临时文件 + 原子 rename；**Windows 上没有退出钩子**——
  `setup_signal_handler` 整个是 `#[cfg(unix)]`，taskkill 无任何通知，设计上必须
  容忍文件丢最近 30s，内存永远是真相）。
- 扩展：`msg_tables` 升级为 `HashMap<String, Option<i64>>`，把 `find_msg_shards`
  的 MAX 结果按同一快照、同一世代号纪律缓存——今天 Fresh 命中路径每次仍全表扫
  MAX（query.rs:1115-1123），纯浪费；缓存后 Fresh 承载分片连那次 open 都省掉。
  （方案 1 落地后 MAX 已降为 3 页下潜，此扩展收益变小但仍为正。）

**收益**：冷启动 `find_msg_shards(since=None)` 从全分片 open（S=60 并发 4 也是
分钟级，「卡死」本体）→ 只有承载分片 + 近期活跃分片真正 open，休眠分片 2 次
stat + 0 数据 IO，**砍 ~90% 分片 open**。冷启动首轮 `q_new_messages` 从全量作废
→ 精准作废。稳态 ≈ 0 增益（内存缓存已覆盖）。

**代价（必须拍板）**：今天 daemon 重启后首轮 `q_new_messages` 的全量作废
（unresolved 兜底，query.rs:3459）等于对「mtime 滞后超 600s slack」LOW 级残余
窗口的**免费全量重置**；持久化让 changed 会话经旧条目 resolve 成功、精准作废，
这个重置永久消失。具体漏消息路径：会话 X 的表因分片滚动新出现在分片 B，持久化
条目只知道旧分片 A，精准作废只打 A；若 B 恰处 mtime 滞后超 slack 的窗口且 B 有
持久化 Fresh 条目（表集不含新表名），aggregate 零 IO 跳过 B，首条消息随检查点
推进永久漏。概率仍 LOW（滞后主要发生在微信持续持句柄期间，重启多伴随开机、
元数据已落定），但必须写进 §4 当新增已知取舍。折中开关（「经持久化条目 resolve
的会话也计 unresolved」）会把持久化路由首轮炸光、收益归零——两者不可兼得。

验证另指出两个「收窄手段」成色不足，只可当启发式：①「加载时要求安静 ≥1h」与
既有 600s trusted_as_of 高度重叠，近似安慰剂；② page-1 header 校验在 WAL 模式下
file-change-counter 只在 checkpoint 时 bump、逻辑首页可能在 WAL 里，对「备份还原」
只能挡部分情形。

**§4 关系**：§4.1/4.2 逐条复用（无新信任捷径）；§4.4/4.5 不动；新增一条已知取舍
（首轮全量重置被取消），需文档化。

### 4.3 方案 6：Names 持久化 ⚠️ 决策点 2

**机制**：`load_names`（query.rs:234）产出的映射连同 contact.db 的
`SourceSnapshot` 存盘（bincode，不用 JSON——几十万条目 JSON 反序列化本身上秒；
`md5_to_uname` 现场重推导不必存）。启动时快照相等 + 安静期通过 ⇒ 直接反序列化
（亚秒），跳过全表扫；否则照旧后台冷扫。

**收益**：warming_up 窗口从十几秒（几十万行随机页读 + 逐页解密）降到亚秒。
注意「撞 15s 启动超时」是 FIX ④ 之前的旧账，现在 socket 绑定已提前，这只是
可用性改善不是救命。**主要 miss 场景**：开机 → 微信启动同步联系人 → contact.db
被写 → 600s 安静期过不去 → 照旧冷扫；真实命中率待现场数据。

**代价（必须拍板）**：解密后的联系人（备注名、昵称、username、verify_flag）
明文落盘，与「不主动扩大明文面」的项目立场冲突（`all_keys.json` 存的是密钥，
不是现成明文，防御纵深不同）。要么用 enc_key 派生密钥加密缓存文件，要么明确
接受明文面扩大——不能悄悄落。

「先用过期 Names 立刻服务 + 后台刷新」第二档推翻 `Option<Arc<Names>>` 显式拒绝
半成品的设计决策（mod.rs:110-114），等现场命中率数据再议，不悄悄做。

**§4 关系**：几乎零交集（Names 不在消息正确性链路上）。

---

## 5. 第三梯队（暂缓，条件触发）

### 5.1 方案 7：跨连接解密页 LRU 缓存（按 WAL 世代作废）

对重建段 `sqlite_master` 随机读的唯一正面打击（daemon 启动后首建之外全命中
进程内 RAM），但验证抓出一个会**静默读错数据**的竞态，原设计不能上线：新 open
的增量扫逐出 pgno 后，池中按旧索引存活的热连接（immutable 快照，合法存在
10 分钟）miss 后从旧 WAL 偏移读出旧内容、以 `(path, pgno)` 回填，新连接命中
→ 陈旧读。修复必须世代键控（WAL 来源用 `(path, salt世代, 帧偏移)`——同世代
append-only ⇒ 偏移即内容地址；或缓存挂世代号、插入时锁内校验）。另有自反风险：
目标机器恰因内存紧才缓存冷，daemon 再常驻 128MB 可能负优化（swap-in 退化）。
实际工作量 600 行以上 + 专门并发测试基建。**等 §7 现场数据确认 S 是主导项再立项。**

前记录 §8 设想的「朴素增量 WAL 刷新（不重建连接）」维持否决：`immutable=1` 下
偷改 VFS 底下的索引无法保证 pager 重推 dbSize，新 btree 页不可达 ⇒ 静默丢行，
依赖 SQLite 未文档化内部行为。

### 5.2 方案 8：WAL 尾部字节探针替代 600s slack

用「读真字节验证」（salt 比对 + 边界后首帧探测）替换「安静满 600s」启发式。
**这是对 §4.1 的正面修改**，必须以「更强信号替换启发式」专项立项。验证泼冷水：
持续活跃的 tail 分片每轮快照必不相等、直接走无条件重建，探针根本没机会出场
（「§3.1 第①条被结构性消除」言过其实）；真实兑现的是 q_history 同轮双开的
第二次重建（对半砍）和 burst 后安静分片。三个实现陷阱见验证记录：槽位必须记
「建连那一刻」的 salt/边界快照（不能读共享缓存当前值，否则复用旧索引连接 =
陈旧读）；边界后只读第一帧帧头（否则 restart 残留场景退化成百 MB 扫描）；
非 checkpoint 主库直改是残余向量，需顺手比对主库句柄级 (len, mtime)。
**方案 1+4 落地后边际收益可能不值这个开口，暂缓。**

### 5.3 方案 9：滚动窗口热镜像（最近 N 天）

daemon 自有 SQLite 只存最近 N 天解密消息，摄入复用轮询管线。验证判 marginal：
路由规则「请求窗口 ⊆ 镜像覆盖窗口」把旗舰场景（`wx history` 无 since 下界，
前记录 §8 故意保留的全量语义）挡在镜像外；乱序写入（手机同步以新 local_id 插
旧 create_time 行）造成摄入缺口 = 镜像与实时路径永久分歧；content_zstd 是压缩
不是加密，明文落盘问题与全量镜像同性质只是体量小；sender 解析是分片本地的
（`load_id2u` 依赖分片连接），摄入时就得落 username。立项前置三硬条件：镜像
加密方案、乱序缺口的产品决策、sender 摄入时解析。**方案 1 落地后轮询痛点已解，
剩余收益面太窄，不立项。**

---

## 6. 明确否决（连同理由，防止将来重提）

1. **全量解密镜像**：踩「无整库落盘解密」红线（`full_decrypt` 被退役正是前车之鉴，
   cache.rs:141-199 是遗迹不是接口）；对轮询痛点零边际收益；摄入缺口使漏消息
   从「可被全表扫捞回」恶化为「永久不可见」，对账系统复杂度不亚于镜像本身。
2. **从 WAL 帧解析消息行**：btree 页无父指针、微信库无 ptrmap ⇒ 页→表归属无解；
   逆向 record 反序列化 + zstd + overflow 链无 oracle 可证；且 session.db 已免费
   提供变更定位，想省的成本不存在。
3. **rowid 游标 CDC**：被事实 B（2.1 天时间倒挡）和方案 1 双重取代——SORTSEQ
   给出同样的 IO 形状、语义正确、复杂度百分之一，且无游标推进的永久漏消息红线。
4. **mmap + `PrefetchVirtualMemory`（对任何微信文件）**：`ERROR_USER_MAPPED_FILE`
   会让微信侧写入报错，生存前提问题，「短窗口」不算消除。
5. **WAL 索引持久化到磁盘**：活跃分片落地即失效；休眠分片在方案 5 后不会被 open；
   剩余场景 WAL 扫是顺序 IO 不是痛点。
6. **session.db 任何缓存**：§4.3 白纸黑字，碰了就是在漏消息护栏上开洞。
7. **轮询错峰**（daemon 无内置轮询循环，节奏由调用方驱动，摊延迟不省 IO）、
   **事后预热下一轮**（分钟级间隔下预热页活不到下轮，白付全额 IO）、
   **主库尾部顺序扫**（schema 页散布全文件；新写在 `-wal` 不在主库尾）、
   **句柄 flag 调优**（RANDOM_ACCESS 关掉近邻预读反而可能变慢）、
   **VFS 通用读合并/预读**（pager 逐页请求，跨页请求几乎不出现）。
8. **冷启动扫描降 IO 优先级**：事实性错误——`find_msg_shards(since=None)` 同步跑
   在请求路径上，降它的优先级就是饿死用户正在等的那次查询。并发度 4 的标定问题
   收缩为：只加 `scan_concurrency` 配置项（默认 4，需同步改 query.rs:874-904 的
   「不做配置项」决策注释），拿现场数据标定，放弃自动探测。

**q_search 的替代线索**：微信自带 `message_fts.db` 全文索引分片（meta.rs:111 注释
证实存在，当前被分片发现逻辑显式排除，密钥已在 `all_keys.json`）。若机械盘上的
搜索是真需求，先调查只读复用它——比造任何镜像便宜一个量级。

---

## 7. 需要拍板的决策点

| # | 决策 | 选项 | 影响 |
|---|------|------|------|
| 1 | 路由持久化 vs 首轮全量重置护栏（§4.2） | A 要冷启动收益，接受 LOW 残余窗口寿命延长（写进 §4）；B 不做方案 5 | A 是冷启动主刀；B 则冷启动只剩方案 1/4 的收益 |
| 2 | Names 缓存明文（§4.3） | A 加密缓存文件（推荐）；B 接受明文；C 不做 | 只影响重启后 warming_up 窗口 |
| 3 | T1 三刀是否即刻开工 | 是 / 否 | 无风险决策，纯排期 |

---

## 8. 落地前置验证清单

1. **真实账号 schema 复核**（方案 1 的软肋）：在至少一个其他账号/微信版本上跑
   `PRAGMA table_info / index_list`，确认 `_SORTSEQ` 存在与 sort_seq 值语义；
   护栏（按表检测 + 回退）已设计，但多一个样本多一分底气。
2. **新旧 SQL 逐行对拍**：真实账号全表对比，含 NULL/0 sort_seq 行的召回。
3. **现场规模数据**（前记录 §7 脚本）：分片数（决定方案 5 价值）、WAL 尺寸
   （决定方案 2/3 价值）、contact.db 体积（决定方案 6 价值）、db_storage 占比。
4. **oracle 对拍新增用例**：方案 3 的 mid-scan 并发 reset；方案 2 的长度快照
   封顶与中途截断报错。

---

## 9. 与 §4 不变量关系汇总

| 方案 | §4.1 门控 | §4.2 mtime==0 | §4.3 真相源 | §4.4 无 await | §4.5 世代号 | §4.6 spawn_blocking |
|------|-----------|---------------|-------------|---------------|-------------|---------------------|
| 1 SORTSEQ | 不碰 | 不碰 | 不碰 | 不碰 | 不碰 | 不碰（既有闭包内） |
| 2 WAL 大块读 | 不碰 | 不碰 | 不碰 | 不碰 | 不碰 | 不碰 |
| 3 WAL 增量索引 | 不碰（读真字节） | 不碰 | 不碰 | 不碰 | 不碰 | 不碰 |
| 4 电梯预读 | 不碰（advisory） | 不碰 | 顺护栏做 | 不碰 | 不碰 | 内部执行 |
| 5 路由持久化 | 复用 | 复用 | 增强+新取舍 | 不碰 | 构造期灌入 | 不碰 |
| 6 Names 持久化 | 复用语义 | 复用 | 无关 | 不碰 | 不碰 | 不碰 |
| 7 页 LRU | 精神一致需论证 | 不碰 | 不碰 | 不碰 | 新增世代键 | 不碰 |
| 8 WAL 探针 | **正面修改** | 保留 | 不碰 | 不碰 | 不碰 | 临界区内同步 |

新增不变量候选（若方案 5 落地）：「持久化路由条目的寿命 = 缓存文件寿命；daemon
重启不再构成全量重置。残余窗口同 §4 已知取舍第一条，概率 LOW。」

---

## 附：分析产物位置

15 个 agent 的完整提案与逐条验证记录（含被否决方案的完整论证）在本机
`%LOCALAPPDATA%\Temp\claude\...\tasks\parsed\` 下（persist-derived / cdc-mirror /
wal-tailing / btree-io / scheduling 五份），临时目录不入库，本文档是唯一存档。
