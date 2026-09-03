# WAL 提交边界与分片扫描瞬时失败（v0.3.4，2026-09-03）

> 作者: okooo5km(十里)

## 现象

PriceKeeper 用户机（23 个高频报价群，一天约 190 万条报价）从 2026-08-11 起零星出现、
2026-08-31 起 90% 的 `history` 查询失败，错误串只有一句：

```
扫描 25231806506@chatroom 的消息分片失败
```

- 失败在 100 多毫秒内返回，不是超时、不是磁盘慢（NVMe，16GB WAL 全量扫描 17 秒）。
- 同一个群同一个下午一会儿成功一会儿失败，daemon 冷启动后最差、越跑越好。
- 消息分片 2 → 5 个、密钥 19 → 22 个，写入量一直在涨。
- 内层根因文本完全看不到，daemon.log 也没有。

## 根因

三层叠加：

1. **`server.rs` 用 `e.to_string()` 回错误。** anyhow 的 `Display` 只打最外层 context，
   `find_msg_shards` 那句 `扫描 X 的消息分片失败` 把真正的 `database disk image is
   malformed` / HMAC 失败全吞了。
2. **`wal_index.rs` 把未提交事务的尾部帧也采纳进视图。** 旧"核心坑 3"是刻意的：只要
   salt 匹配就采纳，与 `crypto::wal::apply_wal` 一致。SQLite 自己的读者只读最后一个
   commit 帧之前的内容；高频写入下几乎每次 `open()` 都会抓拍到微信正在写、还没 commit
   的事务尾巴，B-tree 页撕裂，`prepare(sqlite_master)` 直接报错。写得越猛撞得越多。
3. **调用方不传 `--since`**，daemon 每次都要碰全部分片，任一分片撕裂全员失败（这一层在
   PriceKeeper 侧修）。

## 修复

- `daemon/wal_index.rs::scan_wal_frames`：salt 匹配帧先进 `pending`，遇到
  `commit_pgcnt != 0` 才整体采纳；返回的 `scan_end` 停在最后一个 commit 帧之后，尾部未
  提交帧不进索引、不计数，下次续扫从提交边界重读（事务提交后自然采纳，回滚后被同
  salt 新帧覆盖也能读到正确内容）。增量缓存与磁盘持久化沿用同一个 `scan_end`，语义
  自洽。
- `crypto/wal.rs::apply_wal`：同样只应用已提交帧，oracle 对拍语义保持一致。
- `daemon/query.rs::find_msg_shards`：分片扫描失败先隔 50ms 原地重试一次（`with()`
  失败已丢弃连接，重试会重新 open、重新读 WAL header），仍失败才上抛，错误串带分片
  相对路径：`扫描 <chat> 的消息分片 <rel_key> 失败: <内层原因链>`。
- `daemon/server.rs`：`Response::err(format!("{e:#}"))` 完整错误链回传，并写一行
  `[server] 请求失败: …` 到 daemon.log。
- `daemon/mod.rs`：daemon 侧 `eprintln!` 统一带本地时间戳（macro 文本作用域覆盖全部
  子模块），daemon.log 终于能和 PriceKeeper 调试日志对齐时间线。CLI 侧 stderr 不变。

## 测试

- `wal_index.rs` 新增 `uncommitted_tail_is_excluded_until_commit_then_adopted_incrementally`：
  已提交事务 + 未提交尾巴 → 尾巴整体排除、`scan_end` 停在 commit 边界、pgno 仍指向已
  提交版本；补上 commit 帧后增量续扫从边界重读，整个事务一起采纳且后写覆盖先写。
- `no_commit_frame_yields_none_last_commit_pgcnt` 收紧：未提交帧不计数、不进索引。
- 全套 242 个单测通过。
