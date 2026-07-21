use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config;
use crate::crypto;
use crate::crypto::wal;

use super::vfs;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MtimeEntry {
    db_mt: u64,
    wal_mt: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    db_mtime: u64,
    wal_mtime: u64,
    decrypted_path: PathBuf,
}

/// `DbCache::get_with_mode()` 本次解析 rel_key 时实际走了哪条路径。
///
/// latency tier:
/// - `CacheHit`：~0ms，只返回已有解密产物
/// - `WalIncremental`：典型 <10s，只在 cached DB 上增量 apply WAL
/// - `FullDecrypt`：最慢路径，大库上可能到 ~120s
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Path 1：主 `.db` 和 WAL 都没变，直接命中缓存。
    CacheHit,
    /// Path 2：主 `.db` 没变、只有 WAL 变了，在 cached DB 上增量 apply。
    WalIncremental,
    /// Path 3：主 `.db` 变了或缓存 miss，重新 full decrypt。
    FullDecrypt,
}

impl CacheMode {
    /// 手工固定为 snake_case 字符串，避免未来给 enum 直接 derive `Serialize`
    /// 时静默改变 wire 形态。
    ///
    /// 迁移后 `query.rs` 不再调用它（VFS 路径下没有分级缓存模式的概念了），
    /// 只在非 `test` 构建下才是"死代码"——`cargo test` 里 `vfs_oracle.rs`
    /// 仍然经 `DbCache::get`/`get_with_mode` 走这条旧路径做 oracle 对拍。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            CacheMode::CacheHit => "cache_hit",
            CacheMode::WalIncremental => "wal_incremental",
            CacheMode::FullDecrypt => "full_decrypt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheResolve {
    pub path: PathBuf,
    /// 同 [`CacheMode::as_str`]：`query.rs` 迁移后不再读这个字段，只有
    /// `#[cfg(test)]` 的 oracle 对拍还在用（`derive(Debug, Clone)` 会让
    /// dead_code lint 忽略字段本身的读取分析，这里显式加 `allow` 只是为了
    /// 让非 test 构建的告警更干净）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub mode: CacheMode,
}

/// 解密后数据库的 mtime-aware 缓存
///
/// 当数据库文件（.db）或 WAL 文件（.db-wal）的 mtime 发生变化时，
/// 自动重新解密并更新缓存。跨进程重启可通过持久化 mtime 文件复用已解密的 DB。
pub struct DbCache {
    db_dir: PathBuf,
    cache_dir: PathBuf,
    mtime_file: PathBuf,
    all_keys: HashMap<String, String>, // rel_key -> enc_key(hex)
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
    /// 优化 A：分片 → 会话路由缓存（`query.rs::find_msg_shards` 用）。
    shard_routes: ShardRouteCache,
    /// 优化 B：mtime 门控的热连接池（`query.rs` 热路径查询用）。
    hot_conns: HotConnPool,
}

impl DbCache {
    pub async fn new(db_dir: PathBuf, all_keys: HashMap<String, String>) -> Result<Self> {
        Self::with_dirs(db_dir, config::cache_dir(), config::mtime_file(), all_keys).await
    }

    /// 注入 `cache_dir` / `mtime_file`（测试用 + 生产 `new()` 复用）
    pub(crate) async fn with_dirs(
        db_dir: PathBuf,
        cache_dir: PathBuf,
        mtime_file: PathBuf,
        all_keys: HashMap<String, String>,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(&cache_dir).await?;

        let cache = DbCache {
            db_dir,
            cache_dir,
            mtime_file,
            all_keys,
            inner: Arc::new(Mutex::new(HashMap::new())),
            shard_routes: ShardRouteCache::new(),
            hot_conns: HotConnPool::new(),
        };

        cache.load_persistent().await;
        Ok(cache)
    }

    /// 数据库根目录（即 `<wxchat_base>/db_storage`）。
    /// 上层（attachment resolver）需要 `db_dir.parent()` 来定位 `msg/attach/...` 解密图片。
    pub fn db_dir(&self) -> &Path {
        &self.db_dir
    }

    fn cache_file_path(&self, rel_key: &str) -> PathBuf {
        let hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        self.cache_dir.join(format!("{}.db", hash))
    }

    /// 从持久化文件加载 mtime 记录，复用未过期的解密文件
    async fn load_persistent(&self) {
        let mtime_file = &self.mtime_file;
        let content = match tokio::fs::read_to_string(&mtime_file).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let saved: HashMap<String, MtimeEntry> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };

        let mut inner = self.inner.lock().await;
        let mut reused = 0usize;
        for (rel_key, entry) in &saved {
            let dec_path = PathBuf::from(&entry.path);
            if !dec_path.exists() {
                continue;
            }
            let db_path = self.db_dir.join(
                rel_key
                    .replace('\\', std::path::MAIN_SEPARATOR_STR)
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            );
            let wal_path = wal_path_for(&db_path);

            let db_mt = mtime_nanos(&db_path);
            let _wal_mt = if wal_path.exists() {
                mtime_nanos(&wal_path)
            } else {
                0
            };

            // 只要主 .db 没变，就把 cached 产物载回来。
            // 如果 WAL mtime 变了，后续 `get()` 会自动走 Path 2：在已有 cached DB 上增量 apply_wal，
            // 而不是 daemon 重启后第一条请求又退回全量解密。
            if db_mt == entry.db_mt {
                inner.insert(
                    rel_key.clone(),
                    CacheEntry {
                        db_mtime: db_mt,
                        // 保留"cached 产物构建时看到的 wal_mtime"，让 `get()` 去比较当前 WAL
                        // 是否发生了变化，从而决定 exact-hit 还是 WAL 增量。
                        wal_mtime: entry.wal_mt,
                        decrypted_path: dec_path,
                    },
                );
                reused += 1;
            }
        }
        if reused > 0 {
            eprintln!("[cache] 复用 {} 个已解密 DB", reused);
        }
    }

    /// 持久化 mtime 记录
    async fn save_persistent(&self) {
        let mtime_file = &self.mtime_file;
        let inner = self.inner.lock().await;
        let data: HashMap<String, MtimeEntry> = inner
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    MtimeEntry {
                        db_mt: v.db_mtime,
                        wal_mt: v.wal_mtime,
                        path: v.decrypted_path.to_string_lossy().into_owned(),
                    },
                )
            })
            .collect();
        drop(inner);

        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = tokio::fs::write(&mtime_file, json).await;
        }
    }

    /// 获取解密后的数据库路径
    ///
    /// 三种命中路径：
    /// 1. 主 `.db` 和 WAL mtime 都未变 → 直接返回缓存路径
    /// 2. 主 `.db` 未变、WAL mtime 变了 → 在已有 cached 产物上**增量** `apply_wal`
    ///    （apply_wal 是幂等的：旧帧 redo 同样的 page 写入，新帧追加生效；不重新 full_decrypt）
    /// 3. 主 `.db` mtime 变了 → 重新 `full_decrypt` + `apply_wal`
    ///
    /// WeChat 在写消息时只 append WAL（除非触发 checkpoint），因此 path 2 是常态；
    /// 这条路径把"每次请求都全量解密 ~1.8GB DB（~120s）"压到"只解 WAL 帧（典型 < 10s）"。
    pub async fn get(&self, rel_key: &str) -> Result<Option<PathBuf>> {
        Ok(self.get_with_mode(rel_key).await?.map(|r| r.path))
    }

    /// 加密源文件（主 `.db` 与 `.db-wal` 取较新者）的最后写入时间，unix 秒。
    ///
    /// 不触发任何解密——只读文件 metadata，供调用方在解密前判断"这个分片最近有没有
    /// 被 WeChat 写过"。语义上等价于"这个分片最后一次可能获得新消息的时间"：WeChat
    /// 写消息必然要 append/覆盖对应的 `.db` 或 `.db-wal`，从而 bump 其 mtime。
    ///
    /// 返回 `None` 表示"未知，调用方不允许据此跳过该分片"：
    /// - 主 `.db` 不存在，或其 metadata 不可读（`mtime_nanos` 内部失败会返回 0）
    ///
    /// 注意：不检查 `all_keys` 是否持有该 rel_key 的解密密钥——即使密钥未知，
    /// 也照常返回 mtime；密钥缺失由调用方后续的 `get_with_mode` 走既有的
    /// `None => continue` 路径处理，不影响这里的"是否可跳过"判断。
    pub fn source_freshness_secs(&self, rel_key: &str) -> Option<i64> {
        let db_path = self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );

        let db_mt = mtime_nanos(&db_path);
        if db_mt == 0 {
            // 读取失败（文件不存在 / metadata 出错）——保守起见，未知不等于"很旧"。
            return None;
        }

        let wal_path = wal_path_for(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };

        let newest_nanos = db_mt.max(wal_mt);
        Some((newest_nanos / 1_000_000_000) as i64)
    }

    pub async fn get_with_mode(&self, rel_key: &str) -> Result<Option<CacheResolve>> {
        let enc_key_hex = match self.all_keys.get(rel_key) {
            Some(k) => k.clone(),
            None => return Ok(None),
        };

        let db_path = self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        if !db_path.exists() {
            return Ok(None);
        }

        let wal_path = wal_path_for(&db_path);
        let db_mt = mtime_nanos(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };

        let cached = {
            let inner = self.inner.lock().await;
            inner.get(rel_key).cloned()
        };

        let enc_key_bytes =
            hex_to_32bytes(&enc_key_hex).with_context(|| format!("密钥格式错误: {}", rel_key))?;

        // Path 1 / Path 2：主 .db mtime 未变且 cached 产物仍在
        if let Some(entry) = cached.as_ref() {
            if entry.db_mtime == db_mt && entry.decrypted_path.exists() {
                if entry.wal_mtime == wal_mt {
                    return Ok(Some(CacheResolve {
                        path: entry.decrypted_path.clone(),
                        mode: CacheMode::CacheHit,
                    }));
                }

                // Path 2: WAL-only 变化 → 在 cached 产物上重新 apply_wal
                // 不存在的 WAL 也要更新 wal_mtime=0（虽然 SQLite 不会自发"主库不变 + WAL 清空"）
                let out_path = entry.decrypted_path.clone();
                let t0 = std::time::Instant::now();
                if wal_path.exists() {
                    let out_path2 = out_path.clone();
                    let wal_path2 = wal_path.clone();
                    let key_copy = enc_key_bytes;
                    tokio::task::spawn_blocking(move || {
                        wal::apply_wal(&wal_path2, &out_path2, &key_copy)
                    })
                    .await??;
                }
                eprintln!(
                    "[cache] WAL 增量 {} ({}ms)",
                    rel_key,
                    t0.elapsed().as_millis()
                );

                {
                    let mut inner = self.inner.lock().await;
                    inner.insert(
                        rel_key.to_string(),
                        CacheEntry {
                            db_mtime: db_mt,
                            wal_mtime: wal_mt,
                            decrypted_path: out_path.clone(),
                        },
                    );
                }
                self.save_persistent().await;
                return Ok(Some(CacheResolve {
                    path: out_path,
                    mode: CacheMode::WalIncremental,
                }));
            }
        }

        // Path 3: 主 .db 变了 / 缓存 miss → 全量解密
        let out_path = self.cache_file_path(rel_key);
        let t0 = std::time::Instant::now();
        let db_path2 = db_path.clone();
        let out_path2 = out_path.clone();
        let key_copy = enc_key_bytes;
        tokio::task::spawn_blocking(move || crypto::full_decrypt(&db_path2, &out_path2, &key_copy))
            .await??;

        if wal_path.exists() {
            let out_path3 = out_path.clone();
            let wal_path3 = wal_path.clone();
            let key_copy2 = enc_key_bytes;
            tokio::task::spawn_blocking(move || wal::apply_wal(&wal_path3, &out_path3, &key_copy2))
                .await??;
        }

        eprintln!(
            "[cache] 全量解密 {} ({}ms)",
            rel_key,
            t0.elapsed().as_millis()
        );

        {
            let mut inner = self.inner.lock().await;
            inner.insert(
                rel_key.to_string(),
                CacheEntry {
                    db_mtime: db_mt,
                    wal_mtime: wal_mt,
                    decrypted_path: out_path.clone(),
                },
            );
        }

        self.save_persistent().await;
        Ok(Some(CacheResolve {
            path: out_path,
            mode: CacheMode::FullDecrypt,
        }))
    }

    /// 通过自定义只读 VFS 直接打开加密库，按需解密页而不做整库 `full_decrypt`。
    ///
    /// 与 [`Self::get`] / [`Self::get_with_mode`] 是两条**并行**路径，互不影响：
    /// - `get` / `get_with_mode` 走"整库落盘明文缓存"，仍保留供 oracle 对拍
    ///   与回退使用；
    /// - `open_conn` 走"VFS 按需解页"，`query.rs` 里 ~25 处查询点已全部迁移
    ///   到这条路径（经由 [`Self::conn_params`]，见其文档说明穿越
    ///   `spawn_blocking` 边界的方式）。
    ///
    /// 同步方法：内部只做一次 HashMap 查找 + 文件系统 `exists()` 检查 + VFS
    /// 注册（幂等，见 [`vfs`] 模块文档），均是非阻塞量级的操作，不需要
    /// `spawn_blocking`。返回的 `rusqlite::Connection` 才是真正会做阻塞 I/O
    /// 的对象——调用方应在阻塞线程里驱动查询，不要跨 `.await` 持有这个
    /// `Connection`。
    ///
    /// `query.rs` 迁移后走的是 [`Self::conn_params`] + [`ConnParams::open`]
    /// 这条更细粒度的路径（同步解析参数、阻塞 I/O 延后到 `spawn_blocking`
    /// 内部），本方法目前只被 `#[cfg(test)]` 的 `vfs_oracle.rs` 直接调用做
    /// 对拍，非 test 构建下会报 dead_code，属预期。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open_conn(&self, rel_key: &str) -> Result<rusqlite::Connection> {
        self.resolve_conn_params(rel_key)?.open()
    }

    /// 同 [`Self::open_conn`]，额外返回该分片 VFS 自注册以来累计共享的
    /// [`vfs::ReadStats`] 句柄（多次查询会往同一个计数器里累加），用于诊断 /
    /// 监控队列页展示"这个分片总共按需解密了多少页"。生产查询点用
    /// [`Self::conn_params`] 即可，不需要关心统计句柄；本方法目前只被
    /// `#[cfg(test)]` 的 `vfs_oracle.rs` 对拍使用。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open_conn_with_stats(
        &self,
        rel_key: &str,
    ) -> Result<(rusqlite::Connection, Arc<std::sync::Mutex<vfs::ReadStats>>)> {
        let params = self.resolve_conn_params(rel_key)?;
        vfs::open_conn_with_stats(&params.enc_db_path, params.key, &params.tmp_dir, &params.tag)
    }

    /// 供 `query.rs` 里 `db: &DbCache`（借用，生命周期绑在调用方 async fn 的
    /// 栈帧上）使用：既然这个借用没法直接 move 进 `'static` 的
    /// `tokio::task::spawn_blocking` 闭包，就把 `open_conn` 真正需要的、
    /// 全部 `Send + 'static` 的拥有值（物理路径 / 密钥 / 临时目录 / 诊断 tag）
    /// 在 async 上下文里同步解析出来打包成 [`ConnParams`]，调用方把它 `move`
    /// 进闭包，在闭包内部再调用 [`ConnParams::open`] 建立连接——
    /// 建立、使用、销毁 `rusqlite::Connection` 全程都在阻塞线程内部完成，不
    /// 跨 `.await` 或线程边界持有它。
    ///
    /// 之所以选这个方案而不是把整个 `DbCache` 包一层 `Arc` 传进
    /// `query.rs` 的每个函数签名：`conn_params` 本身只做 HashMap 查找 +
    /// `exists()` 检查，是非阻塞量级的同步调用，不需要 `db` 活过这次调用；
    /// 而真正的阻塞 I/O（VFS 注册 + 扫 WAL 帧头 + `Connection::open`）延后到
    /// [`ConnParams::open`]，天然就应该在 `spawn_blocking` 内部发生。这样
    /// `query.rs` 里已有的"先 await 拿到一份 owned 数据，再 move 进
    /// `spawn_blocking`"的既有代码结构完全不用变，只是 owned 数据从
    /// `PathBuf`（解密产物路径）换成了 [`ConnParams`]。
    pub fn conn_params(&self, rel_key: &str) -> Result<ConnParams> {
        self.resolve_conn_params(rel_key)
    }

    fn resolve_conn_params(&self, rel_key: &str) -> Result<ConnParams> {
        let enc_key_hex = self
            .all_keys
            .get(rel_key)
            .with_context(|| format!("未找到 {} 的解密密钥（all_keys 缺失该 rel_key）", rel_key))?;
        let key = hex_to_32bytes(enc_key_hex)
            .with_context(|| format!("密钥格式错误: {}", rel_key))?;

        let enc_db_path = self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        if !enc_db_path.exists() {
            anyhow::bail!("加密库不存在: {:?}", enc_db_path);
        }

        // VFS 内部临时文件（SQLite 排序临时表等）落盘目录：复用 cache_dir 下的
        // 子目录，与 full_decrypt 产物（cache_dir 根下的 <md5>.db）分开存放。
        let tmp_dir = self.cache_dir.join("vfs-tmp");
        Ok(ConnParams {
            enc_db_path,
            key,
            tmp_dir,
            tag: rel_key.to_string(),
        })
    }

    /// 加密源文件（主 `.db` 与 `.db-wal`）的完整新鲜度快照（mtime + 长度，
    /// 纳秒精度），分量独立返回（不像 [`Self::source_freshness_secs`] 合并
    /// 成"较新的一个"再降精度到秒）——分片路由缓存 / 热连接复用都需要
    /// **分别**感知"只有 WAL 变了"这种场景，合并后的单一值会丢失这个区分度。
    ///
    /// 与 [`Self::source_freshness_secs`] 共享同一套"WeChat 写消息必然 bump
    /// mtime"的事实基础，只是这里保留分量、提高精度到纳秒，额外带上文件
    /// 长度（正确性加固 1/3，见 [`SourceSnapshot`] 文档），服务不同调用方。
    fn source_snapshot(&self, rel_key: &str) -> SourceSnapshot {
        let db_path = self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        let wal_path = wal_path_for(&db_path);
        SourceSnapshot::capture(&db_path, &wal_path)
    }

    /// 优化 A：分片 schema 路由缓存查询。同步、非阻塞（只做 `fs::metadata` +
    /// 内存 `HashMap` 查找），供 `query.rs::find_msg_shards` 在真正 `open()`
    /// 扫描 `sqlite_master` 前先查一遍——miss、快照变了、或快照虽未变但源
    /// 文件"最近太活跃"（未过新鲜度 slack，见 [`SourceSnapshot::trusted_as_of`]）
    /// 都返回 `Stale`（附带《判定这一刻》的快照，调用方重建后必须原样传回，
    /// 不能用重建完成后重新读的快照，见 [`Self::put_shard_schema`] 文档）。
    pub fn shard_route_lookup(&self, rel_key: &str) -> ShardRouteLookup {
        let snapshot = self.source_snapshot(rel_key);
        let now = now_nanos();
        match self.shard_routes.lock().get(rel_key).cloned() {
            Some(e) if e.snapshot == snapshot && snapshot.trusted_as_of(now) => {
                ShardRouteLookup::Fresh(e.msg_tables)
            }
            _ => ShardRouteLookup::Stale(snapshot),
        }
    }

    /// 写回一次真正的 `sqlite_master` 扫描结果（该分片当时全部 `Msg_<md5>`
    /// 表名）。
    ///
    /// # 正确性要求（TOCTOU）
    /// `snapshot` **必须**是《发起判定那一刻》的快照——也就是
    /// [`Self::shard_route_lookup`] 返回 `ShardRouteLookup::Stale` 时携带的
    /// 那一份，绝不能是重建完成后（真正 `open()` + 扫描）重新读一次的快照。
    ///
    /// 理由：若重建期间（排队等待 + 真正的 I/O）文件又被 WeChat 写了一次，
    /// 用《判定时刻》的旧快照写回缓存，下次 `shard_route_lookup` 读到的
    /// 《当前快照》必然不同 → 判 `Stale` → 强制再重建一次，代价只是一次多余
    /// 的重建。反过来，如果用《重建完成后》重新读的快照写回，会出现"缓存
    /// 标签是新的、但缓存内容只反映到重建开始那一刻"的不一致，下次查询会
    /// 因为快照表面匹配而误判为 Fresh、读到过期 schema——这是本模块唯一不
    /// 允许出现的"悄悄查错数据"方向。
    pub fn put_shard_schema(
        &self,
        rel_key: String,
        snapshot: SourceSnapshot,
        msg_tables: HashSet<String>,
    ) {
        self.shard_routes
            .lock()
            .insert(rel_key, ShardSchemaEntry { snapshot, msg_tables });
    }

    /// 优化 B：借这一次查询拿到（或复用）某个分片的常驻热连接句柄。
    /// 同步、非阻塞（`resolve_conn_params` 只做 HashMap 查找 + `exists()`
    /// 检查，`source_snapshot` 只做 `fs::metadata`，`hot_conns.slot` 只是
    /// 内存 HashMap 操作）——真正的阻塞 I/O（可能的重建）延后到
    /// [`HotConnHandle::with`] 内部，调用方应在 `spawn_blocking` 里调用它。
    pub fn hot_conn_handle(&self, rel_key: &str) -> Result<HotConnHandle> {
        let conn_params = self.resolve_conn_params(rel_key)?;
        let snapshot = self.source_snapshot(rel_key);
        let (slot, rebuild_count) = self.hot_conns.slot(rel_key);
        Ok(HotConnHandle {
            slot,
            conn_params,
            snapshot,
            rebuild_count,
        })
    }
}

/// [`DbCache::conn_params`] 的返回值：`open_conn` 建立连接所需的全部数据，
/// 均为 `Send + 'static` 的拥有值，可以安全地 `move` 进
/// `tokio::task::spawn_blocking` 闭包。`rusqlite::Connection` 本身不应该、
/// 也不需要跨越这个边界——真正建立连接的 [`Self::open`] 应该在阻塞线程内部
/// 调用。
#[derive(Debug, Clone)]
pub struct ConnParams {
    enc_db_path: PathBuf,
    key: [u8; 32],
    tmp_dir: PathBuf,
    tag: String,
}

impl ConnParams {
    /// 建立到加密库的只读连接（阻塞调用：VFS 注册 + 扫 WAL 帧头 +
    /// `Connection::open_with_flags_and_vfs`）。只应在 `spawn_blocking`
    /// 内部调用，返回的 `Connection` 也应该在同一个闭包内使用、销毁。
    pub fn open(&self) -> Result<rusqlite::Connection> {
        vfs::open_conn(&self.enc_db_path, self.key, &self.tmp_dir, &self.tag)
    }

    /// 加密库的真实物理路径。VFS 下没有"解密产物路径"这个概念了，
    /// 调用方（`query.rs` 的 debug_source 诊断字段）如果需要展示"数据来自哪个
    /// 文件"，展示这个即可。
    pub fn enc_db_path(&self) -> &Path {
        &self.enc_db_path
    }
}

// ---------------------------------------------------------------------------
// 正确性加固：两个 mtime 门控缓存（优化 A / 优化 B）共享的新鲜度快照
// ---------------------------------------------------------------------------
//
// 背景（HIGH 风险）：优化 A / 优化 B 最初只用跨进程读到的文件 mtime 精确相等
// 判 Fresh。Windows/NTFS 上，微信进程开着句柄持续写 `.db`/`.db-wal` 时，
// `last-write-time` 的跨进程可见性可能滞后于实际写入——某次轮询若恰好落在
// "消息已落盘、mtime 尚未刷新"的窗口，会误判 Fresh、漏掉刚写入的消息；而
// 上层按 `[lastCheckedAt, now)` 左开右闭窗口推进检查点，漏掉的消息不是"下一
// 轮补上"，而是永久跳过。旧的 `shard_skippable`（见 `query.rs`）用 24 小时
// slack 天然躲开了这个问题，但这两个新缓存做的是精确相等比较，反而对这个
// 滞后窗口更敏感，必须单独加固。

/// 源文件《某一时刻》的新鲜度快照：db / wal 各自的 mtime（纳秒精度）与文件
/// 长度（字节）。[`ShardSchemaEntry`]（优化 A）与 [`HotConn`]（优化 B）都
/// 存这个类型、用同一套 [`Self::trusted_as_of`] 判定逻辑，避免两处独立
/// 实现同一套"要不要信任缓存"规则、后续改动漏改一处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceSnapshot {
    db_mtime: u64,
    db_len: u64,
    wal_mtime: u64,
    wal_len: u64,
}

impl SourceSnapshot {
    /// 读取 `db_path` / `wal_path`（若存在）当前的 mtime + 长度。wal 不存在
    /// 时两个分量都固定为 0（与"metadata 失败"共用 0，见
    /// [`Self::has_unknown_component`] 的说明——这是刻意选择，不是疏漏）。
    fn capture(db_path: &Path, wal_path: &Path) -> Self {
        let (db_mtime, db_len) = metadata_mtime_len(db_path);
        let (wal_mtime, wal_len) = if wal_path.exists() {
            metadata_mtime_len(wal_path)
        } else {
            (0, 0)
        };
        Self {
            db_mtime,
            db_len,
            wal_mtime,
            wal_len,
        }
    }

    /// 加固点 3（MEDIUM）：db_mtime 或 wal_mtime 任一为 0，代表"metadata
    /// 读取失败"或"文件缺失"——`mtime_nanos`/`metadata_mtime_len` 用
    /// `unwrap_or(0)` 把这两种情况和"合法的 0 时间戳"合并成同一个值,
    /// 不能再被当作可信的相等比较对象参与判 Fresh，否则"连续两次读取失败"
    /// 会被 0 == 0 误判为"没变"，从而复用一份可能早已过期的路由表/连接。
    ///
    /// wal 缺失（"没有 WAL 文件"）同样落在这条规则里——`Self::capture` 对
    /// "文件不存在" 和 "metadata 出错" 统一回退成 0，两者在这里无法区分,
    /// 因此没有 WAL 文件的分片也永远不会被判 Fresh。这是刻意的保守选择：
    /// 代价只是这类分片少了一部分缓存命中率，换来的是"任何不确定一律重建"
    /// 这条线绝不失守——与既有 `source_freshness_secs` 对 0 显式当"未知,
    /// 不可跳过"的处理方式对称。
    fn has_unknown_component(&self) -> bool {
        self.db_mtime == 0 || self.wal_mtime == 0
    }

    /// 加固点 2（HIGH，核心兜底）：只有当这份快照里 db / wal 最新的 mtime
    /// 比 `now_nanos` 早至少 [`HOT_CACHE_FRESHNESS_SLACK_SECS`]，才允许调用
    /// 方把它当作"足够旧、可以信任"。
    ///
    /// 这是与"mtime/len 精确相等"完全独立的第二个必要条件：即便两次读到的
    /// 快照逐字段相等，只要源文件是"最近 SLACK 秒内被写过"，也必须强制判
    /// Stale、重新读一遍——这正是用来兜住"内容已变、但 mtime 因跨进程可见性
    /// 滞后还没来得及体现出差异"这个窗口的手段：只信任已经安静了一整个
    /// slack 周期的分片，最近活跃的分片永远不走"精确相等就直接信任"这条捷径。
    fn trusted_as_of(&self, now_nanos: u64) -> bool {
        if self.has_unknown_component() {
            return false;
        }
        let newest = self.db_mtime.max(self.wal_mtime);
        // 饱和减法：若 `newest > now_nanos`（mtime 看起来来自"未来"——典型是
        // 本机时钟回拨，或者不同来源读到的系统时钟出现偏斜），age 被钳制为
        // 0，等价于"当作最新、还没过 slack"，强制不信任——任何时钟不确定性
        // 都不能被利用成"看起来很旧从而被误判为可信"。
        let age_nanos = now_nanos.saturating_sub(newest);
        age_nanos >= HOT_CACHE_FRESHNESS_SLACK_NANOS
    }
}

/// 单次 `fs::metadata` 拿到 mtime（纳秒）与文件长度（字节）；metadata 失败
/// 时两者都回退为 0，与 [`mtime_nanos`] 对 mtime 失败的既有回退语义保持
/// 一致，由上层 [`SourceSnapshot::has_unknown_component`] 统一识别并拒绝
/// 信任，不在这一层单独处理。
fn metadata_mtime_len(path: &Path) -> (u64, u64) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let mt = m
                .modified()
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64
                })
                .unwrap_or(0);
            (mt, m.len())
        }
        Err(_) => (0, 0),
    }
}

/// 优化 A/B 判定"是否信任缓存等于当前源文件"的新鲜度容差（秒）。
///
/// # 取值：600 秒（10 分钟，监控默认轮询间隔 5 分钟的两倍）
/// - 现实中 NTFS 跨进程 `last-write-time` 可见性滞后通常是亚秒到个位数秒
///   级别，600 秒有两个数量级以上的安全余量，足够舒适地覆盖这类滞后；
/// - 监控轮询默认 5 分钟一次，把 slack 取到两倍轮询间隔意味着"最近一整个
///   轮询周期都没被写过"的分片才会被信任——一个最近 10 分钟内活跃的分片，
///   本来就大概率刚收到新消息，重新读一遍是必要工作，不是浪费；slack 偏
///   大不产生额外的正确性代价，只是让"这个分片何时开始享受缓存"晚一点,
///   而不是"缓存了不该缓存的东西"；
/// - 与既有 `query.rs::SHARD_FRESHNESS_SLACK_SECS`（24 小时，用于"完全跳过
///   解密"这个不可逆的粗粒度判断）刻意区分量级：这里的"不信任缓存、多解密
///   一次"顶多是性能代价，可以选用小得多、更贴近实际滞后窗口的量级。
const HOT_CACHE_FRESHNESS_SLACK_SECS: u64 = 600;

const HOT_CACHE_FRESHNESS_SLACK_NANOS: u64 = HOT_CACHE_FRESHNESS_SLACK_SECS * 1_000_000_000;

/// 当前墙钟时间，纳秒精度，unix epoch 起算。与 [`mtime_nanos`] 用同一套
/// 精度与回退语义（系统时钟早于 `UNIX_EPOCH` 这种不可能但理论上存在的
/// 场景下 `unwrap_or_default()` 回退到 0，不 panic）。
fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// [`SourceSnapshot`] 加固逻辑的纯函数单元测试：不依赖真实文件 I/O 或
/// `sleep`，直接构造快照数值验证 `has_unknown_component` / `trusted_as_of`
/// 的边界行为。文件系统层面的端到端验证见 `shard_route_tests` /
/// `hot_conn_tests`。
#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn snap(db_mtime: u64, db_len: u64, wal_mtime: u64, wal_len: u64) -> SourceSnapshot {
        SourceSnapshot {
            db_mtime,
            db_len,
            wal_mtime,
            wal_len,
        }
    }

    #[test]
    fn zero_db_mtime_is_unknown() {
        assert!(snap(0, 10, 1_000_000_000, 5).has_unknown_component());
    }

    #[test]
    fn zero_wal_mtime_is_unknown() {
        // wal_mtime=0 既可能是"WAL 缺失"也可能是"metadata 读取失败"，两者
        // 在这一层无法区分，统一按"未知"处理。
        assert!(snap(1_000_000_000, 10, 0, 0).has_unknown_component());
    }

    #[test]
    fn nonzero_mtimes_are_known() {
        assert!(!snap(1_000_000_000, 10, 2_000_000_000, 5).has_unknown_component());
    }

    #[test]
    fn unknown_component_never_trusted_regardless_of_age() {
        // db_mtime=0（未知）时，即便 wal 那部分"看起来"很旧，也绝不能信任。
        let s = snap(0, 10, 2_000_000_000, 5);
        let far_future_now = 10 * HOT_CACHE_FRESHNESS_SLACK_NANOS;
        assert!(!s.trusted_as_of(far_future_now));
    }

    #[test]
    fn fresh_within_slack_is_not_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5);
        // now 只比 newest 早了 (slack - 1) 纳秒的距离，仍落在窗口内。
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS - 1;
        assert!(!s.trusted_as_of(now), "还没过满一个 slack 周期，不能信任");
    }

    #[test]
    fn exactly_at_slack_boundary_is_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5);
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS; // 恰好等于 slack
        assert!(s.trusted_as_of(now), "age == slack 应该允许信任（>= 边界）");
    }

    #[test]
    fn well_beyond_slack_is_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest, 5);
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS * 10;
        assert!(s.trusted_as_of(now));
    }

    #[test]
    fn future_mtime_from_clock_skew_is_never_trusted() {
        // mtime 比 now 还"新"（时钟回拨/偏斜）：饱和减法把 age 钳制为 0，
        // 必须当作"最新"处理，绝不能被判定为可信。
        let newest = 2_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5);
        let now = 1_000_000_000_000u64; // 早于 newest
        assert!(!s.trusted_as_of(now));
    }

    #[test]
    fn different_len_makes_snapshot_unequal_even_with_same_mtime() {
        let a = snap(1_000, 10, 2_000, 5);
        let b = snap(1_000, 11, 2_000, 5);
        assert_ne!(a, b, "长度不同必须视为不同快照，即便 mtime 完全相同");
    }
}

// ---------------------------------------------------------------------------
// 优化 A：分片 → 会话路由缓存
// ---------------------------------------------------------------------------

/// 某个分片《判定时刻》的 [`SourceSnapshot`] + 当时 `sqlite_master` 里出现
/// 的全部 `Msg_<md5>` 表名。只要分片没有被 WeChat 写过（快照未变）且已经
/// 安静了一整个新鲜度 slack 周期（见 [`SourceSnapshot::trusted_as_of`]），
/// 同一个分片被多个不同会话命中时，只有第一个会话触发真正的 `sqlite_master`
/// 扫描，其余全部内存命中——把 `find_msg_shards` 的复杂度从 O(会话数 × 活跃
/// 分片数) 压到 O(真正 dirty 的分片数)。
#[derive(Clone)]
struct ShardSchemaEntry {
    snapshot: SourceSnapshot,
    msg_tables: HashSet<String>,
}

/// rel_key -> [`ShardSchemaEntry`] 的路由缓存。用 `std::sync::Mutex`（不是
/// tokio `Mutex`）：临界区只是纯内存 `HashMap` 读写，不跨越任何 `.await`，
/// 可以直接在同步方法里调用——与本文件里 `source_freshness_secs` 现有的
/// 同步 `fs::metadata` 调用惯例一致。
struct ShardRouteCache {
    inner: std::sync::Mutex<HashMap<String, ShardSchemaEntry>>,
}

impl ShardRouteCache {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ShardSchemaEntry>> {
        // poison-safe：某次持锁期间的无关 panic 不应该永久传染给后续所有
        // 查询（与 `vfs.rs` 的 `VFS_REGISTRY` 既定风格一致）。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// [`DbCache::shard_route_lookup`] 的返回值。
pub enum ShardRouteLookup {
    /// 缓存命中、快照精确相等、且已经安静满一整个新鲜度 slack 周期：可以
    /// 直接信任这份表名集合，零 I/O。见 [`SourceSnapshot::trusted_as_of`]。
    Fresh(HashSet<String>),
    /// miss、快照变了、或快照虽未变但源文件"最近太活跃"（未过 slack）：
    /// 附带《判定时刻》的快照，调用方重建（真正 `open()` 扫描
    /// `sqlite_master`）后必须原样传回这份快照写入缓存，见
    /// [`DbCache::put_shard_schema`] 的 TOCTOU 说明。
    Stale(SourceSnapshot),
}

// ---------------------------------------------------------------------------
// 优化 B：mtime 门控的热连接复用
// ---------------------------------------------------------------------------

/// 同时保留的热连接分片数上限。超过时驱逐最久未用的一个——线性扫描找最小
/// `last_used`，复杂度 O(容量)；容量设计上很小（个位数到十几），可以忽略，
/// 但如果后续把容量调得很大（上百级别），需要换成更高效的数据结构（如
/// `IndexMap` 或双向链表 + 索引），当前实现不适合直接调大这个常量。
const MAX_HOT_SHARDS: usize = 12;

/// 每条热连接的 `PRAGMA cache_size`（负数=KB）：16MB/连接，让 SQLite 自身
/// pager 的页缓存在多次查询之间保持热（配合"同一 Connection 存活"），使
/// 第 2..N 次轮询大概率直接内存命中，不再触发 `decrypt_page` 重新做 AES
/// 解密。
const HOT_CONN_CACHE_SIZE_KB: i64 = -16384;

/// LRU 时钟：只用于 [`HotShardSlot::last_used`] 的相对新旧排序，不是真实
/// 时间，进程内单调递增即可。
static HOT_CONN_CLOCK: AtomicU64 = AtomicU64::new(0);

/// 一个分片当前持有的常驻只读连接快照：连接本身 + 建立它时看到的
/// [`SourceSnapshot`]。复用条件是这份快照与《本次查询发起时刻》读到的当前
/// 快照逐字段完全相同、且已经安静满一整个新鲜度 slack 周期（见
/// [`SourceSnapshot::trusted_as_of`]）；任一条件不满足都必须先丢弃（`Drop`
/// 关闭底层文件句柄）再重新 [`ConnParams::open`]——重建天然重新
/// `build_wal_index`（见 `vfs.rs` `WxVfs::open`），不需要也不允许任何
/// "增量感知 WAL 变化"的逻辑。
///
/// # 不变量：`conn` 只能经 [`HotConnHandle::with`] 在持锁临界区内访问
/// [`ConnParams::open`]（见 `vfs.rs::open_conn`）用
/// `SQLITE_OPEN_NO_MUTEX` 打开连接——这意味着 SQLite 自身**不**为这个
/// `Connection` 提供任何内部互斥，多线程并发直接使用同一个连接是未定义
/// 行为（UB），不是"可能 panic 但安全"。`conn` 字段是模块私有的，池化后
/// 唯一允许的访问路径是 [`HotConnHandle::with`]：它在拿到 `slot` 的
/// `std::sync::Mutex` 之后才把 `&Connection` 借出去，闭包结束、`MutexGuard`
/// 释放之前绝不允许这个引用逃逸。任何新代码都不允许绕过 `with()`
/// 直接触碰这里的 `Connection`（例如把它拷出锁外、或在另一把锁下重新解引用
/// 同一个槽位）——这条约束必须长期维持。
struct HotConn {
    conn: Connection,
    snapshot: SourceSnapshot,
}

/// 单个分片的热连接槽位。`Arc<std::sync::Mutex<Option<HotConn>>>` 因为
/// `Connection: Send` 满足 `Mutex<T>: Sync`，天然是 `Send + Sync + 'static`，
/// 可以安全放进 `HashMap` 常驻、也可以安全 `.clone()` 后 move 进
/// `spawn_blocking`。用槽位粒度的锁（而不是一把全局锁包住整个池子）保证
/// 不同分片的查询完全并行，只有"同一分片被并发查询"时才会在这把小锁上
/// 排队——这正是期望行为：同一个物理 SQLite `Connection` 本来就不允许并发
/// 使用。
struct HotShardSlot {
    slot: Arc<std::sync::Mutex<Option<HotConn>>>,
    last_used: Arc<AtomicU64>,
    /// 这个槽位累计真正触发过多少次重建（`HotConnHandle::with()` 内部调用
    /// `ConnParams::open()`）。生产路径只写不读，存在的唯一目的是给单测一个
    /// 确定性信号去区分"这次调用到底是复用还是重建"——裸指针地址比较不可靠
    /// （分配器，尤其是 Windows 的 Low-Fragmentation Heap，可能把刚 free 的
    /// `sqlite3*` 地址立刻复用给下一个同尺寸对象，实测确有复现）。
    #[cfg_attr(not(test), allow(dead_code))]
    rebuild_count: Arc<AtomicU64>,
}

/// 按分片保留常驻只读连接的池子。
struct HotConnPool {
    shards: std::sync::Mutex<HashMap<String, HotShardSlot>>,
    /// 容量上限，正常固定为 [`MAX_HOT_SHARDS`]；测试用较小值验证驱逐逻辑，
    /// 不需要真的构造十几个物理分片。
    capacity: usize,
}

impl HotConnPool {
    fn new() -> Self {
        Self::with_capacity(MAX_HOT_SHARDS)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            shards: std::sync::Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// 拿到（或创建）某个分片专属的槽位（连接互斥锁 + 重建计数器）。持锁
    /// 时间是纯内存操作（无阻塞 I/O），微秒级，可以直接在 async 上下文里
    /// 同步调用（与 `source_freshness_secs` 现有调用惯例一致）。
    fn slot(&self, rel_key: &str) -> (Arc<std::sync::Mutex<Option<HotConn>>>, Arc<AtomicU64>) {
        let mut map = self.shards.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(rel_key) && map.len() >= self.capacity {
            if let Some(evict_key) = map
                .iter()
                .min_by_key(|(_, v)| v.last_used.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone())
            {
                // 池子只是放弃自己那份 Arc；若此刻有并发查询正 move 着自己
                // clone 的那份在别处用，它手上那份引用计数仍然存活，直到它
                // 自己用完、`with()` 返回、闭包结束才真正 drop、关闭底层
                // 文件句柄——不会出现"驱逐时正在用的连接被强制中断"的问题。
                map.remove(&evict_key);
            }
        }
        let entry = map.entry(rel_key.to_string()).or_insert_with(|| HotShardSlot {
            slot: Arc::new(std::sync::Mutex::new(None)),
            last_used: Arc::new(AtomicU64::new(0)),
            rebuild_count: Arc::new(AtomicU64::new(0)),
        });
        entry
            .last_used
            .store(HOT_CONN_CLOCK.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
        (entry.slot.clone(), entry.rebuild_count.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[cfg(test)]
    fn contains(&self, rel_key: &str) -> bool {
        self.shards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(rel_key)
    }
}

/// [`DbCache::hot_conn_handle`] 的返回值：借这一次查询"顺路"拿到的、可能
/// 复用的常驻连接句柄。`Send + 'static`，可以整体 move 进
/// `tokio::task::spawn_blocking`，用法与 [`ConnParams`] 完全同构：调用方在
/// async 上下文里同步拿到句柄，`move` 进阻塞闭包，闭包内部调用 [`Self::with`]。
///
/// # 不变量：不允许绕过 [`Self::with`] 访问底层连接
/// 与 [`HotConn`] 文档说明的是同一条不变量：底层 `Connection` 用
/// `SQLITE_OPEN_NO_MUTEX` 打开，任何脱离 `with()` 持锁临界区的并发访问都是
/// UB，不是"最坏情况 panic"。`HotConnHandle` 本身不持有 `Connection`
/// （只持有槽位的 `Arc<Mutex<..>>`），这个类型上没有除 `with()` 之外能碰到
/// 连接的方法——新增方法时必须保持这个结构不变。
pub struct HotConnHandle {
    slot: Arc<std::sync::Mutex<Option<HotConn>>>,
    conn_params: ConnParams,
    snapshot: SourceSnapshot,
    /// 见 [`HotShardSlot::rebuild_count`] 文档：生产路径只写不读。
    #[cfg_attr(not(test), allow(dead_code))]
    rebuild_count: Arc<AtomicU64>,
}

impl HotConnHandle {
    /// 加密库的真实物理路径，用途同 [`ConnParams::enc_db_path`]。
    pub fn enc_db_path(&self) -> &Path {
        self.conn_params.enc_db_path()
    }

    /// 只应在 `spawn_blocking` 内部调用：整个"锁定槽位 → 校验快照 → 复用
    /// 或重建 → 执行查询 → 释放锁"临界区在同一次阻塞调用里完整走完，不跨
    /// 越任何 `.await` 让出点——`MutexGuard` 和 `&Connection` 都不会被带出
    /// 这个函数体，调用方在 async fn 里只持有 `HotConnHandle` 本身（值语义，
    /// `Send + 'static`），从不直接接触 `Connection`。
    pub fn with<T>(self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut guard = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_nanos();
        let stale = match guard.as_ref() {
            // 两个独立的必要条件：快照逐字段相等（否则源文件确定变了），
            // 且这份快照已经安静满一整个新鲜度 slack 周期（否则即便逐字段
            // 相等也不敢信——见 `SourceSnapshot::trusted_as_of` 的 HIGH 加固
            // 说明：跨进程 mtime 可见性滞后可能让"已经变了"的文件暂时看起来
            // "没变"）。任一条件不满足都必须重建。
            Some(hot) => hot.snapshot != self.snapshot || !self.snapshot.trusted_as_of(now),
            None => true,
        };
        if stale {
            // 先丢旧连接（Drop 关闭文件句柄）再建新的——新连接的
            // `ConnParams::open()` 内部会重新扫 `-wal` 帧头建索引，天然拿到
            // 这一刻最新的 WAL 视图，不需要任何增量维护逻辑。
            *guard = None;
            let conn = self.conn_params.open()?;
            conn.pragma_update(None, "cache_size", HOT_CONN_CACHE_SIZE_KB)?;
            *guard = Some(HotConn {
                conn,
                snapshot: self.snapshot,
            });
            self.rebuild_count.fetch_add(1, Ordering::Relaxed);
        }
        let hot = guard.as_ref().expect("刚确保过 Some");
        match f(&hot.conn) {
            Ok(v) => Ok(v),
            // 保守丢弃：查询失败可能意味着 schema 假设被打破（例如分片
            // 滚动导致目标表消失），下次访问重新建立更安全——不缓存可能
            // 处于不确定状态的连接。只放弃一次复用机会，不影响正确性。
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }
}

pub(super) fn mtime_nanos(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        })
        .unwrap_or(0)
}

/// `foo/bar.db` → `foo/bar.db-wal`（用 OsString 拼接，避免 display() 的 UTF-8 问题）
fn wal_path_for(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push("-wal");
    db_path.with_file_name(name)
}

fn hex_to_32bytes(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("密钥 hex 长度应为 64，实际为 {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("非法 hex 字符 at {}", i * 2))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 字符 hex（不需要是真 SQLCipher key — 仅用来证明"是否触发了 full_decrypt"）
    const FAKE_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// 路径区分约定：
    /// - 完全 hit / WAL 增量 → `decrypted_path` **内容不变**
    /// - 全量解密 → `crypto::full_decrypt` 把 cached file **重写为 PAGE_SZ 倍数**
    ///   （fake key 解出 4096 字节垃圾，但仍写入 — 不验证内容合法性）
    /// 因此用 cached file 的"size 是否被改"来判断走了哪条路径。
    const ORIGINAL_CACHED_BYTES: &[u8] = b"original cached contents";

    fn unique_tmpdir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("wxeasy-cache-test-{}-{}-{}", tag, pid, nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 准备一份 "DbCache 已经 reuse 了 cached 解密产物" 的初始状态。
    /// 返回 (cache, db_path, decrypted_path, mtime_file, rel_key)。
    async fn setup_seeded_cache(tag: &str) -> (DbCache, PathBuf, PathBuf, PathBuf, String) {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        std::fs::write(&decrypted_path, ORIGINAL_CACHED_BYTES).unwrap();

        let db_mt = mtime_nanos(&db_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": 0u64,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file.clone(), all_keys)
            .await
            .unwrap();

        (cache, db_path, decrypted_path, mtime_file, rel_key)
    }

    #[tokio::test]
    async fn exact_mtime_hit_skips_decrypt() {
        let (cache, _db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("exact").await;

        let p = cache
            .get(&rel_key)
            .await
            .unwrap()
            .expect("cache should hit");
        assert_eq!(p, decrypted_path);

        // 完全 hit → cached file 内容不应被改
        let body = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(body, ORIGINAL_CACHED_BYTES);
    }

    #[tokio::test]
    async fn wal_only_change_uses_incremental_path() {
        // 自己构造（不走 setup_seeded_cache）以便初始 mtime.json 同时写 db_mt 和 wal_mt
        let root = unique_tmpdir("walonly");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap(); // ≤ WAL_HDR_SZ=32 → apply_wal noop

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        std::fs::write(&decrypted_path, ORIGINAL_CACHED_BYTES).unwrap();

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        // 第一次：完全 hit
        let p1 = cache.get(&rel_key).await.unwrap().expect("first get hits");
        assert_eq!(p1, decrypted_path);
        assert_eq!(
            std::fs::read(&decrypted_path).unwrap(),
            ORIGINAL_CACHED_BYTES
        );

        // bump WAL mtime（重写仍 31 bytes，apply_wal 仍 noop）
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal_mt1 = mtime_nanos(&wal_path);
        assert_ne!(wal_mt0, wal_mt1, "rewriting WAL should bump mtime");

        // 第二次：WAL 增量路径
        // 如果错误地走 full_decrypt → cached file 大小会被重写为 ≥ PAGE_SZ
        let p2 = cache
            .get(&rel_key)
            .await
            .unwrap()
            .expect("WAL-incremental path should produce path");
        assert_eq!(p2, decrypted_path);

        let body = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(
            body, ORIGINAL_CACHED_BYTES,
            "WAL-incremental should NOT rewrite cached file"
        );
    }

    #[tokio::test]
    async fn db_mtime_change_triggers_full_decrypt() {
        let (cache, db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("dbchange").await;

        // bump 主 .db 的 mtime（重写一份不同 bytes）
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&db_path, b"different fake encrypted bytes").unwrap();
        assert_ne!(
            mtime_nanos(&db_path),
            cache.inner.lock().await.get(&rel_key).unwrap().db_mtime,
            "rewriting db file should bump mtime"
        );

        // 走 full_decrypt 路径 → fake key 不会让 full_decrypt 失败（它不验证内容），
        // 但会把 cached file 重写为 PAGE_SZ 倍数。原始内容是 24 bytes，重写后应该 ≥ 4096 bytes。
        let p = cache
            .get(&rel_key)
            .await
            .unwrap()
            .expect("cache should produce path");
        assert_eq!(p, decrypted_path);

        let new_size = std::fs::metadata(&decrypted_path).unwrap().len() as usize;
        assert!(
            new_size >= crate::crypto::PAGE_SZ,
            "expected full_decrypt to rewrite cached file to PAGE_SZ multiple, got size={}",
            new_size,
        );
    }

    #[tokio::test]
    async fn get_with_mode_reports_each_path() {
        let root = unique_tmpdir("getwithmode");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        std::fs::write(&decrypted_path, ORIGINAL_CACHED_BYTES).unwrap();

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let hit = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("cache should hit");
        assert_eq!(hit.path, decrypted_path);
        assert_eq!(hit.mode, CacheMode::CacheHit);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("WAL-only change should stay incremental");
        assert_eq!(wal.path, decrypted_path);
        assert_eq!(wal.mode, CacheMode::WalIncremental);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&db_path, b"different bytes").unwrap();
        let full = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("db mtime change should trigger full decrypt");
        assert_eq!(full.path, decrypted_path);
        assert_eq!(full.mode, CacheMode::FullDecrypt);
    }

    #[tokio::test]
    async fn restart_with_wal_change_still_reuses_cached_db_then_applies_wal() {
        let root = unique_tmpdir("restart-wal");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap(); // WAL 增量仍是 noop

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        std::fs::write(&decrypted_path, ORIGINAL_CACHED_BYTES).unwrap();

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        // 模拟 daemon 重启前又有新消息写入 WAL
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal_mt1 = mtime_nanos(&wal_path);
        assert_ne!(wal_mt0, wal_mt1);

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let p = cache
            .get(&rel_key)
            .await
            .unwrap()
            .expect("cache should reuse persisted DB");
        assert_eq!(p, decrypted_path);
        let body = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(
            body, ORIGINAL_CACHED_BYTES,
            "restart + WAL-only change should still reuse cached DB and avoid full_decrypt"
        );
    }

    #[tokio::test]
    async fn source_freshness_secs_returns_db_mtime_when_no_wal() {
        let root = unique_tmpdir("freshness-dbonly");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let expected_secs = (mtime_nanos(&db_path) / 1_000_000_000) as i64;
        assert_eq!(
            cache.source_freshness_secs(&rel_key),
            Some(expected_secs),
            "only main .db exists — freshness should be its mtime"
        );
    }

    #[tokio::test]
    async fn source_freshness_secs_prefers_newer_wal() {
        let root = unique_tmpdir("freshness-wal");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        // WAL 比主 .db 晚写入，mtime 应该更新（模拟"最近有新消息 append 到 WAL"）
        std::thread::sleep(std::time::Duration::from_millis(20));
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let db_mt = mtime_nanos(&db_path);
        let wal_mt = mtime_nanos(&wal_path);
        assert!(wal_mt >= db_mt, "rewriting WAL later should bump its mtime");

        let expected_secs = (wal_mt.max(db_mt) / 1_000_000_000) as i64;
        assert_eq!(cache.source_freshness_secs(&rel_key), Some(expected_secs));
    }

    #[tokio::test]
    async fn source_freshness_secs_none_when_db_missing() {
        let root = unique_tmpdir("freshness-missing");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        assert_eq!(
            cache.source_freshness_secs("message_0.db"),
            None,
            "missing source db must be 'unknown', never 'stale'"
        );
    }
}

/// 供本文件内 `shard_route_tests` / `hot_conn_tests`，以及 `daemon::query`
/// 的测试共用的夹具构造工具：怎么在不依赖真实 SQLCipher 的前提下，构造一份
/// "套用 `crypto::encrypt_page` 往返无损、可以被生产 VFS 路径真实执行 SQL
/// 查询"的加密库。`pub(crate)` 是因为 `daemon::query` 的测试也要用到它。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn unique_tmpdir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("wxeasy-test-{}-{}-{}", tag, pid, nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 固定但任意的 32 字节测试密钥（不需要是真实 SQLCipher 派生密钥——
    /// `encrypt_page`/`decrypt_page` 只要求加解密两侧用同一把 key）。
    pub(crate) fn key_fixture() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        k
    }

    pub(crate) fn key_to_hex(key: &[u8; 32]) -> String {
        key.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 构造一份"看起来像真实 WeChat 分片"的加密 SQLite 库，可以被
    /// `ConnParams::open()`（生产 VFS 路径）打开并执行真实 SQL 查询。
    ///
    /// # 核心技巧
    /// 建库前用 `SQLITE_FCNTL_RESERVE_BYTES` file control 把每页保留字节设为
    /// `crypto::RESERVE_SZ`（80）——之后 SQLite pager 自己就不会往页尾 80
    /// 字节写任何真实内容（这正是真实 SQLCipher 库的行为：那 80 字节本就是
    /// 留给 IV+HMAC 的），使得逐页套用 `crypto::encrypt_page` 的往返变换
    /// 不会丢失任何真实数据，不需要真正链接 SQLCipher 就能造出"生产 VFS
    /// 能完整、正确读出"的加密库。必须在任何写入（含 `CREATE TABLE`）之前
    /// 设置 reserve bytes，否则 pager 已经按 `usable_size = page_size`
    /// 分配了页 1。
    pub(crate) fn build_encrypted_fixture(
        enc_path: &Path,
        key: &[u8; 32],
        table_name: &str,
        rows: &[(i64, i64)],
    ) {
        let plain_path = enc_path.with_extension("plain-fixture.db");
        let _ = std::fs::remove_file(&plain_path);
        {
            let conn = Connection::open(&plain_path).expect("打开明文夹具库失败");
            conn.execute_batch(&format!("PRAGMA page_size={};", crate::crypto::PAGE_SZ))
                .expect("设置 page_size 失败");
            unsafe {
                let raw = conn.handle();
                let mut reserve: std::os::raw::c_int =
                    crate::crypto::RESERVE_SZ as std::os::raw::c_int;
                let db_name = std::ffi::CString::new("main").unwrap();
                let rc = rusqlite::ffi::sqlite3_file_control(
                    raw,
                    db_name.as_ptr(),
                    rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
                    &mut reserve as *mut _ as *mut std::os::raw::c_void,
                );
                assert_eq!(rc, rusqlite::ffi::SQLITE_OK, "设置 reserve bytes 失败");
            }
            conn.execute_batch(&format!(
                "CREATE TABLE [{}] (local_id INTEGER PRIMARY KEY, create_time INTEGER);",
                table_name
            ))
            .expect("建表失败");
            for (id, ts) in rows {
                conn.execute(
                    &format!(
                        "INSERT INTO [{}] (local_id, create_time) VALUES (?1, ?2)",
                        table_name
                    ),
                    rusqlite::params![id, ts],
                )
                .expect("插入夹具数据失败");
            }
            // 默认 journal_mode=DELETE（回滚日志），连接 drop 时主库文件
            // 已是最终提交状态，不会残留 -wal / -journal。
        }

        let plain_bytes = std::fs::read(&plain_path).expect("读取明文夹具失败");
        assert_eq!(
            plain_bytes.len() % crate::crypto::PAGE_SZ,
            0,
            "测试夹具应恰好是整数个页（reserve bytes 生效的前提）"
        );
        let iv = [0x42u8; 16];
        let mut enc_bytes = Vec::with_capacity(plain_bytes.len());
        for (i, chunk) in plain_bytes.chunks(crate::crypto::PAGE_SZ).enumerate() {
            enc_bytes.extend(crate::crypto::encrypt_page(key, chunk, &iv, (i + 1) as u32));
        }
        std::fs::write(enc_path, &enc_bytes).expect("写入加密夹具失败");
        let _ = std::fs::remove_file(&plain_path);
    }

    /// 把某个文件的 mtime 显式回拨到"早已超过新鲜度 slack"的过去时刻，用于
    /// 构造"源文件已经安静很久、允许被判 Fresh"的测试前提——不需要真的
    /// `sleep` 上百秒等待 [`HOT_CACHE_FRESHNESS_SLACK_SECS`] 窗口过期。
    ///
    /// 只回拨 mtime、不改动文件内容/长度——`OpenOptions::write(true)` 不带
    /// `truncate`/`append`，且这里不发起任何 `write_all` 调用。
    pub(crate) fn backdate_beyond_slack(path: &Path) {
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(HOT_CACHE_FRESHNESS_SLACK_SECS + 60);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("打开待回拨 mtime 的文件失败");
        file.set_modified(old).expect("回拨 mtime 失败");
    }
}

/// 优化 A（分片路由缓存）的单元测试：命中 / miss / 快照失效重建，以及三个
/// 正确性加固点（长度加入失效键、新鲜度 slack、0 视为未知）各自的直接验证。
#[cfg(test)]
mod shard_route_tests {
    use super::test_support::{backdate_beyond_slack, unique_tmpdir};
    use super::*;

    /// 默认基线：db + wal 都存在，且都已回拨到"早已安静、超过新鲜度 slack"
    /// 的过去时刻——对应"这个分片已经很久没被微信写过"的常态。需要模拟
    /// "刚被写过"的场景时，测试内部再显式重写文件、不重新回拨。
    async fn setup(tag: &str) -> (DbCache, PathBuf, String) {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();
        backdate_beyond_slack(&db_path);
        backdate_beyond_slack(&wal_path);

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();
        (cache, db_path, rel_key)
    }

    #[tokio::test]
    async fn miss_is_stale_with_current_snapshot() {
        let (cache, _db_path, rel_key) = setup("miss").await;

        let expected = cache.source_snapshot(&rel_key);
        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(got) => assert_eq!(got, expected),
            ShardRouteLookup::Fresh(_) => panic!("从未见过的 rel_key 必须是 Stale，不能是 Fresh"),
        }
    }

    /// 基线正向用例（加固点 2 的另一面）：源文件足够旧、快照逐字段都没变时
    /// 才允许命中——这是唯一被允许走"零 I/O 直接信任"捷径的状态。
    #[tokio::test]
    async fn put_then_lookup_hits_when_quiet_and_unchanged() {
        let (cache, _db_path, rel_key) = setup("hit").await;

        let snapshot = cache.source_snapshot(&rel_key);
        let mut tables = HashSet::new();
        tables.insert("Msg_aaaa".to_string());
        tables.insert("Msg_bbbb".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables.clone());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables),
            ShardRouteLookup::Stale(_) => panic!("快照未变且已安静满一个 slack 周期，应该命中缓存"),
        }
    }

    #[tokio::test]
    async fn db_change_invalidates_cached_route() {
        let (cache, db_path, rel_key) = setup("db-bump").await;

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new());
        assert!(
            matches!(cache.shard_route_lookup(&rel_key), ShardRouteLookup::Fresh(_)),
            "写入后、快照未变、且已安静满 slack，应先命中"
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&db_path, b"different fake encrypted bytes").unwrap();

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(got) => {
                assert_eq!(got, cache.source_snapshot(&rel_key));
                assert_ne!(got, snapshot, "重写 db 文件应该改变快照");
            }
            ShardRouteLookup::Fresh(_) => panic!("db 变了必须判 Stale，不能继续信任旧 schema"),
        }
    }

    #[tokio::test]
    async fn wal_change_invalidates_cached_route() {
        let (cache, db_path, rel_key) = setup("wal-bump").await;

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new());
        assert!(
            matches!(cache.shard_route_lookup(&rel_key), ShardRouteLookup::Fresh(_)),
            "写入后、快照未变、且已安静满 slack，应先命中"
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        let wal_path = wal_path_for(&db_path);
        // 内容无所谓（<=32 字节甚至会被生产 VFS 路径当成"无有效 WAL 帧"），
        // 这里只需要 bump wal 文件的 mtime/内容。
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(_) => {}
            ShardRouteLookup::Fresh(_) => {
                panic!("wal 变了（即便 db 不变）也必须判 Stale")
            }
        }
    }

    /// 加固点 1 的直接验证：mtime 被显式钉回原值（模拟跨进程 mtime 可见性
    /// 滞后到极致——内容已变、mtime 却"看起来没变"），但文件长度确实变了。
    /// 只要失效键里包含长度，这种情况也必须判 Stale。
    #[tokio::test]
    async fn len_change_with_pinned_mtime_invalidates_cached_route() {
        let (cache, db_path, rel_key) = setup("len-pin").await;

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new());
        assert!(
            matches!(cache.shard_route_lookup(&rel_key), ShardRouteLookup::Fresh(_)),
            "写入基线后应先命中"
        );

        // 用不同长度的内容重写 db 文件，再把 mtime 显式钉回原值。
        std::fs::write(&db_path, b"a longer different fake encrypted db payload").unwrap();
        let pinned = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(snapshot.db_mtime);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&db_path)
            .unwrap()
            .set_modified(pinned)
            .unwrap();
        assert_eq!(
            mtime_nanos(&db_path),
            snapshot.db_mtime,
            "测试前提：db mtime 应该被钉回了原值"
        );

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(got) => {
                assert_ne!(
                    got.db_len, snapshot.db_len,
                    "文件长度应该已经变化——这正是本测试要验证的信号"
                );
            }
            ShardRouteLookup::Fresh(_) => panic!(
                "mtime 相同但文件长度已变化，必须判 Stale——这是长度加入失效键要堵的场景"
            ),
        }
    }

    /// 加固点 2（HIGH，核心兜底）的直接验证：db/wal 都是"刚刚写入"的状态
    /// （落在新鲜度 slack 窗口内）。即便快照与缓存条目逐字段完全相等，也
    /// 必须强制判 Stale——只有安静满一整个 slack 周期的分片才允许被信任。
    #[tokio::test]
    async fn recently_written_source_is_never_trusted_even_if_unchanged() {
        let root = unique_tmpdir("recent-route");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();
        // 故意不回拨：mtime 就是"现在"，落在新鲜度 slack 窗口内。

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(got) => {
                assert_eq!(got, snapshot, "快照本身没变，只是还没过新鲜度 slack 窗口");
            }
            ShardRouteLookup::Fresh(_) => {
                panic!("源文件最近 slack 秒内被写过，即便快照精确相等也不能判 Fresh")
            }
        }
    }

    /// 加固点 3（MEDIUM）的直接验证：db 文件不存在时 `source_snapshot` 回退
    /// db_mtime=0（与"metadata 读取失败"共用同一个哨兵值）。即便缓存里凑巧
    /// 也存了一份 db_mtime=0 的"匹配"快照，也不能被判 Fresh——0 不是合法的
    /// 相等比较对象。
    #[tokio::test]
    async fn zero_mtime_component_never_trusted_even_if_cached_matches() {
        let root = unique_tmpdir("zero-mtime-route");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_missing.db".to_string(); // 从未创建这个文件
        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let snapshot = cache.source_snapshot(&rel_key);
        assert_eq!(
            snapshot.db_mtime, 0,
            "测试前提：文件不存在，db_mtime 应为哨兵值 0"
        );

        // 故意把这份"看起来相同"的快照也塞进缓存，模拟"两次读取都失败，
        // 凑巧数值相同"的最坏情况。
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(_) => {}
            ShardRouteLookup::Fresh(_) => panic!("db_mtime=0 是未知哨兵值，永远不能被判 Fresh"),
        }
    }
}

/// 优化 B（热连接复用）的单元测试：快照不变时复用、快照变了必须重建、
/// 查询失败清空槽位、并发访问不 panic、容量驱逐、一次真实数据的端到端
/// 正确性验证，以及三个正确性加固点各自的直接验证。
#[cfg(test)]
mod hot_conn_tests {
    use super::test_support::{
        backdate_beyond_slack, build_encrypted_fixture, key_fixture, key_to_hex, unique_tmpdir,
    };
    use super::*;

    /// `Connection::open_with_flags_and_vfs` 配合 `immutable=1` 会在打开时就
    /// 校验页 1 的 SQLite 魔数（实测：任意字节会直接报 `SQLITE_NOTADB`，不是
    /// "打开时惰性、查询时才校验"），所以即便只是测试"何时复用/何时重建
    /// 连接"这层新逻辑本身，也必须用 [`build_encrypted_fixture`] 造一份真正
    /// 能通过 VFS 打开的库，不能用任意字节的"垃圾"文件。
    ///
    /// 固件默认基线：db + 一份"无有效帧"的 WAL 占位文件（<=32 字节，生产
    /// VFS 路径会当成没有 WAL 帧，不影响查询到的真实数据）都回拨到早已安静
    /// 的过去时刻——新鲜度加固后，wal 缺失（mtime=0）永远判 Stale，固件需要
    /// 一份真实存在、可回拨的 WAL 才能进入"允许复用"的状态。
    async fn setup_fixture_cache(
        tag: &str,
        table_name: &str,
        rows: &[(i64, i64)],
    ) -> (DbCache, String, PathBuf) {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        let key = key_fixture();
        build_encrypted_fixture(&db_path, &key, table_name, rows);
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();
        backdate_beyond_slack(&db_path);
        backdate_beyond_slack(&wal_path);

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), key_to_hex(&key));
        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        (cache, rel_key, db_path)
    }

    /// 借这次调用顺路执行一次最简单的查询（探测连接是否可用），不关心
    /// 返回值——真正的断言看 [`rebuild_count`] 的前后差值。
    async fn probe(cache: &DbCache, rel_key: &str) {
        let hot = cache.hot_conn_handle(rel_key).unwrap();
        tokio::task::spawn_blocking(move || hot.with(|_conn| Ok::<_, anyhow::Error>(())))
            .await
            .unwrap()
            .unwrap();
    }

    /// 某个分片累计触发过多少次真正的重建（`ConnParams::open()`）。用这个
    /// 计数器的前后差值判断"复用 vs 重建"，而不是比较 `conn.handle()` 裸
    /// 指针——实测在"两次调用之间几乎没有其它堆分配"的场景下（例如
    /// `rebuild_when_wal_mtime_changes`），Windows 的 Low-Fragmentation Heap
    /// 会把刚 `sqlite3_close()` 释放的地址立刻原样分配给紧随其后的
    /// `sqlite3_open_v2()`，导致"指针不同"这个信号出现假阴性（明明重建了，
    /// 指针却相同）。计数器是完全确定性的信号，不受分配器行为影响。
    fn rebuild_count(cache: &DbCache, rel_key: &str) -> u64 {
        cache
            .hot_conn_handle(rel_key)
            .unwrap()
            .rebuild_count
            .load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn reuse_when_mtime_unchanged() {
        let (cache, rel_key, _db_path) =
            setup_fixture_cache("reuse", "Msg_test", &[(1, 1000)]).await;

        probe(&cache, &rel_key).await; // 首次访问：slot 为空，必然触发一次重建
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        probe(&cache, &rel_key).await; // mtime 未变：应该复用，不增加计数
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            1,
            "mtime 未变时第二次调用应复用同一个底层连接，不触发重建"
        );
    }

    #[tokio::test]
    async fn rebuild_when_db_mtime_changes() {
        let (cache, rel_key, db_path) =
            setup_fixture_cache("db-bump", "Msg_test", &[(1, 1000)]).await;

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        std::thread::sleep(std::time::Duration::from_millis(20));
        // 重写整份加密文件（内容变化 + bump mtime）。
        build_encrypted_fixture(&db_path, &key_fixture(), "Msg_test", &[(1, 1000), (2, 2000)]);

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "db mtime 变了必须丢弃旧连接、重建新连接"
        );
    }

    #[tokio::test]
    async fn rebuild_when_wal_mtime_changes() {
        let (cache, rel_key, db_path) =
            setup_fixture_cache("wal-bump", "Msg_test", &[(1, 1000)]).await;

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        std::thread::sleep(std::time::Duration::from_millis(20));
        let wal_path = wal_path_for(&db_path);
        // <=32 字节会被生产 VFS 路径当成"无有效 WAL 帧"，这里只需要 bump
        // wal 文件的 mtime 来触发重建判定。
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "wal mtime 变了（即便 db 不变、WAL 内容不构成有效帧）也必须重建"
        );
    }

    #[tokio::test]
    async fn error_in_closure_clears_slot_forcing_rebuild() {
        let (cache, rel_key, _db_path) =
            setup_fixture_cache("err-clear", "Msg_test", &[(1, 1000)]).await;

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        // 制造一次真正的查询失败（不依赖具体 SQL 报错，直接让闭包返回
        // Err，模拟"prepare/schema 假设被打破"这类场景）。mtime 未变，所以
        // 这次调用本身是"复用尝试"而非"重建"，重建计数不应该增加。
        let hot_err = cache.hot_conn_handle(&rel_key).unwrap();
        let err = tokio::task::spawn_blocking(move || {
            hot_err.with(|_conn| Err::<(), _>(anyhow::anyhow!("forced test failure")))
        })
        .await
        .unwrap();
        assert!(err.is_err(), "闭包返回 Err 应该原样传播");
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            1,
            "复用一个已存在连接时查询失败，这次尝试本身不算重建"
        );

        // 但失败必须已经清空槽位——下一次调用必须重新 open()，不能复用一个
        // 可能处于不确定状态的旧连接。
        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "查询失败后应清空槽位，下次必须重建连接"
        );
    }

    #[tokio::test]
    async fn concurrent_access_same_rel_key_does_not_panic() {
        let (cache, rel_key, _db_path) =
            setup_fixture_cache("concurrent", "Msg_test", &[(1, 1000)]).await;
        let cache = Arc::new(cache);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache2 = Arc::clone(&cache);
            let rel_key2 = rel_key.clone();
            handles.push(tokio::spawn(async move {
                let hot = cache2.hot_conn_handle(&rel_key2).unwrap();
                tokio::task::spawn_blocking(move || {
                    hot.with(|conn| {
                        let cnt: i64 =
                            conn.query_row("SELECT count(*) FROM Msg_test", [], |r| r.get(0))?;
                        Ok::<_, anyhow::Error>(cnt)
                    })
                })
                .await
                .unwrap()
            }));
        }

        for h in handles {
            let r = h.await.expect("task 不应该 panic");
            assert_eq!(r.unwrap(), 1, "同一分片并发访问都应该查到正确数据");
        }

        // 槽位粒度的锁完整串行化了"校验 mtime → 复用或重建"整个临界区：
        // 8 次并发访问、mtime 全程未变，理应只有第一个抢到锁的调用触发
        // 一次真正的重建，其余 7 次都在它建好连接后复用——不应该出现"多个
        // 线程都看到 None、各自重建一次"的竞争。
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            1,
            "8 次并发访问、mtime 未变，应该只触发一次重建"
        );
    }

    #[tokio::test]
    async fn lru_eviction_drops_least_recently_used_shard() {
        // 驱逐逻辑本身是纯内存 bookkeeping，不需要真实分片文件，直接测
        // `HotConnPool`（容量调小，不需要真的构造十几个物理分片）。
        let pool = HotConnPool::with_capacity(2);

        let _slot_a = pool.slot("a");
        let _slot_b = pool.slot("b");
        assert_eq!(pool.len(), 2);
        assert!(pool.contains("a") && pool.contains("b"));

        // 访问 "a"（刷新其 last_used），再插入 "c" 应该驱逐最久未用的 "b"。
        let _ = pool.slot("a");
        let _slot_c = pool.slot("c");
        assert_eq!(pool.len(), 2, "容量上限为 2，插入第 3 个分片应触发驱逐");
        assert!(pool.contains("a"), "刚访问过的 a 不应被驱逐");
        assert!(pool.contains("c"), "新插入的 c 应该在池中");
        assert!(!pool.contains("b"), "最久未用的 b 应该被驱逐");
    }

    /// 端到端正确性：通过 `HotConnHandle::with()` 真实执行 SQL 查询，验证
    /// 新连接管理逻辑不影响查询结果本身，且 mtime 不变时复用同一连接。
    #[tokio::test]
    async fn real_query_through_hot_conn_sees_correct_data_and_reuses_connection() {
        let (cache, rel_key, _db_path) =
            setup_fixture_cache("real-query", "Msg_test", &[(1, 1000), (2, 2000)]).await;

        let (ptr1, count1, max_ts1) = {
            let hot = cache.hot_conn_handle(&rel_key).unwrap();
            tokio::task::spawn_blocking(move || {
                hot.with(|conn| {
                    let cnt: i64 =
                        conn.query_row("SELECT count(*) FROM Msg_test", [], |r| r.get(0))?;
                    let max_ts: i64 = conn.query_row(
                        "SELECT MAX(create_time) FROM Msg_test",
                        [],
                        |r| r.get(0),
                    )?;
                    Ok::<_, anyhow::Error>((unsafe { conn.handle() } as usize, cnt, max_ts))
                })
            })
            .await
            .unwrap()
            .unwrap()
        };
        assert_eq!(count1, 2, "应该读到夹具写入的 2 行");
        assert_eq!(max_ts1, 2000);

        // mtime 未变时第二次查询应该复用同一个连接，且结果保持一致。
        let (ptr2, count2) = {
            let hot = cache.hot_conn_handle(&rel_key).unwrap();
            tokio::task::spawn_blocking(move || {
                hot.with(|conn| {
                    let cnt: i64 =
                        conn.query_row("SELECT count(*) FROM Msg_test", [], |r| r.get(0))?;
                    Ok::<_, anyhow::Error>((unsafe { conn.handle() } as usize, cnt))
                })
            })
            .await
            .unwrap()
            .unwrap()
        };
        assert_eq!(ptr1, ptr2, "mtime 未变应复用同一连接");
        assert_eq!(count2, 2);
    }

    /// 加固点 1 的直接验证：把 db 文件重写成不同长度的内容后，将 mtime
    /// 显式钉回原值（模拟跨进程 mtime 可见性滞后到极致的情况）。只有失效键
    /// 里包含长度，这里才能正确识别为 Stale 并重建。
    #[tokio::test]
    async fn rebuild_when_db_len_changes_with_pinned_mtime() {
        let (cache, rel_key, db_path) =
            setup_fixture_cache("len-pin", "Msg_test", &[(1, 1000)]).await;

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        let original_mtime = mtime_nanos(&db_path);
        let original_len = std::fs::metadata(&db_path).unwrap().len();

        // 多插入几百行，确保跨过至少一个 4096 字节页边界、文件长度必然增长
        // （避免"只多一两行仍落在同一页内、长度没变"这种巧合）。
        let many_rows: Vec<(i64, i64)> = (1..=500i64).map(|i| (i, i * 1000)).collect();
        build_encrypted_fixture(&db_path, &key_fixture(), "Msg_test", &many_rows);
        let new_len = std::fs::metadata(&db_path).unwrap().len();
        assert_ne!(new_len, original_len, "测试前提：插入大量行应改变文件长度");

        std::fs::OpenOptions::new()
            .write(true)
            .open(&db_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(original_mtime))
            .unwrap();
        assert_eq!(
            mtime_nanos(&db_path),
            original_mtime,
            "测试前提：mtime 应该被钉回了原值"
        );

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "mtime 相同但文件长度已变化，必须重建——这是长度加入失效键要堵的场景"
        );
    }

    /// 加固点 2（HIGH，核心兜底）的直接验证：db/wal 都是"刚刚写入"的状态
    /// （落在新鲜度 slack 窗口内）。即便内容全程没有任何变化，也必须每次
    /// 都重建、绝不复用——只有安静满一整个 slack 周期才允许复用连接。
    #[tokio::test]
    async fn recently_written_shard_never_reuses_connection_within_slack() {
        let root = unique_tmpdir("recent-hotconn");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        let key = key_fixture();
        build_encrypted_fixture(&db_path, &key, "Msg_test", &[(1, 1000)]);
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();
        // 故意不回拨：两个文件的 mtime 就是"现在"。

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), key_to_hex(&key));
        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1, "首次访问必然重建");

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "文件仍在新鲜度 slack 窗口内，即便内容完全没变也必须重建，不能复用"
        );
    }

    /// 加固点 3（MEDIUM）的直接验证：分片没有 WAL 文件时 wal_mtime 恒为 0
    /// （"文件缺失"与"metadata 读取失败"共用的哨兵值，无法区分）。即便 db
    /// 早已安静很久、两次读到的快照逐字段完全相同，也不能被判定为可信。
    #[tokio::test]
    async fn missing_wal_zero_mtime_never_allows_reuse() {
        let root = unique_tmpdir("no-wal-hotconn");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        let key = key_fixture();
        build_encrypted_fixture(&db_path, &key, "Msg_test", &[(1, 1000)]);
        backdate_beyond_slack(&db_path); // 没有创建任何 -wal 文件

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), key_to_hex(&key));
        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        probe(&cache, &rel_key).await;
        assert_eq!(rebuild_count(&cache, &rel_key), 1);

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "wal_mtime=0（WAL 缺失）是未知哨兵值，永远不能被信任为可复用"
        );
    }
}
