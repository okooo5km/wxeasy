use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// FIX-MEDIUM：全局作废世代号。`invalidate_shard` 每次调用都递增一次；
    /// `put_shard_schema` 回写前比对调用方传入的《判定时刻》世代号与当前
    /// 世代号，不等就放弃写入。用于堵住"扫描 sqlite_master 的窗口期内，
    /// 另一个并发 RPC 对同一 rel_key（甚至任意 rel_key，见下方 `invalidate_shard`
    /// 文档的全局粒度权衡）发起 invalidate，随后过期的回写把已作废的路由
    /// 悄悄复活"这个竞态。`DbCache` 经 `Arc` 被 `server.rs` 每连接
    /// `tokio::spawn` 共享，这不是理论场景。
    ///
    /// LOW-1（"函数内部窗口"加固）：单纯把这个世代号做成 `AtomicU64` 只解决
    /// 了"调用间"竞态（`find_msg_shards` 判定 Stale 到发起扫描之间），没解决
    /// "函数内部窗口"——`put_shard_schema` 曾经是"先单独 `load` 世代号、再
    /// 单独一次 `shard_routes.lock().insert()`"两步分离，中间仍可能被
    /// `invalidate_shard` 插入。现在 `put_shard_schema` 与 `invalidate_shard`
    /// 都把"读/改这个世代号"移进了 `shard_routes` 那把锁的临界区内部完成，
    /// 用锁本身把两者串行化，不再有独立的两步窗口，见两个方法各自的文档。
    route_generation: AtomicU64,
    /// 路由缓存持久化（见 [`RouteCacheFile`]）：write-behind 脏标记 + 上次
    /// 落盘时刻（去抖）。
    routes_dirty: std::sync::atomic::AtomicBool,
    routes_last_flush: std::sync::Mutex<Option<std::time::Instant>>,
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
            route_generation: AtomicU64::new(0),
            routes_dirty: std::sync::atomic::AtomicBool::new(false),
            routes_last_flush: std::sync::Mutex::new(None),
        };

        cache.load_persistent().await;
        // 路由缓存的持久化加载必须发生在**这里**（构造期、server 开始
        // accept 之前）：此刻不存在任何并发调用者，直接灌入 shard_routes
        // 不经过世代号校验是安全的——§4.4/§4.5 的约束管的是并发期的
        // put/invalidate 串行化，构造期天然满足。
        cache.load_route_cache();
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
    ///
    /// FIX 2 后，`query.rs::find_msg_shards` 的热路径改用
    /// [`SourceSnapshot::freshness_secs`]（复用同一份已读取的快照，不再
    /// 单独 stat），这个方法在非 test 构建下因此只剩下文档 / 兼容意义，
    /// 仍保留给未来可能的独立调用方，并继续被下方单元测试直接验证。
    #[cfg_attr(not(test), allow(dead_code))]
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
    ///
    /// `pub(crate)`（FIX 2）：`query.rs::find_msg_shards` 需要在每个分片的
    /// 循环体顶部主动读一次快照，再把同一份值透传给 skip 判定 / 路由
    /// lookup / 热连接门控三处（见 [`Self::shard_route_lookup_with_snapshot`]
    /// / [`Self::hot_conn_handle_with_snapshot`]），消除原本三处各自独立
    /// `fs::metadata` 造成的重复系统调用。
    pub(crate) fn source_snapshot(&self, rel_key: &str) -> SourceSnapshot {
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
    ///
    /// 内部现读一份新快照再委托给 [`Self::shard_route_lookup_with_snapshot`]；
    /// 保留这个签名给独立调用方（不在 `find_msg_shards` 那种"一次快照喂三处"
    /// 的循环里、无快照可复用的场景）。FIX 2 后 `find_msg_shards` 改走
    /// `_with_snapshot` 变体，生产代码暂时没有其它调用点，非 test 构建下
    /// 因此是 dead_code；继续被下方单元测试直接验证，保留给未来的独立
    /// 调用方。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn shard_route_lookup(&self, rel_key: &str) -> ShardRouteLookup {
        let snapshot = self.source_snapshot(rel_key);
        self.shard_route_lookup_with_snapshot(rel_key, snapshot)
    }

    /// FIX 2：[`Self::shard_route_lookup`] 的去重 I/O 版本——判定逻辑完全
    /// 相同，只是快照来源从"内部现读"换成"调用方传入"，供 `find_msg_shards`
    /// 在循环体顶部只读一次 [`SourceSnapshot`] 后，同一份值分别喂给这里、
    /// skip 判定（[`SourceSnapshot::freshness_secs`]）和
    /// [`Self::hot_conn_handle_with_snapshot`]。
    pub(crate) fn shard_route_lookup_with_snapshot(
        &self,
        rel_key: &str,
        snapshot: SourceSnapshot,
    ) -> ShardRouteLookup {
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
    ///
    /// # FIX-MEDIUM（TOCTOU：invalidate 与回写的竞态）
    /// `expected_generation` 必须是《发起判定那一刻》读到的 [`Self::route_generation`]
    /// （与 `snapshot` 同一时刻读取，见 `query.rs::find_msg_shards` 的调用
    /// 处）。写入前会与《此刻》的当前世代号比较：不相等就说明扫描
    /// `sqlite_master` 这段窗口期内，有另一个并发调用（同一 `rel_key` 或
    /// 任意其它 `rel_key`，见 [`Self::invalidate_shard`] 的全局粒度说明）
    /// 触发过 `invalidate_shard`——此时必须放弃这次回写，宁可让下一轮因为
    /// 路由缓存 miss 重新扫一遍，也不能用一份可能已经过期的 schema 悄悄
    /// 复活刚被作废的路由（复活后该分片通常已经安静过 slack，下一轮又会
    /// 被判 Fresh，不会自愈）。
    ///
    /// # LOW-1（"函数内部窗口"：把世代号校验也纳入 `shard_routes` 锁）
    /// 旧实现是"先 `self.route_generation.load()`，再单独一次
    /// `self.shard_routes.lock().insert()`"——两次独立加锁，中间存在一个
    /// 窗口：若 `invalidate_shard`（同一 `rel_key`）恰好落在《load 已经通过》
    /// 和《insert 尚未执行》之间，本次 load 时世代号确实还没变，但 insert
    /// 执行时刻已经晚于那次 invalidate，等价于把一条《本该被作废》的路由
    /// 又悄悄写回缓存——这是上面 FIX-MEDIUM 想堵的同一竞态在"函数内部"的
    /// 变体，两次独立加锁本身留出了这个窗口。
    ///
    /// 现在改为：先拿到 `shard_routes` 那把锁（`guard`），**在持锁期间**才去
    /// `load` 世代号并比较，通过才 `insert`，全程只持这一把锁、不释放不
    /// 重新获取。[`Self::invalidate_shard`] 同样把"移除路由条目"与"世代号
    /// 自增"放进了同一把 `shard_routes` 锁的临界区（见其文档）。于是 put 与
    /// invalidate 在 `shard_routes` 这把锁上严格互斥、串行执行，只有两种
    /// 可能的先后顺序，且都不会遗留"被复活的过期条目"：
    /// - put 先拿到锁：此时 invalidate 还没发生，世代号仍等于
    ///   `expected_generation`，校验通过、正常 insert；invalidate 随后拿到
    ///   锁，把这条刚写入的记录 `remove` 掉、世代号自增——下一次 lookup 会
    ///   因为 miss 判 Stale，不会读到过期数据。
    /// - invalidate 先拿到锁：世代号已经自增；put 随后拿到锁、在锁内
    ///   `load` 到的已经是新世代号，与调用方持有的旧 `expected_generation`
    ///   不相等，直接放弃写入，不会把作废前的旧数据写回。
    ///
    /// 两把子锁（`shard_routes` 用的 `std::sync::Mutex`、`route_generation`
    /// 用的 `AtomicU64`）本身没有合并——这里说的"同一把锁"专指
    /// `shard_routes` 那把 `Mutex`：世代号的读/改被移进了这把锁的临界区
    /// 内部执行，而不是给 `AtomicU64` 自己加锁，因此不引入除
    /// `shard_routes` 之外的新锁、不产生新的跨锁死锁风险。世代号的
    /// load/fetch_add 全程使用 `SeqCst` 且都发生在同一把锁的临界区内，
    /// 因此这里的顺序保证同时来自锁的互斥语义与 `SeqCst` 的内存序，两者
    /// 一致、不冲突。
    pub fn put_shard_schema(
        &self,
        rel_key: String,
        snapshot: SourceSnapshot,
        msg_tables: HashSet<String>,
        expected_generation: u64,
    ) {
        // 先持锁，世代号的读取和校验都必须在这把锁的临界区内部完成——
        // 这是 LOW-1 修复的关键：不能像旧实现那样在锁外单独 load。
        {
            let mut guard = self.shard_routes.lock();
            if self.route_generation.load(Ordering::SeqCst) != expected_generation {
                // 世代号已经变化：期间发生过至少一次 invalidate_shard，这份
                // 回写可能反映的是作废之前的旧状态，直接丢弃，不写入。
                return;
            }
            guard.insert(rel_key, ShardSchemaEntry { snapshot, msg_tables });
        }
        // 持久化 write-behind：锁外打脏标记 + 去抖落盘（见 RouteCacheFile）。
        self.note_routes_dirty();
    }

    /// 路由缓存持久化文件路径。
    fn route_cache_path(&self) -> PathBuf {
        self.cache_dir.join(ROUTE_CACHE_FILE_NAME)
    }

    /// 构造期加载持久化的路由缓存（见 [`RouteCacheFile`] 的安全性论证与
    /// 已拍板取舍）。任何不匹配 / 损坏 ⇒ 静默丢弃走冷路径。
    fn load_route_cache(&self) {
        let content = match std::fs::read_to_string(self.route_cache_path()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let parsed: RouteCacheFile = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };
        if parsed.version != ROUTE_CACHE_VERSION
            || parsed.db_dir != self.db_dir.to_string_lossy()
        {
            return;
        }
        let count = parsed.entries.len();
        if count == 0 {
            return;
        }
        let mut guard = self.shard_routes.lock();
        for (rel_key, entry) in parsed.entries {
            // 只接受当前配置仍然认识的 rel_key，防止改配置后残留条目复活。
            if self.all_keys.contains_key(&rel_key) {
                guard.insert(rel_key, entry);
            }
        }
        eprintln!("[cache] 路由缓存: 从磁盘恢复 {} 个分片条目", count);
    }

    /// write-behind：打脏标记，去抖间隔已过就把当前路由表快照落盘（详见
    /// [`RouteCacheFile`]——文件按「天然可丢最近一个去抖周期」设计）。
    /// 序列化 + 写文件在分离线程执行，不阻塞调用方（put/invalidate 可能
    /// 发生在 async 收割循环里）。
    fn note_routes_dirty(&self) {
        self.routes_dirty
            .store(true, std::sync::atomic::Ordering::Release);
        let now = std::time::Instant::now();
        {
            let mut last = self
                .routes_last_flush
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(prev) = *last {
                if now.duration_since(prev).as_secs() < ROUTE_FLUSH_DEBOUNCE_SECS {
                    return;
                }
            }
            *last = Some(now);
        }
        self.routes_dirty
            .store(false, std::sync::atomic::Ordering::Release);
        let path = self.route_cache_path();
        let file = self.route_cache_snapshot();
        std::thread::spawn(move || {
            let _ = write_route_cache_file(&path, &file);
        });
    }

    /// 测试钩子 + 内部复用：同步落盘当前路由表（绕过去抖）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn flush_routes_now(&self) {
        self.routes_dirty
            .store(false, std::sync::atomic::Ordering::Release);
        let _ = write_route_cache_file(&self.route_cache_path(), &self.route_cache_snapshot());
    }

    fn route_cache_snapshot(&self) -> RouteCacheFile {
        RouteCacheFile {
            version: ROUTE_CACHE_VERSION,
            db_dir: self.db_dir.to_string_lossy().into_owned(),
            entries: self.shard_routes.lock().clone(),
        }
    }

    /// FIX-MEDIUM：读取当前作废世代号（同步、非阻塞，纯原子读）。调用方
    /// （`query.rs::find_msg_shards`）应在"决定重建、真正发起 `spawn_blocking`
    /// 扫描之前"读一次并保留，扫描完成后连同结果一起交给
    /// [`Self::put_shard_schema`]。
    pub(crate) fn route_generation(&self) -> u64 {
        self.route_generation.load(Ordering::SeqCst)
    }

    /// 优化 B：借这一次查询拿到（或复用）某个分片的常驻热连接句柄。
    /// 同步、非阻塞（`resolve_conn_params` 只做 HashMap 查找 + `exists()`
    /// 检查，`source_snapshot` 只做 `fs::metadata`，`hot_conns.slot` 只是
    /// 内存 HashMap 操作）——真正的阻塞 I/O（可能的重建）延后到
    /// [`HotConnHandle::with`] 内部，调用方应在 `spawn_blocking` 里调用它。
    ///
    /// 内部现读一份新快照再委托给 [`Self::hot_conn_handle_with_snapshot`]；
    /// 保留这个签名给所有不经过 `find_msg_shards` 循环、手上没有现成快照的
    /// 独立调用方（`q_history` / `q_new_messages` 等直接按 `shard.rel_key`
    /// 要热连接的场景）。
    pub fn hot_conn_handle(&self, rel_key: &str) -> Result<HotConnHandle> {
        let snapshot = self.source_snapshot(rel_key);
        self.hot_conn_handle_with_snapshot(rel_key, snapshot)
    }

    /// FIX 2：[`Self::hot_conn_handle`] 的去重 I/O 版本，语义完全相同，只是
    /// 快照来源从"内部现读"换成"调用方传入"——用法同
    /// [`Self::shard_route_lookup_with_snapshot`]。
    pub(crate) fn hot_conn_handle_with_snapshot(
        &self,
        rel_key: &str,
        snapshot: SourceSnapshot,
    ) -> Result<HotConnHandle> {
        let conn_params = self.resolve_conn_params(rel_key)?;
        let (slot, rebuild_count) = self.hot_conns.slot(rel_key);
        let cache_size_kb = self.hot_conns.cache_size_kb();
        Ok(HotConnHandle {
            slot,
            conn_params,
            snapshot,
            rebuild_count,
            cache_size_kb,
        })
    }

    /// FIX ②：daemon 预热阶段拿到真实分片数（`msg_db_keys.len()`）后调整
    /// 热连接池容量——`DbCache::new()` 构造时机早于分片数确定（见
    /// `mod.rs::async_run`：`db` 先建好，`msg_db_keys` 才从 `all_keys` 里
    /// 过滤出来），容量没法在构造函数参数里直接给,只能构造后由调用方补
    /// 设置一次。调用方应传入 [`hot_pool_capacity_for_shard_count`] 算出的
    /// 值，且应该在真正开始处理任何查询之前调用（此刻池子还是空的，不会
    /// 有"缩容时需要批量驱逐已有连接"的问题，见 [`HotConnPool::set_capacity`]
    /// 文档）。
    ///
    /// 纯原子写、微秒级，可以在 async 上下文里直接同步调用，不需要
    /// `spawn_blocking`。
    pub fn set_hot_pool_capacity(&self, capacity: usize) {
        self.hot_conns.set_capacity(capacity);
    }

    /// FIX 1：反查"路由缓存里，哪些分片当时记录的 `msg_tables` 包含这个
    /// 表名"。O(路由缓存条目数)，纯内存只读遍历（`ShardRouteCache` 内部是
    /// `std::sync::Mutex<HashMap<..>>`，临界区不跨 `.await`），不做任何
    /// I/O。会话 → 分片的映射本身是稳定的（一个会话的 `Msg_<md5>` 表只会
    /// 出现在它当初被建表的那一个分片里），只要该分片此前被
    /// `find_msg_shards` 真正扫描过、写进过路由缓存，这里就能查到；从未
    /// 被扫描过的分片（典型是全新会话对应的分片）查不到，返回空 —— 调用方
    /// （见 [`Self::invalidate_shard`] 的用法）不需要对这种情况做任何特殊
    /// 处理：新建表必然 bump 该分片的 mtime/len，`shard_route_lookup` 的
    /// 快照比对会自然判 Stale、触发重建，不需要这里额外插手。
    pub fn route_shard_for_table(&self, table_name: &str) -> Vec<String> {
        self.shard_routes.rel_keys_containing(table_name)
    }

    /// FIX 1（核心·焊死"mtime 滞后漏消息"）：强制作废某个分片的路由缓存
    /// 条目 + 热连接，逼它下次被访问时现场重新 `open()`（`ConnParams::open`
    /// 内部 `File::open` + 重新扫 WAL 帧头建索引，直接读当前真实字节，不
    /// 依赖任何 mtime/len 比较）。
    ///
    /// 用途：`q_new_messages` 里 `session.db` 是每轮新读、内容可靠的真相
    /// 源，一旦确认某个会话 `changed`（`session.db` 显示它有新消息），就
    /// 应该在进入这个会话的消息查询前调用本方法作废其承载分片——绕开
    /// "两个 mtime 门控缓存靠跨进程读到的文件 mtime 判新鲜，Windows/NTFS
    /// 上可能滞后于实际写入"这个窗口，不依赖任何时间戳比较，从而不会有
    /// 假阳性。
    ///
    /// 线程安全，走两个子缓存各自既有的锁范式；只在这次调用内做纯内存
    /// HashMap 操作，不跨越任何 `.await`、不做阻塞 I/O。只影响下一次访问，
    /// 找不到对应条目（miss）时两个子操作都是安全的空操作。
    ///
    /// FIX-MEDIUM：额外递增全局 [`Self::route_generation`]（`SeqCst`，
    /// 无条件——即便两个子操作都是 miss 也照样递增，调用方无法区分，也不
    /// 需要区分：递增本身零成本，多余的世代号跳变顶多让个别在飞回写多余地
    /// 被丢弃一次，不影响正确性）。刻意选用**全局**而非按 `rel_key` 分别计数
    /// ——任何一次 `invalidate_shard`（不论作用于哪个 `rel_key`）都会让当前
    /// 所有"正在扫描、尚未回写"的 [`Self::put_shard_schema`] 调用作废，宁可
    /// 换来一些不相关分片的多余重扫，也不实现更复杂的按 key 世代号（那样
    /// 才能精确到"只有同一 rel_key 的并发 invalidate 才丢弃回写"）。这个
    /// 取舍只产生性能代价（多解密/多重扫几次），不产生正确性代价（不会
    /// 漏读、不会复活已作废的路由）。
    ///
    /// # LOW-1（"函数内部窗口"：路由移除与世代号自增现在共享同一把锁）
    /// 路由条目的 `remove` 与世代号的 `fetch_add` 现在放在 `shard_routes`
    /// 那把锁的**同一个**临界区内部完成（[`ShardRouteCache::remove_and_bump_generation`]），
    /// 不再是"remove 内部自己加锁释放锁，外面再单独 fetch_add"这种两步
    /// 分离的写法。这与 [`Self::put_shard_schema`] 把"世代号校验"也挪进
    /// 同一把锁的临界区是同一次修复的两面：`shard_routes` 这把锁把 put 与
    /// invalidate 严格串行化，谁先拿到锁谁的效果先生效，不再存在"remove
    /// 已释放锁、fetch_add 还没执行"这种独立子窗口。
    ///
    /// # LOW-2（已知、故意、有界的不变量：路由失效与热连接逐出非原子）
    /// 清路由（上面这部分，已纳入 `shard_routes` 锁）与逐出热连接
    /// （`self.hot_conns.evict(rel_key)`）依然是**两次独立加锁**——
    /// `shard_routes` 用的 `std::sync::Mutex<HashMap<..>>` 和 `hot_conns`
    /// 用的 `std::sync::Mutex<HashMap<String, HotShardSlot>>` 是两把完全独立
    /// 的锁，这里故意不合并成一次跨锁的原子操作。
    ///
    /// 理论窗口：路由缓存已经标记为 Stale 之后、热连接实际被逐出之前的这
    /// 一小段间隙里，如果有另一个并发查询恰好落在这个间隙、并且它读到的
    /// 《当前快照》与热连接槽位里缓存的旧快照逐字段相等（见
    /// [`HotConnHandle::with`] 的 `stale` 判定），理论上可能复用到一个
    /// "应该被作废但还没来得及被逐出"的旧连接。
    ///
    /// 这个窗口不是本轮新引入的——它是优化 A（路由缓存）/ 优化 B（热连接池）
    /// 这两个独立 mtime 门控缓存的既有设计特性，从它们被引入的第一天起就
    /// 存在。触发它需要同时满足两个苛刻条件：(1) 源文件的跨进程 mtime 可见
    /// 性持续滞后超过 [`HOT_CACHE_FRESHNESS_SLACK_NANOS`]（600 秒）——否则
    /// [`SourceSnapshot::trusted_as_of`] 根本不允许把旧快照当作可信，直接
    /// 强制重建；且 (2) 另一个查询精确撞在"路由已清、热连接未逐出"这几条
    /// 指令之间的极窄窗口。两个条件叠加发生的概率极低。
    ///
    /// 不合并成跨锁原子操作的理由：`shard_routes` 和 `hot_conns` 是两把
    /// 完全独立、服务不同调用路径的锁（前者被 `shard_route_lookup` /
    /// `put_shard_schema` 用，后者被 `hot_conn_handle` / `HotConnHandle::with`
    /// 用），把它们合并成"先拿 A 锁再拿 B 锁"的固定顺序，会给这两把锁引入
    /// 此前不存在的锁顺序依赖——一旦未来任何新代码路径以相反顺序获取这两把
    /// 锁（哪怕只是无意为之），就会产生死锁风险。为了堵一个概率极低、且已
    /// 有其它机制兜底的窗口，去承担真实的死锁风险，得不偿失。
    ///
    /// 最终正确性的兜底不是这里的原子性，而是 [`HotConnHandle::with`] 每次
    /// 使用热连接前都会用《本次查询发起时刻》读到的实时快照，与槽位里缓存
    /// 的快照做逐字段相等比较，并且同样要求这份快照已经 `trusted_as_of`——
    /// 双门控叠加之后，这个理论窗口不会导致"读到错误内容被上层当作正确结果
    /// 使用"，最坏情况也只是多复用一次很快又会被下一次查询判定为 Stale 的
    /// 连接。把这一条视为"已知、故意、有界"的不变量：后来者不应该因为看到
    /// 两次独立加锁就误判为遗漏的 bug 去合并它们。
    pub fn invalidate_shard(&self, rel_key: &str) {
        self.shard_routes
            .remove_and_bump_generation(rel_key, &self.route_generation);
        self.hot_conns.evict(rel_key);
        // 作废也是路由表状态变化，同样打脏标记（去抖之内只是标记，无 IO）。
        self.note_routes_dirty();
    }
}

/// 原子写路由缓存文件：临时文件 + rename（Windows 上 `fs::rename` 走
/// `MOVEFILE_REPLACE_EXISTING`，可覆盖既有文件）。任何失败静默忽略——
/// 文件只是影子，丢了走冷路径。
fn write_route_cache_file(path: &Path, file: &RouteCacheFile) -> std::io::Result<()> {
    let json = serde_json::to_string(file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
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
/// 长度（字节），以及 `wal_present` 显式标记 WAL 文件当时是否存在。
/// [`ShardSchemaEntry`]（优化 A）与 [`HotConn`]（优化 B）都存这个类型、用
/// 同一套 [`Self::trusted_as_of`] 判定逻辑，避免两处独立实现同一套"要不要
/// 信任缓存"规则、后续改动漏改一处。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SourceSnapshot {
    db_mtime: u64,
    db_len: u64,
    wal_mtime: u64,
    wal_len: u64,
    /// FIX 3：显式区分"WAL 文件当时存在"与"WAL 文件当时不存在"。没有这个
    /// 标志，`wal_mtime == 0` 无法区分"合法的没有 WAL 文件"（已 checkpoint
    /// 的休眠分片，正常状态）与"WAL 文件存在但 metadata 读取失败"（真正的
    /// 未知），后者才应该被 [`Self::has_unknown_component`] 拒绝信任。纳入
    /// `#[derive(PartialEq)]` 的相等比较后，"WAL 从不存在变存在"（微信刚
    /// 开始写这个分片）天然让快照判定为不同，强制失效重建——不需要额外的
    /// 特判代码。
    wal_present: bool,
}

impl SourceSnapshot {
    /// 读取 `db_path` / `wal_path`（若存在）当前的 mtime + 长度，并记录 WAL
    /// 是否存在。三态区分（FIX 3）：
    /// - WAL 不存在 → `wal_present=false`，mtime/len 固定为 0，是合法的
    ///   "已 checkpoint 休眠分片"状态，[`Self::has_unknown_component`] 不再
    ///   因此拒绝信任；
    /// - WAL 存在且 metadata 读取成功 → `wal_present=true`，使用真实
    ///   mtime/len；
    /// - WAL 存在但 metadata 读取失败 → `wal_present=true`、mtime/len 回退
    ///   为 0（`metadata_mtime_len` 的既有失败语义）——这才是真正的"未知"，
    ///   由 [`Self::has_unknown_component`] 识别并拒绝信任。
    fn capture(db_path: &Path, wal_path: &Path) -> Self {
        let (db_mtime, db_len) = metadata_mtime_len(db_path);
        let wal_present = wal_path.exists();
        let (wal_mtime, wal_len) = if wal_present {
            metadata_mtime_len(wal_path)
        } else {
            (0, 0)
        };
        Self {
            db_mtime,
            db_len,
            wal_mtime,
            wal_len,
            wal_present,
        }
    }

    /// 加固点 3（MEDIUM，FIX 3 后语义收紧）：只有以下两种情况才算"未知"：
    /// - `db_mtime == 0`：主库 metadata 读取失败或文件缺失；
    /// - `wal_present == true && wal_mtime == 0`：WAL 文件存在，但那一刻
    ///   metadata 读取失败（`unwrap_or(0)` 回退）。
    ///
    /// `wal_present == false`（WAL 文件当时确实不存在，已 checkpoint 的
    /// 休眠分片）不再落入这条规则——这是合法、可信的已知状态，允许参与
    /// Fresh 判定。这是 FIX 3 相对旧版的唯一语义变化：旧版把"WAL 缺失"和
    /// "WAL 存在但读取失败"用同一个哨兵值 0 强行合并成"一律未知"，误杀了
    /// 大量已 checkpoint、不会再变的休眠分片，让它们每轮都被迫重建/重开
    /// 连接。
    fn has_unknown_component(&self) -> bool {
        self.db_mtime == 0 || (self.wal_present && self.wal_mtime == 0)
    }

    /// FIX 2：从这份快照推导 `shard_skippable` 所需的"较新 mtime，秒精度"，
    /// 语义与既有 [`DbCache::source_freshness_secs`] 完全一致（`db_mtime
    /// == 0` 代表主库不可读，返回 `None`；`wal_mtime`——不论是"WAL 缺失"
    /// 还是"WAL 存在但读取失败"，两者这里都固定为 0——仍然照常参与 `max`
    /// 取较新值，不像 [`Self::has_unknown_component`] 那样对 wal 分量单独
    /// 判"未知"）。这是 `shard_skippable` 24 小时宽松 slack 路径的既有
    /// 语义，与优化 A/B 的严格 600 秒 slack 规则刻意不同、不能混用，见
    /// 模块顶部"正确性加固"说明。
    pub(crate) fn freshness_secs(&self) -> Option<i64> {
        if self.db_mtime == 0 {
            return None;
        }
        Some((self.db_mtime.max(self.wal_mtime) / 1_000_000_000) as i64)
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

    fn snap(db_mtime: u64, db_len: u64, wal_mtime: u64, wal_len: u64, wal_present: bool) -> SourceSnapshot {
        SourceSnapshot {
            db_mtime,
            db_len,
            wal_mtime,
            wal_len,
            wal_present,
        }
    }

    #[test]
    fn zero_db_mtime_is_unknown() {
        assert!(snap(0, 10, 1_000_000_000, 5, true).has_unknown_component());
    }

    /// FIX 3：WAL 存在但 metadata 读取失败（`wal_present=true` 却
    /// `wal_mtime=0`）——这才是真正的"未知"，必须拒绝信任。
    #[test]
    fn wal_present_but_zero_mtime_is_unknown() {
        assert!(snap(1_000_000_000, 10, 0, 0, true).has_unknown_component());
    }

    /// FIX 3（核心语义变化）：WAL 文件当时确实不存在（`wal_present=false`）
    /// 是合法的已 checkpoint 休眠分片状态，不再被当作"未知"——与上一个测试
    /// 唯一的区别就是 `wal_present`，用来证明这个标志确实在起区分作用。
    #[test]
    fn wal_absent_is_known() {
        assert!(!snap(1_000_000_000, 10, 0, 0, false).has_unknown_component());
    }

    #[test]
    fn nonzero_mtimes_are_known() {
        assert!(!snap(1_000_000_000, 10, 2_000_000_000, 5, true).has_unknown_component());
    }

    #[test]
    fn unknown_component_never_trusted_regardless_of_age() {
        // db_mtime=0（未知）时，即便 wal 那部分"看起来"很旧，也绝不能信任。
        let s = snap(0, 10, 2_000_000_000, 5, true);
        let far_future_now = 10 * HOT_CACHE_FRESHNESS_SLACK_NANOS;
        assert!(!s.trusted_as_of(far_future_now));
    }

    #[test]
    fn fresh_within_slack_is_not_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5, true);
        // now 只比 newest 早了 (slack - 1) 纳秒的距离，仍落在窗口内。
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS - 1;
        assert!(!s.trusted_as_of(now), "还没过满一个 slack 周期，不能信任");
    }

    #[test]
    fn exactly_at_slack_boundary_is_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5, true);
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS; // 恰好等于 slack
        assert!(s.trusted_as_of(now), "age == slack 应该允许信任（>= 边界）");
    }

    /// FIX 3：无 WAL 的休眠分片（`wal_present=false`）一样能吃到"安静满一个
    /// slack 周期即可信任"这条规则——不再被 `has_unknown_component` 提前
    /// 拦下。
    #[test]
    fn dormant_shard_without_wal_is_trusted_beyond_slack() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, 0, 0, false);
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS;
        assert!(s.trusted_as_of(now), "无 WAL 的休眠分片安静满一个 slack 周期后应该可信");
    }

    #[test]
    fn well_beyond_slack_is_trusted() {
        let newest = 1_000_000_000_000u64;
        let s = snap(newest, 10, newest, 5, true);
        let now = newest + HOT_CACHE_FRESHNESS_SLACK_NANOS * 10;
        assert!(s.trusted_as_of(now));
    }

    #[test]
    fn future_mtime_from_clock_skew_is_never_trusted() {
        // mtime 比 now 还"新"（时钟回拨/偏斜）：饱和减法把 age 钳制为 0，
        // 必须当作"最新"处理，绝不能被判定为可信。
        let newest = 2_000_000_000_000u64;
        let s = snap(newest, 10, newest - 1, 5, true);
        let now = 1_000_000_000_000u64; // 早于 newest
        assert!(!s.trusted_as_of(now));
    }

    #[test]
    fn different_len_makes_snapshot_unequal_even_with_same_mtime() {
        let a = snap(1_000, 10, 2_000, 5, true);
        let b = snap(1_000, 11, 2_000, 5, true);
        assert_ne!(a, b, "长度不同必须视为不同快照，即便 mtime 完全相同");
    }

    /// FIX 3（TOCTOU 关键点）：`wal_present` 从 `false`（WAL 不存在）变成
    /// `true`（微信刚开始写这个分片），即便 mtime/len 数值部分因为都固定
    /// 为 0 而"看起来相同"，两份快照也必须被判定为不同——否则"WAL 刚出现"
    /// 这个关键事件会被漏检，误判为快照没变、继续信任旧缓存。
    #[test]
    fn wal_appearing_makes_snapshot_unequal_even_with_zeroed_mtime_len() {
        let absent = snap(1_000, 10, 0, 0, false);
        let present = snap(1_000, 10, 0, 0, true);
        assert_ne!(
            absent, present,
            "wal_present 翻转必须让快照判定为不同，即便数值分量都还是 0"
        );
    }

    #[test]
    fn freshness_secs_none_when_db_mtime_zero() {
        assert_eq!(snap(0, 10, 5_000_000_000, 5, true).freshness_secs(), None);
    }

    #[test]
    fn freshness_secs_takes_newer_of_db_and_wal() {
        // wal 比 db 新：应取 wal。
        assert_eq!(
            snap(1_000_000_000, 10, 5_000_000_000, 5, true).freshness_secs(),
            Some(5)
        );
        // db 比 wal 新（或 wal 缺失/未知回退为 0）：应取 db。
        assert_eq!(
            snap(7_000_000_000, 10, 0, 0, false).freshness_secs(),
            Some(7)
        );
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
#[derive(Clone, Serialize, Deserialize)]
struct ShardSchemaEntry {
    snapshot: SourceSnapshot,
    msg_tables: HashSet<String>,
}

/// 路由缓存的持久化文件格式（`cache_dir/route_cache.json`）。
///
/// # 为什么可以安全持久化（以及交易掉了什么）
/// [`SourceSnapshot`] 是**纯外部事实**（源文件 mtime 纳秒 + 长度 +
/// `wal_present`），不依赖任何进程内状态；加载回来的条目走与内存条目完全
/// 相同的门控（快照逐字段相等 + `trusted_as_of` 安静期），不需要发明新的
/// 失效机制。版本号或 `db_dir` 身份不匹配、文件损坏 ⇒ 整体丢弃走冷路径；
/// 内存永远是真相，文件只是影子。
///
/// **已拍板的取舍（2026-07-22，Boss 决策：选快）**：daemon 重启后首轮
/// `q_new_messages` 的 unresolved 全量作废，在持久化路由命中时会退化为
/// 精准作废——等于放弃了「重启 = 对 mtime 滞后超 slack 残余窗口的免费
/// 全量重置」这道隐形保险。残余风险为 LOW（需要 mtime 滞后持续超过
/// 600s slack + 分片滚动 + 精准撞窗同时发生；且滞后主要出现在微信持续
/// 持句柄写入期间，而 daemon 重启多伴随开机、元数据已落定）。
///
/// # Windows 无退出钩子
/// `setup_signal_handler` 是 `#[cfg(unix)]`，daemon 被 taskkill 时没有任何
/// 通知——本文件按「天然可丢最近 [`ROUTE_FLUSH_DEBOUNCE_SECS`] 秒」设计，
/// 丢了只是下次冷启动多扫几个分片，不存在正确性影响。
#[derive(Serialize, Deserialize)]
struct RouteCacheFile {
    version: u32,
    /// 身份字段：db_dir 不同的账号绝不混用彼此的路由缓存。
    db_dir: String,
    entries: HashMap<String, ShardSchemaEntry>,
}

const ROUTE_CACHE_VERSION: u32 = 1;
const ROUTE_CACHE_FILE_NAME: &str = "route_cache.json";
/// write-behind 去抖间隔：稳态轮询里 put/invalidate 每轮都发生，去抖后
/// 磁盘写至多每 30 秒一次。
const ROUTE_FLUSH_DEBOUNCE_SECS: u64 = 30;

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

    /// FIX 1：反查哪些 rel_key 当时记录的 `msg_tables` 里含有 `table_name`。
    /// O(条目数) 线性扫描——路由缓存条目数等于"曾经被扫描过的分片数"，量级
    /// 很小（个位数到十几），不需要额外维护反向索引。
    fn rel_keys_containing(&self, table_name: &str) -> Vec<String> {
        self.lock()
            .iter()
            .filter(|(_, entry)| entry.msg_tables.contains(table_name))
            .map(|(rel_key, _)| rel_key.clone())
            .collect()
    }

    /// FIX 1 + LOW-1：作废某个分片的路由缓存条目，并在**同一把锁的临界区
    /// 内部**顺带把 `generation` 自增一次。miss（从未缓存过）是安全的空
    /// 操作，一样会自增世代号（与旧版 `invalidate_shard` 的"无条件递增"
    /// 语义保持一致，见 [`DbCache::invalidate_shard`] 文档）。
    ///
    /// 之所以把这两步合并成一个方法而不是分别暴露 `remove()` +
    /// 调用方自己 `fetch_add()`：把它们拆成两次独立调用又会重新引入
    /// LOW-1 想堵的"函数内部窗口"——调用方在两次调用之间可能被其它线程
    /// 抢占，即便概率很低也失去了"用锁串行化"的保证。合并成一个方法，
    /// 让锁的持有范围精确覆盖这两步操作，是唯一能保证原子性的写法。
    fn remove_and_bump_generation(&self, rel_key: &str, generation: &AtomicU64) {
        let mut guard = self.lock();
        guard.remove(rel_key);
        // 与 `put_shard_schema` 里的 `load` 共享同一把 `shard_routes` 锁的
        // 临界区语义：这里的 `fetch_add` 和那边的 `load` 谁先执行，由锁的
        // 获取顺序决定，不会出现两者交错的中间态。
        generation.fetch_add(1, Ordering::SeqCst);
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

/// 同时保留的热连接分片数上限的**默认值**（daemon 启动、真正拿到分片数
/// 之前的初始值，见 [`HotConnPool::new`]）。超过时驱逐最久未用的一个——
/// 线性扫描找最小 `last_used`，复杂度 O(容量)。
///
/// FIX ②（容量随规模伸缩）之前，这是一个写死的硬上限；固定 12 在大账号
/// （120GB+ 账号实测可能有 65~80 个消息分片）下形同虚设——热连接池天天
/// 被塞满、LRU 反复驱逐刚建好的连接，完全吃不到"同一分片多轮复用"的
/// 收益。FIX ② 后，`mod.rs::async_run` 在预热阶段拿到真实 `msg_db_keys`
/// 数量后，会调用 [`DbCache::set_hot_pool_capacity`]（内部即
/// [`hot_pool_capacity_for_shard_count`] 的换算结果）把容量调整到
/// `[12, 64]` 区间——12 作为下限延续这个常量原来的取值（小账号没有调大的
/// 必要），64 是"当前 O(容量) 线性驱逐扫描 + 下面 [`compute_hot_conn_cache_size_kb`]
/// 内存预算换算仍然安全"的上界；继续往上调，线性驱逐扫描（个位数到十几
/// 量级下可忽略）需要先换成更高效的数据结构（如 `IndexMap` 或双向链表 +
/// 索引）。
const MAX_HOT_SHARDS: usize = 12;

/// FIX ②：热连接池整体内存预算上限（KB）——`容量 × 单连接 cache_size` 必须
/// `≲` 这个值。256MiB 是"多个热连接同时保留页缓存"这件事本身愿意付出的
/// 内存代价上限，不是某个精确测得的数字，选一个足够宽松、又不至于在大账号
/// 上失控增长的量级。
const HOT_CONN_MEMORY_BUDGET_KB: i64 = 256 * 1024;

/// FIX ②：单连接 `PRAGMA cache_size`（负数=KB）的封顶值——对应"容量仍是
/// [`MAX_HOT_SHARDS`] 原值 12"时的历史行为（`262144 / 12 ≈ 21845`，被这个
/// 封顶值夹到 16384），保证容量在小账号上维持这个常量引入前逐字节相同的
/// 单连接缓存大小，`hot_conn_tests` 里全部既有的复用/重建断言不受影响。
const HOT_CONN_CACHE_SIZE_KB_CEILING: i64 = 16_384;

/// FIX ②：单连接 `PRAGMA cache_size`（负数=KB）的下限值——容量被调到
/// 上限附近时，避免单连接缓存小到失去意义（1MiB 仍然能让一次典型查询的
/// 热页留在内存里）。当前 clamp 上限 64 配合 256MiB 预算算出的每连接
/// 4096KB 远高于这个下限，这里只是防御性兜底，不影响 `[12, 64]` 区间内的
/// 实际取值。
const HOT_CONN_CACHE_SIZE_KB_FLOOR: i64 = 1_024;

/// FIX ②：给定热连接池容量，按"容量 × 单连接缓存 ≲ 256MiB"的预算换算每条
/// 连接的 `PRAGMA cache_size`（负数=KB，SQLite 语义：负值单位是 KB）。
///
/// 公式：`per_conn_kb = clamp(HOT_CONN_MEMORY_BUDGET_KB / capacity, FLOOR, CEILING)`，
/// 整数除法向下取整。
///
/// 取 `capacity = 12`（[`MAX_HOT_SHARDS`] 原值，FIX ② 前的固定容量）代入：
/// `262144 / 12 ≈ 21845`，被 `CEILING = 16384` 封顶 → 结果仍是 `-16384`
/// （16MiB/连接），与 FIX ② 之前的行为逐字节不变。
///
/// 取 `capacity = 64`（当前 clamp 上限，见 [`hot_pool_capacity_for_shard_count`]）
/// 代入：`262144 / 64 = 4096` → `-4096`（4MiB/连接），总预算恰好打满
/// 256MiB，与任务描述里给出的例子一致。
fn compute_hot_conn_cache_size_kb(capacity: usize) -> i64 {
    let capacity = capacity.max(1) as i64;
    let per_conn = (HOT_CONN_MEMORY_BUDGET_KB / capacity)
        .clamp(HOT_CONN_CACHE_SIZE_KB_FLOOR, HOT_CONN_CACHE_SIZE_KB_CEILING);
    -per_conn
}

/// FIX ②：热连接池容量随消息分片数伸缩的换算规则，供 `mod.rs::async_run`
/// 预热阶段（`msg_db_keys` 确定之后）调用一次。
///
/// 夹到 `[12, 64]`：下限维持 [`MAX_HOT_SHARDS`] 原值（小账号没有调大的
/// 收益，也不产生任何坏处）；上限 64 是"当前实现仍然安全"的上界——见
/// [`MAX_HOT_SHARDS`] 文档，`HotConnPool::slot` 的驱逐是 O(容量) 线性扫描，
/// 64 这个量级仍然可以忽略不计，继续调大需要先换更高效的数据结构。
pub fn hot_pool_capacity_for_shard_count(shard_count: usize) -> usize {
    shard_count.clamp(12, 64)
}

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
    /// FIX ②：容量上限，用 `AtomicUsize` 而不是普通 `usize`——`DbCache`
    /// （及其内部的 `HotConnPool`）经 `Arc` 被 `server.rs` 每连接共享，
    /// `set_capacity` 需要能在只有 `&self`（不是 `&mut self`）的情况下、
    /// daemon 预热阶段一次性调整容量，不引入额外的锁。默认构造为
    /// [`MAX_HOT_SHARDS`]；生产路径由 `mod.rs::async_run` 在
    /// `msg_db_keys` 确定后调用 [`DbCache::set_hot_pool_capacity`] 一次性
    /// 改成按分片数伸缩的值，测试路径可以继续用较小值验证驱逐逻辑，不需要
    /// 真的构造十几个物理分片。
    capacity: AtomicUsize,
}

impl HotConnPool {
    fn new() -> Self {
        Self::with_capacity(MAX_HOT_SHARDS)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            shards: std::sync::Mutex::new(HashMap::new()),
            capacity: AtomicUsize::new(capacity.max(1)),
        }
    }

    /// FIX ②：把池子容量调整为 `new_capacity`（至少为 1）。生产只在 daemon
    /// 预热阶段、真正开始服务查询之前调用一次（此刻池子还是空的，不存在
    /// "缩容时需要批量驱逐已有条目"的问题）；即便调用时机晚于某些查询已经
    /// 建立了热连接，缩容也不会立刻驱逐既有条目——下一次有新分片需要占位
    /// 时，[`Self::slot`] 里既有的单个驱逐逻辑会按 LRU 顺序逐个补齐差额，
    /// 不需要额外的批量驱逐代码路径。纯原子写，微秒级，可以在 async 上下文
    /// 直接同步调用。
    fn set_capacity(&self, new_capacity: usize) {
        self.capacity.store(new_capacity.max(1), Ordering::Relaxed);
    }

    /// FIX ②：当前容量对应的单连接 `PRAGMA cache_size`（负数=KB），供新建
    /// 热连接时设置——见 [`compute_hot_conn_cache_size_kb`]。
    fn cache_size_kb(&self) -> i64 {
        compute_hot_conn_cache_size_kb(self.capacity.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// 拿到（或创建）某个分片专属的槽位（连接互斥锁 + 重建计数器）。持锁
    /// 时间是纯内存操作（无阻塞 I/O），微秒级，可以直接在 async 上下文里
    /// 同步调用（与 `source_freshness_secs` 现有调用惯例一致）。
    fn slot(&self, rel_key: &str) -> (Arc<std::sync::Mutex<Option<HotConn>>>, Arc<AtomicU64>) {
        let capacity = self.capacity.load(Ordering::Relaxed);
        let mut map = self.shards.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(rel_key) && map.len() >= capacity {
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

    /// FIX 1：把某分片逐出热连接池。池子只是放弃自己那份 `Arc`；若此刻有
    /// 并发查询正 move 着自己 clone 的那份在别处用，它手上那份引用计数仍然
    /// 存活，直到它自己用完、`with()` 返回、闭包结束才真正 drop、关闭底层
    /// 文件句柄——不会出现"驱逐时正在用的连接被强制中断"的问题（与
    /// [`Self::slot`] 容量驱逐分支同一套语义）。miss（从未建立过热连接）是
    /// 安全的空操作。
    fn evict(&self, rel_key: &str) {
        self.shards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(rel_key);
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
    /// FIX ②：新建连接时要设置的 `PRAGMA cache_size`（负数=KB）——取自
    /// 《这次拿句柄那一刻》的池子容量（[`HotConnPool::cache_size_kb`]），
    /// 不是写死的常量。同一个分片在池子扩容/缩容前后重建出的连接，缓存
    /// 大小会随之变化；已经建立、还在被复用的连接不受影响（只有真正触发
    /// 重建时才会用新值重设 `cache_size`）。
    cache_size_kb: i64,
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
            conn.pragma_update(None, "cache_size", self.cache_size_kb)?;
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

    /// [`build_encrypted_fixture`] 的通用版本：把"page_size / reserve bytes /
    /// 逐页 `encrypt_page` 往返变换"这套通用装订工序抽出来，`populate` 回调
    /// 拿到明文库的 `&Connection` 自己决定建几张表、每张表什么 schema、写
    /// 什么数据——用于需要在**同一个分片文件**里塞入多张 `Msg_<md5>` 表
    /// （模拟真实微信"一个分片承载多个会话"场景）、或者需要生产查询真正
    /// 用到的完整列（`local_type` / `real_sender_id` / `message_content` /
    /// `WCDB_CT_message_content`，而不只是 [`build_encrypted_fixture`] 那个
    /// 只测 `MAX(create_time)` 用的最小 schema）的测试。
    ///
    /// 不改动、不复用 [`build_encrypted_fixture`] 自身的实现，避免为了这个
    /// 新用途改动一个已经被十几个既有测试依赖的函数、引入无关回归面。
    pub(crate) fn build_encrypted_fixture_with(
        enc_path: &Path,
        key: &[u8; 32],
        populate: impl FnOnce(&Connection),
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
            populate(&conn);
            // 默认 journal_mode=DELETE，连接 drop 时主库文件已是最终提交
            // 状态，不会残留 -wal / -journal（与 build_encrypted_fixture 相同）。
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

/// 路由缓存持久化（[`RouteCacheFile`]）的单元测试：重启存活、身份/版本
/// 校验、损坏容忍、未知 rel_key 丢弃、加载后门控仍然生效。
#[cfg(test)]
mod route_persistence_tests {
    use super::test_support::{backdate_beyond_slack, unique_tmpdir};
    use super::*;

    struct Env {
        db_dir: PathBuf,
        cache_dir: PathBuf,
        rel_key: String,
        all_keys: HashMap<String, String>,
    }

    fn env(tag: &str) -> Env {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        backdate_beyond_slack(&db_path);
        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), "aa".repeat(32));
        Env {
            db_dir,
            cache_dir,
            rel_key,
            all_keys,
        }
    }

    async fn mk_cache(e: &Env) -> DbCache {
        DbCache::with_dirs(
            e.db_dir.clone(),
            e.cache_dir.clone(),
            e.cache_dir.join("_mtimes.json"),
            e.all_keys.clone(),
        )
        .await
        .unwrap()
    }

    fn put_and_flush(cache: &DbCache, rel_key: &str) -> HashSet<String> {
        let snapshot = cache.source_snapshot(rel_key);
        let mut tables = HashSet::new();
        tables.insert("Msg_persisted".to_string());
        cache.put_shard_schema(
            rel_key.to_string(),
            snapshot,
            tables.clone(),
            cache.route_generation(),
        );
        cache.flush_routes_now();
        tables
    }

    /// 核心场景：daemon「重启」（同目录新建 DbCache）后，安静分片的路由
    /// 直接 Fresh 命中，零 IO——这就是冷启动收益的来源。
    #[tokio::test]
    async fn routes_survive_daemon_restart() {
        let e = env("route-persist-roundtrip");
        let cache = mk_cache(&e).await;
        let tables = put_and_flush(&cache, &e.rel_key);

        let restarted = mk_cache(&e).await;
        match restarted.shard_route_lookup(&e.rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables),
            ShardRouteLookup::Stale(_) => {
                panic!("安静分片的持久化路由应在重启后直接 Fresh 命中")
            }
        }
    }

    /// 加载后门控仍然生效：文件在两次启动之间被写过（快照变了）⇒ 必须
    /// Stale，持久化不构成任何新的信任捷径。
    #[tokio::test]
    async fn loaded_entry_still_fails_gating_after_source_change() {
        let e = env("route-persist-gating");
        let cache = mk_cache(&e).await;
        put_and_flush(&cache, &e.rel_key);

        // 模拟重启间隙微信写入：内容与长度都变、mtime 变新。
        std::fs::write(e.db_dir.join(&e.rel_key), b"changed content, longer than before").unwrap();

        let restarted = mk_cache(&e).await;
        assert!(
            matches!(
                restarted.shard_route_lookup(&e.rel_key),
                ShardRouteLookup::Stale(_)
            ),
            "源文件变化后，加载的持久化条目必须被门控拒绝"
        );
    }

    /// db_dir 身份不匹配 ⇒ 整文件丢弃（不同账号绝不混用路由缓存）。
    #[tokio::test]
    async fn mismatched_db_dir_identity_is_rejected() {
        let e = env("route-persist-identity");
        let cache = mk_cache(&e).await;
        put_and_flush(&cache, &e.rel_key);

        // 把持久化文件原样搬到另一个账号（不同 db_dir）的缓存目录下。
        let other = env("route-persist-identity-other");
        std::fs::copy(
            e.cache_dir.join(ROUTE_CACHE_FILE_NAME),
            other.cache_dir.join(ROUTE_CACHE_FILE_NAME),
        )
        .unwrap();

        let victim = mk_cache(&other).await;
        assert!(
            matches!(
                victim.shard_route_lookup(&other.rel_key),
                ShardRouteLookup::Stale(_)
            ),
            "db_dir 不同的账号必须拒绝加载彼此的路由缓存"
        );
    }

    /// 损坏 / 版本不匹配的文件必须被静默忽略，不影响启动。
    #[tokio::test]
    async fn corrupt_or_wrong_version_files_are_ignored() {
        let e = env("route-persist-corrupt");
        std::fs::write(e.cache_dir.join(ROUTE_CACHE_FILE_NAME), b"{not valid json").unwrap();
        let cache = mk_cache(&e).await;
        assert!(matches!(
            cache.shard_route_lookup(&e.rel_key),
            ShardRouteLookup::Stale(_)
        ));

        let wrong_version = format!(
            r#"{{"version":999,"db_dir":"{}","entries":{{}}}}"#,
            e.db_dir.to_string_lossy().replace('\\', "\\\\")
        );
        std::fs::write(e.cache_dir.join(ROUTE_CACHE_FILE_NAME), wrong_version).unwrap();
        let cache2 = mk_cache(&e).await;
        assert!(matches!(
            cache2.shard_route_lookup(&e.rel_key),
            ShardRouteLookup::Stale(_)
        ));
    }

    /// 配置里已不存在的 rel_key（改配置 / 分片消失）在加载时被丢弃。
    #[tokio::test]
    async fn unknown_rel_keys_are_dropped_on_load() {
        let e = env("route-persist-unknown-key");
        let cache = mk_cache(&e).await;
        put_and_flush(&cache, &e.rel_key);

        let mut stripped = Env {
            db_dir: e.db_dir.clone(),
            cache_dir: e.cache_dir.clone(),
            rel_key: e.rel_key.clone(),
            all_keys: HashMap::new(), // rel_key 不再被配置认识
        };
        stripped.all_keys.insert("other.db".into(), "bb".repeat(32));
        let restarted = mk_cache(&stripped).await;
        assert!(
            matches!(
                restarted.shard_route_lookup(&e.rel_key),
                ShardRouteLookup::Stale(_)
            ),
            "配置不再认识的 rel_key 不得从持久化文件复活"
        );
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
        cache.put_shard_schema(rel_key.clone(), snapshot, tables.clone(), cache.route_generation());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables),
            ShardRouteLookup::Stale(_) => panic!("快照未变且已安静满一个 slack 周期，应该命中缓存"),
        }
    }

    #[tokio::test]
    async fn db_change_invalidates_cached_route() {
        let (cache, db_path, rel_key) = setup("db-bump").await;

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());
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
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());
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
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());
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
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());

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
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(_) => {}
            ShardRouteLookup::Fresh(_) => panic!("db_mtime=0 是未知哨兵值，永远不能被判 Fresh"),
        }
    }

    /// FIX 3（加固点 3 语义收紧后的直接验证）：分片没有 WAL 文件（已
    /// checkpoint 的休眠分片）是合法、可信的已知状态，db 早已安静满一个
    /// slack 周期时应该能正常 Fresh 命中——不再被"wal_mtime==0 一律未知"
    /// 误杀。
    #[tokio::test]
    async fn dormant_shard_without_wal_hits_cache() {
        let root = unique_tmpdir("no-wal-route");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        backdate_beyond_slack(&db_path); // 没有创建任何 -wal 文件

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let snapshot = cache.source_snapshot(&rel_key);
        let mut tables = HashSet::new();
        tables.insert("Msg_aaaa".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables.clone(), cache.route_generation());

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables),
            ShardRouteLookup::Stale(_) => {
                panic!("无 WAL 的休眠分片安静满一个 slack 周期后应该 Fresh 命中")
            }
        }
    }

    /// FIX 3（TOCTOU 关键点）的直接验证：分片一开始没有 WAL 文件（已被
    /// 信任、缓存 Fresh 命中），随后微信开始往这个分片写消息、WAL 文件
    /// 首次出现——即便这里只测"判定"这一层，不推进 slack 窗口，快照的
    /// `wal_present` 从 `false` 翻到 `true` 也必须让缓存判定为不同，强制
    /// Stale，不能被"数值部分看起来没变"蒙混过去。
    #[tokio::test]
    async fn wal_appearing_invalidates_cached_route() {
        let root = unique_tmpdir("wal-appears-route");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        backdate_beyond_slack(&db_path); // 没有创建任何 -wal 文件

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let snapshot = cache.source_snapshot(&rel_key);
        cache.put_shard_schema(rel_key.clone(), snapshot, HashSet::new(), cache.route_generation());
        assert!(
            matches!(cache.shard_route_lookup(&rel_key), ShardRouteLookup::Fresh(_)),
            "测试前提：无 WAL 的休眠分片此刻应该已经 Fresh 命中"
        );

        // 微信刚开始往这个分片写消息：WAL 文件首次出现。
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(got) => {
                assert_ne!(
                    got, snapshot,
                    "wal_present 翻转必须让快照判定为不同"
                );
            }
            ShardRouteLookup::Fresh(_) => {
                panic!("WAL 从不存在变为存在必须强制判 Stale，不能继续信任旧路由缓存")
            }
        }
    }

    /// FIX-MEDIUM 基线正向用例：世代号在读取快照之后、回写之前始终未变
    /// （没有任何并发 invalidate 介入），回写必须正常生效——证明生成号
    /// 校验本身不会误伤"没有竞态发生"的正常路径。
    #[tokio::test]
    async fn matching_generation_write_succeeds() {
        let (cache, _db_path, rel_key) = setup("gen-match").await;

        let snapshot = cache.source_snapshot(&rel_key);
        let expected_generation = cache.route_generation();
        let mut tables = HashSet::new();
        tables.insert("Msg_ok".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables.clone(), expected_generation);

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables, "世代号匹配时应该正常写入"),
            ShardRouteLookup::Stale(_) => panic!("世代号未变，回写不应该被丢弃"),
        }
    }

    /// FIX-MEDIUM 核心场景（invalidate 与 put_shard_schema 回写竞态）：
    /// 模拟"扫描 sqlite_master 期间，另一个并发 RPC 抢先 invalidate 了同一
    /// 分片"——回写必须携带《扫描发起前》的旧世代号，此时必须被丢弃，不能
    /// 用可能过期的 schema 把刚被作废的路由悄悄复活。
    #[tokio::test]
    async fn concurrent_invalidate_during_scan_discards_stale_write() {
        let (cache, _db_path, rel_key) = setup("gen-race").await;

        let snapshot = cache.source_snapshot(&rel_key);
        // 模拟 find_msg_shards 在判定 Stale、发起扫描之前读到的世代号。
        let expected_generation = cache.route_generation();

        // 并发场景：扫描仍在进行时，另一个请求先一步作废了这个分片
        // （典型是 q_new_messages 的 FIX-HIGH 全量/精准作废路径）。
        cache.invalidate_shard(&rel_key);

        // 扫描"完成"，尝试用旧世代号回写——必须被拒绝。
        let mut tables = HashSet::new();
        tables.insert("Msg_stale".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables, expected_generation);

        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Stale(_) => {}
            ShardRouteLookup::Fresh(_) => panic!(
                "过期世代号的回写不应该复活刚被 invalidate_shard 作废的路由缓存"
            ),
        }
    }

    /// FIX-MEDIUM 全局粒度的直接验证：即便被 `invalidate_shard` 的是**另一个
    /// 不相关**的 rel_key，全局世代号依然会变化，导致本分片手上那份旧世代
    /// 号的回写同样被丢弃——这是文档里明确接受的权衡（换来实现简单，代价
    /// 只是多余重扫，不产生漏读）。
    #[tokio::test]
    async fn invalidate_of_unrelated_shard_still_discards_stale_write() {
        let root = unique_tmpdir("gen-global");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        for rel in ["message_0.db", "message_1.db"] {
            let db_path = db_dir.join(rel);
            std::fs::write(&db_path, b"fake encrypted db").unwrap();
            backdate_beyond_slack(&db_path);
        }

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let rel_key_a = "message_0.db".to_string();
        let rel_key_b = "message_1.db".to_string();

        let snapshot_a = cache.source_snapshot(&rel_key_a);
        let expected_generation = cache.route_generation();

        // 只作废 B，A 自身的源文件、路由缓存条目全程都没被碰过。
        cache.invalidate_shard(&rel_key_b);

        let mut tables = HashSet::new();
        tables.insert("Msg_a".to_string());
        cache.put_shard_schema(rel_key_a.clone(), snapshot_a, tables, expected_generation);

        match cache.shard_route_lookup(&rel_key_a) {
            ShardRouteLookup::Stale(_) => {}
            ShardRouteLookup::Fresh(_) => panic!(
                "全局世代号语义下，任何一次 invalidate_shard（即便作用于其它 rel_key）\
                 都必须让在飞的旧世代号回写失效"
            ),
        }
    }

    /// FIX-MEDIUM 护栏：没有任何并发 invalidate 时，世代号本身不会漂移，
    /// 连续多次 put_shard_schema（各自读取当时的世代号）都应该正常生效——
    /// 证明世代号校验不会让稳态下的正常回写链路时断时续。
    #[tokio::test]
    async fn generation_stable_across_sequential_writes_without_invalidate() {
        let (cache, _db_path, rel_key) = setup("gen-stable").await;
        let gen0 = cache.route_generation();

        let snapshot = cache.source_snapshot(&rel_key);
        let mut tables1 = HashSet::new();
        tables1.insert("Msg_one".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables1.clone(), gen0);
        assert!(matches!(
            cache.shard_route_lookup(&rel_key),
            ShardRouteLookup::Fresh(_)
        ));

        // 世代号没有任何 invalidate 介入的情况下应该保持不变。
        let gen1 = cache.route_generation();
        assert_eq!(gen0, gen1, "没有 invalidate 发生，世代号不应该漂移");

        let mut tables2 = HashSet::new();
        tables2.insert("Msg_two".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, tables2.clone(), gen1);
        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => assert_eq!(got, tables2, "第二次回写应该正常生效"),
            ShardRouteLookup::Stale(_) => panic!("世代号未变时不应该丢弃回写"),
        }
    }

    /// LOW-1 直接验证："函数内部窗口"修复后，`put_shard_schema` 的世代号
    /// 校验必须与真正的 `insert` 共享同一把 `shard_routes` 锁的临界区。
    /// 单元测试没有办法确定性地构造出具体的线程抢占顺序，这里改为直接
    /// 验证锁内串行化之后应有的可观察结果：携带一个已经落后于当前世代号
    /// 的 `expected_generation`，无论此刻是否真的有 invalidate 正在进行，
    /// 一定不能 insert；随后换上《当前》世代号重试，必须正常写入成功——
    /// 这正是"校验"与"写入"必须在同一次加锁过程中原子完成"才能保证的行为，
    /// 与旧版"先在锁外 load、再单独加锁 insert"两步分离的写法形成对照。
    #[tokio::test]
    async fn put_shard_schema_rejects_stale_generation_and_accepts_current() {
        let (cache, _db_path, rel_key) = setup("gen-lock-scope").await;

        // 记录一个"过期"的旧世代号，再通过 invalidate 一个不相关的
        // rel_key 让全局世代号跳变几次（本分片的源文件、快照全程不动）。
        let stale_generation = cache.route_generation();
        cache.invalidate_shard("message_unrelated.db");
        cache.invalidate_shard("message_unrelated.db");
        let current_generation = cache.route_generation();
        assert!(
            current_generation > stale_generation,
            "测试前提：世代号应该已经跳变"
        );

        let snapshot = cache.source_snapshot(&rel_key);

        // 携带过期世代号回写：必须被拒绝，即便调用时刻并没有并发线程正在
        // 抢占——只要 expected_generation 落后于当前世代号就不能 insert。
        let mut stale_tables = HashSet::new();
        stale_tables.insert("Msg_stale".to_string());
        cache.put_shard_schema(rel_key.clone(), snapshot, stale_tables, stale_generation);
        assert!(
            matches!(cache.shard_route_lookup(&rel_key), ShardRouteLookup::Stale(_)),
            "过期世代号的回写必须被拒绝，不能 insert"
        );

        // 换上《当前》世代号重试，必须正常写入成功。
        let mut fresh_tables = HashSet::new();
        fresh_tables.insert("Msg_fresh".to_string());
        cache.put_shard_schema(
            rel_key.clone(),
            snapshot,
            fresh_tables.clone(),
            current_generation,
        );
        match cache.shard_route_lookup(&rel_key) {
            ShardRouteLookup::Fresh(got) => {
                assert_eq!(got, fresh_tables, "携带当前世代号的回写应该正常生效")
            }
            ShardRouteLookup::Stale(_) => panic!("携带当前世代号的回写不应该被拒绝"),
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

    /// FIX 3（加固点 3 语义收紧后的直接验证）：分片没有 WAL 文件（已
    /// checkpoint 的休眠分片，`wal_present=false`）是合法、可信的已知状态，
    /// db 早已安静很久、两次读到的快照逐字段完全相同时应该允许复用连接——
    /// 这是相对旧版行为唯一的语义变化，旧版把"WAL 缺失"和"WAL 存在但读取
    /// 失败"用同一个哨兵值 0 强行合并成"一律未知"，误杀了这类分片。
    #[tokio::test]
    async fn dormant_shard_without_wal_reuses_connection() {
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
        assert_eq!(rebuild_count(&cache, &rel_key), 1, "首次访问必然重建");

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            1,
            "无 WAL 文件是合法已知状态（已 checkpoint 休眠分片），db 早已安静，\
             应该允许复用连接，不能每轮都被迫重建"
        );
    }

    /// FIX 3（TOCTOU 关键点）的直接验证：分片一开始没有 WAL 文件（已被信任、
    /// 连接被复用），随后微信开始往这个分片写消息、WAL 文件首次出现。即便
    /// 新出现的 WAL 文件恰好落在新鲜度 slack 窗口内会被 `trusted_as_of`
    /// 天然拦下，这里额外验证的是"快照相等比较"这一层——`wal_present` 从
    /// `false` 翻到 `true` 必须让快照判定为不同，强制重建，不能被"数值
    /// 部分看起来没变"蒙混过去。
    #[tokio::test]
    async fn wal_appearing_forces_rebuild_even_though_dormant() {
        let root = unique_tmpdir("wal-appears-hotconn");
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
        assert_eq!(rebuild_count(&cache, &rel_key), 1, "首次访问必然重建");

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            1,
            "测试前提：无 WAL 的休眠分片此刻应该已经在复用连接"
        );

        // 微信刚开始往这个分片写消息：WAL 文件首次出现。
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        probe(&cache, &rel_key).await;
        assert_eq!(
            rebuild_count(&cache, &rel_key),
            2,
            "WAL 从不存在变为存在必须让快照判定为不同，强制重建，不能继续复用旧连接"
        );
    }

    // -------------------------------------------------------------------
    // FIX ②：热连接池容量随分片数伸缩
    // -------------------------------------------------------------------

    #[test]
    fn hot_pool_capacity_for_shard_count_clamps_to_12_64_range() {
        assert_eq!(hot_pool_capacity_for_shard_count(0), 12, "小于下限夹到 12");
        assert_eq!(hot_pool_capacity_for_shard_count(5), 12);
        assert_eq!(hot_pool_capacity_for_shard_count(12), 12, "边界值原样使用");
        assert_eq!(hot_pool_capacity_for_shard_count(37), 37, "区间内原样使用");
        assert_eq!(hot_pool_capacity_for_shard_count(64), 64, "边界值原样使用");
        assert_eq!(
            hot_pool_capacity_for_shard_count(80),
            64,
            "大于上限（120GB+ 账号实测 65~80 个分片）夹到 64"
        );
    }

    #[test]
    fn cache_size_kb_matches_pre_fix2_default_at_capacity_12() {
        // 容量仍是这个常量引入前的固定值时，单连接缓存必须逐字节不变，
        // 保证上面既有的 reuse/rebuild 系列测试（默认走 `DbCache::new()`
        // 的容量 12）不受这次改动影响。
        assert_eq!(
            compute_hot_conn_cache_size_kb(MAX_HOT_SHARDS),
            -16384,
            "容量 12（旧固定值）时单连接缓存必须与 FIX ② 之前逐字节相同"
        );
    }

    #[test]
    fn cache_size_kb_at_capacity_64_matches_task_example() {
        assert_eq!(
            compute_hot_conn_cache_size_kb(64),
            -4096,
            "容量 64（clamp 上限）时单连接缓存应为 4MiB，匹配任务描述给出的例子"
        );
    }

    #[test]
    fn cache_size_kb_budget_never_exceeds_256mib_across_clamp_range() {
        for capacity in 12..=64usize {
            let per_conn_kb = compute_hot_conn_cache_size_kb(capacity).unsigned_abs();
            let total_kb = per_conn_kb * capacity as u64;
            assert!(
                total_kb <= HOT_CONN_MEMORY_BUDGET_KB as u64,
                "capacity={} per_conn_kb={} total_kb={} 超出 256MiB 预算",
                capacity,
                per_conn_kb,
                total_kb
            );
        }
    }

    #[test]
    fn hot_conn_pool_set_capacity_updates_eviction_threshold() {
        let pool = HotConnPool::with_capacity(2);
        assert_eq!(pool.capacity(), 2);

        pool.set_capacity(3);
        assert_eq!(pool.capacity(), 3, "set_capacity 应该立刻反映到 capacity()");

        let _a = pool.slot("a");
        let _b = pool.slot("b");
        let _c = pool.slot("c");
        assert_eq!(pool.len(), 3, "容量已调到 3，插入第 3 个分片不应触发驱逐");
        assert!(pool.contains("a") && pool.contains("b") && pool.contains("c"));

        // 刷新 a 的 last_used，再插入第 4 个应该驱逐最久未用的 b。
        let _ = pool.slot("a");
        let _d = pool.slot("d");
        assert_eq!(pool.len(), 3, "容量仍是 3，插入第 4 个应该触发一次驱逐");
        assert!(pool.contains("a"), "刚访问过的 a 不应被驱逐");
        assert!(pool.contains("d"), "新插入的 d 应该在池中");
        assert!(!pool.contains("b"), "最久未用的 b 应该被驱逐");
        assert!(pool.contains("c"), "c 比 b 新，不应该被驱逐");
    }

    #[tokio::test]
    async fn dbcache_set_hot_pool_capacity_updates_underlying_pool_and_cache_size() {
        let (cache, _rel_key, _db_path) =
            setup_fixture_cache("capacity-set", "Msg_test", &[(1, 1000)]).await;

        assert_eq!(
            cache.hot_conns.capacity(),
            MAX_HOT_SHARDS,
            "DbCache::new()/with_dirs() 默认容量应保持旧固定值"
        );
        assert_eq!(cache.hot_conns.cache_size_kb(), -16384);

        cache.set_hot_pool_capacity(64);
        assert_eq!(cache.hot_conns.capacity(), 64);
        assert_eq!(
            cache.hot_conns.cache_size_kb(),
            -4096,
            "容量调整后,新建连接的 cache_size 应该跟着重新换算"
        );
    }
}

/// FIX 1（核心·焊死"mtime 滞后漏消息"）的单元测试：`route_shard_for_table`
/// 反查 + `invalidate_shard` 强制作废，直接验证 `q_new_messages` 里
/// "changed 会话 → 承载分片 → 强制作废，逼下次现场重开"这条链路的
/// `DbCache` 一侧行为，不依赖 `query.rs` 的 md5 表名推导（那一层是纯函数
/// 拼接，不需要重复用集成测试覆盖）。
#[cfg(test)]
mod invalidate_tests {
    use super::test_support::{
        backdate_beyond_slack, build_encrypted_fixture, key_fixture, key_to_hex, unique_tmpdir,
    };
    use super::*;

    /// 借这次调用顺路执行一次最简单的查询，只关心 rebuild_count 的前后
    /// 差值——与 `hot_conn_tests::probe` 同构。
    async fn probe(cache: &DbCache, rel_key: &str) {
        let hot = cache.hot_conn_handle(rel_key).unwrap();
        tokio::task::spawn_blocking(move || hot.with(|_conn| Ok::<_, anyhow::Error>(())))
            .await
            .unwrap()
            .unwrap();
    }

    fn rebuild_count(cache: &DbCache, rel_key: &str) -> u64 {
        cache
            .hot_conn_handle(rel_key)
            .unwrap()
            .rebuild_count
            .load(Ordering::Relaxed)
    }

    /// 搭一个"已经被 `find_msg_shards` 扫描过、路由缓存 + 热连接都已建立"
    /// 的分片：db + WAL 都回拨到早已安静的过去时刻（对应真实场景里"这个
    /// 分片按 mtime 判断本该继续被信任"的状态），路由缓存记录它携带
    /// `table_name`，并预热一次热连接。
    async fn setup_carrying_shard(
        tag: &str,
        rel_key: &str,
        table_name: &str,
    ) -> (DbCache, std::path::PathBuf) {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let db_path = db_dir.join(rel_key);
        let key = key_fixture();
        build_encrypted_fixture(&db_path, &key, table_name, &[(1, 1000)]);
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();
        backdate_beyond_slack(&db_path);
        backdate_beyond_slack(&wal_path);

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.to_string(), key_to_hex(&key));
        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        // 路由缓存：记录这个分片当时携带 table_name。
        let snapshot = cache.source_snapshot(rel_key);
        let mut tables = HashSet::new();
        tables.insert(table_name.to_string());
        cache.put_shard_schema(rel_key.to_string(), snapshot, tables, cache.route_generation());

        // 热连接：预热一次，rebuild_count 从 1 开始。
        probe(&cache, rel_key).await;
        assert_eq!(rebuild_count(&cache, rel_key), 1, "预热应该只触发一次重建");
        assert!(
            matches!(cache.shard_route_lookup(rel_key), ShardRouteLookup::Fresh(_)),
            "预热后路由缓存应该已经 Fresh 命中"
        );

        (cache, db_path)
    }

    /// FIX 1 核心场景：`route_shard_for_table` 找到承载分片后，
    /// `invalidate_shard` 必须同时作废路由缓存和热连接——即便源文件的
    /// mtime/len 全程没有任何变化（模拟"内容已经落盘、但跨进程 mtime 可见性
    /// 滞后，stat 看起来还是旧值"这个窗口），下一次访问也必须现场重开，
    /// 不能继续信任任何缓存。
    ///
    /// 注意：`invalidate_shard` 是把 `HotShardSlot`（连接槽位 + 它自己的
    /// `rebuild_count` 计数器）整个从池子里 `remove` 掉，不是"标记为
    /// stale"——所以作废后 `rebuild_count` 不会延续旧值继续累加，而是随着
    /// 下一次访问重建出一个全新槽位、全新计数器，从 1 开始。因此这里不能
    /// 断言"数值递增到 2"，而是先用 `HotConnPool::contains`（`#[cfg(test)]`
    /// 内部可见方法）直接证明槽位真的被移除了，再证明重建后的计数器确实是
    /// "从零开始的第一次构建"（值为 1）——两者合起来才完整证明"没有任何
    /// 旧连接被继续复用"。
    #[tokio::test]
    async fn invalidating_carrying_shard_forces_route_and_hotconn_rebuild() {
        let rel_key = "message_0.db";
        let table_name = "Msg_target";
        let (cache, _db_path) = setup_carrying_shard("fix1-core", rel_key, table_name).await;
        assert!(
            cache.hot_conns.contains(rel_key),
            "预热后热连接槽位应该已经建立"
        );

        let carrying = cache.route_shard_for_table(table_name);
        assert_eq!(
            carrying,
            vec![rel_key.to_string()],
            "route_shard_for_table 应该准确反查到承载该表名的分片"
        );

        cache.invalidate_shard(rel_key);

        // 路由缓存：作废后必须 Stale，即便源文件字节上什么都没变。
        assert!(
            matches!(cache.shard_route_lookup(rel_key), ShardRouteLookup::Stale(_)),
            "invalidate_shard 后路由缓存必须强制 Stale，不能继续信任"
        );

        // 热连接：槽位必须被真正移除，不是"标记为 stale"。
        assert!(
            !cache.hot_conns.contains(rel_key),
            "invalidate_shard 后热连接槽位必须被彻底移除"
        );

        // 下一次访问必须现场重开，重建出的是一个全新计数器（从 0 累加到 1），
        // 不可能是"复用作废前的旧连接"（那个槽位已经不存在了）。
        probe(&cache, rel_key).await;
        assert_eq!(
            rebuild_count(&cache, rel_key),
            1,
            "invalidate_shard 后重建出的是全新槽位 + 全新计数器"
        );
    }

    /// 无关休眠分片保持缓存：作废分片 A 不应该影响分片 B 的路由缓存 /
    /// 热连接，即便两者都早已安静、都被信任。
    #[tokio::test]
    async fn invalidating_one_shard_does_not_touch_unrelated_dormant_shard() {
        let rel_key_a = "message_0.db";
        let rel_key_b = "message_1.db";

        // 两个分片必须共享同一个 db_dir / cache_dir 才能被同一个 DbCache
        // 管理，所以不能直接复用 setup_carrying_shard（它各自建一套目录）；
        // 这里手动搭两个分片，逻辑与 setup_carrying_shard 一致。
        let root = unique_tmpdir("fix1-unrelated");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let key = key_fixture();
        let mut all_keys = HashMap::new();
        for (rel_key, table_name) in [(rel_key_a, "Msg_a"), (rel_key_b, "Msg_b")] {
            let db_path = db_dir.join(rel_key);
            build_encrypted_fixture(&db_path, &key, table_name, &[(1, 1000)]);
            let wal_path = wal_path_for(&db_path);
            std::fs::write(&wal_path, [0u8; 31]).unwrap();
            backdate_beyond_slack(&db_path);
            backdate_beyond_slack(&wal_path);
            all_keys.insert(rel_key.to_string(), key_to_hex(&key));
        }

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        for (rel_key, table_name) in [(rel_key_a, "Msg_a"), (rel_key_b, "Msg_b")] {
            let snapshot = cache.source_snapshot(rel_key);
            let mut tables = HashSet::new();
            tables.insert(table_name.to_string());
            cache.put_shard_schema(rel_key.to_string(), snapshot, tables, cache.route_generation());
            probe(&cache, rel_key).await;
            assert_eq!(rebuild_count(&cache, rel_key), 1);
        }

        assert!(cache.hot_conns.contains(rel_key_a));
        assert!(cache.hot_conns.contains(rel_key_b));

        // 只作废分片 A（承载 Msg_a）。
        for r in cache.route_shard_for_table("Msg_a") {
            cache.invalidate_shard(&r);
        }

        // 分片 A：路由缓存必须强制 Stale，热连接槽位必须被真正移除
        // （见 `invalidating_carrying_shard_forces_route_and_hotconn_rebuild`
        // 的说明：移除后 `rebuild_count` 从全新槽位的 0 重新累加，不是延续
        // 旧值递增到 2）。
        assert!(matches!(
            cache.shard_route_lookup(rel_key_a),
            ShardRouteLookup::Stale(_)
        ));
        assert!(
            !cache.hot_conns.contains(rel_key_a),
            "分片 A 的热连接槽位必须被彻底移除"
        );
        probe(&cache, rel_key_a).await;
        assert_eq!(
            rebuild_count(&cache, rel_key_a),
            1,
            "分片 A 重建出的是全新槽位 + 全新计数器"
        );

        // 分片 B：完全不受影响，路由缓存仍 Fresh，热连接仍复用（rebuild_count
        // 保持 1）。
        assert!(
            matches!(cache.shard_route_lookup(rel_key_b), ShardRouteLookup::Fresh(_)),
            "无关分片的路由缓存不应该被误作废"
        );
        probe(&cache, rel_key_b).await;
        assert_eq!(
            rebuild_count(&cache, rel_key_b),
            1,
            "无关分片的热连接不应该被误驱逐，应该继续复用"
        );
    }

    /// 全新会话路径不 panic：`route_shard_for_table` 对从未被路由缓存记录过
    /// 的表名（典型是全新会话——它对应的分片还从未被 `find_msg_shards`
    /// 真正扫描过）必须返回空集合，而不是 panic 或误报；对空集合调用
    /// `invalidate_shard` 自然是空操作，同样不能 panic。
    #[tokio::test]
    async fn route_shard_for_table_empty_for_never_scanned_table_and_invalidate_is_noop() {
        let root = unique_tmpdir("fix1-new-session");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mtime_file = cache_dir.join("_mtimes.json");
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();

        let carrying = cache.route_shard_for_table("Msg_never_seen_before");
        assert!(
            carrying.is_empty(),
            "从未被路由缓存记录过的表名必须返回空集合"
        );

        // 对一个从未出现过的 rel_key 调用 invalidate_shard：两个子缓存都
        // miss，必须是安全的空操作，不能 panic。
        cache.invalidate_shard("message_never_opened.db");
    }
}

/// FIX ③ 并发场景专项测试：`find_msg_shards` 把分片循环从串行 await 改成
/// `JoinSet` 并发扫描之后，多个分片任务可能真正同时（而不是像旧实现那样
/// 严格逐个）读 [`DbCache::route_generation`]、真正 I/O、再回写
/// [`DbCache::put_shard_schema`]。这里用真实的 `tokio::spawn` 并发（不是
/// 手工摆顺序模拟）直接对 `shard_routes` 这把锁施压，验证
/// FIX-MEDIUM/LOW-1 那套"世代号校验必须在 `shard_routes` 锁的临界区内部
/// 完成"的保护，在真正并发、而不只是"手工排列调用顺序"的场景下依然成立：
/// - 过期的 `expected_generation` 无论被多少个并发任务同时携带，一次都不
///   允许写入成功（不能被并发放大成"总有一个漏网之鱼"）；
/// - 互不相关的 rel_key 并发写入必须互不覆盖、无丢失更新。
///
/// 直接读取 `cache.shard_routes.lock()` 内部 map（而不是经
/// `shard_route_lookup` 判断 Fresh/Stale）：后者还叠加了
/// [`SourceSnapshot::trusted_as_of`] 的新鲜度 slack 判断，对不存在的测试
/// 夹具文件永远是 `Stale`，无法单独证明"世代号校验本身"是否正确——直接查
/// 内部 map 才能精确断言"到底有没有写入过"。
#[cfg(test)]
mod concurrency_tests {
    use super::test_support::unique_tmpdir;
    use super::*;

    async fn empty_cache(tag: &str) -> DbCache {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();
        let mtime_file = cache_dir.join("_mtimes.json");
        DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap()
    }

    /// 核心场景：`find_msg_shards` 并发化后，多个分片扫描任务可能在
    /// "决定重建"那一刻读到同一个（此刻仍然当前、但很快就会过期的）世代
    /// 号——模拟"扫描进行期间，另一个并发请求（例如 `q_new_messages` 的
    /// FIX 1 强制作废）推进了世代号"，随后 16 个并发任务全部携带这个已经
    /// 过期的 `expected_generation` 试图回写。无论 Mutex 内部调度顺序如何
    /// 交错，全部 16 次写入都必须被拒绝——一次都不能让过期数据溜进缓存。
    #[tokio::test]
    async fn stale_generation_write_is_rejected_even_under_real_concurrent_dispatch() {
        let cache = Arc::new(empty_cache("concurrent-stale-gen").await);
        let rel_key = "message_0.db";

        let stale_generation = cache.route_generation();
        let snapshot = cache.source_snapshot(rel_key);

        // 世代号真正推进一次，让下面全部并发写入天然都是"过期"的。
        cache.invalidate_shard(rel_key);
        assert_ne!(
            cache.route_generation(),
            stale_generation,
            "invalidate_shard 后世代号必须前进"
        );

        let mut handles = Vec::new();
        for i in 0..16u32 {
            let cache2 = Arc::clone(&cache);
            let rel_key2 = rel_key.to_string();
            handles.push(tokio::spawn(async move {
                let mut tables = HashSet::new();
                tables.insert(format!("Msg_stale_{}", i));
                cache2.put_shard_schema(rel_key2, snapshot, tables, stale_generation);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert!(
            !cache.shard_routes.lock().contains_key(rel_key),
            "全部 16 次并发写入携带的 expected_generation 都已过期，\
             不允许任何一次写入成功——哪怕是真实并发调度下的任意交错顺序"
        );
    }

    /// 反向对照：互不相关的 rel_key 并发写入（各自读到的 `expected_generation`
    /// 全程未被任何 invalidate 打断）必须全部成功、互不覆盖——证明
    /// `shard_routes` 这把锁在真实多线程压力下不会丢更新，也不会把不同
    /// rel_key 的条目相互污染。
    #[tokio::test]
    async fn concurrent_put_shard_schema_across_distinct_shards_all_persist_independently() {
        let cache = Arc::new(empty_cache("concurrent-distinct").await);
        let rel_keys: Vec<String> = (0..8).map(|i| format!("message_{}.db", i)).collect();

        let mut handles = Vec::new();
        for rel_key in rel_keys.clone() {
            let cache2 = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                let snapshot = cache2.source_snapshot(&rel_key);
                let generation = cache2.route_generation();
                let mut tables = HashSet::new();
                tables.insert(format!("Msg_{}", rel_key));
                // 主动让出一次，放大真实交错窗口（不这样做的话，8 个任务
                // 在单线程 runtime 上也可能凑巧串行跑完，测不出真正的竞争）。
                tokio::task::yield_now().await;
                cache2.put_shard_schema(rel_key, snapshot, tables, generation);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let map = cache.shard_routes.lock();
        assert_eq!(
            map.len(),
            rel_keys.len(),
            "8 个互不相关的并发写入应该全部持久化，互不覆盖、互不丢失"
        );
        for rel_key in &rel_keys {
            assert!(
                map.contains_key(rel_key),
                "分片 {} 的并发写入应该成功持久化",
                rel_key
            );
        }
    }

    /// 混合场景：一批 rel_key 正常并发写入的同时，另一个任务并发对其中
    /// 一部分 rel_key 发起 `invalidate_shard`——验证两类操作真正并发交错时
    /// 不 panic、不死锁，且"最终每个 rel_key 要么完全体现写入、要么完全
    /// 体现作废"（不会出现半写入的中间态,例如 map 里存在一条
    /// `ShardSchemaEntry` 但世代号已经不匹配这种不可能通过 `put_shard_schema`
    /// 正常路径产生的状态）。这里不断言具体哪个 rel_key 最终是哪种状态
    /// （真实调度顺序不确定），只断言"不 panic + 只可能是两种自洽结果之一"。
    #[tokio::test]
    async fn concurrent_writes_and_invalidates_interleave_without_panic_or_torn_state() {
        let cache = Arc::new(empty_cache("concurrent-mixed").await);
        let rel_keys: Vec<String> = (0..6).map(|i| format!("message_{}.db", i)).collect();

        let mut handles = Vec::new();
        for rel_key in rel_keys.clone() {
            let cache2 = Arc::clone(&cache);
            let rel_key_w = rel_key.clone();
            handles.push(tokio::spawn(async move {
                let snapshot = cache2.source_snapshot(&rel_key_w);
                let generation = cache2.route_generation();
                tokio::task::yield_now().await;
                let mut tables = HashSet::new();
                tables.insert(format!("Msg_{}", rel_key_w));
                cache2.put_shard_schema(rel_key_w, snapshot, tables, generation);
            }));

            let cache3 = Arc::clone(&cache);
            let rel_key_i = rel_key.clone();
            handles.push(tokio::spawn(async move {
                tokio::task::yield_now().await;
                cache3.invalidate_shard(&rel_key_i);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // 只要求"不 panic 就能跑到这里"本身已经是主要断言；额外确认 map
        // 内部状态自洽：每一条留存下来的 ShardSchemaEntry，其 rel_key 都在
        // 我们预期的集合内（没有产生任何越界/幽灵条目）。
        let map = cache.shard_routes.lock();
        for rel_key in map.keys() {
            assert!(
                rel_keys.contains(rel_key),
                "不应该出现预期之外的 rel_key 条目: {}",
                rel_key
            );
        }
    }
}
