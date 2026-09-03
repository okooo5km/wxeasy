//! 只读、按页解密、主库+WAL 页级合并的自定义 SQLite VFS。
//!
//! 从 `tools/wx-verify/wxvfs-core/src/vfs.rs` 移植（已在独立原型里通过真实
//! SQLCipher 活体验证，含 WAL 帧 pgno==1 路由 bug 的修复），**复用 wxeasy 自身
//! `crate::crypto::decrypt_page`**（该函数已在上一步修好 pgno==1 误路由的
//! 致命 bug），不重新实现一份解密原语。
//!
//! # 整体思路（"思路 C"）
//! 我们**不**实现 SQLite 的共享内存 / wal-index（`xShmMap` 等）接口，而是让
//! SQLite 核心以为自己打开的是一个"不会变化的单文件数据库"（`immutable=1`），
//! 于是它完全不会去探测、打开或读取 `-wal` 文件——所有关于 WAL 的知识都只存在于
//! [`super::wal_index`] 模块里。
//!
//! 真正的"合并"发生在 [`DatabaseHandle::read_exact_at`] 这一层：SQLite 请求读某个
//! 字节区间时，我们按 4096 字节页对齐拆分该区间，对每一页单独判断——
//! 如果这一页在 WAL 索引里有更新的版本，就从 `-wal` 文件读那份密文解密返回；
//! 否则老老实实从主库文件读该页密文解密返回。SQLite 核心全程不知道自己看到的
//! 某些页其实来自另一个文件，只会观察到"这个不可变快照包含了最新的提交"。
//!
//! # VFS 注册设计（多分片 / 多 key，daemon 长期运行的幂等性）
//! `sqlite_vfs::register` 是**进程级全局副作用**：同名重复注册会失败。daemon
//! 会同时/先后为 `message_0..N`、`session`、`contact` 等多个不同加密库、
//! 不同密钥的 rel_key 调用 `open_conn`，且同一个 rel_key 在 daemon 生命周期内
//! 会被反复调用（每次查询一次）。因此：
//! - 用一个进程级 `OnceLock<Mutex<HashMap<PathBuf, String>>>` 作为注册表，
//!   key 是加密库物理路径的 canonical 形式（不是 rel_key 字符串——canonical
//!   路径能天然处理"同一物理文件从不同 db_dir 拼接出的 rel_key"这种边界，
//!   在测试/oracle 场景下也更稳）。
//! - 每个物理库路径只在首次被请求时注册一个 `WxVfs` 实例（固定了这一个库的
//!   加密路径 + 密钥 + 临时目录），此后所有 `open_conn` 调用复用同一个已注册
//!   的 VFS 名字，只是各自开一条新的 [`rusqlite::Connection`]——`WxVfs::open`
//!   在每次连接打开时都会重新扫描 `-wal` 帧头建索引，所以"复用同一个 VFS
//!   注册"不会让不同时间点的查询看到陈旧的 WAL 视图。
//! - 因为注册只增不减、且以物理路径去重，daemon 长期运行下重复调用
//!   `open_conn`（无论是同一个 rel_key 还是不同 rel_key 指向同一个库的极端
//!   情况）既不会重复注册（避免 `sqlite_vfs::register` 报错），也不会无限
//!   增长（同一物理路径只占一个 entry）。
//!
//! 作者: okooo5km(十里)

use crate::crypto::{decrypt_page, PAGE_SZ};
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use sqlite_vfs::{DatabaseHandle, LockKind, OpenAccess, OpenKind, OpenOptions, Vfs, WalDisabled};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

#[cfg(test)]
use super::wal_index::build_wal_index;
use super::wal_index::{build_wal_index_cached, wal_path_for, WalIndexCache, WalSource};

/// 主库在 `sqlite3_open` 时使用的固定 "路径" 标签。我们的 VFS 完全不理会这个
/// 字符串对应的真实文件系统路径——加密文件路径、密钥、WAL 索引都直接烘焙进
/// [`WxVfs`] 实例，`open()` 命中这个标签时直接用它们，不做真实文件系统查找。
/// 不同 rel_key 各自注册独立命名的 VFS，因此所有注册共用同一个 `MAIN_LABEL`
/// 常量是安全的——SQLite 用 `(vfs_name, db_label)` 二元组定位文件，不会串号。
pub const MAIN_LABEL: &str = "wxeasy-vfs-main";

/// 单次连接的读取统计，用于证明"按需解页"以及区分页面来自主库还是 WAL。
#[derive(Debug, Default, Clone)]
pub struct ReadStats {
    /// 实际被解密过的物理页号集合（1-based pgno），无论来自主库还是 WAL。
    pub pages_decrypted: HashSet<u32>,
    /// 其中来自 WAL 帧覆盖版本的页号集合（是 `pages_decrypted` 的子集）。
    pub pages_from_wal: HashSet<u32>,
    /// 其中来自主库文件本体的页号集合（是 `pages_decrypted` 的子集）。
    pub pages_from_main: HashSet<u32>,
    /// `decrypt_page` 被调用的总次数（同一页可能因为跨越多次 `read_exact_at` 而被重复解密）。
    pub decrypt_calls: u64,
    /// `decrypt_calls * PAGE_SZ`，即"总共对多少字节密文做了 AES 解密"（含重复解密同一页的开销）。
    pub bytes_decrypted_total: u64,
}

impl ReadStats {
    /// 目前只被 `#[cfg(test)]` 的 `vfs_oracle.rs` 对拍用来算"按需解密比例"，
    /// 非 test 构建下报 dead_code 属预期。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn distinct_pages(&self) -> usize {
        self.pages_decrypted.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn distinct_bytes(&self) -> u64 {
        self.pages_decrypted.len() as u64 * PAGE_SZ as u64
    }
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn readonly_err() -> std::io::Error {
    std::io::Error::new(ErrorKind::PermissionDenied, "wxeasy VFS 只读：不支持写操作")
}

/// 只读、逐页解密、主库+WAL 合并的 SQLite VFS。一个实例只服务一个固定的加密库文件
/// （及其可能存在的 `-wal` 伴生文件）。
pub struct WxVfs {
    enc_path: PathBuf,
    key: [u8; 32],
    tmp_dir: PathBuf,
    stats: Arc<Mutex<ReadStats>>,
    /// WAL 帧索引的增量缓存（与 stats 同构：VFS 按物理路径单例注册，缓存
    /// 因此天然按物理路径分域、与 daemon 同寿命）。见 [`WalIndexCache`] 的
    /// 正确性论证。
    wal_cache: Arc<Mutex<WalIndexCache>>,
    /// WAL 帧索引跨 daemon-重启持久化的落盘目录（`{cache_dir}/wal-index`）。
    /// 由 `tmp_dir`（`{cache_dir}/vfs-tmp`）的父目录推导；父目录取不到时为
    /// `None`，退化为纯内存增量缓存。
    wal_persist_dir: Option<PathBuf>,
    tmp_counter: AtomicU64,
}

impl WxVfs {
    pub fn new(
        enc_path: PathBuf,
        key: [u8; 32],
        tmp_dir: PathBuf,
    ) -> (Self, Arc<Mutex<ReadStats>>) {
        let stats = Arc::new(Mutex::new(ReadStats::default()));
        let wal_persist_dir = tmp_dir.parent().map(|c| c.join("wal-index"));
        let vfs = WxVfs {
            enc_path,
            key,
            tmp_dir,
            stats: stats.clone(),
            wal_cache: Arc::new(Mutex::new(WalIndexCache::default())),
            wal_persist_dir,
            tmp_counter: AtomicU64::new(0),
        };
        (vfs, stats)
    }

    fn is_tmp_path(&self, db: &str) -> bool {
        Path::new(db).starts_with(&self.tmp_dir)
    }
}

impl Vfs for WxVfs {
    type Handle = WxFile;

    fn open(&self, db: &str, opts: OpenOptions) -> Result<Self::Handle, std::io::Error> {
        if opts.kind == OpenKind::MainDb && db == MAIN_LABEL {
            if opts.access != OpenAccess::Read {
                // 只允许只读打开主库；防止不小心以读写方式打开加密库。
                return Err(readonly_err());
            }
            let mut file = File::open(&self.enc_path)?;
            let file_len = file.seek(SeekFrom::End(0))?;

            // 扫 -wal 帧头建索引（若 -wal 不存在或没有有效帧，wal 为 None，
            // 行为完全退化为"只读主库"）。每次 open() 都重新读 header 真
            // 字节做判定，保证复用同一个已注册 VFS 时，不同时间点打开的
            // 连接看到的是各自那一刻最新的 WAL 视图；增量缓存只在「salt
            // 未变 + 文件未缩」时把已扫过的同世代帧免于重扫（append-only
            // 协议保证等价，见 WalIndexCache 文档），新帧照常现场解析。
            let wal_path = wal_path_for(&self.enc_path);
            let wal = build_wal_index_cached(
                &wal_path,
                &self.wal_cache,
                self.wal_persist_dir.as_deref(),
            )?;

            return Ok(WxFile::Merged(MergedFile {
                main: file,
                main_len: file_len,
                key: self.key,
                wal,
                stats: self.stats.clone(),
                lock: LockKind::None,
            }));
        }

        // 非主库（journal / temp db 等）：真实落盘的透传文件，仅用于让
        // SQLite 内部的临时排序等机制有地方可写，不涉及加密内容。
        // 注意：因为我们始终以 `immutable=1` URI 打开主库，SQLite 核心不会
        // 主动尝试打开 `<label>-wal` / `<label>-journal`，这个分支实际只会
        // 服务临时文件（TEMP_DB / TEMP_JOURNAL 等 OpenKind）。
        let path = if Path::new(db).is_absolute() {
            PathBuf::from(db)
        } else {
            self.tmp_dir.join(db)
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // 临时/日志类文件在语义上总是"全新的一份"（`temporary_name()` 每次都生成
        // 带纳秒+计数器的唯一文件名），加 `truncate(true)` 确保万一路径巧合复用
        // 到一个残留的旧文件时，也是从空文件开始写，不会把陈旧字节残留进新内容。
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(WxFile::Plain(PlainFile {
            file,
            lock: LockKind::None,
        }))
    }

    fn delete(&self, db: &str) -> Result<(), std::io::Error> {
        if self.is_tmp_path(db) {
            let _ = std::fs::remove_file(db);
        }
        Ok(())
    }

    fn exists(&self, db: &str) -> Result<bool, std::io::Error> {
        if db == MAIN_LABEL {
            return Ok(true);
        }
        if self.is_tmp_path(db) {
            return Ok(Path::new(db).exists());
        }
        // 伪装成"没有" -wal / -journal / -shm 等伴生文件——即便 immutable=1
        // 通常已经让 SQLite 不会问这个问题，这里仍保留防御性行为：绝不能让
        // SQLite 自己发现并直接打开真实的 -wal 文件，WAL 合并必须完全由我们
        // 在页级别接管，否则会和我们的合并逻辑产生冲突的两份视图。
        Ok(false)
    }

    fn temporary_name(&self) -> String {
        let n = self.tmp_counter.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.tmp_dir
            .join(format!("wxcli-vfs-tmp-{}-{}.db", nanos, n))
            .to_string_lossy()
            .into_owned()
    }

    fn random(&self, buffer: &mut [i8]) {
        // 只用于临时文件名等非安全场景，弱随机即可。
        let mut seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        for b in buffer.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = (seed & 0xFF) as i8;
        }
    }

    fn sleep(&self, duration: Duration) -> Duration {
        std::thread::sleep(duration);
        duration
    }

    fn access(&self, db: &str, write: bool) -> Result<bool, std::io::Error> {
        if db == MAIN_LABEL {
            return Ok(!write);
        }
        if self.is_tmp_path(db) {
            return Ok(true);
        }
        Ok(false)
    }
}

pub enum WxFile {
    Merged(MergedFile),
    Plain(PlainFile),
}

/// 主库 + WAL 合并后的只读文件视图。SQLite 核心眼中这就是"一个文件"，
/// 但读取时按页从两个不同的物理文件中挑选数据源。
pub struct MergedFile {
    main: File,
    main_len: u64,
    key: [u8; 32],
    /// `None` 表示没有 -wal，或 -wal 存在但没有一帧 salt 匹配（例如已经
    /// checkpoint 干净）——这两种情况下合并视图退化为纯主库视图。
    wal: Option<WalSource>,
    stats: Arc<Mutex<ReadStats>>,
    lock: LockKind,
}

impl MergedFile {
    /// 数据库总页数：WAL 侧有有效提交时以其 `commit_pgcnt` 为准（WAL 可能把库
    /// 扩大，例如新增消息触发了分裂/新建索引页），否则回退主库物理页数。
    fn total_pages(&self) -> u64 {
        let main_pages = self.main_len.div_ceil(PAGE_SZ as u64);
        match &self.wal {
            Some(w) => match w.index.last_commit_pgcnt() {
                Some(pgcnt) => pgcnt as u64,
                None => main_pages,
            },
            None => main_pages,
        }
    }

    fn read_page_decrypted(&mut self, page_idx: u64) -> Result<Vec<u8>, std::io::Error> {
        let pgno = (page_idx + 1) as u32; // 1-based

        // 优先查 WAL 索引：如果这一页在未 checkpoint 的 WAL 里有更新版本，
        // 必须优先采用它——这正是本模块存在的意义（让 VFS 看到最新报价）。
        if let Some(wal) = self.wal.as_mut() {
            if let Some(offset) = wal.index.offset_for(pgno) {
                let raw = wal.read_raw_page(offset)?;
                // WAL 帧 targeting pgno==1 时，其 page_data 与主库物理首页布局
                // 完全一致——同样带 16 字节 SALT 前缀。直接把真实 pgno 传给
                // `crate::crypto::decrypt_page`，由它自身的 pgno==1 分支统一
                // 处理"主库首页"和"WAL 首页帧"两种来源，不做任何转换。
                let decrypted = decrypt_page(&self.key, &raw, pgno).map_err(io_other)?;

                let mut st = self.stats.lock().unwrap();
                st.pages_decrypted.insert(pgno);
                st.pages_from_wal.insert(pgno);
                st.decrypt_calls += 1;
                st.bytes_decrypted_total += PAGE_SZ as u64;
                drop(st);

                return Ok(decrypted);
            }
        }

        // 否则从主库文件本体读取。
        let page_start = page_idx * PAGE_SZ as u64;
        if page_start >= self.main_len {
            // 这一页既不在 WAL 索引里（上面已经查过），又超出主库物理文件范围——
            // 说明 SQLite 请求了一个我们既没有主库数据也没有 WAL 覆盖的"洞"。
            // 正常情况下不应该发生（total_pages() 已经如实上报了正确的库大小），
            // 出现即说明 total_pages() 计算或 WAL 索引构建有 bug。
            //
            // 关键：这里必须直接返回全零**明文**页，绝不能把这一页当成"主库
            // 密文"喂给 `decrypt_page`——对全零密文做 AES 解密不会解出零，只会
            // 解出看起来正常、实则是垃圾的"随机"明文，而且不会报错，是最危险
            // 的一类"悄悄查错数据"。这里要对齐 `full_decrypt` + `apply_wal`
            // 落盘产物的稀疏零语义：那条路径下，`apply_wal` 用 `Seek` +
            // `write_all` 在明文文件里打洞，从未被任何页写过的字节，操作系统
            // 层面读出来天然就是全零，而不是对全零密文解密的结果。
            //
            // 不更新 `stats`：这一页没有发生任何真实的 AES 解密，计入
            // `pages_decrypted` / `bytes_decrypted_total` 会让诊断队列页的
            // "按需解密比例"失真。
            return Ok(vec![0u8; PAGE_SZ]);
        }
        let mut raw = vec![0u8; PAGE_SZ];
        self.main.seek(SeekFrom::Start(page_start))?;
        let avail = (self.main_len - page_start).min(PAGE_SZ as u64) as usize;
        self.main.read_exact(&mut raw[..avail])?;
        // 若最后一页不足 PAGE_SZ（正常 SQLCipher 库不会出现，防御性处理），
        // 剩余部分保持 0 填充。
        let decrypted = decrypt_page(&self.key, &raw, pgno).map_err(io_other)?;

        let mut st = self.stats.lock().unwrap();
        st.pages_decrypted.insert(pgno);
        st.pages_from_main.insert(pgno);
        st.decrypt_calls += 1;
        st.bytes_decrypted_total += PAGE_SZ as u64;
        drop(st);

        Ok(decrypted)
    }
}

pub struct PlainFile {
    file: File,
    lock: LockKind,
}

impl DatabaseHandle for WxFile {
    type WalIndex = WalDisabled;

    fn size(&self) -> Result<u64, std::io::Error> {
        match self {
            WxFile::Merged(f) => Ok(f.total_pages() * PAGE_SZ as u64),
            WxFile::Plain(f) => Ok(f.file.metadata()?.len()),
        }
    }

    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> Result<(), std::io::Error> {
        match self {
            WxFile::Merged(f) => {
                if buf.is_empty() {
                    return Ok(());
                }
                let page_sz = PAGE_SZ as u64;
                let end = offset + buf.len() as u64; // exclusive
                let first_page = offset / page_sz;
                let last_page = (end - 1) / page_sz;

                for page_idx in first_page..=last_page {
                    let page_start = page_idx * page_sz;
                    let page_end = page_start + page_sz;
                    let decrypted = f.read_page_decrypted(page_idx)?;

                    let copy_start = offset.max(page_start);
                    let copy_end = end.min(page_end);
                    if copy_end > copy_start {
                        let src_off = (copy_start - page_start) as usize;
                        let dst_off = (copy_start - offset) as usize;
                        let len = (copy_end - copy_start) as usize;
                        buf[dst_off..dst_off + len]
                            .copy_from_slice(&decrypted[src_off..src_off + len]);
                    }
                }
                Ok(())
            }
            WxFile::Plain(f) => {
                f.file.seek(SeekFrom::Start(offset))?;
                f.file.read_exact(buf)
            }
        }
    }

    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> Result<(), std::io::Error> {
        match self {
            WxFile::Merged(_) => Err(readonly_err()),
            WxFile::Plain(f) => {
                f.file.seek(SeekFrom::Start(offset))?;
                f.file.write_all(buf)
            }
        }
    }

    fn sync(&mut self, data_only: bool) -> Result<(), std::io::Error> {
        match self {
            WxFile::Merged(_) => Ok(()),
            WxFile::Plain(f) => {
                if data_only {
                    f.file.sync_data()
                } else {
                    f.file.sync_all()
                }
            }
        }
    }

    fn set_len(&mut self, size: u64) -> Result<(), std::io::Error> {
        match self {
            WxFile::Merged(_) => Err(readonly_err()),
            WxFile::Plain(f) => f.file.set_len(size),
        }
    }

    fn lock(&mut self, lock: LockKind) -> Result<bool, std::io::Error> {
        match self {
            WxFile::Merged(f) => {
                f.lock = lock;
                Ok(true)
            }
            WxFile::Plain(f) => {
                f.lock = lock;
                Ok(true)
            }
        }
    }

    fn reserved(&mut self) -> Result<bool, std::io::Error> {
        Ok(false)
    }

    fn current_lock(&self) -> Result<LockKind, std::io::Error> {
        match self {
            WxFile::Merged(f) => Ok(f.lock),
            WxFile::Plain(f) => Ok(f.lock),
        }
    }

    fn wal_index(&self, _readonly: bool) -> Result<Self::WalIndex, std::io::Error> {
        // 与 `immutable=1` 配合：SQLite 核心永远不会真的调用到这里（它认为
        // 库不可变、无需 WAL 机制）。返回 `WalDisabled` 只是满足 trait 要求。
        Ok(WalDisabled)
    }
}

// ---------------------------------------------------------------------------
// VFS 注册表 + 对外 open_conn API
// ---------------------------------------------------------------------------

struct VfsRegistration {
    vfs_name: String,
    /// 首次注册这个物理路径时使用的密钥。同一物理路径此后每次 `ensure_vfs_registered`
    /// 都必须带同一把密钥来——见 [`ensure_vfs_registered`] 里的一致性检查。
    key: [u8; 32],
    /// 该 VFS 自注册以来所有连接共享的累计读取统计（不是"单次查询"的隔离
    /// 统计——多个连接、多次查询会往同一个计数器里累加）。用于给诊断 /
    /// 监控队列页展示"这个分片总共按需解密了多少页"，不追求单次查询隔离。
    /// oracle 对拍需要的"这一次查询精确解了多少页"请用 [`open_fresh_with_stats`]。
    stats: Arc<Mutex<ReadStats>>,
}

static VFS_REGISTRY: OnceLock<Mutex<HashMap<PathBuf, VfsRegistration>>> = OnceLock::new();
static VFS_NAME_SEQ: AtomicU64 = AtomicU64::new(0);

fn registry() -> &'static Mutex<HashMap<PathBuf, VfsRegistration>> {
    VFS_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sanitize_tag(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// 幂等地为 `enc_db_path` 拿到一个已注册的 VFS 名字 + 其累计统计句柄。同一
/// 物理路径（按 canonical 形式去重）在进程生命周期内只注册一次，后续调用
/// 直接复用——这是本模块"多分片 / 多 key、daemon 长期运行不重复注册、不
/// 泄漏"设计的核心：注册表只增不减，且以物理路径而非 rel_key 字符串去重。
///
/// # key 一致性
/// 复用已注册路径时，如果本次传入的 `key` 和首次注册时的 `key` 不一致，
/// 直接返回 `Err`（fail loud），绝不静默复用旧 key 对应的已注册 VFS——那样
/// 会让调用方以为自己在用新 key 查询，实际上读到的是用旧 key 构建的合并视图，
/// 是一类不会报错、只会悄悄查错数据的 bug。出现这种不一致通常意味着同一个
/// 物理文件被两个不同的 rel_key（或密钥轮换后的新旧 key）指向，是配置错误。
fn ensure_vfs_registered(
    enc_db_path: &Path,
    key: [u8; 32],
    tmp_dir: &Path,
    tag: &str,
) -> Result<(String, Arc<Mutex<ReadStats>>)> {
    let dedup_key = enc_db_path
        .canonicalize()
        .unwrap_or_else(|_| enc_db_path.to_path_buf());

    // poison-safe：某次持锁期间 panic（哪怕与本模块无关）不应该永久毒化整个
    // daemon 的 VFS 注册表，导致此后所有 `open_conn` 调用都 panic 传染。
    // 注册表本身只是纯数据（路径 -> 名字/密钥/统计句柄），锁持有者 panic 时
    // 不会留下不一致的中间状态需要担心，可以安全地 `into_inner()` 继续用。
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = reg.get(&dedup_key) {
        anyhow::ensure!(
            entry.key == key,
            "VFS 注册表 key 不一致: {:?} 已用不同密钥注册过（首次 tag 无关，这里拒绝静默复用旧 key），\
             本次 tag={}",
            enc_db_path,
            tag
        );
        return Ok((entry.vfs_name.clone(), entry.stats.clone()));
    }

    let n = VFS_NAME_SEQ.fetch_add(1, Ordering::SeqCst);
    let vfs_name = format!("wxcli-vfs-{}-{}", sanitize_tag(tag), n);
    let (wxvfs, stats) = WxVfs::new(enc_db_path.to_path_buf(), key, tmp_dir.to_path_buf());
    sqlite_vfs::register(&vfs_name, wxvfs, false)
        .map_err(|e| anyhow::anyhow!("注册自定义 VFS 失败: {}", e))
        .with_context(|| format!("enc_db_path={:?}", enc_db_path))?;

    reg.insert(
        dedup_key,
        VfsRegistration {
            vfs_name: vfs_name.clone(),
            key,
            stats: stats.clone(),
        },
    );
    Ok((vfs_name, stats))
}

/// 以只读方式打开一个 SQLCipher4 加密库，返回的连接读到的是"主库 + 同目录
/// `-wal` 文件（若存在且有有效帧）合并后"的最新视图。生产路径使用这个函数，
/// 不需要关心内部读取统计。
///
/// # 参数
/// - `enc_db_path`：加密库的真实物理路径（例如 `.../message_0.db`）。
///   `-wal` 伴生文件路径按 SQLite 标准规则从这个路径推导（追加 `-wal`），
///   调用方不需要也不应该单独传 -wal 路径。
/// - `key`：32 字节 AES 密钥。
/// - `tmp_dir`：VFS 内部临时文件（SQLite 排序临时表等）的落盘目录，调用方
///   保证其存在且可写；建议使用进程私有目录。
/// - `tag`：仅用于生成诊断性的 VFS 注册名（例如日志里能看出是哪个库），
///   不影响功能；重复调用同一 `enc_db_path` 时，`tag` 只在首次注册时生效。
///
/// # 为什么用 `immutable=1`
/// 这是让"WAL 完全由我们在页级别接管、SQLite 核心自己完全不碰 `-wal`"这套
/// 方案成立的关键前提：`immutable=1` 告诉 SQLite 核心"这个数据库文件不会被
/// 其他连接修改，你可以把它当成一个恒定不变的快照来读"，于是 SQLite 会跳过
/// 所有 WAL 探测、共享内存映射（`xShmMap`）、热日志恢复等机制，把我们返回的
/// 合并视图当成唯一的事实来源。如果不加这个参数，SQLite 会尝试自己去 open
/// `<label>-wal` / 请求共享内存锁，而我们的 VFS 根本没实现那套接口，会直接
/// 报 `SQLITE_IOERR_SHMLOCK` 类错误。
pub fn open_conn(
    enc_db_path: &Path,
    key: [u8; 32],
    tmp_dir: &Path,
    tag: &str,
) -> Result<Connection> {
    Ok(open_conn_with_stats(enc_db_path, key, tmp_dir, tag)?.0)
}

/// 同 [`open_conn`]，额外返回该 VFS 注册以来**累计共享**的 [`ReadStats`] 句柄
/// （多个连接、多次查询会往同一个计数器里累加，不是"这一次查询"隔离的统计），
/// 用于给诊断 / 监控队列页展示"这个分片总共按需解密了多少页"。如果需要
/// oracle 对拍那种"这一次查询精确解了多少页"的隔离统计，请用
/// [`open_fresh_with_stats`]。
pub fn open_conn_with_stats(
    enc_db_path: &Path,
    key: [u8; 32],
    tmp_dir: &Path,
    tag: &str,
) -> Result<(Connection, Arc<Mutex<ReadStats>>)> {
    std::fs::create_dir_all(tmp_dir)
        .with_context(|| format!("创建 VFS 临时目录失败: {:?}", tmp_dir))?;

    let (vfs_name, stats) = ensure_vfs_registered(enc_db_path, key, tmp_dir, tag)?;

    let uri = format!("file:{}?immutable=1", MAIN_LABEL);
    let conn = Connection::open_with_flags_and_vfs(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
        &vfs_name,
    )
    .with_context(|| format!("通过自定义 VFS 打开加密库失败: {:?}", enc_db_path))?;

    Ok((conn, stats))
}

/// 诊断 / oracle 专用：**不经过全局注册表去重**，总是注册一个全新命名的 VFS
/// 并返回它专属的 [`ReadStats`] 句柄，从而能精确统计"这一次连接"解密了多少
/// 页/字节。生产路径（[`open_conn`]）不应该使用这个函数——它每次调用都会在
/// 全局 VFS 注册表里留下一条新记录，长期调用会无限增长，只适合"跑一次就退出
/// 的进程"（例如 oracle 对拍测试）。目前只被 `#[cfg(test)]` 使用，非 test
/// 构建下报 dead_code 属预期。
#[cfg_attr(not(test), allow(dead_code))]
pub fn open_fresh_with_stats(
    enc_db_path: &Path,
    key: [u8; 32],
    tmp_dir: &Path,
    tag: &str,
) -> Result<(Connection, Arc<Mutex<ReadStats>>)> {
    std::fs::create_dir_all(tmp_dir)
        .with_context(|| format!("创建 VFS 临时目录失败: {:?}", tmp_dir))?;

    let n = VFS_NAME_SEQ.fetch_add(1, Ordering::SeqCst);
    let vfs_name = format!("wxcli-vfs-fresh-{}-{}", sanitize_tag(tag), n);
    let (wxvfs, stats) = WxVfs::new(enc_db_path.to_path_buf(), key, tmp_dir.to_path_buf());
    sqlite_vfs::register(&vfs_name, wxvfs, false)
        .map_err(|e| anyhow::anyhow!("注册自定义 VFS 失败: {}", e))?;

    let uri = format!("file:{}?immutable=1", MAIN_LABEL);
    let conn = Connection::open_with_flags_and_vfs(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
        &vfs_name,
    )
    .with_context(|| format!("通过自定义 VFS 打开加密库失败: {:?}", enc_db_path))?;

    Ok((conn, stats))
}

/// 主库+WAL 合并逻辑的白盒单元测试。
///
/// 这里刻意**不**通过 `sqlite_vfs::register` + `rusqlite::Connection` 走完整的
/// SQLite 打开流程——`sqlite_vfs::OpenOptions` 的字段对外部 crate 不可公开构造
/// （`delete_on_close` 是私有字段，只能由 `sqlite-vfs` 内部从原始 SQLite flags
/// 构造），所以没有办法从我们自己的测试代码里直接调用 `Vfs::open`。
///
/// 转而直接在同一个模块内构造 [`MergedFile`]（其字段对本文件内的子模块可见），
/// 精确测试我们自己写的"页级合并"算法本身。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_page, RESERVE_SZ};
    use crate::daemon::wal_index::{WAL_FRAME_HDR, WAL_HDR_SZ};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_path(tag: &str) -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("wxeasy-vfs-test-{}-{}-{}", pid, tag, n))
    }

    fn key_fixture() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    }

    fn logical_page_filled(marker: u8, is_first_page_route: bool) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_SZ];
        let region = if is_first_page_route {
            16..PAGE_SZ - RESERVE_SZ
        } else {
            0..PAGE_SZ - RESERVE_SZ
        };
        page[region].fill(marker);
        page
    }

    fn write_wal_header(buf: &mut Vec<u8>, salt1: u32, salt2: u32) {
        let mut h = vec![0u8; WAL_HDR_SZ];
        h[16..20].copy_from_slice(&salt1.to_be_bytes());
        h[20..24].copy_from_slice(&salt2.to_be_bytes());
        buf.extend(h);
    }

    fn write_wal_frame(
        buf: &mut Vec<u8>,
        pgno: u32,
        commit_pgcnt: u32,
        salt1: u32,
        salt2: u32,
        page_data: &[u8],
    ) {
        assert_eq!(page_data.len(), PAGE_SZ);
        let mut fh = vec![0u8; WAL_FRAME_HDR];
        fh[0..4].copy_from_slice(&pgno.to_be_bytes());
        fh[4..8].copy_from_slice(&commit_pgcnt.to_be_bytes());
        fh[8..12].copy_from_slice(&salt1.to_be_bytes());
        fh[12..16].copy_from_slice(&salt2.to_be_bytes());
        buf.extend(fh);
        buf.extend_from_slice(page_data);
    }

    /// 端到端场景（覆盖本模块文档里提到的每一个坑）：
    /// - 主库 3 页：pgno1(marker=1, 走首页路由) / pgno2(marker=2) / pgno3(marker=3)。
    /// - WAL（当前 salt=cur）：
    ///   - 覆盖 pgno=1 → marker=101（首页路由，WAL 帧 targeting pgno=1 与主库
    ///     物理首页布局相同，带 SALT 前缀）；
    ///   - 覆盖 pgno=2 → marker=102；
    ///   - 新增 pgno=4 → marker=104，且是让 `commit_pgcnt` 报告库扩大到 4 页的那一帧；
    /// - WAL 里还有一帧 salt 不匹配、targeting pgno=3 → marker=199，必须被完全忽略，
    ///   读 pgno=3 应该仍然拿到主库原始的 marker=3。
    #[test]
    fn merges_main_and_wal_pages_with_correct_routing_and_size() {
        let key = key_fixture();
        let cur_salt1 = 0xCAFEBABEu32;
        let cur_salt2 = 0xDEADBEEFu32;
        let bad_salt1 = 0x1111_1111u32;
        let bad_salt2 = 0x2222_2222u32;

        // ---- 主库：3 个物理页 ----
        let main_p1 = encrypt_page(&key, &logical_page_filled(1, true), &[0x01; 16], 1);
        let main_p2 = encrypt_page(&key, &logical_page_filled(2, false), &[0x02; 16], 2);
        let main_p3 = encrypt_page(&key, &logical_page_filled(3, false), &[0x03; 16], 3);
        let mut main_bytes = Vec::with_capacity(3 * PAGE_SZ);
        main_bytes.extend(main_p1);
        main_bytes.extend(main_p2);
        main_bytes.extend(main_p3);

        let main_path = tmp_path("main.db");
        std::fs::write(&main_path, &main_bytes).unwrap();

        // ---- WAL：4 帧 ----
        let mut wal_bytes = Vec::new();
        write_wal_header(&mut wal_bytes, cur_salt1, cur_salt2);

        let wal_p1 = encrypt_page(&key, &logical_page_filled(101, true), &[0x11; 16], 1);
        write_wal_frame(&mut wal_bytes, 1, 0, cur_salt1, cur_salt2, &wal_p1);

        let wal_p2 = encrypt_page(&key, &logical_page_filled(102, false), &[0x12; 16], 2);
        write_wal_frame(&mut wal_bytes, 2, 0, cur_salt1, cur_salt2, &wal_p2);

        // salt 不匹配的帧，targeting pgno=3，必须被忽略。
        let bad_p3 = encrypt_page(&key, &logical_page_filled(199, false), &[0x13; 16], 3);
        write_wal_frame(&mut wal_bytes, 3, 0, bad_salt1, bad_salt2, &bad_p3);

        // 新增 pgno=4（主库物理上根本没有这一页），并作为本次提交的收尾帧，
        // 把数据库总页数从 3 扩大到 4。
        let wal_p4 = encrypt_page(&key, &logical_page_filled(104, false), &[0x14; 16], 4);
        write_wal_frame(&mut wal_bytes, 4, 4, cur_salt1, cur_salt2, &wal_p4);

        let wal_path = wal_path_for(&main_path);
        std::fs::write(&wal_path, &wal_bytes).unwrap();

        // ---- 构造 MergedFile（绕开 Vfs::open，直接测算法本体）----
        let wal_source = build_wal_index(&wal_path)
            .unwrap()
            .expect("应解析出有效 WalSource");
        assert_eq!(
            wal_source.index.frames_valid, 3,
            "4帧里应有3帧 salt 匹配（排除 bad 帧）"
        );
        assert_eq!(wal_source.index.last_commit_pgcnt(), Some(4));

        let main_file = File::open(&main_path).unwrap();
        let main_len = main_file.metadata().unwrap().len();
        let stats = Arc::new(Mutex::new(ReadStats::default()));
        let mut wxfile = WxFile::Merged(MergedFile {
            main: main_file,
            main_len,
            key,
            wal: Some(wal_source),
            stats: stats.clone(),
            lock: LockKind::None,
        });

        // size() 必须反映 WAL 扩展后的 4 页，而不是主库物理的 3 页。
        assert_eq!(wxfile.size().unwrap(), 4 * PAGE_SZ as u64);

        let assert_page =
            |wxfile: &mut WxFile, pgno: u32, expected_marker: u8, first_page_route: bool| {
                let mut buf = vec![0u8; PAGE_SZ];
                wxfile
                    .read_exact_at(&mut buf, (pgno as u64 - 1) * PAGE_SZ as u64)
                    .unwrap();
                let region = if first_page_route {
                    16..PAGE_SZ - RESERVE_SZ
                } else {
                    0..PAGE_SZ - RESERVE_SZ
                };
                assert!(
                    buf[region].iter().all(|&b| b == expected_marker),
                    "pgno={} 期望 marker={}，实际内容不匹配",
                    pgno,
                    expected_marker
                );
            };

        // pgno=1：应读到 WAL 覆盖版本（marker=101），不是主库原始的 marker=1。
        assert_page(&mut wxfile, 1, 101, true);
        assert_page(&mut wxfile, 2, 102, false);
        // pgno=3：WAL 里那帧 salt 不匹配，必须被忽略，读到主库原始内容 marker=3。
        assert_page(&mut wxfile, 3, 3, false);
        // pgno=4：纯粹来自 WAL 的扩展页，主库物理上并不存在。
        assert_page(&mut wxfile, 4, 104, false);

        let snap = stats.lock().unwrap().clone();
        assert_eq!(snap.pages_from_wal, [1u32, 2, 4].into_iter().collect());
        assert_eq!(snap.pages_from_main, [3u32].into_iter().collect());
        assert_eq!(snap.distinct_pages(), 4);

        let _ = std::fs::remove_file(&main_path);
        let _ = std::fs::remove_file(&wal_path);
    }

    /// 没有 `-wal`（或 -wal 无效）时必须完全退化为纯主库读取，`size()` 回退到
    /// 主库物理页数——不能因为引入 WAL 合并，就破坏了"没有 WAL 时和旧的纯只读
    /// VFS 行为完全一致"这个前提。
    #[test]
    fn falls_back_to_main_only_when_no_wal() {
        let key = key_fixture();
        let main_p1 = encrypt_page(&key, &logical_page_filled(7, true), &[0x21; 16], 1);
        let main_path = tmp_path("main-no-wal.db");
        std::fs::write(&main_path, &main_p1).unwrap();

        let main_file = File::open(&main_path).unwrap();
        let main_len = main_file.metadata().unwrap().len();
        let stats = Arc::new(Mutex::new(ReadStats::default()));
        let mut wxfile = WxFile::Merged(MergedFile {
            main: main_file,
            main_len,
            key,
            wal: None,
            stats: stats.clone(),
            lock: LockKind::None,
        });

        assert_eq!(wxfile.size().unwrap(), PAGE_SZ as u64);
        let mut buf = vec![0u8; PAGE_SZ];
        wxfile.read_exact_at(&mut buf, 0).unwrap();
        assert!(buf[16..PAGE_SZ - RESERVE_SZ].iter().all(|&b| b == 7));

        let snap = stats.lock().unwrap().clone();
        assert!(snap.pages_from_wal.is_empty());
        assert_eq!(snap.pages_from_main, [1u32].into_iter().collect());

        let _ = std::fs::remove_file(&main_path);
    }

    /// 洞防御：既不在 WAL 索引里、又超出主库物理页范围的页（`page_start >=
    /// main_len`），必须返回全零明文页，不能把这一页当"主库密文"喂给
    /// `decrypt_page`——对全零密文解密不会解出零，只会解出看似合法实则垃圾
    /// 的"随机"明文，且不会报错。用哨兵值预填 buf，确保断言不是"恰好没写"。
    #[test]
    fn hole_page_beyond_wal_and_main_returns_all_zero_not_garbage() {
        let key = key_fixture();
        // 主库只有 1 物理页。
        let main_p1 = encrypt_page(&key, &logical_page_filled(1, true), &[0x41; 16], 1);
        let main_path = tmp_path("hole-main");
        std::fs::write(&main_path, &main_p1).unwrap();

        let main_file = File::open(&main_path).unwrap();
        let main_len = main_file.metadata().unwrap().len();
        let stats = Arc::new(Mutex::new(ReadStats::default()));
        // 没有 WAL：模拟"total_pages() 上报的总页数比实际覆盖范围更大"这种
        // 防御场景——直接绕开 total_pages()，对第 2 页（超出主库 1 页范围）
        // 发起读取。
        let mut wxfile = WxFile::Merged(MergedFile {
            main: main_file,
            main_len,
            key,
            wal: None,
            stats: stats.clone(),
            lock: LockKind::None,
        });

        let mut buf = vec![0xAAu8; PAGE_SZ]; // 非零哨兵
        wxfile.read_exact_at(&mut buf, PAGE_SZ as u64).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "洞页必须是全零明文，不能是 decrypt_page(全零密文) 的垃圾输出"
        );

        // 没有发生真实解密，不应该污染统计。
        let snap = stats.lock().unwrap().clone();
        assert!(snap.pages_decrypted.is_empty());
        assert_eq!(snap.decrypt_calls, 0);

        let _ = std::fs::remove_file(&main_path);
    }

    /// key 一致性：同一物理路径第二次以不同 key 调用 `ensure_vfs_registered`
    /// 必须报错，不能静默复用第一次注册时的 VFS（那样调用方会以为自己在用
    /// 新 key 查询，实际读到的是旧 key 构建的合并视图）。
    #[test]
    fn ensure_vfs_registered_rejects_key_mismatch_on_same_physical_path() {
        let key1 = key_fixture();
        let mut key2 = key1;
        key2[0] ^= 0xFF; // 明显不同的第二把 key

        let main_p1 = encrypt_page(&key1, &logical_page_filled(9, true), &[0x51; 16], 1);
        let main_path = tmp_path("key-mismatch");
        std::fs::write(&main_path, &main_p1).unwrap();
        let tmp_dir = tmp_path("key-mismatch-tmp");

        let (name1, _stats1) =
            ensure_vfs_registered(&main_path, key1, &tmp_dir, "key-mismatch-test").unwrap();

        let err = ensure_vfs_registered(&main_path, key2, &tmp_dir, "key-mismatch-test")
            .expect_err("同一物理路径用不同 key 第二次调用必须报错，不能静默复用旧 key 的 VFS");
        let msg = err.to_string();
        assert!(
            msg.contains("key 不一致"),
            "错误信息应能定位到 key 不一致，实际: {}",
            msg
        );

        // 第一次注册的结果不应受这次失败调用影响，之后仍能用原 key 正常复用。
        let (name1_again, _) =
            ensure_vfs_registered(&main_path, key1, &tmp_dir, "key-mismatch-test").unwrap();
        assert_eq!(name1, name1_again);

        let _ = std::fs::remove_file(&main_path);
    }

    /// 注册表幂等性：同一物理路径反复 `ensure_vfs_registered` 不应重复注册
    /// （否则 `sqlite_vfs::register` 会因为同名冲突而报错——这里直接断言
    /// 返回的 VFS 名字完全一致，说明走的是复用分支而不是重新注册）。
    #[test]
    fn ensure_vfs_registered_is_idempotent_per_physical_path() {
        let key = key_fixture();
        let main_p1 = encrypt_page(&key, &logical_page_filled(9, true), &[0x31; 16], 1);
        let main_path = tmp_path("idempotent.db");
        std::fs::write(&main_path, &main_p1).unwrap();
        let tmp_dir = tmp_path("idempotent-tmp");

        let (name1, stats1) =
            ensure_vfs_registered(&main_path, key, &tmp_dir, "idempotent-test").unwrap();
        let (name2, stats2) =
            ensure_vfs_registered(&main_path, key, &tmp_dir, "idempotent-test").unwrap();
        let (name3, stats3) =
            ensure_vfs_registered(&main_path, key, &tmp_dir, "different-tag-ignored").unwrap();
        assert_eq!(
            name1, name2,
            "同一物理路径重复调用必须复用同一个已注册 VFS 名字"
        );
        assert_eq!(
            name1, name3,
            "第二次调用的 tag 不应影响已注册路径的复用结果"
        );
        assert!(
            Arc::ptr_eq(&stats1, &stats2) && Arc::ptr_eq(&stats1, &stats3),
            "复用同一个已注册 VFS 时，stats 句柄也必须是同一个 Arc（累计统计共享）"
        );

        let _ = std::fs::remove_file(&main_path);
    }

    /// poison-safe 端到端验证（补验，非迁移者原有测试）：从另一个线程真实持锁并
    /// panic，制造一次真正的 `PoisonError`，而不是只信任
    /// `unwrap_or_else(|e| e.into_inner())` 这行代码"看起来对"。验证：
    /// (1) poison 之前已注册的物理路径信息在 poison 之后依然保留（`into_inner`
    ///     没有把注册表清空或换成默认值）；
    /// (2) poison 之后 `ensure_vfs_registered` 仍能正常工作，不会永久传染 panic。
    #[test]
    fn registry_survives_lock_poisoning_from_unrelated_panic() {
        let key = key_fixture();
        let main_p1 = encrypt_page(&key, &logical_page_filled(5, true), &[0x61; 16], 1);
        let main_path = tmp_path("poison-recover");
        std::fs::write(&main_path, &main_p1).unwrap();
        let tmp_dir = tmp_path("poison-recover-tmp");

        let (name_before, _stats_before) =
            ensure_vfs_registered(&main_path, key, &tmp_dir, "poison-before").unwrap();

        // 另一个线程真实拿到锁后 panic（模拟"daemon 里某个与本模块无关的 bug
        // 恰好在持有这把全局注册表锁时崩溃"），验证 poison 之后注册表仍可用。
        let poison_result = std::thread::spawn(|| {
            let _guard = registry().lock().unwrap();
            panic!("intentional poison for test");
        })
        .join();
        assert!(
            poison_result.is_err(),
            "生产线程应该真的 panic 了，否则这个测试没有制造出 poison"
        );

        let (name_after, _stats_after) =
            ensure_vfs_registered(&main_path, key, &tmp_dir, "poison-after").expect(
                "registry 在 poison 后应仍可用（into_inner 恢复），不能永久传染 panic 给所有后续 open_conn 调用",
            );
        assert_eq!(
            name_before, name_after,
            "poison 恢复后应仍能识别 poison 之前已注册的物理路径，不能丢失既有注册表状态"
        );

        let _ = std::fs::remove_file(&main_path);
    }
}
