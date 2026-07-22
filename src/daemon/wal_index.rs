//! WAL 帧索引：只扫帧头、不解密页内容，为 [`super::vfs`] 的按页合并提供
//! `pgno -> -wal 文件内 page_data 偏移` 的映射，以及"WAL 视角下数据库总页数"。
//!
//! 从 `tools/wx-verify/wxvfs-core/src/wal_index.rs` 逐字移植（已在独立原型里
//! 通过真实 SQLCipher 活体验证），仅把 `PAGE_SZ` 换成 wxeasy 自身
//! `crate::crypto::PAGE_SZ`，不改变任何解析/覆盖语义。
//!
//! # WAL 文件格式（SQLite 标准；SQLCipher4 下帧内 page_data 依然是密文）
//! - WAL header（32 字节，大端）：
//!   `magic(4) + format(4) + page_sz(4) + ckpt_seq(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)`
//! - 每帧 = frame_header(24 字节) + page_data(PAGE_SZ 字节)：
//!   `pgno(4) + commit_pgcnt(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)`
//!
//! # 核心坑 1：只有 salt 匹配的帧才是"当前有效事务"
//! WAL 是一个只追加(append-only)的日志。SQLite 每次 checkpoint 或重新开启一轮
//! 写事务时会滚动 salt（写入新的 salt1/salt2 到 WAL header），旧 salt 的帧代表
//! "已经被 checkpoint 过、或者属于更早、已经不再是当前有效快照的事务"。
//! 所以判断一帧是否要采纳，必须比较帧头 salt 与**当前 WAL header** 的 salt，
//! 而不是任何"帧内容看起来正常"之类的启发式判断。
//!
//! # 核心坑 2：同一 pgno 出现多次，后写的覆盖先写的
//! 一个页在同一批未 checkpoint 的事务里可能被改了不止一次（例如同一事务内
//! 多次 UPDATE 同一页，或者连续几个已提交事务都改了同一页）。WAL 是按写入
//! 顺序追加的，因此文件里越靠后出现的同 pgno 帧，数据越新。索引构建时按文件
//! 顺序正向扫描、直接用 `HashMap::insert` 覆盖旧值，天然得到"最新帧生效"的语义。
//!
//! # 核心坑 3（与 wxeasy `crypto::wal::apply_wal` 保持一致的简化行为，务必读完）
//! 标准 SQLite 的 wal-index（`-shm` 共享内存 + `xShmMap`）语义是：一个只读事务在
//! 开始时会固定一个 `mxFrame`（当时 WAL 里最后一个**已提交**帧的位置），只读取
//! `mxFrame` 之前（含）的帧，从而绝不会看到"尚未提交完的半个事务"。
//!
//! 本模块**没有**实现这层"按最后一次提交做截断"的语义——它和 wxeasy 现有的
//! `crypto::wal::apply_wal` 行为完全一致：只要一帧的 salt 匹配，就会被采纳进
//! 合并视图，不管它是否处于一个尚未写完 commit 帧的事务尾部。
//!
//! 这是刻意的选择，不是疏漏：本模块的正确性标准是"与 wxeasy 现有实现内容级
//! 一致"（oracle = full_decrypt + apply_wal），如果 VFS 自作主张去做更严格的
//! "仅提交视图"截断，反而会在 oracle 对拍时产生 VFS 更"正确"但与 oracle 不
//! 一致的差异。
//!
//! # 核心坑 4：WAL 帧的 pgno==1 与主库物理第一页解密路径相同
//! 已被真实 SQLCipher（pysqlcipher3 造活体 WAL + 独立手写 AES 解密双重验证）
//! 实锤：WAL 帧 targeting pgno==1 时，其 page_data 与主库物理首页布局完全
//! 一致，同样带 16 字节 SALT 前缀。本模块只负责记录"哪个 pgno 应该从 WAL 的
//! 什么偏移读"，不关心解密——真正的路由分支在 `crate::crypto::decrypt_page`
//! 里（该函数已在上一步修复过 pgno==1 误路由的致命 bug），这里原样传递真实
//! pgno，不做任何转换。
//!
//! 作者: okooo5km(十里)

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto::PAGE_SZ;

/// WAL header 长度。
pub const WAL_HDR_SZ: usize = 32;
/// WAL 每帧的帧头长度（不含 page_data）。
pub const WAL_FRAME_HDR: usize = 24;

/// 单个 WAL 帧头解析结果（内部用）。
struct FrameHeader {
    pgno: u32,
    commit_pgcnt: u32,
    salt1: u32,
    salt2: u32,
}

impl FrameHeader {
    fn parse(buf: &[u8; WAL_FRAME_HDR]) -> Self {
        FrameHeader {
            pgno: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            commit_pgcnt: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            salt1: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            salt2: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
        }
    }
}

/// 一个 -wal 文件的帧索引：只有偏移量，不含任何解密后 / 加密的页内容，内存占用
/// 只随"有效帧数"线性增长（每条目 `u32 + u64` 量级），不随 WAL 文件大小本身增长。
#[derive(Debug, Default, Clone)]
pub struct WalFrameIndex {
    /// pgno -> 该帧 page_data 在 -wal 文件中的绝对字节偏移（从 WAL 文件开头算，
    /// 已经跳过了 24 字节帧头，指向 page_data 的第一个字节）。
    frame_offsets: HashMap<u32, u64>,
    /// 所有 salt 匹配帧中，最后一个 `commit_pgcnt != 0` 的帧所携带的 commit_pgcnt。
    /// 这就是 WAL 视角下的数据库总页数（标准 SQLite WAL 语义：一次提交时记录的
    /// commit_pgcnt 是"提交后数据库应有的总页数"，WAL 可能把库扩大）。
    /// `None` 表示这个 WAL 文件里没有出现过任何有效的提交帧，此时数据库大小应
    /// 完全回退到主库物理页数。
    last_commit_pgcnt: Option<u32>,
    /// WAL header 中的 salt1/salt2，仅保留用于诊断日志，不参与后续读取逻辑。
    #[allow(dead_code)]
    pub header_salt1: u32,
    #[allow(dead_code)]
    pub header_salt2: u32,
    /// 扫描到的帧总数（含 salt 不匹配、pgno 越界等被丢弃的帧），用于诊断。
    #[allow(dead_code)]
    pub frames_total: usize,
    /// salt 匹配、被采纳进 `frame_offsets` 覆盖过程的帧数（同一 pgno 多次计入多次）。
    #[allow(dead_code)]
    pub frames_valid: usize,
}

impl WalFrameIndex {
    /// 该 pgno 是否有 WAL 覆盖版本；如果有，返回其 page_data 在 -wal 文件中的偏移。
    pub fn offset_for(&self, pgno: u32) -> Option<u64> {
        self.frame_offsets.get(&pgno).copied()
    }

    /// WAL 视角下数据库总页数（用于 file_size），`None` 表示本 WAL 未提供有效提交，
    /// 调用方应回退主库物理页数。
    pub fn last_commit_pgcnt(&self) -> Option<u32> {
        self.last_commit_pgcnt
    }

    /// 索引中登记的不同 pgno 个数（即"被 WAL 覆盖的页数"），用于诊断 / 按需读取证明。
    #[allow(dead_code)]
    pub fn covered_page_count(&self) -> usize {
        self.frame_offsets.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.frame_offsets.is_empty()
    }
}

/// 已打开的 -wal 文件 + 其帧索引。VFS 按需读页时通过这里保留的 `File` 句柄做
/// 定点 `seek + read`，不会把整份 WAL 内容常驻内存。
///
/// `index` 是 `Arc` 共享的**不可变快照**：增量缓存（[`WalIndexCache`]）命中
/// 且无新帧时直接复用同一份 `Arc`（零拷贝）；有新帧时深拷贝一次再扩展成新
/// 快照——已存在连接持有的旧快照绝不会被原地修改（连接的 `immutable=1`
/// 视图必须冻结在它建立那一刻）。
pub struct WalSource {
    file: File,
    pub index: Arc<WalFrameIndex>,
}

impl WalSource {
    /// 读取指定 pgno 对应的 WAL 帧原始（仍是密文）page_data，长度固定 PAGE_SZ。
    /// 调用前必须先用 `index.offset_for(pgno)` 确认存在，这里不重复查表。
    pub fn read_raw_page(&mut self, offset: u64) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; PAGE_SZ];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// 由主库路径推导出同目录下的 `-wal` 伴生文件路径（SQLite 标准命名：
/// 直接在完整文件名后追加 `-wal`，不是替换扩展名）。
pub fn wal_path_for(main_db_path: &Path) -> PathBuf {
    let mut os = main_db_path.as_os_str().to_os_string();
    os.push("-wal");
    PathBuf::from(os)
}

/// 扫描阶段一次底层读的缓冲大小。机械盘上把「每帧 seek + 24 字节小读」的
/// 跨步模式换成 4MiB 级顺序大块读：100MB WAL 的底层读从 ~2.5 万次 syscall
/// 降到 ~25 次，且不再依赖 OS readahead 在内存压力下的可靠性（cache
/// manager 内存吃紧时会收缩 readahead，跨步小读会退化成逐帧等一次旋转
/// 延迟——这正是慢盘卡死场景的隐藏贡献者之一）。
const WAL_SCAN_BUF_SZ: usize = 4 * 1024 * 1024;

/// 帧头扫描的纯逻辑段（从 [`build_wal_index`] 抽出以便直接测试两条守护
/// 语义）。`file_len` 是**扫描开始前**读到的长度快照：
///
/// - **长度快照封顶**：只解析 `file_len` 以内的完整帧。扫描期间微信追加的
///   新帧（reader 可能已经缓冲到其字节）一律不解析——与旧的逐帧 seek 实现
///   完全一致，保证「索引边界 == 快照时刻」的语义。
/// - **中途截断 fail-loud**：`file_len` 以内的字节竟然读不满（微信
///   checkpoint TRUNCATE 把 `-wal` 截短的瞬间）必须原样报错、让整个 open
///   失败由上层重试——绝不能把文件**中段**的 short read 静默当成「半截
///   尾帧」成功返回，否则会在主库正被 checkpoint 回填的瞬间产出一个貌似
///   有效、实则截断的索引，扩大撕裂视图窗口。
///
/// 尾部不足一整帧的残留字节（`file_len` 本身没对齐到帧边界）仍视为
/// 「正在写入中的半截帧」直接忽略——那是写入协议的正常形态，与「快照内
/// 的字节消失了」是两回事。
/// `start_pos` 支持增量续扫（[`WalIndexCache`]）：从上次扫描终点（必然是
/// 完整帧边界）继续解析，`seed` 是上次扫描的累计状态；全量扫描时
/// `start_pos = WAL_HDR_SZ`、`seed` 为默认空状态。返回索引与本次扫描终点
/// （最后一个已解析完整帧之后的字节偏移——**必须**以它作为下次续扫起点，
/// 不能用 `file_len` 推算：`file_len` 可能落在半截尾帧中间）。
fn scan_wal_frames<R: io::Read + io::Seek>(
    reader: &mut R,
    start_pos: u64,
    file_len: u64,
    salt1: u32,
    salt2: u32,
    seed: WalFrameIndex,
) -> io::Result<(WalFrameIndex, u64)> {
    let frame_size = (WAL_FRAME_HDR + PAGE_SZ) as u64;
    let mut frame_offsets = seed.frame_offsets;
    let mut last_commit_pgcnt = seed.last_commit_pgcnt;
    let mut frames_total = seed.frames_total;
    let mut frames_valid = seed.frames_valid;

    let mut pos = start_pos;
    let mut fh_buf = [0u8; WAL_FRAME_HDR];
    reader.seek(SeekFrom::Start(pos))?;

    let mut buffered = io::BufReader::with_capacity(WAL_SCAN_BUF_SZ, reader);
    while pos + frame_size <= file_len {
        // read_exact 在快照边界内读不满 ⇒ UnexpectedEof 原样上抛（fail-loud）。
        buffered.read_exact(&mut fh_buf)?;
        let fh = FrameHeader::parse(&fh_buf);

        let page_data_offset = pos + WAL_FRAME_HDR as u64;
        frames_total += 1;

        // pgno 合法性 + salt 匹配，逐字对齐 wxeasy crypto::wal::apply_wal 的判定条件。
        if fh.pgno != 0 && fh.pgno <= 1_000_000 && fh.salt1 == salt1 && fh.salt2 == salt2 {
            frames_valid += 1;
            // 同一 pgno 多次出现时，后出现的（文件序靠后 = 更新）覆盖先出现的。
            frame_offsets.insert(fh.pgno, page_data_offset);
            if fh.commit_pgcnt != 0 {
                last_commit_pgcnt = Some(fh.commit_pgcnt);
            }
        }

        // 跳过本帧的 page_data，不读取、不解密。`seek_relative` 在缓冲区内
        // 命中时纯指针移动、零 syscall——底层 IO 因此聚合成 4MiB 级顺序读。
        buffered.seek_relative(PAGE_SZ as i64)?;
        pos += frame_size;
    }

    Ok((
        WalFrameIndex {
            frame_offsets,
            last_commit_pgcnt,
            header_salt1: salt1,
            header_salt2: salt2,
            frames_total,
            frames_valid,
        },
        pos,
    ))
}

/// WAL 帧索引的跨重建增量缓存（每个物理 `-wal` 路径一份，挂在 VFS 注册表
/// 条目上、与 daemon 同寿命）。
///
/// # 为什么增量续扫是「读真字节」而不是 metadata 信任
/// WAL 在同一 salt 世代内严格 append-only；checkpoint / reset 必然改写
/// header 的 salt1/salt2（「核心坑 1」已依赖的 SQLite WAL 协议）。因此
/// 「重新读 32 字节 header 比对 salt + 从上次边界续扫」得到的索引与全量
/// 重扫**逐字节等价**——已扫过的帧在同世代内不可能变化，唯一的概率性
/// 假设是 salt1+salt2 共 64 bit 在新旧世代间碰撞（~2⁻⁶⁴，本模块此前从未
/// 依赖跨时刻 salt 比对，这是新增假设，特此注明）。这不触碰 §4.1 的
/// mtime 门控——门控管的是「要不要重建连接」，这里管的是「重建时 WAL
/// 区间要不要重读」，且判定依据是文件真实字节。
///
/// # 并发
/// 多个 open 并发续扫同一分片时各自取快照、各自扫描（锁只保护取/存快照，
/// 不覆盖 IO 段），写回互相覆盖——每次写回都是一份自洽的完整快照（索引
/// 与终点成对），后写者赢即可，不存在「半新半旧」状态。
///
/// # mid-scan reset 的 TOCTOU
/// 续扫期间微信 checkpoint/reset：新世代帧的 salt 与本次 header 快照不
/// 匹配 ⇒ 被逐帧丢弃，与全量扫描的既有行为完全同构，不引入新竞态类别
/// （对应单测 `incremental_scan_drops_frames_from_new_generation`）。
#[derive(Default)]
pub struct WalIndexCache {
    entry: Option<CachedWalScan>,
}

struct CachedWalScan {
    salt1: u32,
    salt2: u32,
    /// 上次扫描终点（完整帧边界，见 [`scan_wal_frames`] 返回值说明）。
    scan_end: u64,
    index: Arc<WalFrameIndex>,
}

/// 带增量缓存的 [`build_wal_index`]。
///
/// 复用条件（全部满足才续扫，否则全量重扫）：header salt 与缓存一致、
/// `file_len >= 缓存终点`。无新帧（`file_len` 不足再放一个完整帧）时直接
/// 零拷贝复用缓存的 `Arc` 快照——稳态轮询里「分片被强制作废重建、但 WAL
/// 本身没长」的场景整段 WAL 重扫直接消失。
pub fn build_wal_index_cached(
    wal_path: &Path,
    cache: &std::sync::Mutex<WalIndexCache>,
) -> io::Result<Option<WalSource>> {
    let mut file = match File::open(wal_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let file_len = file.metadata()?.len();
    if file_len <= WAL_HDR_SZ as u64 {
        return Ok(None);
    }

    let mut header = [0u8; WAL_HDR_SZ];
    file.read_exact(&mut header)?;
    let salt1 = u32::from_be_bytes(header[16..20].try_into().unwrap());
    let salt2 = u32::from_be_bytes(header[20..24].try_into().unwrap());

    // 锁内只做快照取用，IO 全在锁外。
    let cached: Option<(u64, Arc<WalFrameIndex>)> = {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.entry.as_ref().and_then(|e| {
            (e.salt1 == salt1 && e.salt2 == salt2 && file_len >= e.scan_end)
                .then(|| (e.scan_end, e.index.clone()))
        })
    };

    let frame_size = (WAL_FRAME_HDR + PAGE_SZ) as u64;
    let (index, scan_end) = match cached {
        Some((start, snapshot)) if start + frame_size > file_len => {
            // 无新完整帧：零拷贝复用缓存快照，整段 WAL 重扫消失。
            (snapshot, start)
        }
        Some((start, snapshot)) => {
            // 有新帧：深拷贝一次旧快照做种子、只扫增量区间。旧 Arc 不动
            // ——已存在连接的视图保持冻结。
            let seed = (*snapshot).clone();
            let (merged, end) = scan_wal_frames(&mut file, start, file_len, salt1, salt2, seed)?;
            (Arc::new(merged), end)
        }
        None => {
            let (full, end) = scan_wal_frames(
                &mut file,
                WAL_HDR_SZ as u64,
                file_len,
                salt1,
                salt2,
                WalFrameIndex::default(),
            )?;
            (Arc::new(full), end)
        }
    };

    {
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.entry = Some(CachedWalScan {
            salt1,
            salt2,
            scan_end,
            index: index.clone(),
        });
    }

    Ok(Some(WalSource { file, index }))
}

/// 打开 `-wal` 文件并扫描全部帧头，建立索引。
///
/// - 若文件不存在，或存在但小到连一个完整 header 都放不下，返回 `Ok(None)`
///   （语义等价于"没有 WAL，请只读主库"，与 `crypto::wal::apply_wal` 遇到同样
///   情况时直接 `return Ok(())`——即"不做任何改动"——完全对应）。
/// - 扫描阶段只解析每帧的 24 字节帧头、跳过 page_data，绝不解密页内容；
///   底层 IO 是 [`WAL_SCAN_BUF_SZ`] 级的顺序大块读（见 [`scan_wal_frames`]，
///   两条守护语义——长度快照封顶、中途截断 fail-loud——也在那里说明）。
/// - 扫描用完的 `File` 句柄原样留给 [`WalSource`] 做后续随机页读，**不加**
///   `FILE_FLAG_SEQUENTIAL_SCAN` 之类的访问模式提示：该句柄的主要用途是
///   `read_raw_page` 的随机 seek，SEQUENTIAL_SCAN 会让 cache manager 对它
///   激进 evict-behind，反伤后续随机读。
/// 生产路径已改走 [`build_wal_index_cached`]；这个无缓存版本保留给单测与
/// oracle 对拍（每次全量扫描、无跨调用状态，是增量版的对拍基准）。
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_wal_index(wal_path: &Path) -> io::Result<Option<WalSource>> {
    let mut file = match File::open(wal_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let file_len = file.metadata()?.len();
    if file_len <= WAL_HDR_SZ as u64 {
        // 空文件或只有 header 没有任何帧：等价于"没有待合并的 WAL 变更"。
        return Ok(None);
    }

    let mut header = [0u8; WAL_HDR_SZ];
    file.read_exact(&mut header)?;
    let salt1 = u32::from_be_bytes(header[16..20].try_into().unwrap());
    let salt2 = u32::from_be_bytes(header[20..24].try_into().unwrap());

    let (index, _scan_end) = scan_wal_frames(
        &mut file,
        WAL_HDR_SZ as u64,
        file_len,
        salt1,
        salt2,
        WalFrameIndex::default(),
    )?;

    Ok(Some(WalSource {
        file,
        index: Arc::new(index),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_path(tag: &str) -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("wxeasy-wal-index-test-{}-{}-{}", pid, tag, n))
    }

    fn write_wal_header(salt1: u32, salt2: u32) -> Vec<u8> {
        let mut h = vec![0u8; WAL_HDR_SZ];
        h[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes()); // magic（本模块不校验，仅为格式真实感）
        h[4..8].copy_from_slice(&3007000u32.to_be_bytes()); // format version（不校验）
        h[8..12].copy_from_slice(&(PAGE_SZ as u32).to_be_bytes()); // page_sz（不校验，仅诊断意义）
        h[12..16].copy_from_slice(&1u32.to_be_bytes()); // ckpt_seq（不校验）
        h[16..20].copy_from_slice(&salt1.to_be_bytes());
        h[20..24].copy_from_slice(&salt2.to_be_bytes());
        // cksum1/cksum2（24..32）：本模块和 wxeasy 现有 apply_wal 均不校验，留零。
        h
    }

    fn write_frame(pgno: u32, commit_pgcnt: u32, salt1: u32, salt2: u32, fill_byte: u8) -> Vec<u8> {
        let mut f = vec![0u8; WAL_FRAME_HDR + PAGE_SZ];
        f[0..4].copy_from_slice(&pgno.to_be_bytes());
        f[4..8].copy_from_slice(&commit_pgcnt.to_be_bytes());
        f[8..12].copy_from_slice(&salt1.to_be_bytes());
        f[12..16].copy_from_slice(&salt2.to_be_bytes());
        // cksum1/cksum2（16..24）：不校验，留零。
        // page_data 内容对索引构建阶段无意义（索引只记偏移，不读内容），
        // 用 fill_byte 填充只是方便测试里用偏移读出来做"是不是这一帧"的旁证。
        f[WAL_FRAME_HDR..].fill(fill_byte);
        f
    }

    /// 核心场景：同一 pgno 出现两次（一次旧 salt / 一次新 salt 各一次，且新 salt
    /// 内部还出现两次），验证：
    /// - 旧 salt 的帧被正确排除（frames_valid 不计入它）；
    /// - 新 salt 内同一 pgno 的两帧，索引最终指向"文件序更靠后"的那一帧；
    /// - `last_commit_pgcnt` 取"新 salt 范围内最后一个 commit_pgcnt!=0 帧"的值。
    #[test]
    fn salt_filtering_and_last_write_wins() {
        let path = tmp_path("filter-and-override");
        let cur_salt1 = 0xAAAA_AAAA;
        let cur_salt2 = 0xBBBB_BBBB;
        let old_salt1 = 0x1111_1111;
        let old_salt2 = 0x2222_2222;

        let mut buf = write_wal_header(cur_salt1, cur_salt2);
        // 帧0：旧 salt，pgno=7，应被忽略。
        buf.extend(write_frame(7, 0, old_salt1, old_salt2, 0x01));
        // 帧1：新 salt，pgno=7，第一次写入，先写入的版本。
        buf.extend(write_frame(7, 0, cur_salt1, cur_salt2, 0x02));
        // 帧2：新 salt，pgno=7，第二次写入（同一事务内又改了一次同一页），应覆盖帧1。
        buf.extend(write_frame(7, 5, cur_salt1, cur_salt2, 0x03));
        // 帧3：新 salt，pgno=9，另一个页，作为这次提交的收尾帧（真实提交页数=5）。
        buf.extend(write_frame(9, 5, cur_salt1, cur_salt2, 0x04));

        std::fs::write(&path, &buf).unwrap();

        let src = build_wal_index(&path).unwrap().expect("应当解析出一个有效 WalSource");
        assert_eq!(src.index.frames_total, 4);
        // 帧0（旧salt）被排除，帧1/2/3有效 => frames_valid = 3
        assert_eq!(src.index.frames_valid, 3);
        assert_eq!(src.index.covered_page_count(), 2, "pgno=7 和 pgno=9 各算一个覆盖页");
        assert_eq!(src.index.last_commit_pgcnt(), Some(5));

        // pgno=7 应该指向帧2（0x03 填充），不是帧1（0x02）或帧0（0x01，且帧0本就该被排除）。
        let offset_pgno7 = src.index.offset_for(7).expect("pgno=7 应命中 WAL 索引");
        let mut src_mut = src;
        let raw7 = src_mut.read_raw_page(offset_pgno7).unwrap();
        assert!(raw7.iter().all(|&b| b == 0x03), "pgno=7 必须读到最后写入的那一帧（0x03），而不是更早的 0x01/0x02");

        let offset_pgno9 = src_mut.index.offset_for(9).expect("pgno=9 应命中 WAL 索引");
        let raw9 = src_mut.read_raw_page(offset_pgno9).unwrap();
        assert!(raw9.iter().all(|&b| b == 0x04));

        assert!(src_mut.index.offset_for(0).is_none(), "pgno=0 恒非法，不应出现在索引里");

        let _ = std::fs::remove_file(&path);
    }

    /// 没有任何提交帧（`commit_pgcnt` 全为 0）时，`last_commit_pgcnt` 必须是
    /// `None`，调用方据此回退主库物理页数——这对应"抓拍到一个尚未提交完的
    /// 事务尾巴"这种边界场景（详见模块顶部"核心坑3"注释）。
    #[test]
    fn no_commit_frame_yields_none_last_commit_pgcnt() {
        let path = tmp_path("no-commit");
        let s1 = 0x5555_5555;
        let s2 = 0x6666_6666;
        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(3, 0, s1, s2, 0x9));
        std::fs::write(&path, &buf).unwrap();

        let src = build_wal_index(&path).unwrap().unwrap();
        assert_eq!(src.index.frames_valid, 1);
        assert_eq!(src.index.last_commit_pgcnt(), None);

        let _ = std::fs::remove_file(&path);
    }

    /// pgno 越界（0 或 > 1_000_000）必须被丢弃，即便 salt 匹配——这是防御性
    /// 校验，避免损坏/截断的 WAL 文件里出现的垃圾字节被解释成一个荒谬的页码。
    #[test]
    fn out_of_range_pgno_is_rejected() {
        let path = tmp_path("out-of-range-pgno");
        let s1 = 0x7777_7777;
        let s2 = 0x8888_8888;
        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(0, 0, s1, s2, 0x1)); // pgno=0 非法
        buf.extend(write_frame(2_000_000, 0, s1, s2, 0x2)); // 超过 1_000_000
        buf.extend(write_frame(42, 1, s1, s2, 0x3)); // 唯一合法帧
        std::fs::write(&path, &buf).unwrap();

        let src = build_wal_index(&path).unwrap().unwrap();
        assert_eq!(src.index.frames_total, 3);
        assert_eq!(src.index.frames_valid, 1);
        assert_eq!(src.index.covered_page_count(), 1);
        assert!(src.index.offset_for(42).is_some());

        let _ = std::fs::remove_file(&path);
    }

    /// 文件不存在 / 只有 header 没有任何帧时，必须返回 `Ok(None)`，
    /// 语义上等价于 wxeasy `crypto::wal::apply_wal` 遇到同样情况时"不做任何改动"。
    #[test]
    fn missing_or_header_only_wal_returns_none() {
        let missing = tmp_path("missing");
        assert!(build_wal_index(&missing).unwrap().is_none());

        let header_only = tmp_path("header-only");
        let buf = write_wal_header(1, 2);
        std::fs::write(&header_only, &buf).unwrap();
        assert!(build_wal_index(&header_only).unwrap().is_none());

        let _ = std::fs::remove_file(&header_only);
    }

    /// 守护语义 1（长度快照封顶）：扫描以 `file_len` 快照为界——实际字节
    /// 比快照多（模拟「扫描开始后微信又追加了新帧、且已被缓冲读读进来」）
    /// 时，快照之外的完整帧必须被忽略，索引边界严格等于快照时刻。
    #[test]
    fn frames_beyond_len_snapshot_are_ignored() {
        let s1 = 0xAB_u32;
        let s2 = 0xCD_u32;
        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(1, 1, s1, s2, 0x1));
        let snapshot_len = buf.len() as u64;
        // 快照之后追加的完整帧：字节在 reader 里可读，但不得被解析。
        buf.extend(write_frame(2, 2, s1, s2, 0x2));

        let mut cursor = std::io::Cursor::new(buf);
        let (index, scan_end) = scan_wal_frames(
            &mut cursor,
            WAL_HDR_SZ as u64,
            snapshot_len,
            s1,
            s2,
            WalFrameIndex::default(),
        )
        .unwrap();
        assert_eq!(index.frames_total, 1, "快照之外的帧不得被解析");
        assert!(index.offset_for(1).is_some());
        assert!(index.offset_for(2).is_none(), "快照后追加的 pgno=2 不得进索引");
        assert_eq!(index.last_commit_pgcnt(), Some(1));
        assert_eq!(
            scan_end, snapshot_len,
            "扫描终点应停在快照边界（此处快照恰好是完整帧边界）"
        );
    }

    /// 守护语义 2（中途截断 fail-loud）：`file_len` 快照以内的字节读不满
    /// （微信 checkpoint TRUNCATE 把 -wal 截短的瞬间）必须报错让上层重试，
    /// 绝不能静默返回一个截断的索引。
    #[test]
    fn truncation_inside_len_snapshot_fails_loud() {
        let s1 = 0x11_u32;
        let s2 = 0x22_u32;
        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(1, 1, s1, s2, 0x1));
        buf.extend(write_frame(2, 2, s1, s2, 0x2));
        let claimed_len = buf.len() as u64;
        // 模拟截断：快照说有两帧，实际字节在第二帧帧头中间就断了
        // （残留 < 24 字节帧头，read_exact 必然 UnexpectedEof——这正是旧
        // 逐帧实现的报错点，缓冲实现必须原样保留）。
        buf.truncate(WAL_HDR_SZ + (WAL_FRAME_HDR + PAGE_SZ) + 10);

        let mut cursor = std::io::Cursor::new(buf);
        let err = scan_wal_frames(
            &mut cursor,
            WAL_HDR_SZ as u64,
            claimed_len,
            s1,
            s2,
            WalFrameIndex::default(),
        )
        .expect_err("快照内字节缺失必须报错，不能静默成功");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// 增量缓存核心场景：同 salt 追加帧跨两次 open 累积；无新帧时零拷贝
    /// 复用同一份 Arc 快照；同 pgno 的新帧跨增量边界覆盖旧帧。
    #[test]
    fn incremental_cache_extends_and_reuses_across_rebuilds() {
        let path = tmp_path("incremental-extend");
        let s1 = 0xAA11_u32;
        let s2 = 0xBB22_u32;
        let cache = std::sync::Mutex::new(WalIndexCache::default());

        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(7, 2, s1, s2, 0x01));
        buf.extend(write_frame(8, 2, s1, s2, 0x02));
        std::fs::write(&path, &buf).unwrap();

        let first = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert_eq!(first.index.frames_total, 2);
        assert_eq!(first.index.covered_page_count(), 2);
        let first_arc = first.index.clone();

        // 无变化的重建：必须零拷贝复用同一份快照。
        let reused = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert!(
            Arc::ptr_eq(&first_arc, &reused.index),
            "无新帧时必须复用缓存的同一份 Arc 快照"
        );

        // 同 salt 追加两帧：pgno=7 被新帧覆盖，pgno=9 新增。
        let mut appended = buf.clone();
        appended.extend(write_frame(7, 3, s1, s2, 0x03));
        appended.extend(write_frame(9, 3, s1, s2, 0x04));
        std::fs::write(&path, &appended).unwrap();

        let mut second = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert_eq!(second.index.frames_total, 4, "增量帧数应累积到旧快照之上");
        assert_eq!(second.index.covered_page_count(), 3);
        assert_eq!(second.index.last_commit_pgcnt(), Some(3));
        let off7 = second.index.offset_for(7).unwrap();
        let raw7 = second.read_raw_page(off7).unwrap();
        assert!(
            raw7.iter().all(|&b| b == 0x03),
            "pgno=7 必须指向增量边界之后的新帧"
        );
        // 旧连接持有的快照必须保持冻结，不受后续扩展影响。
        assert_eq!(first_arc.covered_page_count(), 2);
        assert!(first_arc.offset_for(9).is_none());

        // 与无缓存全量扫描对拍：内容级一致。
        let oracle = build_wal_index(&path).unwrap().unwrap();
        assert_eq!(oracle.index.covered_page_count(), 3);
        assert_eq!(oracle.index.offset_for(7), second.index.offset_for(7));
        assert_eq!(oracle.index.offset_for(8), second.index.offset_for(8));
        assert_eq!(oracle.index.offset_for(9), second.index.offset_for(9));
        assert_eq!(
            oracle.index.last_commit_pgcnt(),
            second.index.last_commit_pgcnt()
        );

        let _ = std::fs::remove_file(&path);
    }

    /// checkpoint/reset 换 salt 后：header 不匹配 ⇒ 缓存失效、全量重扫，
    /// 新索引只含新世代帧；增量续扫期间混进的新世代帧也会被 salt 过滤掉
    /// （与全量扫描的既有行为同构）。
    #[test]
    fn incremental_cache_invalidated_by_salt_change() {
        let path = tmp_path("incremental-salt-change");
        let cache = std::sync::Mutex::new(WalIndexCache::default());
        let (old_s1, old_s2) = (0x1111_u32, 0x2222_u32);
        let (new_s1, new_s2) = (0x3333_u32, 0x4444_u32);

        let mut buf = write_wal_header(old_s1, old_s2);
        buf.extend(write_frame(5, 1, old_s1, old_s2, 0x01));
        std::fs::write(&path, &buf).unwrap();
        let first = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert_eq!(first.index.frames_valid, 1);

        // reset：新 header + 旧世代残留帧 + 新世代帧（restart 的典型形态）。
        let mut reset = write_wal_header(new_s1, new_s2);
        reset.extend(write_frame(5, 0, old_s1, old_s2, 0x0A)); // 旧世代残留
        reset.extend(write_frame(6, 2, new_s1, new_s2, 0x0B));
        std::fs::write(&path, &reset).unwrap();

        let second = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert_eq!(second.index.frames_total, 2, "salt 变化必须触发全量重扫");
        assert_eq!(second.index.frames_valid, 1, "旧世代残留帧必须被过滤");
        assert!(second.index.offset_for(5).is_none());
        assert!(second.index.offset_for(6).is_some());

        let _ = std::fs::remove_file(&path);
    }

    /// 同 salt 但文件比缓存终点还短（理论上只可能是 salt 碰撞或文件被外部
    /// 篡改）：不许增量、必须全量重扫，且不得报错。
    #[test]
    fn incremental_cache_rejects_shrunk_file() {
        let path = tmp_path("incremental-shrunk");
        let cache = std::sync::Mutex::new(WalIndexCache::default());
        let (s1, s2) = (0x5A5A_u32, 0x6B6B_u32);

        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(1, 1, s1, s2, 0x01));
        buf.extend(write_frame(2, 2, s1, s2, 0x02));
        std::fs::write(&path, &buf).unwrap();
        build_wal_index_cached(&path, &cache).unwrap().unwrap();

        // 同 salt、但只剩一帧。
        buf.truncate(WAL_HDR_SZ + (WAL_FRAME_HDR + PAGE_SZ));
        std::fs::write(&path, &buf).unwrap();
        let after = build_wal_index_cached(&path, &cache).unwrap().unwrap();
        assert_eq!(after.index.frames_total, 1, "缩短的文件必须全量重扫");
        assert!(after.index.offset_for(2).is_none());

        let _ = std::fs::remove_file(&path);
    }

    /// 尾部残留半截帧（写入过程中被截断的典型形态）必须被忽略，不能 panic
    /// 或者把半截 page_data 错误地当成一整帧解析。
    #[test]
    fn trailing_partial_frame_is_ignored() {
        let path = tmp_path("trailing-partial");
        let s1 = 0x1234_5678;
        let s2 = 0x9abc_def0;
        let mut buf = write_wal_header(s1, s2);
        buf.extend(write_frame(1, 1, s1, s2, 0x7));
        buf.extend_from_slice(&[0u8; WAL_FRAME_HDR + 10]); // 不足一整帧的尾巴
        std::fs::write(&path, &buf).unwrap();

        let src = build_wal_index(&path).unwrap().unwrap();
        assert_eq!(src.index.frames_total, 1, "半截尾帧不应被计入");
        assert_eq!(src.index.frames_valid, 1);

        let _ = std::fs::remove_file(&path);
    }
}
