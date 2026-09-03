//! 函数级 oracle 对拍：`DbCache::open_conn`（VFS 按需解页）vs
//! `DbCache::get` + `Connection::open`（现有 full_decrypt 明文路径）。
//!
//! 只跑一次、需要真实微信数据 + 密钥，**不起 daemon**、不改动 `query.rs`。
//! 密钥经环境变量传入，不落盘、不进源码；只比较表名/行数/`(local_id,
//! create_time)` 这类结构化字段，绝不打印聊天正文或二进制内容。
//!
//! ```text
//! # PowerShell
//! $env:WX_MSG_KEY = "<message_0.db 的 64 位十六进制密钥>"
//! $env:WX_SESSION_KEY = "<session.db 的 64 位十六进制密钥>"
//! cargo test --release --bin wxeasy -- --ignored oracle_vfs_matches_full_decrypt
//! ```
//!
//! 默认路径指向本机真实微信数据（可用 `WX_MSG_DB` / `WX_SESSION_DB` 覆盖）：
//! - `message/message_0.db` @ `C:\Users\okooo\Documents\xwechat_files\a1206407149_c11a\db_storage`
//! - `session/session.db`   @ 同上
//!
//! 作者: okooo5km(十里)

use anyhow::{Context, Result};
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::cache::DbCache;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn open_plain(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("打开明文库失败: {:?}", path))
}

fn list_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn count_all(conn: &Connection, tables: &[String]) -> Result<BTreeMap<String, i64>> {
    let mut out = BTreeMap::new();
    for t in tables {
        let sql = format!("SELECT count(*) FROM {}", quote_ident(t));
        let cnt: i64 = conn
            .query_row(&sql, [], |row| row.get(0))
            .with_context(|| format!("count(*) 失败: {}", t))?;
        out.insert(t.clone(), cnt);
    }
    Ok(out)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let sql = format!("PRAGMA table_info({})", quote_ident(table));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?; // column 1 = name
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// message 表固定用 `local_id` / `create_time`；其它表动态探测一个"看起来
/// 像时间"的列和一个可作为行标识的列，找不到就返回 `None`。
fn pick_id_time_columns(
    conn: &Connection,
    table: &str,
    prefer_msg_style: bool,
) -> Result<Option<(String, String)>> {
    let cols = table_columns(conn, table)?;
    if prefer_msg_style
        && cols.iter().any(|c| c == "local_id")
        && cols.iter().any(|c| c == "create_time")
    {
        return Ok(Some(("local_id".to_string(), "create_time".to_string())));
    }
    let time_col = cols
        .iter()
        .find(|c| c.eq_ignore_ascii_case("create_time"))
        .or_else(|| cols.iter().find(|c| c.to_lowercase().contains("time")))
        .cloned();
    let Some(time_col) = time_col else {
        return Ok(None);
    };
    let id_col = cols
        .iter()
        .find(|c| c.eq_ignore_ascii_case("local_id"))
        .or_else(|| cols.iter().find(|c| c.to_lowercase().contains("usrname")))
        .or_else(|| cols.iter().find(|c| **c != time_col))
        .cloned()
        .unwrap_or_else(|| "rowid".to_string());
    Ok(Some((id_col, time_col)))
}

#[derive(Debug, Clone, PartialEq)]
struct IdTimeRow {
    id: String,
    time: String,
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => "NULL".to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        // 结构化字段（local_id/create_time 之类）理论上不会是 Text/Blob，但防御性地
        // 只记录长度而不是内容，避免不小心把某个奇怪 schema 下的正文字段打印出来。
        Value::Text(s) => format!("<text len={}>", s.len()),
        Value::Blob(b) => format!("<blob {}B>", b.len()),
    }
}

fn latest_rows(
    conn: &Connection,
    table: &str,
    id_col: &str,
    time_col: &str,
    limit: usize,
) -> Result<Vec<IdTimeRow>> {
    let sql = format!(
        "SELECT {}, {} FROM {} ORDER BY {} DESC LIMIT {}",
        quote_ident(id_col),
        quote_ident(time_col),
        quote_ident(table),
        quote_ident(time_col),
        limit
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        let id: Value = row.get(0)?;
        let time: Value = row.get(1)?;
        Ok(IdTimeRow {
            id: value_to_string(&id),
            time: value_to_string(&time),
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn pick_max_table(counts: &BTreeMap<String, i64>, prefix: Option<&str>) -> Option<String> {
    counts
        .iter()
        .filter(|(k, _)| prefix.map(|p| k.starts_with(p)).unwrap_or(true))
        .max_by_key(|(_, v)| **v)
        .map(|(k, _)| k.clone())
}

struct CaseSpec {
    name: &'static str,
    rel_key: &'static str,
    db_env: &'static str,
    db_default: String,
    key_env: &'static str,
    max_table_prefix: Option<&'static str>,
    prefer_msg_style_columns: bool,
}

/// 把一个真实加密库（+ 可能存在的 -wal）复制进独立的 scratch db_dir，规避与
/// 正在运行的微信客户端并发写入的竞态窗口——复制期间主库和 WAL 的相对新旧
/// 关系可能与"复制这一刻"不完全原子，但对拍双方（VFS / full_decrypt+apply_wal）
/// 之后都只读这同一份复制品，不影响"两条路径读同一份输入是否一致"这个核心断言。
fn stage_case(spec: &CaseSpec, scratch_root: &Path) -> Result<(DbCache, String)> {
    let real_db_path = PathBuf::from(env_or(spec.db_env, &spec.db_default));
    anyhow::ensure!(
        real_db_path.exists(),
        "{} 不存在: {:?}",
        spec.db_env,
        real_db_path
    );
    let key_hex = std::env::var(spec.key_env).with_context(|| {
        format!(
            "需要设置环境变量 {}（{} 的 32 字节十六进制密钥）",
            spec.key_env, spec.rel_key
        )
    })?;

    let case_dir = scratch_root.join(spec.name);
    let db_dir = case_dir.join("db_storage");
    let cache_dir = case_dir.join("cache");
    std::fs::create_dir_all(&db_dir)?;
    std::fs::create_dir_all(&cache_dir)?;

    // rel_key 形如 "message/message_0.db"，按其目录结构在 scratch db_dir 下复刻。
    let staged_db_path = db_dir.join(
        spec.rel_key
            .replace('\\', std::path::MAIN_SEPARATOR_STR)
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    if let Some(parent) = staged_db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&real_db_path, &staged_db_path)
        .with_context(|| format!("复制主库失败: {:?} -> {:?}", real_db_path, staged_db_path))?;

    let real_wal_path = {
        let mut s = real_db_path.as_os_str().to_os_string();
        s.push("-wal");
        PathBuf::from(s)
    };
    if real_wal_path.exists() {
        let mut staged_wal = staged_db_path.as_os_str().to_os_string();
        staged_wal.push("-wal");
        std::fs::copy(&real_wal_path, PathBuf::from(&staged_wal))
            .with_context(|| format!("复制 -wal 失败: {:?}", real_wal_path))?;
    }

    let mut all_keys = std::collections::HashMap::new();
    all_keys.insert(spec.rel_key.to_string(), key_hex);

    let mtime_file = cache_dir.join("_mtimes.json");
    let db = futures_lite_block_on(DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys))?;
    Ok((db, spec.rel_key.to_string()))
}

/// 本模块只在 `#[tokio::test]` 里跑（有 tokio 运行时），这里直接用
/// `Handle::current().block_on` 在同步 helper 里跑一小段 async 代码，避免把
/// `stage_case` 也写成 async fn 传染到调用方（调用方后面还要穿插同步的
/// `open_conn`/`Connection::open`，混着写反而更乱）。
fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

/// 核心对拍：
/// (a) `db.open_conn(rel_key)`（VFS 按需解页）
/// (b) `db.get(rel_key)` + `Connection::open`（现有 full_decrypt 明文路径）
/// 两条路径查同样的 `SELECT name FROM sqlite_master ...` + 目标表 count(*) +
/// 最新 20 条 `(id, time)`，逐项断言一致；并报告 VFS 按需解密的字节数占比。
fn run_oracle_case(spec: &CaseSpec, scratch_root: &Path) -> Result<()> {
    let (db, rel_key) = stage_case(spec, scratch_root)?;

    // ---- (a) VFS 路径：DbCache::open_conn，模拟 query.rs 里
    //          `tokio::task::spawn_blocking` 驱动同步 rusqlite 查询的方式。
    let (vfs_tables, vfs_counts, vfs_stats) = {
        let (conn, stats) = db
            .open_conn_with_stats(&rel_key)
            .with_context(|| format!("open_conn_with_stats 失败: {}", rel_key))?;
        let tables = list_tables(&conn)?;
        let counts = count_all(&conn, &tables)?;
        let snap = stats.lock().unwrap().clone();
        (tables, counts, snap)
    };

    // ---- (b) oracle 路径：现有 get() + Connection::open(明文)，逐字对齐
    //          query.rs 里 ~25 处查询点的既有调用模式。
    let oracle_path = futures_lite_block_on(db.get(&rel_key))?
        .with_context(|| format!("db.get({}) 未返回路径（密钥缺失或源文件不存在）", rel_key))?;
    let oracle_conn = open_plain(&oracle_path)?;
    let oracle_tables = list_tables(&oracle_conn)?;
    let oracle_counts = count_all(&oracle_conn, &oracle_tables)?;

    assert_eq!(
        vfs_tables, oracle_tables,
        "[{}] 表名列表不一致: vfs={:?} oracle={:?}",
        spec.name, vfs_tables, oracle_tables
    );
    assert_eq!(
        vfs_counts, oracle_counts,
        "[{}] 各表 count(*) 不一致",
        spec.name
    );

    // ---- 最新 20 条 (id, time) 对拍，目标表用行数最大的表（message_0.db 限定
    //      Msg_ 前缀，session.db 不限定）。
    let max_table = pick_max_table(&oracle_counts, spec.max_table_prefix)
        .with_context(|| format!("[{}] 没有可用的表做 latest-N 对拍", spec.name))?;
    let (id_col, time_col) =
        pick_id_time_columns(&oracle_conn, &max_table, spec.prefer_msg_style_columns)?
            .with_context(|| format!("[{}] 表 {} 找不到可用的时间/标识列", spec.name, max_table))?;

    let limit = 20usize;
    let oracle_rows = latest_rows(&oracle_conn, &max_table, &id_col, &time_col, limit)?;

    let vfs_rows = {
        let (conn2, _stats2) = db.open_conn_with_stats(&rel_key)?;
        latest_rows(&conn2, &max_table, &id_col, &time_col, limit)?
    };

    assert_eq!(
        vfs_rows, oracle_rows,
        "[{}] 表 {} 最新 {} 条 ({}, {}) 不一致",
        spec.name, max_table, limit, id_col, time_col
    );

    let file_size = std::fs::metadata(&oracle_path)
        .map(|m| m.len())
        .unwrap_or(0)
        .max(1);
    let ratio_pct = (vfs_stats.distinct_bytes() as f64) / (file_size as f64) * 100.0;
    eprintln!(
        "[oracle:{}] tables_match=true counts_match=true latest{}_match=true \
         vfs_distinct_pages={} (wal={}, main={}) vfs_distinct_bytes={} oracle_plain_size={} ratio={:.4}%",
        spec.name,
        limit,
        vfs_stats.distinct_pages(),
        vfs_stats.pages_from_wal.len(),
        vfs_stats.pages_from_main.len(),
        vfs_stats.distinct_bytes(),
        file_size,
        ratio_pct
    );
    assert!(
        ratio_pct < 50.0,
        "[{}] VFS 按需解密比例过高({:.2}%)，怀疑退化成了全量解密",
        spec.name,
        ratio_pct
    );

    Ok(())
}

fn default_scratch_root() -> PathBuf {
    PathBuf::from(env_or(
        "WX_VFS_ORACLE_SCRATCH",
        r"C:\Users\okooo\AppData\Local\Temp\claude\C--Users-okooo-Desktop-PriceKeeper\a35c54b4-eab0-4bd6-877a-362e3d91bc88\scratchpad\wxeasy-vfs-oracle-run",
    ))
}

/// `message/message_0.db`：VFS 合并视图必须与 `full_decrypt`（+ `apply_wal`）
/// 逐项一致——表名、count(*)、最新 20 条 `(local_id, create_time)`。
///
/// 需要真实数据 + 密钥，默认 `#[ignore]`；手动运行：
/// `cargo test --release --bin wxeasy -- --ignored oracle_message_0_open_conn_matches_full_decrypt`
///
/// 用 `flavor = "multi_thread"`：内部 `run_oracle_case` 需要用
/// `tokio::task::block_in_place` 把 `DbCache::get()`（async）桥接回同步调用链
/// （便于和同步的 `open_conn`/`Connection::open` 穿插调用），而 `block_in_place`
/// 只在多线程运行时下可用，单线程 `#[tokio::test]` 默认 flavor 会直接 panic。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要真实微信数据 + WX_MSG_KEY 环境变量，CI 默认不跑"]
async fn oracle_message_0_open_conn_matches_full_decrypt() {
    let spec = CaseSpec {
        name: "message_0",
        rel_key: "message/message_0.db",
        db_env: "WX_MSG_DB",
        db_default: r"C:\Users\okooo\Documents\xwechat_files\a1206407149_c11a\db_storage\message\message_0.db"
            .to_string(),
        key_env: "WX_MSG_KEY",
        max_table_prefix: Some("Msg_"),
        prefer_msg_style_columns: true,
    };
    let scratch_root = default_scratch_root();
    std::fs::create_dir_all(&scratch_root).unwrap();
    run_oracle_case(&spec, &scratch_root).expect("oracle 对拍失败");
}

/// 活体 WAL 集成级验证（临时诊断测试，验证完成后应移除）：直接对一份
/// **未 checkpoint 过、真实 SQLCipher 产出的活体 `-wal`**（含 pgno==1 帧，因为
/// `CREATE TABLE` 必然改写 schema 所在的第 1 页）跑迁移后的集成路径
/// `DbCache::conn_params(rel_key)?.open()`——这正是 `query.rs` 里 ~25 处查询点
/// 实际使用的调用序列，不是孤立调用 `wxvfs-core`/`vfs.rs` 的白盒单测。
///
/// 素材由 `scratchpad/livewal/make_live_wal.py` 用 `sqlcipher3`（真实 SQLCipher，
/// 非本项目自研解密）在真实 `message_0.db` 的副本上开 WAL 模式、关闭
/// autocheckpoint、跑两轮 `CREATE TABLE` + `INSERT` + `commit()`，然后
/// `os._exit(0)` 硬退出（不调用 `close()`，避免触发"最后一个连接关闭时自动
/// checkpoint"抹掉这些帧）冻结出来的。
///
/// 断言：
/// 1. 通过 VFS 打开后能看到新建的 `wxvfs_livewal_test` 表（证明 WAL 里的
///    schema 变更—— pgno=1 帧——被正确合并进视图，而不是仍停留在 checkpoint
///    前的旧 schema）；
/// 2. 该表 `count(*)` 与 sqlcipher3 写入时的真实行数（120）一致；
/// 3. 原有的真实微信表（如 `Name2Id`）在合并 WAL 后依然可查，证明 WAL 合并
///    没有破坏无关页面。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 scratchpad/livewal/message_0.db(+wal) 活体快照 + WX_MSG_KEY 环境变量，CI 默认不跑"]
async fn live_wal_create_table_visible_through_migrated_conn_params_path() {
    let key_hex = std::env::var("WX_MSG_KEY").expect("需要设置 WX_MSG_KEY");
    let live_dir = PathBuf::from(env_or(
        "WX_LIVEWAL_DIR",
        r"C:\Users\okooo\AppData\Local\Temp\claude\C--Users-okooo-Desktop-PriceKeeper\a35c54b4-eab0-4bd6-877a-362e3d91bc88\scratchpad\livewal",
    ));
    let live_db = live_dir.join("message_0.db");
    let live_wal = live_dir.join("message_0.db-wal");
    assert!(live_db.exists(), "活体快照主库不存在: {:?}", live_db);
    assert!(
        live_wal.exists(),
        "活体快照 -wal 不存在（未 checkpoint 的活体帧）: {:?}",
        live_wal
    );

    // 按生产 db_dir 布局重新拼一份 rel_key 结构（rel_key = "message/message_0.db"），
    // 这样 `DbCache::conn_params` 走的是和 query.rs 完全一致的路径拼接逻辑。
    let scratch_root = default_scratch_root().join("livewal-integration");
    let db_dir = scratch_root.join("db_storage");
    let rel_key = "message/message_0.db";
    let staged_db = db_dir.join("message").join("message_0.db");
    let staged_wal = db_dir.join("message").join("message_0.db-wal");
    std::fs::create_dir_all(staged_db.parent().unwrap()).unwrap();
    std::fs::copy(&live_db, &staged_db).expect("复制活体主库失败");
    std::fs::copy(&live_wal, &staged_wal).expect("复制活体 -wal 失败");

    let cache_dir = scratch_root.join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let mtime_file = cache_dir.join("_mtimes.json");
    let mut all_keys = std::collections::HashMap::new();
    all_keys.insert(rel_key.to_string(), key_hex);
    let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
        .await
        .expect("DbCache::with_dirs 失败");

    // 这就是 query.rs 迁移后真正使用的调用序列：async 上下文里同步拿
    // ConnParams，move 进 spawn_blocking，闭包内部 `.open()` 建连接、查询、销毁。
    let conn_params = db
        .conn_params(rel_key)
        .expect("conn_params 应成功解析（key/文件都存在）");
    let (table_exists, live_count, name2id_count): (bool, i64, i64) =
        tokio::task::spawn_blocking(move || {
            let conn = conn_params
                .open()
                .expect("迁移后集成路径打开活体 WAL 快照失败（NOTADB？）");

            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='wxvfs_livewal_test'",
                    [],
                    |row| row.get(0),
                )
                .ok()
                .flatten();

            let cnt: i64 = conn
                .query_row("SELECT count(*) FROM wxvfs_livewal_test", [], |row| {
                    row.get(0)
                })
                .expect("查询活体表 count(*) 失败");

            // 原有真实微信表在 WAL 合并后必须仍可正常查询，证明合并没有破坏无关页面。
            let name2id_cnt: i64 = conn
                .query_row("SELECT count(*) FROM Name2Id", [], |row| row.get(0))
                .expect("查询原有 Name2Id 表失败——WAL 合并可能破坏了无关表");

            (exists.is_some(), cnt, name2id_cnt)
        })
        .await
        .expect("spawn_blocking join 失败");

    assert!(
        table_exists,
        "活体 WAL 里 CREATE TABLE（改写 pgno=1 schema 页）没有被合并进视图——\
         迁移后的集成路径可能仍停留在 checkpoint 前的旧 schema"
    );
    assert_eq!(
        live_count, 120,
        "活体表行数应与 sqlcipher3 写入时的真实行数(120)一致"
    );
    eprintln!(
        "[live-wal-integration] table_exists={} live_count={} name2id_count={} (原表仍可查询，证明合并未破坏无关页面)",
        table_exists, live_count, name2id_count
    );
}

/// `session/session.db` 同理（不限定表前缀、动态探测时间/标识列）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要真实微信数据 + WX_SESSION_KEY 环境变量，CI 默认不跑"]
async fn oracle_session_open_conn_matches_full_decrypt() {
    let spec = CaseSpec {
        name: "session",
        rel_key: "session/session.db",
        db_env: "WX_SESSION_DB",
        db_default:
            r"C:\Users\okooo\Documents\xwechat_files\a1206407149_c11a\db_storage\session\session.db"
                .to_string(),
        key_env: "WX_SESSION_KEY",
        max_table_prefix: None,
        prefer_msg_style_columns: false,
    };
    let scratch_root = default_scratch_root();
    std::fs::create_dir_all(&scratch_root).unwrap();
    run_oracle_case(&spec, &scratch_root).expect("oracle 对拍失败");
}
