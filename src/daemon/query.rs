use anyhow::{Context, Result};
use chrono::{Local, TimeZone, Timelike};
use regex::Regex;
use roxmltree::{Document, Node};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use super::cache::{DbCache, ShardRouteLookup, SourceSnapshot};
use super::meta::{derive_status, discover_unknown_shards, Meta};

/// `cache_mode_per_shard` / debug 输出里统一填的占位值：VFS 按需解页下不再有
/// `cache_hit` / `wal_incremental` / `full_decrypt` 这种分级概念（每次查询都是
/// 同一条"按需解页"路径），但保留这个 JSON 字段本身（不删字段、只改语义），
/// 避免下游消费者（CLI --debug-source / 监控队列页）解析时突然缺字段。
const VFS_CACHE_MODE_LABEL: &str = "vfs";

/// 静态编译的 Msg 表名正则，避免在热路径中重复编译
fn msg_table_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^Msg_[0-9a-f]{32}$").unwrap())
}

/// 判定会话类型。返回值固定为 `group` / `official_account` / `folded` / `private` 之一。
///
/// 判据次序：
/// 1. `@chatroom` / 折叠入口特殊 username
/// 2. `contact.verify_flag` 非 0 —— 覆盖所有被微信官方打了认证标的账号，
///    包括 username 为 `wxid_*` 但实为公众号的情况（如"人物"），
///    以及品牌服务号 `cmb4008205555`、系统号 `qqsafe` / `mphelper` 等
/// 3. username 前缀兜底（`gh_*` / `biz_*` / `@*` 等）—— 在 contact 表未加载或没记录时
///    仍能给出正确结果
pub fn chat_type_of(username: &str, names: &Names) -> &'static str {
    if username.contains("@chatroom") {
        return "group";
    }
    if username == "brandsessionholder" || username == "@placeholder_foldgroup" {
        return "folded";
    }
    if names.is_verified(username) {
        return "official_account";
    }
    if username.starts_with("gh_") || username.starts_with("biz_") {
        return "official_account";
    }
    // `@` 开头的剩余 username（如 `@opencustomerservicemsg`）是微信内部系统账号，
    // 通常不落在 contact 表里，verify_flag 兜不住，按前缀兜底。
    if username.starts_with('@') {
        return "official_account";
    }
    "private"
}

/// 联系人名称缓存
#[derive(Clone)]
pub struct Names {
    /// username -> display_name
    pub map: HashMap<String, String>,
    /// md5(username) -> username（用于从 Msg_<md5> 表名反推联系人）
    pub md5_to_uname: HashMap<String, String>,
    /// 消息 DB 的相对路径列表（message/message_N.db）
    pub msg_db_keys: Vec<String>,
    /// username -> contact.verify_flag（0=真人，非 0 通常为公众号/服务号/认证账号）
    pub verify_flags: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct MessageShard {
    rel_key: String,
    /// 加密库的真实物理路径。VFS 下不再有"解密产物路径"这个概念——这里存的
    /// 是密文文件本身，**只用于 debug_source 诊断展示**；实际查询一律经
    /// `rel_key` 重新调用 `DbCache::conn_params` 解析（进 `spawn_blocking`
    /// 前拿到 Send+'static 的 `ConnParams`，闭包内部再 `.open()`）。
    path: std::path::PathBuf,
    table: String,
    max_ts: i64,
}

impl Names {
    pub fn display(&self, username: &str) -> String {
        self.map
            .get(username)
            .cloned()
            .unwrap_or_else(|| username.to_string())
    }

    /// 是否被微信官方标了认证/服务号 flag。未在 contact 表中的 username 返回 false。
    pub fn is_verified(&self, username: &str) -> bool {
        self.verify_flags.get(username).copied().unwrap_or(0) != 0
    }
}

fn current_unknown_shards(db: &DbCache, names: &Names) -> Vec<String> {
    discover_unknown_shards(db.db_dir(), &names.msg_db_keys)
}

fn meta_for_shards(
    scanned: usize,
    shards: &[MessageShard],
    shard_hits: usize,
    unknown_shards: Vec<String>,
    session_last_timestamp: Option<i64>,
    windowed: bool,
    with_meta: bool,
    debug_source: bool,
) -> Meta {
    let latest = shards.first();
    let chat_latest_timestamp = latest.map(|s| s.max_ts);
    Meta {
        chat_latest_timestamp,
        chat_latest_db: latest.map(|s| s.rel_key.clone()),
        session_last_timestamp,
        shards_scanned: scanned,
        shards_hit: shard_hits,
        unknown_shards: unknown_shards.clone(),
        status: derive_status(
            chat_latest_timestamp,
            session_last_timestamp,
            &unknown_shards,
            windowed,
        ),
        per_shard_latest: if with_meta || debug_source {
            Some(
                shards
                    .iter()
                    .map(|s| (s.rel_key.clone(), s.max_ts))
                    .collect(),
            )
        } else {
            None
        },
        cache_mode_per_shard: if with_meta || debug_source {
            Some(
                shards
                    .iter()
                    .map(|s| (s.rel_key.clone(), VFS_CACHE_MODE_LABEL.to_string()))
                    .collect(),
            )
        } else {
            None
        },
        shard_paths: if debug_source {
            Some(
                shards
                    .iter()
                    .map(|s| (s.rel_key.clone(), s.path.to_string_lossy().into_owned()))
                    .collect(),
            )
        } else {
            None
        },
    }
}

fn meta_for_global_query(
    scanned: usize,
    hit: usize,
    unknown_shards: Vec<String>,
    windowed: bool,
    with_meta: bool,
    debug_source: bool,
    cache_modes: Option<HashMap<String, String>>,
    shard_paths: Option<HashMap<String, String>>,
) -> Meta {
    Meta {
        chat_latest_timestamp: None,
        chat_latest_db: None,
        session_last_timestamp: None,
        shards_scanned: scanned,
        shards_hit: hit,
        unknown_shards: unknown_shards.clone(),
        status: derive_status(None, None, &unknown_shards, windowed),
        per_shard_latest: if with_meta || debug_source {
            Some(HashMap::new())
        } else {
            None
        },
        cache_mode_per_shard: if with_meta || debug_source {
            cache_modes
        } else {
            None
        },
        shard_paths: if debug_source { shard_paths } else { None },
    }
}

async fn session_last_timestamp(db: &DbCache, username: &str) -> Option<i64> {
    let conn_params = match db.conn_params("session/session.db") {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[freshness] skip session_last_timestamp {}: {}",
                username, e
            );
            return None;
        }
    };

    let username = username.to_string();
    let username_for_query = username.clone();
    match tokio::task::spawn_blocking(move || -> Result<Option<i64>> {
        let conn = conn_params.open()?;
        let ts = conn
            .query_row(
                "SELECT last_timestamp FROM SessionTable WHERE username = ?",
                [&username_for_query],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        Ok(ts)
    })
    .await
    {
        Ok(Ok(ts)) => ts,
        Ok(Err(e)) => {
            eprintln!(
                "[freshness] skip session_last_timestamp {}: {}",
                username, e
            );
            None
        }
        Err(e) => {
            eprintln!(
                "[freshness] task error session_last_timestamp {}: {}",
                username, e
            );
            None
        }
    }
}

/// 加载联系人缓存（从 contact/contact.db）
pub async fn load_names(db: &DbCache) -> Result<Names> {
    let mut map = HashMap::new();
    let mut verify_flags: HashMap<String, i64> = HashMap::new();
    // 密钥缺失 / contact.db 不存在时，与旧版 `db.get(..)` 返回 `None` 语义一致：
    // 静默产出空联系人表，不当作错误往上抛。
    if let Ok(conn_params) = db.conn_params("contact/contact.db") {
        // FIX 4：daemon 启动阶段的 stderr 输出到这里之后会有一段静默——
        // `contact.db` 在机械盘上可能是几十万行的全表扫描，没有任何输出会
        // 让人误以为卡死（今日已实测撞到一次慢机场景）。改成手动逐行迭代
        // （而不是 `query_map(..).collect()` 一次性拿全部结果），每
        // `PROGRESS_LOG_EVERY_ROWS` 行打一条阶段性进度日志——纯诊断用途，
        // 不影响解析出的联系人数据本身。
        const PROGRESS_LOG_EVERY_ROWS: u64 = 20_000;
        let rows: Vec<(String, String, String, i64)> = tokio::task::spawn_blocking(move || {
            let conn = conn_params.open().context("打开 contact.db 失败")?;
            let mut stmt =
                conn.prepare("SELECT username, nick_name, remark, verify_flag FROM contact")?;
            let mut rows = Vec::new();
            let mut scanned = 0u64;
            let mut rows_iter = stmt.query([])?;
            while let Some(row) = rows_iter.next()? {
                rows.push((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, String>(2).unwrap_or_default(),
                    row.get::<_, i64>(3).unwrap_or(0),
                ));
                scanned += 1;
                if scanned % PROGRESS_LOG_EVERY_ROWS == 0 {
                    eprintln!("[names] 联系人加载中... 已扫描 {} 行", scanned);
                }
            }
            Ok::<_, anyhow::Error>(rows)
        })
        .await??;

        for (uname, nick, remark, vf) in rows {
            let display = if !remark.is_empty() {
                remark
            } else if !nick.is_empty() {
                nick
            } else {
                uname.clone()
            };
            verify_flags.insert(uname.clone(), vf);
            map.insert(uname, display);
        }
    }

    let md5_to_uname: HashMap<String, String> = map
        .keys()
        .map(|u| (format!("{:x}", md5::compute(u.as_bytes())), u.clone()))
        .collect();

    Ok(Names {
        map,
        md5_to_uname,
        msg_db_keys: Vec::new(),
        verify_flags,
    })
}

/// 查询最近会话列表
pub async fn q_sessions(
    db: &DbCache,
    names: &Names,
    limit: usize,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    let conn_params = db
        .conn_params("session/session.db")
        .context("无法解密 session.db")?;

    let limit_val = limit;
    let rows: Vec<(String, i64, Vec<u8>, i64, i64, String, String)> =
        tokio::task::spawn_blocking(move || {
            let conn = conn_params.open()?;
            let mut stmt = conn.prepare(
                "SELECT username, unread_count, summary, last_timestamp,
                    last_msg_type, last_msg_sender, last_sender_display_name
             FROM SessionTable
             WHERE last_timestamp > 0
             ORDER BY last_timestamp DESC LIMIT ?",
            )?;
            let rows = stmt
                .query_map([limit_val as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1).unwrap_or(0),
                        get_content_bytes(row, 2),
                        row.get::<_, i64>(3).unwrap_or(0),
                        row.get::<_, i64>(4).unwrap_or(0),
                        row.get::<_, String>(5).unwrap_or_default(),
                        row.get::<_, String>(6).unwrap_or_default(),
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(rows)
        })
        .await??;

    let mut results = Vec::new();
    let mut group_nickname_cache: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (username, unread, summary_bytes, ts, msg_type, sender, sender_name) in rows {
        let display = names.display(&username);
        let chat_type = chat_type_of(&username, names);
        let is_group = chat_type == "group";

        // 尝试 zstd 解压 summary
        let summary = decompress_or_str(&summary_bytes);
        let summary = strip_group_prefix(&summary);

        let sender_display = if is_group && !sender.is_empty() {
            if !group_nickname_cache.contains_key(&username) {
                let nicknames = load_group_nicknames(db, &username)
                    .await
                    .unwrap_or_default();
                group_nickname_cache.insert(username.clone(), nicknames);
            }
            let empty = HashMap::new();
            let group_nicknames = group_nickname_cache.get(&username).unwrap_or(&empty);
            sender_display(&sender, &sender_name, &names.map, group_nicknames)
        } else {
            String::new()
        };

        results.push(json!({
            "chat": display,
            "username": username,
            "is_group": is_group,
            "chat_type": chat_type,
            "unread": unread,
            "last_msg_type": fmt_type(msg_type),
            "last_sender": sender_display,
            "summary": summary,
            "timestamp": ts,
            "time": fmt_time(ts, "%m-%d %H:%M"),
        }));
    }
    let latest_ts = results
        .first()
        .and_then(|v| v.get("timestamp"))
        .and_then(|v| v.as_i64());
    let unknown_shards = current_unknown_shards(db, names);
    let meta = Meta {
        chat_latest_timestamp: latest_ts,
        chat_latest_db: latest_ts.map(|_| "session/session.db".to_string()),
        session_last_timestamp: None,
        shards_scanned: 0,
        shards_hit: 0,
        unknown_shards: unknown_shards.clone(),
        status: derive_status(latest_ts, None, &unknown_shards, false),
        per_shard_latest: if with_meta || debug_source {
            Some(HashMap::new())
        } else {
            None
        },
        cache_mode_per_shard: None,
        shard_paths: None,
    };
    Ok(json!({ "sessions": results, "meta": meta }))
}

/// 查询聊天记录
pub async fn q_history(
    db: &DbCache,
    names: &Names,
    chat: &str,
    limit: usize,
    offset: usize,
    since: Option<i64>,
    until: Option<i64>,
    msg_type: Option<i64>,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    let username =
        resolve_username(chat, names).with_context(|| format!("找不到联系人: {}", chat))?;
    let display = names.display(&username);
    let chat_type = chat_type_of(&username, names);
    let is_group = chat_type == "group";

    let (shards, scanned, skipped) = find_msg_shards(db, names, &username, since).await?;
    if shards.is_empty() {
        if skipped > 0 {
            // 空结果是因为所有分片都被 since 窗口的 mtime 判定跳过了（不可能含新消息），
            // 不是"找不到消息记录"。调用方（PriceKeeper 微信监控）把 bail 错误当作
            // daemon/缓存异常信号触发重启恢复流程；安静群每个检查周期都会命中这个分支，
            // 必须返回正常的空结果而不是报错。
            let unknown_shards = current_unknown_shards(db, names);
            let session_ts = session_last_timestamp(db, &username).await;
            let meta = meta_for_shards(
                scanned,
                &shards,
                0,
                unknown_shards,
                session_ts,
                true,
                with_meta,
                debug_source,
            );
            return Ok(json!({
                "chat": display,
                "username": username,
                "is_group": is_group,
                "chat_type": chat_type,
                "count": 0,
                "messages": [],
                "meta": meta,
            }));
        }
        anyhow::bail!("找不到 {} 的消息记录", display);
    }

    let mut all_msgs: Vec<Value> = Vec::new();
    let mut shard_hits = 0usize;
    let group_nicknames = if is_group {
        load_group_nicknames(db, &username)
            .await
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    for shard in &shards {
        let hot = db.hot_conn_handle(&shard.rel_key)?;
        let tname = shard.table.clone();
        let uname = username.clone();
        let is_group2 = is_group;
        let names_map = names.map.clone();
        let group_nicknames2 = group_nicknames.clone();
        let since2 = since;
        let until2 = until;
        let limit2 = limit;
        let offset2 = offset;

        let msgs: Vec<Value> = tokio::task::spawn_blocking(move || {
            hot.with(|conn| {
                // per-DB 软上限：offset + limit 已足够全局分页，避免大群全量加载
                let per_db_cap = offset2 + limit2;
                query_messages(
                    conn,
                    &tname,
                    &uname,
                    is_group2,
                    &names_map,
                    &group_nicknames2,
                    since2,
                    until2,
                    msg_type,
                    per_db_cap,
                    0,
                )
            })
        })
        .await??;

        if !msgs.is_empty() {
            shard_hits += 1;
        }
        all_msgs.extend(msgs);
    }

    all_msgs.sort_by_key(|m| std::cmp::Reverse(m["timestamp"].as_i64().unwrap_or(0)));
    let paged: Vec<Value> = all_msgs.into_iter().skip(offset).take(limit).collect();
    let mut paged = paged;
    paged.sort_by_key(|m| m["timestamp"].as_i64().unwrap_or(0));
    let windowed = offset > 0 || since.is_some() || until.is_some() || msg_type.is_some();
    let unknown_shards = current_unknown_shards(db, names);
    let session_ts = session_last_timestamp(db, &username).await;
    let meta = meta_for_shards(
        scanned,
        &shards,
        shard_hits,
        unknown_shards,
        session_ts,
        windowed,
        with_meta,
        debug_source,
    );

    Ok(json!({
        "chat": display,
        "username": username,
        "is_group": is_group,
        "chat_type": chat_type,
        "count": paged.len(),
        "messages": paged,
        "meta": meta,
    }))
}

/// 搜索消息
pub async fn q_search(
    db: &DbCache,
    names: &Names,
    keyword: &str,
    chats: Option<Vec<String>>,
    limit: usize,
    since: Option<i64>,
    until: Option<i64>,
    msg_type: Option<i64>,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    let mut targets: Vec<(String, String, String, String)> = Vec::new(); // (rel_key, table, display, uname)
    let mut scanned_rel_keys: HashSet<String> = HashSet::new();
    let mut cache_modes: HashMap<String, String> = HashMap::new();
    let mut shard_paths: HashMap<String, String> = HashMap::new();

    if let Some(chat_names) = chats {
        for chat_name in &chat_names {
            if let Some(uname) = resolve_username(chat_name, names) {
                let (shards, _, _) = find_msg_shards(db, names, &uname, None).await?;
                for shard in shards {
                    scanned_rel_keys.insert(shard.rel_key.clone());
                    cache_modes.insert(shard.rel_key.clone(), VFS_CACHE_MODE_LABEL.to_string());
                    shard_paths.insert(
                        shard.rel_key.clone(),
                        shard.path.to_string_lossy().into_owned(),
                    );
                    targets.push((shard.rel_key, shard.table, names.display(&uname), uname.clone()));
                }
            }
        }
    } else {
        // 全局搜索：遍历所有消息 DB
        for rel_key in &names.msg_db_keys {
            let conn_params = match db.conn_params(rel_key) {
                Ok(p) => p,
                Err(_) => continue,
            };
            scanned_rel_keys.insert(rel_key.clone());
            cache_modes.insert(rel_key.clone(), VFS_CACHE_MODE_LABEL.to_string());
            shard_paths.insert(
                rel_key.clone(),
                conn_params.enc_db_path().to_string_lossy().into_owned(),
            );
            let md5_lookup = names.md5_to_uname.clone();
            let names_map = names.map.clone();
            let rel_key2 = rel_key.clone();

            let table_targets: Vec<(String, String, String, String)> =
                match tokio::task::spawn_blocking(move || {
                    let conn = conn_params.open()?;
                    let mut stmt = conn.prepare(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'",
                    )?;
                    let table_names: Vec<String> = stmt
                        .query_map([], |row| row.get(0))?
                        .filter_map(|r| r.ok())
                        .collect();

                    let re = msg_table_re();
                    let mut result = Vec::new();
                    for tname in table_names {
                        if !re.is_match(&tname) {
                            continue;
                        }
                        let hash = &tname[4..];
                        let uname = md5_lookup.get(hash).cloned().unwrap_or_default();
                        let display = if uname.is_empty() {
                            String::new()
                        } else {
                            names_map
                                .get(&uname)
                                .cloned()
                                .unwrap_or_else(|| uname.clone())
                        };
                        result.push((rel_key2.clone(), tname, display, uname));
                    }
                    Ok::<_, anyhow::Error>(result)
                })
                .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        eprintln!("[search] skip DB {}: {}", rel_key, e);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[search] task error {}: {}", rel_key, e);
                        continue;
                    }
                };

            targets.extend(table_targets);
        }
    }

    // 按 rel_key 分组（VFS 下没有"解密产物路径"这个身份可用来分组去重了——
    // 一个 rel_key 天然对应一个物理加密库、一次 `conn_params`/`open_conn`）。
    let mut by_rel_key: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    for (rel_key, t, d, u) in targets {
        by_rel_key.entry(rel_key).or_default().push((t, d, u));
    }

    let mut group_usernames = HashSet::new();
    for table_list in by_rel_key.values() {
        for (_, _, uname) in table_list {
            if uname.contains("@chatroom") {
                group_usernames.insert(uname.clone());
            }
        }
    }
    let group_nicknames_by_chat = load_group_nickname_maps(db, group_usernames)
        .await
        .unwrap_or_default();
    let group_nicknames_by_chat = Arc::new(group_nicknames_by_chat);

    // 多个 message_*.db 之间没有数据依赖，并发解密 + 查询。每个 DB 内部仍按
    // table 串行（共享同一 sqlite Connection 不能跨线程移动）。原版本是 N 个 DB
    // 串行 await，活跃账号上 N 个分片要轮 N 次磁盘 IO；现在 JoinSet 把它们一次
    // 全部 dispatch 到 blocking pool，整体 latency 退化为单 DB 慢路径。
    let kw = keyword.to_string();
    let mut join_set: tokio::task::JoinSet<Result<(String, Vec<Value>)>> =
        tokio::task::JoinSet::new();
    // 并发上限见 `MAX_CONCURRENT_SHARD_SCANS` 文档：全局搜索（不带 `chats`
    // 过滤）会对 `names.msg_db_keys` 里的每个分片各 dispatch 一次，与
    // `find_msg_shards` 冷启动同属"对分片无差别并发派发"的形状，同样的机械
    // 盘寻道风暴风险，复用同一个常量、同一套限流 helper。
    let scan_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHARD_SCANS));
    for (rel_key, table_list) in by_rel_key {
        // FIX 4：具名 chat 分支的 `rel_key` 来自 `find_msg_shards`，已经用
        // `hot_conn_handle_with_snapshot` 开过（或复用过）一次热连接；全局
        // 扫描分支的 `rel_key` 虽然还没有热连接（前面列表名时是直接
        // `conn_params.open()` 的独立一次性打开），但改用 `hot_conn_handle`
        // 也完全兼容——miss 时照常现开一个，还能顺便把这次打开的连接留进
        // 热连接池供后续查询复用。两个分支统一走这条路径，消除具名 chat
        // 分支原本"已经开过热连接又 `conn_params.open()` 二次打开"的浪费。
        let hot = match db.hot_conn_handle(&rel_key) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[search] skip DB {}: {}", rel_key, e);
                continue;
            }
        };
        let kw2 = kw.clone();
        let since2 = since;
        let until2 = until;
        let limit2 = limit * 3;
        let names_map2 = names.map.clone();
        let group_nicknames_by_chat2 = Arc::clone(&group_nicknames_by_chat);
        let rel_key_for_log = rel_key.clone();

        spawn_shard_scan(&mut join_set, &scan_semaphore, move || {
            hot.with(|conn| {
            let mut all = Vec::new();
            let empty_group_nicknames = HashMap::new();
            for (tname, display, uname) in &table_list {
                let is_group = uname.contains("@chatroom");
                let group_nicknames = group_nicknames_by_chat2
                    .get(uname)
                    .unwrap_or(&empty_group_nicknames);
                match search_in_table(
                    conn,
                    tname,
                    &uname,
                    is_group,
                    &names_map2,
                    group_nicknames,
                    &kw2,
                    since2,
                    until2,
                    msg_type,
                    limit2,
                ) {
                    Ok(rows) => {
                        for mut row in rows {
                            if row
                                .get("chat")
                                .map(|v| v.as_str().unwrap_or(""))
                                .unwrap_or("")
                                .is_empty()
                            {
                                if let Some(obj) = row.as_object_mut() {
                                    obj.insert(
                                        "chat".into(),
                                        serde_json::Value::String(if display.is_empty() {
                                            tname.clone()
                                        } else {
                                            display.clone()
                                        }),
                                    );
                                }
                            }
                            all.push(row);
                        }
                    }
                    Err(e) => eprintln!(
                        "[search] skip table {} (rel_key={}): {}",
                        tname, rel_key_for_log, e
                    ),
                }
            }
            Ok((rel_key_for_log, all))
            })
        });
    }

    let mut results: Vec<Value> = Vec::new();
    let mut hit_rel_keys: HashSet<String> = HashSet::new();
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok((rel_key, rows))) => {
                if !rows.is_empty() {
                    hit_rel_keys.insert(rel_key);
                }
                results.extend(rows)
            }
            Ok(Err(e)) => eprintln!("[search] skip DB: {}", e),
            Err(e) => eprintln!("[search] task error: {}", e),
        }
    }

    results.sort_by_key(|r| std::cmp::Reverse(r["timestamp"].as_i64().unwrap_or(0)));
    let paged: Vec<Value> = results.into_iter().take(limit).collect();
    let unknown_shards = current_unknown_shards(db, names);
    // 全局搜索 / keyword 过滤天然是窗口化结果，没有稳定的 chat-level latest baseline，
    // 不参与 stale 推导；这里只保留 unknown_shards 这类 daemon 全局健康信号。
    let meta = meta_for_global_query(
        scanned_rel_keys.len(),
        hit_rel_keys.len(),
        unknown_shards,
        true,
        with_meta,
        debug_source,
        Some(cache_modes),
        Some(shard_paths),
    );
    Ok(json!({ "keyword": keyword, "count": paged.len(), "results": paged, "meta": meta }))
}

/// 查询联系人
///
/// 只返回真实联系人（`chat_type_of == "private"`）。`names.map` 是从 `contact` 表
/// 全量加载的，里面同时包含群（`@chatroom`）、公众号（`gh_*` / `biz_*` / verify_flag != 0）、
/// 折叠入口（`brandsessionholder` / `@placeholder_foldgroup`）以及微信内部 `@xxx` 系统账号。
/// 这些都不应该出现在 `wxeasy contacts` 输出里，统一走 `chat_type_of` 这条同样的真相判定。
pub async fn q_contacts(names: &Names, query: Option<&str>, limit: usize) -> Result<Value> {
    let mut contacts: Vec<Value> = names
        .map
        .iter()
        .filter(|(u, _)| chat_type_of(u, names) == "private")
        .map(|(u, d)| json!({ "username": u, "display": d }))
        .collect();

    if let Some(q) = query {
        let low = q.to_lowercase();
        contacts.retain(|c| {
            c["display"]
                .as_str()
                .map(|s| s.to_lowercase().contains(&low))
                .unwrap_or(false)
                || c["username"]
                    .as_str()
                    .map(|s| s.to_lowercase().contains(&low))
                    .unwrap_or(false)
        });
    }

    contacts.sort_by(|a, b| {
        a["display"]
            .as_str()
            .unwrap_or("")
            .cmp(b["display"].as_str().unwrap_or(""))
    });

    let total = contacts.len();
    contacts.truncate(limit);
    Ok(json!({ "contacts": contacts, "total": total }))
}

// ─── 内部辅助函数 ────────────────────────────────────────────────────────────

fn resolve_username(chat_name: &str, names: &Names) -> Option<String> {
    if names.map.contains_key(chat_name)
        || chat_name.contains("@chatroom")
        || chat_name.starts_with("wxid_")
    {
        return Some(chat_name.to_string());
    }
    let low = chat_name.to_lowercase();
    // 精确匹配显示名：排序后取第一个，保证确定性
    let mut exact: Vec<&String> = names
        .map
        .iter()
        .filter(|(_, display)| display.to_lowercase() == low)
        .map(|(uname, _)| uname)
        .collect();
    exact.sort();
    if let Some(u) = exact.into_iter().next() {
        return Some(u.clone());
    }
    // 模糊匹配：取 display name 最短的（最精确），相同长度取字典序最小
    let mut candidates: Vec<(&String, &String)> = names
        .map
        .iter()
        .filter(|(_, display)| display.to_lowercase().contains(&low))
        .collect();
    candidates.sort_by_key(|(uname, display)| (display.len(), uname.as_str()));
    candidates
        .into_iter()
        .next()
        .map(|(uname, _)| uname.clone())
}

async fn find_msg_tables(
    db: &DbCache,
    names: &Names,
    username: &str,
) -> Result<Vec<(String, String)>> {
    // (rel_key, table)：调用方经 `DbCache::conn_params(rel_key)` 重新解析连接，
    // 不再传递 `MessageShard.path`（那只是诊断用的密文物理路径，不能直接 `Connection::open`）。
    let (shards, _, _) = find_msg_shards(db, names, username, None).await?;
    Ok(shards.into_iter().map(|s| (s.rel_key, s.table)).collect())
}

/// 冷分片跳过判定的安全容差（秒）：吸收时钟偏差与文件系统落盘延迟。
///
/// 安全性论证：WeChat 只会在真正写入新消息时 append/覆盖对应分片的 `.db` 或
/// `.db-wal`，因此"分片包含 create_time >= since 的行"是"该分片源文件 mtime
/// 不早于 since"的必要条件（逆否命题：mtime 早于 since，则分片不可能含有
/// create_time >= since 的行）。24 小时的 slack 用来吸收：落盘延迟、NTFS/HFS
/// 时间戳精度、以及本机时钟与消息 create_time 之间的偏差——比 `meta.rs` 里
/// `STALE_THRESHOLD_SECS` 用的量级更保守，宁可少跳过也不能误跳过含新消息的分片。
const SHARD_FRESHNESS_SLACK_SECS: i64 = 24 * 3600;

/// 判断一个分片是否可以跳过解密（按加密源文件 mtime 与 `since` 窗口比较）。
///
/// - `since` 为 `None`（无时间下界）→ 全量查询语义不变，永不跳过。
/// - `freshness` 为 `None`（源文件缺失/不可读，未知）→ 保守起见，永不跳过。
/// - 否则：源文件 mtime 早于 `since - SLACK` → 可以跳过。
fn shard_skippable(freshness: Option<i64>, since: Option<i64>) -> bool {
    match (freshness, since) {
        (Some(f), Some(s)) => f + SHARD_FRESHNESS_SLACK_SECS < s,
        _ => false,
    }
}

/// 分片级并发扫描（[`find_msg_shards`] / [`q_search`] 全局分支的 `JoinSet`）
/// 允许同时真正发起磁盘 I/O 的分片数上限。
///
/// # 为什么不能无限并发
/// 目标部署环境是机械硬盘（HDD），只有一个物理磁头/一条寻道臂。`JoinSet`
/// 把"对哪些分片发起扫描"和"这些扫描真正跑多快"两件事分开了：不加上限时，
/// `since=None` 冷启动会对全部 `need_rebuild` 分片（活跃大账号可达 60~80
/// 个）一次性 `spawn_blocking`，每个任务几乎同时对不同分片文件发起
/// `open()` + 逐页解密，等价于让 HDD 同时响应几十个随机位置的读请求——
/// 机械寻道时间（通常几毫秒到十几毫秒）与理论上"完全并行"节省的时间相比
/// 会占主导，磁头在几十个目标扇区之间来回抖动，总耗时可能比老的串行实现
/// 更差（负优化）。这与 SSD 相反：SSD 没有机械寻道开销，高并发随机读能
/// 直接换来更高的聚合吞吐，越并发越快。
///
/// # 为什么选 4 而不是 1 或者更大
/// - 选 1（退化回串行）放弃了并发化本来要解决的问题：单个分片的解密+查询
///   仍然有纯 CPU 开销（AES 逐页解密、HMAC 校验、SQLite 解析），值太小时
///   没法用"发起下一个分片的 I/O"去重叠"当前分片的 CPU 解密"这部分延迟，
///   丧失并发化的收益。
/// - 选一个双位数的值（例如 16、32）本质上和不设上限没有区别——目标机器
///   上的机械盘队列深度撑不住那么多并发随机 I/O，寻道抖动的负面效应会
///   重新主导总耗时，等于没修。
/// - 4 是一个"既能靠适度重叠隐藏部分寻道 / 解密延迟，又远低于机械盘寻道
///   风暴阈值"的保守折中：现代 HDD 的原生指令队列（NCQ）在浅深度（个位数）
///   时仍能有效做电梯调度合并，深度一旦上到几十就会开始退化。选一个偏
///   保守的小值，代价只是"极端场景下没有榨干理论并行上限"，换来的是
///   任何硬件（尤其是这个项目明确要支持的慢速机械盘）上都不会比串行更差。
///
/// 不做成运行时可配置项：这是一个纯粹的硬件特性折中，不是业务参数，写死
/// 常量比暴露一个用户很难正确设置的配置项更安全。
const MAX_CONCURRENT_SHARD_SCANS: usize = 4;

/// 把"先拿信号量许可、许可到手后才真正 `spawn_blocking` 执行分片 I/O"这个
/// 模式封装成一个共享 helper，供 [`find_msg_shards`] 和 [`q_search`] 全局
/// 扫描分支的 `JoinSet` 复用（消除重复代码，见 [`MAX_CONCURRENT_SHARD_SCANS`]
/// 的取值论证）。
///
/// # 为什么信号量的 `.await` 必须放在 `spawn` 出去的任务内部，而不是调用方
/// 调用方（`find_msg_shards` 的判定循环）对"逐分片同步完成判定、循环体内
/// 无任何 `.await`"这个不变量有严格要求（避免与其它并发调用者交错出新的
/// 判定期竞态，见 `find_msg_shards` 文档"FIX 3：判定同步、I/O 并发"一节）。
/// 这里用 `join_set.spawn(async move { .. })` 包一层普通异步任务、把
/// `semaphore.acquire_owned().await` 放进这个新任务自己的执行体内部——从
/// 调用方（判定循环）的视角看，`spawn` 本身仍然是同步注册、立即返回、不
/// 产生任何让出点，只是把"等待许可"这件事推迟到任务自己被调度执行的时候，
/// 不会让判定循环出现新的交错窗口。真正的限流发生在"已经 spawn 出去的
/// 任务里最多只有 `MAX_CONCURRENT_SHARD_SCANS` 个能拿到许可、跑进
/// `spawn_blocking` 做真实 I/O"，其余任务在 `acquire_owned().await` 上
/// 排队，不占用阻塞线程池。
///
/// # 错误语义：与"直接 `join_set.spawn_blocking(work)`"完全等价
/// `work` 内部返回的 `Err`（真实 I/O/解密错误）原样透传；`work` 所在的
/// `spawn_blocking` 任务本身 panic/被 abort 时，`.unwrap_or_else` 把这种
/// 情况也转换成一个 `Err`，与"work 自己返回 Err"合并成同一个出口——调用方
/// 不需要再额外区分"内层阻塞任务 panic"和"内层阻塞任务正常返回 Err"这两
/// 种情况（原来直接用 `spawn_blocking` 时，前者是外层 `JoinSet` 的
/// `JoinError`，后者是 `Ok(Err(e))`；现在统一成后一种形态）。两种情况下
/// `find_msg_shards` / `q_search` 最终都会让整个调用返回 `Err`，"任一分片
/// 失败、整体失败、不返回部分结果"这条既有语义不变，只是内部错误分类的
/// 归并方式变了。
fn spawn_shard_scan<F, T>(
    join_set: &mut tokio::task::JoinSet<Result<T>>,
    semaphore: &Arc<tokio::sync::Semaphore>,
    work: F,
) where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let semaphore = Arc::clone(semaphore);
    join_set.spawn(async move {
        // 信号量只在 `close()` 后才会返回 Err，这里从不主动 close，`expect`
        // 只是让"不会失败"这个不变量在类型上显式可见。
        let _permit = semaphore
            .acquire_owned()
            .await
            .expect("MAX_CONCURRENT_SHARD_SCANS 信号量不会被 close()");
        tokio::task::spawn_blocking(work)
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("分片扫描阻塞任务异常退出: {}", e)))
    });
}

/// 定位某个 chat 对应 `Msg_<md5>` 表所在的消息分片。
///
/// `since`：调用方已知的时间下界（unix 秒）。传 `Some(s)` 时，会在解密前先用
/// `DbCache::source_freshness_secs` 读取每个分片加密源文件的 mtime；mtime 早于
/// `s - SHARD_FRESHNESS_SLACK_SECS` 的分片被判定为"不可能含有新消息"而跳过解密
/// （见 `shard_skippable`）。传 `None` 时行为与跳过逻辑加入前完全一致。
///
/// 返回 `(命中分片, scanned, skipped)`：`scanned` 是实际解密并查询过的分片数
/// （语义不变，跳过的分片不计入）；`skipped` 是因 mtime 判定被跳过的分片数。
/// [`find_msg_shards`] 并发扫描（FIX 3）单个分片任务的完整结果：把
/// `put_shard_schema` 回写、结果拼装所需的一切拥有型数据都装进来，避免
/// `JoinSet` 完成顺序不确定时还要额外维护"结果 -> 判定期上下文"的外部
/// 关联表。
struct ShardScanOutcome {
    rel_key: String,
    tables_opt: Option<HashSet<String>>,
    max_ts: Option<i64>,
    enc_path: std::path::PathBuf,
    snap_at_judgement: Option<SourceSnapshot>,
    expected_generation: u64,
}

/// 定位某个 chat 对应 `Msg_<md5>` 表所在的消息分片。
///
/// `since`：调用方已知的时间下界（unix 秒）。传 `Some(s)` 时，会在解密前先用
/// `DbCache::source_freshness_secs` 读取每个分片加密源文件的 mtime；mtime 早于
/// `s - SHARD_FRESHNESS_SLACK_SECS` 的分片被判定为"不可能含有新消息"而跳过解密
/// （见 `shard_skippable`）。传 `None` 时行为与跳过逻辑加入前完全一致。
///
/// 返回 `(命中分片, scanned, skipped)`：`scanned` 是实际解密并查询过的分片数
/// （语义不变，跳过的分片不计入）；`skipped` 是因 mtime 判定被跳过的分片数。
///
/// # FIX 3：判定同步、I/O 并发
/// `since=None`（`find_msg_tables` / `q_search` 全局-命名分支 / `q_stats` /
/// `q_attachments` 等"全量发现"场景）下 `shard_skippable` 恒为 false，
/// daemon 刚重启、路由缓存为空时会对**全部** `S` 个消息分片逐一真正
/// `open()` + 扫 `sqlite_master`——旧实现串行 `await`，总耗时是"各分片之和"
/// （几十秒到数分钟）。这里把逻辑拆成两段：
/// 1. **判定段**（skip / 路由缓存 Fresh-Stale / `expected_generation`
///    读取）保持逐分片同步完成，与旧实现的时序完全一致，不引入新的判定间
///    竞态——这段本身没有任何 `.await`，多个分片之间天然串行、不重叠。
/// 2. **I/O 段**（真正需要重建或已确认命中目标表的分片）用 `JoinSet` 一次性
///    `spawn_blocking` 派发（参照 [`q_search`] 全局分支 ~634-638 的现成
///    范式），总耗时从"各分片之和"降到"最大值"。
///
/// 并发化后 `expected_generation`/`put_shard_schema` 的 TOCTOU 保护为什么
/// 仍然正确：见 `DbCache::put_shard_schema` 文档——世代号是**全局**原子
/// 计数器，校验（`route_generation.load() != expected_generation`）与写入
/// 都在 `shard_routes` 那把 `std::sync::Mutex` 的同一个临界区内完成，这个
/// 机制从设计上就是为了"任意数量的并发调用者互相竞争"而存在的（它已经在
/// 服务"不同并发 RPC 连接各自调用 find_msg_shards"这个更早就存在的并发
/// 场景）；这里在**同一次** `find_msg_shards` 调用内部把多个分片的 I/O
/// 并发化，不过是让这套已经为任意并发设计的机制多服务几个同时在飞的
/// 调用者，不改变、不放宽任何单次校验本身的正确性。并发测试见
/// `cache::concurrency_tests`。
async fn find_msg_shards(
    db: &DbCache,
    names: &Names,
    username: &str,
    since: Option<i64>,
) -> Result<(Vec<MessageShard>, usize, usize)> {
    let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
    if !msg_table_re().is_match(&table_name) {
        return Ok((Vec::new(), 0, 0));
    }

    let total = names.msg_db_keys.len();
    let mut scanned = 0usize;
    let mut skipped = 0usize;

    // 判定段：逐分片同步完成（无 `.await`），与旧实现的时序语义完全一致；
    // 只是把"真正需要 open() 的分片"收集起来，延后到下面并发派发，而不是
    // 判定完一个就立刻同步等它的 I/O 完成。
    let mut join_set: tokio::task::JoinSet<Result<ShardScanOutcome>> = tokio::task::JoinSet::new();
    // 并发上限见 `MAX_CONCURRENT_SHARD_SCANS` 文档：这次调用自己的分片扫描
    // 批次最多同时 `MAX_CONCURRENT_SHARD_SCANS` 个在真正做磁盘 I/O，不影响
    // 判定段本身（下面循环体内依旧没有任何 `.await`）。
    let scan_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHARD_SCANS));

    for rel_key in &names.msg_db_keys {
        // FIX 2：每分片只读一次 SourceSnapshot（至多 1 次主库 metadata + 1 次
        // WAL exists()/metadata），透传给下面 skip 判定 / 路由 lookup / 热
        // 连接门控三处，消除原本三处各自独立 stat 造成的 4~6 次重复系统
        // 调用。三处判定逻辑与去重前完全一致，只是快照来源统一成"调用方
        // 传入"。三处调用在时间上本就紧挨着（都是同步、非阻塞调用，中间
        // 没有任何 `.await` 让出点），合并成一次读取不会引入新的 TOCTOU
        // 窗口。
        let snapshot = db.source_snapshot(rel_key);

        if shard_skippable(snapshot.freshness_secs(), since) {
            skipped += 1;
            continue;
        }

        // 优化 A（分片路由缓存）：miss / 快照变了才真正 open() 重建（一次性
        // 列出该分片全部 Msg_ 表名，不止查目标表）；命中且快照未变、确认
        // 不含目标表时零阻塞 I/O 直接跳过。同一个分片被多个不同会话命中时，
        // 只有第一个触发真正的 sqlite_master 扫描，把复杂度从 O(会话×分片)
        // 压到 O(dirty 分片数)。
        let (cached_tables, need_rebuild, snap_at_judgement) =
            match db.shard_route_lookup_with_snapshot(rel_key, snapshot) {
                ShardRouteLookup::Fresh(tables) => (tables, false, None),
                ShardRouteLookup::Stale(snapshot) => (HashSet::new(), true, Some(snapshot)),
            };
        if !need_rebuild && !cached_tables.contains(&table_name) {
            continue;
        }

        // 优化 B（热连接复用）：借这一次查询顺路拿到（或复用）该分片的常驻
        // 连接。
        let hot = match db.hot_conn_handle_with_snapshot(rel_key, snapshot) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let enc_path = hot.enc_db_path().to_path_buf();
        scanned += 1;
        let tname = table_name.clone();
        let rel_key_owned = rel_key.clone();

        // FIX-MEDIUM（invalidate 与 put_shard_schema 回写竞态，保持不变）：
        // 在真正发起 `spawn_blocking` 扫描之前读一次当前作废世代号。
        // `DbCache` 经 `Arc` 被 `server.rs` 每连接 `tokio::spawn` 共享，
        // 下面这次扫描（排队 + sqlite_master I/O）期间完全可能有另一个并发
        // 请求对同一分片（或任意分片，见 `DbCache::invalidate_shard` 的
        // 全局粒度说明）调用 `invalidate_shard`；如果扫描完成后仍然无条件
        // 回写，会用一份可能已经过期的 schema 把刚被作废的路由悄悄复活。
        // 下面 `put_shard_schema` 调用会拿这份 `expected_generation` 与
        // 《回写那一刻》的当前世代号比较，不等就放弃写入——并发化只是把
        // "发起 spawn_blocking 之后的等待"改成并发，这一步读取的时序位置
        // 与旧实现完全相同。
        let expected_generation = db.route_generation();

        spawn_shard_scan(&mut join_set, &scan_semaphore, move || -> Result<ShardScanOutcome> {
            let (tables_opt, max_ts) = hot.with(|conn| {
                if need_rebuild {
                    let mut stmt = conn.prepare(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'",
                    )?;
                    let tables: HashSet<String> = stmt
                        .query_map([], |row| row.get::<_, String>(0))?
                        .filter_map(|r| r.ok())
                        .collect();
                    let ts = if tables.contains(&tname) {
                        conn.query_row(
                            &format!("SELECT MAX(create_time) FROM [{}]", tname),
                            [],
                            |row| row.get(0),
                        )
                        .ok()
                        .flatten()
                    } else {
                        None
                    };
                    Ok::<_, anyhow::Error>((Some(tables), ts))
                } else {
                    // 缓存已确认该分片含目标表（否则上面已经 continue）；
                    // 万一实际不一致（理论上不该发生——任何写入都会 bump
                    // mtime 使缓存失效），查询失败时 `.ok()` 安全退化为
                    // None，不 panic、不误报数据。
                    let ts = conn
                        .query_row(
                            &format!("SELECT MAX(create_time) FROM [{}]", tname),
                            [],
                            |row| row.get(0),
                        )
                        .ok()
                        .flatten();
                    Ok((None, ts))
                }
            })?;
            Ok(ShardScanOutcome {
                rel_key: rel_key_owned,
                tables_opt,
                max_ts,
                enc_path,
                snap_at_judgement,
                expected_generation,
            })
        });
    }

    // I/O 段：并发收割。任意一个分片扫描失败（真实 I/O/decrypt 错误，不是
    // "确认不含目标表"这种正常空结果）都立刻中止并把错误原样传播给调用方
    // ——与旧实现的 `.await??` 语义完全一致：旧实现里任何一次 `?` 失败都会
    // 让整个 `find_msg_shards` 立刻返回 `Err`，不会把"部分分片失败"降级
    // 处理成"跳过失败的分片、返回其余分片的部分结果"。仍在 `JoinSet` 里
    // 排队/执行的其它分片任务会在 `join_set` 被 drop 时收到 abort 信号；
    // 由于它们是 `spawn_blocking`（协作式取消对阻塞线程无效），可能会把
    // 当前这次 I/O 跑完，但其结果不会被读取、不会被回写，不产生任何副作用
    // 之外的正确性影响。
    let mut results: Vec<MessageShard> = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        let outcome = match joined {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                return Err(e.context(format!("扫描 {} 的消息分片失败", username)));
            }
            Err(e) => {
                anyhow::bail!("扫描 {} 的消息分片任务异常: {}", username, e);
            }
        };

        if let Some(tables) = outcome.tables_opt {
            // 必须用《判定时刻》的 snap_at_judgement（`shard_route_lookup`
            // 返回 Stale 时携带的快照），不能用重建完成后重新读的快照——
            // 否则会把"重建期间发生的新写入"误判为"缓存仍新鲜"，见
            // `DbCache::put_shard_schema` 的 TOCTOU 说明。`need_rebuild` 为
            // true 时这份快照必然是 `Some`（上面 `Stale` 分支赋的值），
            // `expect` 只是让这个不变量在类型上显式可见。
            let snapshot = outcome
                .snap_at_judgement
                .expect("need_rebuild 时快照必然存在");
            db.put_shard_schema(
                outcome.rel_key.clone(),
                snapshot,
                tables,
                outcome.expected_generation,
            );
        }

        if let Some(ts) = outcome.max_ts {
            results.push(MessageShard {
                rel_key: outcome.rel_key,
                path: outcome.enc_path,
                table: table_name.clone(),
                max_ts: ts,
            });
        }
    }

    if skipped > 0 {
        eprintln!(
            "[shards] {}: 按源文件 mtime 跳过 {}/{} 个冷分片 (since={})",
            username,
            skipped,
            total,
            since.unwrap_or_default()
        );
    }

    // 按最大时间戳降序排列（最新的优先）——并发完成顺序不确定，排序保证
    // 输出顺序与旧实现完全一致。
    results.sort_by_key(|s| std::cmp::Reverse(s.max_ts));
    Ok((results, scanned, skipped))
}

#[cfg(test)]
mod shard_skip_tests {
    use super::*;

    #[test]
    fn no_since_never_skips() {
        // 无时间下界 → 全量查询语义，任何 freshness 都不跳过
        assert!(!shard_skippable(None, None));
        assert!(!shard_skippable(Some(0), None));
        assert!(!shard_skippable(Some(i64::MAX), None));
    }

    #[test]
    fn unknown_freshness_never_skips() {
        // 源文件缺失/不可读 → 未知，保守起见不跳过
        assert!(!shard_skippable(None, Some(1_000_000)));
    }

    #[test]
    fn stale_shard_beyond_slack_is_skipped() {
        let since = 1_000_000i64;
        // freshness 比 since 早了 slack+1 秒 → 明确跳过
        let freshness = since - SHARD_FRESHNESS_SLACK_SECS - 1;
        assert!(shard_skippable(Some(freshness), Some(since)));
    }

    #[test]
    fn shard_within_slack_window_is_not_skipped() {
        let since = 1_000_000i64;
        // freshness 只比 since 早了 slack-1 秒 → 仍在容差窗口内，不跳过
        let freshness = since - SHARD_FRESHNESS_SLACK_SECS + 1;
        assert!(!shard_skippable(Some(freshness), Some(since)));
    }

    #[test]
    fn boundary_exactly_at_slack_is_not_skipped() {
        let since = 1_000_000i64;
        // freshness + slack == since（不是严格小于）→ 边界值不跳过
        let freshness = since - SHARD_FRESHNESS_SLACK_SECS;
        assert!(!shard_skippable(Some(freshness), Some(since)));
    }

    #[test]
    fn fresher_than_since_is_not_skipped() {
        let since = 1_000_000i64;
        assert!(!shard_skippable(Some(since + 10), Some(since)));
    }
}

/// FIX 3（并发扫描）的集成测试：用真实 VFS 可打开的加密夹具（复用
/// `cache::test_support`）搭多个消息分片，端到端验证 `find_msg_shards`
/// 并发化后：(a) 功能结果与旧的逐分片串行实现完全等价（命中哪些分片、
/// 每个分片的 max_ts、按 max_ts 降序排序），(b) 冷启动（路由缓存为空，
/// `since=None`）下确实会对全部分片并发发起真正的 open()，(c) 任意一个
/// 分片打开失败都会让整个调用立刻返回 `Err`，不会静默降级成"跳过失败
/// 分片、返回其余分片的部分结果"——这是刻意保留的旧行为，不是并发化的
/// 副作用。
#[cfg(test)]
mod find_msg_shards_concurrency_tests {
    use super::super::cache::test_support::{
        backdate_beyond_slack, build_encrypted_fixture, key_fixture, key_to_hex, unique_tmpdir,
    };
    use super::*;

    fn names_for(msg_db_keys: Vec<String>) -> Names {
        Names {
            map: HashMap::new(),
            md5_to_uname: HashMap::new(),
            msg_db_keys,
            verify_flags: HashMap::new(),
        }
    }

    fn wal_sidecar_path(db_path: &std::path::Path) -> std::path::PathBuf {
        let mut name = db_path.file_name().unwrap().to_os_string();
        name.push("-wal");
        db_path.with_file_name(name)
    }

    /// 冷启动场景：daemon 刚重启，路由缓存为空，`since=None`（`shard_skippable`
    /// 恒 false）——`names.msg_db_keys` 里的全部分片都会走 need_rebuild 真正
    /// open()，这正是 FIX 3 要并发化的场景。三个分片：一个承载目标表（较新
    /// 消息）、一个承载目标表的"旧半"（模拟分片滚动，同一个 uname 的表分布
    /// 在两个分片里）、一个完全不相关。
    #[tokio::test]
    async fn concurrently_scans_all_dirty_shards_and_returns_results_sorted_by_max_ts_desc() {
        let root = unique_tmpdir("find-shards-concurrent");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let username = "alice";
        let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
        let key = key_fixture();
        let mut all_keys = HashMap::new();

        // shard_new：承载目标表，较新的消息（max create_time = 5000）。
        let shard_new = db_dir.join("message_0.db");
        build_encrypted_fixture(&shard_new, &key, &table_name, &[(1, 1000), (2, 5000)]);
        backdate_beyond_slack(&shard_new);
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));

        // shard_unrelated：不承载目标表，只有一张无关的表。
        let shard_unrelated = db_dir.join("message_1.db");
        build_encrypted_fixture(&shard_unrelated, &key, "Msg_someone_else", &[(1, 9999)]);
        backdate_beyond_slack(&shard_unrelated);
        all_keys.insert("message_1.db".to_string(), key_to_hex(&key));

        // shard_old：模拟分片滚动——同一个 table_name 出现在另一个分片里，
        // 承载更早的消息（max create_time = 3000）。
        let shard_old = db_dir.join("message_2.db");
        build_encrypted_fixture(&shard_old, &key, &table_name, &[(1, 500), (2, 3000)]);
        backdate_beyond_slack(&shard_old);
        all_keys.insert("message_2.db".to_string(), key_to_hex(&key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = names_for(vec![
            "message_0.db".to_string(),
            "message_1.db".to_string(),
            "message_2.db".to_string(),
        ]);

        let (shards, scanned, skipped) = find_msg_shards(&db, &names, username, None)
            .await
            .expect("冷启动下应该成功并发扫描全部分片");

        assert_eq!(skipped, 0, "since=None 时不应该跳过任何分片");
        assert_eq!(scanned, 3, "路由缓存为空，全部 3 个分片都应该真正被 open 扫描");

        assert_eq!(shards.len(), 2, "只有承载目标表的两个分片应该出现在结果里");
        assert_eq!(
            shards[0].rel_key, "message_0.db",
            "按 max_ts 降序，更新的分片应该排在前面"
        );
        assert_eq!(shards[0].max_ts, 5000);
        assert_eq!(shards[1].rel_key, "message_2.db");
        assert_eq!(shards[1].max_ts, 3000);

        // 并发扫描附带效果：路由缓存应该已经记下这三个分片各自的 schema，
        // 后续同一批分片的查询可以直接命中 Fresh，不需要重新 open。
        assert!(matches!(
            db.shard_route_lookup("message_0.db"),
            ShardRouteLookup::Fresh(_)
        ));
        assert!(matches!(
            db.shard_route_lookup("message_1.db"),
            ShardRouteLookup::Fresh(_)
        ));
        assert!(matches!(
            db.shard_route_lookup("message_2.db"),
            ShardRouteLookup::Fresh(_)
        ));
    }

    /// 两个分片：一个承载目标表，一个不承载。第二次调用（路由缓存已经
    /// Fresh）时：
    /// - 承载目标表的分片仍然需要 touch 一次去拿 `MAX(create_time)`——
    ///   `scanned` 统计的是"发起了真正的连接层查询"，不是"发起了
    ///   `sqlite_master` 全表扫描"，路由缓存 Fresh 在这种情况下省下的是
    ///   "重新扫描 schema"，不是"完全不碰这个分片"，这与优化 A 的既有
    ///   文档语义一致（"命中且快照未变、**确认不含目标表**时零阻塞 I/O
    ///   直接跳过"——反过来，确认**含**目标表时不属于这条零 I/O 路径）。
    /// - 不承载目标表的分片应该完全零 I/O 跳过（这条才是"路由缓存命中时
    ///   跳过"真正生效的场景），证明并发化没有破坏这条既有优化。
    #[tokio::test]
    async fn second_call_reuses_route_cache_to_skip_only_the_non_matching_shard() {
        let root = unique_tmpdir("find-shards-warm");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let username = "bob";
        let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
        let key = key_fixture();
        let mut all_keys = HashMap::new();

        let shard_match = db_dir.join("message_0.db");
        build_encrypted_fixture(&shard_match, &key, &table_name, &[(1, 1000)]);
        // 路由缓存的 Fresh 判定同时要求"snapshot 相等"与
        // `SourceSnapshot::trusted_as_of`（安静满一个 600s 新鲜度 slack），
        // 回拨 mtime 让第二次调用不用真的等待 600 秒就能进入"可信"状态。
        backdate_beyond_slack(&shard_match);
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));

        let shard_other = db_dir.join("message_1.db");
        build_encrypted_fixture(&shard_other, &key, "Msg_unrelated", &[(1, 1)]);
        backdate_beyond_slack(&shard_other);
        all_keys.insert("message_1.db".to_string(), key_to_hex(&key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = names_for(vec!["message_0.db".to_string(), "message_1.db".to_string()]);

        let (first, first_scanned, _) = find_msg_shards(&db, &names, username, None)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first_scanned, 2, "第一次调用路由缓存为空，两个分片都必须真正 open");

        let (second, second_scanned, _) = find_msg_shards(&db, &names, username, None)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].rel_key, "message_0.db");
        assert_eq!(second[0].max_ts, 1000, "复用路由缓存 schema 后查到的 max_ts 应该仍然正确");
        assert_eq!(
            second_scanned, 1,
            "只有承载目标表的分片需要 touch 一次拿 MAX(create_time)；\
             不承载目标表的分片路由缓存 Fresh 后应该零 I/O 跳过"
        );
    }

    /// 错误传播不降级：并发化之前，串行实现里任何一个分片 open 失败都会
    /// 通过 `.await??` 立刻让整个 `find_msg_shards` 返回 `Err`；并发化后
    /// 必须保持这个"任一失败、整体失败"的语义，不能悄悄把失败的分片当作
    /// "跳过"处理、只返回其余分片的部分结果——那样会把一次真实的 I/O/解密
    /// 异常伪装成"这个会话没有更多消息"，对监控工具是不可接受的静默降级。
    #[tokio::test]
    async fn any_shard_open_failure_aborts_whole_call_not_partial_results() {
        let root = unique_tmpdir("find-shards-error");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let username = "carol";
        let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
        let key = key_fixture();
        let mut all_keys = HashMap::new();

        // shard_good：真正命中目标表，本该被正常返回。
        let shard_good = db_dir.join("message_0.db");
        build_encrypted_fixture(&shard_good, &key, &table_name, &[(1, 1000)]);
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));

        // shard_bad：密钥已登记（能通过 resolve_conn_params），但磁盘内容是
        // 垃圾字节——`ConnParams::open()` 内部用 `immutable=1` 打开时会在
        // 校验页 1 魔数那一步直接报 SQLITE_NOTADB，模拟真实的解密/损坏错误。
        let shard_bad = db_dir.join("message_1.db");
        std::fs::write(&shard_bad, vec![0x13u8; 4096]).unwrap();
        all_keys.insert("message_1.db".to_string(), key_to_hex(&key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = names_for(vec!["message_0.db".to_string(), "message_1.db".to_string()]);

        let result = find_msg_shards(&db, &names, username, None).await;
        assert!(
            result.is_err(),
            "任意一个分片 open 失败都必须让整个调用返回 Err，不能静默降级成部分结果"
        );
    }

    /// 分片滚动 + 并发场景下，wal-only 变化也必须让 join_set 里对应的分片
    /// 走 need_rebuild 真正重扫——防止并发化引入"某个分片在批次里被漏判为
    /// Fresh"这类回归（wal 存在性是 SourceSnapshot 相等性判断的一部分，
    /// 见 cache.rs `wal_appearing_makes_snapshot_unequal_even_with_zeroed_mtime_len`）。
    #[tokio::test]
    async fn wal_only_change_forces_rebuild_for_the_affected_shard_in_a_concurrent_batch() {
        let root = unique_tmpdir("find-shards-wal-change");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let username = "dave";
        let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
        let key = key_fixture();
        let mut all_keys = HashMap::new();

        let shard_a = db_dir.join("message_0.db");
        build_encrypted_fixture(&shard_a, &key, &table_name, &[(1, 1000)]);
        backdate_beyond_slack(&shard_a);
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));

        let shard_b = db_dir.join("message_1.db");
        build_encrypted_fixture(&shard_b, &key, "Msg_unrelated", &[(1, 1)]);
        backdate_beyond_slack(&shard_b);
        all_keys.insert("message_1.db".to_string(), key_to_hex(&key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = names_for(vec!["message_0.db".to_string(), "message_1.db".to_string()]);

        let (_first, first_scanned, _) = find_msg_shards(&db, &names, username, None)
            .await
            .unwrap();
        assert_eq!(first_scanned, 2, "首次调用两个分片都应该真正 open");

        // 只给 shard_a 追加一个 WAL 文件（模拟微信刚开始往这个分片写新消息），
        // 不动 shard_b。
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(wal_sidecar_path(&shard_a), [0u8; 31]).unwrap();

        let (second, second_scanned, _) = find_msg_shards(&db, &names, username, None)
            .await
            .unwrap();
        assert_eq!(
            second_scanned, 1,
            "只有 WAL 变化的 shard_a 应该重新 open，shard_b 应该继续走路由缓存零 I/O"
        );
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].rel_key, "message_0.db");
    }
}

/// [`MAX_CONCURRENT_SHARD_SCANS`] / [`spawn_shard_scan`] 专项测试：
/// - 并发度确实被限制在上限内，且不是被误伤退化成纯串行（峰值应该真的
///   触达上限）；
/// - 限流只改变"谁先谁后拿到许可"这个调度节奏，不改变最终结果集——不丢、
///   不重、不篡改任何一个任务的产出；
/// - 接到真实 `find_msg_shards` 上、分片数明显超过并发上限时，功能结果
///   （命中哪些分片、每个分片的 max_ts、排序）与不限流时的既有测试
///   （`find_msg_shards_concurrency_tests`）完全一致。
#[cfg(test)]
mod shard_scan_concurrency_cap_tests {
    use super::super::cache::test_support::{
        backdate_beyond_slack, build_encrypted_fixture, key_fixture, key_to_hex, unique_tmpdir,
    };
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 直接对 [`spawn_shard_scan`] + [`MAX_CONCURRENT_SHARD_SCANS`] 施压，不
    /// 经过任何真实分片/磁盘 I/O：用一个共享计数器记录"同一时刻有多少个
    /// work 闭包正在执行"，配一个足够宽（60ms）的睡眠窗口让调度器有充分
    /// 机会把其它已经拿到许可的任务也调度上来同时跑，验证峰值恰好等于
    /// 上限——既不超过（安全性），也确实触达上限（不是被误伤退化成串行）。
    #[tokio::test]
    async fn spawn_shard_scan_bounds_concurrency_to_the_configured_cap() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHARD_SCANS));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let total_tasks = MAX_CONCURRENT_SHARD_SCANS * 4;
        let mut join_set: tokio::task::JoinSet<Result<usize>> = tokio::task::JoinSet::new();
        for i in 0..total_tasks {
            let active2 = Arc::clone(&active);
            let peak2 = Arc::clone(&peak);
            spawn_shard_scan(&mut join_set, &semaphore, move || {
                let cur = active2.fetch_add(1, Ordering::SeqCst) + 1;
                peak2.fetch_max(cur, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(80));
                active2.fetch_sub(1, Ordering::SeqCst);
                Ok(i)
            });
        }

        let mut results = Vec::new();
        while let Some(joined) = join_set.join_next().await {
            results.push(joined.expect("任务不应 panic").expect("任务不应返回 Err"));
        }
        results.sort_unstable();

        assert!(
            peak.load(Ordering::SeqCst) <= MAX_CONCURRENT_SHARD_SCANS,
            "并发峰值 {} 不能超过上限 {}",
            peak.load(Ordering::SeqCst),
            MAX_CONCURRENT_SHARD_SCANS
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            MAX_CONCURRENT_SHARD_SCANS,
            "任务数远多于上限、睡眠窗口足够宽时，峰值应该恰好触达上限，\
             证明确实在并发跑、不是被误伤退化成串行"
        );
        assert_eq!(
            results,
            (0..total_tasks).collect::<Vec<_>>(),
            "限流不应该丢失或重复任何一个任务的结果"
        );
    }

    /// 结果集一致性：同一批任务分别跑"不限流（直接 `spawn_blocking`）"和
    /// "限流（经 `spawn_shard_scan`）"两条路径，产出必须完全相同——限流
    /// 只是调度节奏的改变，不是又一次"部分结果"降级。
    #[tokio::test]
    async fn capped_concurrency_yields_identical_result_set_to_uncapped() {
        let total_tasks = MAX_CONCURRENT_SHARD_SCANS * 3;

        let mut baseline_set: tokio::task::JoinSet<Result<usize>> = tokio::task::JoinSet::new();
        for i in 0..total_tasks {
            baseline_set.spawn_blocking(move || Ok(i));
        }
        let mut baseline: Vec<usize> = Vec::new();
        while let Some(joined) = baseline_set.join_next().await {
            baseline.push(joined.expect("baseline 任务不应 panic").expect("baseline 任务不应返回 Err"));
        }
        baseline.sort_unstable();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHARD_SCANS));
        let mut capped_set: tokio::task::JoinSet<Result<usize>> = tokio::task::JoinSet::new();
        for i in 0..total_tasks {
            spawn_shard_scan(&mut capped_set, &semaphore, move || Ok(i));
        }
        let mut capped: Vec<usize> = Vec::new();
        while let Some(joined) = capped_set.join_next().await {
            capped.push(joined.expect("capped 任务不应 panic").expect("capped 任务不应返回 Err"));
        }
        capped.sort_unstable();

        assert_eq!(
            capped, baseline,
            "限流只应该改变调度节奏，不应该丢失/重复/篡改任何一个任务的结果"
        );
    }

    /// 接到真实 `find_msg_shards` 上：分片数明显超过并发上限（cap + 3）时，
    /// 功能结果仍然正确——命中目标表的分片一个不漏、`max_ts` 与排序都与
    /// `find_msg_shards_concurrency_tests`（不受并发上限约束，因为分片数
    /// 没超过它）里验证过的语义完全一致。
    #[tokio::test]
    async fn find_msg_shards_stays_correct_when_shard_count_exceeds_the_concurrency_cap() {
        let root = unique_tmpdir("find-shards-over-cap");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let username = "erin";
        let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
        let key = key_fixture();
        let mut all_keys = HashMap::new();
        let shard_count = MAX_CONCURRENT_SHARD_SCANS + 3;
        let mut msg_db_keys = Vec::new();

        for i in 0..shard_count {
            let rel_key = format!("message_{}.db", i);
            let path = db_dir.join(&rel_key);
            if i == 0 {
                // 承载目标表的较新一段。
                build_encrypted_fixture(&path, &key, &table_name, &[(1, 1000), (2, 4000)]);
            } else if i == shard_count - 1 {
                // 分片滚动：目标表也出现在最后一个分片，承载更旧的一段。
                build_encrypted_fixture(&path, &key, &table_name, &[(1, 200), (2, 2000)]);
            } else {
                build_encrypted_fixture(
                    &path,
                    &key,
                    &format!("Msg_unrelated_{}", i),
                    &[(1, 1)],
                );
            }
            backdate_beyond_slack(&path);
            all_keys.insert(rel_key.clone(), key_to_hex(&key));
            msg_db_keys.push(rel_key);
        }

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = Names {
            map: HashMap::new(),
            md5_to_uname: HashMap::new(),
            msg_db_keys,
            verify_flags: HashMap::new(),
        };

        let (shards, scanned, skipped) = find_msg_shards(&db, &names, username, None)
            .await
            .expect("分片数超过并发上限时仍应成功扫描全部分片");

        assert_eq!(skipped, 0, "since=None 时不应该跳过任何分片");
        assert_eq!(
            scanned, shard_count,
            "并发上限只限制同时在飞的任务数，不应该漏扫任何分片"
        );
        assert_eq!(shards.len(), 2, "承载目标表的两个分片都应该被找到");
        assert_eq!(shards[0].rel_key, "message_0.db");
        assert_eq!(shards[0].max_ts, 4000);
        assert_eq!(shards[1].rel_key, format!("message_{}.db", shard_count - 1));
        assert_eq!(shards[1].max_ts, 2000);
    }
}

fn query_messages(
    conn: &Connection,
    table: &str,
    chat_username: &str,
    is_group: bool,
    names_map: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
    since: Option<i64>,
    until: Option<i64>,
    msg_type: Option<i64>,
    limit: usize,
    offset: usize,
) -> Result<Vec<Value>> {
    let id2u = load_id2u(conn);

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(s) = since {
        clauses.push("create_time >= ?".into());
        params.push(Box::new(s));
    }
    if let Some(u) = until {
        clauses.push("create_time <= ?".into());
        params.push(Box::new(u));
    }
    if let Some(t) = msg_type {
        push_msg_type_filter(&mut clauses, &mut params, t);
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let sql = format!(
        "SELECT local_id, local_type, create_time, real_sender_id,
                message_content, WCDB_CT_message_content
         FROM [{}] {} ORDER BY create_time DESC LIMIT ? OFFSET ?",
        table, where_clause
    );

    params.push(Box::new(limit as i64));
    params.push(Box::new(offset as i64));

    let params_ref: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_ref.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                get_content_bytes(row, 4),
                row.get::<_, i64>(5).unwrap_or(0),
            ))
        })?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    let mut result = Vec::new();
    for (local_id, local_type, ts, real_sender_id, content_bytes, ct) in rows {
        let content = decompress_message(&content_bytes, ct);
        let sender = sender_label(
            real_sender_id,
            &content,
            is_group,
            chat_username,
            &id2u,
            names_map,
            group_nicknames,
        );
        let text = fmt_content(local_id, local_type, &content, is_group);
        let url = appmsg_url_for_message(local_type, &content);

        let mut msg = json!({
            "timestamp": ts,
            "time": fmt_time(ts, "%Y-%m-%d %H:%M"),
            "sender": sender,
            "content": text,
            "type": fmt_type(local_type),
            "local_id": local_id,
        });
        if let Some(u) = url {
            msg["url"] = serde_json::Value::String(u);
        }
        result.push(msg);
    }
    Ok(result)
}

fn search_in_table(
    conn: &Connection,
    table: &str,
    chat_username: &str,
    is_group: bool,
    names_map: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
    keyword: &str,
    since: Option<i64>,
    until: Option<i64>,
    msg_type: Option<i64>,
    limit: usize,
) -> Result<Vec<Value>> {
    let id2u = load_id2u(conn);
    // 转义 LIKE 通配符，使用 '\' 作为 ESCAPE 字符
    let escaped_kw = keyword
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let search_decoded_content = msg_type == Some(49);
    let keyword_lower = keyword.to_lowercase();
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if !search_decoded_content {
        clauses.push("message_content LIKE ? ESCAPE '\\'".to_string());
        params.push(Box::new(format!("%{}%", escaped_kw)));
    }
    if let Some(s) = since {
        clauses.push("create_time >= ?".into());
        params.push(Box::new(s));
    }
    if let Some(u) = until {
        clauses.push("create_time <= ?".into());
        params.push(Box::new(u));
    }
    if let Some(t) = msg_type {
        push_msg_type_filter(&mut clauses, &mut params, t);
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    let limit_clause = if search_decoded_content {
        ""
    } else {
        " LIMIT ?"
    };
    let sql = format!(
        "SELECT local_id, local_type, create_time, real_sender_id,
                message_content, WCDB_CT_message_content
         FROM [{}] {} ORDER BY create_time DESC{}",
        table, where_clause, limit_clause
    );
    if !search_decoded_content {
        params.push(Box::new(limit as i64));
    }

    let params_ref: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_ref.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                get_content_bytes(row, 4),
                row.get::<_, i64>(5).unwrap_or(0),
            ))
        })?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    let mut result = Vec::new();
    for (local_id, local_type, ts, real_sender_id, content_bytes, ct) in rows {
        let content = decompress_message(&content_bytes, ct);
        let sender = sender_label(
            real_sender_id,
            &content,
            is_group,
            chat_username,
            &id2u,
            names_map,
            group_nicknames,
        );
        let text = fmt_content(local_id, local_type, &content, is_group);
        if search_decoded_content && !matches_search_text(&content, &text, keyword, &keyword_lower)
        {
            continue;
        }
        let url = appmsg_url_for_message(local_type, &content);

        let mut msg = json!({
            "timestamp": ts,
            "time": fmt_time(ts, "%Y-%m-%d %H:%M"),
            "chat": "",
            "sender": sender,
            "content": text,
            "type": fmt_type(local_type),
        });
        if let Some(u) = url {
            msg["url"] = serde_json::Value::String(u);
        }
        result.push(msg);
        if search_decoded_content && result.len() >= limit {
            break;
        }
    }
    Ok(result)
}

fn push_msg_type_filter(
    clauses: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
    msg_type: i64,
) {
    clauses.push("(local_type & 4294967295) = ?".into());
    params.push(Box::new(msg_type));
}

fn matches_search_text(raw: &str, formatted: &str, keyword: &str, keyword_lower: &str) -> bool {
    contains_search_text(raw, keyword, keyword_lower)
        || contains_search_text(formatted, keyword, keyword_lower)
}

fn contains_search_text(haystack: &str, keyword: &str, keyword_lower: &str) -> bool {
    haystack.contains(keyword)
        || (!keyword_lower.is_empty() && haystack.to_lowercase().contains(keyword_lower))
}

fn load_id2u(conn: &Connection) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT rowid, user_name FROM Name2Id") {
        let _ = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map(|rows| {
                for r in rows.flatten() {
                    map.insert(r.0, r.1);
                }
            });
    }
    map
}

async fn load_group_nicknames(
    db: &DbCache,
    chat_username: &str,
) -> Result<HashMap<String, String>> {
    if !chat_username.contains("@chatroom") {
        return Ok(HashMap::new());
    }
    let Ok(conn_params) = db.conn_params("contact/contact.db") else {
        return Ok(HashMap::new());
    };
    let chat = chat_username.to_string();
    tokio::task::spawn_blocking(move || {
        let conn = conn_params.open()?;
        Ok::<_, anyhow::Error>(load_group_nickname_map_from_conn(&conn, &chat, None))
    })
    .await?
}

async fn load_group_nickname_maps(
    db: &DbCache,
    chat_usernames: HashSet<String>,
) -> Result<HashMap<String, HashMap<String, String>>> {
    if chat_usernames.is_empty() {
        return Ok(HashMap::new());
    }
    let Ok(conn_params) = db.conn_params("contact/contact.db") else {
        return Ok(HashMap::new());
    };
    tokio::task::spawn_blocking(move || {
        let conn = conn_params.open()?;
        let mut out = HashMap::new();
        for chat in chat_usernames {
            let nicknames = load_group_nickname_map_from_conn(&conn, &chat, None);
            if !nicknames.is_empty() {
                out.insert(chat, nicknames);
            }
        }
        Ok::<_, anyhow::Error>(out)
    })
    .await?
}

fn load_group_nickname_map_from_conn(
    conn: &Connection,
    chat_username: &str,
    targets: Option<&HashSet<String>>,
) -> HashMap<String, String> {
    if !chat_username.contains("@chatroom") {
        return HashMap::new();
    }
    let ext = load_group_ext_buffer(conn, chat_username);

    let owned_targets = if targets.is_none() {
        load_group_member_username_set(conn, chat_username)
    } else {
        None
    };
    let targets = targets.or(owned_targets.as_ref());

    ext.as_deref()
        .map(|buf| parse_group_nickname_map(buf, targets))
        .unwrap_or_default()
}

fn load_group_ext_buffer(conn: &Connection, chat_username: &str) -> Option<Vec<u8>> {
    [
        "SELECT ext_buffer FROM chat_room WHERE username = ? LIMIT 1",
        "SELECT ext_buffer FROM chat_room WHERE chat_room_name = ? LIMIT 1",
        "SELECT ext_buffer FROM chat_room WHERE name = ? LIMIT 1",
    ]
    .iter()
    .find_map(|sql| {
        conn.query_row(sql, [chat_username], |row| row.get::<_, Option<Vec<u8>>>(0))
            .ok()
            .flatten()
    })
}

fn load_group_member_username_set(
    conn: &Connection,
    chat_username: &str,
) -> Option<HashSet<String>> {
    let room_id: i64 = [
        "SELECT id FROM chat_room WHERE username = ?",
        "SELECT id FROM chat_room WHERE chat_room_name = ?",
        "SELECT id FROM chat_room WHERE name = ?",
    ]
    .iter()
    .find_map(|sql| {
        conn.query_row(sql, [chat_username], |row| row.get::<_, i64>(0))
            .ok()
    })
    .unwrap_or(0);

    if room_id == 0 {
        return None;
    }

    let mut stmt = conn
        .prepare(
            "SELECT c.username
         FROM chatroom_member cm
         LEFT JOIN contact c ON c.id = cm.member_id
         WHERE cm.room_id = ?",
        )
        .ok()?;
    let usernames: HashSet<String> = stmt
        .query_map([room_id], |row| row.get::<_, String>(0))
        .ok()?
        .filter_map(|r| r.ok())
        .filter(|uid| !uid.is_empty())
        .collect();

    if usernames.is_empty() {
        None
    } else {
        Some(usernames)
    }
}

fn decode_proto_varint(raw: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut pos = offset;
    while pos < raw.len() {
        let byte = raw[pos];
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn proto_len_fields<'a>(raw: &'a [u8]) -> Vec<(u64, &'a [u8])> {
    let mut fields = Vec::new();
    let mut idx = 0usize;
    while idx < raw.len() {
        let Some((tag, next)) = decode_proto_varint(raw, idx) else {
            break;
        };
        if next <= idx {
            break;
        }
        idx = next;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                let Some((_, next)) = decode_proto_varint(raw, idx) else {
                    break;
                };
                if next <= idx {
                    break;
                }
                idx = next;
            }
            1 => {
                let Some(next) = idx.checked_add(8) else {
                    break;
                };
                if next > raw.len() {
                    break;
                }
                idx = next;
            }
            2 => {
                let Some((size, next)) = decode_proto_varint(raw, idx) else {
                    break;
                };
                if next <= idx {
                    break;
                }
                idx = next;
                let Ok(size) = usize::try_from(size) else {
                    break;
                };
                let Some(end) = idx.checked_add(size) else {
                    break;
                };
                if end > raw.len() {
                    break;
                }
                fields.push((field_no, &raw[idx..end]));
                idx = end;
            }
            5 => {
                let Some(next) = idx.checked_add(4) else {
                    break;
                };
                if next > raw.len() {
                    break;
                }
                idx = next;
            }
            _ => break,
        }
    }
    fields
}

fn proto_string_fields(raw: &[u8]) -> Vec<(u64, String)> {
    proto_len_fields(raw)
        .into_iter()
        .filter_map(|(field_no, value)| {
            if value.is_empty() || value.len() > 256 {
                return None;
            }
            let text = std::str::from_utf8(value).ok()?.trim().to_string();
            if text.is_empty() || text.chars().any(char::is_control) {
                return None;
            }
            Some((field_no, text))
        })
        .collect()
}

fn is_strong_username_hint(value: &str) -> bool {
    value.starts_with("wxid_")
        || value.ends_with("@chatroom")
        || value.starts_with("gh_")
        || value.contains('@')
}

fn looks_like_username(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if is_strong_username_hint(value) {
        return true;
    }
    if value.len() < 6 || value.len() > 32 || value.chars().any(char::is_whitespace) {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn pick_member_username(
    strings: &[(u64, String)],
    targets: Option<&HashSet<String>>,
) -> Option<String> {
    if let Some(targets) = targets {
        return strings
            .iter()
            .find(|(_, value)| targets.contains(value))
            .map(|(_, value)| value.clone());
    }

    for field_no in [1u64, 4u64] {
        if let Some((_, value)) = strings
            .iter()
            .find(|(f, value)| *f == field_no && looks_like_username(value))
        {
            return Some(value.clone());
        }
    }

    strings
        .iter()
        .find(|(_, value)| is_strong_username_hint(value))
        .or_else(|| strings.iter().find(|(_, value)| looks_like_username(value)))
        .map(|(_, value)| value.clone())
}

fn pick_group_nickname(strings: &[(u64, String)], username: &str) -> Option<String> {
    let mut best_score = i64::MIN;
    let mut best = String::new();

    for (idx, (field_no, value)) in strings.iter().enumerate() {
        let value = value.trim();
        if value.is_empty()
            || value == username
            || is_strong_username_hint(value)
            || value.contains('\n')
            || value.contains('\r')
            || value.len() > 64
        {
            continue;
        }

        let mut score = 0i64;
        if *field_no == 2 {
            score += 100;
        }
        if !looks_like_username(value) {
            score += 20;
        }
        score += (32usize.saturating_sub(value.len())) as i64;
        score = score * 1000 - idx as i64;

        if score > best_score {
            best_score = score;
            best = value.to_string();
        }
    }

    if best.is_empty() {
        None
    } else {
        Some(best)
    }
}

fn parse_group_nickname_map(
    ext_buffer: &[u8],
    targets: Option<&HashSet<String>>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if ext_buffer.is_empty() {
        return out;
    }

    for (_, chunk) in proto_len_fields(ext_buffer) {
        let strings = proto_string_fields(chunk);
        if strings.is_empty() {
            continue;
        }
        let Some(username) = pick_member_username(&strings, targets) else {
            continue;
        };
        if out.contains_key(&username) {
            continue;
        }
        if let Some(nickname) = pick_group_nickname(&strings, &username) {
            out.insert(username, nickname);
        }
    }

    out
}

fn contact_display(
    uid: &str,
    nick: &str,
    remark: &str,
    names_map: &HashMap<String, String>,
) -> String {
    if !remark.is_empty() {
        remark.to_string()
    } else if !nick.is_empty() {
        nick.to_string()
    } else {
        names_map
            .get(uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}

fn sender_display(
    username: &str,
    fallback_sender_name: &str,
    names: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
) -> String {
    if username.is_empty() {
        return String::new();
    }
    group_nicknames
        .get(username)
        .filter(|s| !s.is_empty())
        .cloned()
        .or_else(|| names.get(username).cloned())
        .or_else(|| {
            if fallback_sender_name.is_empty() {
                None
            } else {
                Some(fallback_sender_name.to_string())
            }
        })
        .unwrap_or_else(|| username.to_string())
}

fn group_top_senders(
    sender_counts: &HashMap<String, i64>,
    names: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
    limit: usize,
) -> Vec<Value> {
    let mut top_senders: Vec<Value> = sender_counts
        .iter()
        .map(|(username, count)| {
            json!({
                "sender": sender_display(username, "", names, group_nicknames),
                "count": count,
            })
        })
        .collect();
    top_senders.sort_by(|a, b| {
        b["count"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["count"].as_i64().unwrap_or(0))
            .then_with(|| {
                a["sender"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["sender"].as_str().unwrap_or(""))
            })
    });
    top_senders.truncate(limit);
    top_senders
}

fn sender_label(
    real_sender_id: i64,
    content: &str,
    is_group: bool,
    chat_username: &str,
    id2u: &HashMap<i64, String>,
    names: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
) -> String {
    let sender_uname = id2u.get(&real_sender_id).cloned().unwrap_or_default();
    if is_group {
        if !sender_uname.is_empty() && sender_uname != chat_username {
            return sender_display(&sender_uname, "", names, group_nicknames);
        }
        if content.contains(":\n") {
            let raw = content.splitn(2, ":\n").next().unwrap_or("");
            return sender_display(raw, "", names, group_nicknames);
        }
        return String::new();
    }
    if !sender_uname.is_empty() && sender_uname != chat_username {
        return names.get(&sender_uname).cloned().unwrap_or(sender_uname);
    }
    String::new()
}

/// 读取消息内容列（兼容 TEXT 和 BLOB 两种存储类型）
///
/// SQLite 中 message_content 在未压缩时为 TEXT，zstd 压缩后为 BLOB。
/// rusqlite 的 Vec<u8> FromSql 只接受 BLOB，读 TEXT 会静默返回空。
fn get_content_bytes(row: &rusqlite::Row<'_>, idx: usize) -> Vec<u8> {
    // 先尝试 BLOB，再 fallback 到 TEXT→bytes
    row.get::<_, Vec<u8>>(idx)
        .or_else(|_| row.get::<_, String>(idx).map(|s| s.into_bytes()))
        .unwrap_or_default()
}

fn decompress_message(data: &[u8], ct: i64) -> String {
    if ct == 4 && !data.is_empty() {
        // zstd 压缩
        if let Ok(dec) = zstd::decode_all(data) {
            return String::from_utf8_lossy(&dec).into_owned();
        }
    }
    String::from_utf8_lossy(data).into_owned()
}

fn decompress_or_str(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    // 尝试 zstd 解压
    if let Ok(dec) = zstd::decode_all(data) {
        if let Ok(s) = String::from_utf8(dec) {
            return s;
        }
    }
    String::from_utf8_lossy(data).into_owned()
}

fn strip_group_prefix(s: &str) -> String {
    if s.contains(":\n") {
        s.splitn(2, ":\n").nth(1).unwrap_or(s).to_string()
    } else {
        s.to_string()
    }
}

pub fn fmt_type(t: i64) -> String {
    let base = (t as u64 & 0xFFFFFFFF) as i64;
    match base {
        1 => "文本".into(),
        3 => "图片".into(),
        34 => "语音".into(),
        42 => "名片".into(),
        43 => "视频".into(),
        47 => "表情".into(),
        48 => "位置".into(),
        49 => "链接/文件".into(),
        50 => "通话".into(),
        10000 => "系统".into(),
        10002 => "撤回".into(),
        _ => format!("type={}", base),
    }
}

fn fmt_content(local_id: i64, local_type: i64, content: &str, is_group: bool) -> String {
    let base = (local_type as u64 & 0xFFFFFFFF) as i64;
    match base {
        3 => return format!("[图片] local_id={}", local_id),
        34 => return "[语音]".into(),
        43 => return "[视频]".into(),
        47 => return "[表情]".into(),
        50 => return "[通话]".into(),
        10000 => return parse_sysmsg(content).unwrap_or_else(|| "[系统消息]".into()),
        10002 => return parse_revoke(content).unwrap_or_else(|| "[撤回了一条消息]".into()),
        _ => {}
    }

    let text = if is_group && content.contains(":\n") {
        content.splitn(2, ":\n").nth(1).unwrap_or(content)
    } else {
        content
    };

    if base == 49 && text.contains("<appmsg") {
        if let Some(parsed) = parse_appmsg(text) {
            return parsed;
        }
    }
    text.to_string()
}

/// 解析撤回消息 XML，提取被撤回的内容摘要
/// `<sysmsg type="revokemsg"><revokemsg><content>...</content></revokemsg></sysmsg>`
fn parse_revoke(xml: &str) -> Option<String> {
    let inner = extract_xml_text(xml, "content")?;
    // 有时 content 是 "xxx recalled a message" 英文，有时是中文
    if inner.is_empty() {
        return Some("[撤回了一条消息]".into());
    }
    // 尝试简化：如果是 XML 格式的撤回内容，直接显示摘要
    Some(format!(
        "[撤回] {}",
        inner.chars().take(30).collect::<String>()
    ))
}

/// 解析系统消息 XML（群通知等）
fn parse_sysmsg(xml: &str) -> Option<String> {
    // 常见格式：<sysmsg type="...">...</sysmsg>
    // 尝试提取 content 标签
    if let Some(s) = extract_xml_text(xml, "content") {
        if !s.is_empty() {
            return Some(format!("[系统] {}", s.chars().take(50).collect::<String>()));
        }
    }
    // 纯文本系统消息（无 XML）
    if !xml.starts_with('<') {
        return Some(format!(
            "[系统] {}",
            xml.chars().take(50).collect::<String>()
        ));
    }
    Some("[系统消息]".into())
}

fn parse_appmsg(text: &str) -> Option<String> {
    if let Some(parsed) = parse_appmsg_dom(text) {
        return Some(parsed);
    }
    parse_appmsg_legacy(text)
}

fn parse_appmsg_dom(text: &str) -> Option<String> {
    let doc = Document::parse(text).ok()?;
    let appmsg = doc.descendants().find(|node| node.has_tag_name("appmsg"))?;
    let title = xml_text(xml_child(appmsg, "title")).unwrap_or_default();
    let atype = xml_text(xml_child(appmsg, "type")).unwrap_or_default();
    match atype.as_str() {
        "6" => Some(format_file_appmsg(appmsg, &title)),
        "19" => Some(format_record_appmsg(appmsg, &title)),
        _ => None,
    }
}

fn parse_appmsg_legacy(text: &str) -> Option<String> {
    let title = extract_xml_text(text, "title")?;
    let atype = extract_xml_text(text, "type").unwrap_or_default();
    match atype.as_str() {
        "6" => Some(if !title.is_empty() {
            format!("[文件] {}", title)
        } else {
            "[文件]".into()
        }),
        "57" => {
            let ref_content = quote_refermsg_content(text)
                .or_else(|| {
                    extract_xml_text(text, "content").and_then(|s| quote_content_text(&s, 40))
                })
                .unwrap_or_default();
            let quote = if !title.is_empty() {
                format!("[引用] {}", title)
            } else {
                "[引用]".into()
            };
            if !ref_content.is_empty() {
                Some(format!("{}\n  \u{21b3} {}", quote, ref_content))
            } else {
                Some(quote)
            }
        }
        "33" | "36" | "44" => Some(if !title.is_empty() {
            format!("[小程序] {}", title)
        } else {
            "[小程序]".into()
        }),
        _ => Some(if !title.is_empty() {
            format!("[链接] {}", title)
        } else {
            "[链接/文件]".into()
        }),
    }
}

fn format_file_appmsg<'a, 'input>(appmsg: Node<'a, 'input>, title: &str) -> String {
    let mut meta = Vec::new();
    if let Some(size) = xml_child(appmsg, "appattach")
        .and_then(|attach| xml_text(xml_child(attach, "totallen")))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|size| *size > 0)
    {
        meta.push(format_byte_size(size));
    }
    if let Some(ext) = xml_child(appmsg, "appattach")
        .and_then(|attach| xml_text(xml_child(attach, "fileext")))
        .filter(|ext| !ext.is_empty())
    {
        meta.push(ext);
    }

    let base = if !title.is_empty() {
        format!("[文件] {}", title)
    } else {
        "[文件]".into()
    };
    if meta.is_empty() {
        base
    } else {
        format!("{} ({})", base, meta.join(", "))
    }
}

fn format_record_appmsg<'a, 'input>(appmsg: Node<'a, 'input>, title: &str) -> String {
    let items = record_item_lines(appmsg);
    let mut header = if !title.is_empty() {
        format!("[合并聊天记录] {}", title)
    } else {
        "[合并聊天记录]".into()
    };
    if !items.is_empty() {
        header.push_str(&format!(" ({}条)", items.len()));
    }

    let mut lines = vec![header];
    if items.is_empty() {
        if let Some(desc) = xml_text(xml_child(appmsg, "des")).filter(|desc| !desc.is_empty()) {
            lines.push(format!("  {}", collapse_text(&desc, 120)));
        }
    } else {
        for item in items.iter().take(10) {
            lines.push(format!("  - {}", item));
        }
        if items.len() > 10 {
            lines.push(format!("  - ... 还有{}条", items.len() - 10));
        }
    }
    lines.join("\n")
}

fn record_item_lines<'a, 'input>(appmsg: Node<'a, 'input>) -> Vec<String> {
    let mut lines = record_item_lines_from_node(appmsg);
    if !lines.is_empty() {
        return lines;
    }

    let Some(record_xml) =
        xml_text(xml_child(appmsg, "recorditem")).filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    let unescaped = unescape_html(&record_xml);
    for candidate in [&record_xml, &unescaped] {
        if let Ok(doc) = Document::parse(candidate) {
            lines = record_item_lines_from_node(doc.root_element());
            if !lines.is_empty() {
                break;
            }
        }
    }
    lines
}

fn record_item_lines_from_node<'a, 'input>(node: Node<'a, 'input>) -> Vec<String> {
    node.descendants()
        .filter(|child| child.has_tag_name("dataitem"))
        .filter_map(format_record_item)
        .collect()
}

fn format_record_item<'a, 'input>(item: Node<'a, 'input>) -> Option<String> {
    let name = first_child_text(item, &["sourcename", "datasrcname", "sourceusername"]);
    let desc = first_child_text(item, &["datadesc", "datatitle", "datafmt"]).or_else(|| {
        item.attribute("datatype")
            .and_then(record_datatype_label)
            .map(str::to_string)
    })?;
    let desc = collapse_text(&desc, 100);
    if let Some(name) = name.filter(|value| !value.is_empty()) {
        Some(format!("{}: {}", name, desc))
    } else {
        Some(desc)
    }
}

fn first_child_text<'a, 'input>(node: Node<'a, 'input>, tags: &[&str]) -> Option<String> {
    tags.iter()
        .find_map(|tag| xml_text(xml_child(node, tag)))
        .filter(|value| !value.is_empty())
}

fn record_datatype_label(datatype: &str) -> Option<&'static str> {
    match datatype {
        "1" => Some("[文本]"),
        "2" => Some("[图片]"),
        "3" => Some("[语音]"),
        "4" => Some("[视频]"),
        "6" => Some("[文件]"),
        "17" => Some("[链接]"),
        _ => None,
    }
}

fn quote_refermsg_content(text: &str) -> Option<String> {
    let refer = extract_xml_text(text, "refermsg")?;
    let content = extract_xml_text(&refer, "content")
        .and_then(|s| quote_content_text(&s, 80))
        .or_else(|| {
            extract_xml_text(&refer, "type")
                .and_then(|t| quote_refermsg_type_label(&t).map(str::to_string))
        })?;
    match extract_xml_text(&refer, "displayname") {
        Some(name) if !name.is_empty() => Some(format!("{}: {}", name, content)),
        _ => Some(content),
    }
}

fn quote_content_text(raw: &str, max_chars: usize) -> Option<String> {
    let unescaped = unescape_html(raw);
    if unescaped.contains("<appmsg") {
        if let Some(parsed) = parse_appmsg(&unescaped) {
            return Some(parsed);
        }
    }
    let collapsed = collapse_text(&unescaped, max_chars);
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

fn quote_refermsg_type_label(t: &str) -> Option<&'static str> {
    match t {
        "1" => None,
        "3" => Some("[图片]"),
        "34" => Some("[语音]"),
        "43" => Some("[视频]"),
        "47" => Some("[表情]"),
        "49" => Some("[链接/文件]"),
        _ => None,
    }
}

fn collapse_text(text: &str, max_chars: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > max_chars {
        format!(
            "{}...",
            collapsed.chars().take(max_chars).collect::<String>()
        )
    } else {
        collapsed
    }
}

fn format_byte_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format_decimal_unit(bytes_f / GB, "GB")
    } else if bytes_f >= MB {
        format_decimal_unit(bytes_f / MB, "MB")
    } else if bytes_f >= KB {
        format_decimal_unit(bytes_f / KB, "KB")
    } else {
        format!("{} B", bytes)
    }
}

fn format_decimal_unit(value: f64, unit: &str) -> String {
    let mut s = format!("{:.1}", value);
    if s.ends_with(".0") {
        s.truncate(s.len() - 2);
    }
    format!("{} {}", s, unit)
}

fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let content_start = start + open.len();
    let end = xml[content_start..].find(&close)?;
    Some(xml[content_start..content_start + end].trim().to_string())
}

fn appmsg_url_for_message(local_type: i64, content: &str) -> Option<String> {
    if (local_type as u64 & 0xFFFFFFFF) != 49 {
        return None;
    }
    extract_appmsg_url(content)
}

fn extract_favorite_url(content: &str) -> Option<String> {
    let url = extract_xml_text(content, "link").map(|s| unescape_html(strip_xml_cdata(&s)))?;
    if url.is_empty() || !(url.starts_with("http://") || url.starts_with("https://")) {
        return None;
    }
    Some(url)
}

fn strip_xml_cdata(s: &str) -> &str {
    s.strip_prefix("<![CDATA[")
        .and_then(|inner| inner.strip_suffix("]]>"))
        .unwrap_or(s)
}

/// 从 appmsg XML 中提取链接 URL（优先取 <url>，fallback 到 <url1>）
fn extract_appmsg_url(text: &str) -> Option<String> {
    let xml = strip_group_prefix(text);
    if !xml.contains("<appmsg") {
        return None;
    }
    if extract_xml_text(&xml, "type").as_deref() == Some("57") {
        return None;
    }
    let url = extract_xml_text(&xml, "url")
        .or_else(|| extract_xml_text(&xml, "url1"))
        .map(|s| unescape_html(strip_xml_cdata(&s)))?;
    if url.is_empty() || !(url.starts_with("http://") || url.starts_with("https://")) {
        return None;
    }
    Some(url)
}

fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let start = xml.find(&open)?;
    let tag_end = start + xml[start..].find('>')?;
    let attr_pat = format!(r#"{}=""#, attr);
    let attr_start = start + xml[start..tag_end].find(&attr_pat)? + attr_pat.len();
    let attr_end = attr_start + xml[attr_start..tag_end].find('"')?;
    let value = xml[attr_start..attr_end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn unescape_html(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod appmsg_tests {
    use super::*;

    #[test]
    fn parse_forwarded_chat_record_expands_record_items() {
        let xml = r#"
<msg>
  <appmsg appid="" sdkver="0">
    <title>群聊的聊天记录</title>
    <des>张三: 早上好
李四: 收到</des>
    <type>19</type>
    <recorditem>&lt;recordinfo&gt;&lt;datalist count="2"&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;张三&lt;/sourcename&gt;&lt;sourcetime&gt;1710000000&lt;/sourcetime&gt;&lt;datadesc&gt;早上好 &amp;amp; coffee&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;dataitem datatype="2"&gt;&lt;sourcename&gt;李四&lt;/sourcename&gt;&lt;sourcetime&gt;1710000060&lt;/sourcetime&gt;&lt;datafmt&gt;图片&lt;/datafmt&gt;&lt;datadesc&gt;[图片]&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem>
  </appmsg>
</msg>
        "#;

        assert_eq!(
            parse_appmsg(xml).as_deref(),
            Some(
                "[合并聊天记录] 群聊的聊天记录 (2条)\n  - 张三: 早上好 & coffee\n  - 李四: [图片]"
            )
        );
    }

    #[test]
    fn parse_file_appmsg_includes_attachment_metadata() {
        let xml = r#"
<msg>
  <appmsg appid="" sdkver="0">
    <title>report.pdf</title>
    <type>6</type>
    <appattach>
      <totallen>1536</totallen>
      <fileext>pdf</fileext>
    </appattach>
    <md5>abcdef123456</md5>
  </appmsg>
</msg>
        "#;

        assert_eq!(
            parse_appmsg(xml).as_deref(),
            Some("[文件] report.pdf (1.5 KB, pdf)")
        );
    }

    #[test]
    fn parse_quote_appmsg_reads_refermsg_content() {
        let xml = r#"
<msg>
  <appmsg appid="" sdkver="0">
    <title>我也没有用ai啊</title>
    <type>57</type>
    <content />
    <refermsg>
      <type>1</type>
      <displayname>不再熬夜</displayname>
      <content>昨天用 claude 爬小红书数据来着</content>
    </refermsg>
  </appmsg>
</msg>
        "#;

        assert_eq!(
            parse_appmsg(xml).as_deref(),
            Some("[引用] 我也没有用ai啊\n  \u{21b3} 不再熬夜: 昨天用 claude 爬小红书数据来着")
        );
    }

    #[test]
    fn query_messages_filters_appmsg_by_base_type() {
        // 这里用一个纯本地明文临时库测试 `query_messages` 的过滤/解析逻辑，
        // 与"打开加密微信库"完全无关，所以保留 `Connection::open` 直连，不
        // 走 `DbCache::conn_params`/VFS。签名改为 `&Connection` 后，这里改成
        // 显式建连后传引用即可。
        let path = temp_db_path("query_messages_filters_appmsg_by_base_type");
        let conn = Connection::open(&path).expect("open temp db");
        conn.execute(
            "CREATE TABLE Msg_test (
                local_id INTEGER,
                local_type INTEGER,
                create_time INTEGER,
                real_sender_id INTEGER,
                message_content TEXT,
                WCDB_CT_message_content INTEGER
            )",
            [],
        )
        .expect("create message table");
        conn.execute(
            "INSERT INTO Msg_test VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                1_i64,
                ((57_i64) << 32) | 49_i64,
                1775146911_i64,
                0_i64,
                r#"<msg><appmsg><title>我也没有用ai啊</title><type>57</type><content /><refermsg><displayname>不再熬夜</displayname><content>昨天用 claude 爬小红书数据来着</content></refermsg></appmsg></msg>"#,
                0_i64
            ],
        )
        .expect("insert quote message");

        let rows = query_messages(
            &conn,
            "Msg_test",
            "wxid_r605h38n08mv22",
            false,
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            Some(49),
            10,
            0,
        )
        .expect("query messages");

        drop(conn);
        let _ = std::fs::remove_file(&path);

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["content"].as_str(),
            Some("[引用] 我也没有用ai啊\n  \u{21b3} 不再熬夜: 昨天用 claude 爬小红书数据来着")
        );
    }

    #[test]
    fn search_in_table_filters_appmsg_by_base_type() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute(
            "CREATE TABLE Msg_test (
                local_id INTEGER,
                local_type INTEGER,
                create_time INTEGER,
                real_sender_id INTEGER,
                message_content TEXT,
                WCDB_CT_message_content INTEGER
            )",
            [],
        )
        .expect("create message table");
        conn.execute(
            "INSERT INTO Msg_test VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                1_i64,
                ((57_i64) << 32) | 49_i64,
                1775146911_i64,
                0_i64,
                r#"<msg><appmsg><title>我也没有用ai啊</title><type>57</type><content /><refermsg><displayname>不再熬夜</displayname><content>昨天用 claude 爬小红书数据来着</content></refermsg></appmsg></msg>"#,
                0_i64
            ],
        )
        .expect("insert quote message");

        let rows = search_in_table(
            &conn,
            "Msg_test",
            "wxid_r605h38n08mv22",
            false,
            &HashMap::new(),
            &HashMap::new(),
            "claude",
            None,
            None,
            Some(49),
            10,
        )
        .expect("search messages");

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["content"].as_str(),
            Some("[引用] 我也没有用ai啊\n  \u{21b3} 不再熬夜: 昨天用 claude 爬小红书数据来着")
        );
    }

    #[test]
    fn search_in_table_matches_decompressed_formatted_appmsg_content() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute(
            "CREATE TABLE Msg_test (
                local_id INTEGER,
                local_type INTEGER,
                create_time INTEGER,
                real_sender_id INTEGER,
                message_content BLOB,
                WCDB_CT_message_content INTEGER
            )",
            [],
        )
        .expect("create message table");
        let xml = r#"<msg><appmsg><title>我也没有用ai啊</title><type>57</type><content /><refermsg><displayname>不再熬夜</displayname><content>昨天用 claude 爬小红书数据来着</content></refermsg></appmsg></msg>"#;
        let compressed = zstd::encode_all(xml.as_bytes(), 0).expect("compress appmsg xml");
        conn.execute(
            "INSERT INTO Msg_test VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                1_i64,
                ((57_i64) << 32) | 49_i64,
                1775146911_i64,
                0_i64,
                compressed,
                4_i64
            ],
        )
        .expect("insert compressed quote message");

        let rows = search_in_table(
            &conn,
            "Msg_test",
            "wxid_r605h38n08mv22",
            false,
            &HashMap::new(),
            &HashMap::new(),
            "claude",
            None,
            None,
            Some(49),
            10,
        )
        .expect("search messages");

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["content"].as_str(),
            Some("[引用] 我也没有用ai啊\n  \u{21b3} 不再熬夜: 昨天用 claude 爬小红书数据来着")
        );
    }

    fn temp_db_path(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "wxeasy-{}-{}-{}.db",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before unix epoch")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }
}

fn fmt_time(ts: i64, fmt: &str) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format(fmt).to_string())
        .unwrap_or_else(|| ts.to_string())
}

// ─── 新增命令查询函数 ──────────────────────────────────────────────────────────

/// 查询有未读消息的会话
///
/// `filter`：按 chat_type 过滤，None 或空 Vec 等价于 "all"。
/// 可选值：`private` / `group` / `official` / `folded` / `all`。
/// 多选支持在 CLI 层用逗号分隔后传入多个元素。
pub async fn q_unread(
    db: &DbCache,
    names: &Names,
    limit: usize,
    filter: Option<Vec<String>>,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    let conn_params = db
        .conn_params("session/session.db")
        .context("无法解密 session.db")?;

    // 归一化 filter：小写 + 去除别名。返回 None 代表"不过滤"。
    let filter_set: Option<std::collections::HashSet<&'static str>> = filter.and_then(|v| {
        let mut set = std::collections::HashSet::new();
        for raw in v {
            match raw.trim().to_lowercase().as_str() {
                "" | "all" => return None,
                "private" => {
                    set.insert("private");
                }
                "group" => {
                    set.insert("group");
                }
                "official" | "official_account" => {
                    set.insert("official_account");
                }
                "folded" | "fold" => {
                    set.insert("folded");
                }
                _ => {} // 未知值忽略，避免拼错导致什么都不返回
            }
        }
        if set.is_empty() {
            None
        } else {
            Some(set)
        }
    });

    // 有 filter 时必须全表扫：SQL LIMIT 会把想要的公众号先筛掉。
    // 无 filter 时保留 LIMIT，避免重度用户的大量未读会话拖慢默认路径。
    let has_filter = filter_set.is_some();
    let limit_val = limit;
    let rows: Vec<(String, i64, Vec<u8>, i64, i64, String, String)> =
        tokio::task::spawn_blocking(move || {
            let conn = conn_params.open()?;
            let sql = if has_filter {
                "SELECT username, unread_count, summary, last_timestamp,
                    last_msg_type, last_msg_sender, last_sender_display_name
             FROM SessionTable WHERE unread_count > 0
             ORDER BY last_timestamp DESC"
            } else {
                "SELECT username, unread_count, summary, last_timestamp,
                    last_msg_type, last_msg_sender, last_sender_display_name
             FROM SessionTable WHERE unread_count > 0
             ORDER BY last_timestamp DESC LIMIT ?"
            };
            let mut stmt = conn.prepare(sql)?;
            let map_row = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1).unwrap_or(0),
                    get_content_bytes(row, 2),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, i64>(4).unwrap_or(0),
                    row.get::<_, String>(5).unwrap_or_default(),
                    row.get::<_, String>(6).unwrap_or_default(),
                ))
            };
            let rows = if has_filter {
                stmt.query_map([], map_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                stmt.query_map([limit_val as i64], map_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            Ok::<_, anyhow::Error>(rows)
        })
        .await??;

    let mut results = Vec::new();
    let mut group_nickname_cache: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (username, unread, summary_bytes, ts, msg_type, sender, sender_name) in rows {
        let chat_type = chat_type_of(&username, names);
        if let Some(ref set) = filter_set {
            if !set.contains(chat_type) {
                continue;
            }
        }
        if results.len() >= limit {
            break;
        }

        let display = names.display(&username);
        let is_group = chat_type == "group";
        let summary = decompress_or_str(&summary_bytes);
        let summary = strip_group_prefix(&summary);
        let sender_display = if is_group && !sender.is_empty() {
            if !group_nickname_cache.contains_key(&username) {
                let nicknames = load_group_nicknames(db, &username)
                    .await
                    .unwrap_or_default();
                group_nickname_cache.insert(username.clone(), nicknames);
            }
            let empty = HashMap::new();
            let group_nicknames = group_nickname_cache.get(&username).unwrap_or(&empty);
            sender_display(&sender, &sender_name, &names.map, group_nicknames)
        } else {
            String::new()
        };
        results.push(json!({
            "chat": display,
            "username": username,
            "is_group": is_group,
            "chat_type": chat_type,
            "unread": unread,
            "last_msg_type": fmt_type(msg_type),
            "last_sender": sender_display,
            "summary": summary,
            "timestamp": ts,
            "time": fmt_time(ts, "%m-%d %H:%M"),
        }));
    }
    let total = results.len();
    let latest_ts = results
        .first()
        .and_then(|v| v.get("timestamp"))
        .and_then(|v| v.as_i64());
    let unknown_shards = current_unknown_shards(db, names);
    let meta = Meta {
        chat_latest_timestamp: latest_ts,
        chat_latest_db: latest_ts.map(|_| "session/session.db".to_string()),
        session_last_timestamp: None,
        shards_scanned: 0,
        shards_hit: 0,
        unknown_shards: unknown_shards.clone(),
        status: derive_status(latest_ts, None, &unknown_shards, false),
        per_shard_latest: if with_meta || debug_source {
            Some(HashMap::new())
        } else {
            None
        },
        cache_mode_per_shard: None,
        shard_paths: None,
    };
    Ok(json!({ "sessions": results, "total": total, "meta": meta }))
}

/// 查询群成员：优先从 contact.db 的 chatroom_member/chat_room 表获取完整列表，
/// 若表不存在则退化为从消息记录聚合有发言记录的成员
pub async fn q_members(db: &DbCache, names: &Names, chat: &str) -> Result<Value> {
    let username =
        resolve_username(chat, names).with_context(|| format!("找不到联系人: {}", chat))?;

    if !username.contains("@chatroom") {
        anyhow::bail!("'{}' 不是群聊，无法查看群成员", names.display(&username));
    }

    let display = names.display(&username);
    let names_map = names.map.clone();

    // 优先路径：contact.db → chatroom_member + chat_room（完整成员列表）
    if let Ok(conn_params) = db.conn_params("contact/contact.db") {
        let uname2 = username.clone();
        let names_map2 = names_map.clone();

        let members_opt: Option<Vec<Value>> = tokio::task::spawn_blocking(move || {
            let conn = conn_params.open()?;

            let has_table: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='chatroom_member'",
                    [],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if !has_table {
                return Ok::<_, anyhow::Error>(None);
            }

            // 从 chat_room 表获取整数 room_id 和群主
            // WeChat 不同版本列名可能不同：username / chat_room_name / name
            let (room_id, owner): (i64, String) = [
                "SELECT id, owner FROM chat_room WHERE username = ?",
                "SELECT id, owner FROM chat_room WHERE chat_room_name = ?",
                "SELECT id, owner FROM chat_room WHERE name = ?",
            ]
            .iter()
            .find_map(|sql| {
                conn.query_row(sql, [&uname2], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1).unwrap_or_default(),
                    ))
                })
                .ok()
            })
            .unwrap_or((0, String::new()));

            if room_id == 0 {
                return Ok::<_, anyhow::Error>(None);
            }

            let mut stmt = conn.prepare(
                "SELECT c.username, c.nick_name, c.remark
                 FROM chatroom_member cm
                 LEFT JOIN contact c ON c.id = cm.member_id
                 WHERE cm.room_id = ?",
            )?;
            let raw: Vec<(String, String, String)> = stmt
                .query_map([room_id], |row| {
                    Ok((
                        row.get::<_, String>(0).unwrap_or_default(),
                        row.get::<_, String>(1).unwrap_or_default(),
                        row.get::<_, String>(2).unwrap_or_default(),
                    ))
                })?
                .filter_map(|r| r.ok())
                .filter(|(uid, _, _)| !uid.is_empty())
                .collect();

            if raw.is_empty() {
                return Ok(None);
            }

            let target_usernames: HashSet<String> =
                raw.iter().map(|(uid, _, _)| uid.clone()).collect();
            let group_nicknames =
                load_group_nickname_map_from_conn(&conn, &uname2, Some(&target_usernames));

            let mut members: Vec<Value> = raw
                .iter()
                .map(|(uid, nick, remark)| {
                    let contact_display = contact_display(uid, nick, remark, &names_map2);
                    let group_nickname = group_nicknames.get(uid).cloned().unwrap_or_default();
                    let disp = if group_nickname.is_empty() {
                        contact_display.clone()
                    } else {
                        group_nickname.clone()
                    };
                    let is_owner = uid == &owner && !owner.is_empty();
                    json!({
                        "username": uid,
                        "display": disp,
                        "contact_display": contact_display,
                        "group_nickname": group_nickname,
                        "is_owner": is_owner,
                    })
                })
                .collect();

            // 群主排首位，其余按 display 字典序
            members.sort_by(|a, b| {
                let ao = a["is_owner"].as_bool().unwrap_or(false);
                let bo = b["is_owner"].as_bool().unwrap_or(false);
                if ao != bo {
                    return bo.cmp(&ao);
                }
                a["display"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["display"].as_str().unwrap_or(""))
            });

            Ok(Some(members))
        })
        .await??;

        if let Some(members) = members_opt {
            return Ok(json!({
                "chat": display,
                "username": username,
                "count": members.len(),
                "members": members,
            }));
        }
    }

    // 降级路径：从消息记录中聚合发言过的成员
    let tables = find_msg_tables(db, names, &username).await?;
    if tables.is_empty() {
        return Ok(json!({
            "chat": display,
            "username": username,
            "count": 0,
            "members": [],
        }));
    }

    let mut sender_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (rel_key, table_name) in &tables {
        // FIX 4：`tables` 来自 `find_msg_tables` → `find_msg_shards`，后者
        // 已经用 `hot_conn_handle_with_snapshot` 为这个 rel_key 开过（或
        // 复用过）一次热连接。这里改用 `hot_conn_handle` 复用同一个槽位，
        // 消除原本 `conn_params.open()` 造成的第二次物理打开。
        let hot = match db.hot_conn_handle(rel_key) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let tname = table_name.clone();
        let uname = username.clone();

        let senders: Vec<String> = tokio::task::spawn_blocking(move || {
            hot.with(|conn| {
                let id2u = load_id2u(conn);
                let mut stmt = conn.prepare(&format!(
                    "SELECT DISTINCT real_sender_id FROM [{}] WHERE real_sender_id > 0",
                    tname
                ))?;
                let ids: Vec<i64> = stmt
                    .query_map([], |row| row.get(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                let senders: Vec<String> = ids
                    .iter()
                    .filter_map(|id| id2u.get(id))
                    .filter(|u| *u != &uname)
                    .cloned()
                    .collect();
                Ok::<_, anyhow::Error>(senders)
            })
        })
        .await??;

        sender_set.extend(senders);
    }

    let group_nicknames = load_group_nicknames(db, &username)
        .await
        .unwrap_or_default();
    let mut members: Vec<Value> = sender_set
        .iter()
        .map(|u| {
            let contact_display = names_map.get(u).cloned().unwrap_or_else(|| u.clone());
            let group_nickname = group_nicknames.get(u).cloned().unwrap_or_default();
            let display = if group_nickname.is_empty() {
                contact_display.clone()
            } else {
                group_nickname.clone()
            };
            json!({
                "username": u,
                "display": display,
                "contact_display": contact_display,
                "group_nickname": group_nickname,
                "is_owner": false,
            })
        })
        .collect();
    members.sort_by(|a, b| {
        a["display"]
            .as_str()
            .unwrap_or("")
            .cmp(b["display"].as_str().unwrap_or(""))
    });

    Ok(json!({
        "chat": display,
        "username": username,
        "count": members.len(),
        "members": members,
    }))
}

/// FIX-HIGH（新会话覆盖漏洞）：计算 `q_new_messages` 本轮需要强制作废的
/// 消息分片集合。
///
/// 对每个 `changed` 会话尝试用 `route_shard_for_table` 反查其 `Msg_<md5>`
/// 表当前记录在哪个（些）分片的路由缓存里：
/// - 能定位到 → 精准加入该分片（对应旧版 FIX 1 的行为，覆盖"已知会话，
///   缓存里有记录"的稳态）。
/// - 定位不到（`route_shard_for_table` 返回空——典型是全新会话，其
///   `Msg_<md5>` 表从未出现在任何缓存的 `ShardSchemaEntry.msg_tables` 里）
///   → 记一次"unresolved"，不单独处理这个会话。
///
/// # 性能护栏（必须保持）
/// 全量作废（返回值退化为 `all_msg_db_keys` 全集）**只在本轮确实存在至少
/// 一个 unresolved 的 changed 会话时触发一次**——绝不能因为"处理了一个全
/// 新会话"就连带对每一轮都做全量 nuke。稳态下（`changed` 全是已知会话、
/// 都能精准定位到承载分片）只返回精准命中的分片集合，不触碰
/// `all_msg_db_keys` 里任何一个无关分片，缓存命中率不受影响——这是唯一
/// 允许存在的 `if` 分支，新增逻辑时不能绕过它。
///
/// 纯函数、同步、只读（`route_shard_for_table` 内部只做一次 `Mutex` 加锁
/// 后的内存线性扫描，不做任何 I/O），不涉及任何 `.await`，可以在单元测试
/// 里直接调用、不需要真实 session.db。
fn shards_to_force_invalidate(
    db: &DbCache,
    changed: &[(String, i64)],
    all_msg_db_keys: &[String],
) -> HashSet<String> {
    let mut resolved: HashSet<String> = HashSet::new();
    let mut has_unresolved = false;
    for (uname, _) in changed {
        let table_name = format!("Msg_{:x}", md5::compute(uname.as_bytes()));
        let carrying = db.route_shard_for_table(&table_name);
        if carrying.is_empty() {
            has_unresolved = true;
        } else {
            resolved.extend(carrying);
        }
    }
    if has_unresolved {
        // 性能护栏：只有这一个分支会返回全集，且只在本轮真的存在 unresolved
        // 会话时才走到这里。
        all_msg_db_keys.iter().cloned().collect()
    } else {
        resolved
    }
}

/// [`shards_to_force_invalidate`] 的单元测试：只依赖 `DbCache` 的路由缓存
/// 这层内存 bookkeeping（`put_shard_schema` / `route_shard_for_table`），
/// 不需要构造真实的 session.db 或消息分片文件——`route_shard_for_table`
/// 本身只做内存 `HashMap` 查找，`SourceSnapshot` 的具体数值在这里无关紧要。
#[cfg(test)]
mod force_invalidate_tests {
    use super::super::cache::test_support::unique_tmpdir;
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

    fn msg_table_name(uname: &str) -> String {
        format!("Msg_{:x}", md5::compute(uname.as_bytes()))
    }

    /// 性能护栏的正向证明：`changed` 里全部是"已知会话"（`route_shard_for_table`
    /// 都能精准定位到承载分片）时，只返回这些精准命中的分片，绝不触碰
    /// `all_msg_db_keys` 里其它无关（甚至从未被扫描过）的分片。
    #[tokio::test]
    async fn all_known_changed_sessions_only_invalidate_their_precise_shards() {
        let db = empty_cache("force-inv-known").await;

        let alice_table = msg_table_name("alice");
        let bob_table = msg_table_name("bob");

        let mut tables0 = HashSet::new();
        tables0.insert(alice_table.clone());
        db.put_shard_schema(
            "message_0.db".to_string(),
            db.source_snapshot("message_0.db"),
            tables0,
            db.route_generation(),
        );

        let mut tables1 = HashSet::new();
        tables1.insert(bob_table.clone());
        db.put_shard_schema(
            "message_1.db".to_string(),
            db.source_snapshot("message_1.db"),
            tables1,
            db.route_generation(),
        );

        let changed = vec![("alice".to_string(), 1_i64), ("bob".to_string(), 2_i64)];
        let all_msg_db_keys = vec![
            "message_0.db".to_string(),
            "message_1.db".to_string(),
            // message_2.db 从未被扫描、从未出现在任何路由缓存条目里——
            // 代表一个休眠、不相关的分片，绝不应该被牵连作废。
            "message_2.db".to_string(),
        ];

        let got = shards_to_force_invalidate(&db, &changed, &all_msg_db_keys);

        let expected: HashSet<String> =
            ["message_0.db".to_string(), "message_1.db".to_string()]
                .into_iter()
                .collect();
        assert_eq!(
            got, expected,
            "changed 全为已知会话时只应精准作废承载分片，不能牵连无关分片 message_2.db"
        );
    }

    /// FIX-HIGH 核心场景：`changed` 里存在至少一个"定位不到承载分片"的会话
    /// （全新会话）时，必须退化为对 `all_msg_db_keys` 全集作废——即便另一个
    /// 会话本身是已知的、能精准定位。
    #[tokio::test]
    async fn unresolved_new_session_forces_full_invalidate_of_all_msg_shards() {
        let db = empty_cache("force-inv-unresolved").await;

        let alice_table = msg_table_name("alice");
        let mut tables0 = HashSet::new();
        tables0.insert(alice_table.clone());
        db.put_shard_schema(
            "message_0.db".to_string(),
            db.source_snapshot("message_0.db"),
            tables0,
            db.route_generation(),
        );

        // "charlie" 是全新会话：它的 Msg_<md5> 表从未被任何 put_shard_schema
        // 记录过，route_shard_for_table 对它必然返回空。
        let changed = vec![
            ("alice".to_string(), 1_i64),
            ("charlie".to_string(), 2_i64),
        ];
        let all_msg_db_keys = vec![
            "message_0.db".to_string(),
            "message_1.db".to_string(),
            "message_2.db".to_string(),
        ];

        let got = shards_to_force_invalidate(&db, &changed, &all_msg_db_keys);

        let expected: HashSet<String> = all_msg_db_keys.iter().cloned().collect();
        assert_eq!(
            got, expected,
            "存在至少一个定位不到承载分片的 changed 会话时，必须退化为全量作废"
        );
    }

    /// 边界情况：`changed` 为空时不应 panic，也不应误触发全量作废（虽然
    /// `q_new_messages` 实际会在更早的 `changed.is_empty()` 分支直接返回，
    /// 这里独立验证函数自身在这个输入上的行为是良定义的）。
    #[tokio::test]
    async fn empty_changed_returns_empty_set() {
        let db = empty_cache("force-inv-empty").await;
        let all_msg_db_keys = vec!["message_0.db".to_string()];
        let got = shards_to_force_invalidate(&db, &[], &all_msg_db_keys);
        assert!(got.is_empty());
    }

    /// 多个 unresolved 会话、且已知会话精准命中了多个不同分片时，返回值
    /// 仍然是"全部 all_msg_db_keys"，而不是"已知会话命中的分片 ∪ 猜测"——
    /// 证明 unresolved 分支完全替换掉精准命中结果，语义上不是简单并集。
    #[tokio::test]
    async fn full_invalidate_returns_exactly_all_keys_not_a_union() {
        let db = empty_cache("force-inv-exact").await;

        let alice_table = msg_table_name("alice");
        let mut tables0 = HashSet::new();
        tables0.insert(alice_table);
        db.put_shard_schema(
            "message_0.db".to_string(),
            db.source_snapshot("message_0.db"),
            tables0,
            db.route_generation(),
        );

        let changed = vec![
            ("alice".to_string(), 1_i64),
            ("new_one".to_string(), 2_i64),
            ("new_two".to_string(), 3_i64),
        ];
        let all_msg_db_keys = vec![
            "message_0.db".to_string(),
            "message_1.db".to_string(),
            "message_2.db".to_string(),
            "message_3.db".to_string(),
        ];

        let got = shards_to_force_invalidate(&db, &changed, &all_msg_db_keys);
        let expected: HashSet<String> = all_msg_db_keys.iter().cloned().collect();
        assert_eq!(got, expected, "全量作废时结果必须恰好等于 all_msg_db_keys 全集");
        assert_eq!(got.len(), 4);
    }
}

/// [`q_new_messages`] 聚合执行专用的会话上下文：展示名 / 会话类型 / 群昵称 /
/// 本轮增量下界，按会话预先算好一次，供按分片聚合查询时复用——群昵称需要
/// 独立一次 `contact.db` async 查询（[`load_group_nicknames`]），在这里统一
/// 按会话预取一次，避免在按分片的循环里对同一会话重复触发。
struct SessionCtx {
    display: String,
    chat_type: &'static str,
    is_group: bool,
    group_nicknames: HashMap<String, String>,
    since_ts: i64,
}

/// [`aggregate_new_messages_by_shard`] 里，单个分片单个命中会话的一次消息
/// 查询任务：把 [`SessionCtx`] 里"整个 changed 批次共享一次"的字段与
/// "这次任务专属"的 `table` 打包成拥有型数据，供 move 进 `spawn_blocking`
/// 闭包（同一个分片承载的全部任务在**同一次**闭包调用里依次跑完，见函数
/// 文档"为什么必须在同一个 hot.with() 闭包内做完发现 + 查询"一节）。
struct ShardMessageJob {
    uname: String,
    table: String,
    since_ts: i64,
    display: String,
    chat_type: &'static str,
    is_group: bool,
    group_nicknames: HashMap<String, String>,
}

/// [`aggregate_new_messages_by_shard`] 的返回值：聚合后的消息，与按分片的
/// 诊断 bookkeeping（对齐 [`q_new_messages`] 原本从逐会话 `find_msg_shards`
/// 返回值里手工攒出来的同名字段，语义差异见函数文档最后一节）。
#[derive(Default)]
struct NewMessagesShardAggregate {
    messages: Vec<Value>,
    scanned_rel_keys: HashSet<String>,
    hit_rel_keys: HashSet<String>,
    cache_modes: HashMap<String, String>,
    shard_paths: HashMap<String, String>,
    /// 仅用于日志：本轮真正触发过 I/O（进入 `hot_conn_handle_with_snapshot`
    /// 及之后）的分片数。
    scanned_shards: usize,
    /// 仅用于日志：按 mtime 判定安全跳过、未触发任何 I/O 的分片数。
    skipped_shards: usize,
}

/// FIX 1（聚合执行，替代原来"逐会话调用 [`find_msg_shards`] + 逐会话再次
/// `hot_conn_handle` 查消息"这两步分离的执行路径）：把本轮 `changed` 全部
/// 会话按承载分片聚合，每个分片只 open（或复用）一次热连接，在**同一次**
/// `hot.with()` 闭包内依次查完它承载的全部 changed 会话的消息——每个 dirty
/// 分片本轮的 open 次数从 `2×C`（C 为 changed 会话数）降到 1。
///
/// # 为什么必须在同一个 `hot.with()` 闭包内做完"发现 + 查询"
/// [`SourceSnapshot::trusted_as_of`]（600 秒 slack）意味着：一个分片只要
/// 最近（< 600s）被 WeChat 写过——这正是它承载的会话出现在 `changed` 里的
/// 原因——它的热连接就"永远不被信任"，任何两次独立的
/// [`super::cache::HotConnHandle::with`] 调用之间都会强制重建一次，哪怕两次
/// 调用之间数据完全没变、间隔只有几毫秒；门控看的是《快照年龄》而不是
/// 《两次调用之间是否真的有变化》。所以哪怕把"schema 发现"和"消息查询"
/// 分成两次挨着的 `.with()` 调用，同一个 dirty 分片依然会被 open 两次——
/// 唯一能把单个分片的开销压到 1 次的办法，是让 schema 发现（`need_rebuild`
/// 时的 `sqlite_master` 扫描）与这个分片承载的全部匹配会话的消息查询共享
/// 同一次 `hot.with()` 闭包、同一个已经建立好的 `&Connection` 引用。
///
/// # 与 [`find_msg_shards`] 共享、且严格不放宽的判据
/// 新鲜度 skip（[`shard_skippable`]）、路由缓存 Fresh/Stale
/// （`DbCache::shard_route_lookup_with_snapshot`）、`expected_generation`
/// TOCTOU 保护（`DbCache::put_shard_schema`）、热连接门控
/// （`DbCache::hot_conn_handle_with_snapshot` + `HotConnHandle::with`）逐条
/// 保持不变——这里只是把"对哪个分片做判定"的粒度从"每个会话各自遍历全部
/// 分片"改成"遍历一次全部分片，每个分片内部一次性匹配、一次性查询本轮
/// 全部相关会话"。唯一的差异：`shard_skippable` 的 `since` 参数改用本轮
/// 全部会话 `since_ts` 的**最小值**（最保守下界）——只要某分片按这个最
/// 保守下界都判定不可能有新消息，对"since 更晚"的会话（下界更高、要求更
/// 严格）自然也不可能有，不会漏判；代价仅仅是个别分片本可以对部分会话更早
/// 跳过、现在没跳过，不产生正确性问题。
///
/// # 与旧执行路径的输出差异（仅限诊断字段，非功能字段）
/// `scanned_rel_keys` / `cache_modes` / `shard_paths` 判定"一个分片是否算
/// 命中"时，旧路径经 `find_msg_shards` 内部一次额外的
/// `SELECT MAX(create_time)` 确认"目标表存在且至少有一行"；这里为了不做
/// 那次纯诊断用途的额外查询，改用"目标表存在于该分片的 `sqlite_master`
/// （或缓存的 `msg_tables`）"作为判定条件——唯一的差异场景是"表存在但恰好
/// 零行"（旧路径的 `MAX` 会返回 NULL、不计入命中），这种表在实践中不会
/// 出现（微信消息表都是首次写入消息时才建表，建表和写入同一事务）。
/// `hit_rel_keys`（实际查到消息）与 `messages` / `new_state` 依赖的时间戳
/// 等**功能字段**不受这个差异影响，判定条件与旧路径逐字段相同（都是"这次
/// `WHERE create_time > since_ts` 查询是否非空"）。
async fn aggregate_new_messages_by_shard(
    db: &DbCache,
    names: &Names,
    changed: &[(String, i64)],
    session_ctx: &HashMap<String, SessionCtx>,
    per_table_limit: usize,
) -> Result<NewMessagesShardAggregate> {
    // uname 去重后按 table_name 分组：一个 table_name 理论上只对应一个
    // uname（md5 碰撞概率为零），用 Vec 只是防御性地保留"万一"的语义。
    let mut unames_by_table: HashMap<String, Vec<String>> = HashMap::new();
    for (uname, _) in changed {
        if !session_ctx.contains_key(uname) {
            continue;
        }
        let table_name = format!("Msg_{:x}", md5::compute(uname.as_bytes()));
        if !msg_table_re().is_match(&table_name) {
            continue;
        }
        unames_by_table
            .entry(table_name)
            .or_default()
            .push(uname.clone());
    }

    let mut agg = NewMessagesShardAggregate::default();
    if unames_by_table.is_empty() {
        return Ok(agg);
    }

    // 最保守的 since 下界：见函数文档"与 find_msg_shards 共享、且严格不
    // 放宽的判据"一节。
    let min_since = changed
        .iter()
        .filter_map(|(uname, _)| session_ctx.get(uname).map(|c| c.since_ts))
        .min();

    let names_map = names.map.clone();

    for rel_key in &names.msg_db_keys {
        let snapshot = db.source_snapshot(rel_key);

        if shard_skippable(snapshot.freshness_secs(), min_since) {
            agg.skipped_shards += 1;
            continue;
        }

        let (cached_tables, need_rebuild, snap_at_judgement) =
            match db.shard_route_lookup_with_snapshot(rel_key, snapshot) {
                ShardRouteLookup::Fresh(tables) => (tables, false, None),
                ShardRouteLookup::Stale(s) => (HashSet::new(), true, Some(s)),
            };

        let mut candidate_tables: Vec<String> = Vec::new();
        if need_rebuild {
            candidate_tables.extend(unames_by_table.keys().cloned());
        } else {
            for table in unames_by_table.keys() {
                if cached_tables.contains(table) {
                    candidate_tables.push(table.clone());
                }
            }
            if candidate_tables.is_empty() {
                // Fresh 且该分片缓存的表集合与本轮全部目标表都不相交：零 I/O 跳过。
                continue;
            }
        }

        let hot = match db.hot_conn_handle_with_snapshot(rel_key, snapshot) {
            Ok(h) => h,
            Err(_) => continue,
        };
        agg.scanned_shards += 1;
        let enc_path = hot.enc_db_path().to_path_buf();
        // FIX-MEDIUM（保持不变）：必须紧跟着这次判定同步读取，不能等到
        // spawn_blocking 完成之后再读——道理与 find_msg_shards 完全相同
        // （见 DbCache::put_shard_schema 文档）。
        let expected_generation = db.route_generation();

        // 把候选任务打包成拥有型数据，一次性 move 进闭包；need_rebuild 时
        // 候选是"本轮全部目标表"（还不知道这个分片实际承载哪些，闭包内
        // 扫完 sqlite_master 后再精确过滤），非 need_rebuild 时已经是精确
        // 命中集合。
        let mut jobs_ctx: Vec<ShardMessageJob> = Vec::new();
        for table in &candidate_tables {
            if let Some(unames) = unames_by_table.get(table) {
                for uname in unames {
                    let Some(ctx) = session_ctx.get(uname) else {
                        continue;
                    };
                    jobs_ctx.push(ShardMessageJob {
                        uname: uname.clone(),
                        table: table.clone(),
                        since_ts: ctx.since_ts,
                        display: ctx.display.clone(),
                        chat_type: ctx.chat_type,
                        is_group: ctx.is_group,
                        group_nicknames: ctx.group_nicknames.clone(),
                    });
                }
            }
        }

        let names_map2 = names_map.clone();
        let rel_key_for_log = rel_key.clone();

        let (tables_opt, matched_any, msgs): (Option<HashSet<String>>, bool, Vec<Value>) =
            match tokio::task::spawn_blocking(move || {
                hot.with(|conn| {
                    let scanned_tables = if need_rebuild {
                        let mut stmt = conn.prepare(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'",
                        )?;
                        let tables: HashSet<String> = stmt
                            .query_map([], |row| row.get::<_, String>(0))?
                            .filter_map(|r| r.ok())
                            .collect();
                        Some(tables)
                    } else {
                        None
                    };

                    let jobs: Vec<ShardMessageJob> = match &scanned_tables {
                        Some(t) => jobs_ctx
                            .into_iter()
                            .filter(|job| t.contains(&job.table))
                            .collect(),
                        None => jobs_ctx,
                    };
                    let matched_any = !jobs.is_empty();

                    let mut result = Vec::new();
                    if matched_any {
                        let id2u = load_id2u(conn);
                        for job in jobs {
                            let sql = format!(
                                "SELECT local_id, local_type, create_time, real_sender_id,
                                        message_content, WCDB_CT_message_content
                                 FROM [{}] WHERE create_time > ? ORDER BY create_time ASC LIMIT ?",
                                job.table
                            );
                            let rows: Vec<_> = conn
                                .prepare(&sql)
                                .and_then(|mut stmt| {
                                    stmt.query_map(
                                        rusqlite::params![job.since_ts, per_table_limit as i64],
                                        |row| {
                                            Ok((
                                                row.get::<_, i64>(0)?,
                                                row.get::<_, i64>(1)?,
                                                row.get::<_, i64>(2)?,
                                                row.get::<_, i64>(3)?,
                                                get_content_bytes(row, 4),
                                                row.get::<_, i64>(5).unwrap_or(0),
                                            ))
                                        },
                                    )
                                    .map(|it| it.filter_map(|r| r.ok()).collect())
                                })
                                .unwrap_or_default();

                            for (local_id, local_type, ts, real_sender_id, content_bytes, ct) in
                                rows
                            {
                                let content = decompress_message(&content_bytes, ct);
                                let sender = sender_label(
                                    real_sender_id,
                                    &content,
                                    job.is_group,
                                    &job.uname,
                                    &id2u,
                                    &names_map2,
                                    &job.group_nicknames,
                                );
                                let text =
                                    fmt_content(local_id, local_type, &content, job.is_group);
                                let url = appmsg_url_for_message(local_type, &content);
                                let mut msg = json!({
                                    "chat": job.display,
                                    "username": job.uname,
                                    "is_group": job.is_group,
                                    "chat_type": job.chat_type,
                                    "timestamp": ts,
                                    "time": fmt_time(ts, "%Y-%m-%d %H:%M"),
                                    "sender": sender,
                                    "content": text,
                                    "type": fmt_type(local_type),
                                });
                                if let Some(u) = url {
                                    msg["url"] = serde_json::Value::String(u);
                                }
                                result.push(msg);
                            }
                        }
                    }

                    Ok::<_, anyhow::Error>((scanned_tables, matched_any, result))
                })
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    eprintln!("[new-messages] skip {}: {}", rel_key_for_log, e);
                    continue;
                }
                Err(e) => {
                    eprintln!("[new-messages] task error: {}", e);
                    continue;
                }
            };

        if let Some(tables) = tables_opt {
            let snapshot = snap_at_judgement.expect("need_rebuild 时快照必然存在");
            db.put_shard_schema(rel_key.clone(), snapshot, tables, expected_generation);
        }

        if matched_any {
            agg.scanned_rel_keys.insert(rel_key.clone());
            agg.cache_modes
                .insert(rel_key.clone(), VFS_CACHE_MODE_LABEL.to_string());
            agg.shard_paths
                .insert(rel_key.clone(), enc_path.to_string_lossy().into_owned());
        }
        if !msgs.is_empty() {
            agg.hit_rel_keys.insert(rel_key.clone());
        }
        agg.messages.extend(msgs);
    }

    Ok(agg)
}

/// [`aggregate_new_messages_by_shard`] 端到端测试：这是四项规模修复里唯一
/// 改动了核心消息拉取语义的一处（把"逐会话调用 `find_msg_shards` + 逐会话
/// 再次 `hot_conn_handle` 查消息"改成"按分片聚合、一次 `hot.with()` 闭包内
/// 查完该分片承载的全部 changed 会话"），但改造前的人工审查没有任何测试
/// 直接跑过这条聚合路径。这里用真实的加密 VFS 夹具（同一个分片文件里塞
/// 两张不同会话的 `Msg_<md5>` 表，模拟"一个分片承载多个会话"的真实场景）
/// 直接验证：
/// - 两个会话各自 `since_ts` 不同时，各自只拿到自己下界之后的消息；
/// - 两个会话的消息互不串号（`chat` / `username` / `is_group` / `chat_type`
///   / 内容归属都精确对应各自会话，不会被同一个分片内的另一张表污染）；
/// - 群会话的 `group_nicknames` → `sender` 归属正确；
/// - 通过公开入口 [`q_new_messages`] 走一遍完整流程时，`new_state` 对每个
///   会话分别正确推进（含"未变化会话原样保留"这个第三种情况，与"变化且
///   有消息返回"两个会话的推进值分别核对，不是笼统断言"整体被 advance"）；
/// - 边界：`changed` 为空（或全部不在 `session_ctx` 里）时返回正常空结果，
///   不触碰任何分片、不报错。
#[cfg(test)]
mod aggregate_new_messages_by_shard_tests {
    use super::super::cache::test_support::{
        build_encrypted_fixture_with, key_fixture, key_to_hex, unique_tmpdir,
    };
    use super::*;

    fn names_for(map: HashMap<String, String>, msg_db_keys: Vec<String>) -> Names {
        Names {
            map,
            md5_to_uname: HashMap::new(),
            msg_db_keys,
            verify_flags: HashMap::new(),
        }
    }

    /// 构造一个加密分片文件，可以在**同一个分片**里塞多张 `Msg_<md5>`
    /// 表——每张表用生产查询真正要读的完整列（`local_type` 固定为 1，
    /// 纯文本消息；`WCDB_CT_message_content` 固定为 0，未压缩），`rows`
    /// 每条是 `(local_id, create_time, real_sender_id, message_content)`。
    fn build_shard_with_message_tables(
        enc_path: &std::path::Path,
        key: &[u8; 32],
        tables: &[(&str, &[(i64, i64, i64, &str)])],
    ) {
        // 先转成拥有型数据，一次性 move 进 `build_encrypted_fixture_with`
        // 的 `FnOnce(&Connection)` 回调（回调不能借用外部传入的 `&[...]`
        // 引用，闭包本身要求 `'static`-free 但仍需在回调内部拥有自己的
        // 数据副本，避免生命周期纠缠)。
        let tables_owned: Vec<(String, Vec<(i64, i64, i64, String)>)> = tables
            .iter()
            .map(|(name, rows)| {
                (
                    name.to_string(),
                    rows.iter()
                        .map(|(id, ts, sender, content)| (*id, *ts, *sender, content.to_string()))
                        .collect(),
                )
            })
            .collect();
        build_encrypted_fixture_with(enc_path, key, move |conn| {
            for (table_name, rows) in &tables_owned {
                conn.execute_batch(&format!(
                    "CREATE TABLE [{}] (
                        local_id INTEGER PRIMARY KEY,
                        local_type INTEGER,
                        create_time INTEGER,
                        real_sender_id INTEGER,
                        message_content TEXT,
                        WCDB_CT_message_content INTEGER
                    );",
                    table_name
                ))
                .expect("建消息表失败");
                for (id, ts, sender, content) in rows {
                    conn.execute(
                        &format!(
                            "INSERT INTO [{}] (local_id, local_type, create_time, \
                             real_sender_id, message_content, WCDB_CT_message_content) \
                             VALUES (?1, 1, ?2, ?3, ?4, 0)",
                            table_name
                        ),
                        rusqlite::params![id, ts, sender, content],
                    )
                    .expect("插入消息夹具失败");
                }
            }
        });
    }

    /// 同一个分片里两个会话（一私聊一群聊），各自 `since_ts` 不同、各自
    /// 消息不互相污染，群聊 `sender` 按 `group_nicknames` 正确归属。核心
    /// 单元测试：直接调用 [`aggregate_new_messages_by_shard`]，不经过
    /// `q_new_messages` 那层 session.db 读取，聚焦聚合函数本身的正确性。
    #[tokio::test]
    async fn two_sessions_sharing_one_shard_do_not_cross_contaminate() {
        let root = unique_tmpdir("aggregate-two-sessions");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let uname_a = "wxid_alice".to_string();
        let uname_b = "9999group@chatroom".to_string();
        let table_a = format!("Msg_{:x}", md5::compute(uname_a.as_bytes()));
        let table_b = format!("Msg_{:x}", md5::compute(uname_b.as_bytes()));

        let key = key_fixture();
        let shard_path = db_dir.join("message_0.db");
        build_shard_with_message_tables(
            &shard_path,
            &key,
            &[
                (
                    table_a.as_str(),
                    &[
                        (1, 1000, 0, "hello 1 from alice chat"),
                        (2, 2000, 0, "hello 2 from alice chat"),
                        (3, 3000, 0, "hello 3 from alice chat"),
                    ],
                ),
                (
                    table_b.as_str(),
                    &[
                        (1, 500, 0, "wxid_member1:\nhi from member1 (too old, must not leak)"),
                        (2, 1500, 0, "wxid_member2:\nhi from member2"),
                        (3, 2500, 0, "wxid_member1:\nsecond msg from member1"),
                    ],
                ),
            ],
        );
        let mut all_keys = HashMap::new();
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let mut names_map = HashMap::new();
        names_map.insert(uname_a.clone(), "Alice 私聊".to_string());
        names_map.insert(uname_b.clone(), "群聊 A".to_string());
        let names = names_for(names_map, vec!["message_0.db".to_string()]);

        let mut group_nicknames = HashMap::new();
        group_nicknames.insert("wxid_member1".to_string(), "群昵称1".to_string());
        group_nicknames.insert("wxid_member2".to_string(), "群昵称2".to_string());

        let mut session_ctx = HashMap::new();
        session_ctx.insert(
            uname_a.clone(),
            SessionCtx {
                display: names.display(&uname_a),
                chat_type: chat_type_of(&uname_a, &names),
                is_group: false,
                group_nicknames: HashMap::new(),
                since_ts: 1500, // 会话 A 自己的下界
            },
        );
        session_ctx.insert(
            uname_b.clone(),
            SessionCtx {
                display: names.display(&uname_b),
                chat_type: chat_type_of(&uname_b, &names),
                is_group: true,
                group_nicknames: group_nicknames.clone(),
                since_ts: 800, // 会话 B 自己的下界，与 A 不同
            },
        );

        let changed = vec![(uname_a.clone(), 0i64), (uname_b.clone(), 0i64)];

        let agg = aggregate_new_messages_by_shard(&db, &names, &changed, &session_ctx, 200)
            .await
            .expect("聚合查询不应失败");

        assert_eq!(agg.scanned_shards, 1, "只有一个分片，且它命中目标表，应该被真正 open 一次");
        assert_eq!(agg.skipped_shards, 0);
        assert!(agg.scanned_rel_keys.contains("message_0.db"));
        assert!(agg.hit_rel_keys.contains("message_0.db"));

        assert_eq!(agg.messages.len(), 4, "会话 A 2 条 + 会话 B 2 条，不多不少");

        let msgs_a: Vec<&Value> = agg
            .messages
            .iter()
            .filter(|m| m["username"].as_str() == Some(uname_a.as_str()))
            .collect();
        let msgs_b: Vec<&Value> = agg
            .messages
            .iter()
            .filter(|m| m["username"].as_str() == Some(uname_b.as_str()))
            .collect();
        assert_eq!(msgs_a.len(), 2, "会话 A：since_ts=1500，只应命中 ts=2000/3000");
        assert_eq!(msgs_b.len(), 2, "会话 B：since_ts=800，只应命中 ts=1500/2500");

        // ---- 各自 since_ts 下界都不多不少 ----
        let mut ts_a: Vec<i64> = msgs_a.iter().map(|m| m["timestamp"].as_i64().unwrap()).collect();
        ts_a.sort_unstable();
        assert_eq!(ts_a, vec![2000, 3000], "会话 A 不应包含 ts=1000（<= since_ts=1500）");

        let mut ts_b: Vec<i64> = msgs_b.iter().map(|m| m["timestamp"].as_i64().unwrap()).collect();
        ts_b.sort_unstable();
        assert_eq!(ts_b, vec![1500, 2500], "会话 B 不应包含 ts=500（<= since_ts=800）");

        // ---- 互不串号：会话归属字段精确对应各自会话，没有被对方污染 ----
        for m in &msgs_a {
            assert_eq!(m["chat"].as_str(), Some("Alice 私聊"));
            assert_eq!(m["is_group"].as_bool(), Some(false));
            assert_eq!(m["chat_type"].as_str(), Some("private"));
            // 私聊消息不经过群消息的 "sender:\n" 前缀剥离，内容原样保留。
            assert!(m["content"].as_str().unwrap().starts_with("hello"));
        }
        for m in &msgs_b {
            assert_eq!(m["chat"].as_str(), Some("群聊 A"));
            assert_eq!(m["is_group"].as_bool(), Some(true));
            assert_eq!(m["chat_type"].as_str(), Some("group"));
            // 群消息内容不应残留会话 A 的文本。
            assert!(!m["content"].as_str().unwrap().contains("alice"));
        }

        // ---- 群昵称 / sender_label 归属正确（按各自 real_sender 精确对应，
        //      不能被同一个分片内批处理的另一条消息覆盖）----
        let msg_1500 = msgs_b
            .iter()
            .find(|m| m["timestamp"].as_i64() == Some(1500))
            .expect("ts=1500 的消息应该存在");
        assert_eq!(msg_1500["sender"].as_str(), Some("群昵称2"), "ts=1500 来自 wxid_member2");
        assert_eq!(
            msg_1500["content"].as_str(),
            Some("hi from member2"),
            "群消息内容应该剥离 \"sender:\\n\" 前缀"
        );

        let msg_2500 = msgs_b
            .iter()
            .find(|m| m["timestamp"].as_i64() == Some(2500))
            .expect("ts=2500 的消息应该存在");
        assert_eq!(
            msg_2500["sender"].as_str(),
            Some("群昵称1"),
            "ts=2500 来自 wxid_member1，不能被 member2 的归属覆盖"
        );
    }

    /// 通过公开入口 [`q_new_messages`] 走完整流程（session.db 读取 →
    /// changed 判定 → 聚合查询 → `new_state` 重建），核对 `new_state` 对
    /// 每个会话分别正确推进：两个变化的会话分别 advance 到"本轮返回的最大
    /// 时间戳"（不是笼统 advance 到同一个值），一个未变化的会话原样保留
    /// `session.db` 的 `last_timestamp`，不受聚合影响。
    #[tokio::test]
    async fn q_new_messages_advances_new_state_independently_per_session() {
        let root = unique_tmpdir("aggregate-new-state");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let uname_a = "wxid_alice2".to_string();
        let uname_b = "wxid_bob2".to_string();
        let uname_c = "wxid_carol_unchanged".to_string();
        let table_a = format!("Msg_{:x}", md5::compute(uname_a.as_bytes()));
        let table_b = format!("Msg_{:x}", md5::compute(uname_b.as_bytes()));

        let key = key_fixture();
        let shard_path = db_dir.join("message_0.db");
        build_shard_with_message_tables(
            &shard_path,
            &key,
            &[
                (
                    table_a.as_str(),
                    &[
                        (1, 1000, 0, "a-1"),
                        (2, 2000, 0, "a-2"),
                        (3, 3000, 0, "a-3"),
                    ],
                ),
                (
                    table_b.as_str(),
                    &[(1, 400, 0, "b-1"), (2, 1500, 0, "b-2"), (3, 2500, 0, "b-3")],
                ),
            ],
        );

        let session_key = key_fixture();
        let session_dir = db_dir.join("session");
        std::fs::create_dir_all(&session_dir).unwrap();
        let session_path = session_dir.join("session.db");
        build_encrypted_fixture_with(&session_path, &session_key, |conn| {
            conn.execute_batch(
                "CREATE TABLE SessionTable (username TEXT, last_timestamp INTEGER);",
            )
            .expect("建 SessionTable 失败");
            for (uname, ts) in [
                ("wxid_alice2", 3000i64),
                ("wxid_bob2", 2500i64),
                ("wxid_carol_unchanged", 900i64),
            ] {
                conn.execute(
                    "INSERT INTO SessionTable (username, last_timestamp) VALUES (?1, ?2)",
                    rusqlite::params![uname, ts],
                )
                .expect("插入 session 行失败");
            }
        });

        let mut all_keys = HashMap::new();
        all_keys.insert("message_0.db".to_string(), key_to_hex(&key));
        all_keys.insert("session/session.db".to_string(), key_to_hex(&session_key));

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();
        let names = names_for(HashMap::new(), vec!["message_0.db".to_string()]);

        // 三个会话各自的“上次已知 last_timestamp”：a / b 都 < session.db
        // 里的当前值（视为变化），c 与 session.db 当前值相等（视为未变化）。
        let mut state = HashMap::new();
        state.insert(uname_a.clone(), 1500i64);
        state.insert(uname_b.clone(), 800i64);
        state.insert(uname_c.clone(), 900i64);

        let result = q_new_messages(&db, &names, Some(state), 100, false, false)
            .await
            .expect("q_new_messages 不应失败");

        assert_eq!(result["count"].as_u64(), Some(4), "a 2 条 + b 2 条，c 未变化不产出消息");

        let messages = result["messages"].as_array().expect("messages 应该是数组");
        let ts_a: Vec<i64> = messages
            .iter()
            .filter(|m| m["username"].as_str() == Some(uname_a.as_str()))
            .map(|m| m["timestamp"].as_i64().unwrap())
            .collect();
        let ts_b: Vec<i64> = messages
            .iter()
            .filter(|m| m["username"].as_str() == Some(uname_b.as_str()))
            .map(|m| m["timestamp"].as_i64().unwrap())
            .collect();
        assert_eq!(ts_a, vec![2000, 3000], "a 的消息不应包含 ts=1000（<= since_ts=1500）");
        assert_eq!(ts_b, vec![1500, 2500], "b 的消息不应包含 ts=400（<= since_ts=800）");
        assert!(
            messages
                .iter()
                .all(|m| m["username"].as_str() == Some(uname_a.as_str())
                    || m["username"].as_str() == Some(uname_b.as_str())),
            "不应该出现除 a/b 之外的会话（尤其是未变化的 c）"
        );

        let new_state = result["new_state"].as_object().expect("new_state 应该是对象");
        assert_eq!(
            new_state[&uname_a].as_i64(),
            Some(3000),
            "a：有消息返回，应该 advance 到本轮返回的最大时间戳"
        );
        assert_eq!(
            new_state[&uname_b].as_i64(),
            Some(2500),
            "b：有消息返回，应该 advance 到本轮返回的最大时间戳（与 a 的推进值不同，\
             证明不是笼统 advance 到同一个值）"
        );
        assert_eq!(
            new_state[&uname_c].as_i64(),
            Some(900),
            "c：session.db 里未变化，应该原样保留，不受本轮聚合影响"
        );
    }

    /// 边界：`changed` 为空时必须返回默认空聚合结果，不报错、不触碰任何
    /// 分片（`names.msg_db_keys` 指向一个从未在 `all_keys` 里注册过密钥、
    /// 磁盘上也不存在的分片——如果实现意外触碰它，`hot_conn_handle` 会失败,
    /// 但函数本身必须在到达那一步之前就已经提前返回)。
    #[tokio::test]
    async fn empty_changed_returns_empty_aggregate_without_touching_any_shard() {
        let root = unique_tmpdir("aggregate-empty-changed");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mtime_file = cache_dir.join("_mtimes.json");
        let db = DbCache::with_dirs(db_dir, cache_dir, mtime_file, HashMap::new())
            .await
            .unwrap();
        // 故意指向一个不存在的分片：密钥未注册、文件也没建过。
        let names = names_for(HashMap::new(), vec!["message_never_created.db".to_string()]);
        let session_ctx: HashMap<String, SessionCtx> = HashMap::new();

        let agg = aggregate_new_messages_by_shard(&db, &names, &[], &session_ctx, 200)
            .await
            .expect("changed 为空时不应该报错");

        assert!(agg.messages.is_empty());
        assert!(agg.scanned_rel_keys.is_empty());
        assert!(agg.hit_rel_keys.is_empty());
        assert_eq!(agg.scanned_shards, 0, "不应该触碰任何分片（包括那个不存在的分片）");
        assert_eq!(agg.skipped_shards, 0);

        // 边界的另一面：changed 非空，但其中的 uname 都不在 session_ctx
        // 里（防御性保护，真实调用方目前不会出现这种情况，但函数自身的
        // 契约不应该依赖调用方保证）——同样应该在触碰分片之前就提前返回。
        let changed = vec![("wxid_not_in_session_ctx".to_string(), 0i64)];
        let agg2 = aggregate_new_messages_by_shard(&db, &names, &changed, &session_ctx, 200)
            .await
            .expect("changed 里的 uname 都不在 session_ctx 时不应该报错");
        assert!(agg2.messages.is_empty());
        assert_eq!(agg2.scanned_shards, 0);
    }
}

/// 查询新消息：以 session.db 的 last_timestamp 作为 inbox 索引，
/// 只查询 last_timestamp > state[username] 的会话，精确且高效
pub async fn q_new_messages(
    db: &DbCache,
    names: &Names,
    state: Option<HashMap<String, i64>>,
    limit: usize,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    // 首次运行（state=None）或未见过的会话，用 24h 前作为起点，
    // 避免第一次运行时把全量历史消息涌入
    let fallback_ts = chrono::Utc::now().timestamp() - 86400;

    // 1. 从 session.db 读取所有会话的当前 last_timestamp
    let session_conn_params = db
        .conn_params("session/session.db")
        .context("无法解密 session.db")?;

    let all_sessions: Vec<(String, i64)> = tokio::task::spawn_blocking(move || {
        let conn = session_conn_params.open()?;
        let mut stmt = conn.prepare(
            "SELECT username, last_timestamp FROM SessionTable WHERE last_timestamp > 0",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1).unwrap_or(0)))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>(rows)
    })
    .await??;

    // 2. 记录 session.db 的当前快照（用于构建 new_state 基础）
    let session_ts_map: HashMap<String, i64> = all_sessions
        .iter()
        .map(|(u, ts)| (u.clone(), *ts))
        .collect();

    // 3. 找出有新消息的会话
    // 不在 state 中的会话（首次运行或新会话）以 fallback_ts 为基准
    let changed: Vec<(String, i64)> = all_sessions
        .into_iter()
        .filter(|(uname, ts)| {
            let last_known = state
                .as_ref()
                .and_then(|m| m.get(uname))
                .copied()
                .unwrap_or(fallback_ts);
            *ts > last_known
        })
        .collect();

    let unknown_shards = current_unknown_shards(db, names);

    if changed.is_empty() {
        let meta = meta_for_global_query(
            0,
            0,
            unknown_shards,
            true,
            with_meta,
            debug_source,
            Some(HashMap::new()),
            Some(HashMap::new()),
        );
        return Ok(json!({
            "count": 0,
            "messages": [],
            "new_state": session_ts_map,
            "meta": meta,
        }));
    }

    // FIX 1（核心·焊死"mtime 滞后漏消息"）：session.db 是本轮新读、内容可靠
    // 的真相源，`changed` 集合准确反映"哪些会话确实有新消息"——不依赖任何
    // mtime 比较。在进入下面 per-session 查询循环之前，把"承载了这些
    // changed 会话消息表"的路由缓存条目 + 热连接强制作废，逼它们下一次被
    // 访问时现场重新 `open()`（`File::open` + 重新扫 WAL 帧头建索引，直接
    // 读当前真实字节），绕开 Windows/NTFS 上跨进程 mtime 可见性可能滞后于
    // 实际写入、导致某轮轮询误判缓存新鲜、漏掉刚落盘新消息的窗口——而漏掉
    // 的消息不是"下一轮补上"，是随 `lastCheckedAt` 推进后永久跳过。
    //
    // FIX-HIGH（新会话覆盖漏洞）：`route_shard_for_table` 对"全新会话"
    // （其 `Msg_<md5>` 表从未出现在任何缓存的 `ShardSchemaEntry.msg_tables`
    // 里，典型是本轮才第一次收到消息的会话）必然返回空——不能像旧版那样
    // 就此放行，指望"新建表必然 bump 该分片 mtime/len，下面
    // `find_msg_shards` 会自然判 Stale、触发重建"这个兜底：这个兜底本身
    // 依赖的正是 FIX 1 要绕开的"跨进程 mtime/len 可见性"假设，一旦新表恰好
    // 建在一个"此前已扫描、已安静超过新鲜度 slack、本次 metadata 又恰好
    // 滞后报旧值"的分片里，`find_msg_shards` 会把它误判 Fresh（缓存的表集
    // 不含新表名）直接跳过，导致这个全新会话的首条消息永久漏掉。
    //
    // 详见 [`shards_to_force_invalidate`]：只要本轮 `changed` 里存在至少
    // 一个"定位不到承载分片"的会话，就退化为对 `names.msg_db_keys` 全部
    // 消息分片各作废一次（逼 `find_msg_shards` 本轮对所有非 dormant 分片
    // 现场重新 `open()`），代价仅仅是这一轮多几次重扫；changed 全是已知
    // 会话（都能精准定位到承载分片）的稳态下，只精准作废这些分片，不做
    // 全量 nuke，缓存命中率不受影响。
    {
        let shards_to_invalidate = shards_to_force_invalidate(db, &changed, &names.msg_db_keys);
        for rel_key in &shards_to_invalidate {
            db.invalidate_shard(rel_key);
        }
    }

    // 4. 按分片聚合查询有新消息的会话的消息表（FIX 1：把"逐会话调用
    //    find_msg_shards + 逐会话再次 hot_conn_handle 查消息"这两步分离的
    //    执行路径，改造成"按分片聚合、每个 dirty 分片本轮只 open 一次"，
    //    详见 aggregate_new_messages_by_shard 文档）。
    // per_table_limit 取 limit*5 防止单表截断，最终由全局 truncate 收尾
    let per_table_limit = limit.saturating_mul(5).max(200);

    // 只给本轮真正 changed 的会话预算展示名 / 会话类型 / 群昵称 / 增量
    // 下界，供下面按分片聚合查询时直接复用。
    let mut session_ctx: HashMap<String, SessionCtx> = HashMap::new();
    for (uname, _) in &changed {
        let since_ts = state
            .as_ref()
            .and_then(|m| m.get(uname))
            .copied()
            .unwrap_or(fallback_ts);
        let chat_type = chat_type_of(uname, names);
        let is_group = chat_type == "group";
        let group_nicknames = if is_group {
            load_group_nicknames(db, uname).await.unwrap_or_default()
        } else {
            HashMap::new()
        };
        session_ctx.insert(
            uname.clone(),
            SessionCtx {
                display: names.display(uname),
                chat_type,
                is_group,
                group_nicknames,
                since_ts,
            },
        );
    }

    let agg =
        aggregate_new_messages_by_shard(db, names, &changed, &session_ctx, per_table_limit)
            .await?;
    eprintln!(
        "[shards] q_new_messages 聚合批次: {} 个会话变化, {} 个分片 open, {} 个分片按 mtime 跳过 (共 {} 个消息分片)",
        changed.len(),
        agg.scanned_shards,
        agg.skipped_shards,
        names.msg_db_keys.len()
    );

    let mut all_msgs: Vec<Value> = agg.messages;
    let scanned_rel_keys = agg.scanned_rel_keys;
    let hit_rel_keys = agg.hit_rel_keys;
    let cache_modes = agg.cache_modes;
    let shard_paths = agg.shard_paths;

    all_msgs.sort_by_key(|m| m["timestamp"].as_i64().unwrap_or(0));
    all_msgs.truncate(limit);

    // 5. 重建 new_state，防止全局 limit 截断导致消息永久丢失：
    //    - 未变化的会话：沿用 session.db 的 last_timestamp（即 session_ts_map）
    //    - 变化但全被截断（无消息在最终结果中）：
    //        * 后续调用 (state=Some)：保留旧 since_ts，下次重试拿这部分消息
    //        * 首次调用 (state=None)：advance 到 session_ts，避免 since_ts 锁死在
    //          fallback_ts 导致后续每次都回扫 24h。窗口会随调用次数 + 时间累积扩大，
    //          性能持续衰退。代价：首次 + 被截断会话的老消息看不到，需走 `wxeasy history`。
    //    - 变化且有消息返回：advance 到该会话在结果中的最大 timestamp（增量 fetch 标准语义）
    let returned_max_ts: HashMap<String, i64> = {
        let mut m: HashMap<String, i64> = HashMap::new();
        for msg in &all_msgs {
            if let (Some(u), Some(ts)) = (msg["username"].as_str(), msg["timestamp"].as_i64()) {
                let e = m.entry(u.to_string()).or_insert(0);
                if ts > *e {
                    *e = ts;
                }
            }
        }
        m
    };
    let mut new_state = session_ts_map;
    for (uname, _) in &changed {
        let in_results = returned_max_ts.contains_key(uname);
        let prev = state.as_ref().and_then(|m| m.get(uname)).copied();
        let next_ts = match (in_results, prev) {
            (true, _) => {
                // 有消息返回：advance 到 returned_max；返回的最大 ts 通常 ≤ session_ts，
                // 这样下次查 `since > returned_max` 仍能拿到 returned_max..session_ts 的截断尾巴。
                returned_max_ts[uname]
            }
            (false, Some(prev)) => prev, // 后续 + 截断：保持旧 since
            (false, None) => {
                // 首次 + 截断：advance 到 session_ts 兜底，避免 since_ts 锁死。
                new_state.get(uname).copied().unwrap_or(fallback_ts)
            }
        };
        new_state.insert(uname.clone(), next_ts);
    }

    let meta = meta_for_global_query(
        scanned_rel_keys.len(),
        hit_rel_keys.len(),
        unknown_shards,
        true,
        with_meta,
        debug_source,
        Some(cache_modes),
        Some(shard_paths),
    );

    Ok(json!({
        "count": all_msgs.len(),
        "messages": all_msgs,
        "new_state": new_state,
        "meta": meta,
    }))
}

/// 查询收藏内容（favorite/favorite.db 的 fav_db_item 表）
pub async fn q_favorites(
    db: &DbCache,
    limit: usize,
    fav_type: Option<i64>,
    query: Option<String>,
) -> Result<Value> {
    let conn_params = db
        .conn_params("favorite/favorite.db")
        .context("找不到 favorite.db，请确认微信数据目录")?;

    let rows: Vec<Value> = tokio::task::spawn_blocking(move || {
        let conn = conn_params.open()?;

        let mut clauses: Vec<&'static str> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(t) = fav_type {
            clauses.push("type = ?");
            params.push(Box::new(t));
        }
        let like_str: Option<String> = query.map(|q| {
            let esc = q
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{}%", esc)
        });
        if let Some(ref s) = like_str {
            clauses.push("content LIKE ? ESCAPE '\\'");
            params.push(Box::new(s.clone()));
        }

        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        params.push(Box::new(limit as i64));

        let sql = format!(
            "SELECT local_id, type, update_time, content, fromusr, realchatname
             FROM fav_db_item {} ORDER BY update_time DESC LIMIT ?",
            where_clause
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows: Vec<Value> = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok((
                    row.get::<_, i64>(0).unwrap_or(0),
                    row.get::<_, i64>(1).unwrap_or(0),
                    row.get::<_, i64>(2).unwrap_or(0),
                    row.get::<_, String>(3).unwrap_or_default(),
                    row.get::<_, String>(4).unwrap_or_default(),
                    row.get::<_, String>(5).unwrap_or_default(),
                ))
            })?
            .filter_map(|r| r.ok())
            .map(|(local_id, ftype, ts, content, fromusr, chatname)| {
                let type_str = match ftype {
                    1 => "文本",
                    2 => "图片",
                    5 => "文章",
                    19 => "名片",
                    20 => "视频",
                    _ => "其他",
                };
                // 安全截断（按 Unicode 字符而非字节）
                let preview: String = content.chars().take(100).collect();
                let preview = if content.chars().count() > 100 {
                    format!("{}...", preview)
                } else {
                    preview
                };
                // WeChat 部分版本的 update_time 为毫秒，10位以上判定为毫秒后转秒
                let ts_secs = if ts > 9_999_999_999 { ts / 1000 } else { ts };
                let mut item = json!({
                    "id": local_id,
                    "type": type_str,
                    "type_num": ftype,
                    "time": fmt_time(ts_secs, "%Y-%m-%d %H:%M"),
                    "timestamp": ts_secs,
                    "preview": preview,
                    "from": fromusr,
                    "chat": chatname,
                });
                if ftype == 5 {
                    if let Some(url) = extract_favorite_url(&content) {
                        item["url"] = Value::String(url);
                    }
                }
                item
            })
            .collect();

        Ok::<_, anyhow::Error>(rows)
    })
    .await??;

    Ok(json!({
        "count": rows.len(),
        "items": rows,
    }))
}

/// 聊天统计：消息总数、类型分布、发言排行、24小时分布
pub async fn q_stats(
    db: &DbCache,
    names: &Names,
    chat: &str,
    since: Option<i64>,
    until: Option<i64>,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    let username =
        resolve_username(chat, names).with_context(|| format!("找不到联系人: {}", chat))?;
    let display = names.display(&username);
    let chat_type = chat_type_of(&username, names);
    let is_group = chat_type == "group";

    let (shards, scanned, _) = find_msg_shards(db, names, &username, None).await?;
    if shards.is_empty() {
        anyhow::bail!("找不到 {} 的消息记录", display);
    }

    // 跨所有分片 DB 累计统计
    let mut total: i64 = 0;
    let mut type_counts: HashMap<String, i64> = HashMap::new();
    let mut sender_counts: HashMap<String, i64> = HashMap::new();
    let mut hour_counts = [0i64; 24];
    let group_nicknames = if is_group {
        load_group_nicknames(db, &username)
            .await
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let mut shard_hits = 0usize;

    for shard in &shards {
        // FIX 4：`shards` 来自 `find_msg_shards`，已经用
        // `hot_conn_handle_with_snapshot` 为这个 rel_key 开过（或复用过）
        // 一次热连接。这里改用 `hot_conn_handle` 复用同一个槽位，消除原本
        // `conn_params.open()` 造成的第二次物理打开。
        let hot = db.hot_conn_handle(&shard.rel_key)?;
        let tname = shard.table.clone();
        let uname = username.clone();
        let is_group2 = is_group;

        // 用 SQL GROUP BY 在数据库侧聚合，避免把全量消息内容加载进内存
        let result: (i64, HashMap<String, i64>, HashMap<String, i64>, [i64; 24]) =
            tokio::task::spawn_blocking(move || {
                hot.with(|conn| {
                let id2u = load_id2u(conn);

                let mut clauses = Vec::new();
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
                if let Some(s) = since {
                    clauses.push("create_time >= ?");
                    params.push(Box::new(s));
                }
                if let Some(u) = until {
                    clauses.push("create_time <= ?");
                    params.push(Box::new(u));
                }
                let where_clause = if clauses.is_empty() {
                    String::new()
                } else {
                    format!("WHERE {}", clauses.join(" AND "))
                };
                let params_ref: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();

                // 1. 总数
                let count: i64 = conn.query_row(
                    &format!("SELECT COUNT(*) FROM [{}] {}", tname, where_clause),
                    params_ref.as_slice(),
                    |row| row.get(0),
                ).unwrap_or(0);

                // 2. 类型分布：SQL GROUP BY，不加载消息内容
                let type_sql = format!(
                    "SELECT (local_type & 0xFFFFFFFF), COUNT(*) FROM [{}] {} GROUP BY (local_type & 0xFFFFFFFF)",
                    tname, where_clause
                );
                let mut type_c: HashMap<String, i64> = HashMap::new();
                if let Ok(mut stmt) = conn.prepare(&type_sql) {
                    let _ = stmt.query_map(params_ref.as_slice(), |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    }).map(|rows| {
                        for r in rows.flatten() {
                            *type_c.entry(fmt_type(r.0)).or_insert(0) += r.1;
                        }
                    });
                }

                // 3. 小时分布：只取时间戳，不加载消息内容
                let hour_sql = format!(
                    "SELECT create_time FROM [{}] {}",
                    tname, where_clause
                );
                let mut hour_c = [0i64; 24];
                if let Ok(mut stmt) = conn.prepare(&hour_sql) {
                    let _ = stmt.query_map(params_ref.as_slice(), |row| row.get::<_, i64>(0))
                        .map(|rows| {
                            for ts in rows.flatten() {
                                if let Some(dt) = Local.timestamp_opt(ts, 0).single() {
                                    let h = dt.hour() as usize;
                                    if h < 24 { hour_c[h] += 1; }
                                }
                            }
                        });
                }

                // 4. 发言排行：只取 real_sender_id，不加载消息内容
                // where_clause 可能已含 WHERE，用 AND 追加而非重复写 WHERE
                let sender_filter = if where_clause.is_empty() {
                    "WHERE real_sender_id > 0".to_string()
                } else {
                    format!("{} AND real_sender_id > 0", where_clause)
                };
                let sender_sql = format!(
                    "SELECT real_sender_id, COUNT(*) FROM [{}] {} GROUP BY real_sender_id",
                    tname, sender_filter
                );
                let mut sender_c: HashMap<String, i64> = HashMap::new();
                if is_group2 {
                    if let Ok(mut stmt) = conn.prepare(&sender_sql) {
                        let _ = stmt.query_map(params_ref.as_slice(), |row| {
                            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                        }).map(|rows| {
                            for (id, cnt) in rows.flatten() {
                                if let Some(u) = id2u.get(&id) {
                                    if u != &uname {
                                        *sender_c.entry(u.clone()).or_insert(0) += cnt;
                                    }
                                }
                            }
                        });
                    }
                }

                Ok::<_, anyhow::Error>((count, type_c, sender_c, hour_c))
                })
            }).await??;

        let (count, type_c, sender_c, hour_c) = result;
        if count > 0 {
            shard_hits += 1;
        }
        total += count;
        for (k, v) in type_c {
            *type_counts.entry(k).or_insert(0) += v;
        }
        for (k, v) in sender_c {
            *sender_counts.entry(k).or_insert(0) += v;
        }
        for i in 0..24 {
            hour_counts[i] += hour_c[i];
        }
    }

    // 类型分布，按数量降序
    let mut by_type: Vec<Value> = type_counts
        .iter()
        .map(|(t, c)| json!({ "type": t, "count": c }))
        .collect();
    by_type.sort_by_key(|v| std::cmp::Reverse(v["count"].as_i64().unwrap_or(0)));

    // 发言排行，Top 10
    let top_senders = group_top_senders(&sender_counts, &names.map, &group_nicknames, 10);

    // 24小时分布
    let by_hour: Vec<Value> = hour_counts
        .iter()
        .enumerate()
        .map(|(h, c)| json!({ "hour": h, "count": c }))
        .collect();
    let windowed = since.is_some() || until.is_some();
    let unknown_shards = current_unknown_shards(db, names);
    let session_ts = session_last_timestamp(db, &username).await;
    let meta = meta_for_shards(
        scanned,
        &shards,
        shard_hits,
        unknown_shards,
        session_ts,
        windowed,
        with_meta,
        debug_source,
    );

    Ok(json!({
        "chat": display,
        "username": username,
        "is_group": is_group,
        "chat_type": chat_type,
        "total": total,
        "by_type": by_type,
        "top_senders": top_senders,
        "by_hour": by_hour,
        "meta": meta,
    }))
}

/// 查询朋友圈互动通知（点赞 + 评论），对应微信 app 右上角的红点入口。
/// 空 `content` 是点赞，非空是评论正文。
pub async fn q_sns_notifications(
    db: &DbCache,
    names: &Names,
    limit: usize,
    since: Option<i64>,
    until: Option<i64>,
    include_read: bool,
) -> Result<Value> {
    let conn_params = db.conn_params("sns/sns.db").context("无法解密 sns.db")?;

    let conn_params2 = conn_params.clone();
    type Row = (i64, i64, i64, i64, String, String, String);
    let rows: Vec<Row> = tokio::task::spawn_blocking(move || {
        let conn = conn_params2.open()?;
        let mut clauses: Vec<&str> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if !include_read {
            clauses.push("is_unread = 1");
        }
        if let Some(s) = since {
            clauses.push("create_time >= ?");
            params.push(Box::new(s));
        }
        if let Some(u) = until {
            clauses.push("create_time <= ?");
            params.push(Box::new(u));
        }
        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT local_id, create_time, type, feed_id, from_username, from_nickname, content
             FROM SnsMessage_tmp3 {} ORDER BY create_time DESC LIMIT ?",
            where_clause
        );
        params.push(Box::new(limit as i64));
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2).unwrap_or(0),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, String>(4).unwrap_or_default(),
                    row.get::<_, String>(5).unwrap_or_default(),
                    row.get::<_, String>(6).unwrap_or_default(),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>(rows)
    })
    .await??;

    // 一次性取出涉及的 feed 原帖，避免 N+1 查询
    let feed_ids: Vec<i64> = {
        let mut v: Vec<i64> = rows.iter().map(|r| r.3).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let conn_params3 = conn_params.clone();
    let feed_ids_clone = feed_ids.clone();
    let feeds: HashMap<i64, (String, String)> = tokio::task::spawn_blocking(move || {
        if feed_ids_clone.is_empty() {
            return Ok::<_, anyhow::Error>(HashMap::new());
        }
        let conn = conn_params3.open()?;
        let placeholders = std::iter::repeat("?")
            .take(feed_ids_clone.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT tid, user_name, content FROM SnsTimeLine WHERE tid IN ({})",
            placeholders
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = feed_ids_clone
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = conn.prepare(&sql)?;
        let mut map = HashMap::new();
        let mut rows2 = stmt.query(params.as_slice())?;
        while let Some(row) = rows2.next()? {
            let tid: i64 = row.get(0)?;
            let author: String = row.get::<_, String>(1).unwrap_or_default();
            let content: String = row.get::<_, String>(2).unwrap_or_default();
            let preview = extract_xml_text(&content, "contentDesc")
                .map(|s| s.chars().take(60).collect::<String>())
                .unwrap_or_default();
            // 原帖 user_name 偶尔为空（转发帖），再从 XML 兜一下
            let author = if author.is_empty() {
                extract_xml_text(&content, "username").unwrap_or_default()
            } else {
                author
            };
            map.insert(tid, (author, preview));
        }
        Ok(map)
    })
    .await??;

    let mut out = Vec::with_capacity(rows.len());
    for (_local_id, ct, _typ, fid, from_u, from_nick, content) in rows {
        let kind = if content.trim().is_empty() {
            "like"
        } else {
            "comment"
        };
        let display = if !from_nick.is_empty() {
            from_nick.clone()
        } else {
            names.display(&from_u)
        };
        let (feed_author_u, feed_preview) = feeds.get(&fid).cloned().unwrap_or_default();
        let feed_author_display = if feed_author_u.is_empty() {
            String::new()
        } else {
            names.display(&feed_author_u)
        };
        out.push(json!({
            "type": kind,
            "time": fmt_time(ct, "%m-%d %H:%M"),
            "timestamp": ct,
            "from_username": from_u,
            "from_nickname": display,
            "content": content,
            "feed_id": fid,
            "feed_author_username": feed_author_u,
            "feed_author": feed_author_display,
            "feed_preview": feed_preview,
        }));
    }
    let total = out.len();
    Ok(json!({ "notifications": out, "total": total }))
}

// 朋友圈扫描的硬上限：单次查询最多解析这么多行 SnsTimeLine，
// 防止用户传超大 limit 或者底层数据异常时把 daemon 卡住。
// 当前账号 ~10k+ 帖子，5w 上限留足缓冲。
const SNS_MAX_LIMIT: usize = 10_000;
const SNS_MAX_SCAN: usize = 50_000;

/// 转义 SQL LIKE 模式中的元字符。配合 `ESCAPE '\\'` 使用。
/// 反斜杠必须最先转义，否则后续替换出的 `\%` / `\_` 会被再次吞掉。
fn escape_like_pattern(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('%', r"\%")
        .replace('_', r"\_")
}

fn xml_child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.has_tag_name(tag))
}

fn xml_text<'a, 'input>(node: Option<Node<'a, 'input>>) -> Option<String> {
    node.and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn xml_attr<'a, 'input>(node: Option<Node<'a, 'input>>, attr: &str) -> Option<String> {
    node.and_then(|n| n.attribute(attr))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn insert_media_string(out: &mut serde_json::Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        out.insert(key.to_string(), Value::String(value));
    }
}

fn insert_media_i64(out: &mut serde_json::Map<String, Value>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        out.insert(key.to_string(), Value::from(value));
    }
}

/// 从已经定位到的 `<TimelineObject>` 节点里抽 `<mediaList>/<media>` 数组。
/// 字段名与 artifacts 仓库 `wechat_sns_dump.py::_parse_media` 对齐，
/// 便于跨实现 diff。缺失字段直接省略（不输出 null），供下游代理图片 / 离线渲染。
fn parse_media_from_timeline(timeline: Node) -> Vec<Value> {
    let Some(media_list) =
        xml_child(timeline, "ContentObject").and_then(|node| xml_child(node, "mediaList"))
    else {
        return Vec::new();
    };

    media_list
        .children()
        .filter(|node| node.is_element() && node.has_tag_name("media"))
        .map(|media| {
            let url_el = xml_child(media, "url");
            let thumb_el = xml_child(media, "thumb");
            let size_el = xml_child(media, "size");
            let mut out = serde_json::Map::new();

            insert_media_string(&mut out, "type", xml_text(xml_child(media, "type")));
            insert_media_string(&mut out, "sub_type", xml_text(xml_child(media, "sub_type")));
            insert_media_string(&mut out, "url", xml_text(url_el));
            insert_media_string(&mut out, "thumb", xml_text(thumb_el));
            insert_media_string(&mut out, "md5", xml_attr(url_el, "md5"));
            insert_media_string(&mut out, "url_key", xml_attr(url_el, "key"));
            insert_media_string(&mut out, "url_token", xml_attr(url_el, "token"));
            insert_media_string(&mut out, "url_enc_idx", xml_attr(url_el, "enc_idx"));
            insert_media_string(&mut out, "thumb_key", xml_attr(thumb_el, "key"));
            insert_media_string(&mut out, "thumb_token", xml_attr(thumb_el, "token"));
            insert_media_string(&mut out, "thumb_enc_idx", xml_attr(thumb_el, "enc_idx"));
            insert_media_i64(
                &mut out,
                "width",
                xml_attr(size_el, "width").and_then(|v| v.parse::<i64>().ok()),
            );
            insert_media_i64(
                &mut out,
                "height",
                xml_attr(size_el, "height").and_then(|v| v.parse::<i64>().ok()),
            );
            insert_media_i64(
                &mut out,
                "total_size",
                xml_attr(size_el, "totalSize").and_then(|v| v.parse::<i64>().ok()),
            );
            insert_media_string(
                &mut out,
                "video_md5",
                xml_text(xml_child(media, "videomd5")),
            );
            insert_media_i64(
                &mut out,
                "video_duration",
                xml_text(xml_child(media, "videoDuration")).and_then(|v| v.parse::<i64>().ok()),
            );

            Value::Object(out)
        })
        .collect()
}

/// 从 `SnsTimeLine.content` 整段 XML 抽 media[]。仅供单测使用 —— 生产路径走
/// `parse_post_xml`，那边已经把整份 doc parse 一次直接复用 timeline 节点。
#[cfg(test)]
fn parse_post_media(xml: &str) -> Vec<Value> {
    let Ok(doc) = Document::parse(xml) else {
        return Vec::new();
    };
    let Some(timeline) = doc.descendants().find(|n| n.has_tag_name("TimelineObject")) else {
        return Vec::new();
    };
    parse_media_from_timeline(timeline)
}

/// SnsTimeLine 行解析产物。不含 display name（依赖 Names，需要出 spawn_blocking 再补）。
struct ParsedPost {
    tid: i64,
    create_time: i64,
    author_username: String,
    content: String,
    media: Vec<Value>,
    location: String,
}

fn parse_post_xml_fallback(tid: i64, user_name_column: &str, content: &str) -> ParsedPost {
    let create_time = extract_xml_text(content, "createTime")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let text = extract_xml_text(content, "contentDesc")
        .map(|s| unescape_html(&s))
        .unwrap_or_default();
    let author_username = if user_name_column.is_empty() {
        extract_xml_text(content, "username")
            .map(|s| unescape_html(&s))
            .unwrap_or_default()
    } else {
        user_name_column.to_string()
    };
    let location = extract_xml_attr(content, "location", "poiName")
        .map(|s| unescape_html(&s))
        .unwrap_or_default();

    ParsedPost {
        tid,
        create_time,
        author_username,
        content: text,
        media: Vec::new(),
        location,
    }
}

/// 纯 XML 解析，无 Names 依赖，可以在 spawn_blocking 里跑。
/// user_name_column 为空时从 TimelineObject/<username> 兜底（转发帖）。
///
/// 单 roxmltree DOM 解析一次出全部字段（createTime / contentDesc / username / media / location），
/// 取代旧版 regex + DOM 双解析。XML entity 解码（`&lt;` / `&amp;` 等）由 roxmltree 自动处理，
/// 旧版 `extract_xml_text` 是字符串扫描不解码 —— 因此 `content` / `location` / `username` 字段
/// 现在会输出解码后的文本，对下游是更正确的语义。
/// 如果 XML 已损坏到无法 DOM parse，或缺少 `TimelineObject`，则退回轻量 string
/// fallback，尽量保住 createTime / contentDesc / username / location，避免一条帖子
/// 因为局部坏 XML 被整体打成零值，影响排序 / 搜索 / 作者过滤语义。
fn parse_post_xml(tid: i64, user_name_column: &str, content: &str) -> ParsedPost {
    let Ok(doc) = Document::parse(content) else {
        return parse_post_xml_fallback(tid, user_name_column, content);
    };
    let Some(timeline) = doc.descendants().find(|n| n.has_tag_name("TimelineObject")) else {
        return parse_post_xml_fallback(tid, user_name_column, content);
    };

    let create_time = xml_text(xml_child(timeline, "createTime"))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let text = xml_text(xml_child(timeline, "contentDesc")).unwrap_or_default();
    let author_username = if user_name_column.is_empty() {
        xml_text(xml_child(timeline, "username")).unwrap_or_default()
    } else {
        user_name_column.to_string()
    };
    let media = parse_media_from_timeline(timeline);
    let location = xml_child(timeline, "location")
        .and_then(|n| n.attribute("poiName"))
        .map(str::to_string)
        .unwrap_or_default();

    ParsedPost {
        tid,
        create_time,
        author_username,
        content: text,
        media,
        location,
    }
}

fn post_to_value(p: ParsedPost, names: &Names) -> Value {
    let author = if p.author_username.is_empty() {
        String::new()
    } else {
        names.display(&p.author_username)
    };
    json!({
        "tid": p.tid,
        "timestamp": p.create_time,
        "time": fmt_time(p.create_time, "%Y-%m-%d %H:%M"),
        "author_username": p.author_username,
        "author": author,
        "content": p.content,
        "media_count": p.media.len() as i64,
        "media": p.media,
        "location": p.location,
    })
}

/// 查询朋友圈时间线：按时间/作者筛选。用于浏览自己或好友的朋友圈。
pub async fn q_sns_feed(
    db: &DbCache,
    names: &Names,
    limit: usize,
    since: Option<i64>,
    until: Option<i64>,
    user: Option<&str>,
) -> Result<Value> {
    let conn_params = db.conn_params("sns/sns.db").context("无法解密 sns.db")?;

    let limit = limit.min(SNS_MAX_LIMIT);
    let user_uname = match user {
        Some(q) => {
            Some(resolve_username(q, names).with_context(|| format!("找不到联系人: {}", q))?)
        }
        None => None,
    };

    // user 过滤不在 SQL 层做：SnsTimeLine.user_name 列对部分（转发）帖子是空，
    // 真正作者只在 XML <username> 里。SQL 层 `user_name = ?` 会把这部分提前漏掉，
    // 让 parse_post_xml 的 fallback 失效。所以扫全表 → parse → 用 ParsedPost.author_username 过滤。
    // (createTime 也不是列，本来就要扫全表 parse XML 才能正确按时间排序。)
    let parsed: Vec<ParsedPost> = tokio::task::spawn_blocking(move || {
        let conn = conn_params.open()?;
        let sql = "SELECT tid, user_name, content FROM SnsTimeLine ORDER BY tid DESC";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1).unwrap_or_default(),
            row.get::<_, String>(2).unwrap_or_default(),
        )))?;

        let mut scanned = 0usize;
        let mut out: Vec<ParsedPost> = Vec::new();
        for row in rows {
            scanned += 1;
            if scanned > SNS_MAX_SCAN {
                eprintln!(
                    "[sns_feed] scan 超过硬上限 {}，结果可能不完整。建议加 --user / --since 缩小范围。",
                    SNS_MAX_SCAN
                );
                break;
            }
            let (tid, uname, content) = row?;
            let p = parse_post_xml(tid, &uname, &content);
            if let Some(u) = user_uname.as_ref() { if &p.author_username != u { continue; } }
            if let Some(s) = since { if p.create_time < s { continue; } }
            if let Some(u) = until { if p.create_time > u { continue; } }
            out.push(p);
        }
        // tid DESC 不严格等于 createTime DESC（不同账号 tid 生成算法不同），
        // 所以要先收齐全部匹配的、按 create_time 排序，再 truncate —— 否则会丢帖。
        out.sort_by_key(|p| std::cmp::Reverse(p.create_time));
        out.truncate(limit);
        Ok::<_, anyhow::Error>(out)
    }).await??;

    let posts: Vec<Value> = parsed
        .into_iter()
        .map(|p| post_to_value(p, names))
        .collect();
    let total = posts.len();
    Ok(json!({ "posts": posts, "total": total }))
}

/// 搜索朋友圈全文：在 contentDesc（正文）里匹配 keyword，可叠加时间 / 作者过滤。
pub async fn q_sns_search(
    db: &DbCache,
    names: &Names,
    keyword: &str,
    limit: usize,
    since: Option<i64>,
    until: Option<i64>,
    user: Option<&str>,
) -> Result<Value> {
    if keyword.trim().is_empty() {
        anyhow::bail!("搜索关键词不能为空");
    }
    let conn_params = db.conn_params("sns/sns.db").context("无法解密 sns.db")?;

    let limit = limit.min(SNS_MAX_LIMIT);
    let user_uname = match user {
        Some(q) => {
            Some(resolve_username(q, names).with_context(|| format!("找不到联系人: {}", q))?)
        }
        None => None,
    };

    // SQL LIKE 在 content 上粗筛 keyword（这步省掉绝大多数行的 XML parse 开销）。
    // user 不在 SQL 层过滤，原因同 q_sns_feed：SnsTimeLine.user_name 列对部分（转发）
    // 帖子为空，真实作者只在 XML <username> 里。
    let like_pattern = format!("%{}%", escape_like_pattern(keyword));
    let keyword_owned = keyword.to_string();

    let parsed: Vec<ParsedPost> = tokio::task::spawn_blocking(move || {
        let conn = conn_params.open()?;
        let sql = "SELECT tid, user_name, content FROM SnsTimeLine \
                   WHERE content LIKE ? ESCAPE '\\' ORDER BY tid DESC";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([&like_pattern], |row| Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1).unwrap_or_default(),
            row.get::<_, String>(2).unwrap_or_default(),
        )))?;

        let needle = keyword_owned.to_lowercase();
        let mut scanned = 0usize;
        let mut out: Vec<ParsedPost> = Vec::new();
        for row in rows {
            scanned += 1;
            if scanned > SNS_MAX_SCAN {
                eprintln!(
                    "[sns_search] scan 超过硬上限 {}，结果可能不完整。建议缩小 keyword 或加 --user / --since。",
                    SNS_MAX_SCAN
                );
                break;
            }
            let (tid, uname, content) = row?;
            let desc = extract_xml_text(&content, "contentDesc").unwrap_or_default();
            if !desc.to_lowercase().contains(&needle) { continue; }

            let p = parse_post_xml(tid, &uname, &content);
            if let Some(u) = user_uname.as_ref() { if &p.author_username != u { continue; } }
            if let Some(s) = since { if p.create_time < s { continue; } }
            if let Some(u) = until { if p.create_time > u { continue; } }
            out.push(p);
        }
        out.sort_by_key(|p| std::cmp::Reverse(p.create_time));
        out.truncate(limit);
        Ok::<_, anyhow::Error>(out)
    }).await??;

    let posts: Vec<Value> = parsed
        .into_iter()
        .map(|p| post_to_value(p, names))
        .collect();
    let total = posts.len();
    Ok(json!({ "keyword": keyword, "posts": posts, "total": total }))
}

// ─── 公众号文章查询 ───────────────────────────────────────────────────────────

/// 一条公众号文章的解析产物
#[derive(Debug)]
struct BizArticle {
    /// 接收该推送的时间戳（即消息的 create_time）
    recv_time: i64,
    /// 公众号 username
    account_username: String,
    /// 文章标题
    title: String,
    /// 文章链接
    url: String,
    /// 摘要
    digest: String,
    /// 封面图
    cover: String,
    /// 文章发布时间（pub_time，单位秒）
    pub_time: i64,
}

/// 从 biz_message 表的单条 XML 解析出全部 article items
fn parse_biz_xml_items(recv_time: i64, account_username: &str, xml: &str) -> Vec<BizArticle> {
    let mut items = Vec::new();
    let mut search_from = 0;
    loop {
        let Some(item_start) = xml[search_from..].find("<item>") else {
            break;
        };
        let abs_start = search_from + item_start;
        let Some(item_end) = xml[abs_start..].find("</item>") else {
            break;
        };
        let abs_end = abs_start + item_end + 7;
        let item_xml = &xml[abs_start..abs_end];

        let title = extract_cdata(item_xml, "title").unwrap_or_default();
        let url = extract_cdata(item_xml, "url").unwrap_or_default();
        // Skip items with no URL or empty title (e.g. payment entries)
        if url.is_empty() || title.is_empty() {
            search_from = abs_end;
            continue;
        }
        let digest = extract_cdata(item_xml, "digest").unwrap_or_default();
        let cover = extract_cdata(item_xml, "cover").unwrap_or_default();
        let pub_time = extract_xml_text(item_xml, "pub_time")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(recv_time);

        items.push(BizArticle {
            recv_time,
            account_username: account_username.to_string(),
            title,
            url,
            digest,
            cover,
            pub_time,
        });
        search_from = abs_end;
    }
    items
}

/// 提取 CDATA 或普通文本内容： `<tag><![CDATA[...]]></tag>` 或 `<tag>...</tag>`
///
/// 注意: 内容匹配到 `</tag>` 之前的内容。CDATA 块中的 "]]"已在 "]]\x3e" 之前，
/// 所以 inner 为 `<![CDATA[content]]>` 或 `<![CDATA[content]]` （如果 ">" 被 close tag 吸掉）
fn extract_cdata(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    let inner = xml[start..start + end].trim();
    if inner.starts_with("<![CDATA[") {
        // inner = `<![CDATA[content]]>` → strip 9-char `<![CDATA[` prefix + 3-char `]]>` suffix
        let body = &inner[9..];
        // Strip `]]>` (normal) or `]]` (edge case)
        let cdata_end = b"]]>";
        let cdata_end2 = b"]]";
        let content: &str = if body.as_bytes().ends_with(cdata_end) {
            &body[..body.len() - 3]
        } else if body.as_bytes().ends_with(cdata_end2) {
            &body[..body.len() - 2]
        } else {
            body
        };
        let content = content.trim();
        if content.is_empty() {
            None
        } else {
            Some(content.to_string())
        }
    } else if inner.is_empty() {
        None
    } else {
        Some(unescape_html(inner))
    }
}

/// 查询公众号文章推送（biz_message_0.db）
///
/// 每条消息可能包含多篇文章（多图文推送）。返回所有文章展开就的平底列表。
pub async fn q_biz_articles(
    db: &DbCache,
    names: &Names,
    limit: usize,
    account: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    unread: bool,
) -> Result<Value> {
    let biz_conn_params = db
        .conn_params("message/biz_message_0.db")
        .context("无法解密 biz_message_0.db，请确认 all_keys.json 包含对应密钥")?;

    // 开启 --unread：从 session.db 拿"公众号 + unread_count>0"的 username 子集，
    // 作为合集过滤（与 --account 取交集），后续结果按 account_username 去重取顶 1 篇。
    let unread_usernames: Option<std::collections::HashSet<String>> = if unread {
        let session_conn_params = db
            .conn_params("session/session.db")
            .context("无法解密 session.db")?;
        let unread_rows: Vec<String> = tokio::task::spawn_blocking(move || {
            let conn = session_conn_params.open()?;
            let mut stmt =
                conn.prepare("SELECT username FROM SessionTable WHERE unread_count > 0")?;
            let rows: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            Ok::<_, anyhow::Error>(rows)
        })
        .await??;
        // 仅保留公众号类型的未读会话
        let set: std::collections::HashSet<String> = unread_rows
            .into_iter()
            .filter(|u| chat_type_of(u, names) == "official_account")
            .collect();
        if set.is_empty() {
            // 没有未读公众号 → 直接空返回，避免打 biz 表扫描
            return Ok(json!({ "count": 0, "articles": [] }));
        }
        Some(set)
    } else {
        None
    };

    // 1. 从 Name2Id 表获取 rowid -> username 映射，再推导 md5 -> username
    let biz_conn_params2 = biz_conn_params.clone();
    let id2username: HashMap<i64, String> = tokio::task::spawn_blocking(move || {
        let conn = biz_conn_params2.open()?;
        let mut stmt =
            conn.prepare("SELECT rowid, user_name FROM Name2Id WHERE user_name LIKE 'gh_%'")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>(rows.into_iter().collect())
    })
    .await??;

    // 构建 md5(username) -> username 映射
    let md5_to_uname: HashMap<String, String> = id2username
        .values()
        .map(|u| (format!("{:x}", md5::compute(u.as_bytes())), u.clone()))
        .collect();

    // 2. 如果 指定了 --account，找到匹配的 username 列表
    let account_low = account.as_deref().map(|s| s.to_lowercase());
    let mut target_usernames: Option<Vec<String>> = account_low.as_ref().map(|low| {
        id2username
            .values()
            .filter(|u| {
                let display = names.display(u);
                display.to_lowercase().contains(low.as_str())
                    || u.to_lowercase().contains(low.as_str())
            })
            .cloned()
            .collect()
    });

    // --unread 与 --account 取交集（进一步缩小范围）
    if let Some(ref unread_set) = unread_usernames {
        target_usernames = Some(match target_usernames.take() {
            Some(acc_list) => acc_list
                .into_iter()
                .filter(|u| unread_set.contains(u))
                .collect(),
            None => unread_set.iter().cloned().collect(),
        });
        // 交集为空 → 提前返回
        if target_usernames
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(false)
        {
            return Ok(json!({ "count": 0, "articles": [] }));
        }
    }

    // 3. 进行数据库查询
    let biz_conn_params3 = biz_conn_params.clone();
    let since2 = since;
    let until2 = until;
    let target_hashes: Option<Vec<String>> = target_usernames.as_ref().map(|unames| {
        unames
            .iter()
            .map(|u| format!("{:x}", md5::compute(u.as_bytes())))
            .collect()
    });

    let rows: Vec<(String, i64, i64, Vec<u8>, i64)> = tokio::task::spawn_blocking(move || {
        let conn = biz_conn_params3.open()?;

        // 列出所有 Msg_<hash> 表
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")?;
        let table_names: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        let re = regex::Regex::new(r"^Msg_[0-9a-f]{32}$").unwrap();
        let mut all_rows: Vec<(String, i64, i64, Vec<u8>, i64)> = Vec::new();

        for tname in &table_names {
            if !re.is_match(tname) {
                continue;
            }
            let hash = &tname[4..];

            // account 过滤
            if let Some(ref hashes) = target_hashes {
                if !hashes.iter().any(|h| h == hash) {
                    continue;
                }
            }

            let username = md5_to_uname.get(hash).cloned().unwrap_or_default();

            // 构建过滤条件
            let mut clauses: Vec<String> = Vec::new();
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            // local_type & 0xFFFFFFFF = 49 是 appmsg（公众号文章）
            clauses.push("(local_type & 4294967295) = 49".to_string());
            if let Some(s) = since2 {
                clauses.push("create_time >= ?".to_string());
                params.push(Box::new(s));
            }
            if let Some(u) = until2 {
                clauses.push("create_time <= ?".to_string());
                params.push(Box::new(u));
            }
            let where_clause = format!("WHERE {}", clauses.join(" AND "));

            let sql = format!(
                "SELECT create_time, WCDB_CT_message_content, message_content \
                 FROM [{}] {} ORDER BY create_time DESC",
                tname, where_clause
            );

            let params_ref: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            if let Ok(mut inner_stmt) = conn.prepare(&sql) {
                let msg_rows: Vec<_> = inner_stmt
                    .query_map(params_ref.as_slice(), |row| {
                        Ok((
                            username.clone(),
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1).unwrap_or(0),
                            get_content_bytes(row, 2),
                            0i64,
                        ))
                    })
                    .map(|it| it.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();
                all_rows.extend(msg_rows);
            }
        }
        Ok::<_, anyhow::Error>(all_rows)
    })
    .await??;

    // 4. 解压并解析 XML
    let mut articles: Vec<BizArticle> = Vec::new();
    for (username, recv_time, ct, content_bytes, _) in rows {
        let content = decompress_message(&content_bytes, ct);
        if content.is_empty() {
            continue;
        }
        let items = parse_biz_xml_items(recv_time, &username, &content);
        articles.extend(items);
    }

    // 5. 按 pub_time DESC 排序
    articles.sort_by_key(|a| std::cmp::Reverse(a.pub_time));

    // --unread 语义 A：每个公众号只保留最新 1 篇（已按 pub_time 排序，取首条即可）
    if unread {
        let mut seen = std::collections::HashSet::<String>::new();
        articles.retain(|a| seen.insert(a.account_username.clone()));
    }

    articles.truncate(limit);

    let results: Vec<Value> = articles
        .into_iter()
        .map(|a| {
            let account_display = names.display(&a.account_username);
            json!({
                "time": fmt_time(a.pub_time, "%Y-%m-%d %H:%M"),
                "timestamp": a.pub_time,
                "recv_time": a.recv_time,
                "recv_time_str": fmt_time(a.recv_time, "%Y-%m-%d %H:%M"),
                "account": account_display,
                "account_username": a.account_username,
                "title": a.title,
                "url": a.url,
                "digest": a.digest,
                "cover_url": a.cover,
            })
        })
        .collect();

    Ok(json!({ "count": results.len(), "articles": results }))
}

// ─── 附件（当前先支持图片）查询与提取 ─────────────────────────────────
//
// 设计要点：
// - `q_attachments` 只走 `Msg_<chat_md5>` 表，按 `local_type & 0xFFFFFFFF IN (...)` 过滤
//   出附件消息行，再编出 `attachment_id`。**不**去翻 `message_resource.db`，因为列出动作
//   要可枚举几千条；resource lookup 留到 `q_extract` 才做。
// - `q_extract` 走完整链：`AttachmentId` → `message_resource.db` 查 md5 →
//   `<wxchat_base>/msg/attach/...` 找 .dat → 按 magic 分发到 v1/v2 decoder → 写盘。
// - V2 image AES key 通过 `image_key::default_provider()` 拿（codex 后续填实现）。
//   缺 key 时 V2 解码会返回明确错误，CLI 直接抛给用户。

/// 列出某会话内的附件消息（当前仅 image）。返回每条的 `attachment_id`，
/// 后续传给 `Extract` 才真正读 message_resource.db + 解密 .dat。
pub async fn q_attachments(
    db: &DbCache,
    names: &Names,
    chat: &str,
    kinds: Option<Vec<String>>,
    limit: usize,
    offset: usize,
    since: Option<i64>,
    until: Option<i64>,
    with_meta: bool,
    debug_source: bool,
) -> Result<Value> {
    use crate::attachment::{AttachmentId, AttachmentKind};

    let username =
        resolve_username(chat, names).with_context(|| format!("找不到联系人: {}", chat))?;
    let display = names.display(&username);
    let chat_type = chat_type_of(&username, names);
    let is_group = chat_type == "group";

    // 解析 kinds → 低 32 bit local_type 集合
    let kind_filters: Vec<(AttachmentKind, i64)> = parse_attachment_kinds(kinds.as_deref())?;
    if kind_filters.is_empty() {
        anyhow::bail!("kinds 为空 — 当前至少传一种 image");
    }
    let lo32_types: Vec<i64> = kind_filters.iter().map(|(_, t)| *t).collect();
    // local_type → AttachmentKind 反查（mask 完后定 kind）
    let type_to_kind: HashMap<i64, AttachmentKind> =
        kind_filters.iter().map(|(k, t)| (*t, *k)).collect();

    let (shards, scanned, _) = find_msg_shards(db, names, &username, None).await?;
    if shards.is_empty() {
        anyhow::bail!("找不到 {} 的消息记录", display);
    }

    // 群聊需要 sender 显示名
    let group_nicknames = if is_group {
        load_group_nicknames(db, &username)
            .await
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    let mut all_rows: Vec<(i64, i64, i64, i64, String, i64, i64)> = Vec::new();
    let mut shard_hits = 0usize;
    // 元组：(local_id, local_type_lo32, create_time, real_sender_id, sender_label, ts_for_sort, db_idx)
    for (db_idx, shard) in shards.iter().enumerate() {
        // FIX 4：`shards` 来自 `find_msg_shards`，已经用
        // `hot_conn_handle_with_snapshot` 为这个 rel_key 开过（或复用过）
        // 一次热连接。这里改用 `hot_conn_handle` 复用同一个槽位，消除原本
        // `conn_params.open()` 造成的第二次物理打开。
        let hot = db.hot_conn_handle(&shard.rel_key)?;
        let tname = shard.table.clone();
        let uname = username.clone();
        let is_group2 = is_group;
        let names_map = names.map.clone();
        let group_nicknames2 = group_nicknames.clone();
        let lo32_types2 = lo32_types.clone();
        let since2 = since;
        let until2 = until;
        // per-DB 软上限避免巨群全量加载
        let per_db_cap = (offset + limit).max(limit) * 2;
        let db_idx2 = db_idx as i64;

        let rows: Vec<(i64, i64, i64, i64, String, i64, i64)> =
            tokio::task::spawn_blocking(move || {
                hot.with(|conn| {
                let id2u = load_id2u(conn);

                // local_type 在 DB 里可能带高位 flag，过滤要 mask 低 32 bit
                let placeholders = lo32_types2
                    .iter()
                    .map(|_| "?")
                    .collect::<Vec<_>>()
                    .join(",");
                let mut clauses: Vec<String> =
                    vec![format!("(local_type & 4294967295) IN ({})", placeholders)];
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = lo32_types2
                    .iter()
                    .map(|t| Box::new(*t) as Box<dyn rusqlite::types::ToSql>)
                    .collect();
                if let Some(s) = since2 {
                    clauses.push("create_time >= ?".into());
                    params.push(Box::new(s));
                }
                if let Some(u) = until2 {
                    clauses.push("create_time <= ?".into());
                    params.push(Box::new(u));
                }
                let where_clause = format!("WHERE {}", clauses.join(" AND "));

                let sql = format!(
                    "SELECT local_id, local_type, create_time, real_sender_id,
                            message_content, WCDB_CT_message_content
                     FROM [{}] {} ORDER BY create_time DESC LIMIT ?",
                    tname, where_clause
                );
                params.push(Box::new(per_db_cap as i64));

                let params_ref: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows: Vec<(i64, i64, i64, i64, String, i64, i64)> = stmt
                    .query_map(params_ref.as_slice(), |row| {
                        let local_id: i64 = row.get(0)?;
                        let raw_type: i64 = row.get(1)?;
                        let lo32 = (raw_type as u64 & 0xFFFFFFFF) as i64;
                        let ts: i64 = row.get(2)?;
                        let real_sender_id: i64 = row.get(3)?;
                        let content_bytes = get_content_bytes(row, 4);
                        let ct: i64 = row.get::<_, i64>(5).unwrap_or(0);
                        let content = decompress_message(&content_bytes, ct);
                        let sender = if is_group2 {
                            sender_label(
                                real_sender_id,
                                &content,
                                true,
                                &uname,
                                &id2u,
                                &names_map,
                                &group_nicknames2,
                            )
                        } else {
                            String::new()
                        };
                        Ok((local_id, lo32, ts, real_sender_id, sender, ts, db_idx2))
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok::<_, anyhow::Error>(rows)
                })
            })
            .await??;
        if !rows.is_empty() {
            shard_hits += 1;
        }
        all_rows.extend(rows);
    }

    // 全局按 ts DESC 排序后分页
    all_rows.sort_by_key(|r| std::cmp::Reverse(r.5));
    let paged: Vec<_> = all_rows.into_iter().skip(offset).take(limit).collect();

    // 翻成 JSON
    let mut results: Vec<Value> = Vec::with_capacity(paged.len());
    for (local_id, lo32, ts, _real_sender_id, sender, _ts2, _db_idx) in paged {
        let kind = type_to_kind
            .get(&lo32)
            .copied()
            .unwrap_or(AttachmentKind::Image); // 理论不会 fallthrough
        let id = AttachmentId {
            v: 1,
            chat: username.clone(),
            local_id,
            create_time: ts,
            kind,
            db: None,
        };
        let id_str = id.encode()?;

        let mut row = json!({
            "attachment_id": id_str,
            "kind": kind.as_str(),
            "type": fmt_type(lo32),
            "local_id": local_id,
            "timestamp": ts,
            "time": fmt_time(ts, "%Y-%m-%d %H:%M"),
        });
        if is_group && !sender.is_empty() {
            row["sender"] = Value::String(sender);
        }
        results.push(row);
    }
    let unknown_shards = current_unknown_shards(db, names);
    let session_ts = session_last_timestamp(db, &username).await;
    let meta = meta_for_shards(
        scanned,
        &shards,
        shard_hits,
        unknown_shards,
        session_ts,
        true,
        with_meta,
        debug_source,
    );

    Ok(json!({
        "chat": display,
        "username": username,
        "is_group": is_group,
        "chat_type": chat_type,
        "count": results.len(),
        "attachments": results,
        "meta": meta,
    }))
}

/// 解码 attachment_id → 查 message_resource.db → 找本地 .dat → 解密 → 写盘。
pub async fn q_extract(
    db: &DbCache,
    _names: &Names,
    attachment_id: &str,
    output: &str,
    overwrite: bool,
) -> Result<Value> {
    use crate::attachment::{
        attachment_id::AttachmentId,
        decoder::{self, V2KeyMaterial},
        image_key, resolver,
    };

    let id = AttachmentId::decode(attachment_id)
        .context("解析 attachment_id 失败（不是合法 base64url(json)？）")?;

    let output_path = std::path::PathBuf::from(output);
    if output_path.exists() && !overwrite {
        anyhow::bail!(
            "目标已存在：{}（加 --overwrite 覆盖）",
            output_path.display()
        );
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("创建输出目录失败：{}", parent.display()))?;
        }
    }

    // 1) 拿 message_resource.db
    let resource_path = db
        .get("message/message_resource.db")
        .await?
        .context("无法解密 message_resource.db（请确认 all_keys.json 包含该 DB 的密钥）")?;

    // 2) 推 wxchat_base = db_dir.parent()，再拼 attach_root
    let wxchat_base = db
        .db_dir()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("db_dir 没有 parent，无法推断 xwechat_files 根目录"))?
        .to_path_buf();
    let attach_root = resolver::attach_root_for(&wxchat_base);

    // 3) blocking pool 跑 resolver + 读盘 + 解码
    let id_for_task = id.clone();
    let resource_path2 = resource_path.clone();
    let attach_root2 = attach_root.clone();
    let wxchat_base2 = wxchat_base.clone();
    let output_path2 = output_path.clone();

    let report: Value = tokio::task::spawn_blocking(move || -> Result<Value> {
        let resolved = resolver::resolve_blocking(&id_for_task, &resource_path2, &attach_root2)?;

        let dat_bytes = std::fs::read(&resolved.dat_path)
            .with_context(|| format!("读取 .dat 失败：{}", resolved.dat_path.display()))?;

        // V2 image key — 平台相关。`ImageKeyMaterial` 同时给 aes_key + xor_key。
        // xor_key 不能硬编码 0x88：实测 macOS 真实账号上是 `uin & 0xff` 派生的（0xa2 等），
        // 所以这里桥接时必须把 provider 的 xor_key 透传给 V2KeyMaterial。
        // 缺 key 时让 decoder 自己抛带诊断的错。
        let provider = image_key::default_provider();
        let key_material = if let Some(p) = provider.as_ref() {
            // 从 wxchat_base 末段拿 wxid
            let wxid = wxchat_base2
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            if wxid.is_empty() {
                None
            } else {
                match p.get_key(&wxid) {
                    Ok(km) => Some(km),
                    Err(e) => {
                        eprintln!(
                            "[extract] image key 提取失败 (wxid={}): {} — V2 文件将无法解码",
                            wxid, e
                        );
                        None
                    }
                }
            }
        } else {
            None
        };
        let v2_key = match key_material.as_ref() {
            Some(km) => V2KeyMaterial {
                aes_key: Some(&km.aes_key),
                xor_key: km.xor_key,
            },
            None => V2KeyMaterial::default(),
        };

        let decoded = decoder::dispatch(&dat_bytes, v2_key)?;

        // 写盘
        std::fs::write(&output_path2, &decoded.data)
            .with_context(|| format!("写出文件失败：{}", output_path2.display()))?;

        // 注意：不要在这里塞 `ok: true`。dispatch 会用 Response::ok(v) 包一层，
        // Response 的 `data: Value` 字段是 #[serde(flatten)] 写出的，本 payload
        // 的 `ok` 会和 Response 自带的 `ok` 在线上拼成两个同名 key，CLI 反序列化时
        // serde_json 直接报 "duplicate field"，业务请求看上去像 daemon 解析失败。
        Ok(json!({
            "kind": id_for_task.kind.as_str(),
            "md5": resolved.md5,
            "dat_path": resolved.dat_path.display().to_string(),
            "dat_size": resolved.size,
            "output": output_path2.display().to_string(),
            "output_size": decoded.data.len(),
            "format": decoded.format,
            "decoder": decoded.decoder,
        }))
    })
    .await??;

    Ok(report)
}

/// 解析 `kinds` 参数到 `(AttachmentKind, lo32_local_type)` 列表。
/// 当前只支持 image；命令名保留成 `attachments` 是为了后续扩到其他附件类型时不 break CLI。
fn parse_attachment_kinds(
    kinds: Option<&[String]>,
) -> Result<Vec<(crate::attachment::AttachmentKind, i64)>> {
    use crate::attachment::AttachmentKind;
    let raw = kinds.unwrap_or(&[]);
    if raw.is_empty() {
        return Ok(vec![(AttachmentKind::Image, 3)]);
    }
    let mut out: Vec<(AttachmentKind, i64)> = Vec::with_capacity(raw.len());
    let mut seen = HashSet::<&'static str>::new();
    for k in raw {
        let (kind, t): (AttachmentKind, i64) = match k.to_ascii_lowercase().as_str() {
            "image" | "img" => (AttachmentKind::Image, 3),
            "voice" | "audio" | "video" | "file" => {
                anyhow::bail!(
                    "当前只支持 image 提取；video/file/voice 的资源路径与 decoder 还没接通"
                )
            }
            other => anyhow::bail!("未知附件类型：{}（当前仅支持 image）", other),
        };
        if seen.insert(kind.as_str()) {
            out.push((kind, t));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod biz_tests {
    use super::*;

    #[test]
    fn extract_cdata_normal() {
        let xml = "<title><![CDATA[TencentResearch]]></title>";
        assert_eq!(extract_cdata(xml, "title"), Some("TencentResearch".into()));
    }

    #[test]
    fn extract_cdata_empty() {
        let xml = "<cover><![CDATA[]]></cover>";
        assert_eq!(extract_cdata(xml, "cover"), None);
    }

    #[test]
    fn extract_cdata_url() {
        let xml = "<url><![CDATA[http://mp.weixin.qq.com/s?__biz=abc&mid=123]]></url>";
        let result = extract_cdata(xml, "url");
        assert!(result.is_some());
        let url = result.unwrap();
        assert!(url.starts_with("http://mp.weixin.qq.com"));
        assert!(!url.contains("CDATA"));
    }

    #[test]
    fn extract_cdata_no_cdata_wrapper() {
        let xml = "<pub_time>1700000000</pub_time>";
        assert_eq!(extract_cdata(xml, "pub_time"), Some("1700000000".into()));
    }

    #[test]
    fn parse_biz_xml_items_single_article() {
        let xml = r#"<msg><appmsg><mmreader><category><item>
            <title><![CDATA[Test Article Title]]></title>
            <url><![CDATA[http://mp.weixin.qq.com/s?test=1]]></url>
            <digest><![CDATA[Test Digest]]></digest>
            <cover><![CDATA[https://example.com/cover.jpg]]></cover>
            <pub_time>1700000000</pub_time>
        </item></category></mmreader></appmsg></msg>"#;

        let items = parse_biz_xml_items(1699999999, "gh_test123", xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Test Article Title");
        assert_eq!(items[0].url, "http://mp.weixin.qq.com/s?test=1");
        assert_eq!(items[0].digest, "Test Digest");
        assert_eq!(items[0].pub_time, 1700000000);
        assert_eq!(items[0].account_username, "gh_test123");
    }

    #[test]
    fn parse_biz_xml_items_skips_no_url() {
        let xml = r#"<msg><mmreader><category><item>
            <title><![CDATA[Has Title No URL]]></title>
            <url><![CDATA[]]></url>
            <pub_time>1700000001</pub_time>
        </item></category></mmreader></msg>"#;
        let items = parse_biz_xml_items(1700000001, "gh_test", xml);
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn parse_biz_xml_items_multi_article() {
        let xml = r#"<msg><mmreader><category>
        <item>
            <title><![CDATA[Article 1]]></title>
            <url><![CDATA[http://mp.weixin.qq.com/s?a=1]]></url>
            <pub_time>1700000010</pub_time>
        </item>
        <item>
            <title><![CDATA[Article 2]]></title>
            <url><![CDATA[http://mp.weixin.qq.com/s?a=2]]></url>
            <pub_time>1700000020</pub_time>
        </item>
        </category></mmreader></msg>"#;
        let items = parse_biz_xml_items(1700000000, "gh_multi", xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Article 1");
        assert_eq!(items[1].title, "Article 2");
    }

    #[test]
    fn parse_biz_xml_items_pub_time_fallback() {
        // When pub_time is missing, should fall back to recv_time
        let xml = r#"<item>
            <title><![CDATA[No PubTime]]></title>
            <url><![CDATA[http://mp.weixin.qq.com/s?x=1]]></url>
        </item>"#;
        let items = parse_biz_xml_items(1700000099, "gh_fallback", xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].pub_time, 1700000099); // falls back to recv_time
    }
}

#[cfg(test)]
mod group_nickname_tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    fn len_field(field_no: u64, bytes: &[u8]) -> Vec<u8> {
        let mut out = varint((field_no << 3) | 2);
        out.extend(varint(bytes.len() as u64));
        out.extend(bytes);
        out
    }

    fn string_field(field_no: u64, value: &str) -> Vec<u8> {
        len_field(field_no, value.as_bytes())
    }

    fn member_chunk(username: &str, group_nickname: &str) -> Vec<u8> {
        let mut member = Vec::new();
        member.extend(string_field(1, username));
        member.extend(string_field(2, group_nickname));
        len_field(1, &member)
    }

    #[test]
    fn parses_group_nickname_member_chunks() {
        let mut ext_buffer = Vec::new();
        ext_buffer.extend(member_chunk("wxid_alice", "Alice In Group"));
        ext_buffer.extend(member_chunk("bob_123456", "Bob Card"));

        let nicknames = parse_group_nickname_map(&ext_buffer, None);

        assert_eq!(
            nicknames.get("wxid_alice").map(String::as_str),
            Some("Alice In Group")
        );
        assert_eq!(
            nicknames.get("bob_123456").map(String::as_str),
            Some("Bob Card")
        );
    }

    #[test]
    fn target_filter_anchors_member_username_choice() {
        let mut member = Vec::new();
        member.extend(string_field(3, "candidate_name"));
        member.extend(string_field(4, "wxid_target"));
        member.extend(string_field(2, "Target Card"));
        let ext_buffer = len_field(1, &member);
        let targets = HashSet::from(["wxid_target".to_string()]);

        let nicknames = parse_group_nickname_map(&ext_buffer, Some(&targets));

        assert_eq!(
            nicknames.get("wxid_target").map(String::as_str),
            Some("Target Card")
        );
        assert!(!nicknames.contains_key("candidate_name"));
    }

    #[test]
    fn group_top_senders_keeps_duplicate_display_names_separate() {
        let sender_counts =
            HashMap::from([("wxid_alice".to_string(), 7), ("wxid_bob".to_string(), 3)]);
        let names = HashMap::from([
            ("wxid_alice".to_string(), "Alice Contact".to_string()),
            ("wxid_bob".to_string(), "Bob Contact".to_string()),
        ]);
        let group_nicknames = HashMap::from([
            ("wxid_alice".to_string(), "同名".to_string()),
            ("wxid_bob".to_string(), "同名".to_string()),
        ]);

        let top = group_top_senders(&sender_counts, &names, &group_nicknames, 10);

        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["sender"].as_str(), Some("同名"));
        assert_eq!(top[0]["count"].as_i64(), Some(7));
        assert_eq!(top[1]["sender"].as_str(), Some("同名"));
        assert_eq!(top[1]["count"].as_i64(), Some(3));
    }
}

#[cfg(test)]
mod sns_tests {
    use super::*;

    fn make_post_xml(
        create_time: &str,
        desc: &str,
        username_tag: Option<&str>,
        media: usize,
        location: Option<&str>,
    ) -> String {
        let username = username_tag
            .map(|u| format!("<username>{}</username>", u))
            .unwrap_or_default();
        let media_tags = "<media><type>2</type></media>".repeat(media);
        let content_object = if media > 0 {
            format!(
                "<ContentObject><mediaList>{}</mediaList></ContentObject>",
                media_tags
            )
        } else {
            String::new()
        };
        let loc = location
            .map(|p| format!(r#"<location poiName="{}" longitude="0" latitude="0" />"#, p))
            .unwrap_or_default();
        format!(
            "<TimelineObject>{}<createTime>{}</createTime><contentDesc>{}</contentDesc>{}{}</TimelineObject>",
            username, create_time, desc, content_object, loc
        )
    }

    #[test]
    fn parse_uses_user_name_column_when_present() {
        let xml = make_post_xml("1700000000", "hello", Some("wxid_xml"), 0, None);
        let p = parse_post_xml(1, "wxid_column", &xml);
        assert_eq!(p.author_username, "wxid_column");
        assert_eq!(p.create_time, 1700000000);
        assert_eq!(p.content, "hello");
        assert_eq!(p.media.len(), 0);
        assert_eq!(p.location, "");
    }

    #[test]
    fn parse_falls_back_to_xml_username_when_column_empty() {
        let xml = make_post_xml("1700000001", "world", Some("wxid_xml_only"), 0, None);
        let p = parse_post_xml(2, "", &xml);
        assert_eq!(p.author_username, "wxid_xml_only");
    }

    #[test]
    fn parse_handles_missing_create_time() {
        let xml = "<TimelineObject><contentDesc>x</contentDesc></TimelineObject>";
        let p = parse_post_xml(3, "wxid", xml);
        assert_eq!(p.create_time, 0);
        assert_eq!(p.content, "x");
    }

    #[test]
    fn parse_counts_media_and_extracts_location() {
        let xml = make_post_xml("1700000002", "post", None, 3, Some("Wuxi"));
        let p = parse_post_xml(4, "wxid", &xml);
        assert_eq!(p.media.len(), 3);
        assert_eq!(p.location, "Wuxi");
    }

    #[test]
    fn parse_when_both_column_and_xml_username_empty_returns_empty_author() {
        let xml = "<TimelineObject><createTime>1700000003</createTime><contentDesc>orphan</contentDesc></TimelineObject>";
        let p = parse_post_xml(5, "", xml);
        assert_eq!(p.author_username, "");
    }

    #[test]
    fn parse_decodes_xml_entities_in_content() {
        // 单 DOM 解析的副作用：roxmltree 自动把 &lt; / &amp; / &quot; 等还原成原字符；
        // 旧版 extract_xml_text 字符串扫描不解码，会把 "&lt;world&gt;" 原样输出。
        // 新版语义对下游更正确（拿到的就是用户真实内容），把这个行为锁进测试。
        let xml = "<TimelineObject><contentDesc>Hello &lt;world&gt; &amp; friends</contentDesc></TimelineObject>";
        let p = parse_post_xml(6, "wxid", xml);
        assert_eq!(p.content, "Hello <world> & friends");
    }

    #[test]
    fn parse_malformed_xml_falls_back_to_string_fields_when_column_present() {
        let xml = "<TimelineObject><createTime>1700000007</createTime><contentDesc>A &amp; B</contentDesc><location poiName=\"Wuxi &amp; Lake\" /><not valid xml";
        let p = parse_post_xml(7, "wxid_fallback", xml);
        assert_eq!(p.create_time, 1700000007);
        assert_eq!(p.content, "A & B");
        assert_eq!(p.author_username, "wxid_fallback");
        assert!(p.media.is_empty());
        assert_eq!(p.location, "Wuxi & Lake");
    }

    #[test]
    fn parse_malformed_xml_can_still_use_xml_username_when_column_empty() {
        let xml = "<TimelineObject><createTime>1700000008</createTime><contentDesc>broken</contentDesc><username>wxid_xml_only</username><not valid xml";
        let p = parse_post_xml(8, "", xml);
        assert_eq!(p.create_time, 1700000008);
        assert_eq!(p.content, "broken");
        assert_eq!(p.author_username, "wxid_xml_only");
        assert!(p.media.is_empty());
    }

    #[test]
    fn parse_without_timeline_object_falls_back_to_string_fields() {
        let xml = "<SnsDataItem><createTime>1700000009</createTime><contentDesc>still here</contentDesc><username>wxid_outer</username></SnsDataItem>";
        let p = parse_post_xml(9, "", xml);
        assert_eq!(p.create_time, 1700000009);
        assert_eq!(p.content, "still here");
        assert_eq!(p.author_username, "wxid_outer");
        assert!(p.media.is_empty());
    }

    #[test]
    fn escape_like_pattern_escapes_backslash_first() {
        // 反斜杠必须在 % / _ 之前转义；否则后面塞进去的 \% / \_ 会被再次双转义吃掉
        assert_eq!(escape_like_pattern("a\\b"), "a\\\\b");
        assert_eq!(escape_like_pattern("100%"), "100\\%");
        assert_eq!(escape_like_pattern("foo_bar"), "foo\\_bar");
    }

    #[test]
    fn escape_like_pattern_combined() {
        // \%_ 三个元字符同时出现
        let escaped = escape_like_pattern("a\\b%c_d");
        assert_eq!(escaped, "a\\\\b\\%c\\_d");
    }

    #[test]
    fn escape_like_pattern_no_special_chars_unchanged() {
        assert_eq!(escape_like_pattern("hello world"), "hello world");
        assert_eq!(escape_like_pattern("中文关键词"), "中文关键词");
        assert_eq!(escape_like_pattern(""), "");
    }

    #[test]
    fn extract_appmsg_url_unescapes_html_entities() {
        let xml = concat!(
            "<appmsg>",
            "<type>5</type>",
            "<url>https://mp.weixin.qq.com/s?__biz=MzI4&amp;mid=2247&amp;idx=1</url>",
            "</appmsg>"
        );
        assert_eq!(
            extract_appmsg_url(xml).as_deref(),
            Some("https://mp.weixin.qq.com/s?__biz=MzI4&mid=2247&idx=1")
        );
    }

    #[test]
    fn extract_appmsg_url_strips_group_prefix_and_cdata() {
        let xml = concat!(
            "wxid_sender:\n",
            "<appmsg>",
            "<type>5</type>",
            "<url><![CDATA[https://example.com/x?a=1&b=2]]></url>",
            "</appmsg>"
        );
        assert_eq!(
            extract_appmsg_url(xml).as_deref(),
            Some("https://example.com/x?a=1&b=2")
        );
    }

    #[test]
    fn extract_appmsg_url_falls_back_to_url1() {
        let xml = concat!(
            "<appmsg>",
            "<type>5</type>",
            "<url1>https://example.com/fallback</url1>",
            "</appmsg>"
        );
        assert_eq!(
            extract_appmsg_url(xml).as_deref(),
            Some("https://example.com/fallback")
        );
    }

    #[test]
    fn extract_appmsg_url_ignores_non_http_values() {
        let xml = concat!(
            "<appmsg>",
            "<type>5</type>",
            "<url>weixin://bizmsgmenu?msgmenucontent=foo</url>",
            "</appmsg>"
        );
        assert_eq!(extract_appmsg_url(xml), None);
    }

    #[test]
    fn extract_appmsg_url_ignores_refermsg() {
        let xml = concat!(
            "<appmsg>",
            "<type>57</type>",
            "<url>https://example.com/nested</url>",
            "</appmsg>"
        );
        assert_eq!(extract_appmsg_url(xml), None);
    }

    #[test]
    fn extract_favorite_url_reads_link_tag() {
        let xml = concat!(
            "<favitem>",
            "<type>5</type>",
            "<link><![CDATA[https://mp.weixin.qq.com/s?__biz=foo&mid=1]]></link>",
            "</favitem>"
        );
        assert_eq!(
            extract_favorite_url(xml).as_deref(),
            Some("https://mp.weixin.qq.com/s?__biz=foo&mid=1")
        );
    }

    #[test]
    fn extract_favorite_url_ignores_non_http_values() {
        let xml = concat!(
            "<favitem>",
            "<type>5</type>",
            "<link>weixin://favorites/item/1</link>",
            "</favitem>"
        );
        assert_eq!(extract_favorite_url(xml), None);
    }

    fn media_object(value: &Value) -> &serde_json::Map<String, Value> {
        value.as_object().expect("media entry should be an object")
    }

    #[test]
    fn single_image_media() {
        let xml = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList>
        <media>
          <type>2</type>
          <url enc_idx="1" key="placeholder-key" token="placeholder-token" md5="placeholder-md5">https://szmmsns.qpic.cn/&lt;redacted&gt;/image.jpg</url>
          <thumb enc_idx="0" key="placeholder-thumb-key" token="placeholder-thumb-token">https://szmmsns.qpic.cn/&lt;redacted&gt;/thumb.jpg</thumb>
          <size width="1440" height="1080" totalSize="123456" />
        </media>
      </mediaList>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        let media = parse_post_media(xml);
        assert_eq!(media.len(), 1);

        let item = media_object(&media[0]);
        assert_eq!(item.get("type").and_then(Value::as_str), Some("2"));
        assert_eq!(
            item.get("url").and_then(Value::as_str),
            Some("https://szmmsns.qpic.cn/<redacted>/image.jpg")
        );
        assert_eq!(
            item.get("thumb").and_then(Value::as_str),
            Some("https://szmmsns.qpic.cn/<redacted>/thumb.jpg")
        );
        assert_eq!(item.get("url_enc_idx").and_then(Value::as_str), Some("1"));
        assert_eq!(
            item.get("url_key").and_then(Value::as_str),
            Some("placeholder-key")
        );
        assert_eq!(
            item.get("url_token").and_then(Value::as_str),
            Some("placeholder-token")
        );
        assert_eq!(
            item.get("md5").and_then(Value::as_str),
            Some("placeholder-md5")
        );
        assert_eq!(item.get("width").and_then(Value::as_i64), Some(1440));
        assert_eq!(item.get("height").and_then(Value::as_i64), Some(1080));
        assert_eq!(item.get("total_size").and_then(Value::as_i64), Some(123456));
    }

    #[test]
    fn three_images_media() {
        let xml = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList>
        <media>
          <type>2</type>
          <sub_type>10</sub_type>
          <url enc_idx="1" key="placeholder-key-1" token="placeholder-token-1">https://szmmsns.qpic.cn/&lt;redacted&gt;/image-1.jpg</url>
          <thumb>https://szmmsns.qpic.cn/&lt;redacted&gt;/thumb-1.jpg</thumb>
          <size width="100" height="200" totalSize="111" />
        </media>
        <media>
          <type>2</type>
          <sub_type>11</sub_type>
          <url enc_idx="0" key="placeholder-key-2" token="placeholder-token-2">https://szmmsns.qpic.cn/&lt;redacted&gt;/image-2.jpg</url>
          <thumb>https://szmmsns.qpic.cn/&lt;redacted&gt;/thumb-2.jpg</thumb>
          <size width="300" height="400" totalSize="222" />
        </media>
        <media>
          <type>6</type>
          <url>https://szmmsns.qpic.cn/&lt;redacted&gt;/image-3.jpg</url>
          <thumb enc_idx="1" key="placeholder-thumb-key-3" token="placeholder-thumb-token-3">https://szmmsns.qpic.cn/&lt;redacted&gt;/thumb-3.jpg</thumb>
          <size width="500" height="600" totalSize="333" />
        </media>
      </mediaList>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        let media = parse_post_media(xml);
        assert_eq!(media.len(), 3);

        let first = media_object(&media[0]);
        assert_eq!(first.get("sub_type").and_then(Value::as_str), Some("10"));
        assert_eq!(
            first.get("url_key").and_then(Value::as_str),
            Some("placeholder-key-1")
        );

        let second = media_object(&media[1]);
        assert_eq!(second.get("sub_type").and_then(Value::as_str), Some("11"));
        assert_eq!(second.get("width").and_then(Value::as_i64), Some(300));

        let third = media_object(&media[2]);
        assert_eq!(third.get("type").and_then(Value::as_str), Some("6"));
        assert_eq!(
            third.get("thumb_key").and_then(Value::as_str),
            Some("placeholder-thumb-key-3")
        );
    }

    #[test]
    fn video_media() {
        let xml = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList>
        <media>
          <type>15</type>
          <url enc_idx="1" key="placeholder-video-key" token="placeholder-video-token">https://szmmsns.qpic.cn/&lt;redacted&gt;/video.mp4</url>
          <thumb>https://szmmsns.qpic.cn/&lt;redacted&gt;/video-thumb.jpg</thumb>
          <size width="720" height="1280" />
          <videomd5>&lt;placeholder-video-md5&gt;</videomd5>
          <videoDuration>37</videoDuration>
        </media>
      </mediaList>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        let media = parse_post_media(xml);
        assert_eq!(media.len(), 1);

        let item = media_object(&media[0]);
        assert_eq!(
            item.get("video_md5").and_then(Value::as_str),
            Some("<placeholder-video-md5>")
        );
        assert_eq!(item.get("video_duration").and_then(Value::as_i64), Some(37));
        assert!(!item.contains_key("total_size"));
    }

    #[test]
    fn text_only_post() {
        let without_media_list = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <type>1</type>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;
        let empty_media_list = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList />
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        assert!(parse_post_media(without_media_list).is_empty());
        assert!(parse_post_media(empty_media_list).is_empty());
    }

    #[test]
    fn malformed_xml() {
        let xml = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList>
        <media>
          <type>2</type>
      </mediaList>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        assert!(parse_post_media(xml).is_empty());
    }

    #[test]
    fn size_without_total_size_omits_total_size_key() {
        let xml = r#"
<SnsDataItem>
  <TimelineObject>
    <ContentObject>
      <mediaList>
        <media>
          <type>2</type>
          <size width="640" height="480" />
        </media>
      </mediaList>
    </ContentObject>
  </TimelineObject>
</SnsDataItem>
        "#;

        let media = parse_post_media(xml);
        assert_eq!(media.len(), 1);
        let item = media_object(&media[0]);
        assert_eq!(item.get("width").and_then(Value::as_i64), Some(640));
        assert_eq!(item.get("height").and_then(Value::as_i64), Some(480));
        assert!(!item.contains_key("total_size"));
    }
}
