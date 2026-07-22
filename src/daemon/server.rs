use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::cache::DbCache;
use super::query::Names;
use crate::ipc::{Request, Response};

/// 启动 IPC server（Unix socket / Windows named pipe）
///
/// FIX 4（socket 先于 contact.db 加载可见）：`names` 用 `Option<Arc<Names>>`
/// 而不是 `Arc<Names>`——`None` 表示"daemon 联系人还在后台加载中"，`Some`
/// 表示"已就绪，可以正常提供依赖 names 的查询"。`mod.rs::async_run` 现在
/// 把 `query::load_names` 放进一个独立的 `tokio::spawn` 后台任务，`serve`
/// 本身（socket/pipe 绑定 + accept 循环）不再等它完成——这样即便
/// `contact.db` 在慢机上要扫很久，CLI 的存活探测（`Request::Ping`，`serve`
/// 绑定完成后立刻可服务，见 [`dispatch`]）也不会被拖慢，从根上解决"CLI
/// 15s 启动超时被机械盘上的 contact.db 冷扫触发"这个问题。
pub async fn serve(db: Arc<DbCache>, names: Arc<tokio::sync::RwLock<Option<Arc<Names>>>>) -> Result<()> {
    #[cfg(unix)]
    serve_unix(db, names).await?;
    #[cfg(windows)]
    serve_windows(db, names).await?;
    Ok(())
}

#[cfg(unix)]
async fn serve_unix(db: Arc<DbCache>, names: Arc<tokio::sync::RwLock<Option<Arc<Names>>>>) -> Result<()> {
    use tokio::net::UnixListener;
    let sock_path = crate::config::sock_path();

    // 删除旧 socket 文件
    if sock_path.exists() {
        let _ = tokio::fs::remove_file(&sock_path).await;
    }

    let listener = UnixListener::bind(&sock_path)?;
    // 设置权限 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("[server] 监听 {}", sock_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let db2 = Arc::clone(&db);
        let names2 = Arc::clone(&names);

        tokio::spawn(async move {
            if let Err(e) = handle_connection_unix(stream, db2, names2).await {
                eprintln!("[server] 连接处理错误: {}", e);
            }
        });
    }
}

#[cfg(unix)]
async fn handle_connection_unix(
    stream: tokio::net::UnixStream,
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Option<Arc<Names>>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let line = match lines.next_line().await? {
        Some(l) => l,
        None => return Ok(()),
    };

    // 解析请求
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("JSON 解析错误: {}", e));
            writer.write_all(resp.to_json_line()?.as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = dispatch(req, &db, &names).await;
    writer.write_all(resp.to_json_line()?.as_bytes()).await?;
    Ok(())
}

#[cfg(windows)]
async fn serve_windows(
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Option<Arc<Names>>>>,
) -> Result<()> {
    use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced, ListenerOptions};

    // interprocess 的 GenericNamespaced 在 Windows 上会自动拼接 `\\.\pipe\` 前缀，
    // 这里必须传相对名；client 端用 `\\.\pipe\wxeasy-daemon` 直接打开可以对上
    let name = "wxeasy-daemon".to_ns_name::<GenericNamespaced>()?;
    let opts = ListenerOptions::new().name(name);
    let listener = opts.create_tokio()?;

    eprintln!("[server] 监听 \\\\.\\pipe\\wxeasy-daemon");

    loop {
        let conn = listener.accept().await?;
        let db2 = Arc::clone(&db);
        let names2 = Arc::clone(&names);

        tokio::spawn(async move {
            if let Err(e) = handle_connection_windows(conn, db2, names2).await {
                eprintln!("[server] 连接处理错误: {}", e);
            }
        });
    }
}

#[cfg(windows)]
async fn handle_connection_windows(
    conn: interprocess::local_socket::tokio::Stream,
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Option<Arc<Names>>>>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(conn);
    let mut lines = BufReader::new(reader).lines();

    let line = match lines.next_line().await? {
        Some(l) => l,
        None => return Ok(()),
    };

    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("JSON 解析错误: {}", e));
            writer.write_all(resp.to_json_line()?.as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = dispatch(req, &db, &names).await;
    writer.write_all(resp.to_json_line()?.as_bytes()).await?;
    Ok(())
}

/// FIX 4：`names` 在联系人加载完成前是 `None`（"预热中"），完成后被后台
/// 任务原子地换成 `Some(Arc<Names>)`（一次性构建，之后不可变，共享 `Arc`
/// 即可，见旧版注释）。
///
/// `Ping` / `ReloadConfig` 不依赖 names，提前处理、不等锁里的值是否就绪——
/// 尤其是 `Ping`：`cli/transport.rs::is_alive` 全靠它判断"daemon 是否已经
/// 起来到能接受连接"，必须在 socket 绑定后立刻可用，不能等 contact.db 扫完。
///
/// 其余请求目前统一按"依赖 names"处理：本次修复的范围是"让 socket 尽快
/// 可连接 + 让预热中状态可辨识"，没有对每个 query 函数做"是否真的用到
/// contact 派生字段"的逐一审计——保守地统一处理，未就绪时返回
/// [`Response::warming_up`]，绝不用一份空/半成品的 `Names` 悄悄提供服务
/// （那会让会话显示名、群昵称、`is_verified` 判定全部错乱，比"稍等重试"
/// 更糟）。细粒度放行"不依赖 names 的纯分片查询"留作后续优化，见
/// `mod.rs` 里 FIX 4 的说明。
async fn dispatch(
    req: Request,
    db: &DbCache,
    names: &tokio::sync::RwLock<Option<Arc<Names>>>,
) -> Response {
    use super::query;
    use crate::ipc::Request::*;

    if matches!(req, Ping) {
        return Response::ok(serde_json::json!({ "pong": true }));
    }
    if matches!(req, ReloadConfig) {
        return Response::ok(serde_json::json!({ "reloading": true }));
    }

    // 取 guard → O(1) clone Arc → 立即 drop 锁。后续 await 期间不持有锁，
    // 多个并发 IPC 请求可以真正并行。
    let names_arc: Arc<Names> = {
        let guard = names.read().await;
        match guard.as_ref() {
            Some(n) => Arc::clone(n),
            None => {
                return Response::warming_up(
                    "daemon 正在后台加载联系人（预热中），请稍后重试",
                );
            }
        }
    };

    match req {
        Ping | ReloadConfig => unreachable!("Ping / ReloadConfig 已在上面提前返回"),
        Sessions {
            limit,
            with_meta,
            debug_source,
        } => match query::q_sessions(db, &names_arc, limit, with_meta, debug_source).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        History {
            chat,
            limit,
            offset,
            since,
            until,
            msg_type,
            with_meta,
            debug_source,
        } => {
            match query::q_history(
                db,
                &names_arc,
                &chat,
                limit,
                offset,
                since,
                until,
                msg_type,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Search {
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            with_meta,
            debug_source,
        } => {
            match query::q_search(
                db,
                &names_arc,
                &keyword,
                chats,
                limit,
                since,
                until,
                msg_type,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Contacts { query, limit } => {
            match query::q_contacts(&names_arc, query.as_deref(), limit).await {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Unread {
            limit,
            filter,
            with_meta,
            debug_source,
        } => match query::q_unread(db, &names_arc, limit, filter, with_meta, debug_source).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        Members { chat } => match query::q_members(db, &names_arc, &chat).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        NewMessages {
            state,
            limit,
            with_meta,
            debug_source,
        } => {
            match query::q_new_messages(db, &names_arc, state, limit, with_meta, debug_source).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Favorites {
            limit,
            fav_type,
            query,
        } => match query::q_favorites(db, limit, fav_type, query).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        Stats {
            chat,
            since,
            until,
            with_meta,
            debug_source,
        } => {
            match query::q_stats(db, &names_arc, &chat, since, until, with_meta, debug_source).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        SnsNotifications {
            limit,
            since,
            until,
            include_read,
        } => {
            match query::q_sns_notifications(db, &names_arc, limit, since, until, include_read)
                .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        SnsFeed {
            limit,
            since,
            until,
            user,
        } => match query::q_sns_feed(db, &names_arc, limit, since, until, user.as_deref()).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        SnsSearch {
            keyword,
            limit,
            since,
            until,
            user,
        } => {
            match query::q_sns_search(
                db,
                &names_arc,
                &keyword,
                limit,
                since,
                until,
                user.as_deref(),
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        BizArticles {
            limit,
            account,
            since,
            until,
            unread,
        } => {
            match query::q_biz_articles(db, &names_arc, limit, account, since, until, unread).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Attachments {
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            with_meta,
            debug_source,
        } => {
            match query::q_attachments(
                db,
                &names_arc,
                &chat,
                kinds,
                limit,
                offset,
                since,
                until,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Extract {
            attachment_id,
            output,
            overwrite,
        } => match query::q_extract(db, &names_arc, &attachment_id, &output, overwrite).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
    }
}

/// FIX 4 单元测试：`dispatch` 在 `names` 未就绪（`None`）时的分支行为——
/// `Ping`/`ReloadConfig` 不等待、立刻正常响应；其它请求返回
/// `Response::warming_up`（而不是一个看似成功但内容是空/半成品的响应）；
/// `names` 就绪后恢复正常路由，不再卡在预热分支。
#[cfg(test)]
mod dispatch_warmup_tests {
    use super::super::cache::test_support::unique_tmpdir;
    use super::*;
    use std::collections::HashMap;

    async fn empty_db(tag: &str) -> DbCache {
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

    fn empty_names() -> Names {
        Names {
            map: HashMap::new(),
            md5_to_uname: HashMap::new(),
            msg_db_keys: Vec::new(),
            verify_flags: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn ping_answers_immediately_even_while_names_not_ready() {
        let db = empty_db("dispatch-warmup-ping").await;
        let names: tokio::sync::RwLock<Option<Arc<Names>>> = tokio::sync::RwLock::new(None);

        let resp = dispatch(Request::Ping, &db, &names).await;
        assert!(resp.ok, "Ping 不依赖 names，即便未就绪也必须立刻正常响应");
        assert!(!resp.warming_up);
        assert_eq!(
            resp.data.get("pong").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn reload_config_answers_immediately_even_while_names_not_ready() {
        let db = empty_db("dispatch-warmup-reload").await;
        let names: tokio::sync::RwLock<Option<Arc<Names>>> = tokio::sync::RwLock::new(None);

        let resp = dispatch(Request::ReloadConfig, &db, &names).await;
        assert!(resp.ok, "ReloadConfig 不依赖 names，即便未就绪也必须立刻正常响应");
        assert!(!resp.warming_up);
    }

    #[tokio::test]
    async fn names_dependent_request_returns_warming_up_while_not_ready() {
        let db = empty_db("dispatch-warmup-sessions-cold").await;
        let names: tokio::sync::RwLock<Option<Arc<Names>>> = tokio::sync::RwLock::new(None);

        let resp = dispatch(
            Request::Sessions {
                limit: 20,
                with_meta: false,
                debug_source: false,
            },
            &db,
            &names,
        )
        .await;

        assert!(
            !resp.ok,
            "预热中响应的 ok 必须是 false，保证只看 ok/error 的旧客户端安全退化为报错"
        );
        assert!(
            resp.warming_up,
            "必须显式标记 warming_up=true，供新客户端区分预热中与真失败"
        );
        assert!(resp.error.is_some(), "预热中响应也应该带一句人类可读的说明");
        assert_eq!(
            resp.data,
            serde_json::Value::Null,
            "预热中响应不应该携带任何看似有效的业务数据"
        );
    }

    /// 未就绪时不止 Sessions，任意一个"依赖 names"的请求都应该走同一条
    /// warming_up 分支，不能挑着放行——这里用 Members / NewMessages 再
    /// 交叉验证一次，覆盖之前直接引用 `names_arc` 字段的两类典型用法
    /// （聊天名解析 / 会话 map 遍历）。
    #[tokio::test]
    async fn other_names_dependent_requests_also_return_warming_up() {
        let db = empty_db("dispatch-warmup-others").await;
        let names: tokio::sync::RwLock<Option<Arc<Names>>> = tokio::sync::RwLock::new(None);

        let members_resp = dispatch(
            Request::Members {
                chat: "someone".to_string(),
            },
            &db,
            &names,
        )
        .await;
        assert!(members_resp.warming_up);

        let new_messages_resp = dispatch(
            Request::NewMessages {
                state: None,
                limit: 200,
                with_meta: false,
                debug_source: false,
            },
            &db,
            &names,
        )
        .await;
        assert!(new_messages_resp.warming_up);
    }

    #[tokio::test]
    async fn names_dependent_request_no_longer_warms_up_once_ready() {
        let db = empty_db("dispatch-warmup-ready").await;
        let names: tokio::sync::RwLock<Option<Arc<Names>>> =
            tokio::sync::RwLock::new(Some(Arc::new(empty_names())));

        let resp = dispatch(
            Request::Sessions {
                limit: 20,
                with_meta: false,
                debug_source: false,
            },
            &db,
            &names,
        )
        .await;

        // names 已就绪后必须真正路由到 q_sessions（这里用的空夹具 DbCache
        // 没有注册任何密钥，q_sessions 会因为找不到 session.db 的密钥而
        // 返回 Err——这是预期之中的、与"预热中"完全无关的失败，用来确认
        // 请求确实穿过了 warming_up 分支、走到了真正的查询路径）。
        assert!(
            !resp.warming_up,
            "names 已就绪时绝不应该再落入预热中分支"
        );
    }
}
