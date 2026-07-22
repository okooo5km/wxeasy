pub mod cache;
pub mod meta;
mod names_cache;
pub mod query;
pub mod server;
pub mod vfs;
pub mod wal_index;

/// 函数级 oracle 对拍（`DbCache::open_conn` vs `full_decrypt`+`Connection::open`）。
/// 需要真实微信数据 + 密钥（经环境变量传入），只在 `cargo test` 里编译、且用
/// `#[ignore]` 默认跳过，不影响正常 `cargo build` / CI 单测。
#[cfg(test)]
mod vfs_oracle;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config;

/// daemon 入口
///
/// 当 WXEASY_DAEMON_MODE 环境变量设置时，main() 调用此函数
pub fn run() {
    let rt = tokio::runtime::Runtime::new().expect("无法创建 tokio runtime");
    if let Err(e) = rt.block_on(async_run()) {
        eprintln!("[daemon] 启动失败: {}", e);
        std::process::exit(1);
    }
}

async fn async_run() -> Result<()> {
    // 确保工作目录存在
    let cli_dir = config::cli_dir();
    tokio::fs::create_dir_all(&cli_dir).await?;
    tokio::fs::create_dir_all(config::cache_dir()).await?;

    let pid = std::process::id();

    // 注册 SIGTERM / SIGINT 处理
    setup_signal_handler().await;

    eprintln!("[daemon] wxeasy-daemon 启动 (PID {})", pid);

    // 加载配置
    let cfg = config::load_config()?;
    eprintln!("[daemon] DB_DIR: {}", cfg.db_dir.display());

    // 加载密钥
    let keys_content = tokio::fs::read_to_string(&cfg.keys_file)
        .await
        .map_err(|e| anyhow::anyhow!("读取密钥文件 {:?} 失败: {}", cfg.keys_file, e))?;
    let keys_raw: serde_json::Value = serde_json::from_str(&keys_content)?;
    let all_keys = extract_keys(&keys_raw);
    eprintln!("[daemon] 密钥数量: {}", all_keys.len());

    // 初始化 DbCache
    let db = Arc::new(cache::DbCache::new(cfg.db_dir.clone(), all_keys.clone()).await?);

    // 收集消息 DB 列表
    let msg_db_keys: Vec<String> = all_keys
        .keys()
        .filter(|k| {
            let k = k.replace('\\', "/");
            k.contains("message/message_")
                && k.ends_with(".db")
                && !k.contains("_fts")
                && !k.contains("_resource")
        })
        .cloned()
        .collect();

    // FIX ②：热连接池容量按实际分片数伸缩，避免固定 12 在大账号（可能
    // 65~80 个消息分片）下形同虚设、LRU 反复抖动驱逐。必须晚于
    // `msg_db_keys` 确定、早于任何查询开始服务（此刻池子还是空的，见
    // `cache::HotConnPool::set_capacity` 文档）。
    let hot_pool_capacity = cache::hot_pool_capacity_for_shard_count(msg_db_keys.len());
    db.set_hot_pool_capacity(hot_pool_capacity);
    eprintln!(
        "[daemon] 热连接池容量: {} (消息分片数: {})",
        hot_pool_capacity,
        msg_db_keys.len()
    );

    // FIX ④（socket 先于 contact.db 加载可见）：
    //
    // 曾经这里会同步 `.await` `load_names()`（扫 `contact` 全表）完成之后，
    // 才把 `names_arc` 传给 `server::serve()` 去绑定 socket/pipe——意味着
    // socket/pipe 在联系人加载完成前压根不存在。`contact.db` 在机械盘上可能
    // 是几十万行的全表冷扫，慢到能撑满甚至超过
    // `cli/transport.rs::STARTUP_TIMEOUT_SECS`（15 秒）——CLI 那 15 秒本意是
    // 等"daemon 进程起来、socket 可连接"，结果被"进程早就起来了、只是
    // socket 还没绑"这个额外的串行阶段吃掉，表现成"daemon 启动超时"，但
    // 实际上 daemon 只是在扫 contact 表（今日已实测撞到一次）。
    //
    // 现在把 socket/pipe 绑定（`server::serve` 内部）和 `load_names()` 解耦：
    // `names_arc` 先以"未就绪"（`None`）状态传给 `serve()`，`serve()` 立刻
    // 绑定 socket/pipe、开始 accept 连接——`Request::Ping`（`is_alive` 唯一
    // 依赖的请求，见 `server::dispatch` 文档）在这一刻就能正常响应，不再被
    // contact.db 冷扫拖慢。`load_names()` 挪进一个独立的后台 `tokio::spawn`，
    // 完成后把结果原子地换成 `Some(Arc<Names>)`。
    //
    // 曾经这里还会顺带 `db.get("session/session.db")` / `db.get("sns/sns.db")`
    // 抢先把这两个库整库 `full_decrypt` 一遍——目的是让第一次查询不用现场等
    // 全量解密。但 session.db 在慢机上可能有几百 MB，全量解密就是几十秒，
    // 这正是"wxeasy-daemon 冷启动几十秒/0.6.4 靠 20 分钟暖机窗口硬扛"的根因。
    // 现在所有查询点都已经迁移到 VFS 按需解页（见 `query.rs`），根本不需要
    // 全量解密就能查——预热阶段全量解密 session.db/sns.db 完全是浪费时间，
    // 直接去掉，daemon 冷启动从几十秒压到秒级。
    //
    // 用 `Option<Arc<Names>>` 而不是"先塞一个只有 msg_db_keys、其它字段为空
    // 的半成品 `Names`"：`None` 是一个类型层面就无法被误读成"联系人表真的
    // 是空的"的显式状态，`server::dispatch` 据此统一返回"预热中"响应（见其
    // 文档），绝不会用半成品数据悄悄提供服务、把会话显示名/群昵称/
    // `is_verified` 判定搞错。
    let names_arc: Arc<tokio::sync::RwLock<Option<Arc<query::Names>>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    {
        let db_for_names = Arc::clone(&db);
        let names_arc_for_task = Arc::clone(&names_arc);
        let msg_db_keys_for_task = msg_db_keys.clone();
        tokio::spawn(async move {
            eprintln!("[daemon] 后台加载联系人...");
            let t0 = std::time::Instant::now();
            let names_raw = query::load_names(&*db_for_names).await.unwrap_or_else(|e| {
                eprintln!("[daemon] 加载联系人失败: {}", e);
                query::Names {
                    map: HashMap::new(),
                    md5_to_uname: HashMap::new(),
                    msg_db_keys: Vec::new(),
                    verify_flags: HashMap::new(),
                }
            });
            let mut names = names_raw;
            names.msg_db_keys = msg_db_keys_for_task;

            eprintln!(
                "[daemon] 联系人加载完成，共 {} 个 ({}ms)",
                names.map.len(),
                t0.elapsed().as_millis()
            );

            let mut guard = names_arc_for_task.write().await;
            *guard = Some(Arc::new(names));
        });
    }

    // 启动 IPC server（阻塞）——socket/pipe 在这一刻就绑定，不等待上面的
    // 后台加载任务完成。
    let serve_result = server::serve(Arc::clone(&db), Arc::clone(&names_arc)).await;
    cleanup_ipc_files();
    serve_result?;

    Ok(())
}

/// 从 all_keys.json 提取 rel_key -> enc_key 映射
///
/// 兼容两种格式：
/// - `{ "rel/path.db": { "enc_key": "hex" } }`（Python 版原生格式）
/// - `{ "rel/path.db": "hex" }`（简化格式）
fn extract_keys(json: &serde_json::Value) -> HashMap<String, String> {
    let mut result = HashMap::new();
    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            if k.starts_with('_') {
                continue;
            }
            let enc_key = if let Some(s) = v.as_str() {
                s.to_string()
            } else if let Some(obj2) = v.as_object() {
                obj2.get("enc_key")
                    .and_then(|e| e.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                continue;
            };
            if !enc_key.is_empty() {
                // 统一路径分隔符
                let rel = k.replace('\\', "/");
                result.insert(rel, enc_key);
            }
        }
    }
    result
}

/// 设置信号处理（Unix: SIGTERM/SIGINT）
async fn setup_signal_handler() {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("无法监听 SIGTERM");
        let mut int = signal(SignalKind::interrupt()).expect("无法监听 SIGINT");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        cleanup_and_exit();
    });
}

#[cfg(unix)]
fn cleanup_and_exit() {
    cleanup_ipc_files();
    std::process::exit(0);
}

fn cleanup_ipc_files() {
    let _ = std::fs::remove_file(config::sock_path());
    let _ = std::fs::remove_file(config::pid_path());
}
