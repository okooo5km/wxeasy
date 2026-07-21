pub mod cache;
pub mod meta;
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

    // 预热：只加载联系人（`load_names` 已经走 `DbCache::open_conn` 的 VFS 按需
    // 解页路径）。
    //
    // 曾经这里还会顺带 `db.get("session/session.db")` / `db.get("sns/sns.db")`
    // 抢先把这两个库整库 `full_decrypt` 一遍——目的是让第一次查询不用现场等
    // 全量解密。但 session.db 在慢机上可能有几百 MB，全量解密就是几十秒，
    // 这正是"wxeasy-daemon 冷启动几十秒/0.6.4 靠 20 分钟暖机窗口硬扛"的根因。
    // 现在所有查询点都已经迁移到 VFS 按需解页（见 `query.rs`），根本不需要
    // 全量解密就能查——预热阶段全量解密 session.db/sns.db 完全是浪费时间，
    // 直接去掉，daemon 冷启动从几十秒压到秒级。
    eprintln!("[daemon] 预热...");
    let names_raw = query::load_names(&*db).await.unwrap_or_else(|e| {
        eprintln!("[daemon] 加载联系人失败: {}", e);
        query::Names {
            map: HashMap::new(),
            md5_to_uname: HashMap::new(),
            msg_db_keys: Vec::new(),
            verify_flags: HashMap::new(),
        }
    });
    let mut names = names_raw;
    names.msg_db_keys = msg_db_keys;

    eprintln!("[daemon] 预热完成，联系人 {} 个", names.map.len());

    // 包一层内部 Arc：IPC 请求取 guard 后只做 Arc::clone（O(1)），
    // 避免每次请求都全量 clone 几千个联系人的 HashMap。
    // 用 tokio::sync::RwLock 允许 guard 跨 await（当前不跨，为未来 reload 留余地）。
    let names_arc = Arc::new(tokio::sync::RwLock::new(Arc::new(names)));

    // 启动 IPC server（阻塞）
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
