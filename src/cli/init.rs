use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config;
use crate::scanner;

pub fn cmd_init(force: bool, live: bool, relaunch: bool) -> Result<()> {
    // 查找 config.json
    let config_path = find_or_create_config_path();

    // 检查是否已初始化。显式 --live/--relaunch 意味着要重新抓，跳过短路。
    if !force && !live && !relaunch && config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                let db_dir = cfg.get("db_dir").and_then(|v| v.as_str()).unwrap_or("");
                let keys_file = cfg
                    .get("keys_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all_keys.json");
                let keys_path = if std::path::Path::new(keys_file).is_absolute() {
                    std::path::PathBuf::from(keys_file)
                } else {
                    config_path
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join(keys_file)
                };
                if !db_dir.is_empty()
                    && !db_dir.contains("your_wxid")
                    && std::path::Path::new(db_dir).exists()
                    && keys_path.exists()
                {
                    println!("已初始化，数据目录: {}", db_dir);
                    println!("如需重新扫描密钥，使用 --force");
                    return Ok(());
                }
            }
        }
    }

    // Step 1: 检测 db_dir
    println!("检测微信数据目录...");
    let db_dir = config::auto_detect_db_dir()
        .context("未能自动检测到微信数据目录\n请手动编辑 config.json 中的 db_dir 字段")?;
    println!("找到数据目录: {}", db_dir.display());

    // Step 2: 获取密钥。自动判断处理方式——
    //   · 先读微信版本：≤4.1.9 走 wx-cli 同源稳态扫描；≥4.1.10 先复用密钥，不自动 live-hook。
    //   · --live：附加已登录微信实时抓（增量）；--relaunch：带起微信一次抓齐（全量）。
    let entries = acquire_keys(&db_dir, &config_path, live, relaunch)?;

    // === 权限边界 ===
    // 扫描完成后立即 drop 到调用用户身份，后续文件写入都是用户属主。
    // 未来 daemon（由 `wxeasy sessions` 以用户身份 fork）才能往 ~/.wxeasy/
    // 写 socket/log/pid。
    #[cfg(unix)]
    drop_privileges_if_sudo()?;

    // 确保父目录存在（如 ~/.wxeasy/），必须在任何写入之前
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建目录失败: {}", parent.display()))?;
    }

    // Step 3: 保存 all_keys.json
    let keys_file_path = keys_file_path_of(&config_path);
    persist_keys(&keys_file_path, &entries)?;
    println!("成功准备 {} 个数据库密钥", entries.len());
    println!("密钥已保存: {}", keys_file_path.display());

    // Step 4: 保存 config.json
    let mut cfg = HashMap::new();
    // 读取已有配置
    if config_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&config_path) {
            if let Ok(v) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&c) {
                for (k, val) in v {
                    cfg.insert(k, val);
                }
            }
        }
    }
    cfg.insert("db_dir".into(), json!(db_dir.to_string_lossy()));
    cfg.entry("keys_file".into())
        .or_insert_with(|| json!("all_keys.json"));
    cfg.entry("decrypted_dir".into())
        .or_insert_with(|| json!("decrypted"));

    std::fs::write(&config_path, serde_json::to_string_pretty(&cfg)?)
        .context("写入 config.json 失败")?;
    println!("配置已保存: {}", config_path.display());

    // init 之后必须停掉旧 daemon（它用的是旧 config），下次调用会自动重启
    let _ = crate::cli::transport::stop_daemon();

    println!("初始化完成，可以使用 wxeasy sessions / wxeasy history 等命令了");

    #[cfg(target_os = "macos")]
    {
        eprintln!();
        eprintln!("[macOS] 副作用提示：");
        eprintln!("   如果你是通过对 /Applications/WeChat.app 做 ad-hoc 重签来让 init 走通的，");
        eprintln!("   之后 macOS 可能弹 \"微信\" 想访问其他 App 的数据（在微信里打开公众号文章");
        eprintln!("   时尤其常见）。这是 ad-hoc 重签后 WeChat 的 code identity 变了导致的，");
        eprintln!("   不是 wxeasy 在读其他 App 数据。");
        eprintln!("   完整说明：https://github.com/okooo5km/wxeasy/blob/main/docs/macos-permission-guide.md#六微信-想访问其他-app-的数据-弹窗");
        eprintln!("   （如果你的 WeChat 仍是 Apple 官方签名、init 是靠 GUI Terminal + 开发者工具");
        eprintln!("    授权走通的，则不会出现这个弹窗，可以忽略本提示。）");
    }

    Ok(())
}

pub fn cmd_wechat_version(json: bool) -> Result<()> {
    let report = scanner::version_report();
    let value = serde_json::to_value(&report)?;
    crate::cli::output::print_value(&value, &crate::cli::output::resolve(json))
}

/// 如果当前以 root 身份运行且是通过 sudo 启动的，drop 到调用用户身份，
/// 并迁移旧版本遗留的 root 属主 `~/.wxeasy/`。
///
/// 只影响本进程；daemon（后续 fork）会继承调用用户身份。
#[cfg(unix)]
fn drop_privileges_if_sudo() -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // 当前不是 root（用户直接以非 root 跑的 `wxeasy init`）→ 什么都不做
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let sudo_uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    let sudo_gid: Option<u32> = std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok());
    let (uid, gid) = match (sudo_uid, sudo_gid) {
        (Some(u), Some(g)) if u != 0 => (u, g),
        // 直接以 root 登陆（非 sudo），没有"调用用户"可还原 → 保持 root
        _ => return Ok(()),
    };

    // 迁移旧版本遗留：如果 ~/.wxeasy/ 已存在且属 root，把它 chown 回调用用户，
    // 顺便把 raw key 文件的权限也收紧到 0600（旧版默认 0644，世界可读等于泄露）。
    // 这些必须在 setuid 之前做：chown 需要 root，chmod 也只有属主或 root 能改。
    let cli_dir = config::cli_dir();
    if cli_dir.exists() {
        let _ = chown_recursive(&cli_dir, uid, gid);
        let _ = tighten_perms(&cli_dir);
    }

    // 设置 umask，让后续 create 出来的文件/目录默认是 0600 / 0700。
    unsafe {
        libc::umask(0o077);
    }

    // 必须先 setgid 再 setuid：一旦 uid 降下来就没法再改 gid 了。
    unsafe {
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({}) 失败: {}", gid, std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({}) 失败: {}", uid, std::io::Error::last_os_error());
        }
    }

    // chown 递归实现
    fn chown_recursive(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        chown_one(path, uid, gid)?;
        let md = std::fs::symlink_metadata(path)?;
        if md.is_dir() {
            for entry in std::fs::read_dir(path)? {
                chown_recursive(&entry?.path(), uid, gid)?;
            }
        }
        Ok(())
    }
    fn chown_one(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL")
        })?;
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// 目录收紧到 0700，所有 *.json 文件（含 all_keys.json 这类 raw key）收紧到 0600。
    fn tighten_perms(cli_dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cli_dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(cli_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(())
    }

    Ok(())
}

/// 获取密钥的决策入口：先读微信版本，再决定走哪条提钥路径。
///
/// - 显式 `--live` / `--relaunch`：直接走 live-hook（增量 / 全量），失败上抛。
/// - ≤4.1.9：wx-cli 同源的原始稳态扫描 + 历史复用。不自动 live-hook。
/// - ≥4.1.10：先校验复用 `all_keys.json`。缺钥时提示显式 `--live`，不自动切换。
/// - 版本未知：先尝试原始扫描再复用，仍然不自动 live-hook。
fn acquire_keys(
    db_dir: &Path,
    config_path: &Path,
    live: bool,
    relaunch: bool,
) -> Result<Vec<scanner::KeyEntry>> {
    let expected = scanner::collect_db_salts(db_dir).len();
    let version = scanner::detect_wechat_version();
    match version {
        Some(v) if v.uses_classic_scan() => {
            println!("检测到微信 {v}（≤4.1.9）：走原始稳态扫描，不自动切换 live-hook。");
        }
        Some(v) => {
            println!("检测到微信 {v}（≥4.1.10）：内存不再常驻 raw key。默认先复用已有密钥。");
        }
        None => {
            println!("未能读取微信客户端版本，先按原始稳态扫描 + 历史密钥复用处理。");
        }
    }

    // 显式实时抓取
    if live || relaunch {
        if let Some(v) = version {
            if v.uses_classic_scan() {
                eprintln!(
                    "提示：当前微信 {v} 通常用 `wxeasy init` 稳态扫描即可；`--live` / `--relaunch` 是 4.1.10+ 路径。仍按指定执行。"
                );
            } else {
                eprintln!(
                    "注意：4.1.10+ 客户端可能监测数据库解密／提钥。已有密钥请优先复用，不要无故重新抓取。"
                );
            }
        }
        let mode = if relaunch {
            scanner::LiveMode::Relaunch
        } else {
            scanner::LiveMode::Attach
        };
        return live_flow(db_dir, config_path, mode, expected);
    }

    // 已确认的 4.1.10+ 跳过原始扫描：特征串不在内存里，macOS 还可能逼出 ad-hoc 重签。
    let try_classic = version.map(|v| v.uses_classic_scan()).unwrap_or(true);
    let mut entries = Vec::new();
    if try_classic {
        println!("扫描加密密钥（需要管理员/root 权限）...");
        entries = scanner::scan_keys(db_dir).unwrap_or_else(|e| {
            eprintln!("内存扫描失败: {}", e);
            Vec::new()
        });
    }

    // 历史 all_keys.json 校验复用补缺
    if entries.len() < expected {
        println!(
            "{} {}/{}，尝试复用本机已有密钥并校验...",
            if try_classic {
                "内存扫描命中"
            } else {
                "高版本跳过内存扫描，当前密钥"
            },
            entries.len(),
            expected
        );
        let reused = reuse_verified_keys(db_dir, config_path, &entries);
        if reused.len() > entries.len() {
            println!("校验复用后可用密钥: {}/{}", reused.len(), expected);
            entries = reused;
        }
    }

    if entries.len() < expected {
        print_incomplete_guidance(version, entries.len(), expected);
    }

    if entries.is_empty() {
        anyhow::bail!("{}", empty_keys_hint(version, config_path));
    }

    Ok(entries)
}

fn print_incomplete_guidance(version: Option<scanner::WeChatVersion>, got: usize, expected: usize) {
    eprintln!("密钥尚未覆盖全部数据库（{got}/{expected}）。");
    match version {
        Some(v) if v.uses_classic_scan() => {
            eprintln!(
                "当前微信 {v} 应走原始稳态扫描。请确认微信正在运行，并在 macOS 上用 sudo / 必要的调试权限重试。"
            );
        }
        Some(v) => {
            eprintln!("当前微信 {v} ≥ 4.1.10，原始内存扫描通常 0 命中。");
            eprintln!("已有 all_keys.json 会自动校验复用；缺的库需要显式：");
            eprintln!("  wxeasy init --live      # 附加已登录微信，打开缺失会话触发开库");
            eprintln!("  wxeasy init --relaunch  # 重启微信并在登录时抓取");
            eprintln!(
                "新版客户端可能监测数据库解密／提钥。密钥已齐时不要 --force，也不要无故 live。"
            );
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            eprintln!("本机是 Intel Mac，LLDB 抓取尚未支持；缺钥时只能复用历史密钥，或把微信钉在 4.1.9 再扫描。");
        }
        None => {
            eprintln!("未能识别微信版本。已尝试原始稳态扫描 + 历史复用。");
            eprintln!("若微信是 4.1.9 及更早：确认进程在跑后重试 `wxeasy init`。");
            eprintln!("若微信是 4.1.10+：不要再盲扫，改用 `wxeasy init --live` 或 `--relaunch`。");
        }
    }
}

fn empty_keys_hint(version: Option<scanner::WeChatVersion>, config_path: &Path) -> String {
    let keys_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("all_keys.json");
    let version_line = match version {
        Some(v) if v.uses_classic_scan() => format!(
            "当前微信 {v} ≤ 4.1.9，原始稳态扫描应收齐密钥。请确认微信正在运行，并在 macOS 上使用 sudo。"
        ),
        Some(v) => format!(
            "当前微信 {v} ≥ 4.1.10，进程内存不再常驻 raw key。不要再用默认 `init` 盲扫。"
        ),
        None => "未能读取微信版本。4.1.9 及更早走默认扫描；4.1.10+ 必须显式 live-hook。".into(),
    };
    format!(
        "未能获取任何可用数据库密钥。\n\
         {version_line}\n\
         可行路径：\n\
         1) 把已有 all_keys.json 放到 {} 后重试（会做 page1 校验）\n\
         2) 微信 4.1.9 及更早：保持微信运行，再执行 `wxeasy init` / `sudo wxeasy init`\n\
         3) 微信 4.1.10+（Windows／macOS Apple Silicon）：`wxeasy init --live` 或 `--relaunch`",
        keys_path.display()
    )
}

/// 显式实时抓取流程。
///
/// **先**用历史 all_keys.json 校验复用垫底，再把已可用的库作为 `existing` 传给
/// live-hook——否则 Attach 模式下微信登录时已开过的库不会再触发开库，`done` 永远
/// 到不了 `total`，事件循环会空转到用户 Ctrl-C，且补缺发生在抓取之后而永不执行。
fn live_flow(
    db_dir: &Path,
    config_path: &Path,
    mode: scanner::LiveMode,
    expected: usize,
) -> Result<Vec<scanner::KeyEntry>> {
    // 历史复用垫底：让 live 只针对真正缺失的库
    let mut entries = reuse_verified_keys(db_dir, config_path, &[]);
    if !entries.is_empty() {
        println!(
            "历史密钥校验复用 {}/{} 个，实时抓取只针对缺失的库。",
            entries.len(),
            expected
        );
    }
    if entries.len() >= expected {
        println!("历史密钥已覆盖全部库，无需实时抓取。");
        return Ok(entries);
    }

    // 保命：抓取前先把已复用的落盘，避免实时抓取被 Ctrl-C 中断时丢失
    let _ = persist_keys(&keys_file_path_of(config_path), &entries);

    let live_found = scanner::capture_keys_live(db_dir, mode, &entries)?;
    merge_entries(&mut entries, live_found.into_iter());

    // 抓取后再复用补缺（幂等兜底）
    if entries.len() < expected {
        let reused = reuse_verified_keys(db_dir, config_path, &entries);
        if reused.len() > entries.len() {
            entries = reused;
        }
    }
    Ok(entries)
}

/// 把新抓到的密钥并入 base（按 db_name 去重，已有的不覆盖）。
fn merge_entries(
    base: &mut Vec<scanner::KeyEntry>,
    extra: impl Iterator<Item = scanner::KeyEntry>,
) {
    use std::collections::HashSet;
    let mut names: HashSet<String> = base.iter().map(|e| e.db_name.clone()).collect();
    for e in extra {
        if names.insert(e.db_name.clone()) {
            base.push(e);
        }
    }
}

/// all_keys.json 的落盘路径（config.json 同目录）。
fn keys_file_path_of(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("all_keys.json")
}

/// 把密钥写入 all_keys.json（`{db_name: {enc_key}}`）。
fn persist_keys(keys_file_path: &Path, entries: &[scanner::KeyEntry]) -> Result<()> {
    let mut keys_json = serde_json::Map::new();
    for entry in entries {
        keys_json.insert(entry.db_name.clone(), json!({ "enc_key": entry.enc_key }));
    }
    if let Some(parent) = keys_file_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(keys_file_path, serde_json::to_string_pretty(&keys_json)?)
        .context("写入 all_keys.json 失败")?;
    Ok(())
}

/// 从本机已有 all_keys.json 候选中复用仍能通过 page1 校验的密钥。
/// 合并策略：内存扫描结果优先，缺失项用旧密钥补齐。
fn reuse_verified_keys(
    db_dir: &std::path::Path,
    config_path: &std::path::Path,
    scanned: &[scanner::KeyEntry],
) -> Vec<scanner::KeyEntry> {
    use crate::crypto::verify_enc_key_for_db;
    use std::collections::HashMap;

    let mut by_db: HashMap<String, scanner::KeyEntry> = HashMap::new();
    for e in scanned {
        by_db.insert(e.db_name.clone(), e.clone());
    }

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(parent) = config_path.parent() {
        candidates.push(parent.join("all_keys.json"));
    }
    candidates.push(config::cli_dir().join("all_keys.json"));
    // 兼容改名前的 wx-cli 配置目录
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".wx-cli").join("all_keys.json"));
        candidates.push(home.join(".wxeasy").join("all_keys.json"));
    }

    for path in candidates {
        if !path.exists() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(map) = v.as_object() else {
            continue;
        };
        eprintln!("校验旧密钥文件: {}", path.display());
        for (db_name, meta) in map {
            if by_db.contains_key(db_name) {
                continue;
            }
            let enc_key = meta
                .get("enc_key")
                .and_then(|x| x.as_str())
                .or_else(|| meta.as_str())
                .unwrap_or("");
            if enc_key.len() != 64 || !enc_key.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let Ok(key_bytes) = hex_decode32(enc_key) else {
                continue;
            };
            let db_path = db_dir.join(db_name.replace('/', std::path::MAIN_SEPARATOR_STR));
            if !db_path.exists() {
                continue;
            }
            if verify_enc_key_for_db(&db_path, &key_bytes) {
                by_db.insert(
                    db_name.clone(),
                    scanner::KeyEntry {
                        db_name: db_name.clone(),
                        enc_key: enc_key.to_lowercase(),
                        salt: String::new(),
                    },
                );
            }
        }
    }

    by_db.into_values().collect()
}

fn hex_decode32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("bad hex len");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("hex: {}", e))?;
        out[i] = b;
    }
    Ok(out)
}

fn find_or_create_config_path() -> std::path::PathBuf {
    // 如果当前工作目录或可执行文件目录已有 config.json，沿用它（支持便携模式）
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("config.json");
        if p.exists() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.json");
            if p.exists() {
                return p;
            }
        }
    }
    // 默认写入 ~/.wxeasy/config.json（与 load_config 的最终查找路径保持一致）
    config::cli_dir().join("config.json")
}
