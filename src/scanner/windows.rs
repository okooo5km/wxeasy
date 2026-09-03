/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
use anyhow::Result;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOCACHE, PAGE_READWRITE, PAGE_WRITECOMBINE,
    PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{collect_db_salts, KeyEntry};

const HEX_PATTERN_LEN: usize = 96;
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 查找所有 Weixin.exe 进程 PID（4.x 常有多进程，密钥可能不在主进程）
fn find_wechat_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(s) => s,
        Err(_) => return pids,
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return pids;
        }
        loop {
            let name =
                std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
            if name.eq_ignore_ascii_case("Weixin.exe") {
                pids.push(entry.th32ProcessID);
            }
            if Process32Next(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    // 冷启动：稳态下 4.1.10+ 常常 0 命中；多轮短窗可提高登录/开库瞬间的抓取率。
    // 环境变量：WXEASY_SCAN_ROUNDS（默认 1）、WXEASY_SCAN_INTERVAL_MS（默认 400）
    let rounds: usize = std::env::var("WXEASY_SCAN_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let interval_ms: u64 = std::env::var("WXEASY_SCAN_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());
    if db_salts.is_empty() {
        anyhow::bail!("数据目录下没有加密 .db：{}", db_dir.display());
    }

    // salt -> db_name（同一 salt 理论上只对应一个库）
    let mut salt_to_db: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (salt, name) in &db_salts {
        salt_to_db
            .entry(salt.clone())
            .or_insert_with(|| name.clone());
    }

    // page1 校验用：预读各库路径
    let db_paths: Vec<(String, std::path::PathBuf)> = db_salts
        .iter()
        .map(|(_salt, name)| {
            let p = db_dir.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
            (name.clone(), p)
        })
        .collect();

    let mut matched: std::collections::HashMap<String, KeyEntry> = std::collections::HashMap::new();
    let mut total_candidates = 0usize;

    for round in 1..=rounds {
        let pids = find_wechat_pids();
        if pids.is_empty() {
            if round == 1 {
                anyhow::bail!("找不到 Weixin.exe 进程，请确认微信正在运行");
            }
            eprintln!("轮次 {}/{}: Weixin 尚未出现，等待...", round, rounds);
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            continue;
        }
        if round == 1 || rounds > 1 {
            eprintln!("轮次 {}/{} WeChat PIDs: {:?}", round, rounds, pids);
        }

        for pid in pids {
            // SAFETY: OpenProcess 请求读取权限
            let process = match unsafe {
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            } {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("PID {} OpenProcess 失败: {}（可尝试管理员权限）", pid, e);
                    continue;
                }
            };

            eprintln!("扫描进程内存 PID {} ...", pid);
            let raw_keys = match scan_memory(process) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("PID {} 扫描失败: {}", pid, e);
                    unsafe {
                        let _ = CloseHandle(process);
                    }
                    continue;
                }
            };
            total_candidates += raw_keys.len();
            eprintln!("PID {} 找到 {} 个候选密钥", pid, raw_keys.len());

            // SAFETY: 关闭进程句柄
            unsafe {
                let _ = CloseHandle(process);
            }

            for (key_hex, salt_hex) in raw_keys {
                if matched.len() >= db_salts.len() {
                    break;
                }
                // 1) salt 直接命中（古典路径）
                if !salt_hex.is_empty() {
                    if let Some(db_name) = salt_to_db.get(&salt_hex) {
                        matched.entry(db_name.clone()).or_insert(KeyEntry {
                            db_name: db_name.clone(),
                            enc_key: key_hex.clone(),
                            salt: salt_hex.clone(),
                        });
                        continue;
                    }
                }

                // 2) 4.1.10+ ：无可靠 salt 时，用 page1 强校验对未匹配库试钥
                let Ok(key_bytes) = hex_to_32(&key_hex) else {
                    continue;
                };
                for (db_name, db_path) in &db_paths {
                    if matched.contains_key(db_name) {
                        continue;
                    }
                    if crate::crypto::verify_enc_key_for_db(db_path, &key_bytes) {
                        let salt = super::read_db_salt(db_path).unwrap_or_default();
                        matched.insert(
                            db_name.clone(),
                            KeyEntry {
                                db_name: db_name.clone(),
                                enc_key: key_hex.clone(),
                                salt,
                            },
                        );
                        eprintln!("page1 校验命中: {}", db_name);
                    }
                }
            }

            if matched.len() >= db_salts.len() {
                break;
            }
        }

        if matched.len() >= db_salts.len() {
            break;
        }
        if round < rounds {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }

    let entries: Vec<KeyEntry> = matched.into_values().collect();
    eprintln!(
        "匹配到 {}/{} 个密钥（候选总数 {}，轮次 {}）",
        entries.len(),
        db_salts.len(),
        total_candidates,
        rounds
    );
    if entries.is_empty() {
        eprintln!(
            "提示: 微信 4.1.10+ 可能启用 cipher_memory_security，稳态内存中不再常驻明文 raw key / x'<key><salt>'。\n\
             冷启动尝试: 退出微信后运行 set WXEASY_SCAN_ROUNDS=40 再 wxeasy init --force，随即重新登录微信。\n\
             若有升级前 all_keys.json，init 会自动校验复用。"
        );
    }
    Ok(entries)
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("bad len");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(out)
}

fn scan_memory(process: HANDLE) -> Result<Vec<(String, String)>> {
    let mut results: Vec<(String, String)> = Vec::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        // 只扫描已提交的可读可写页面。Windows 的保护位可能带 modifier bits，
        // 也可能是 WRITECOPY / EXECUTE_READWRITE 这种同样可读可写的保护类型。
        if mbi.State == MEM_COMMIT && is_writable_readable_page(mbi.Protect.0) {
            scan_region(process, base, region_size, &mut results);
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }

    Ok(results)
}

fn is_writable_readable_page(protect: u32) -> bool {
    let base = protect & !(PAGE_GUARD.0 | PAGE_NOCACHE.0 | PAGE_WRITECOMBINE.0);
    matches!(
        base,
        x if x == PAGE_READWRITE.0
            || x == PAGE_WRITECOPY.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
    )
}

fn scan_region(process: HANDLE, base: usize, size: usize, results: &mut Vec<(String, String)>) {
    let overlap = HEX_PATTERN_LEN + 3;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            search_pattern(&buf, results);
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

#[inline]
fn is_hex_char(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    // 1) 经典 WCDB/SQLCipher raw key 串：x'<64hex_key><32hex_salt>'
    let total = HEX_PATTERN_LEN + 3;
    if buf.len() >= total {
        let mut i = 0;
        while i + total <= buf.len() {
            if buf[i] != b'x' || buf[i + 1] != b'\'' {
                i += 1;
                continue;
            }
            let hex_start = i + 2;
            let all_hex = buf[hex_start..hex_start + HEX_PATTERN_LEN]
                .iter()
                .all(|&c| is_hex_char(c));
            if !all_hex {
                i += 1;
                continue;
            }
            if buf[hex_start + HEX_PATTERN_LEN] != b'\'' {
                i += 1;
                continue;
            }
            let key_hex = String::from_utf8_lossy(&buf[hex_start..hex_start + 64]).to_lowercase();
            let salt_hex =
                String::from_utf8_lossy(&buf[hex_start + 64..hex_start + 96]).to_lowercase();
            let is_dup = results.iter().any(|(k, s)| k == &key_hex && s == &salt_hex);
            if !is_dup {
                results.push((key_hex, salt_hex));
            }
            i += total;
        }
    }

    // 2) 4.1.10+ 兼容：无 x'...' 包裹的 96 连续 hex（key||salt）
    if buf.len() >= 96 {
        let mut i = 0;
        while i + 96 <= buf.len() {
            if !is_hex_char(buf[i]) {
                i += 1;
                continue;
            }
            let mut ok = true;
            for j in 0..96 {
                if !is_hex_char(buf[i + j]) {
                    ok = false;
                    i = i + j + 1;
                    break;
                }
            }
            if !ok {
                continue;
            }
            let left_ok = i == 0 || !is_hex_char(buf[i - 1]);
            let right_ok = i + 96 >= buf.len() || !is_hex_char(buf[i + 96]);
            if left_ok && right_ok {
                let key_hex = String::from_utf8_lossy(&buf[i..i + 64]).to_lowercase();
                let salt_hex = String::from_utf8_lossy(&buf[i + 64..i + 96]).to_lowercase();
                let is_dup = results.iter().any(|(k, s)| k == &key_hex && s == &salt_hex);
                if !is_dup {
                    results.push((key_hex, salt_hex));
                }
            }
            i += 1;
        }
    }

    // 3) 裸 64-hex raw key（无 salt）：供 page1 校验路径使用；salt 字段留空
    if buf.len() >= 64 {
        let mut i = 0;
        while i + 64 <= buf.len() {
            if !is_hex_char(buf[i]) {
                i += 1;
                continue;
            }
            let mut ok = true;
            for j in 0..64 {
                if !is_hex_char(buf[i + j]) {
                    ok = false;
                    i = i + j + 1;
                    break;
                }
            }
            if !ok {
                continue;
            }
            // 若实际是 96+ hex 串的前缀，交给 96 分支；这里要求右边界不是 hex
            let left_ok = i == 0 || !is_hex_char(buf[i - 1]);
            let right_ok = i + 64 >= buf.len() || !is_hex_char(buf[i + 64]);
            if left_ok && right_ok {
                let key_hex = String::from_utf8_lossy(&buf[i..i + 64]).to_lowercase();
                let is_dup = results.iter().any(|(k, s)| k == &key_hex && s.is_empty());
                if !is_dup {
                    results.push((key_hex, String::new()));
                }
            }
            i += 1;
        }
    }
}
