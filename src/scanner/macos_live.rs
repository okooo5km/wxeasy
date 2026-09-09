//! CommonCrypto PBKDF2 capture and conversion to wxeasy's per-database AES keys.
//! Based on pandorafuture/wx-cli (MIT), see doc/pandorafuture-MIT.txt.

use super::KeyEntry;
use crate::crypto::{PAGE_SZ, RESERVE_SZ, SALT_SZ};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::io::Read;
use std::path::Path;

#[derive(serde::Deserialize)]
struct Candidate {
    password: String,
    salt: String,
}

fn decode<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn derive_verified(password: &[u8; 32], page: &[u8]) -> Option<[u8; 32]> {
    if page.len() != PAGE_SZ || page.starts_with(crate::crypto::SQLITE_HDR) {
        return None;
    }
    let mut enc_key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha512>(password, &page[..SALT_SZ], 256_000, &mut enc_key);
    let mac_salt: Vec<u8> = page[..SALT_SZ].iter().map(|v| v ^ 0x3a).collect();
    let mut mac_key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha512>(&enc_key, &mac_salt, 2, &mut mac_key);
    let end = PAGE_SZ - RESERVE_SZ + 16;
    let mut mac = Hmac::<Sha512>::new_from_slice(&mac_key).ok()?;
    mac.update(&page[SALT_SZ..end]);
    mac.update(&1u32.to_le_bytes());
    mac.verify_slice(&page[end..]).ok()?;
    Some(enc_key)
}

fn verified_entries(db_dir: &Path, output: &str, existing: &[KeyEntry]) -> Vec<KeyEntry> {
    let mut pages = Vec::new();
    for (salt, name) in super::collect_db_salts(db_dir) {
        let mut page = vec![0; PAGE_SZ];
        if std::fs::File::open(db_dir.join(&name))
            .and_then(|mut f| f.read_exact(&mut page))
            .is_ok()
        {
            pages.push((salt, name, page));
        }
    }
    let mut found = Vec::new();
    let mut passwords = std::collections::HashSet::new();
    for line in output
        .lines()
        .filter_map(|l| l.strip_prefix("WXEASY_KEY "))
        .take(32)
    {
        let Ok(candidate) = serde_json::from_str::<Candidate>(line) else {
            continue;
        };
        let (Some(password), Some(salt)) = (
            decode::<32>(&candidate.password),
            decode::<16>(&candidate.salt),
        ) else {
            continue;
        };
        // Only consider calls for a database in the selected account.
        if !pages.iter().any(|(_, _, p)| p[..16] == salt) || !passwords.insert(password) {
            continue;
        }
        // An account password can cover multiple salts; verify every DB independently.
        for (salt, name, page) in &pages {
            if existing
                .iter()
                .chain(found.iter())
                .any(|e: &KeyEntry| &e.db_name == name)
            {
                continue;
            }
            if let Some(enc_key) = derive_verified(&password, page) {
                found.push(KeyEntry {
                    db_name: name.clone(),
                    salt: salt.clone(),
                    enc_key: super::hex::encode(&enc_key),
                });
            }
        }
    }
    found
}

#[cfg(target_os = "macos")]
pub fn run_capture(
    db_dir: &Path,
    mode: super::LiveMode,
    existing: &[KeyEntry],
) -> anyhow::Result<Vec<KeyEntry>> {
    use anyhow::{bail, Context};
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    if !cfg!(target_arch = "aarch64") {
        bail!("macOS 实时提钥目前仅支持 Apple Silicon；Intel 请使用历史密钥或稳态扫描");
    }
    if !Command::new("xcrun")
        .args(["--find", "lldb"])
        .output()?
        .status
        .success()
    {
        bail!("缺少 LLDB，请先安装 Xcode Command Line Tools（xcode-select --install）");
    }
    let path = std::env::temp_dir().join(format!(
        "wxeasy-lldb-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    let script = path.join("capture.py");
    std::fs::write(&script, include_str!("macos_capture.py"))?;
    // JSON quoting protects whitespace and quotes in temporary directory names.
    let import = format!(
        "command script import {}",
        serde_json::to_string(&script.to_string_lossy())?
    );
    eprintln!("macOS LLDB 抓取最多等待 120 秒，请登录微信并打开缺失的会话。需要可用的调试权限。");
    let mut child = Command::new("xcrun")
        .args([
            "lldb",
            "--no-lldbinit",
            "--batch",
            "-o",
            &import,
            "-o",
            "wxeasy_capture",
            "-o",
            "quit",
        ])
        .env(
            "WXEASY_CAPTURE_MODE",
            if mode == super::LiveMode::Relaunch {
                "relaunch"
            } else {
                "attach"
            },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("启动 LLDB 失败")?;
    let mut stdout = child.stdout.take().context("LLDB stdout 不可用")?;
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let _ = stdout.read_to_string(&mut output);
        output
    });
    let deadline = Instant::now() + Duration::from_secs(140);
    let mut timed_out = false;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = reader.join().unwrap_or_default();
    let entries = verified_entries(db_dir, &output, existing);
    if timed_out || output.contains("WXEASY_ERROR") {
        eprintln!("LLDB 未正常完成；已保留通过校验的结果。请检查微信状态、SIP 与开发者工具权限。");
    }
    if entries.is_empty() {
        bail!("未捕获可验证的密钥。检查 LLDB 调试权限，或用 `wxeasy init --relaunch` 在登录时抓取；不会自动修改 SIP 或签名");
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_candidates() {
        assert!(decode::<32>(&"é".repeat(32)).is_none());
        assert!(decode::<32>(&"g".repeat(64)).is_none());
        assert!(decode::<32>("00").is_none());
        assert!(derive_verified(&[0; 32], &[0; 16]).is_none());
    }

    #[test]
    fn derives_key_and_rejects_tampered_page() {
        let password = [0x42; 32];
        let salt = [0xaa; 16];
        let mut key = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha512>(&password, &salt, 256_000, &mut key);
        // Independent vector generated with Python hashlib.pbkdf2_hmac.
        assert_eq!(
            super::super::hex::encode(&key),
            "35b20cfae5fc9aa9f83b4ba5ade2f1d0e26c8cc07d010277a6472cf05ce6ddba"
        );
        let mut plain = vec![0; PAGE_SZ];
        plain[16..24].copy_from_slice(crate::crypto::SQLITE_PAGE1_META_PREFIX);
        let mut page = crate::crypto::encrypt_page(&key, &plain, &[0x11; 16], 1);
        let mut mac_key = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha512>(&key, &[0x90; 16], 2, &mut mac_key);
        let end = PAGE_SZ - 64;
        let mut mac = Hmac::<Sha512>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[16..end]);
        mac.update(&1u32.to_le_bytes());
        page[end..].copy_from_slice(&mac.finalize().into_bytes());
        assert_eq!(derive_verified(&password, &page), Some(key));
        assert_ne!(password, key);
        // A call for an already-covered DB must still be usable to fill another
        // DB in the same account; unknown salts and duplicate records are ignored.
        let dir = std::env::temp_dir().join(format!("wxeasy-macos-kdf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.db"), &page).unwrap();
        std::fs::write(dir.join("b.db"), &page).unwrap();
        let existing = vec![KeyEntry {
            db_name: "a.db".into(),
            salt: "aa".repeat(16),
            enc_key: super::super::hex::encode(&key),
        }];
        let record = format!(
            "WXEASY_KEY {{\"password\":\"{}\",\"salt\":\"{}\"}}\n",
            "42".repeat(32),
            "aa".repeat(16)
        );
        let found = verified_entries(
            &dir,
            &format!("WXEASY_KEY invalid\n{record}{record}"),
            &existing,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].db_name, "b.db");
        assert_eq!(found[0].enc_key, existing[0].enc_key);
        assert!(verified_entries(
            &dir,
            &record.replace(&"aa".repeat(16), &"bb".repeat(16)),
            &[]
        )
        .is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
        page[100] ^= 1;
        assert!(derive_verified(&password, &page).is_none());
    }
}
