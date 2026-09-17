//! 读取本机微信桌面版版本，并据此选择提钥路径。
//!
//! 4.1.9 及更早：进程内存里还能扫到 `x'<key><salt>'`，走从 wx-cli 继承的原始稳态扫描。
//! 4.1.10 起：`cipher_memory_security` 把 raw key 用完即擦，稳态扫描常 0 命中，
//! 才需要 Windows 硬件断点 / macOS LLDB。不要在未判断版本时直接走后一条。

use serde::Serialize;
use std::fmt;
use std::path::Path;

/// 微信桌面客户端版本。`4.1.9` 与 `4.1.9.57` 都合法，缺省段补 0。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WeChatVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: u32,
}

impl WeChatVersion {
    pub const fn new(major: u32, minor: u32, patch: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    /// 4.1.10 起改走 live-hook；小于该版本用原始稳态扫描。
    pub const LIVEHOOK_SINCE: WeChatVersion = WeChatVersion::new(4, 1, 10, 0);

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut parts = [0u32; 4];
        let mut n = 0usize;
        for raw in s.split('.') {
            if n >= 4 {
                break;
            }
            let token = raw
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();
            if token.is_empty() {
                return None;
            }
            parts[n] = token.parse().ok()?;
            n += 1;
        }
        if n < 2 {
            return None;
        }
        Some(Self::new(parts[0], parts[1], parts[2], parts[3]))
    }

    /// 是否仍适用 wx-cli 同源的内存特征串扫描。
    pub fn uses_classic_scan(self) -> bool {
        self < Self::LIVEHOOK_SINCE
    }
}

impl fmt::Display for WeChatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.build == 0 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(
                f,
                "{}.{}.{}.{}",
                self.major, self.minor, self.patch, self.build
            )
        }
    }
}

/// 探测本机已安装／正在运行的微信版本。读不到返回 `None`，由调用方走保守启发式。
pub fn detect_wechat_version() -> Option<WeChatVersion> {
    detect_impl()
}

/// 给 CLI / agent 看的版本与提钥路径报告。
#[derive(Debug, Clone, Serialize)]
pub struct WeChatVersionReport {
    pub wxeasy_version: String,
    pub wechat_version: Option<String>,
    pub classic_scan: Option<bool>,
    /// `classic_scan` / `reuse` / `unknown`
    pub strategy: String,
    pub next_command: String,
    pub user_hint: String,
}

pub fn version_report() -> WeChatVersionReport {
    report_for(detect_wechat_version())
}

pub fn report_for(version: Option<WeChatVersion>) -> WeChatVersionReport {
    let wxeasy_version = env!("CARGO_PKG_VERSION").to_string();
    match version {
        Some(v) if v.uses_classic_scan() => WeChatVersionReport {
            wxeasy_version,
            wechat_version: Some(v.to_string()),
            classic_scan: Some(true),
            strategy: "classic_scan".into(),
            next_command: classic_init_command().into(),
            user_hint: format!(
                "当前微信 {v}（≤4.1.9）。用 `{}` 做原始稳态扫描即可，不要 --live / --relaunch。",
                classic_init_command()
            ),
        },
        Some(v) => WeChatVersionReport {
            wxeasy_version,
            wechat_version: Some(v.to_string()),
            classic_scan: Some(false),
            strategy: "reuse".into(),
            next_command: "wxeasy init".into(),
            user_hint: format!(
                "当前微信 {v}（≥4.1.10）。默认只复用已有密钥，运行 `wxeasy init` 即可。不要自动 --live / --relaunch；新版客户端可能监测数据库解密。"
            ),
        },
        None => WeChatVersionReport {
            wxeasy_version,
            wechat_version: None,
            classic_scan: None,
            strategy: "unknown".into(),
            next_command: String::new(),
            user_hint: "未能自动读取微信版本。请先在微信「关于」或安装目录确认：4.1.9 及更早才能用默认扫描提钥；4.1.10+ 只复用已有密钥，不要直接 --live。".into(),
        },
    }
}

fn classic_init_command() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "wxeasy init"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "sudo wxeasy init"
    }
}

#[cfg(target_os = "macos")]
fn detect_impl() -> Option<WeChatVersion> {
    let mut apps = vec![std::path::PathBuf::from("/Applications/WeChat.app")];
    if let Some(home) = dirs::home_dir() {
        apps.push(home.join("Applications/WeChat.app"));
    }
    for app in apps {
        let plist = app.join("Contents/Info.plist");
        if let Some(v) = version_from_macos_plist(&plist) {
            return Some(v);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn version_from_macos_plist(plist: &Path) -> Option<WeChatVersion> {
    if !plist.exists() {
        return None;
    }
    if let Ok(bytes) = std::fs::read(plist) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if let Some(v) = parse_short_version_from_plist_xml(text) {
                return Some(v);
            }
        }
    }
    for (bin, args) in [
        (
            "/usr/libexec/PlistBuddy",
            vec![
                "-c".into(),
                "Print :CFBundleShortVersionString".into(),
                plist.display().to_string(),
            ],
        ),
        (
            "/usr/bin/defaults",
            vec![
                "read".into(),
                plist.with_file_name("Info").display().to_string(),
                "CFBundleShortVersionString".into(),
            ],
        ),
    ] {
        if let Ok(out) = std::process::Command::new(bin).args(&args).output() {
            if out.status.success() {
                if let Some(v) = WeChatVersion::parse(&String::from_utf8_lossy(&out.stdout)) {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_short_version_from_plist_xml(xml: &str) -> Option<WeChatVersion> {
    let key = "<key>CFBundleShortVersionString</key>";
    let i = xml.find(key)?;
    let rest = &xml[i + key.len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")?;
    WeChatVersion::parse(rest[start..start + end].trim())
}

#[cfg(target_os = "windows")]
fn detect_impl() -> Option<WeChatVersion> {
    for path in windows_weixin_candidates() {
        if let Some(v) = windows_file_version(&path) {
            return Some(v);
        }
        if let Some(v) = version_from_parent_dir(&path) {
            return Some(v);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_weixin_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for pid in windows_weixin_pids() {
        if let Some(p) = windows_process_image(pid) {
            out.push(p);
        }
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Ok(pf) = std::env::var(var) {
            let root = std::path::PathBuf::from(pf).join("Tencent").join("Weixin");
            out.push(root.join("Weixin.exe"));
            if let Ok(entries) = std::fs::read_dir(&root) {
                for entry in entries.flatten() {
                    let exe = entry.path().join("Weixin.exe");
                    if exe.is_file() {
                        out.push(exe);
                    }
                }
            }
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn windows_weixin_pids() -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    let mut pids = Vec::new();
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(s) => s,
        Err(_) => return pids,
    };
    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
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

#[cfg(target_os = "windows")]
fn windows_process_image(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = vec![0u16; 512];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len)
    };
    let _ = unsafe { CloseHandle(h) };
    if ok.is_err() || len == 0 {
        return None;
    }
    Some(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &buf[..len as usize],
    )))
}

#[cfg(target_os = "windows")]
fn windows_file_version(path: &Path) -> Option<WeChatVersion> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };

    if !path.is_file() {
        return None;
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut dummy = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut dummy)) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    unsafe {
        GetFileVersionInfoW(PCWSTR(wide.as_ptr()), 0, size, buf.as_mut_ptr() as *mut _).ok()?;
    }
    let mut lp: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    let sub: [u16; 2] = [0x5c, 0];
    let ok = unsafe {
        VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(sub.as_ptr()),
            &mut lp,
            &mut len,
        )
    };
    if !ok.as_bool() || lp.is_null() || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>() {
        return None;
    }
    let info = unsafe { &*(lp as *const VS_FIXEDFILEINFO) };
    Some(WeChatVersion::new(
        (info.dwFileVersionMS >> 16) & 0xffff,
        info.dwFileVersionMS & 0xffff,
        (info.dwFileVersionLS >> 16) & 0xffff,
        info.dwFileVersionLS & 0xffff,
    ))
}

#[cfg(target_os = "windows")]
fn version_from_parent_dir(path: &Path) -> Option<WeChatVersion> {
    WeChatVersion::parse(path.parent()?.file_name()?.to_str()?)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn detect_impl() -> Option<WeChatVersion> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_common_wechat_versions() {
        assert_eq!(
            WeChatVersion::parse("4.1.9").unwrap(),
            WeChatVersion::new(4, 1, 9, 0)
        );
        assert_eq!(
            WeChatVersion::parse("4.1.9.57").unwrap(),
            WeChatVersion::new(4, 1, 9, 57)
        );
        assert_eq!(
            WeChatVersion::parse("4.1.13\n").unwrap(),
            WeChatVersion::new(4, 1, 13, 0)
        );
        assert!(WeChatVersion::parse("abc").is_none());
        assert!(WeChatVersion::parse("4").is_none());
    }

    #[test]
    fn classic_scan_cutoff_is_4_1_10() {
        assert!(WeChatVersion::parse("3.8.2").unwrap().uses_classic_scan());
        assert!(WeChatVersion::parse("4.0.0").unwrap().uses_classic_scan());
        assert!(WeChatVersion::parse("4.1.9").unwrap().uses_classic_scan());
        assert!(WeChatVersion::parse("4.1.9.57")
            .unwrap()
            .uses_classic_scan());
        assert!(!WeChatVersion::parse("4.1.10").unwrap().uses_classic_scan());
        assert!(!WeChatVersion::parse("4.1.11.24")
            .unwrap()
            .uses_classic_scan());
        assert!(!WeChatVersion::parse("4.1.13").unwrap().uses_classic_scan());
        assert!(!WeChatVersion::parse("5.0.0").unwrap().uses_classic_scan());
    }

    #[test]
    fn report_routes_by_version() {
        let classic = report_for(WeChatVersion::parse("4.1.9"));
        assert_eq!(classic.strategy, "classic_scan");
        assert_eq!(classic.classic_scan, Some(true));
        assert!(classic.user_hint.contains("4.1.9"));
        assert!(!classic.next_command.contains("--live"));

        let high = report_for(WeChatVersion::parse("4.1.13"));
        assert_eq!(high.strategy, "reuse");
        assert_eq!(high.classic_scan, Some(false));
        assert_eq!(high.next_command, "wxeasy init");
        assert!(high.user_hint.contains("不要自动 --live"));

        let unknown = report_for(None);
        assert_eq!(unknown.strategy, "unknown");
        assert!(unknown.wechat_version.is_none());
        assert!(unknown.next_command.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_xml_plist_short_version() {
        let xml = r#"<?xml version="1.0"?>
        <plist><dict>
            <key>CFBundleShortVersionString</key>
            <string>4.1.13</string>
        </dict></plist>"#;
        assert_eq!(
            parse_short_version_from_plist_xml(xml).unwrap(),
            WeChatVersion::new(4, 1, 13, 0)
        );
    }
}
