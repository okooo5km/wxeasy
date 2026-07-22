//! Windows 命名管道占用诊断（`\\.\pipe\wxeasy-daemon`）
//!
//! 背景：daemon 的 IPC 端点是一个全局命名管道，`interprocess` 建它时带
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` 语义——同一时刻只有一个进程能持有这个
//! 名字，且管道的 DACL 来自「创建者那张令牌」。一旦持有者跑在跟当前用户
//! 不同的令牌上下文里（管理员提权的宿主程序拉起的 daemon、沙箱等受限令牌
//! 环境、另一个 Windows 账号），整机 wxeasy 会以最难排查的方式瘫痪：
//!
//! - 客户端 `Connect` 一律 `拒绝访问 (os error 5)`，而
//!   [`crate::cli::transport::is_alive`] 把任何连接失败都归成「daemon 没运行」；
//! - 于是 CLI 去拉新 daemon，新 daemon 抢同名管道同样吃 `os error 5`，
//!   重试 5s 后退出；
//! - 用户侧只看到「wxeasy-daemon 启动超时（>15s）」，daemon.log 里也只有
//!   一行「管道暂不可用（旧实例退出中？）」——症状跟真正的代码故障、跟慢盘
//!   性能问题几乎无法区分，而唯一有效的解法（管理员终端 taskkill 掉残留
//!   实例）根本猜不到。
//!
//! 这个模块负责把「猜不到」变成「照着做」：探明管道究竟是不存在、可连接、
//! 拒绝访问还是实例全忙，尽力找出占用者 PID，并生成一段能直接照抄执行的
//! 指引。它只做诊断，不做任何「自动修复」——杀掉一个当前令牌够不着的进程
//! 本来就需要用户主动提权，替他猜着杀反而危险。
//!
//! 整个模块只在 Windows 上编译（见 `main.rs` 的 `#[cfg(windows)] mod`），
//! Unix 侧的 socket 没有这类跨令牌不可见性问题。

use std::fmt::Write as _;

/// 客户端侧的完整管道路径（`interprocess` 的 `GenericNamespaced` 会自己
/// 拼这个前缀，server 端传的是相对名 `wxeasy-daemon`）。
pub const PIPE_PATH: &str = r"\\.\pipe\wxeasy-daemon";

/// `current_exe()` 拿不到时，用来匹配进程名的兜底可执行文件名。
const FALLBACK_EXE_NAME: &str = "wxeasy.exe";

/// 疑似占用者最多列几个，避免把日志/报错刷成一堵墙。
const MAX_SUSPECTS: usize = 8;

const ERROR_FILE_NOT_FOUND_CODE: u32 = 2;
const ERROR_PATH_NOT_FOUND_CODE: u32 = 3;
const ERROR_ACCESS_DENIED_CODE: u32 = 5;
const ERROR_PIPE_BUSY_CODE: u32 = 231;

/// 一次 `CreateFileW` 探测的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    /// 管道名不存在——没有任何进程在监听，问题不在占用。
    Missing,
    /// 能打开客户端句柄，管道本身健康可用。
    Reachable,
    /// `ERROR_ACCESS_DENIED (5)`：管道在，但当前令牌无权连接。本模块存在的理由。
    AccessDenied,
    /// `ERROR_PIPE_BUSY (231)`：管道在、有权连接，只是实例全被占着——daemon 是活的。
    Busy,
    /// 其它 Win32 错误码，原样带出来供排查。
    Failed(u32),
}

/// 进程快照里一个疑似 wxeasy 实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonProcess {
    pub pid: u32,
    /// 可执行文件路径。`None` 表示当前令牌查不到——这本身就是强信号：
    /// 对方多半跑在更高完整性级别（提权）或另一个账号下。
    pub exe: Option<String>,
}

/// 一次完整诊断的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeDiagnosis {
    pub state: PipeState,
    /// 管道服务端进程 PID。只有成功打开句柄（[`PipeState::Reachable`]）时才
    /// 拿得到——`GetNamedPipeServerProcessId` 需要一个已连上的句柄，而恰恰在
    /// 「拒绝访问」这个最需要知道 PID 的场景里我们没有句柄，所以才必须有
    /// [`PipeDiagnosis::suspects`] 这条兜底路径。
    pub server_pid: Option<u32>,
    /// 兜底：进程快照里所有疑似 wxeasy 的进程（已排除当前进程自己）。
    pub suspects: Vec<DaemonProcess>,
}

impl PipeDiagnosis {
    /// 面向用户的诊断说明（多行，不含末尾换行）。
    ///
    /// `None` 表示这次探测没有额外信息可讲——典型是管道压根不存在，那属于
    /// 「daemon 没起来」的常规故障，调用方原有的「请查看日志」指引才是对的，
    /// 硬凑一段诊断只会稀释真正有用的信息。
    pub fn advice(&self) -> Option<String> {
        match self.state {
            PipeState::Missing => None,
            PipeState::AccessDenied => Some(self.render_access_denied()),
            PipeState::Busy => Some(format!(
                "{PIPE_PATH} 存在且当前用户有权访问，但所有管道实例都在忙\n\
                 （ERROR_PIPE_BUSY）——daemon 是活的，只是被并发请求占满了。\n\
                 稍等几秒重试即可；若长期如此，说明有查询卡死，请看日志。"
            )),
            PipeState::Reachable => {
                let pid = self
                    .server_pid
                    .map(|p| format!("服务端 PID {p}"))
                    .unwrap_or_else(|| "服务端 PID 未知".to_string());
                Some(format!(
                    "{PIPE_PATH} 现在可以正常连接（{pid}）——管道层面没有问题，\n\
                     多半是 daemon 刚刚才就绪，或者它能接受连接却答不了 Ping\n\
                     （联系人加载卡住 / 查询线程挂死）。重跑一次命令；仍失败请看日志。"
                ))
            }
            PipeState::Failed(code) => Some(format!(
                "{PIPE_PATH} 探测失败：Win32 错误码 {code}。\n\
                 这不是已知的占用场景，请连同日志一起反馈。"
            )),
        }
    }

    fn render_access_denied(&self) -> String {
        let mut msg = String::new();
        let _ = write!(
            msg,
            "{PIPE_PATH} 已存在，但当前用户无权连接（拒绝访问 / os error 5）。\n\n\
             成因：有一个 wxeasy-daemon 实例是在「跟你不同的令牌上下文」里被拉起的，\n\
             常见于以管理员身份运行的程序调用了 wxeasy、沙箱等受限令牌环境、另一个\n\
             Windows 账号。它创建的管道 DACL 只认那张令牌，于是既挡住了所有普通\n\
             客户端，也让新 daemon 抢不到同名管道——CLI 只能一路超时。\n\
             注意：关掉那个宿主程序没用，daemon 是 DETACHED_PROCESS，早就脱离父进程了。"
        );

        if self.suspects.is_empty() {
            let _ = write!(
                msg,
                "\n\n进程快照里没找到 wxeasy 进程——占用者可能跑在当前令牌看不到的会话里，\n\
                 也可能是别的程序占用了同名管道。请在管理员终端里确认后清理：\n\n    \
                 tasklist | findstr /i wxeasy\n    \
                 taskkill /F /PID <上一步查到的 PID>"
            );
            return msg;
        }

        let _ = write!(msg, "\n\n疑似残留实例：");
        for p in &self.suspects {
            let _ = match &p.exe {
                Some(exe) => write!(msg, "\n  - PID {}（{}）", p.pid, exe),
                None => write!(
                    msg,
                    "\n  - PID {}（当前令牌查不到它的路径，多半就是它：跑在更高完整性级别或其它账号下）",
                    p.pid
                ),
            };
        }

        let kill_args = self
            .suspects
            .iter()
            .map(|p| format!("/PID {}", p.pid))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = write!(
            msg,
            "\n\n修复：在管理员终端（右键开始菜单 → 终端(管理员)）执行\n\n    \
             taskkill /F {kill_args}\n\n\
             然后重新运行原命令。普通令牌下 taskkill / Stop-Process / WMI 都会被拒绝，\n\
             别在非管理员终端里反复试。"
        );
        msg
    }
}

/// 探测管道并汇总诊断信息。
///
/// 注意这会真的去 `CreateFileW` 打开管道（成功时相当于一次空连接，daemon
/// 侧读到 EOF 就收摊，见 `daemon::server::handle_connection_windows`），
/// 所以只在失败路径上调用它，别放进热路径。
pub fn diagnose() -> PipeDiagnosis {
    let (state, server_pid) = probe_pipe();
    // 只有「拒绝访问」这一种状态需要指认占用者，其余状态的结论跟进程列表
    // 无关——不为它们白跑一次 ToolHelp 快照（冷启动路径上每次都会走到）。
    let suspects = if state == PipeState::AccessDenied {
        find_wxeasy_processes()
    } else {
        Vec::new()
    };
    PipeDiagnosis {
        state,
        server_pid,
        suspects,
    }
}

/// CLI 侧：可直接追加到报错/输出末尾的诊断段落，没什么可说时返回 `None`。
///
/// 两个调用点共用：`start_daemon` 启动超时、`daemon status` 显示「未运行」
/// ——它俩都是「探活失败」的表象，真因可能完全不同。
pub fn hint() -> Option<String> {
    diagnose().advice()
}

/// CLI 侧：拉起 daemon 之前的快速判死。
///
/// 管道处于 [`PipeState::AccessDenied`] 时，再 spawn 一个 daemon 也只会撞
/// 同一堵墙（抢不到同名管道 → 5s 后自杀），用户白等满 15s 启动超时。这里
/// 直接把结论摆出来，省掉那 15s 和一个注定失败的进程。
///
/// 只对「拒绝访问」判死：其余状态（管道不存在 / 可连接 / 全忙）都可能是
/// 正常竞态，照旧走原来的启动流程，绝不因为一次探测就拦下合法的冷启动。
pub fn preflight_before_spawn() -> anyhow::Result<()> {
    let diag = diagnose();
    if diag.state != PipeState::AccessDenied {
        return Ok(());
    }
    anyhow::bail!(
        "连不上 wxeasy-daemon，也无法接管它的管道\n\n{}",
        diag.advice().unwrap_or_default()
    )
}

/// daemon 侧：管道绑定最终失败时写进 daemon.log 的诊断行。
///
/// 返回逐行文本，由调用方加上 `[server]` 前缀输出——日志里每行都带前缀才
/// 好 grep，也不会跟别的输出交织成一坨。
pub fn bind_failure_report(err: &std::io::Error) -> Vec<String> {
    let access_denied = err.raw_os_error() == Some(ERROR_ACCESS_DENIED_CODE as i32);
    render_bind_failure(&err.to_string(), access_denied, &diagnose())
}

/// [`bind_failure_report`] 的纯函数内核（探测结果由外部传入，便于单测）。
fn render_bind_failure(err_display: &str, access_denied: bool, diag: &PipeDiagnosis) -> Vec<String> {
    let mut lines = vec![format!("绑定 {PIPE_PATH} 失败: {err_display}")];
    if !access_denied {
        lines.push(
            "这不是权限问题，请对照上面的错误码排查（同名管道被非 wxeasy 程序占用也会走到这里）。"
                .to_string(),
        );
        return lines;
    }
    lines.push("重试预算耗尽——已经不是「旧实例正在退出」的短暂竞态了。".to_string());
    match diag.advice() {
        Some(advice) => lines.extend(advice.lines().map(|l| l.to_string())),
        None => lines.push(
            "但探测发现管道此刻并不存在（竞态刚解除？），可以直接重试启动 daemon。".to_string(),
        ),
    }
    lines
}

/// 以客户端身份打开管道，用错误码区分「不存在 / 拒绝访问 / 全忙 / 可用」。
///
/// 为什么不是先列 `\\.\pipe\` 目录再判断：目录枚举只能回答「名字在不在」，
/// 而这里真正要区分的是「在、但连不上」——只有实打实地 `CreateFileW` 一次，
/// 拿到的错误码才有这个分辨率。
fn probe_pipe() -> (PipeState, Option<u32>) {
    probe_pipe_path(PIPE_PATH)
}

/// [`probe_pipe`] 的实现，管道路径可传入——测试要能拿一个确定不存在的名字、
/// 和一个自造的问题管道来验证错误码映射，而不去碰用户真在跑的 daemon。
fn probe_pipe_path(path: &str) -> (PipeState, Option<u32>) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: 标准 Win32 调用，路径是本地构造的 NUL 结尾宽字符串；成功拿到
    // 的句柄在下面立刻 CloseHandle，不外泄。
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )
    };

    match handle {
        Ok(h) => {
            let mut pid: u32 = 0;
            // SAFETY: h 是刚打开的有效管道句柄，pid 是栈上变量；随后关闭句柄。
            let server_pid = unsafe {
                let got = GetNamedPipeServerProcessId(h, &mut pid);
                let _ = CloseHandle(h);
                if got.is_ok() && pid != 0 {
                    Some(pid)
                } else {
                    None
                }
            };
            (PipeState::Reachable, server_pid)
        }
        Err(e) => {
            let code = win32_code_from_hresult(e.code().0 as u32);
            let state = match code {
                ERROR_FILE_NOT_FOUND_CODE | ERROR_PATH_NOT_FOUND_CODE => PipeState::Missing,
                ERROR_ACCESS_DENIED_CODE => PipeState::AccessDenied,
                ERROR_PIPE_BUSY_CODE => PipeState::Busy,
                other => PipeState::Failed(other),
            };
            (state, None)
        }
    }
}

/// `HRESULT_FROM_WIN32` 的逆运算：`0x8007xxxx` 的低 16 位才是 Win32 错误码。
fn win32_code_from_hresult(hr: u32) -> u32 {
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        hr & 0xFFFF
    } else {
        hr
    }
}

/// 遍历进程快照，找出所有疑似 wxeasy 的进程（排除当前进程）。
///
/// 用 ToolHelp 快照而不是 `tasklist`：不用 spawn 子进程、没有控制台编码坑，
/// 而且快照对提权进程同样可见（够不着的只是路径，PID 一定拿得到）——这正是
/// 在「拒绝访问」场景下唯一还能指认占用者的手段。
fn find_wxeasy_processes() -> Vec<DaemonProcess> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let self_pid = std::process::id();
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| FALLBACK_EXE_NAME.to_string());

    let mut found = Vec::new();
    // SAFETY: 标准 ToolHelp 快照遍历，失败时返回 Err 不产生句柄。
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(s) => s,
        Err(_) => return found,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: entry.dwSize 已按文档填好，快照句柄有效，循环结束后关闭。
    unsafe {
        if Process32FirstW(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return found;
        }
        loop {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if entry.th32ProcessID != self_pid && process_name_matches(&name, &exe_name) {
                found.push(DaemonProcess {
                    pid: entry.th32ProcessID,
                    exe: process_image_path(entry.th32ProcessID),
                });
            }
            if found.len() >= MAX_SUSPECTS || Process32NextW(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
    found
}

/// 进程名是否算「疑似 wxeasy」。
///
/// 除了跟当前 exe 同名，也认所有以 `wxeasy` 打头的名字——npm 分发包、重命名
/// 过的旧版本、`wxeasy-daemon.exe` 之类都能兜住；宁可多列一个让用户自己认，
/// 也别漏掉真正锁着管道的那个。
fn process_name_matches(name: &str, current_exe_name: &str) -> bool {
    name.eq_ignore_ascii_case(current_exe_name) || name.to_ascii_lowercase().starts_with("wxeasy")
}

/// 尽力拿到进程的可执行文件路径；拿不到返回 `None`（提权 / 跨账号进程的常见
/// 结果，调用方会把这件事本身当作线索展示给用户）。
fn process_image_path(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: 标准 Win32 调用；句柄成对关闭。
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = vec![0u16; 260];
    let mut len = buf.len() as u32;
    // SAFETY: buf/len 匹配，调用后立即关闭句柄。
    let ok = unsafe {
        let r = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        r.is_ok()
    };
    if !ok {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(state: PipeState, suspects: Vec<DaemonProcess>) -> PipeDiagnosis {
        PipeDiagnosis {
            state,
            server_pid: None,
            suspects,
        }
    }

    fn suspect(pid: u32, exe: Option<&str>) -> DaemonProcess {
        DaemonProcess {
            pid,
            exe: exe.map(|s| s.to_string()),
        }
    }

    #[test]
    fn hresult_decodes_back_to_win32_code() {
        // HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) == 0x80070005
        assert_eq!(win32_code_from_hresult(0x8007_0005), 5);
        assert_eq!(win32_code_from_hresult(0x8007_0002), 2);
        assert_eq!(win32_code_from_hresult(0x8007_00E7), 231);
        // 非 FACILITY_WIN32 的 HRESULT 原样返回，不做假解码
        assert_eq!(win32_code_from_hresult(0x8000_4005), 0x8000_4005);
    }

    #[test]
    fn missing_pipe_has_no_advice() {
        // 管道不存在属于「daemon 没起来」的常规故障，硬凑诊断只会稀释调用方
        // 原有的「请查看日志」指引。
        assert!(diag(PipeState::Missing, vec![]).advice().is_none());
    }

    #[test]
    fn access_denied_advice_names_pids_and_kill_command() {
        let advice = diag(
            PipeState::AccessDenied,
            vec![suspect(8124, None), suspect(9001, Some(r"C:\bin\wxeasy.exe"))],
        )
        .advice()
        .expect("拒绝访问必须给出诊断");

        assert!(advice.contains("PID 8124"));
        assert!(advice.contains(r"C:\bin\wxeasy.exe"));
        // 一条命令带上全部 PID，用户复制一次就够
        assert!(advice.contains("taskkill /F /PID 8124 /PID 9001"));
        assert!(advice.contains("管理员终端"));
    }

    #[test]
    fn access_denied_without_suspects_still_gives_a_recipe() {
        // 找不到嫌疑进程时不能就此收声——用户仍然需要一条能查出占用者的命令。
        let advice = diag(PipeState::AccessDenied, vec![])
            .advice()
            .expect("拒绝访问必须给出诊断");
        assert!(advice.contains("tasklist | findstr /i wxeasy"));
        assert!(advice.contains("taskkill /F /PID"));
    }

    #[test]
    fn busy_and_reachable_advice_never_suggest_killing() {
        // 这两种状态下 daemon 是活的、管道是健康的，绝不能引导用户去杀进程。
        for state in [PipeState::Busy, PipeState::Reachable] {
            let advice = diag(state, vec![]).advice().expect("应给出说明");
            assert!(!advice.contains("taskkill"), "{state:?} 不该建议 taskkill");
        }
    }

    #[test]
    fn failed_state_surfaces_raw_code() {
        let advice = diag(PipeState::Failed(1234), vec![]).advice().unwrap();
        assert!(advice.contains("1234"));
    }

    #[test]
    fn bind_failure_report_only_diagnoses_permission_errors() {
        let other = std::io::Error::from_raw_os_error(32); // ERROR_SHARING_VIOLATION
        let lines =
            render_bind_failure(&other.to_string(), false, &diag(PipeState::Missing, vec![]));
        assert!(lines.iter().all(|l| !l.contains("taskkill")));
        assert!(lines[0].contains(PIPE_PATH));
    }

    #[test]
    fn bind_failure_report_expands_access_denied_advice_into_log_lines() {
        let denied = std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED_CODE as i32);
        let lines = render_bind_failure(
            &denied.to_string(),
            true,
            &diag(PipeState::AccessDenied, vec![suspect(8124, None)]),
        );
        // 逐行返回，调用方好加 [server] 前缀；不能有内嵌换行
        assert!(lines.iter().all(|l| !l.contains('\n')));
        assert!(lines.iter().any(|l| l.contains("taskkill /F /PID 8124")));
        assert!(lines.iter().any(|l| l.contains("重试预算耗尽")));
    }

    #[test]
    fn process_name_matching_is_case_insensitive_and_covers_variants() {
        assert!(process_name_matches("wxeasy.exe", "wxeasy.exe"));
        assert!(process_name_matches("WXEASY.EXE", "wxeasy.exe"));
        assert!(process_name_matches("wxeasy-daemon.exe", "wxeasy.exe"));
        // 换过名字的分发包：跟当前 exe 同名也算
        assert!(process_name_matches("wx.exe", "wx.exe"));
        assert!(!process_name_matches("Weixin.exe", "wxeasy.exe"));
        assert!(!process_name_matches("explorer.exe", "wxeasy.exe"));
    }

    /// 真机烟雾测试：探测本身不能 panic、不能挂住。管道存在与否都合法，这里
    /// 只保证 FFI 调用序列（CreateFileW → GetNamedPipeServerProcessId →
    /// CloseHandle，以及 ToolHelp 遍历）在真实系统上跑得通。
    #[test]
    fn diagnose_runs_on_real_system() {
        let d = diagnose();
        if d.state != PipeState::AccessDenied {
            assert!(d.suspects.is_empty(), "只有拒绝访问才该翻进程快照");
        }
        // advice() 对任意状态都不能 panic
        let _ = d.advice();
    }

    /// 真机验证「不存在」这条分支：拿一个确定没人建过的管道名去探，必须落到
    /// [`PipeState::Missing`]（而不是被当成某种失败）——这条分支决定了正常冷
    /// 启动路径不会被 [`preflight_before_spawn`] 误拦。
    #[test]
    fn probing_a_nonexistent_pipe_reports_missing() {
        let name = format!(r"\\.\pipe\wxeasy-diag-absent-{}", std::process::id());
        let (state, pid) = probe_pipe_path(&name);
        assert_eq!(state, PipeState::Missing);
        assert!(pid.is_none());
    }

    /// 真机验证「拒绝访问」这条分支——整个模块的价值全押在这个映射上：真出事
    /// 时 `CreateFileW` 给的必须是 `ERROR_ACCESS_DENIED`，映射错了这套诊断在
    /// 现场就是哑的。
    ///
    /// 现场成因是管道 DACL 只认创建者那张令牌，测试里没法造一个跨令牌进程，
    /// 于是用另一种同样返回 `ERROR_ACCESS_DENIED` 的方式复现：建一个只入站
    /// （`PIPE_ACCESS_INBOUND`）的管道，而探测按客户端惯例要读+写权限，访问
    /// 模式不兼容 → 内核回 5。验的是错误码到 [`PipeState`] 的映射，这正是我们
    /// 自己写的那段逻辑；DACL 会给出 5 则是现场实测过的既有事实。
    #[test]
    fn probing_a_pipe_we_may_not_open_reports_access_denied() {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Storage::FileSystem::PIPE_ACCESS_INBOUND;
        use windows::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT};

        // 名字带上 PID，绝不和真在跑的 daemon 管道撞名
        let name = format!(r"\\.\pipe\wxeasy-diag-denied-{}", std::process::id());
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: 标准 Win32 调用，名字是本地构造的 NUL 结尾宽字符串；句柄在
        // 断言前后成对关闭（断言失败也已先关闭，不泄漏到别的用例）。
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                1,
                0,
                0,
                0,
                None,
            )
        };
        assert!(!server.is_invalid(), "建测试管道失败，无法验证该分支");

        let (state, pid) = probe_pipe_path(&name);
        // SAFETY: 关闭上面刚建的有效句柄。
        unsafe {
            let _ = CloseHandle(server);
        }

        assert_eq!(state, PipeState::AccessDenied);
        assert!(pid.is_none(), "连不上就拿不到服务端 PID，只能走进程快照兜底");
    }
}
