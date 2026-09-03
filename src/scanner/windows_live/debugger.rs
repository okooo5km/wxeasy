//! 调试事件循环 + 附加/启动/分离 + SeDebugPrivilege 提权 + 命中收集校验。
//!
//! 核心：在设钥函数入口下硬件断点，微信**开库瞬间**命中时读 `rcx`（→ 32 字节
//! raw key），用 page1 强校验筛出真正解得开库的 key。attach 与 relaunch 两种模式
//! 走**同一套**事件驱动逻辑——`DebugActiveProcess` 会补发已加载模块的 LOAD_DLL
//! 和已存在线程的 CREATE_THREAD 事件，所以线程句柄统一来自调试事件，无需手动
//! 枚举 / OpenThread。
//!
//! UX 铁律（实测教训）：
//! - relaunch 不强杀微信，提示用户手动退出再带起（反复强杀会触发重新认证卡登录）；
//! - 附加成功后**立即** `DebugSetProcessKillOnExit(FALSE)`，即便 wxeasy 被 Ctrl-C
//!   强杀也不会连累微信；
//! - 不设死超时，耐心等开库（自动登录几秒、扫码几分钟都要能等），周期性提示进度；
//! - 命中后置 `EFlags.RF` 越过断点防重入；DR 寄存器每线程都要铺。
//!
//! 署名：okooo5km(十里)

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf, MAIN_SEPARATOR_STR};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_NOT_ALL_ASSIGNED,
    EXCEPTION_SINGLE_STEP, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    ReadProcessMemory, WaitForDebugEvent, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32First, Process32Next,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    DEBUG_PROCESS, PROCESS_INFORMATION, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    STARTUPINFOW,
};

use super::hwbp::{self, HitRegs};
use super::locate::locate_key_schedule_funcs;
use crate::crypto::verify_enc_key_for_db;
use crate::scanner::{collect_db_salts, read_db_salt, KeyEntry, LiveMode};

/// EXCEPTION_BREAKPOINT（`int3`）异常码——附加/加载器阶段的初始断点，需吞掉。
const EXCEPTION_BREAKPOINT_CODE: u32 = 0x8000_0003;

/// 每个被调试进程的运行时状态。
struct ProcState {
    /// 进程句柄（来自 CREATE_PROCESS 事件，用于 ReadProcessMemory）。
    hproc: HANDLE,
    /// 是否已定位 Weixin.dll 并铺好断点。
    armed: bool,
    /// tid → 线程句柄（来自 CREATE_PROCESS / CREATE_THREAD 事件）。
    threads: HashMap<u32, HANDLE>,
    /// 已铺设的断点 VA（用于给后来的新线程补铺）。
    cand_vas: Vec<u64>,
}

/// live-hook 抓取入口：按 `mode` 附加或带起微信，等开库命中，返回抓到的密钥。
///
/// `existing` 是已经可用的密钥（旧稳态扫描 / 历史复用得到），对应的库会被跳过，
/// 只抓仍缺的库；抓齐（含 existing）即结束。
pub fn run_capture(db_dir: &Path, mode: LiveMode, existing: &[KeyEntry]) -> Result<Vec<KeyEntry>> {
    // 尽力启用 SeDebugPrivilege（管理员 token 默认 disabled）。失败也继续——
    // 真正没权限时下面的 DebugActiveProcess / CreateProcess 会给出明确报错。
    if let Err(e) = enable_se_debug_privilege() {
        eprintln!("提示：启用 SeDebugPrivilege 失败（{e}），若附加失败请以管理员身份运行。");
    }

    let db_salts = collect_db_salts(db_dir);
    if db_salts.is_empty() {
        bail!("数据目录下没有加密 .db：{}", db_dir.display());
    }
    // 目标库：(相对名, 磁盘路径)
    let all_dbs: Vec<(String, PathBuf)> = db_salts
        .iter()
        .map(|(_, name)| {
            let p = db_dir.join(name.replace('/', MAIN_SEPARATOR_STR));
            (name.clone(), p)
        })
        .collect();
    let total = all_dbs.len();

    // 已完成集合（existing 覆盖的库）；found 只装本次新抓的
    let mut done: HashSet<String> = existing.iter().map(|e| e.db_name.clone()).collect();
    let mut found: HashMap<String, KeyEntry> = HashMap::new();

    eprintln!(
        "共 {} 个加密库，已可用 {} 个，本次待抓取 {} 个。",
        total,
        done.len(),
        total.saturating_sub(done.len())
    );

    // 附加 / 带起
    match mode {
        LiveMode::Attach => {
            let pid = find_wechat_pid()
                .context("找不到 Weixin.exe 进程，请先启动并登录微信，再用 wxeasy init --live")?;
            unsafe { DebugActiveProcess(pid) }.map_err(|e| {
                anyhow!("附加到微信失败（通常是权限不足，请以管理员身份运行）: {e}")
            })?;
            // 立即保命：无论如何分离/退出都不杀微信
            unsafe { DebugSetProcessKillOnExit(false) }.ok();
            eprintln!(
                "已附加到微信（PID {pid}）。请在微信里打开几个会话、或等待消息同步以触发开库——\n\
                 raw key 只在开库那一刻明文存在，断点必须在场时发生一次开库才能抓到。"
            );
        }
        LiveMode::Relaunch => {
            let exe = prepare_relaunch()?;
            let pid = launch_wechat_debugged(&exe)?;
            unsafe { DebugSetProcessKillOnExit(false) }.ok();
            eprintln!(
                "已以调试模式带起微信（PID {pid}）。请扫码 / 确认登录，登录同步会集中打开全部库，\n\
                 我会在开库瞬间逐个抓取——请耐心等待。"
            );
        }
    }

    // 磁盘候选 RVA 缓存（首个加载 Weixin.dll 的进程解析一次，多进程共用）
    let mut cand_rvas: Option<Vec<u32>> = None;
    let mut procs: HashMap<u32, ProcState> = HashMap::new();
    let mut idle_ticks: u32 = 0;

    loop {
        let mut ev = DEBUG_EVENT::default();
        // 500ms 超时轮询：既能耐心等（不设死超时），又能周期检查是否抓齐 / 让
        // 用户 Ctrl-C 中断（kill-on-exit 已置 FALSE，强杀 wxeasy 不连累微信）。
        if unsafe { WaitForDebugEvent(&mut ev, 500) }.is_err() {
            if done.len() >= total {
                break;
            }
            idle_ticks += 1;
            if idle_ticks % 20 == 0 {
                eprintln!(
                    "… 仍在等待微信开库（已 {}/{}）。可在微信里打开会话 / 等同步；Ctrl-C 结束。",
                    done.len(),
                    total
                );
            }
            continue;
        }
        idle_ticks = 0;

        let pid = ev.dwProcessId;
        let tid = ev.dwThreadId;
        let ev_code = ev.dwDebugEventCode;
        let mut cont = DBG_CONTINUE;
        let mut process_gone = false;

        if ev_code == CREATE_PROCESS_DEBUG_EVENT {
            let info = unsafe { ev.u.CreateProcessInfo };
            let st = procs.entry(pid).or_insert_with(|| ProcState {
                hproc: info.hProcess,
                armed: false,
                threads: HashMap::new(),
                cand_vas: Vec::new(),
            });
            st.hproc = info.hProcess;
            if !info.hThread.is_invalid() {
                st.threads.insert(tid, info.hThread);
            }
            close_if(info.hFile);
            try_arm(&mut procs, pid, &mut cand_rvas);
        } else if ev_code == CREATE_THREAD_DEBUG_EVENT {
            let info = unsafe { ev.u.CreateThread };
            if let Some(st) = procs.get_mut(&pid) {
                st.threads.insert(tid, info.hThread);
                if st.armed {
                    let vas = st.cand_vas.clone();
                    let _ = hwbp::arm_thread(info.hThread, &vas);
                }
            }
        } else if ev_code == LOAD_DLL_DEBUG_EVENT {
            let info = unsafe { ev.u.LoadDll };
            close_if(info.hFile);
            // Weixin.dll 可能此刻才加载（relaunch 模式）——尝试武装
            try_arm(&mut procs, pid, &mut cand_rvas);
        } else if ev_code == EXCEPTION_DEBUG_EVENT {
            let er = unsafe { ev.u.Exception };
            let code = er.ExceptionRecord.ExceptionCode;
            if code == EXCEPTION_SINGLE_STEP {
                // 硬件断点命中报单步异常
                let hthread = procs.get(&pid).and_then(|st| st.threads.get(&tid)).copied();
                let hproc = procs.get(&pid).map(|st| st.hproc);
                match (hthread, hproc) {
                    (Some(ht), Some(hp)) if hwbp::is_our_hit(ht) => {
                        if let Ok(regs) = hwbp::read_hit_regs(ht) {
                            handle_hit(hp, regs, &all_dbs, &mut done, &mut found, total);
                        }
                        // 置 RF 越过这条指令，防止同址重入
                        let _ = hwbp::step_over(ht);
                        cont = DBG_CONTINUE;
                    }
                    _ => cont = DBG_EXCEPTION_NOT_HANDLED,
                }
            } else if code.0 as u32 == EXCEPTION_BREAKPOINT_CODE {
                // 附加/加载器初始断点：吞掉，避免微信崩溃
                cont = DBG_CONTINUE;
            } else {
                // 微信自身的 first-chance 异常：交回它自己的 handler，别干扰运行
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if ev_code == EXIT_THREAD_DEBUG_EVENT {
            // 线程退出：系统随后会关闭这个 hThread，先从表里摘除，避免残留失效句柄
            // （否则 detach_all 会对已关闭句柄操作，长时间等待时 map 还会无界增长）。
            if let Some(st) = procs.get_mut(&pid) {
                st.threads.remove(&tid);
            }
        } else if ev_code == EXIT_PROCESS_DEBUG_EVENT {
            procs.remove(&pid);
            if procs.is_empty() {
                process_gone = true;
            }
        }

        let _ = unsafe { ContinueDebugEvent(pid, tid, cont) };

        if done.len() >= total {
            eprintln!("已抓齐全部 {total} 个库的密钥。");
            break;
        }
        if process_gone {
            eprintln!(
                "被调试的微信进程已全部退出，结束抓取（已 {}/{}）。",
                done.len(),
                total
            );
            break;
        }
    }

    detach_all(&procs);
    Ok(found.into_values().collect())
}

/// 命中处理：从 rcx/rdx/r8/r9 取候选 key（直接 32B + 解一层指针后 32B），逐个
/// 对未匹配库做 page1 强校验，命中即入账。实测 4.1.11.24 是 `rcx` off 0 直接命中，
/// 其余寄存器 / 解指针变体用于版本鲁棒（多套 AES 时靠校验筛真 key）。
fn handle_hit(
    hproc: HANDLE,
    regs: HitRegs,
    all_dbs: &[(String, PathBuf)],
    done: &mut HashSet<String>,
    found: &mut HashMap<String, KeyEntry>,
    total: usize,
) {
    let mut cands: Vec<[u8; 32]> = Vec::new();
    for reg in [regs.rcx, regs.rdx, regs.r8, regs.r9] {
        if let Some(b) = read_mem(hproc, reg, 32) {
            if let Some(k) = to32(&b) {
                cands.push(k);
            }
        }
        // 解一层指针：*(reg) 作为地址再读 32B
        if let Some(p) = read_mem(hproc, reg, 8) {
            let ptr = u64::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]);
            if let Some(b) = read_mem(hproc, ptr, 32) {
                if let Some(k) = to32(&b) {
                    cands.push(k);
                }
            }
        }
    }

    for key in &cands {
        for (name, path) in all_dbs {
            if done.contains(name) {
                continue;
            }
            if verify_enc_key_for_db(path, key) {
                let salt = read_db_salt(path).unwrap_or_default();
                found.insert(
                    name.clone(),
                    KeyEntry {
                        db_name: name.clone(),
                        enc_key: hex32(key),
                        salt,
                    },
                );
                done.insert(name.clone());
                eprintln!("  ✓ 命中密钥：{}  ({}/{})", name, done.len(), total);
            }
        }
    }
}

/// 若某进程已加载 Weixin.dll 且尚未武装，则定位设钥函数并给它所有已知线程铺断点。
fn try_arm(procs: &mut HashMap<u32, ProcState>, pid: u32, cand_rvas: &mut Option<Vec<u32>>) {
    let st = match procs.get_mut(&pid) {
        Some(s) => s,
        None => return,
    };
    if st.armed {
        return;
    }
    let (base, path) = match find_weixin_module(pid) {
        Some(x) => x,
        None => return, // Weixin.dll 还没加载
    };

    // 首次解析磁盘 DLL 的候选 RVA（多进程共用同一份）
    if cand_rvas.is_none() {
        match locate_key_schedule_funcs(Path::new(&path), 4) {
            Ok(c) => {
                let rvas: Vec<u32> = c.iter().map(|f| f.rva).collect();
                eprintln!(
                    "已定位 Weixin.dll 中 {} 个设钥函数候选（aeskeygenassist 命中最多者优先）。",
                    rvas.len()
                );
                *cand_rvas = Some(rvas);
            }
            Err(e) => {
                eprintln!("定位设钥函数失败：{e}");
                return;
            }
        }
    }
    let rvas = match cand_rvas.as_ref() {
        Some(r) if !r.is_empty() => r,
        _ => return,
    };
    let vas: Vec<u64> = rvas.iter().map(|r| base + *r as u64).collect();

    let mut armed_any = false;
    for h in st.threads.values() {
        if hwbp::arm_thread(*h, &vas).is_ok() {
            armed_any = true;
        }
    }
    st.cand_vas = vas;
    st.armed = true;
    if armed_any {
        eprintln!(
            "已在 Weixin.dll（base {:#x}）铺设硬件断点，等待开库瞬间…",
            base
        );
    }
}

/// 分离：清除断点、关掉 kill-on-exit、逐进程 DebugActiveProcessStop（微信继续存活）。
fn detach_all(procs: &HashMap<u32, ProcState>) {
    unsafe { DebugSetProcessKillOnExit(false) }.ok();
    for (pid, st) in procs {
        for h in st.threads.values() {
            let _ = hwbp::disarm_thread(*h);
        }
        unsafe { DebugActiveProcessStop(*pid) }.ok();
    }
}

/// relaunch 前置：若微信在运行，记录其 exe 路径并提示用户手动退出，等它退干净；
/// 若没运行，探测安装目录里的 Weixin.exe。返回可启动的 Weixin.exe 路径。
fn prepare_relaunch() -> Result<PathBuf> {
    let running = find_all_wechat_pids();
    if running.is_empty() {
        return locate_installed_wechat_exe()
            .context("未找到 Weixin.exe，请先手动启动一次微信，或改用 wxeasy init --live 附加");
    }

    let exe = get_wechat_exe_path(running[0]).context("无法获取正在运行的 Weixin.exe 路径")?;
    eprintln!("检测到微信正在运行（PID {running:?}）。");
    eprintln!("要一次抓齐全部密钥，需要在调试器接管下重新启动微信。");
    eprintln!("请【手动完全退出微信】（右键托盘图标 → 退出）。");
    eprintln!("⚠ 不要反复强杀微信——那会触发重新认证卡在登录界面。");
    eprintln!("等待微信退出中…（退出后我会自动带起，并等你扫码登录）");

    // 不设死超时，耐心等用户手动退出
    loop {
        if find_all_wechat_pids().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    eprintln!("微信已退出，正在以调试模式重新启动…");
    Ok(exe)
}

/// 以 DEBUG_PROCESS 启动微信（跟随子进程树——微信可能经 launcher 拉起主进程）。
fn launch_wechat_debugged(exe: &Path) -> Result<u32> {
    let app: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            PWSTR::null(),
            None,
            None,
            false,
            DEBUG_PROCESS,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    }
    .map_err(|e| anyhow!("以调试模式启动 Weixin.exe 失败: {e}"))?;
    // 我们靠调试事件重新拿句柄，这里返回的直接关掉
    close_if(pi.hThread);
    close_if(pi.hProcess);
    Ok(pi.dwProcessId)
}

/// 探测常见安装目录里的 Weixin.exe。
fn locate_installed_wechat_exe() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Ok(pf) = std::env::var(var) {
            cands.push(
                PathBuf::from(pf)
                    .join("Tencent")
                    .join("Weixin")
                    .join("Weixin.exe"),
            );
        }
    }
    cands.into_iter().find(|p| p.exists())
}

/// 通过 QueryFullProcessImageNameW 拿某 PID 的可执行文件绝对路径。
fn get_wechat_exe_path(pid: u32) -> Option<PathBuf> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = vec![0u16; 512];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len)
    };
    unsafe {
        let _ = CloseHandle(h);
    }
    ok.ok()?;
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// 用 ToolHelp 模块快照找某 PID 的 Weixin.dll，返回 (模块基址, 磁盘路径)。
fn find_weixin_module(pid: u32) -> Option<(u64, String)> {
    let snap = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPMODULE.0 | TH32CS_SNAPMODULE32.0),
            pid,
        )
    }
    .ok()?;
    let mut me = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = None;
    unsafe {
        if Module32FirstW(snap, &mut me).is_ok() {
            loop {
                let name = wide_to_string(&me.szModule);
                if name.eq_ignore_ascii_case("Weixin.dll") {
                    let path = wide_to_string(&me.szExePath);
                    result = Some((me.modBaseAddr as u64, path));
                    break;
                }
                if Module32NextW(snap, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    result
}

/// 枚举所有 Weixin.exe 进程 PID。
fn find_all_wechat_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(s) => s,
        Err(_) => return pids,
    };
    let mut entry = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
    unsafe {
        if Process32First(snap, &mut entry).is_ok() {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy();
                if name.eq_ignore_ascii_case("Weixin.exe") {
                    pids.push(entry.th32ProcessID);
                }
                if Process32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

fn find_wechat_pid() -> Option<u32> {
    find_all_wechat_pids().into_iter().next()
}

/// 启用当前进程 token 的 SeDebugPrivilege（调试其它进程所需）。
fn enable_se_debug_privilege() -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(TOKEN_ADJUST_PRIVILEGES.0 | TOKEN_QUERY.0),
            &mut token,
        )
        .map_err(|e| anyhow!("OpenProcessToken 失败: {e}"))?;

        let mut luid = LUID::default();
        let lookup = LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid);
        if let Err(e) = lookup {
            let _ = CloseHandle(token);
            return Err(anyhow!("LookupPrivilegeValueW(SeDebugPrivilege) 失败: {e}"));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjust = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        // AdjustTokenPrivileges 即使权限未真正授予也返回 TRUE，必须查 GetLastError：
        // ERROR_NOT_ALL_ASSIGNED 表示当前 token 拿不到 SeDebugPrivilege（通常是没以
        // 管理员身份运行），此时返回成功会误导——提前报清晰错误。
        let last = GetLastError();
        let _ = CloseHandle(token);
        adjust.map_err(|e| anyhow!("AdjustTokenPrivileges 失败: {e}"))?;
        if last == ERROR_NOT_ALL_ASSIGNED {
            return Err(anyhow!(
                "SeDebugPrivilege 未授予（通常是未以管理员身份运行）"
            ));
        }
    }
    Ok(())
}

/// 从目标进程读 `len` 字节；读满才返回 Some。
fn read_mem(hproc: HANDLE, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            hproc,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut read),
        )
    }
    .is_ok();
    if ok && read >= len {
        Some(buf)
    } else {
        None
    }
}

fn to32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() >= 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v[..32]);
        Some(a)
    } else {
        None
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// 句柄非空则关闭（CREATE_PROCESS / LOAD_DLL 事件带的 file handle 需调试器关闭）。
fn close_if(h: HANDLE) {
    if !h.is_invalid() {
        unsafe {
            let _ = CloseHandle(h);
        }
    }
}
