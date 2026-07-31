//! 硬件断点（x64 调试寄存器 Dr0–Dr7）：铺设执行断点、命中判定、置 RF 越过。
//!
//! 为什么用硬件断点而非 INT3 软件断点：**不修改目标内存**，不触发 WCDB/微信的
//! 代码完整性校验，也不留 `0xCC` 痕迹。DR 寄存器是**每线程**的（在 `CONTEXT`
//! 里），所以要给每个会执行到设钥函数的线程分别铺设。
//!
//! 署名：okooo5km(十里)

use anyhow::{anyhow, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64,
    CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_FLAGS, CONTEXT_INTEGER_AMD64,
};

/// EFlags 的 Resume Flag（bit 16）：命中执行断点后置位，CPU 会把这条指令执行
/// 一次而不重新触发断点，抑制同址重入。
const EFLAGS_RF: u32 = 1 << 16;

/// 一次读到的关键整数寄存器（候选 raw key 指针）。
#[derive(Debug, Clone, Copy)]
pub struct HitRegs {
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
}

/// 读写 DR / 整数 / 控制寄存器所需的 ContextFlags 组合（AMD64）。
fn ctx_flags() -> CONTEXT_FLAGS {
    CONTEXT_FLAGS(
        CONTEXT_DEBUG_REGISTERS_AMD64.0 | CONTEXT_CONTROL_AMD64.0 | CONTEXT_INTEGER_AMD64.0,
    )
}

/// 取一个已置好 ContextFlags 的空 CONTEXT（`#[repr(align(16))]` 由 windows crate 保证）。
fn fresh_context() -> CONTEXT {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = ctx_flags();
    ctx
}

/// 在一个线程上铺设最多 4 个执行断点（Dr0..Dr3）。
///
/// `addrs`：候选函数入口 VA（运行时地址）。超过 4 个只取前 4（DR 寄存器上限）。
/// 执行断点要求 `RWn = 00`（执行）、`LENn = 00`。
pub fn arm_thread(hthread: HANDLE, addrs: &[u64]) -> Result<()> {
    let mut ctx = fresh_context();
    unsafe { GetThreadContext(hthread, &mut ctx) }
        .map_err(|e| anyhow!("GetThreadContext 失败: {e}"))?;

    let mut dr7 = ctx.Dr7;
    for (i, &addr) in addrs.iter().take(4).enumerate() {
        match i {
            0 => ctx.Dr0 = addr,
            1 => ctx.Dr1 = addr,
            2 => ctx.Dr2 = addr,
            3 => ctx.Dr3 = addr,
            _ => unreachable!(),
        }
        // L{i}：本地启用位在 bit (i*2)
        dr7 |= 1u64 << (i * 2);
        // RW{i} + LEN{i} 各 2 bit，位于 bit (16 + i*4)..(20 + i*4)；执行断点全清 0
        dr7 &= !(0b1111u64 << (16 + i * 4));
    }
    ctx.Dr7 = dr7;
    ctx.ContextFlags = ctx_flags();
    unsafe { SetThreadContext(hthread, &ctx) }
        .map_err(|e| anyhow!("SetThreadContext 失败: {e}"))?;
    Ok(())
}

/// 清除一个线程上的全部硬件断点（分离前恢复现场，避免残留 DR 影响微信）。
pub fn disarm_thread(hthread: HANDLE) -> Result<()> {
    let mut ctx = fresh_context();
    unsafe { GetThreadContext(hthread, &mut ctx) }
        .map_err(|e| anyhow!("GetThreadContext 失败: {e}"))?;
    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    // 清 L0..L3 启用位与对应 RW/LEN 字段
    ctx.Dr7 &= !0xFF_00FFu64;
    ctx.Dr6 = 0;
    ctx.ContextFlags = ctx_flags();
    unsafe { SetThreadContext(hthread, &ctx) }
        .map_err(|e| anyhow!("SetThreadContext 失败: {e}"))?;
    Ok(())
}

/// 命中后置 EFlags.RF 越过断点、清 Dr6，避免同一指令无限重入。
pub fn step_over(hthread: HANDLE) -> Result<()> {
    let mut ctx = fresh_context();
    unsafe { GetThreadContext(hthread, &mut ctx) }
        .map_err(|e| anyhow!("GetThreadContext 失败: {e}"))?;
    ctx.EFlags |= EFLAGS_RF;
    ctx.Dr6 = 0;
    ctx.ContextFlags = ctx_flags();
    unsafe { SetThreadContext(hthread, &ctx) }
        .map_err(|e| anyhow!("SetThreadContext 失败: {e}"))?;
    Ok(())
}

/// 读命中线程的 Rcx/Rdx/R8/R9（AES-NI 密钥扩展的候选 key 指针）。
pub fn read_hit_regs(hthread: HANDLE) -> Result<HitRegs> {
    let mut ctx = fresh_context();
    unsafe { GetThreadContext(hthread, &mut ctx) }
        .map_err(|e| anyhow!("GetThreadContext 失败: {e}"))?;
    Ok(HitRegs {
        rcx: ctx.Rcx,
        rdx: ctx.Rdx,
        r8: ctx.R8,
        r9: ctx.R9,
    })
}

/// 判断 Dr6 低 4 位是否指示我们的 Dr0..Dr3 命中（区分微信自身的单步/异常）。
pub fn is_our_hit(hthread: HANDLE) -> bool {
    let mut ctx = fresh_context();
    if unsafe { GetThreadContext(hthread, &mut ctx) }.is_err() {
        return false;
    }
    ctx.Dr6 & 0b1111 != 0
}
