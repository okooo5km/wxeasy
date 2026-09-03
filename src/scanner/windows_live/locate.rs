//! 定位 Weixin.dll 中的 AES-NI 密钥扩展函数（设钥断点地址）。
//!
//! 版本鲁棒策略，不写死 RVA：
//! 1. 用 `object` 纯 Rust 解析磁盘上的 Weixin.dll（PE64）。
//! 2. 在 `.text` 里扫 `aeskeygenassist` 指令（字节 `66 0F 3A DF`）。
//! 3. 用 `.pdata`（x64 异常表 `RUNTIME_FUNCTION`）把每个命中归组到所属函数。
//! 4. 候选 = aeskeygenassist 命中数最多的函数（AES 密钥扩展特征），按强度降序。
//!
//! 多候选无妨：微信里有多套 AES（网络 mmtls + 两套 SQLCipher），全部下断点，
//! 靠 page1 校验筛出真正能解库的 key，其余淘汰（见 `debugger` 命中处理）。
//!
//! 署名：okooo5km(十里)

use anyhow::{bail, Context, Result};
use object::read::pe::PeFile64;
use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::path::Path;

/// `aeskeygenassist xmm, xmm, imm8` 的操作码前缀（`66 0F 3A DF`）。
const AESKEYGENASSIST: &[u8] = &[0x66, 0x0F, 0x3A, 0xDF];

/// 一个候选设钥函数：入口 RVA + 命中的 aeskeygenassist 数量（特征强度）。
#[derive(Debug, Clone)]
pub struct FuncCandidate {
    /// 函数入口相对虚拟地址（运行时 VA = 模块基址 + rva）。
    pub rva: u32,
    /// 该函数内 aeskeygenassist 命中数，越多越像 AES 密钥扩展。
    pub hits: usize,
}

/// 解析磁盘 DLL，返回按特征强度降序的候选函数入口 RVA（最多 `take_top` 个）。
///
/// 实测 4.1.11.24 的设钥函数含 31 条 aeskeygenassist，稳居榜首。
pub fn locate_key_schedule_funcs(dll_path: &Path, take_top: usize) -> Result<Vec<FuncCandidate>> {
    let data =
        std::fs::read(dll_path).with_context(|| format!("读取 {} 失败", dll_path.display()))?;
    let pe = PeFile64::parse(&*data).context("解析 Weixin.dll（PE64）失败")?;
    let image_base = pe.relative_address_base();

    // 取 .text（扫指令）与 .pdata（函数边界）。object 的 section.address() 对 PE
    // 返回 image_base + RVA，减去 image_base 得纯 RVA。
    let mut text: Option<(u32, Vec<u8>)> = None;
    let mut pdata: Option<Vec<u8>> = None;
    for section in pe.sections() {
        let name = section.name().unwrap_or_default();
        let rva = section.address().saturating_sub(image_base) as u32;
        match name {
            ".text" => {
                let sdata = section.data().unwrap_or(&[]).to_vec();
                text = Some((rva, sdata));
            }
            ".pdata" => {
                pdata = Some(section.data().unwrap_or(&[]).to_vec());
            }
            _ => {}
        }
    }
    let (text_rva, text_data) = text.context("Weixin.dll 缺少 .text section")?;

    // 1) 扫 aeskeygenassist 命中的 RVA
    let mut hit_rvas: Vec<u32> = Vec::new();
    let mut i = 0usize;
    while i + AESKEYGENASSIST.len() <= text_data.len() {
        if &text_data[i..i + AESKEYGENASSIST.len()] == AESKEYGENASSIST {
            hit_rvas.push(text_rva + i as u32);
            i += AESKEYGENASSIST.len();
        } else {
            i += 1;
        }
    }
    if hit_rvas.is_empty() {
        bail!("Weixin.dll 的 .text 里未发现 aeskeygenassist，可能不是预期版本或非 AES-NI 构建");
    }

    // 2) 用 .pdata 函数边界把命中归组到所属函数入口
    let funcs = parse_pdata(pdata.as_deref());
    let mut counts: HashMap<u32, usize> = HashMap::new();
    if funcs.is_empty() {
        // 没有 .pdata（异常表被裁剪）：退化为每个命中地址独立成候选，仍可下断点尝试
        for r in &hit_rvas {
            *counts.entry(*r).or_insert(0) += 1;
        }
    } else {
        for r in &hit_rvas {
            if let Some(begin) = func_of(&funcs, *r) {
                *counts.entry(begin).or_insert(0) += 1;
            }
        }
    }
    if counts.is_empty() {
        bail!("aeskeygenassist 命中无法归入任何 .pdata 函数边界");
    }

    // 3) 按命中数降序（并列时地址升序，稳定）取前 take_top
    let mut cands: Vec<FuncCandidate> = counts
        .into_iter()
        .map(|(rva, hits)| FuncCandidate { rva, hits })
        .collect();
    cands.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.rva.cmp(&b.rva)));
    cands.truncate(take_top.max(1));
    Ok(cands)
}

/// 解析 .pdata：x64 `RUNTIME_FUNCTION` 数组，每 12 字节
/// `(begin_rva: u32, end_rva: u32, unwind_rva: u32)`，小端。返回按 begin 排序的
/// `(begin, end)` 区间。
fn parse_pdata(pdata: Option<&[u8]>) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    if let Some(d) = pdata {
        for chunk in d.chunks_exact(12) {
            let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            // .pdata 尾部可能有全零填充项
            if begin == 0 && end == 0 {
                continue;
            }
            if end > begin {
                out.push((begin, end));
            }
        }
        out.sort_by_key(|(b, _)| *b);
    }
    out
}

/// 二分查找 rva 落在哪个函数区间，命中则返回函数入口 begin_rva。
fn func_of(funcs: &[(u32, u32)], rva: u32) -> Option<u32> {
    // funcs 已按 begin 升序。找最后一个 begin <= rva 的区间，再判 rva < end。
    let idx = match funcs.binary_search_by(|(b, _)| b.cmp(&rva)) {
        Ok(i) => i,
        Err(0) => return None,
        Err(i) => i - 1,
    };
    let (begin, end) = funcs[idx];
    if rva >= begin && rva < end {
        Some(begin)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pdata_skips_zero_and_sorts() {
        // 三个 RUNTIME_FUNCTION：乱序 + 一个全零填充
        let mut raw = Vec::new();
        let push = |raw: &mut Vec<u8>, b: u32, e: u32, u: u32| {
            raw.extend_from_slice(&b.to_le_bytes());
            raw.extend_from_slice(&e.to_le_bytes());
            raw.extend_from_slice(&u.to_le_bytes());
        };
        push(&mut raw, 0x2000, 0x2100, 0);
        push(&mut raw, 0x1000, 0x1200, 0);
        push(&mut raw, 0, 0, 0); // 填充
        let funcs = parse_pdata(Some(&raw));
        assert_eq!(funcs, vec![(0x1000, 0x1200), (0x2000, 0x2100)]);
    }

    #[test]
    fn func_of_maps_rva_to_enclosing_function() {
        let funcs = vec![(0x1000, 0x1200), (0x2000, 0x2100)];
        assert_eq!(func_of(&funcs, 0x1000), Some(0x1000)); // 入口
        assert_eq!(func_of(&funcs, 0x1150), Some(0x1000)); // 函数内部
        assert_eq!(func_of(&funcs, 0x1200), None); // 恰好 end（开区间）
        assert_eq!(func_of(&funcs, 0x2050), Some(0x2000));
        assert_eq!(func_of(&funcs, 0x500), None); // 第一个函数之前
        assert_eq!(func_of(&funcs, 0x9000), None); // 所有函数之后
    }
}
