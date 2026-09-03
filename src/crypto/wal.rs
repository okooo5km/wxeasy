use anyhow::Result;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use super::{decrypt_page, PAGE_SZ};

pub const WAL_HDR_SZ: usize = 32;
pub const WAL_FRAME_HDR: usize = 24;

/// 将 WAL 文件中的变更应用到已解密的数据库文件
///
/// WAL 格式（SQLite 标准，SQLCipher 4 的 WAL 帧也被加密）：
/// - WAL header (32 bytes): magic(4) + format(4) + page_sz(4) + ckpt_seq(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)
/// - 每帧：frame_header(24 bytes) + page_data(PAGE_SZ bytes)
///   - frame_header: pgno(4) + commit_pgcnt(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)
pub fn apply_wal(wal_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if !wal_path.exists() {
        return Ok(());
    }

    let wal_data = std::fs::read(wal_path)?;
    if wal_data.len() <= WAL_HDR_SZ {
        return Ok(());
    }

    // 读取 WAL 头中的 salt1 / salt2
    let s1 = u32::from_be_bytes(wal_data[16..20].try_into().unwrap());
    let s2 = u32::from_be_bytes(wal_data[20..24].try_into().unwrap());

    let frame_size = WAL_FRAME_HDR + PAGE_SZ;
    let frame_area = &wal_data[WAL_HDR_SZ..];

    // 打开输出文件做随机写
    let mut db_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out_path)?;

    let mut pos = 0usize;
    while pos + frame_size <= frame_area.len() {
        let fh = &frame_area[pos..pos + WAL_FRAME_HDR];
        let page_data = &frame_area[pos + WAL_FRAME_HDR..pos + frame_size];

        let pgno = u32::from_be_bytes(fh[0..4].try_into().unwrap());
        let fs1 = u32::from_be_bytes(fh[8..12].try_into().unwrap());
        let fs2 = u32::from_be_bytes(fh[12..16].try_into().unwrap());

        pos += frame_size;

        // 跳过无效页码
        if pgno == 0 || pgno > 1_000_000 {
            continue;
        }
        // salt 不匹配的帧属于已检查点或旧事务
        if fs1 != s1 || fs2 != s2 {
            continue;
        }

        let mut page_buf = page_data.to_vec();
        if page_buf.len() < PAGE_SZ {
            page_buf.resize(PAGE_SZ, 0);
        }

        // fork patch（修复 WAL 帧 pgno==1 解密路由反了的致命 bug）：
        // 原上游这里写的是 `if pgno == 1 { 2 } else { pgno }`，把 pgno==1 的
        // WAL 帧强行当成"非首页"解密。这是一个已被真实 SQLCipher 实锤证伪的
        // 错误假设——用 pysqlcipher3 造出真实活体 WAL、再配合独立手写的 AES
        // 解密双重验证后确认：WAL 帧 targeting pgno==1 时，其 page_data 与
        // 主库物理首页布局完全一致，同样带 16 字节 SALT 前缀，必须走"首页"
        // 解密路径（跳 SALT、写回 SQLite 魔数）。原实现把它当非首页解密只会
        // 解出乱码，SQLite 打开直接报 `file is not a database`——这极可能是
        // 慢机上 wxeasy-daemon 反复出现 NOTADB 的根因之一（凡是导致数据库总页数
        // 变化，例如收消息扩页，或建表/schema 变更的提交都会写 page1 进
        // WAL）。修复方式：直接把真实 pgno 传给 decrypt_page，由它自身现成的
        // pgno==1 分支统一处理"主库首页"和"WAL 首页帧"两种来源，pgno>1 的帧
        // 行为不变。此修改作为 fork patch 的一部分保留。
        let dec = decrypt_page(enc_key, &page_buf, pgno)?;
        let file_offset = (pgno as u64 - 1) * PAGE_SZ as u64;
        db_file.seek(SeekFrom::Start(file_offset))?;
        db_file.write_all(&dec)?;
    }

    Ok(())
}
