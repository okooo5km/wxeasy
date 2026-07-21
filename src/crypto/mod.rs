pub mod wal;

use aes::Aes256;
use anyhow::{bail, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use std::io::{Read, Write};
use std::path::Path;

type Block = aes::cipher::Block<Aes256>;

pub const PAGE_SZ: usize = 4096;
pub const SALT_SZ: usize = 16;
pub const RESERVE_SZ: usize = 80; // IV(16) + HMAC(64)

/// SQLite 文件头魔数（16字节）
pub const SQLITE_HDR: &[u8] = b"SQLite format 3\x00";

type Aes256CbcDec = Decryptor<Aes256>;

/// 解密单个 SQLCipher 4 页
///
/// - `enc_key`: 32字节 AES 密钥
/// - `page_data`: 原始加密页面数据（PAGE_SZ 字节）
/// - `pgno`: 页码（从1开始）
///
/// 返回解密后的完整页面（PAGE_SZ 字节）
pub fn decrypt_page(enc_key: &[u8; 32], page_data: &[u8], pgno: u32) -> Result<Vec<u8>> {
    if page_data.len() < PAGE_SZ {
        bail!("页面数据不足 {} 字节", PAGE_SZ);
    }

    // IV 位于页面末尾 RESERVE_SZ 区域的前16字节
    let iv_offset = PAGE_SZ - RESERVE_SZ;
    let iv: &[u8; 16] = page_data[iv_offset..iv_offset + 16]
        .try_into()
        .expect("IV 长度固定为 16");

    let mut result = vec![0u8; PAGE_SZ];

    if pgno == 1 {
        // 第一页：跳过 salt(16字节)，解密 [SALT_SZ..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        // 写入 SQLite 文件头
        result[..16].copy_from_slice(SQLITE_HDR);
        // 写入解密数据（从第16字节开始）
        result[16..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
        // （已经是零，无需显式操作）
    } else {
        // 其他页：解密 [0..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
    }

    Ok(result)
}

/// AES-256-CBC 解密（不去除 padding，SQLCipher 不使用 PKCS#7 padding）
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("密文长度不是 AES 块大小的倍数: {}", data.len());
    }
    // 将 &[u8] 复制为 Block 数组，避免 unsafe from_raw_parts_mut
    let mut blocks: Vec<Block> = data.chunks_exact(16).map(Block::clone_from_slice).collect();
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_blocks_mut(&mut blocks);
    Ok(blocks.iter().flat_map(|b| b.iter().copied()).collect())
}

/// [仅测试用] `decrypt_page` 的精确逆运算：把一份"期望解密结果"重新加密回
/// 合法的 SQLCipher4 密文页，用于在单元测试里构造可信的加密页/WAL 帧，而不
/// 依赖一份真实的微信数据库。逐字对齐 `tools/wx-verify/wxvfs-core` 里已验证
/// 过的同名测试 helper，供 `daemon::vfs` 的白盒单测复用。
///
/// - `pgno == 1` 时，参与加密的是 `logical_page[16..PAGE_SZ-RESERVE_SZ]`
///   （`logical_page[0..16]` 会被 `decrypt_page` 强制覆盖为 [`SQLITE_HDR`]，
///   加密侧无需还原）；
/// - `pgno != 1` 时，参与加密的是 `logical_page[0..PAGE_SZ-RESERVE_SZ]`。
#[cfg(test)]
pub(crate) fn encrypt_page(enc_key: &[u8; 32], logical_page: &[u8], iv: &[u8; 16], pgno: u32) -> Vec<u8> {
    use cbc::cipher::BlockEncryptMut;
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    assert_eq!(logical_page.len(), PAGE_SZ, "测试构造的逻辑页必须是完整 PAGE_SZ 字节");

    let mut result = vec![0u8; PAGE_SZ];
    let iv_offset = PAGE_SZ - RESERVE_SZ;

    if pgno == 1 {
        let plain = &logical_page[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let mut blocks: Vec<Block> = plain.chunks_exact(16).map(Block::clone_from_slice).collect();
        Aes256CbcEnc::new(enc_key.into(), iv.into()).encrypt_blocks_mut(&mut blocks);
        // 加密侧的头 16 字节代表 SALT，测试里内容不重要（decrypt_page 从不读取它）。
        result[..SALT_SZ].fill(0xAA);
        for (i, b) in blocks.iter().enumerate() {
            result[SALT_SZ + i * 16..SALT_SZ + i * 16 + 16].copy_from_slice(b);
        }
    } else {
        let plain = &logical_page[..PAGE_SZ - RESERVE_SZ];
        let mut blocks: Vec<Block> = plain.chunks_exact(16).map(Block::clone_from_slice).collect();
        Aes256CbcEnc::new(enc_key.into(), iv.into()).encrypt_blocks_mut(&mut blocks);
        for (i, b) in blocks.iter().enumerate() {
            result[i * 16..i * 16 + 16].copy_from_slice(b);
        }
    }

    result[iv_offset..iv_offset + 16].copy_from_slice(iv);
    // 保留区剩余的 HMAC 部分（64 字节）本项目从不校验，留零即可。
    result
}

/// WeChat 4.x / SQLCipher4 在 page_size=4096、reserve=80 时，page1 解密后
/// 逻辑页 offset 16 起固定出现的文件头字段前缀：
/// `page_size=0x1000, write/read_ver=2, reserved=80, max_embed=64, fracs=32/32`。
/// 用于快速判断 32 字节 raw key 是否正确（比仅看是否写出 `SQLite format 3` 更强，
/// 因为 `decrypt_page` 会强制写入文件头魔数）。
pub const SQLITE_PAGE1_META_PREFIX: &[u8] = &[0x10, 0x00, 0x02, 0x02, 0x50, 0x40, 0x20, 0x20];

/// 用 page1 元数据魔数验证 raw key 是否能解开指定加密库。
pub fn verify_enc_key_for_db(db_path: &Path, enc_key: &[u8; 32]) -> bool {
    let mut page = vec![0u8; PAGE_SZ];
    let mut f = match std::fs::File::open(db_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if f.read_exact(&mut page).is_err() {
        return false;
    }
    // 明文库无需 key
    if page.starts_with(SQLITE_HDR) {
        return true;
    }
    match decrypt_page(enc_key, &page, 1) {
        Ok(dec) => {
            // decrypt_page 会把 [0..16] 写成 SQLITE_HDR；真密钥时 [16..24] 为固定 meta
            dec.len() >= 24 && &dec[16..24] == SQLITE_PAGE1_META_PREFIX
        }
        Err(_) => false,
    }
}

/// 完整解密一个 SQLCipher 数据库文件（流式，逐页读写避免全量载入内存）
///
/// 读取 `db_path`，按 PAGE_SZ 分页解密，写入 `out_path`
pub fn full_decrypt(db_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut input = std::fs::File::open(db_path)?;
    let file_size = input.metadata()?.len() as usize;
    if file_size == 0 {
        bail!("数据库文件为空: {}", db_path.display());
    }

    let mut output = std::fs::File::create(out_path)?;
    let total_pages = (file_size + PAGE_SZ - 1) / PAGE_SZ;
    let mut page_buf = vec![0u8; PAGE_SZ];

    for pgno in 1..=total_pages {
        let page_start = (pgno - 1) * PAGE_SZ;
        let bytes_remaining = file_size.saturating_sub(page_start);
        read_page(&mut input, &mut page_buf, bytes_remaining)?;
        let dec = decrypt_page(enc_key, &page_buf, pgno as u32)?;
        output.write_all(&dec)?;
    }

    Ok(())
}

fn read_page(
    input: &mut impl Read,
    page_buf: &mut [u8],
    bytes_remaining: usize,
) -> std::io::Result<usize> {
    let expected = bytes_remaining.min(PAGE_SZ);
    input.read_exact(&mut page_buf[..expected])?;
    if expected < PAGE_SZ {
        page_buf[expected..].fill(0);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::{read_page, PAGE_SZ};
    use std::io::{self, Read};

    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        chunk_idx: usize,
        offset: usize,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks,
                chunk_idx: 0,
                offset: 0,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.chunk_idx >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = &self.chunks[self.chunk_idx];
            let remaining = &chunk[self.offset..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.offset += n;
            if self.offset == chunk.len() {
                self.chunk_idx += 1;
                self.offset = 0;
            }
            Ok(n)
        }
    }

    #[test]
    fn read_page_reads_across_short_chunks() {
        let mut reader = ChunkedReader::new(vec![vec![1; 32], vec![2; PAGE_SZ - 32]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, PAGE_SZ).unwrap();

        assert_eq!(n, PAGE_SZ);
        assert_eq!(page_buf[0], 1);
        assert_eq!(page_buf[31], 1);
        assert_eq!(page_buf[32], 2);
        assert_eq!(page_buf[PAGE_SZ - 1], 2);
    }

    #[test]
    fn read_page_zero_pads_last_partial_page() {
        let mut reader = ChunkedReader::new(vec![vec![7; 8], vec![9; 4]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, 12).unwrap();

        assert_eq!(n, 12);
        assert_eq!(&page_buf[..8], &[7; 8]);
        assert_eq!(&page_buf[8..12], &[9; 4]);
        assert!(page_buf[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_page_errors_on_early_eof() {
        let mut reader = ChunkedReader::new(vec![vec![1; 8]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let err = read_page(&mut reader, &mut page_buf, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
