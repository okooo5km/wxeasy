//! 联系人派生表（`Names` 的 map / verify_flags）的**加密**持久化缓存。
//!
//! # 解决什么
//! `load_names` 对 contact.db 做全表扫描 + 逐页解密——几十万行联系人在
//! 机械盘上是十几秒级，整段时间 daemon 处于 `warming_up` 拒答窗口。把
//! 派生结果缓存到磁盘后，重启且 contact.db 未变时直接反序列化（亚秒），
//! 跳过全表扫描。
//!
//! # 为什么必须加密（已拍板：2026-07-22，Boss 决策选「加密缓存」方案）
//! map / verify_flags 是 contact.db 解密后的现成明文（备注名、昵称、
//! username）。项目立场是**不主动扩大明文面**——缓存文件用 contact.db
//! 自身的 `enc_key` 做 AES-256-CBC + HMAC-SHA256（encrypt-then-MAC）。
//! 不引入新密钥、密钥不落新盘（`enc_key` 本就存于 `all_keys.json`，属
//! 既有威胁模型）；拿不到 enc_key 的攻击者拿到缓存文件读不出任何内容，
//! 拿得到 enc_key 的攻击者本就能直接解 contact.db，防御纵深不变。
//!
//! # 失效判定
//! 与路由缓存同一套哲学（见 [`super::cache::SourceSnapshot`]）：文件内
//! 记录构建时 contact.db 的快照，加载时要求「快照逐字段相等 + 已安静满
//! 一个 slack 周期」，否则走冷扫描。已知短板：开机 → 微信同步联系人 →
//! contact.db 被写 → 安静期过不去 → 照旧冷扫——最需要缓存的时刻最容易
//! miss，真实命中率待现场数据（roadmap §4.3 的预告）。
//!
//! # 文件格式（`cache_dir/names_cache.bin`）
//! `magic "WXNC"(4B) || iv(16B) || ciphertext || hmac_tag(32B)`
//! - 明文 = zstd(serde_json(NamesCacheFile))
//! - MAC 覆盖 `magic || iv || ciphertext`，先验 MAC 再解密
//! - IV = SHA256(时间纳秒 || 明文)[..16]：内容或时刻不同则 IV 不同，
//!   避免固定 key 下的 CBC IV 复用
//! 任何一步失败（长度、magic、MAC、解密、解压、解析、版本、db_dir、
//! 快照）都静默返回 `None` 走冷路径——文件只是影子，内存才是真相。
//!
//! 作者: okooo5km(十里)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cache::{now_nanos, SourceSnapshot};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"WXNC";
const IV_LEN: usize = 16;
const TAG_LEN: usize = 32;
const NAMES_CACHE_VERSION: u32 = 1;
const NAMES_CACHE_FILE_NAME: &str = "names_cache.bin";
/// MAC 密钥域分离标签（enc_key 同时用于 AES 与 HMAC 派生，必须分域）。
const MAC_DOMAIN: &[u8] = b"wxeasy-names-cache-mac-v1";

#[derive(Serialize, Deserialize)]
struct NamesCacheFile {
    version: u32,
    /// 身份字段：不同账号（db_dir）绝不混用彼此的联系人缓存。
    db_dir: String,
    /// 构建时刻 contact.db 的快照（判定时刻语义：扫描**开始前**采集，
    /// 扫描期间 contact.db 被写只会让缓存显得更旧、下次判 Stale 重扫，
    /// 方向安全——与 put_shard_schema 的 TOCTOU 纪律同向）。
    snapshot: SourceSnapshot,
    map: HashMap<String, String>,
    verify_flags: HashMap<String, i64>,
}

fn cache_file_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(NAMES_CACHE_FILE_NAME)
}

fn mac_key(enc_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MAC_DOMAIN);
    h.update(enc_key);
    h.finalize().into()
}

/// 加载并验证缓存。返回 `Some((map, verify_flags))` 仅当：文件完整、MAC
/// 通过、版本与 db_dir 匹配、快照与 `current` 逐字段相等、且 `current`
/// 已安静满一个 slack 周期。
pub(crate) fn load_names_cache(
    cache_dir: &Path,
    db_dir: &Path,
    enc_key: &[u8; 32],
    current: SourceSnapshot,
) -> Option<(HashMap<String, String>, HashMap<String, i64>)> {
    if !current.trusted_as_of(now_nanos()) {
        return None;
    }
    let raw = std::fs::read(cache_file_path(cache_dir)).ok()?;
    if raw.len() < MAGIC.len() + IV_LEN + TAG_LEN || &raw[..MAGIC.len()] != MAGIC {
        return None;
    }
    let (body, tag) = raw.split_at(raw.len() - TAG_LEN);

    // encrypt-then-MAC：先验 MAC（常量时间比较），再碰密文。
    let mut mac = HmacSha256::new_from_slice(&mac_key(enc_key)).ok()?;
    mac.update(body);
    mac.verify_slice(tag).ok()?;

    let iv: [u8; IV_LEN] = body[MAGIC.len()..MAGIC.len() + IV_LEN].try_into().ok()?;
    let ciphertext = &body[MAGIC.len() + IV_LEN..];
    let compressed = Aes256CbcDec::new(enc_key.into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .ok()?;
    let json = zstd::decode_all(compressed.as_slice()).ok()?;
    let parsed: NamesCacheFile = serde_json::from_slice(&json).ok()?;

    if parsed.version != NAMES_CACHE_VERSION
        || parsed.db_dir != db_dir.to_string_lossy()
        || parsed.snapshot != current
    {
        return None;
    }
    Some((parsed.map, parsed.verify_flags))
}

/// 加密写回（临时文件 + 原子 rename）。失败静默忽略——影子文件而已。
pub(crate) fn store_names_cache(
    cache_dir: &Path,
    db_dir: &Path,
    enc_key: &[u8; 32],
    snapshot: SourceSnapshot,
    map: &HashMap<String, String>,
    verify_flags: &HashMap<String, i64>,
) {
    let file = NamesCacheFile {
        version: NAMES_CACHE_VERSION,
        db_dir: db_dir.to_string_lossy().into_owned(),
        snapshot,
        map: map.clone(),
        verify_flags: verify_flags.clone(),
    };
    let Ok(json) = serde_json::to_vec(&file) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(json.as_slice(), 3) else {
        return;
    };

    let mut iv_src = Sha256::new();
    iv_src.update(now_nanos().to_le_bytes());
    iv_src.update(&compressed);
    let digest = iv_src.finalize();
    let iv: [u8; IV_LEN] = digest[..IV_LEN]
        .try_into()
        .expect("SHA256 摘要必然 ≥ 16 字节");

    let ciphertext = Aes256CbcEnc::new(enc_key.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(&compressed);

    let mut out = Vec::with_capacity(MAGIC.len() + IV_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    let Ok(mut mac) = HmacSha256::new_from_slice(&mac_key(enc_key)) else {
        return;
    };
    mac.update(&out);
    out.extend_from_slice(&mac.finalize().into_bytes());

    let path = cache_file_path(cache_dir);
    let tmp = path.with_extension("bin.tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

#[cfg(test)]
mod tests {
    use super::super::cache::test_support::{backdate_beyond_slack, unique_tmpdir};
    use super::*;

    struct Env {
        cache_dir: PathBuf,
        db_dir: PathBuf,
        contact_path: PathBuf,
        key: [u8; 32],
    }

    fn env(tag: &str) -> Env {
        let root = unique_tmpdir(tag);
        let cache_dir = root.join("cache");
        let db_dir = root.join("db_storage");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::create_dir_all(db_dir.join("contact")).unwrap();
        let contact_path = db_dir.join("contact").join("contact.db");
        std::fs::write(&contact_path, b"fake contact db").unwrap();
        backdate_beyond_slack(&contact_path);
        Env {
            cache_dir,
            db_dir,
            contact_path,
            key: [0x5A; 32],
        }
    }

    fn snap(e: &Env) -> SourceSnapshot {
        let wal = PathBuf::from(format!("{}-wal", e.contact_path.display()));
        SourceSnapshot::capture(&e.contact_path, &wal)
    }

    fn sample() -> (HashMap<String, String>, HashMap<String, i64>) {
        let mut map = HashMap::new();
        map.insert("wxid_abc".to_string(), "老王".to_string());
        map.insert("wxid_def".to_string(), "测试群".to_string());
        let mut vf = HashMap::new();
        vf.insert("wxid_abc".to_string(), 0);
        vf.insert("wxid_def".to_string(), 24);
        (map, vf)
    }

    #[test]
    fn roundtrip_hits_when_snapshot_unchanged_and_quiet() {
        let e = env("names-roundtrip");
        let (map, vf) = sample();
        let s = snap(&e);
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, s, &map, &vf);

        let got = load_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e))
            .expect("快照未变且安静，应命中");
        assert_eq!(got.0, map);
        assert_eq!(got.1, vf);
    }

    #[test]
    fn source_change_invalidates() {
        let e = env("names-source-change");
        let (map, vf) = sample();
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);

        // contact.db 变了（内容 + 长度 + mtime），即便随后再回拨 mtime 使
        // 其「安静」，快照逐字段相等也不成立 ⇒ None。
        std::fs::write(&e.contact_path, b"newer contact db, different length").unwrap();
        backdate_beyond_slack(&e.contact_path);
        assert!(load_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e)).is_none());
    }

    #[test]
    fn recent_write_fails_quiet_gate() {
        let e = env("names-not-quiet");
        let (map, vf) = sample();
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);

        // mtime 拉回现在：快照没变？——不，set_modified 改了 mtime，快照
        // 本身也变了；这里单测「安静期」这一道门：构造 mtime=现在、快照
        // 相等的场景需要 store 时就用「现在」的快照。
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&e.contact_path)
            .unwrap();
        file.set_modified(std::time::SystemTime::now()).unwrap();
        drop(file);
        let fresh_snap = snap(&e);
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, fresh_snap, &map, &vf);
        assert!(
            load_names_cache(&e.cache_dir, &e.db_dir, &e.key, fresh_snap).is_none(),
            "刚被写过（未安静满 slack）的 contact.db 不得信任缓存"
        );
    }

    #[test]
    fn tampered_or_wrong_key_is_rejected() {
        let e = env("names-tamper");
        let (map, vf) = sample();
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);
        let path = e.cache_dir.join(NAMES_CACHE_FILE_NAME);

        // 篡改密文中间一个字节 ⇒ MAC 拒绝。
        let mut raw = std::fs::read(&path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();
        assert!(load_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e)).is_none());

        // 换密钥 ⇒ MAC 拒绝。
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);
        let wrong_key = [0xA5; 32];
        assert!(load_names_cache(&e.cache_dir, &e.db_dir, &wrong_key, snap(&e)).is_none());
    }

    #[test]
    fn mismatched_db_dir_is_rejected() {
        let e = env("names-identity");
        let (map, vf) = sample();
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);
        let other_db_dir = e.db_dir.join("elsewhere");
        assert!(
            load_names_cache(&e.cache_dir, &other_db_dir, &e.key, snap(&e)).is_none(),
            "db_dir 身份不匹配必须拒绝"
        );
    }

    /// 文件内容不含明文：备注名/昵称的字节不得出现在缓存文件里。
    #[test]
    fn cache_file_contains_no_plaintext() {
        let e = env("names-no-plaintext");
        let (map, vf) = sample();
        store_names_cache(&e.cache_dir, &e.db_dir, &e.key, snap(&e), &map, &vf);
        let raw = std::fs::read(e.cache_dir.join(NAMES_CACHE_FILE_NAME)).unwrap();
        for needle in ["wxid_abc", "老王", "verify_flags"] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "缓存文件里出现了明文片段: {}",
                needle
            );
        }
    }
}
