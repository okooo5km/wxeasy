# Windows 微信 4.1.10+：密钥扫描限制与复用策略

本文说明 **Windows 微信 4.1.10 及更新版本**（实测覆盖 **Weixin 4.1.11.x**）上，`wxeasy init` 的密钥获取行为、为何「冷启动扫内存」常失败，以及如何用 **校验复用** 维持可用。

> 范围：Windows 客户端（进程名 `Weixin.exe`）。  
> macOS / Linux 的内存特征与权限路径不同，见 [macos-3x-vs-4x-decryption-guide.md](./macos-3x-vs-4x-decryption-guide.md) 与 [macos-permission-guide.md](./macos-permission-guide.md)。

---

## 一、结论速览

| 项目 | 4.1.9.x 及更早（典型） | 4.1.10+（实测 4.1.11） |
|------|------------------------|------------------------|
| 磁盘 SQLCipher 参数 | AES-256-CBC + HMAC-SHA512，page=4096，reserve=80 | **相同**（旧密钥仍可解密同一账号库） |
| 数据路径配置 | 绝对路径或可解析路径 | 常见令牌 `MyDocument:` / `MyDocuments:` / `Documents:` |
| 内存中 `x'<64hex_key><32hex_salt>'` | 常可扫描到 | **稳态几乎不存在** |
| 可读内存中 raw 32B / 常见编码变体 / AES 扩展表 | 常有机会 | **稳态实测 0 命中** |
| 登录/开库后短窗 hex 扫描 | 有机会 | **实测仍 0 有效密钥**（见 §五） |
| 推荐路径 | `wxeasy init` 内存扫描 | **扫描 + page1 校验复用 `all_keys.json`**；冷启动无旧钥时用 **Frida AES-NI 设钥 hook**（§八） |

**一句话：**

- **加密格式没换** → 升级前/本机已有密钥，校验通过后可继续用。  
- **被动内存提钥变难** → 不能依赖「冷启动、无旧密钥、只靠扫进程」在 4.1.10+ 上稳定成功。  
- **动态 hook 可突破** → 库被使用时 `aesni_set_encrypt_key(bits=256)` 仍暴露 32B raw key（`tools/frida_capture_keys.py`）。  
- **`~/.wxeasy/all_keys.json` 是生产资产** → 务必备份，勿泄露。

---

## 二、磁盘侧：仍然兼容

### 2.1 加密参数（与 wxeasy 解密器一致）

微信 4.x Windows 本地库仍为 SQLCipher 4 风格用法（raw key 直接作 AES key，不做再派生口令串）：

| 参数 | 值 |
|------|-----|
| page_size | 4096 |
| KDF / 口令串 | 不适用（32 字节 raw key 直接 AES） |
| 页内 IV | 页尾 reserve 区前 16 字节 |
| HMAC | SHA512，64 字节 |
| reserve | 80（16 IV + 64 HMAC） |
| 密文起点 | 跳过页首 16 字节 salt（仅 page1） |

### 2.2 page1 强校验（防误报）

解密后逻辑页偏移 16 起应出现固定元数据前缀（wxeasy 常量 `SQLITE_PAGE1_META_PREFIX`）：

```text
10 00 02 02 50 40 20 20
```

含义对应 SQLite 页头字段组合（page_size=4096、版本字段、reserved=80、嵌入 HMAC 长度等）。  
**仅检查「解密后像不像 SQLite 文件头」不够**：实现里 `decrypt_page` 会强制写入标准 SQLite header，弱校验会产生大量假阳性。

`init` 复用与 Windows 扫描器的「无 salt 候选」路径均走 `verify_enc_key_for_db`（page1 强校验）。

### 2.3 数据目录探测（4.1.10+ 路径修复）

微信配置里可能出现文档目录令牌，而不是完整绝对路径：

- `MyDocument:` / `MyDocuments:` / `Documents:`

wxeasy 会解析这些令牌，并在必要时扫描：

```text
%USERPROFILE%\Documents\xwechat_files\*\db_storage
%USERPROFILE%\文档\xwechat_files\*\db_storage
```

典型库路径形态：

```text
...\Documents\xwechat_files\<account_id>\db_storage\
  session\session.db
  contact\contact.db
  message\message_0.db
  ...
```

---

## 三、内存侧：4.1.10+ 发生了什么

### 3.1 经典扫描器假设

旧逻辑在微信进程可读内存中找：

```text
x'<64 位 hex 密钥><32 位 hex salt>'
```

用 DB 文件头 16 字节 salt 与后半段匹配，即可绑定「库 → 密钥」。

### 3.2 4.1.10+ 行为（工程结论）

模块与字符串侧仍可见 WCDB / SQLCipher 相关符号（如 `cipher_memory_security`、`hexkey`、`CipherConfig` 等，常见于 `roam_server.dll` 一带），但运行时表现为：

1. **稳态下**不再在可读页中长期保留 `x'…'` 或裸 raw key。  
2. 对**已知正确密钥**做全进程搜索：raw、hex、大小写、常见字节序/异或变体、AES-256 扩展密钥表片段 → **0 命中**。  
3. salt 仍可能出现在内存（映射/元数据），但 **邻域不是 key**。  
4. 退出微信 → 重新登录后的 **多轮短窗 hex 扫描**（数百～数千候选 + page1 校验）→ **仍 0 有效密钥**。

因此：把「冷启动 = 再扫一次内存」当作 4.1.10+ 的默认成功路径 **不成立**。

### 3.3 扫描器仍保留的能力（尽力而为）

Windows 扫描器（`src/scanner/windows.rs`）当前仍会：

- 枚举多个 `Weixin.exe` PID  
- 匹配 `x'…'`、连续 96-hex（key\|\|salt）、裸 64-hex  
- 对无可靠 salt 的候选做 **page1 强校验** 试钥  
- 支持多轮短窗环境变量（见 §六）

这些用于 **4.1.9 及特征仍暴露的环境**，以及未来若客户端回退/短暂泄露时的兼容；**不能**当作 4.1.11 冷启动保证。

---

## 四、`init` 复用策略（当前推荐生产路径）

### 4.1 流程

```text
wxeasy init [--force]
  ├─ 自动探测 db_dir
  ├─ 内存扫描（可能 0 命中）
  ├─ 若命中数 < 加密库数量：
  │    从本机候选 all_keys.json 读取 enc_key
  │    对每个尚未命中的库做 page1 强校验
  │    扫描结果优先，旧密钥只补缺
  └─ 写入 ~/.wxeasy/all_keys.json + config.json
```

扫描完全失败但复用成功时，日志类似：

```text
内存扫描命中 0/18，尝试复用本机已有密钥并校验...
校验旧密钥文件: C:\Users\<you>\.wxeasy\all_keys.json
校验复用后可用密钥: 18/18
初始化完成
```

### 4.2 候选密钥文件路径（按实现顺序尝试）

1. 当前 `config.json` 同目录下的 `all_keys.json`  
2. `cli_dir()` 下的 `all_keys.json`（通常即 `~/.wxeasy/all_keys.json`）  
3. 兼容改名前：`~/.wx-cli/all_keys.json`  
4. 再次：`~/.wxeasy/all_keys.json`

> **注意：** `~/.wxeasy` 与 `~/.wx-cli` **不自动共用 daemon 管道/缓存**；仅在 `init` 复用时会读旧目录里的密钥文件。身份改名后请以 `~/.wxeasy` 为准。

### 4.3 密钥是否会因「重启微信」失效？

在 **磁盘密钥未轮换** 的前提下（同一账号、同一套加密库 salt/密钥）：

- **不会**因为微信进程重启就失效。  
- 失效场景主要是：换账号、客户端重装并换了库、密钥被轮换、或 `all_keys.json` 丢失/损坏。  
- 4.1.10+ 上「重启后再 `init --force`」若扫描为 0，**依赖的是磁盘上已有密钥的校验复用**，不是重新从内存「领新钥」。

### 4.4 密钥文件格式

`~/.wxeasy/all_keys.json` 示例：

```json
{
  "session/session.db": { "enc_key": "<64 hex chars>" },
  "contact/contact.db": { "enc_key": "<64 hex chars>" },
  "message/message_0.db": { "enc_key": "<64 hex chars>" }
}
```

- `enc_key`：32 字节 AES raw key 的 hex（64 字符）  
- 敏感：等同于本地聊天库的解密能力，**勿提交 git、勿分享、建议备份到加密位置**

---

## 五、实测摘要（Weixin 4.1.11，供排障对照）

以下为工程侧在 **4.1.11.x** 上的代表性结果（账号库约 18 个加密 DB；仅作行为说明，非保证所有机器一致）：

| 实验 | 结果 |
|------|------|
| 旧 `all_keys` 解密磁盘库（page1 强校验） | **18/18 通过** |
| 稳态：已知 key 的 raw/hex/编码变体/扩展表 | **0** |
| 稳态：salt 邻域候选 + 强校验 | **0** |
| 退出 → 重登后 Python 短窗 hex 扫描（约 120s） | 候选数百，**有效 0/18** |
| 同窗口 `WXEASY_SCAN_ROUNDS=60` 的 `init --force` | 候选数千，扫描 **0/18**，复用 **18/18** |
| Frida hook `aesni_set_encrypt_key`（bits=256）+ page1 校验 | **可捕获正在使用的库密钥**（见 §八） |
| `wxeasy sessions`（复用后） | 正常 |

**冷启动定义（本文）：** 本机 **没有任何** 可通过 page1 校验的历史 `all_keys.json` / 等价密钥备份，仅依赖当前 4.1.10+ **被动内存扫描**。  
在该定义下，`wxeasy init` **内置扫描不保证成功**。动态 hook（§八）是另一条路径。

---

## 六、环境变量与操作建议

### 6.1 多轮扫描（尽力而为）

| 变量 | 默认 | 含义 |
|------|------|------|
| `WXEASY_SCAN_ROUNDS` | `1` | 内存扫描轮数 |
| `WXEASY_SCAN_INTERVAL_MS` | `400` | 轮间间隔（毫秒） |

PowerShell 示例（**不保证** 4.1.11 冷启动成功；有旧密钥时仍会走复用）：

```powershell
# 可选：先完全退出微信，再开扫，随后立刻登录
$env:WXEASY_SCAN_ROUNDS = "50"
$env:WXEASY_SCAN_INTERVAL_MS = "300"
wxeasy init --force
```

### 6.2 升级微信前的检查清单

1. **备份** `%USERPROFILE%\.wxeasy\all_keys.json` 与 `config.json`  
2. 若仍在用旧目录，同时备份 `%USERPROFILE%\.wx-cli\all_keys.json`  
3. 升级后运行 `wxeasy init --force`（管理员权限更利于 `OpenProcess`）  
4. 若日志显示扫描 0 命中但复用 N/N → **预期行为**，用 `wxeasy sessions` 验证  
5. 若复用也为 0 → 见 §七

### 6.3 日常使用

- 查询命令 **不需要** 微信正在运行（密钥与缓存在 `~/.wxeasy`；解密读的是磁盘库）。  
- 新消息依赖微信进程写入本地 DB；微信离线时只能看到已落盘数据。  
- daemon 在首次查询时自动拉起；`init --force` 后如密钥变更，必要时 `wxeasy daemon stop` 再查一次以重载。

---

## 七、失败时怎么排

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| 扫描 0，复用 18/18 | 4.1.10+ 正常 | 无需处理；备份 `all_keys.json` |
| 扫描 0，复用 0 | 无旧密钥 / 密钥与当前库不匹配 / 路径错 | 恢复备份密钥；确认 `db_dir` 指向当前账号 `db_storage` |
| 找不到数据目录 | 令牌路径 / 自定义文档目录 | 检查 `Documents\xwechat_files`；手动改 `config.json` 的 `db_dir` |
| `OpenProcess` 失败 | 权限不足 | 管理员 PowerShell 再 `init` |
| 仅部分库有密钥 | 新分片 / 新库 | 有旧全量密钥时复用应补齐；否则需曾成功扫描或备份含新库条目的 keys |
| 完全冷启动（无任何 keys） | 内存不再暴露 raw key | **当前不支持保证成功**；见 §八 |

---

## 八、4.1.10+ 动态提钥（Frida AES-NI 设钥 hook）

### 8.1 原理（2026-07 在 Weixin 4.1.11.24 验证）

| 观察 | 结论 |
|------|------|
| 稳态可读内存 | raw 32B / `x'…'` / AES 扩展表 **不驻留**（`cipher_memory_security` 一类行为） |
| BCrypt 设钥 | 基本无 DB 相关调用；密码学在 `Weixin.dll` 内静态 OpenSSL |
| 软件 AES_set_* 表 | 存在但 DB 路径几乎不走 |
| **AES-NI `aesni_set_encrypt_key`** | 某库被真正解锁/读写时，以 **bits=256** 调用，**RCX = 32 字节 raw DB key** |
| `roam_server.dll` 内同类符号 | 有独立实现；实测 DB 主路径多在 **Weixin.dll** |

因此：

- **被动扫内存** ≈ 失败（4.1.10+ 预期）
- **在 AES-256 设钥瞬间 hook** ≈ 可拿到正在使用的库密钥
- 捕获后仍用 **page1 强校验** 绑定到具体 `*.db`（与 `init` 复用同一套密码学）

调用链特征（示意）：DB 使用 → `aesni_set_decrypt_key` / `aesni_set_encrypt_key`（OpenSSL AES-NI）→ userKey 为 32B。

### 8.2 工具：`tools/frida_capture_keys.py`

```powershell
pip install frida==16.5.9 pycryptodome
# 微信已登录；建议管理员 PowerShell
python tools/frida_capture_keys.py --seconds 120 --merge
# 可选显式指定账号库目录
python tools/frida_capture_keys.py --db-dir "D:\wechat\xwechat_files\<id>\db_storage" --seconds 180 --merge
wxeasy init   # 合并后走校验复用写入 config
```

脚本行为：

1. 附加加载了 `Weixin.dll` 的 `Weixin.exe`
2. 在 `Weixin.dll` / `roam_server.dll` 内 **特征扫描** `aesni_set_encrypt_key` 序言（不写死单一版本 RVA）
3. 仅处理 `bits == 256` 的设钥，读取 32 字节 userKey
4. 对 `db_storage` 下加密库做 page1 强校验
5. `--merge` 时写入 `~/.wxeasy/all_keys.json`（`source: frida_aesni_set_key`）

**覆盖率提示：** 只有「捕获窗口内被触达」的库会出钥。请在运行期间切换会话、打开联系人/朋友圈/收藏/搜索等；重新登录通常能一次拉起更多库。未触达的库会留在输出的 `missing` 列表中，可加长 `--seconds` 再跑或与已有 `all_keys.json` 合并。

### 8.3 仍不在保证范围内的事

1. **`wxeasy init` 内置被动内存扫描**在 4.1.10+ 冷启动成功（无 hook、无历史 keys）。  
2. 未授权访问他人微信数据。  
3. 绕过账号登录态「远程偷钥」。  
4. 依赖已下架第三方闭源提钥工具作为唯一备份链。  
5. Frida 脚本在 **所有** 微信小版本上的 RVA/特征 100% 命中（特征扫描会尽量自适应，大改版仍可能要更新）。

**务实策略：**

- 优先保管已校验的 `all_keys.json`（密钥未轮换则长期有效）；  
- 冷启动 / 丢钥：用 §8.2 动态捕获补齐，再 `wxeasy init`；  
- 升级微信前备份 `~/.wxeasy/`。

---

## 九、与代码的对应关系

| 能力 | 位置 |
|------|------|
| Windows 多 PID / 多模式扫描 / 多轮 / page1 试钥 | `src/scanner/windows.rs` |
| page1 强校验 | `src/crypto/mod.rs`（`verify_enc_key_for_db`、`SQLITE_PAGE1_META_PREFIX`） |
| 扫描失败后的校验复用 | `src/cli/init.rs`（`reuse_verified_keys`） |
| `MyDocument:` 等路径与 `xwechat_files` 回退扫描 | `src/config.rs` |
| 配置与密钥目录 | `~/.wxeasy/`（`config.json`、`all_keys.json`） |
| 4.1.10+ Frida AES-NI 动态提钥（可选） | `tools/frida_capture_keys.py` |

---

## 十、相关文档

- [README — 快速开始 / 原理](../README.md)  
- [macOS 3.x vs 4.x 解密指南](./macos-3x-vs-4x-decryption-guide.md)  
- [macOS 权限与签名指南](./macos-permission-guide.md)  
