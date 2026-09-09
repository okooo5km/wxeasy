---
name: wxeasy
description: "wxeasy — 从本地微信数据库查询聊天记录、联系人、会话、收藏等。用户提到微信聊天记录、联系人、消息历史、群成员、收藏内容时，使用此 skill 安装并调用 wxeasy。"
---

# wxeasy

## Triggers

- 查微信聊天记录
- 微信消息历史
- 微信联系人
- 微信群成员
- 微信群昵称 / 群名片
- 微信收藏
- wechat history / messages / contacts
- wxeasy
- 帮我看看微信里
- 搜索微信消息

## 平台与安装

本 Skill 对应 **wxeasy v0.4.0**。macOS LLDB 提钥需要 v0.4.0 或更高版本。

优先使用 wxeasy，避免混用 pandorafuture 的 wx-cli 命令和配置格式。v0.4.0 提供 Windows x86_64、macOS ARM／Intel Release 二进制；Linux 保留源码兼容性检查。npm 发布已停用，不推荐 npm 安装旧包。

- Windows：从 GitHub Release 下载 `wxeasy-windows-x86_64.exe`，或运行仓库 `install.ps1`。
- macOS：从包含对应产物的 Release 下载 `wxeasy-macos-arm64`／`wxeasy-macos-x86_64`；`install.sh` 使用同名资源。
- 从 [v0.4.0 Release](https://github.com/okooo5km/wxeasy/releases/tag/v0.4.0) 下载对应平台文件；Linux 使用 `cargo build --release --locked`。历史 Windows-only Release 不会补发 Mac 文件。
- 用 `wxeasy --version` 和 `wxeasy init --help` 确认实际安装版本。

## 初始化与补齐密钥

先确保微信桌面版已安装、数据目录已建立。普通查询无需提权。

```bash
wxeasy init
wxeasy init --force
```

初始化保留稳态扫描和本机历史密钥校验复用。已有密钥重启微信后通常仍有效；不要因为重启就删除配置。数据库出现新分片时重新初始化，再重启 daemon。

### Windows

管理员 PowerShell 中运行 `wxeasy init`。新版稳态扫描零命中时会自动尝试现有硬件断点方案；这不等于完全不支持新版。

```powershell
wxeasy init --live
wxeasy init --relaunch
```

`--live` 附加已运行微信，需打开缺失会话触发开库；`--relaunch` 会重启微信，登录过程中抓取。现有仓库记录验证过微信 4.1.11.24，不保证未来所有版本。见 [Windows 实现记录](docs/wechat-4.1.11-key-extraction-rust.md)。

### macOS

- 旧版稳态扫描通常需要 `sudo wxeasy init` 及可用的调试权限。
- Apple Silicon 新增 LLDB 抓取路径；需要 Xcode Command Line Tools 提供 LLDB 和 Python。建议从当前登录用户的终端运行。
- `wxeasy init --live` 附加微信，最长约 120 秒；`wxeasy init --relaunch` 会重启微信并捕获登录时的 PBKDF2 调用。
- Intel 二进制可构建，但新版 LLDB 抓取尚不支持；继续使用稳态扫描或历史密钥。
- 上游声明支持微信 4.1.7+ ARM；这是上游范围，不代表 wxeasy 集成已经完成真实微信全版本实测。
- 调试失败时检查 SIP、开发者工具授权、LLDB 和微信安装路径。上游说明 SIP 关闭是其提钥前提；不要保证 sudo 或重签名可以绕过 SIP。
- 不自动关闭 SIP、重签名微信、重置 TCC 或重启微信。只有用户明确选择重启抓取时才执行 `--relaunch`。签名和系统权限由用户自行决定，不把全量 TCC reset 当默认初始化步骤。

原始 PBKDF2 输入与 `all_keys.json` 的派生 AES `enc_key` 不可互换，禁止直接复制上游原始 key 到该字段。候选密钥不展示、不写调试日志。完整原理、许可和验证边界见 [上游分析](doc/pandorafuture-wx-cli-analysis.md)。

## Linux

可从源码构建并尝试 `sudo wxeasy init`。当前没有 Linux 发布产物，也没有实时断点提钥实现。

---

## 命令速查

所有命令默认输出 YAML，更省 token & 易读；`--json` 可切换为 JSON（方便 `jq` 处理等）。

### 会话与消息

```bash
# 最近 20 个会话
wxeasy sessions

# 有未读消息的会话
wxeasy unread

# 只看真人（私聊 + 群聊）的未读，过滤公众号与折叠入口
wxeasy unread --filter private,group

# 上次检查后的新消息（增量）
wxeasy new-messages
wxeasy new-messages --json          # JSON 输出，适合 agent 解析

# 聊天记录（支持昵称/备注名）
wxeasy history "张三"
wxeasy history "张三" -n 2000
wxeasy history "AI群" --since 2026-04-01 --until 2026-04-15 -n 100

# 全库搜索
wxeasy search "关键词"
wxeasy search "关键词" -n 500
wxeasy search "会议" --in "工作群" --since 2026-01-01
```

`history` / `search` / `export` 都支持 `-n` / `--limit` 指定返回条数。默认值只是为了避免一次输出过多，不是硬上限。

`sessions` / `unread` / `history` / `new-messages` / `stats` 的输出都带 `chat_type` 字段，agent 可据此分流：

| 取值 | 含义 | username 特征 |
|------|------|--------------|
| `private` | 真人私聊 | `wxid_*` 或自定义短号 |
| `group` | 群聊 | `*@chatroom` |
| `official_account` | 公众号 / 订阅号 / 服务号 / 系统通知 | `gh_*`、`biz_*`、`mphelper`、`qqsafe`、`@opencustomerservicemsg` |
| `folded` | 折叠入口（订阅号折叠、折叠群聊的聚合条目） | `brandsessionholder`、`@placeholder_foldgroup` |

`wxeasy unread --filter` 支持 `private` / `group` / `official` / `folded` / `all`，逗号分隔多选。默认 `all`。

群聊消息里的 `last_sender`、`sender` 和 `stats.top_senders` 会优先显示群昵称（群名片）。如果本地数据库没有群昵称，再回退到联系人备注、微信昵称或 username。

`sessions` / `unread` / `history` / `search` / `new-messages` / `stats` / `attachments` 的 stdout 现在统一是 wrapper：

```json
{
  "messages": [...],
  "meta": {
    "status": "ok",
    "unknown_shards": [],
    "chat_latest_timestamp": 1715750400,
    "chat_latest_db": "message/message_2.db",
    "session_last_timestamp": 1715760000
  }
}
```

其中：

- `status = possibly_stale_unknown_shards`：磁盘上出现 daemon 不认识的新 `message_N.db`，先跑 `wxeasy init --force`
- `status = possibly_stale`：`session.db` 记录的最新时间明显领先于本次查到的最新消息，结果可能漏消息
- `status = windowed`：这次查询本来就是窗口化/过滤后的局部视图，不应把它当作"全量最新状态"
- `--with-meta`：额外返回 `per_shard_latest` / `cache_mode_per_shard`
- `--debug-source`：在 `--with-meta` 基础上再暴露真实 `shard_paths`

引用消息（appmsg `type=57`）在 `history` / `search` / `new-messages` 输出里会展开为两行：第一行是当前回复，第二行以 `↳` 开头显示被引用原文，例如：

```text
[引用] 当前回复
  ↳ 发送者: 被引用内容
```

`--type link` / `--type file` 会覆盖微信 appmsg 的链接、文件、合并聊天记录和引用消息等变体；`search --type link` 也会匹配解压并格式化后的引用原文。

### 联系人与群组

```bash
# 联系人列表 / 搜索（仅真人，不含群和公众号）
wxeasy contacts
wxeasy contacts --query "李"

# 群聊列表 / 搜索
wxeasy groups
wxeasy groups --query "AI"

# 群成员列表
wxeasy members "AI交流群"
```

`wxeasy groups --json` 每个群包含 `username`、`display` 与 `member_count`；`member_count` 依赖本地 contact.db 的 `chatroom_member` 表，老版本微信缺该表时字段省略（列表本身不受影响）。

`wxeasy members --json` 每个成员包含：

- `username`：微信内部 username
- `display`：推荐展示名，优先使用群昵称
- `contact_display`：联系人备注或微信昵称
- `group_nickname`：群昵称；没有记录时为空字符串
- `is_owner`：是否群主

Agent 展示群成员时优先用 `display`。需要区分群昵称和联系人名时，再读取 `group_nickname` 与 `contact_display`。

### 朋友圈（SNS）

三个命令，作用各不同：

```bash
# 1) 互动通知（点赞 / 评论，默认仅未读）
wxeasy sns-notifications
wxeasy sns-notifications --include-read --since 2026-04-01 -n 100

# 2) 时间线：浏览本地缓存的朋友圈帖子
wxeasy sns-feed                                    # 近 20 条
wxeasy sns-feed --user "张三"                      # 只看某人
wxeasy sns-feed --since 2026-04-01 --until 2026-04-18 -n 100

# 3) 全文搜索：在正文里找关键词
wxeasy sns-search "关键词"
wxeasy sns-search "婚礼" --user "李四" --since 2023-01-01 -n 50
```

**字段区分**：

- `sns-notifications` 返回"通知"条目：`type`（`like`/`comment`）、`from_nickname`、`content`（评论正文，点赞为空）、`feed_preview` + `feed_author`（对应的原帖）
- `sns-feed` / `sns-search` 返回"帖子"条目：`author`、`content`（朋友圈正文）、`media`、`media_count`（图片/视频数）、`location`、`timestamp`；`media` 字段含每张图的 url/thumb/key/token/md5/enc_idx/size，供下游做图片代理或离线渲染。`media_count = media.len()`，按 DOM 解析的合法 `<media>` 子节点计数（malformed XML 返回 0）

> 只保存你本地刷到过的朋友圈（微信 app 按需下载）。没刷到过的帖子不在本地，任何命令都拿不到。

### 公众号文章

公众号的文章推送存在独立的 `biz_message_0.db`，与普通 `message_0.db` 分开：

```bash
# 最近 50 篇（默认）
wxeasy biz-articles

# 更多
wxeasy biz-articles -n 200

# 限定公众号（名称模糊匹配 display name / username）
wxeasy biz-articles --account "返朴"

# 时间范围（YYYY-MM-DD，发布时间，非接收时间）
wxeasy biz-articles --since 2026-05-01 --until 2026-05-10

# 仅有未读消息的公众号，每号取最新 1 篇（适合"今天有什么新推送"扫描）
wxeasy biz-articles --unread
wxeasy biz-articles --unread --account "Datawhale"   # 与 --account 取交集

# 下游消费：拿 URL 做内容抓取
wxeasy biz-articles --since 2026-05-10 --json | jq '.[].url'
```

每条返回的字段：`account` / `account_username`（`gh_*`）/ `title` / `url`（`mp.weixin.qq.com` 链接）/ `digest` / `cover_url` / `time` + `timestamp`（文章发布时间）/ `recv_time_str` + `recv_time`（微信接收推送的时间）。多图文推送会展开为多行。

### 附件提取（图片）

聊天里的图片本体在 `xwechat_files/<wxid>/msg/attach/...` 下加密存储（`.dat`），需要按消息所在 `message_resource.db` 的 md5 + 平台相关 image key 才能解码。两步走：

```bash
# 1) 先列出图片附件，拿到不透明的 attachment_id
wxeasy attachments "张三"
wxeasy attachments "AI群" --kind image -n 100
wxeasy attachments "AI群" --since 2026-04-01 --until 2026-04-15

# 2) 用 attachment_id 把单个资源解密写到指定路径
wxeasy extract <attachment_id> -o ~/Desktop/photo.jpg
wxeasy extract <attachment_id> -o /tmp/x.jpg --overwrite
```

`attachments` 输出每条带：`attachment_id` / `kind`（当前固定 `image`）/ `type` / `local_id` / `timestamp` / `time`，群聊里另带 `sender`。命令名保留成 `attachments` 是为了后续扩到其他附件类型时不 break CLI。

`extract` 报告里带：`md5` / `dat_path` / `dat_size` / `output` / `output_size` / `format`（实际识别出的图片格式：jpg / png / gif / webp / hevc 等）/ `decoder`（实际选用的解码器：`legacy_xor` / `v1_aes` / `v2`）。

支持的解码档位：
- **legacy XOR**：早期单字节 XOR，无 magic（按文件首字节探测格式自动反推）
- **V1 fixed-AES**（`07 08 V1 08 07`）：AES-128-ECB + 固定 key `cfcd208495d565ef`
- **V2 AES + XOR**（`07 08 V2 08 07`）：AES-128-ECB + raw + XOR；AES key 平台派生

V2 image key 提取（macOS / Windows 自动；Linux 暂不支持）：
- macOS：`kvcomm` cache（`key_<uin>_*.statistic` 文件名取 uin → `md5(str(uin) + wxid)[:16]`）+ brute-force fallback；`xor_key = uin & 0xff`
- Windows：扫 `Weixin.exe` 内存匹配 `[A-Za-z0-9]{32|16}` 候选，按 V2 template ciphertext-block 反验

### 收藏与统计

```bash
# 全部收藏
wxeasy favorites

# 按类型筛选：text / image / article / card / video
wxeasy favorites --type image

# 搜索收藏内容
wxeasy favorites --query "关键词"

# 聊天统计（发言人、消息类型、活跃时段）
wxeasy stats "AI群"
wxeasy stats "AI群" --since 2026-01-01
```

### 导出

```bash
# 导出为 Markdown（默认）
wxeasy export "张三" --format markdown -o chat.md
wxeasy export "张三" -n 2000 --format markdown -o chat.md

# 导出为 JSON
wxeasy export "AI群" --since 2026-01-01 --format json -o chat.json
```

### Daemon 管理

```bash
wxeasy daemon status
wxeasy daemon stop
wxeasy daemon logs --follow
```

---

## Agent 使用建议

查询结果需要程序处理时，统一加 `--json`：

```bash
wxeasy sessions --json
wxeasy new-messages --json
wxeasy search "关键词" --json | jq '.results[0]'
wxeasy history "张三" --json -n 50 | jq '.messages[0]'
wxeasy history "张三" --json | jq '.meta'
wxeasy history "张三" --json --with-meta | jq '.meta.cache_mode_per_shard'
```

CHAT 参数支持昵称、备注名、微信 ID，模糊匹配。不确定准确名称时，先用 `wxeasy contacts --query` 搜索。

---

## 数据文件位置

```
~/.wxeasy/
├── config.json       # 配置
├── all_keys.json     # 数据库密钥（敏感，勿分享）
├── daemon.sock       # Unix socket
├── daemon.pid / .log
└── cache/            # 解密后的数据库缓存
```

---

## 常见问题

**微信重启后是否要重新 init？**  
- 磁盘密钥未轮换时，**已保存的 `all_keys.json` 通常仍然有效**，不必因重启而重扫。  
- 若查询失败、换了账号/数据目录、或新增多分片库：再跑 `wxeasy init --force`（macOS/Linux 常用 `sudo`；Windows 建议管理员）。  
- **Windows 4.1.10+**：稳态扫描常为零；初始化会尝试历史复用和硬件断点抓取，必要时显式使用 `--relaunch`。

**daemon 无响应**：`wxeasy daemon stop` 后重新调用任意命令自动重启。`init --force` 更新密钥后若结果仍旧，先 stop daemon 再查。

**找不到聊天**：用 `wxeasy contacts --query` 确认昵称/备注名，或用微信 ID 直接查询。

**为什么只能获取 500 条消息？**：这是默认输出条数，不是硬限制。显式传 `-n` 即可，例如 `wxeasy history "张三" -n 2000` 或 `wxeasy export "张三" -n 2000 -o chat.md`。

**Windows 升级微信后 init 扫描 0 命中**：可能是新版内存密钥保护；检查历史复用和实时断点抓取日志，必要时显式运行 `wxeasy init --relaunch`。文档：[docs/windows-4.1.10-keys-and-reuse.md](docs/windows-4.1.10-keys-and-reuse.md)。
