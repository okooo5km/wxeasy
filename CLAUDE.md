# wxeasy Project Rules

## After Every Code Change

**Rust 代码改动后，必须立刻运行：**

```bash
cargo check
```

不允许在 `cargo check` 通过之前提交或推送。

**改动涉及跨平台代码（`#[cfg(...)]` / `Cargo.toml` dependencies）时，额外运行：**

```bash
cargo check --target x86_64-unknown-linux-gnu
cargo check --target x86_64-pc-windows-gnu   # 在 macOS 上用这个，msvc 需要 MSVC 工具链
```

macOS 上需要一次性安装 target 和交叉编译器：

```bash
rustup target add x86_64-pc-windows-gnu
brew install mingw-w64   # 提供 x86_64-w64-mingw32-gcc，zstd-sys 等 C 依赖需要
```

这两条 check 命令用于提前暴露 Linux/Windows 特有的编译错误，**只做类型检查**（不 link）。

## IPC / 跨平台同库约定

动任何 IPC / 网络代码时：**两端必须用同一个库、同一套 API**。例如 server 用 `interprocess::local_socket::tokio::Listener`，client 就必须用 `interprocess::local_socket::Stream::connect`，不能用 `std::fs::OpenOptions` 打开同名路径——即使 kernel 名字对上了，底层的 framing / overlapped 模式也不兼容。

## Cargo.toml 修改规则

- 修改版本号后，必须运行 `cargo update --workspace` 更新 Cargo.lock
- 添加/移动 `[target.'cfg(...)'.dependencies]` section 时，确认后续依赖没有被意外归入该 section（TOML section 持续到下一个 header）
- 改完后运行 `cargo check` 验证

## Git 规则

- 每次 commit 后必须 push（`git push wxeasy main`）
- 打 tag 前确认 `cargo check` 和 `cargo update --workspace` 都已完成
- remote 使用 `wxeasy`（SSH），不用 `origin`

## 平台兼容性检查清单

改动以下内容时必须做跨平台 check：

- [ ] `libc::` 调用 → 确认函数在 Linux 和 macOS 都存在（`__error` 是 macOS 专属，用 `std::io::Error::last_os_error()` 代替）
- [ ] `#[cfg(unix)]` 块 → unix 包括 macOS 和 Linux，不能用 macOS 专属 API
- [ ] `Cargo.toml` dependency section 顺序 → 检查是否有 dep 意外落入 target section
- [ ] Windows named pipe 代码 → 确认函数都已定义，trait import 齐全

## CI 结构

Release workflow 构建 Windows x86_64、macOS Apple Silicon 和 macOS Intel，分别在原生 runner 上运行 cargo check、cargo test 和 release build。Linux 只运行兼容性 check，不发布二进制。npm 发布仍未恢复。

- main push／workflow_dispatch：构建验证；v* tag：上传同名二进制与第三方许可。
- macOS 产物名保持 install.sh 的约定：wxeasy-macos-arm64、wxeasy-macos-x86_64。
- macOS ARM 新增显式 init --live／--relaunch，使用系统 LLDB；Intel 仅保留稳态扫描和历史密钥复用。
- LLDB 捕获的是 PBKDF2 原始输入，必须按每个数据库的 salt 派生并校验 page1 HMAC，再写入 all_keys.json 的 enc_key。严禁把原始输入当 AES key。
- 不自动重签名、修改 SIP／TCC，不把候选密钥打印到日志。只有显式 --relaunch 才重启微信。
- 修改捕获协议后运行 python -m unittest discover -s tests -p 'test_macos_capture.py' 和 cargo test scanner::macos_live。
- 上游比较基线与限制见 [分析记录](doc/pandorafuture-wx-cli-analysis.md)，新增文档统一放 doc/。
- workflow 禁用时用 gh workflow list --all 诊断，不以没有 run 作为成功证据。
