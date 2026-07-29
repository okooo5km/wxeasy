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

自 v0.3.3 起只构建并发布 **Windows** 版本（`release.yml`）：

```
build job（windows-latest）
  ├── cargo build --release --locked --target x86_64-pc-windows-msvc
  ├── 打包 wxeasy-windows-x86_64.exe → upload-artifact
  └── 打 tag 时上传到 GitHub Release（softprops/action-gh-release）
```

- 触发：push main（仅构建验证，不发布）/ push tag `v*`（构建 + 发布）/ workflow_dispatch。
- 已停用：mac/Linux 构建、独立 check job、整套 npm 发布（`publish-npm`）。
- 注意：源码仍保留 macOS/Linux 的 `#[cfg]` 分支，本地改动仍按上面「平台兼容性检查清单」做跨平台 `cargo check`；CI 不再产出非 Windows 二进制。
- **坑：workflow 可能处于 `disabled_manually` 状态**——此时 push/tag 都不触发任何 run（表现为「推了没反应」）。先 `gh workflow list --all` 看状态，禁用了就 `gh workflow enable Release` 重新启用，再用 `gh workflow run Release --ref main` 手动补跑。
- action 运行时须为 **node24**（GitHub 已弃用 node20，否则 Actions 报警告）：当前锁 `checkout@v5`、`cache@v5`、`upload-artifact@v7`、`softprops/action-gh-release@v3`。反直觉点：`upload-artifact@v5` 仍是 node20，必须用 v7；升版本前先 `gh api repos/<owner>/<action>/contents/action.yml?ref=<tag> --jq .content | base64 -d | grep using:` 逐个核实运行时。
