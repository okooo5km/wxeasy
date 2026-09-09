## 中文

- **macOS 下载恢复**：提供 Apple Silicon 和 Intel 版本，可与 Windows 版本使用相同的查询命令。
- **Apple Silicon 新增提钥方式**：内存扫描找不到密钥时，可用 `wxeasy init --live` 附加微信，或用 `wxeasy init --relaunch` 重启微信并在登录时获取密钥。
- **初始化指引更新**：Skill 和安装说明已区分各平台的能力、权限要求和密钥补齐方式。Windows 继续使用现有硬件断点提钥方案。

macOS 实时提钥需要 LLDB 与可用的系统调试权限，目前仅支持 Apple Silicon；真实微信进程的端到端提钥仍待实机验收。Intel 保留稳态扫描与历史密钥复用。程序不会自动修改 SIP、微信签名或 TCC。Linux 当前仅支持源码构建，npm 包暂不发布，请使用本页二进制。

## English

- **macOS downloads are back**: Apple Silicon and Intel binaries are available alongside Windows, with the same query commands.
- **New key capture option on Apple Silicon**: If memory scanning finds no keys, use `wxeasy init --live` to attach to WeChat, or `wxeasy init --relaunch` to restart WeChat and capture keys during login.
- **Updated setup guidance**: The Skill and installation guide now distinguish platform capabilities, permissions, and missing-key recovery. Windows retains its existing hardware-breakpoint capture method.

Live capture on macOS requires LLDB and working system debugging permissions and currently supports Apple Silicon only. End-to-end capture against a real WeChat process still needs device validation. Intel retains memory scanning and verified saved-key reuse. The tool does not automatically change SIP, WeChat signing, or TCC. Linux currently requires a source build; npm packages are not being published. Use the binaries attached to this release.
