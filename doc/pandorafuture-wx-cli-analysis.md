# pandorafuture/wx-cli 平台适配分析

分析日期：2026-09-09。上游基线：`2abe708f55bfe135539a385df856fdc58f97fc74`。本仓库起点：`2d0e57f`。

## 结论

保留 Windows 现有硬件断点实现，复用上游的 CommonCrypto 捕获思路，为 macOS ARM 接入显式 LLDB 提钥。恢复 ARM 与 Intel 的原生构建，但 Intel 不声明具备新版实时提钥能力。两条路径最终都转换成 wxeasy 已有的逐库 `enc_key`，查询、WAL、VFS 和 IPC 不换实现。

这不是把上游整个 workspace 搬过来。它的账户级原始密钥、REST 服务、CLI、路径和我们不同，直接整仓替换会破坏 Windows 功能与现有命令契约。

## 一、所谓“支持新版本”实际是什么

上游 README 声明 macOS Apple Silicon、微信 4.1.7 及以上；提交 `6c7fdda` 放宽了版本接受规则。声明的版本范围不能视为每个版本均已测试，更不构成 Windows 支持证据。[上游 README](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/README.md)、[版本规则提交](https://github.com/pandorafuture/wx-cli/commit/6c7fdda)

关键变化是绕开“等微信登录后再从稳态内存找密钥”的时间限制：在 PBKDF2 正在使用原始输入时捕获它。上游 `lldb.rs` 会停止微信，以 LLDB 等待附加，再打开微信；解析密码和 salt，匹配账户后进行 HMAC 校验。它仍保留另一条 Mach VM 扫描派生密钥的路径，不能混淆两种密钥材料。[LLDB 流程](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-keychain/src/lldb.rs)、[密钥类型](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-decrypt/src/key_material.rs)

上游没有给出 Windows 的新函数定位、PE 特征或寄存器实证。本次没有用 README 的版本号替代二进制层面的验证。

## 二、捕获点、调用约定与 Windows 迁移判断

上游断点设置在 `CCKeyDerivationPBKDF`。ARM64 的 `x1/x2` 是 password 指针／长度，`x3/x4` 是 salt 指针／长度，`x5/x6` 是 PRF／轮数。其脚本只读 ARM 寄存器，因此 Intel 构建也不能直接使用同一脚本。[捕获脚本](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-keychain/src/script.rs)

Windows 没有可直接照搬的 CommonCrypto API 入口。我们已有的 `windows_live/locate.rs` 扫描 `Weixin.dll` 的 `aeskeygenassist` 特征，借助 PE `.pdata` 找函数边界；`debugger.rs` 通过 Win32 调试事件与硬件断点截获 AES 设钥输入，再逐库验证。现有工程记录验证过 4.1.11.24。学习的共同原则是“在用钥瞬间捕获、用真实数据库验证”，平台机制不应强行统一。[本仓库实现记录](../docs/wechat-4.1.11-key-extraction-rust.md)

所以，本次不新增未经 Windows 二进制验证的 PBKDF2 hook，也不替换已经具有版本特征定位的 AES-NI 路径。未来如果上游提供 Windows 实证，或我们的特征定位在新版本失效，再评估新的捕获点。

## 三、必须转换密钥，不能复制字段

上游 LLDB 返回的 32 字节是 PBKDF2 原始输入。wxeasy 的 `all_keys.json` 中 `enc_key` 则是 AES-256 的派生密钥。尽管都可以表示为 64 个 hex 字符，两者不能互换。

转换参数为 PBKDF2-HMAC-SHA512、256000 轮、每个数据库自己的 16 字节 salt、32 字节输出。HMAC key 用派生 AES key 和 `salt XOR 0x3a` 再做两轮 PBKDF2。page1 HMAC 覆盖 salt 后的密文和 IV，再附加小端页码 1，和页尾 64 字节比较。[KDF 实现](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-decrypt/src/kdf.rs)、[参数](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-decrypt/src/params.rs)、[首个页校验](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/crates/wx-decrypt/src/db.rs)

本次适配会对所选账户的每个缺失数据库分别派生和验证，拒绝损坏页和无关调用。不假定所有数据库共享同一 salt，也不因一个库验证通过就把同一个 AES key 复制给全部库。已覆盖的库保持现有结果。

## 四、集成与上游的差异

新增 `src/scanner/macos_live.rs` 和嵌入式 `macos_capture.py`，沿用 `init --live`／`--relaunch`。普通 macOS `init` 保留稳态扫描、历史复用，不自动重启微信。Windows 默认自动补齐逻辑不变。

Python callback 在读取内存之前限定 PBKDF2、SHA512、256000 轮、32 字节输入和 16 字节 salt；只输出去重且有数量上限的候选。候选通过匿名 stdout 管道交给 Rust，既不转发终端，也不保存上游那样的密码调试日志。临时脚本放在独占的 0700 目录，退出后移除。

抓取循环最长 120 秒，Rust 子进程看门狗上限 140 秒。正常退出、超时和脚本异常都尝试停止进程、清除断点、分离调试器。若 LLDB 本身卡死而触发外层强制结束，需要检查微信是否恢复运行；不能把“杀掉调试器”当成分离成功。API 行为依据 [LLDB SBTarget](https://lldb.llvm.org/python_api/lldb.SBTarget.html) 与 [SBProcess](https://lldb.llvm.org/python_api/lldb.SBProcess.html)。

`--relaunch` 在设置符号断点后直接由 LLDB 启动标准路径的微信可执行文件，保证登录前就设好断点。当前限定 `/Applications/WeChat.app/Contents/MacOS/WeChat` 和原生 ARM；自定义安装路径、Rosetta 和多进程附加不宣称支持。

## 五、权限与许可

上游明确写了关闭 SIP 是其密钥提取前提，并列出开发者工具授权与 LLDB／Python 依赖。是否能附加仍取决于设备权限和应用签名。wxeasy 不自动关闭 SIP、不自动重签名、不批量清理 TCC；这些不是普通查询的前置操作。[上游前置条件](https://github.com/pandorafuture/wx-cli/blob/2abe708f55bfe135539a385df856fdc58f97fc74/README.md)

上游采用 MIT，与本项目 Apache-2.0 下的集成兼容。保留完整的上游版权和许可于 [pandorafuture-MIT.txt](pandorafuture-MIT.txt)，Release 随附该许可。复用范围是捕获寄存器的思路／脚本与派生算法，不使用上游命令名称或密钥存储格式。

## 六、验证边界

验证分三层：Windows 本机 Rust 检查与单元测试；Python 模拟测试验证过滤、去重、短读和分离；原生 macOS／Windows CI 检查、测试、构建，Linux 执行兼容性检查。

本次没有在真实 macOS 微信进程上提取密钥，也没有修改 Boss 的微信进程或系统权限。即便 CI 全通过，仍需要真实 Apple Silicon 设备验收：旧密钥缺失时执行 `init --relaunch`，确认账户选对、逐库通过 HMAC、查询结果正确、微信继续运行，之后验证重新启动查询和增量补齐。Intel 仅验证构建和旧路径，不标为新版 LLDB 支持。

最新执行结果见本任务最终交付说明；不要把本文件的验证方案误读成所有步骤已经完成。

## 七、持续跟进

已创建 Codex 每周一上午十点的上游检查，仅有值得迁移的变化才通知。每次比较以本文件的 commit 为起点，关注捕获入口、ABI、KDF 参数、微信版本实证、权限要求、候选校验及许可。记录观察到的新 commit 与可迁移判断，不因无关 UI／REST 功能更新自动改本仓库。

可复核命令：

```bash
git ls-remote https://github.com/pandorafuture/wx-cli.git refs/heads/main
git log 2abe708f55bfe135539a385df856fdc58f97fc74..HEAD -- crates/wx-keychain crates/wx-decrypt
```

第二条需在上游 checkout 中 fetch 后运行。定时监控不授权自动重启微信、改变系统权限或发布版本。
