## 中文

- **按微信版本选择提钥方式**：`wxeasy init` 会读取本机微信版本。4.1.9 及更早使用原来的内存扫描；4.1.10 及以上默认只复用已有密钥，不再自动走 live-hook。
- **新增 `wxeasy wechat-version`**：自动显示微信版本、该用哪条路径，以及下一步命令。Agent 应先运行此命令，再把结果告诉用户。
- **高版本不再默认提钥**：4.1.10+ 客户端可能监测数据库解密。密钥已齐时继续复用即可；只有缺钥且用户明确要求时，才使用 `--live` / `--relaunch`。

Linux 当前仅支持源码构建，npm 包暂不发布，请使用本页二进制。

## English

- **Key setup follows the WeChat version**: `wxeasy init` reads the local WeChat version. 4.1.9 and earlier use the original memory scan; 4.1.10 and later reuse saved keys by default and no longer auto-switch to live-hook.
- **New `wxeasy wechat-version` command**: Prints the WeChat version, the matching setup path, and the next command. Agents should run this first and tell the user the result.
- **Newer WeChat no longer extracts keys by default**: 4.1.10+ clients may monitor database decryption. If keys already exist, keep reusing them. Use `--live` / `--relaunch` only when keys are missing and the user explicitly asks.

Linux currently requires a source build; npm packages are not being published. Use the binaries attached to this release.
