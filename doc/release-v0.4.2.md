## 中文

- **`extract` 优先取高清原图**：同一张图有高清（`_h.dat`）、中尺寸（`.dat`，常为 HEVC）、缩略图（`_t.dat`）三档。此前优先取中尺寸，拿到的不是原图；现在按高清 > 中尺寸 > 缩略图选择，`dat_path` 会指向 `_h.dat`，输出原格式、原尺寸。高清版本需要在微信里点开或下载过才会存在。
- 升级后先运行 `wxeasy daemon stop`，让 daemon 用新版本重启。

Linux 当前仅支持源码构建，npm 包暂不发布，请使用本页二进制。

## English

- **`extract` now prefers the full-resolution original**: WeChat stores up to three versions of an image: HD (`_h.dat`), medium (`.dat`, often HEVC) and thumbnail (`_t.dat`). Previously the medium version won, so the output was not the original. The order is now HD > medium > thumbnail; `dat_path` points to `_h.dat` and the output keeps the original format and size. The HD version exists only after the image was opened or downloaded in WeChat.
- After upgrading, run `wxeasy daemon stop` so the daemon restarts on the new version.

Linux currently requires a source build; npm packages are not being published. Use the binaries attached to this release.
