//! Windows live-hook 提钥（微信 4.1.10+）。
//!
//! 旧的「稳态扫内存找 `x'<key><salt>'`」在 4.1.10+ 因 `cipher_memory_security`
//! 用完即擦而失效；本模块改用**调试器 + 硬件断点**，在设钥函数（AES-NI 密钥扩展）
//! 入口截获开库瞬间的 raw key，纯 Rust + Win32 API，不依赖 Frida / 注入 DLL。
//!
//! - [`locate`]：解析磁盘 Weixin.dll，按 aeskeygenassist 特征 + `.pdata` 边界定位设钥函数；
//! - [`hwbp`]：DR 寄存器铺设执行断点、命中判定、置 RF 越过；
//! - [`debugger`]：调试事件循环、附加/带起/分离、命中收集与 page1 校验。
//!
//! 署名：okooo5km(十里)

mod debugger;
mod hwbp;
mod locate;

pub use debugger::run_capture;
