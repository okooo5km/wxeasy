mod attachment;
mod cli;
mod config;
mod crypto;
mod daemon;
mod ipc;
/// Windows 命名管道占用诊断。Unix 的 socket 没有这类「管道还在、但当前
/// 令牌连不上也接管不了」的问题，整个模块不在非 Windows 上编译。
#[cfg(windows)]
mod pipe_diag;
mod scanner;

fn main() {
    if std::env::var("WXEASY_DAEMON_MODE").is_ok() {
        daemon::run();
    } else {
        cli::run();
    }
}
