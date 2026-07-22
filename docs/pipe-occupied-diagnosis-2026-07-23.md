# Windows 管道占用诊断：设计与真机复现备案（2026-07-23）

## 故障模式

wxeasy-daemon 在与当前用户不同的令牌上下文里被拉起（提权宿主程序调用
wxeasy、沙箱受限令牌、另一 Windows 账号）后，`\\.\pipe\wxeasy-daemon`
的 DACL 只认创建者那张令牌：普通客户端 Connect 全部
`拒绝访问 (os error 5)`，被 `is_alive` 误判成「daemon 未运行」；CLI 拉
新 daemon，新实例抢同名管道同样吃 os error 5，重试 5s 后退出；用户只
看到「启动超时（>15s）」。关掉宿主程序无效——daemon 是
DETACHED_PROCESS，早已脱离父进程；普通令牌 taskkill / Stop-Process /
WMI 全被拒，唯一解法是管理员终端 `taskkill /F /PID <pid>`。
真实事故：2026-07-23 价表管家（提权运行）拉起的 daemon（PID 8124）
锁死整机 wxeasy。

## 诊断机制（commit 1d47149，src/pipe_diag.rs，仅 Windows 编译）

`CreateFileW` 打开管道，按错误码定性：不存在(2/3) / 拒绝访问(5) /
全忙(231) / 可连接；可连接时 `GetNamedPipeServerProcessId` 拿服务端
PID；拒绝访问时退回 ToolHelp 进程快照指认疑似 wxeasy 实例（快照对提
权进程可见，`QueryFullProcessImageNameW` 查不到路径这件事本身作为
「多半就是它」的线索展示），生成含 `taskkill /F /PID` 的管理员终端指
引。四个出口：

1. `ensure_daemon` spawn 前预检——管道被占死直接报诊断，不再白等 15s；
2. `start_daemon` 启动超时——报错追加探测结论；
3. `daemon status` 显示「未运行」时——若探出被占死当场说明；
4. `serve_windows` 绑定重试预算（5s）耗尽——逐行 `[server]` 前缀写进
   daemon.log。重试期内不提前定性：正常 stop/restart 竞态的错误码同
   样是 os error 5（FILE_FLAG_FIRST_PIPE_INSTANCE 语义）。

只做诊断不做自动修复——杀一个当前令牌够不着的进程本就需要用户主动提
权，替用户猜着杀反而危险。

## 真机复现（2026-07-23，v0.3.2 release，管理员终端手动拉提权 daemon）

提权实例 PID 27804 占住管道后，普通令牌侧三个出口全部命中：

- `daemon status`：「未运行」+ 完整诊断，精确指认 PID 27804 且 exe
  全路径解析成功（普通令牌对提权进程 PROCESS_QUERY_LIMITED_INFORMATION
  可用，「查不到路径」兜底未触发）；
- `groups` 查询：**42ms 快速失败**（原行为：白等 15s 超时后只有一句
  「启动超时」），错误文本含同款诊断；
- 手动拉 daemon：重试 5s 后打出「重试预算耗尽——已经不是『旧实例正在
  退出』的短暂竞态了」+ 逐行 `[server]` 报告，进程干净退出无残留。

清理即照抄诊断文案里的 `taskkill /F /PID 27804`（管理员终端），指引
本身同轮验证。管道释放后三个出口全部静默，正常路径零噪音；正常
stop → 冷启动流程未被预检误拦。

附注：从 CLI 会话内 `Start-Process -Verb RunAs` 弹 UAC 会被系统自动
拒绝（consent.exe 一闪而过），复现提权场景须真人在管理员终端操作。
