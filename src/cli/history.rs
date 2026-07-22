use super::output::{emit_warnings, print_response, OutputOpts};
use super::transport;
use crate::ipc::Request;
use anyhow::Result;

pub fn cmd_history(
    chat: String,
    limit: usize,
    offset: usize,
    since: Option<String>,
    until: Option<String>,
    msg_type: Option<String>,
    opts: OutputOpts,
) -> Result<()> {
    // FIX 3（CLI 兜底，只加提示、不改默认值）：daemon 侧 `since=None` 时
    // `shard_skippable` 恒为 false，daemon 刚重启、路由缓存为空时会对
    // *全部* 消息分片串行/并发扫描一遍——手滑漏传 `--since` 是这类全库扫描
    // 最常见的触发源。这里只在 stderr 打一行提示，**不改变**不传 `--since`
    // 时的实际查询语义（仍然是"无时间下界，返回全部历史里最新的 N 条"）：
    // PriceKeeper（已知调用方，见 `src-tauri/src/lib.rs` 的
    // `run_wx_history_json` / `WxReadyProbe::History`）依赖这个"不传
    // `--since` 就拿真正意义上最新一条消息"的兜底语义做 wx-cli 就绪探测
    // （`-n 1` 只要一条最近消息，用来判断 wx-cli 是否能正常读到聊天记录）；
    // 如果把默认值悄悄改成"最近 30 天"，一个近 30 天没有新消息的会话会让
    // 这个探测误判为"读不到历史记录"，从而把"wx-cli 工作正常、只是这个
    // 会话最近没消息"误报成"wx-cli 故障"，属于典型的破坏已知调用方语义的
    // 场景，因此这里退化为只加提示。
    if since.is_none() {
        eprintln!("未指定 --since，将查询全部历史（可能触发全库扫描），如需限定范围请传 --since YYYY-MM-DD");
    }
    let since_ts = since.as_deref().map(parse_time).transpose()?;
    let until_ts = until.as_deref().map(parse_time_end).transpose()?;
    let type_val = msg_type.as_deref().and_then(parse_msg_type);
    let (with_meta, debug_source) = opts.request_flags();

    let req = Request::History {
        chat,
        limit,
        offset,
        since: since_ts,
        until: until_ts,
        msg_type: type_val,
        with_meta,
        debug_source,
    };
    let resp = transport::send(req)?;
    emit_warnings(&resp.data);
    print_response(&resp.data, &opts)
}

pub fn parse_time(s: &str) -> Result<i64> {
    use chrono::{Local, TimeZone};
    for fmt in &["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Local
                .from_local_datetime(&dt)
                .single()
                .map(|d| d.timestamp())
                .ok_or_else(|| anyhow::anyhow!("本地时间歧义: {}", s));
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = d.and_hms_opt(0, 0, 0).unwrap();
        return Local
            .from_local_datetime(&dt)
            .single()
            .map(|d| d.timestamp())
            .ok_or_else(|| anyhow::anyhow!("本地时间歧义: {}", s));
    }
    anyhow::bail!(
        "无法解析时间 '{}'，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS",
        s
    )
}

pub fn parse_time_end(s: &str) -> Result<i64> {
    use chrono::{Local, TimeZone};
    if s.len() == 10 {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            let dt = d.and_hms_opt(23, 59, 59).unwrap();
            return Local
                .from_local_datetime(&dt)
                .single()
                .map(|d| d.timestamp())
                .ok_or_else(|| anyhow::anyhow!("本地时间歧义: {}", s));
        }
    }
    parse_time(s)
}

/// 将消息类型字符串转为 local_type 整数，未知类型返回 None
pub fn parse_msg_type(s: &str) -> Option<i64> {
    match s {
        "text" => Some(1),
        "image" => Some(3),
        "voice" => Some(34),
        "video" => Some(43),
        "sticker" => Some(47),
        "location" => Some(48),
        "link" | "file" => Some(49),
        "call" => Some(50),
        "system" => Some(10000),
        _ => None,
    }
}
