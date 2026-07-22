use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// CLI 向 daemon 发送的请求（换行符分隔 JSON，与 Python 版兼容）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Sessions {
        #[serde(default = "default_limit_20")]
        limit: usize,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    History {
        chat: String,
        #[serde(default = "default_limit_50")]
        limit: usize,
        #[serde(default)]
        offset: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        msg_type: Option<i64>,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    Search {
        keyword: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        chats: Option<Vec<String>>,
        #[serde(default = "default_limit_20")]
        limit: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        msg_type: Option<i64>,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    Contacts {
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        #[serde(default = "default_limit_50")]
        limit: usize,
    },
    /// 查看群聊列表。与 `Contacts` 对称：`Contacts` 只返回真人（private），
    /// 群聊在这里独立出口，不用再从 `Sessions` 间接翻。
    Groups {
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        #[serde(default = "default_limit_50")]
        limit: usize,
    },
    Unread {
        #[serde(default = "default_limit_20")]
        limit: usize,
        /// 按会话类型过滤：private / group / official / folded / all，支持多选
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    Members {
        chat: String,
    },
    NewMessages {
        /// 上次检查时各会话的 last_timestamp 快照（username -> ts）
        /// None 表示首次运行，会返回 new_state 供下次使用
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<HashMap<String, i64>>,
        #[serde(default = "default_limit_200")]
        limit: usize,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    Stats {
        chat: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    Favorites {
        #[serde(default = "default_limit_50")]
        limit: usize,
        /// 类型过滤：1=文本,2=图片,5=文章,19=名片,20=视频
        #[serde(skip_serializing_if = "Option::is_none")]
        fav_type: Option<i64>,
        /// 内容关键词搜索
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// 朋友圈互动通知（点赞 + 评论）
    SnsNotifications {
        #[serde(default = "default_limit_50")]
        limit: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        /// 包含已读通知（默认仅未读）
        #[serde(default)]
        include_read: bool,
    },
    /// 朋友圈时间线（按时间 / 作者筛选帖子）
    SnsFeed {
        #[serde(default = "default_limit_20")]
        limit: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        /// 作者昵称 / 备注名 / 微信 username，模糊匹配
        #[serde(skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// 查询公众号文章推送（biz_message_0.db）
    BizArticles {
        #[serde(default = "default_limit_50")]
        limit: usize,
        /// 公众号名称过滤（模糊匹配 display name，None = 全部）
        #[serde(skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        /// 只看有未读消息的公众号，每个公众号取最新 1 篇
        #[serde(default)]
        unread: bool,
    },
    /// 朋友圈全文搜索（匹配 contentDesc）
    SnsSearch {
        keyword: String,
        #[serde(default = "default_limit_20")]
        limit: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// 重新加载配置和密钥（init --force 后 daemon 不会自动重读）
    ReloadConfig,
    /// 列出某个会话里的图片附件
    /// 输出每条带 `attachment_id`（不透明 base64url 句柄），传给 `Extract` 时取回本体
    Attachments {
        chat: String,
        /// 类型过滤：当前仅支持 image
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kinds: Option<Vec<String>>,
        #[serde(default = "default_limit_50")]
        limit: usize,
        #[serde(default)]
        offset: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
        #[serde(default, skip_serializing_if = "is_false")]
        with_meta: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        debug_source: bool,
    },
    /// 提取（解密）单个附件的本体到指定路径
    Extract {
        /// `Attachments` 返回的不透明 ID
        attachment_id: String,
        /// 写入的绝对路径（daemon 直接写盘，不经 socket 传 binary）
        output: String,
        /// 已存在时是否覆盖
        #[serde(default)]
        overwrite: bool,
    },
}

/// daemon 的响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// FIX 4：daemon 后台加载联系人期间（socket 已经可连接，但
    /// `contact.db` 还没扫完）对依赖 names 的请求返回的区分信号——`ok`
    /// 仍是 `false`（保证旧客户端只看 `ok`/`error` 时的行为退化成"当作
    /// 错误处理"这个安全默认，不会被误当作成功），但新客户端（这里指
    /// `cli/transport.rs` 的 `send_unix`/`send_windows`）应该识别这个
    /// 字段，走"有限次数 + 有进度提示的重试"而不是立刻报错——这正是"预热
    /// 中"与"真失败"的区分点。默认 `false` 且 `skip_serializing_if`，旧版
    /// JSON payload 里不会出现这个字段，字段本身的增加不改变既有响应的
    /// 序列化结果。
    #[serde(default, skip_serializing_if = "is_false")]
    pub warming_up: bool,
    #[serde(flatten)]
    pub data: Value,
}

impl Response {
    pub fn ok(data: Value) -> Self {
        Self {
            ok: true,
            error: None,
            warming_up: false,
            data,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            warming_up: false,
            data: Value::Null,
        }
    }

    /// FIX 4：daemon 正在后台加载联系人、尚未就绪时的响应。`ok=false` 保证
    /// 旧客户端安全退化为"当作错误"；`warming_up=true` 供新客户端识别并
    /// 重试，见字段文档。
    pub fn warming_up(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            warming_up: true,
            data: Value::Null,
        }
    }

    pub fn to_json_line(&self) -> anyhow::Result<String> {
        let s = serde_json::to_string(self)?;
        Ok(s + "\n")
    }
}

fn default_limit_20() -> usize {
    20
}
fn default_limit_50() -> usize {
    50
}
fn default_limit_200() -> usize {
    200
}
fn is_false(v: &bool) -> bool {
    !*v
}
