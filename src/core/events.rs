//! Event bus — granular deltas with source attribution, fanned out to all
//! subscribers (web WebSocket clients, MCP shim event subscribers, internal
//! observers).

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use ts_rs::TS;

/// Who originated a mutation or call.  Every event carries this so the UI can
/// attribute ("Claude renamed this 3s ago" vs "you renamed this 2 days ago").
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../web/src/types/")]
pub enum Source {
    User,
    Claude,
    Codex,
    Plugin,
    Tool,
    System,
}

impl Source {
    pub fn from_str_or_user(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "claude" => Source::Claude,
            "codex" => Source::Codex,
            "plugin" => Source::Plugin,
            "tool" => Source::Tool,
            "system" => Source::System,
            _ => Source::User,
        }
    }
}

/// Granular event delta.  Wire JSON uses dotted `type` discriminator
/// (`function.renamed`, `comment.added`, …) so it reads naturally on the
/// browser side.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type")]
#[ts(export, export_to = "../web/src/types/")]
pub enum Event {
    #[serde(rename = "function.renamed")]
    FunctionRenamed {
        vaddr: String,
        old: Option<String>,
        new: String,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "comment.added")]
    CommentAdded {
        vaddr: String,
        text: String,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "note.added")]
    NoteAdded {
        id: i64,
        vaddr: Option<String>,
        text: String,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "note.deleted")]
    NoteDeleted { id: i64, source: Source, ts: i64 },
    #[serde(rename = "vuln_score.set")]
    VulnScoreSet {
        vaddr: String,
        score: u8,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "finding.created")]
    FindingCreated {
        id: String,
        kind: String,
        severity: String,
        vaddr: Option<String>,
        rule: String,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "finding.updated")]
    FindingUpdated {
        id: String,
        status: Option<String>,
        owner: Option<String>,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "job.started")]
    JobStarted {
        id: String,
        kind: String,
        ts: i64,
    },
    #[serde(rename = "job.progress")]
    JobProgress { id: String, pct: f32 },
    #[serde(rename = "job.finished")]
    JobFinished { id: String, status: String, ts: i64 },
    #[serde(rename = "job.cancelled")]
    JobCancelled { id: String, ts: i64 },
    #[serde(rename = "job.failed")]
    JobFailed { id: String, error: String, ts: i64 },
    #[serde(rename = "tool.call")]
    ToolCall {
        id: String,
        job_id: Option<String>,
        name: String,
        source: Source,
        ts: i64,
    },
    #[serde(rename = "tool.result")]
    ToolResult {
        id: String,
        name: String,
        ok: bool,
        bytes: usize,
        ts: i64,
    },
    #[serde(rename = "navigation")]
    Navigation {
        vaddr: String,
        source: Source,
        ts: i64,
    },
}

/// Broadcast bus.  Subscribers are dropped if they lag too far behind.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        EventBus { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    pub fn emit(&self, ev: Event) {
        let _ = self.tx.send(ev);
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

pub fn now_ts() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
