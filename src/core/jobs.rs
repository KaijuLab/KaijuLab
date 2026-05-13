//! Async job model with cancellation.  Long-running operations
//! (`scan_vulnerabilities`, `match_all_functions`, large decompilations) run
//! as jobs so the web UI can show progress and cancel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use ts_rs::TS;
use uuid::Uuid;

use super::events::{now_ts, Event, EventBus};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct JobId(pub String);

impl JobId {
    pub fn new() -> Self {
        JobId(format!("j_{}", &Uuid::new_v4().simple().to_string()[..8]))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum JobStatus {
    Pending,
    Running,
    Ok,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum JobKind {
    ScanVuln,
    MatchAllFunctions,
    Decompile,
    AgentBridge,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct Job {
    pub id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub error: Option<String>,
    pub result_summary: Option<String>,
    pub progress: f32,
}

/// Cancellation handle a job can poll.  Backed by AtomicBool so it is cheap to
/// check in tight loops inside `spawn_blocking` workers.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

struct JobEntry {
    job: Job,
    cancel: CancellationToken,
    _handle: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct JobRunner {
    jobs: Arc<DashMap<String, JobEntry>>,
    events: EventBus,
}

impl JobRunner {
    pub fn new(events: EventBus) -> Self {
        JobRunner {
            jobs: Arc::new(DashMap::new()),
            events,
        }
    }

    /// Register a job and return its id + cancellation token.  The caller is
    /// responsible for spawning the actual work and calling `finish()` /
    /// `fail()` when done.
    pub fn register(&self, kind: JobKind) -> (JobId, CancellationToken) {
        let id = JobId::new();
        let token = CancellationToken::new();
        let job = Job {
            id: id.0.clone(),
            kind: kind.clone(),
            status: JobStatus::Running,
            created_at: now_ts(),
            finished_at: None,
            error: None,
            result_summary: None,
            progress: 0.0,
        };
        let kind_str = serde_json::to_string(&kind).unwrap_or_else(|_| "custom".into());
        self.events.emit(Event::JobStarted {
            id: id.0.clone(),
            kind: kind_str.trim_matches('"').to_string(),
            ts: now_ts(),
        });
        self.jobs.insert(
            id.0.clone(),
            JobEntry {
                job,
                cancel: token.clone(),
                _handle: None,
            },
        );
        (id, token)
    }

    pub fn progress(&self, id: &JobId, pct: f32) {
        if let Some(mut entry) = self.jobs.get_mut(&id.0) {
            entry.job.progress = pct;
        }
        self.events.emit(Event::JobProgress {
            id: id.0.clone(),
            pct,
        });
    }

    pub fn finish(&self, id: &JobId, summary: Option<String>) {
        if let Some(mut entry) = self.jobs.get_mut(&id.0) {
            entry.job.status = JobStatus::Ok;
            entry.job.finished_at = Some(now_ts());
            entry.job.result_summary = summary;
        }
        self.events.emit(Event::JobFinished {
            id: id.0.clone(),
            status: "ok".into(),
            ts: now_ts(),
        });
    }

    pub fn fail(&self, id: &JobId, err: String) {
        if let Some(mut entry) = self.jobs.get_mut(&id.0) {
            entry.job.status = JobStatus::Failed;
            entry.job.finished_at = Some(now_ts());
            entry.job.error = Some(err.clone());
        }
        self.events.emit(Event::JobFailed {
            id: id.0.clone(),
            error: err,
            ts: now_ts(),
        });
    }

    pub fn cancel(&self, id: &str) -> bool {
        if let Some(entry) = self.jobs.get(id) {
            entry.cancel.cancel();
            self.events.emit(Event::JobCancelled {
                id: id.to_string(),
                ts: now_ts(),
            });
            true
        } else {
            false
        }
    }

    pub fn get(&self, id: &str) -> Option<Job> {
        self.jobs.get(id).map(|e| e.job.clone())
    }

    pub fn list(&self) -> Vec<Job> {
        let mut v: Vec<Job> = self.jobs.iter().map(|e| e.job.clone()).collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }
}
