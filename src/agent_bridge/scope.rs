//! Context pack: the compact, explicit bundle handed to a bridge invocation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum WritePolicy {
    /// Suggestions only; results land in the inspector as proposed mutations.
    Suggest,
    /// Apply mutations immediately to the project DB.
    Apply,
    /// Read-only; no writes.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum Target {
    Function { vaddr: String },
    Range { start: String, end: String },
    Finding { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct ContextPack {
    pub workspace_summary: String,
    pub target: Target,
    #[ts(type = "Record<string, unknown>")]
    pub annotations: Value,
    pub prior_findings: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub write_policy: WritePolicy,
    #[ts(type = "Record<string, unknown>")]
    pub output_schema: Value,
}
