//! Findings — first-class actionable observations produced by tools, agents,
//! or analysts.  The findings board is the platform's primary output queue.

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use super::workspace::Workspace;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum FindingKind {
    Vuln,
    HashMatch,
    ImportOfInterest,
    CfgAnomaly,
    StringOfInterest,
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../web/src/types/")]
pub enum Severity {
    Info,
    Low,
    Med,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum FindingStatus {
    New,
    Triaging,
    Confirmed,
    Dismissed,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum Evidence {
    Disasm {
        vaddr: String,
        length: u32,
    },
    Decompile {
        vaddr: String,
    },
    Xref {
        from: String,
        to: String,
    },
    String {
        offset: u64,
        text: String,
    },
    Import {
        name: String,
    },
    ToolOutput {
        tool: String,
        #[ts(type = "Record<string, unknown>")]
        args: serde_json::Value,
        snippet: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum CreatedBy {
    Tool { name: String },
    Agent { agent: String },
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub vaddr: Option<String>,
    pub rule: String,
    pub rationale: String,
    pub evidence: Vec<Evidence>,
    pub suggested_actions: Vec<String>,
    pub status: FindingStatus,
    pub owner: Option<String>,
    pub created_by: CreatedBy,
    pub notes: Vec<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Input for creating a finding via API/MCP.
#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct CreateFinding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub vaddr: Option<String>,
    pub rule: String,
    pub rationale: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub suggested_actions: Vec<String>,
    pub created_by: CreatedBy,
}

#[derive(Debug, Clone, Default, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct UpdateFinding {
    pub status: Option<FindingStatus>,
    pub owner: Option<String>,
    #[serde(default)]
    pub append_notes: Vec<i64>,
}

pub fn create_finding(ws: &Workspace, input: CreateFinding) -> anyhow::Result<Finding> {
    let finding = {
        let now = super::events::now_ts();
        let id = format!("f_{}", &Uuid::new_v4().simple().to_string()[..8]);
        Finding {
            id: id.clone(),
            kind: input.kind,
            severity: input.severity,
            vaddr: input.vaddr,
            rule: input.rule,
            rationale: input.rationale,
            evidence: input.evidence,
            suggested_actions: input.suggested_actions,
            status: FindingStatus::New,
            owner: None,
            created_by: input.created_by,
            notes: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    };
    ws.with_project(|p| p.findings.push(finding.clone()));
    ws.save_project()?;
    Ok(finding)
}

pub fn update_finding(
    ws: &Workspace,
    id: &str,
    patch: UpdateFinding,
) -> anyhow::Result<Option<Finding>> {
    let updated = ws.with_project(|p| {
        let f = p.findings.iter_mut().find(|f| f.id == id)?;
        if let Some(s) = patch.status {
            f.status = s;
        }
        if let Some(o) = patch.owner {
            f.owner = Some(o);
        }
        for n in patch.append_notes {
            if !f.notes.contains(&n) {
                f.notes.push(n);
            }
        }
        f.updated_at = super::events::now_ts();
        Some(f.clone())
    });
    if updated.is_some() {
        ws.save_project()?;
    }
    Ok(updated)
}

pub fn get_finding(ws: &Workspace, id: &str) -> Option<Finding> {
    ws.with_project(|p| p.findings.iter().find(|f| f.id == id).cloned())
}

pub fn list_findings(ws: &Workspace) -> Vec<Finding> {
    let mut v = ws.with_project(|p| p.findings.clone());
    v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    v
}
