//! MCP resources — the three lightweight, truly browseable surfaces.

use anyhow::{anyhow, Result};
use serde_json::json;

use crate::core::{findings, workspace::Workspace};

pub fn list() -> serde_json::Value {
    json!([
        {
            "uri": "kaiju://workspace",
            "name": "Workspace",
            "description": "Active binary path, display name, write policy.",
            "mimeType": "application/json"
        },
        {
            "uri": "kaiju://findings",
            "name": "Findings",
            "description": "Findings board snapshot.",
            "mimeType": "application/json"
        },
        {
            "uri": "kaiju://project/notes",
            "name": "Notes",
            "description": "All free-form analyst notes for the active binary.",
            "mimeType": "application/json"
        }
    ])
}

pub fn read(workspace: &Workspace, uri: &str) -> Result<String> {
    match uri {
        "kaiju://workspace" => Ok(serde_json::to_string_pretty(&workspace.info())?),
        "kaiju://findings" => {
            let findings = findings::list_findings(workspace);
            Ok(serde_json::to_string_pretty(&findings)?)
        }
        "kaiju://project/notes" => {
            let notes = workspace.with_project(|p| p.notes.clone());
            Ok(serde_json::to_string_pretty(&notes)?)
        }
        other => Err(anyhow!("unknown resource uri: {}", other)),
    }
}
