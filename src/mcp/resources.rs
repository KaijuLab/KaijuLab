//! MCP resources — the three lightweight, truly browseable surfaces.

use anyhow::{anyhow, Result};
use serde_json::json;

use crate::core::workspace::Workspace;

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
            // Findings live in the daemon's FindingStore; standalone shim has
            // no access.  Return an empty list when running standalone.
            Ok("[]".into())
        }
        "kaiju://project/notes" => {
            let notes = workspace.with_project(|p| p.notes.clone());
            Ok(serde_json::to_string_pretty(&notes)?)
        }
        other => Err(anyhow!("unknown resource uri: {}", other)),
    }
}
