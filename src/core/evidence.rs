//! Append-only dynamic-analysis evidence store.
//!
//! Runtime/debug/verification outputs are observations, not mutable project
//! annotations. Keep them in a JSONL sidecar so agents, jobs, reports, and the
//! UI can cite stable evidence IDs without rewriting the main project DB.

use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: String,
    pub kind: String,
    pub binary_path: String,
    pub binary_sha256: String,
    pub created_at: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub data: Value,
}

pub fn evidence_path(binary: &Path) -> PathBuf {
    let name = binary
        .file_name()
        .map(|n| format!("{}.kaiju.evidence.jsonl", n.to_string_lossy()))
        .unwrap_or_else(|| "binary.kaiju.evidence.jsonl".to_string());
    let mut dir = binary.to_path_buf();
    dir.pop();
    dir.push(name);
    dir
}

pub fn append(
    binary: &Path,
    kind: &str,
    summary: impl Into<String>,
    tags: Vec<String>,
    data: Value,
) -> Result<EvidenceRecord> {
    let record = EvidenceRecord {
        id: format!("ev_{}", &Uuid::new_v4().simple().to_string()[..10]),
        kind: kind.to_string(),
        binary_path: binary.to_string_lossy().into_owned(),
        binary_sha256: sha256_file(binary)?,
        created_at: chrono::Utc::now().to_rfc3339(),
        summary: summary.into(),
        tags,
        data,
    };
    let path = evidence_path(binary);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&record)?)?;
    Ok(record)
}

pub fn list(binary: &Path, kind: Option<&str>, limit: usize) -> Result<Vec<EvidenceRecord>> {
    let path = evidence_path(binary);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut records = Vec::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<EvidenceRecord>(&line) {
            if kind.map_or(true, |k| k == record.kind) {
                records.push(record);
            }
        }
    }
    records.reverse();
    records.truncate(limit.max(1));
    Ok(records)
}

pub fn execution_profiles(binary: &Path, runtime: Value) -> Value {
    json!({
        "kind": "execution_profiles",
        "binary": binary,
        "evidence_path": evidence_path(binary),
        "runtime": runtime,
        "profiles": [
            {
                "id": "native-readonly",
                "runner": "native",
                "policy": {
                    "network": "disabled by default",
                    "filesystem": "workspace read-only plus artifact dir",
                    "timeout_required": true
                }
            },
            {
                "id": "qemu-foreign",
                "runner": "qemu-user",
                "policy": {
                    "sysroot": "required for dynamically linked foreign targets",
                    "debugger": "gdb-multiarch via qemu -g",
                    "timeout_required": true
                }
            },
            {
                "id": "hostile-sample",
                "runner": "container-or-sandbox",
                "policy": {
                    "network": "deny",
                    "filesystem": "explicit allowlist",
                    "writes": "artifact directory only",
                    "human_approval": "required before execution"
                }
            }
        ],
    })
}

pub fn debug_session_contract(binary: &Path) -> Value {
    json!({
        "kind": "debug_session_contract",
        "binary": binary,
        "state": "live_session_foundation",
        "evidence_path": evidence_path(binary),
        "commands": [
            "start",
            "set_breakpoint",
            "delete_breakpoint",
            "continue",
            "step_instruction",
            "read_registers",
            "read_memory",
            "write_memory",
            "disassemble_pc",
            "snapshot",
            "stop"
        ],
        "current_implementation": {
            "one_shot_probe": "kaijulab api debug-probe",
            "persistent_sessions": "daemon-owned gdb/gdb-multiarch sessions via /api/debug/sessions and debug-session-* CLI commands",
            "evidence": "start/action/stop append immutable evidence records"
        },
        "evidence_rule": "every continue/step/crash/snapshot should append an immutable evidence record",
    })
}

pub fn benchmark_smoke_plan(binary: &Path) -> Value {
    json!({
        "kind": "benchmark_smoke_plan",
        "binary": binary,
        "checks": [
            {"id": "index", "command": "index-build", "expect": "success"},
            {"id": "runtime", "command": "runtime-run --timeout-secs 2", "expect": "success or structured blocker"},
            {"id": "debug", "command": "debug-probe --timeout-secs 8", "expect": "registers or structured blocker"},
            {"id": "evidence", "command": "evidence-list", "expect": "JSON list"}
        ],
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hex::encode(hasher.finalize()))
}
