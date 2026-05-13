//! Persistent recovery database and analyst correction API.

use std::path::Path;

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::project::Project;

use super::recovery::{self, RecoveredFunction, RecoveredXref, RecoveryIndex};
use super::workspace::Workspace;

const RECOVERY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS recovery_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_functions (
    start TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    name TEXT NOT NULL,
    confidence TEXT NOT NULL,
    source TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS recovery_blocks (
    function_start TEXT NOT NULL,
    start TEXT NOT NULL,
    end TEXT NOT NULL,
    instruction_count INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (function_start, start)
);
CREATE TABLE IF NOT EXISTS recovery_edges (
    function_start TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (function_start, from_addr, to_addr, kind)
);
CREATE TABLE IF NOT EXISTS recovery_xrefs (
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    kind TEXT NOT NULL,
    function_start TEXT,
    mnemonic TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (from_addr, to_addr, kind)
);
CREATE TABLE IF NOT EXISTS recovery_corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    vaddr TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    note TEXT,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCorrection {
    pub action: String,
    pub vaddr: String,
    pub target: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    pub data: Value,
}

pub fn rebuild(ws: &Workspace, max_functions: usize) -> Result<RecoveryIndex> {
    let index = recovery::recover(ws.binary_path(), max_functions)?;
    persist(ws.binary_path(), &index)?;
    Ok(load(ws.binary_path())?.unwrap_or(index))
}

pub fn load_or_rebuild(ws: &Workspace, max_functions: usize) -> Result<RecoveryIndex> {
    match load(ws.binary_path())? {
        Some(index) => Ok(index),
        None => rebuild(ws, max_functions),
    }
}

pub fn load(path: &Path) -> Result<Option<RecoveryIndex>> {
    let conn = open(path)?;
    let meta_count: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_meta", [], |r| r.get(0))?;
    if meta_count == 0 {
        return Ok(None);
    }
    let binary = path.to_string_lossy().into_owned();
    let architecture = meta(&conn, "architecture")?.unwrap_or_else(|| "unknown".to_string());
    let entry = meta(&conn, "entry")?;

    let mut stmt = conn.prepare("SELECT data FROM recovery_functions ORDER BY start")?;
    let functions = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .flatten()
        .filter_map(|text| serde_json::from_str::<RecoveredFunction>(&text).ok())
        .collect::<Vec<_>>();

    let mut stmt = conn.prepare("SELECT data FROM recovery_xrefs ORDER BY to_addr, from_addr")?;
    let xrefs = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .flatten()
        .filter_map(|text| serde_json::from_str::<RecoveredXref>(&text).ok())
        .collect::<Vec<_>>();

    let block_count = functions.iter().map(|f| f.blocks.len()).sum();
    let edge_count = functions.iter().map(|f| f.edges.len()).sum();
    Ok(Some(RecoveryIndex {
        kind: "recovery_index".to_string(),
        schema_version: 1,
        binary,
        architecture,
        entry,
        stats: recovery::RecoveryStats {
            executable_sections: meta(&conn, "executable_sections")?
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            function_count: functions.len(),
            block_count,
            edge_count,
            xref_count: xrefs.len(),
        },
        functions,
        xrefs,
    }))
}

pub fn correction(ws: &Workspace, input: RecoveryCorrection) -> Result<Value> {
    let conn = open(ws.binary_path())?;
    conn.execute(
        "INSERT INTO recovery_corrections (action, vaddr, target, note, data) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            input.action,
            normalize_addr(&input.vaddr),
            input.target.as_deref().map(normalize_addr),
            input.note,
            serde_json::to_string(&input.data)?,
        ],
    )?;
    let id = conn.last_insert_rowid();
    apply_correction(ws.binary_path(), id)?;
    Ok(json!({ "ok": true, "id": id }))
}

pub fn corrections(path: &Path) -> Result<Value> {
    let conn = open(path)?;
    let mut stmt = conn.prepare(
        "SELECT id, action, vaddr, target, status, note, data, created_at FROM recovery_corrections ORDER BY id DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let data: String = row.get(6)?;
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "action": row.get::<_, String>(1)?,
                "vaddr": row.get::<_, String>(2)?,
                "target": row.get::<_, Option<String>>(3)?,
                "status": row.get::<_, String>(4)?,
                "note": row.get::<_, Option<String>>(5)?,
                "data": serde_json::from_str::<Value>(&data).unwrap_or(Value::Null),
                "created_at": row.get::<_, String>(7)?,
            }))
        })?
        .flatten()
        .collect::<Vec<_>>();
    Ok(json!({ "kind": "recovery_corrections", "items": rows }))
}

fn persist(path: &Path, index: &RecoveryIndex) -> Result<()> {
    let mut conn = open(path)?;
    let tx = conn.transaction()?;
    tx.execute_batch(
        "
        DELETE FROM recovery_meta;
        DELETE FROM recovery_functions;
        DELETE FROM recovery_blocks;
        DELETE FROM recovery_edges;
        DELETE FROM recovery_xrefs;
        ",
    )?;
    put_meta(&tx, "architecture", &index.architecture)?;
    if let Some(entry) = &index.entry {
        put_meta(&tx, "entry", entry)?;
    }
    put_meta(
        &tx,
        "executable_sections",
        &index.stats.executable_sections.to_string(),
    )?;

    for function in &index.functions {
        tx.execute(
            "INSERT INTO recovery_functions (start, size, name, confidence, source, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                normalize_addr(&function.start),
                function.size as i64,
                function.name,
                function.confidence,
                serde_json::to_string(&function.source)?,
                serde_json::to_string(function)?,
            ],
        )?;
        for block in &function.blocks {
            tx.execute(
                "INSERT INTO recovery_blocks (function_start, start, end, instruction_count, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    normalize_addr(&function.start),
                    normalize_addr(&block.start),
                    normalize_addr(&block.end),
                    block.instruction_count as i64,
                    serde_json::to_string(block)?,
                ],
            )?;
        }
        for edge in &function.edges {
            tx.execute(
                "INSERT INTO recovery_edges (function_start, from_addr, to_addr, kind, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    normalize_addr(&function.start),
                    normalize_addr(&edge.from),
                    normalize_addr(&edge.to),
                    edge.kind,
                    serde_json::to_string(edge)?,
                ],
            )?;
        }
    }
    for xref in &index.xrefs {
        tx.execute(
            "INSERT OR REPLACE INTO recovery_xrefs (from_addr, to_addr, kind, function_start, mnemonic, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                normalize_addr(&xref.from),
                normalize_addr(&xref.to),
                xref.kind,
                xref.function.as_deref().map(normalize_addr),
                xref.mnemonic,
                serde_json::to_string(xref)?,
            ],
        )?;
    }
    tx.commit()?;
    replay_corrections(path)?;
    Ok(())
}

fn replay_corrections(path: &Path) -> Result<()> {
    let conn = open(path)?;
    let ids = conn
        .prepare("SELECT id FROM recovery_corrections WHERE status = 'active' ORDER BY id")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .flatten()
        .collect::<Vec<_>>();
    drop(conn);
    for id in ids {
        apply_correction(path, id)?;
    }
    Ok(())
}

fn apply_correction(path: &Path, id: i64) -> Result<()> {
    let conn = open(path)?;
    let (action, vaddr, target, note, data): (String, String, Option<String>, Option<String>, String) =
        conn.query_row(
            "SELECT action, vaddr, target, note, data FROM recovery_corrections WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
    let parsed = serde_json::from_str::<Value>(&data).unwrap_or(Value::Null);
    match action.as_str() {
        "rename_function" => {
            let name = parsed
                .get("name")
                .and_then(|v| v.as_str())
                .or(note.as_deref())
                .unwrap_or("FUN_user");
            if let Some(mut function) = load_function(&conn, &vaddr)? {
                function.name = name.to_string();
                function.confidence = "analyst".to_string();
                function.source.push("analyst_correction".to_string());
                conn.execute(
                    "UPDATE recovery_functions SET name = ?1, confidence = 'analyst', source = ?2, data = ?3 WHERE start = ?4",
                    params![
                        name,
                        serde_json::to_string(&function.source)?,
                        serde_json::to_string(&function)?,
                        vaddr,
                    ],
                )?;
            }
            conn.execute(
                "UPDATE recovery_functions SET name = ?1, confidence = 'analyst' WHERE start = ?2",
                params![name, vaddr],
            )?;
        }
        "mark_data" => {
            conn.execute("DELETE FROM recovery_functions WHERE start = ?1", params![vaddr])?;
            conn.execute("DELETE FROM recovery_blocks WHERE function_start = ?1", params![vaddr])?;
            conn.execute("DELETE FROM recovery_edges WHERE function_start = ?1", params![vaddr])?;
        }
        "mark_code" | "split_function" => {
            let name = parsed
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("FUN_{}", vaddr.trim_start_matches("0x")));
            let function = RecoveredFunction {
                start: vaddr.clone(),
                size: 1,
                name,
                confidence: "analyst".to_string(),
                source: vec![action.clone()],
                blocks: Vec::new(),
                edges: Vec::new(),
            };
            conn.execute(
                "INSERT OR REPLACE INTO recovery_functions (start, size, name, confidence, source, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    vaddr,
                    1_i64,
                    function.name,
                    function.confidence,
                    serde_json::to_string(&function.source)?,
                    serde_json::to_string(&function)?,
                ],
            )?;
        }
        "merge_function" => {
            if let Some(target) = target {
                conn.execute("DELETE FROM recovery_functions WHERE start = ?1", params![vaddr])?;
                conn.execute(
                    "UPDATE recovery_blocks SET function_start = ?1 WHERE function_start = ?2",
                    params![target, vaddr],
                )?;
                conn.execute(
                    "UPDATE recovery_edges SET function_start = ?1 WHERE function_start = ?2",
                    params![target, vaddr],
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn open(binary: &Path) -> Result<Connection> {
    let db = Project::db_path(&binary.to_string_lossy());
    let conn = Connection::open(db)?;
    conn.execute_batch(RECOVERY_SCHEMA)?;
    Ok(conn)
}

fn put_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO recovery_meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM recovery_meta WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
}

fn load_function(conn: &Connection, start: &str) -> Result<Option<RecoveredFunction>> {
    let mut stmt = conn.prepare("SELECT data FROM recovery_functions WHERE start = ?1")?;
    let mut rows = stmt.query(params![start])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let data: String = row.get(0)?;
    Ok(serde_json::from_str::<RecoveredFunction>(&data).ok())
}

fn normalize_addr(addr: impl AsRef<str>) -> String {
    let raw = addr.as_ref().trim();
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    u64::from_str_radix(hex, 16)
        .map(|v| format!("0x{v:x}"))
        .unwrap_or_else(|_| raw.to_ascii_lowercase())
}
