//! Persistent project database — stores renames, comments, type annotations,
//! struct definitions, and vulnerability scores across sessions.
//!
//! Storage: SQLite (`.kaiju.db` next to the binary).
//! Migration: if a legacy `.kaiju.json` sidecar is found and no `.kaiju.db`
//! exists yet, the JSON is loaded and immediately migrated to SQLite.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

// ─── Struct definitions ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructField {
    /// Byte offset from the struct base.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Field name.
    pub name: String,
    /// Type string, e.g. "char*", "uint32_t", "struct Node*".
    pub type_str: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    /// Total size in bytes (0 = unknown).
    pub total_size: usize,
    pub fields: Vec<StructField>,
}

impl StructDef {
    /// Look up the field that covers `offset`.
    pub fn field_at(&self, offset: usize) -> Option<&StructField> {
        self.fields
            .iter()
            .find(|f| offset >= f.offset && offset < f.offset + f.size.max(1))
    }

    /// Pretty-print as a C struct definition.
    pub fn to_c(&self) -> String {
        let mut out = format!("struct {} {{\n", self.name);
        for f in &self.fields {
            out.push_str(&format!(
                "    /* +0x{:02x} */ {} {};\n",
                f.offset, f.type_str, f.name
            ));
        }
        out.push_str("};");
        out
    }
}

// ─── Function signature ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// C type string for the return value, e.g. "int", "char*", "void".
    pub return_type: Option<String>,
    /// Positional parameter type overrides.  Index 0 → arg_1, index 1 → arg_2, …
    pub param_types: Vec<Option<String>>,
    /// Positional parameter name overrides.  Empty string = keep default.
    pub param_names: Vec<Option<String>>,
}

// ─── Project ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Project {
    /// Virtual address → user-assigned function/global name.
    pub renames: HashMap<u64, String>,
    /// Virtual address → analyst comment.
    pub comments: HashMap<u64, String>,
    /// fn_vaddr → { decompiler_var_name → user_name }
    pub var_renames: HashMap<u64, HashMap<String, String>>,
    /// fn_vaddr → signature (return type + param types/names)
    pub signatures: HashMap<u64, FunctionSignature>,
    /// Named struct definitions, keyed by struct name.
    pub structs: HashMap<String, StructDef>,
    /// fn_vaddr → vulnerability suspicion score (0–10).
    pub vuln_scores: HashMap<u64, u8>,
    /// Analyst notes (free-form text, optionally anchored to a vaddr).
    pub notes: Vec<Note>,

    /// SQLite database path (not serialized — set at load time).
    #[serde(skip)]
    pub db_path_field: Option<PathBuf>,
    /// Legacy JSON sidecar path, kept for migration detection (not serialized).
    #[serde(skip)]
    pub sidecar_path: Option<PathBuf>,
}

// ─── Analyst notes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Note {
    /// Auto-assigned row-id from SQLite.
    pub id: i64,
    /// Optional virtual address the note is anchored to.
    pub vaddr: Option<u64>,
    /// Free-form note text.
    pub text: String,
    /// ISO-8601 timestamp set at insert time.
    pub timestamp: String,
}

// ─── Helper: encode/decode vaddrs as "0x{:016x}" TEXT ─────────────────────────

fn vaddr_key(v: u64) -> String {
    format!("0x{:016x}", v)
}

fn parse_vaddr(s: &str) -> u64 {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

// ─── SQLite schema ────────────────────────────────────────────────────────────

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS renames (
    vaddr TEXT PRIMARY KEY,
    name  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
    vaddr TEXT PRIMARY KEY,
    text  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS var_renames (
    fn_vaddr TEXT NOT NULL,
    old_name TEXT NOT NULL,
    new_name TEXT NOT NULL,
    PRIMARY KEY (fn_vaddr, old_name)
);
CREATE TABLE IF NOT EXISTS signatures (
    fn_vaddr TEXT PRIMARY KEY,
    data     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS structs (
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_scores (
    vaddr TEXT    PRIMARY KEY,
    score INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    vaddr     TEXT,
    text      TEXT    NOT NULL,
    timestamp TEXT    NOT NULL DEFAULT (datetime('now'))
);
";

impl Project {
    // ── Path helpers ──────────────────────────────────────────────────────────

    /// Path to the SQLite database for a binary (primary storage).
    pub fn db_path(binary: &str) -> PathBuf {
        let p = PathBuf::from(binary);
        let name = p
            .file_name()
            .map(|n| format!("{}.kaiju.db", n.to_string_lossy()))
            .unwrap_or_else(|| "binary.kaiju.db".to_string());
        let mut dir = p.clone();
        dir.pop();
        dir.push(name);
        dir
    }

    /// Path to the legacy JSON sidecar (used for migration only).
    pub fn project_path(binary: &str) -> PathBuf {
        let p = PathBuf::from(binary);
        let name = p
            .file_name()
            .map(|n| format!("{}.kaiju.json", n.to_string_lossy()))
            .unwrap_or_else(|| "binary.kaiju.json".to_string());
        let mut dir = p.clone();
        dir.pop();
        dir.push(name);
        dir
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// Load the project for a binary.
    /// Checks for `.kaiju.db` first; falls back to `.kaiju.json` (migrating it
    /// automatically to SQLite on first load); returns an empty project if neither exists.
    pub fn load_for(binary: &str) -> Self {
        let db   = Self::db_path(binary);
        let json = Self::project_path(binary);

        if db.exists() {
            if let Ok(p) = Self::load_from_db(&db) {
                return p;
            }
        }

        if json.exists() {
            let mut p = Self::load_from_json(&json);
            p.db_path_field = Some(db.clone());
            p.sidecar_path  = Some(json);
            // Migrate JSON → SQLite (best-effort; ignore errors)
            let _ = p.save();
            return p;
        }

        // No existing data
        Project {
            db_path_field: Some(db),
            sidecar_path:  Some(json),
            ..Default::default()
        }
    }

    fn load_from_db(path: &PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;

        let mut p = Project {
            db_path_field: Some(path.clone()),
            ..Default::default()
        };

        // renames
        {
            let mut stmt = conn.prepare("SELECT vaddr, name FROM renames")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows.flatten() {
                p.renames.insert(parse_vaddr(&row.0), row.1);
            }
        }
        // comments
        {
            let mut stmt = conn.prepare("SELECT vaddr, text FROM comments")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows.flatten() {
                p.comments.insert(parse_vaddr(&row.0), row.1);
            }
        }
        // var_renames
        {
            let mut stmt = conn.prepare("SELECT fn_vaddr, old_name, new_name FROM var_renames")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows.flatten() {
                p.var_renames
                    .entry(parse_vaddr(&row.0))
                    .or_default()
                    .insert(row.1, row.2);
            }
        }
        // signatures
        {
            let mut stmt = conn.prepare("SELECT fn_vaddr, data FROM signatures")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows.flatten() {
                if let Ok(sig) = serde_json::from_str::<FunctionSignature>(&row.1) {
                    p.signatures.insert(parse_vaddr(&row.0), sig);
                }
            }
        }
        // structs
        {
            let mut stmt = conn.prepare("SELECT name, data FROM structs")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows.flatten() {
                if let Ok(def) = serde_json::from_str::<StructDef>(&row.1) {
                    p.structs.insert(row.0, def);
                }
            }
        }
        // vuln_scores
        {
            let mut stmt = conn.prepare("SELECT vaddr, score FROM vuln_scores")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows.flatten() {
                p.vuln_scores.insert(parse_vaddr(&row.0), row.1.clamp(0, 10) as u8);
            }
        }
        // notes
        {
            let mut stmt = conn
                .prepare("SELECT id, vaddr, text, timestamp FROM notes ORDER BY id")
                .unwrap_or_else(|_| conn.prepare("SELECT 0, NULL, '', '' WHERE 0").unwrap());
            let rows = stmt.query_map([], |row| {
                Ok(Note {
                    id:        row.get::<_, i64>(0)?,
                    vaddr:     row.get::<_, Option<String>>(1)?
                                  .as_deref()
                                  .map(parse_vaddr),
                    text:      row.get::<_, String>(2)?,
                    timestamp: row.get::<_, String>(3)?,
                })
            });
            if let Ok(rows) = rows {
                p.notes = rows.flatten().collect();
            }
        }

        Ok(p)
    }

    fn load_from_json(path: &PathBuf) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<Project>(&s).ok())
            .unwrap_or_default()
    }

    fn init_schema(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Persist to the SQLite database.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .db_path_field
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No database path set"))?;

        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;

        // Clear and rewrite (simple; fine for project sizes we handle)
        conn.execute_batch("
            DELETE FROM renames;
            DELETE FROM comments;
            DELETE FROM var_renames;
            DELETE FROM signatures;
            DELETE FROM structs;
            DELETE FROM vuln_scores;
        ")?;

        for (vaddr, name) in &self.renames {
            conn.execute(
                "INSERT INTO renames (vaddr, name) VALUES (?1, ?2)",
                params![vaddr_key(*vaddr), name],
            )?;
        }
        for (vaddr, text) in &self.comments {
            conn.execute(
                "INSERT INTO comments (vaddr, text) VALUES (?1, ?2)",
                params![vaddr_key(*vaddr), text],
            )?;
        }
        for (fn_vaddr, renames) in &self.var_renames {
            for (old, new) in renames {
                conn.execute(
                    "INSERT INTO var_renames (fn_vaddr, old_name, new_name) VALUES (?1, ?2, ?3)",
                    params![vaddr_key(*fn_vaddr), old, new],
                )?;
            }
        }
        for (fn_vaddr, sig) in &self.signatures {
            let data = serde_json::to_string(sig)?;
            conn.execute(
                "INSERT INTO signatures (fn_vaddr, data) VALUES (?1, ?2)",
                params![vaddr_key(*fn_vaddr), data],
            )?;
        }
        for (name, def) in &self.structs {
            let data = serde_json::to_string(def)?;
            conn.execute(
                "INSERT INTO structs (name, data) VALUES (?1, ?2)",
                params![name, data],
            )?;
        }
        for (vaddr, score) in &self.vuln_scores {
            conn.execute(
                "INSERT INTO vuln_scores (vaddr, score) VALUES (?1, ?2)",
                params![vaddr_key(*vaddr), *score as i64],
            )?;
        }
        // Notes are NOT cleared/rewritten on save — they are appended individually
        // via add_note() to preserve auto-increment IDs.

        Ok(())
    }

    // ── Notes ────────────────────────────────────────────────────────────────

    /// Append a new analyst note and persist it to SQLite immediately.
    /// Returns the new note (with the auto-assigned id and timestamp).
    pub fn add_note(&mut self, vaddr: Option<u64>, text: String) -> anyhow::Result<Note> {
        let path = self
            .db_path_field
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No database path set"))?;
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;
        let vaddr_str = vaddr.map(|v| vaddr_key(v));
        conn.execute(
            "INSERT INTO notes (vaddr, text) VALUES (?1, ?2)",
            params![vaddr_str, &text],
        )?;
        let id = conn.last_insert_rowid();
        let timestamp: String = conn
            .query_row("SELECT timestamp FROM notes WHERE id = ?1", params![id], |r| r.get(0))
            .unwrap_or_else(|_| "unknown".to_string());
        let note = Note { id, vaddr, text, timestamp };
        self.notes.push(note.clone());
        Ok(note)
    }

    /// Delete a note by its id. Returns true if a row was deleted.
    pub fn delete_note(&mut self, id: i64) -> anyhow::Result<bool> {
        let path = self
            .db_path_field
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No database path set"))?;
        let conn = Connection::open(path)?;
        let deleted = conn.execute("DELETE FROM notes WHERE id = ?1", params![id])? > 0;
        self.notes.retain(|n| n.id != id);
        Ok(deleted)
    }

    // ── Mutations ────────────────────────────────────────────────────────────

    pub fn rename(&mut self, vaddr: u64, name: String) {
        self.renames.insert(vaddr, name);
    }

    pub fn comment(&mut self, vaddr: u64, text: String) {
        self.comments.insert(vaddr, text);
    }

    /// Rename a local variable inside a specific function.
    pub fn rename_var(&mut self, fn_vaddr: u64, old_name: String, new_name: String) {
        self.var_renames
            .entry(fn_vaddr)
            .or_default()
            .insert(old_name, new_name);
    }

    /// Set the return type for a function.
    pub fn set_return_type(&mut self, fn_vaddr: u64, type_str: String) {
        self.signatures
            .entry(fn_vaddr)
            .or_default()
            .return_type = Some(type_str);
    }

    /// Set the type of the N-th parameter (1-indexed, matching arg_1, arg_2, …).
    pub fn set_param_type(&mut self, fn_vaddr: u64, param_n: usize, type_str: String) {
        let sig = self.signatures.entry(fn_vaddr).or_default();
        let idx = param_n.saturating_sub(1);
        if sig.param_types.len() <= idx {
            sig.param_types.resize(idx + 1, None);
        }
        sig.param_types[idx] = Some(type_str);
    }

    /// Set the name of the N-th parameter (1-indexed).
    pub fn set_param_name(&mut self, fn_vaddr: u64, param_n: usize, name: String) {
        let sig = self.signatures.entry(fn_vaddr).or_default();
        let idx = param_n.saturating_sub(1);
        if sig.param_names.len() <= idx {
            sig.param_names.resize(idx + 1, None);
        }
        sig.param_names[idx] = Some(name);
    }

    /// Define or replace a struct.
    pub fn define_struct(&mut self, def: StructDef) {
        self.structs.insert(def.name.clone(), def);
    }

    /// Set or update the vulnerability suspicion score for a function (0 = clean, 10 = critical).
    pub fn set_vuln_score(&mut self, vaddr: u64, score: u8) {
        self.vuln_scores.insert(vaddr, score.min(10));
    }

    // ── Lookups ──────────────────────────────────────────────────────────────

    pub fn get_name(&self, vaddr: u64) -> Option<String> {
        self.renames.get(&vaddr).cloned()
    }

    pub fn get_comment(&self, vaddr: u64) -> Option<&str> {
        self.comments.get(&vaddr).map(|s| s.as_str())
    }

    pub fn get_signature(&self, fn_vaddr: u64) -> Option<&FunctionSignature> {
        self.signatures.get(&fn_vaddr)
    }

    pub fn get_vuln_score(&self, vaddr: u64) -> Option<u8> {
        self.vuln_scores.get(&vaddr).copied()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bin_path() -> String {
        format!(
            "/tmp/kaijulab_test_{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        )
    }

    // ── project_path derivation ───────────────────────────────────────────────

    #[test]
    fn project_path_adds_kaiju_json() {
        assert_eq!(
            Project::project_path("/tmp/mybinary"),
            PathBuf::from("/tmp/mybinary.kaiju.json")
        );
    }

    #[test]
    fn db_path_adds_kaiju_db() {
        assert_eq!(
            Project::db_path("/tmp/mybinary"),
            PathBuf::from("/tmp/mybinary.kaiju.db")
        );
    }

    #[test]
    fn project_path_preserves_existing_extension() {
        assert_eq!(
            Project::project_path("/home/user/crackme.elf"),
            PathBuf::from("/home/user/crackme.elf.kaiju.json")
        );
    }

    // ── rename / comment ─────────────────────────────────────────────────────

    #[test]
    fn rename_and_lookup() {
        let mut p = Project::default();
        p.rename(0x401000, "main".to_string());
        assert_eq!(p.get_name(0x401000), Some("main".to_string()));
        assert_eq!(p.get_name(0x401001), None);
    }

    #[test]
    fn rename_overwrites_previous() {
        let mut p = Project::default();
        p.rename(0x401000, "old".to_string());
        p.rename(0x401000, "new".to_string());
        assert_eq!(p.get_name(0x401000), Some("new".to_string()));
    }

    #[test]
    fn comment_and_lookup() {
        let mut p = Project::default();
        p.comment(0x401010, "sets up stack frame".to_string());
        assert_eq!(p.get_comment(0x401010), Some("sets up stack frame"));
        assert_eq!(p.get_comment(0xdeadbeef), None);
    }

    // ── variable renames ─────────────────────────────────────────────────────

    #[test]
    fn var_rename_stored_per_function() {
        let mut p = Project::default();
        p.rename_var(0x401000, "arg_1".to_string(), "buf".to_string());
        p.rename_var(0x401000, "arg_2".to_string(), "len".to_string());
        p.rename_var(0x402000, "arg_1".to_string(), "fd".to_string());

        assert_eq!(p.var_renames[&0x401000]["arg_1"], "buf");
        assert_eq!(p.var_renames[&0x401000]["arg_2"], "len");
        assert_eq!(p.var_renames[&0x402000]["arg_1"], "fd");
        assert!(!p.var_renames[&0x402000].contains_key("arg_2"));
    }

    // ── signatures ───────────────────────────────────────────────────────────

    #[test]
    fn set_and_get_return_type() {
        let mut p = Project::default();
        p.set_return_type(0x401000, "int".to_string());
        assert_eq!(
            p.get_signature(0x401000).and_then(|s| s.return_type.as_deref()),
            Some("int")
        );
    }

    #[test]
    fn set_param_type_one_indexed() {
        let mut p = Project::default();
        p.set_param_type(0x401000, 1, "const char*".to_string());
        p.set_param_type(0x401000, 2, "size_t".to_string());
        let sig = p.get_signature(0x401000).unwrap();
        assert_eq!(sig.param_types[0].as_deref(), Some("const char*"));
        assert_eq!(sig.param_types[1].as_deref(), Some("size_t"));
    }

    #[test]
    fn set_param_type_sparse_no_panic() {
        let mut p = Project::default();
        p.set_param_type(0x401000, 3, "int".to_string());
        let sig = p.get_signature(0x401000).unwrap();
        assert_eq!(sig.param_types.len(), 3);
        assert!(sig.param_types[0].is_none());
        assert!(sig.param_types[1].is_none());
        assert_eq!(sig.param_types[2].as_deref(), Some("int"));
    }

    #[test]
    fn set_param_name_one_indexed() {
        let mut p = Project::default();
        p.set_param_name(0x401000, 1, "url".to_string());
        p.set_param_name(0x401000, 2, "url_len".to_string());
        let sig = p.get_signature(0x401000).unwrap();
        assert_eq!(sig.param_names[0].as_deref(), Some("url"));
        assert_eq!(sig.param_names[1].as_deref(), Some("url_len"));
    }

    // ── vuln scores ──────────────────────────────────────────────────────────

    #[test]
    fn vuln_score_clamp() {
        let mut p = Project::default();
        p.set_vuln_score(0x401000, 255); // clamped to 10
        assert_eq!(p.get_vuln_score(0x401000), Some(10));
        p.set_vuln_score(0x401000, 7);
        assert_eq!(p.get_vuln_score(0x401000), Some(7));
        assert_eq!(p.get_vuln_score(0x999999), None);
    }

    // ── struct definitions ───────────────────────────────────────────────────

    #[test]
    fn define_and_retrieve_struct() {
        let mut p = Project::default();
        p.define_struct(StructDef {
            name: "node".to_string(),
            total_size: 16,
            fields: vec![
                StructField { offset: 0,  size: 8, name: "next".to_string(),  type_str: "struct node*".to_string() },
                StructField { offset: 8,  size: 4, name: "value".to_string(), type_str: "int32_t".to_string() },
                StructField { offset: 12, size: 4, name: "flags".to_string(), type_str: "uint32_t".to_string() },
            ],
        });
        assert!(p.structs.contains_key("node"));
        assert_eq!(p.structs["node"].total_size, 16);
        assert_eq!(p.structs["node"].fields.len(), 3);
    }

    #[test]
    fn struct_overwrite() {
        let mut p = Project::default();
        p.define_struct(StructDef { name: "s".to_string(), total_size: 4, fields: vec![] });
        p.define_struct(StructDef { name: "s".to_string(), total_size: 8, fields: vec![] });
        assert_eq!(p.structs["s"].total_size, 8);
    }

    #[test]
    fn struct_field_at_offset() {
        let def = StructDef {
            name: "s".to_string(),
            total_size: 8,
            fields: vec![
                StructField { offset: 0, size: 4, name: "a".to_string(), type_str: "int".to_string() },
                StructField { offset: 4, size: 4, name: "b".to_string(), type_str: "int".to_string() },
            ],
        };
        assert_eq!(def.field_at(0).map(|f| f.name.as_str()), Some("a"));
        assert_eq!(def.field_at(3).map(|f| f.name.as_str()), Some("a"));
        assert_eq!(def.field_at(4).map(|f| f.name.as_str()), Some("b"));
        assert!(def.field_at(8).is_none());
    }

    #[test]
    fn struct_to_c_format() {
        let def = StructDef {
            name: "point".to_string(),
            total_size: 8,
            fields: vec![
                StructField { offset: 0, size: 4, name: "x".to_string(), type_str: "int".to_string() },
                StructField { offset: 4, size: 4, name: "y".to_string(), type_str: "int".to_string() },
            ],
        };
        let c = def.to_c();
        assert!(c.starts_with("struct point {"));
        assert!(c.contains("int x;"));
        assert!(c.contains("int y;"));
        assert!(c.trim_end().ends_with("};"));
    }

    // ── save / load roundtrip (SQLite) ───────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let bin = fake_bin_path();
        let db = Project::db_path(&bin);

        {
            let mut p = Project::load_for(&bin);
            p.rename(0x401000, "main".to_string());
            p.comment(0x401010, "prologue".to_string());
            p.rename_var(0x401000, "arg_1".to_string(), "argc".to_string());
            p.set_return_type(0x401000, "int".to_string());
            p.set_param_type(0x401000, 1, "int".to_string());
            p.set_param_name(0x401000, 1, "argc".to_string());
            p.set_vuln_score(0x401000, 8);
            p.define_struct(StructDef {
                name: "ctx".to_string(),
                total_size: 8,
                fields: vec![StructField {
                    offset: 0, size: 8,
                    name: "ptr".to_string(),
                    type_str: "void*".to_string(),
                }],
            });
            p.save().expect("save failed");
        }

        assert!(db.exists(), "database file should have been created");

        let p2 = Project::load_for(&bin);
        assert_eq!(p2.get_name(0x401000), Some("main".to_string()));
        assert_eq!(p2.get_comment(0x401010), Some("prologue"));
        assert_eq!(p2.var_renames[&0x401000]["arg_1"], "argc");
        assert_eq!(
            p2.get_signature(0x401000).and_then(|s| s.return_type.as_deref()),
            Some("int")
        );
        assert_eq!(
            p2.get_signature(0x401000).and_then(|s| s.param_types[0].as_deref()),
            Some("int")
        );
        assert!(p2.structs.contains_key("ctx"));
        assert_eq!(p2.get_vuln_score(0x401000), Some(8));

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let p = Project::load_for("/tmp/definitely_does_not_exist_kaijulab.bin");
        assert!(p.renames.is_empty());
        assert!(p.comments.is_empty());
        assert!(p.var_renames.is_empty());
        assert!(p.signatures.is_empty());
        assert!(p.structs.is_empty());
        assert!(p.vuln_scores.is_empty());
    }
}
