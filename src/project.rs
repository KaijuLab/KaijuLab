//! Persistent project sidecar — stores renames, comments, type annotations,
//! and struct definitions across sessions.
//!
//! The sidecar lives at `<binary>.kaiju.json` next to the binary.
//! All data is plain JSON — human-readable and diff-friendly.

use std::collections::HashMap;
use std::path::PathBuf;

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
    ///
    /// Keys are the names as they appear in decompiler output *before* this
    /// project's substitutions are applied (e.g. "RAX", "var_1", "arg_1").
    pub var_renames: HashMap<u64, HashMap<String, String>>,
    /// fn_vaddr → signature (return type + param types/names)
    pub signatures: HashMap<u64, FunctionSignature>,
    /// Named struct definitions, keyed by struct name.
    pub structs: HashMap<String, StructDef>,
    /// The path to the sidecar file (not serialized).
    #[serde(skip)]
    pub sidecar_path: Option<PathBuf>,
}

impl Project {
    // ── Persistence ──────────────────────────────────────────────────────────

    /// Derive the sidecar path for a given binary path.
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

    /// Load the project for a binary, or return an empty project if no sidecar exists.
    pub fn load_for(binary: &str) -> Self {
        let path = Self::project_path(binary);
        if !path.exists() {
            return Self {
                sidecar_path: Some(path),
                ..Default::default()
            };
        }
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let mut p: Project = serde_json::from_str(&s).unwrap_or_default();
                p.sidecar_path = Some(path);
                p
            }
            Err(_) => Self {
                sidecar_path: Some(path),
                ..Default::default()
            },
        }
    }

    /// Persist to the sidecar file.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .sidecar_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No sidecar path set"))?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
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
}
