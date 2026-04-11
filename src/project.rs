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
        // Setting param 3 without setting 1 or 2 must not panic
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
        assert_eq!(def.field_at(3).map(|f| f.name.as_str()), Some("a")); // still inside field a
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

    // ── save / load roundtrip ────────────────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let bin = fake_bin_path();
        let sidecar = Project::project_path(&bin);

        {
            let mut p = Project::load_for(&bin);
            p.rename(0x401000, "main".to_string());
            p.comment(0x401010, "prologue".to_string());
            p.rename_var(0x401000, "arg_1".to_string(), "argc".to_string());
            p.set_return_type(0x401000, "int".to_string());
            p.set_param_type(0x401000, 1, "int".to_string());
            p.set_param_name(0x401000, 1, "argc".to_string());
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

        assert!(sidecar.exists(), "sidecar file should have been created");

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

        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let p = Project::load_for("/tmp/definitely_does_not_exist_kaijulab.bin");
        assert!(p.renames.is_empty());
        assert!(p.comments.is_empty());
        assert!(p.var_renames.is_empty());
        assert!(p.signatures.is_empty());
        assert!(p.structs.is_empty());
    }
}
