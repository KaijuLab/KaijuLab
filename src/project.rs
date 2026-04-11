//! Persistent project sidecar — stores renames and comments across sessions.
//!
//! The sidecar file lives at `<binary>.kaiju.json` next to the binary.
//! All data is plain JSON so it's human-readable and diff-friendly.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Project {
    /// Virtual address → user-assigned name.
    pub renames: HashMap<u64, String>,
    /// Virtual address → analyst comment.
    pub comments: HashMap<u64, String>,
    /// The path to the sidecar file (not serialized).
    #[serde(skip)]
    pub sidecar_path: Option<PathBuf>,
}

impl Project {
    /// Derive the sidecar path for a given binary path.
    pub fn project_path(binary: &str) -> PathBuf {
        let mut p = PathBuf::from(binary);
        let name = p
            .file_name()
            .map(|n| format!("{}.kaiju.json", n.to_string_lossy()))
            .unwrap_or_else(|| "binary.kaiju.json".to_string());
        p.pop();
        p.push(name);
        p
    }

    /// Load the project for a binary, or return an empty project if the file doesn't exist.
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

    /// Store or overwrite a name for a virtual address.
    pub fn rename(&mut self, vaddr: u64, name: String) {
        self.renames.insert(vaddr, name);
    }

    /// Store or overwrite a comment for a virtual address.
    pub fn comment(&mut self, vaddr: u64, text: String) {
        self.comments.insert(vaddr, text);
    }

    /// Look up a user-defined name for a virtual address.
    pub fn get_name(&self, vaddr: u64) -> Option<String> {
        self.renames.get(&vaddr).cloned()
    }

    /// Look up a user-defined comment for a virtual address.
    pub fn get_comment(&self, vaddr: u64) -> Option<&str> {
        self.comments.get(&vaddr).map(|s| s.as_str())
    }
}

// Ensure the `sidecar_path` field is skipped during comparison in tests
impl PartialEq for Project {
    fn eq(&self, other: &Self) -> bool {
        self.renames == other.renames && self.comments == other.comments
    }
}
