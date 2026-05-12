//! Workspace — the active binary plus shared state.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::project::Project;

/// Permissions flags the daemon was launched with.  MCP write-tools consult
/// these before dispatching dangerous operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritePolicy {
    pub allow_patch: bool,
    pub allow_exec: bool,
}

#[derive(Clone)]
pub struct Workspace {
    inner: Arc<WorkspaceInner>,
}

struct WorkspaceInner {
    binary_path: PathBuf,
    binary_hash: String,
    display_name: String,
    project: Mutex<Project>,
    policy: WritePolicy,
}

/// JSON snapshot of workspace metadata returned by `GET /api/workspace`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct WorkspaceInfo {
    pub binary_path: String,
    pub display_name: String,
    pub workspace_hash: String,
    pub allow_patch: bool,
    pub allow_exec: bool,
}

impl Workspace {
    pub fn open(path: impl AsRef<Path>, policy: WritePolicy) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            anyhow::bail!("binary path does not exist: {}", path.display());
        }
        let binary_hash = hash_path(&path);
        let display_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let project = Project::load_for(&path.to_string_lossy());
        Ok(Workspace {
            inner: Arc::new(WorkspaceInner {
                binary_path: path,
                binary_hash,
                display_name,
                project: Mutex::new(project),
                policy,
            }),
        })
    }

    pub fn binary_path(&self) -> &Path {
        &self.inner.binary_path
    }

    pub fn binary_path_str(&self) -> String {
        self.inner.binary_path.to_string_lossy().into_owned()
    }

    pub fn workspace_hash(&self) -> &str {
        &self.inner.binary_hash
    }

    pub fn display_name(&self) -> &str {
        &self.inner.display_name
    }

    pub fn policy(&self) -> WritePolicy {
        self.inner.policy
    }

    pub fn info(&self) -> WorkspaceInfo {
        WorkspaceInfo {
            binary_path: self.binary_path_str(),
            display_name: self.display_name().to_string(),
            workspace_hash: self.workspace_hash().to_string(),
            allow_patch: self.inner.policy.allow_patch,
            allow_exec: self.inner.policy.allow_exec,
        }
    }

    /// Acquire a lock on the project state for read or write.  Callers should
    /// drop the guard before doing any blocking work.
    pub fn with_project<R>(&self, f: impl FnOnce(&mut Project) -> R) -> R {
        let mut guard = self.inner.project.lock().expect("project mutex poisoned");
        f(&mut guard)
    }

    /// Persist the project to its SQLite DB.
    pub fn save_project(&self) -> Result<()> {
        let guard = self.inner.project.lock().expect("project mutex poisoned");
        guard.save()
    }
}

fn hash_path(path: &Path) -> String {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8]) // 16 hex chars — short, collision-free in practice
}

/// Directory holding per-workspace Unix sockets and runtime state.
pub fn runtime_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = PathBuf::from(home).join(".kaiju").join("run");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Unix-socket path for a given workspace hash.
pub fn socket_path_for(hash: &str) -> Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("{}.sock", hash)))
}
