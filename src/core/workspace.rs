//! Workspace — the active binary plus shared state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::project::Project;

use super::events::EventBus;

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

// ─── Workspace registry ──────────────────────────────────────────────────────

/// Holds every workspace the daemon has opened, plus a server-wide notion of
/// which one is "active" for routes that don't specify a workspace explicitly.
#[derive(Clone)]
pub struct WorkspaceRegistry {
    inner: Arc<RwLock<RegistryInner>>,
    bus: EventBus,
    policy: WritePolicy,
}

struct RegistryInner {
    workspaces: HashMap<String, Workspace>,
    active: Option<String>,
}

/// Snapshot for `GET /api/workspaces`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct RegistrySnapshot {
    pub active: Option<String>,
    pub workspaces: Vec<WorkspaceInfo>,
}

impl WorkspaceRegistry {
    pub fn new(bus: EventBus, policy: WritePolicy) -> Self {
        WorkspaceRegistry {
            inner: Arc::new(RwLock::new(RegistryInner {
                workspaces: HashMap::new(),
                active: None,
            })),
            bus,
            policy,
        }
    }

    pub fn policy(&self) -> WritePolicy {
        self.policy
    }

    /// Open a binary as a workspace.  Re-opens the same binary are idempotent
    /// (returns the existing Workspace).  Marks the new workspace as active.
    /// The caller is responsible for spawning the per-workspace Unix socket
    /// via `spawn_socket_listener` below.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<Workspace> {
        let ws = Workspace::open(path, self.policy)?;
        let hash = ws.workspace_hash().to_string();
        let mut g = self.inner.write().unwrap();
        let entry = g.workspaces.entry(hash.clone()).or_insert_with(|| ws.clone()).clone();
        g.active = Some(hash);
        // Best-effort: append to recent-files list.
        let path_str = entry.binary_path_str();
        drop(g);
        let _ = append_recent(&path_str);
        Ok(entry)
    }

    pub fn close(&self, hash: &str) -> bool {
        let mut g = self.inner.write().unwrap();
        let removed = g.workspaces.remove(hash).is_some();
        if g.active.as_deref() == Some(hash) {
            g.active = g.workspaces.keys().next().cloned();
        }
        // Tear down the per-workspace socket file (the listener task exits
        // because the listener was bound to a path that no longer exists once
        // we remove it; in practice the task will error and respawn on next
        // open).
        if let Ok(p) = socket_path_for(hash) {
            let _ = std::fs::remove_file(p);
        }
        removed
    }

    pub fn activate(&self, hash: &str) -> bool {
        let mut g = self.inner.write().unwrap();
        if g.workspaces.contains_key(hash) {
            g.active = Some(hash.to_string());
            true
        } else {
            false
        }
    }

    pub fn active(&self) -> Option<Workspace> {
        let g = self.inner.read().unwrap();
        g.active.as_deref().and_then(|h| g.workspaces.get(h)).cloned()
    }

    pub fn get(&self, hash: &str) -> Option<Workspace> {
        self.inner.read().unwrap().workspaces.get(hash).cloned()
    }

    pub fn snapshot(&self) -> RegistrySnapshot {
        let g = self.inner.read().unwrap();
        let mut workspaces: Vec<WorkspaceInfo> = g.workspaces.values().map(|w| w.info()).collect();
        workspaces.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        RegistrySnapshot {
            active: g.active.clone(),
            workspaces,
        }
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }
}

// ─── Recent files ────────────────────────────────────────────────────────────

pub fn recent_files_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".kaiju").join("recent.json"))
}

pub fn read_recent() -> Vec<String> {
    let Ok(path) = recent_files_path() else {
        return Vec::new();
    };
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

fn append_recent(path: &str) -> Result<()> {
    let p = recent_files_path()?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut list = read_recent();
    list.retain(|x| x != path);
    list.insert(0, path.to_string());
    list.truncate(16);
    std::fs::write(&p, serde_json::to_string_pretty(&list)?)?;
    Ok(())
}
