//! `codex exec --json` adapter (skeleton).  See claude.rs for status.

use anyhow::{anyhow, Result};

use super::scope::ContextPack;

#[derive(Debug, Clone, Default)]
pub struct CodexAdapter {
    pub binary: Option<std::path::PathBuf>,
    pub timeout_secs: Option<u64>,
}

impl CodexAdapter {
    pub async fn run(&self, _prompt: &str, _pack: &ContextPack) -> Result<String> {
        Err(anyhow!(
            "codex bridge not yet implemented; configure `codex` CLI and pass --enable-bridge to serve"
        ))
    }
}
