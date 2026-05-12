//! `claude -p --output-format=stream-json` adapter (skeleton).
//!
//! The full implementation parses streaming JSON, captures session IDs for
//! retry/continue, and emits `agent.delta` events.  PR #1 wires the interface
//! and returns a NotImplemented stub so the REST endpoint shape is locked in.

use anyhow::{anyhow, Result};

use super::scope::ContextPack;

#[derive(Debug, Clone, Default)]
pub struct ClaudeAdapter {
    /// Optional path to the `claude` binary.  Defaults to PATH lookup.
    pub binary: Option<std::path::PathBuf>,
    pub timeout_secs: Option<u64>,
}

impl ClaudeAdapter {
    pub async fn run(&self, _prompt: &str, _pack: &ContextPack) -> Result<String> {
        Err(anyhow!(
            "claude bridge not yet implemented; configure `claude` CLI and pass --enable-bridge to serve"
        ))
    }
}
