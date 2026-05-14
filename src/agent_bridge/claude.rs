//! Optional `claude -p` adapter for schema-bound, non-interactive bridge jobs.
//!
//! This path is disabled by default because `claude -p` is moving behind a
//! paid/API-backed feature gate. KaijuLab should prefer the embedded
//! interactive Claude Code console or prompt-pack workflows unless a user
//! explicitly opts into this adapter.

use std::time::Duration;

use anyhow::{anyhow, Result};

use super::scope::ContextPack;

#[derive(Debug, Clone, Default)]
pub struct ClaudeAdapter {
    /// Optional path to the `claude` binary.  Defaults to PATH lookup.
    pub binary: Option<std::path::PathBuf>,
    pub timeout_secs: Option<u64>,
}

impl ClaudeAdapter {
    pub async fn run(&self, prompt: &str, pack: &ContextPack) -> Result<String> {
        if std::env::var("KAIJULAB_ENABLE_CLAUDE_P").ok().as_deref() != Some("1") {
            return Err(anyhow!(
                "claude -p adapter is disabled by default; use the interactive Agent Console or set KAIJULAB_ENABLE_CLAUDE_P=1 to opt in"
            ));
        }
        let full_prompt = bridge_prompt(prompt, pack);
        let timeout = Duration::from_secs(super::timeout_secs(120, self.timeout_secs));
        let permission_mode = std::env::var("KAIJULAB_AGENT_PERMISSION_MODE")
            .unwrap_or_else(|_| "dontAsk".to_string());
        let args = [
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--permission-mode",
            permission_mode.as_str(),
        ];
        let out =
            super::run_with_stdin(self.binary.as_ref(), "claude", &args, &full_prompt, timeout)
                .await?;
        Ok(super::final_text_from_jsonish(&out))
    }
}

fn bridge_prompt(prompt: &str, pack: &ContextPack) -> String {
    format!(
        "{prompt}\n\nContext pack JSON:\n{}\n\nReturn only the requested output shape.",
        serde_json::to_string_pretty(pack).unwrap_or_default()
    )
}
