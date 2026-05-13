//! `claude -p` adapter for schema-bound, non-interactive bridge jobs.

use std::time::Duration;

use anyhow::Result;

use super::scope::ContextPack;

#[derive(Debug, Clone, Default)]
pub struct ClaudeAdapter {
    /// Optional path to the `claude` binary.  Defaults to PATH lookup.
    pub binary: Option<std::path::PathBuf>,
    pub timeout_secs: Option<u64>,
}

impl ClaudeAdapter {
    pub async fn run(&self, prompt: &str, pack: &ContextPack) -> Result<String> {
        let full_prompt = bridge_prompt(prompt, pack);
        let timeout = Duration::from_secs(super::timeout_secs(120, self.timeout_secs));
        let out = super::run_with_stdin(
            self.binary.as_ref(),
            "claude",
            &[
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--include-partial-messages",
                "--permission-mode",
                "dontAsk",
            ],
            &full_prompt,
            timeout,
        )
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
