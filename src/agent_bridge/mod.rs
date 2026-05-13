//! Local CLI bridges to the user's existing Claude Code and Codex installs.
//!
//! Scope: schema-bound, non-interactive jobs only.  Interactive analysis is
//! the user's primary Claude Code session driving KaijuLab through MCP.

pub mod claude;
pub mod codex;
pub mod prompts;
pub mod scope;

use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::{anyhow, Context, Result};
use tokio::{io::AsyncWriteExt, process::Command};

pub use scope::WritePolicy;

fn timeout_secs(default: u64, override_secs: Option<u64>) -> u64 {
    override_secs
        .or_else(|| {
            std::env::var("KAIJULAB_AGENT_TIMEOUT")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
        })
        .unwrap_or(default)
        .clamp(5, 900)
}

async fn run_with_stdin(
    binary: Option<&PathBuf>,
    program: &str,
    args: &[&str],
    stdin: &str,
    timeout: Duration,
) -> Result<String> {
    let exe = binary
        .map(|p| p.as_os_str().to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from(program));
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {}", program))?;

    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin
            .write_all(stdin.as_bytes())
            .await
            .with_context(|| format!("failed to write prompt to {}", program))?;
    }

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| anyhow!("{} timed out after {}s", program, timeout.as_secs()))?
        .with_context(|| format!("{} failed", program))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(anyhow!(
            "{} exited with {}: {}",
            program,
            output.status,
            stderr.trim()
        ));
    }
    if stdout.trim().is_empty() && !stderr.trim().is_empty() {
        Ok(stderr)
    } else {
        Ok(stdout)
    }
}

fn final_text_from_jsonish(output: &str) -> String {
    let mut final_text = String::new();
    for line in output.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(s) = v.get("result").and_then(|v| v.as_str()) {
            final_text = s.to_string();
        } else if let Some(s) = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
        {
            final_text.push_str(s);
        } else if let Some(s) = v.get("delta").and_then(|v| v.as_str()) {
            final_text.push_str(s);
        } else if let Some(s) = v.get("text").and_then(|v| v.as_str()) {
            final_text.push_str(s);
        }
    }
    if final_text.trim().is_empty() {
        output.trim().to_string()
    } else {
        final_text
    }
}
