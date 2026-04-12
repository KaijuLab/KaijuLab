use std::collections::HashMap;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::llm::{LlmBackend, LlmMessage, ToolResult};
use crate::tools;
use crate::ui;

// ─── Events sent to the TUI ──────────────────────────────────────────────────

/// Events the agent emits so the TUI can update its panels in real time.
/// When no channel is attached (one-shot / plain-text mode) these are never
/// created — the agent falls back to the `ui::print_*` functions instead.
/// Lightweight summary of one message in the LLM history, for the Context tab.
#[derive(Debug, Clone)]
pub struct ContextEntry {
    pub role: &'static str,   // "user" | "assistant"
    pub kind: &'static str,   // "text" | "tool_call" | "tool_result"
    pub tool_name: Option<String>,
    pub char_count: usize,
    pub preview: String,      // first ~100 chars of content
}

#[derive(Debug)]
pub enum AgentEvent {
    /// LLM is generating a response.
    Thinking,
    /// LLM issued a tool call.
    ToolCall { name: String, display_args: String },
    /// Tool finished; `output` is the full result string.
    ToolResult { name: String, output: String },
    /// LLM produced a final text response (non-streaming fallback or after streaming).
    LlmText(String),
    /// A single streaming text chunk from the LLM (partial response).
    LlmTextChunk(String),
    /// Agent turn is complete.
    Done,
    /// API or tool error.
    Error(String),
    /// The agent is actively examining a virtual address.
    /// The TUI uses this to highlight and scroll to the address.
    Focus { vaddr: u64, tool: String },
    /// Snapshot of the current LLM context window, for the Context tab.
    ContextUpdate(Vec<ContextEntry>),
    /// Updated vulnerability scores from a scan_vulnerabilities / set_vuln_score run.
    /// Maps fn_vaddr → score (0–10). TUI uses these for [!] badges in Functions tab.
    VulnScores(HashMap<u64, u8>),
}

/// Estimated character budget before we start trimming old tool-result messages.
/// ~80 K chars ≈ 20 K tokens, comfortable headroom under typical 128 K limits.
const MAX_HISTORY_CHARS: usize = 80_000;

/// Replace the oldest tool-result messages with compact summaries until the total
/// estimated character count falls below `MAX_HISTORY_CHARS`.
/// Plain user/assistant text is never dropped so the conversation thread stays coherent.
/// Summaries are injected as user messages so the LLM knows what data was seen,
/// even though the full output is gone.
fn trim_history(history: &mut Vec<crate::llm::LlmMessage>) {
    loop {
        let total: usize = history.iter().map(|m| m.estimated_chars()).sum();
        if total <= MAX_HISTORY_CHARS {
            break;
        }
        if let Some(pos) = history.iter().position(|m| m.is_tool_result_message()) {
            let summary = summarize_tool_result_msg(&history[pos]);
            history[pos] = crate::llm::LlmMessage::user_text(summary);
        } else {
            break; // nothing left to compress
        }
    }
}

/// Build a compact summary of a tool-result message so the LLM retains
/// awareness of what was found without the full output consuming context budget.
fn summarize_tool_result_msg(msg: &crate::llm::LlmMessage) -> String {
    use crate::llm::MessageContent;
    let parts: Vec<String> = msg.content.iter().filter_map(|c| {
        if let MessageContent::ToolResult(tr) = c {
            let lines = tr.content.lines().count();
            // Keep the first 3 non-empty lines as a preview
            let preview: String = tr.content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ");
            let preview = if preview.len() > 300 {
                format!("{}…", &preview[..300])
            } else {
                preview
            };
            Some(format!(
                "[context-compressed] Previously called `{}` ({} lines). Preview: {}",
                tr.name, lines, preview
            ))
        } else {
            None
        }
    }).collect();
    parts.join("\n")
}

const SYSTEM_PROMPT: &str = "\
You are KaijuLab, an expert reverse-engineering assistant. \
You analyse binary files using the tools available to you. \
Start with file_info to understand the file format, then use other tools \
to dig deeper as needed. Be precise, technical, and explain your reasoning \
step by step. When you encounter addresses or offsets, prefer the \
disassemble tool to verify what the code actually does.";

static LOADED_SYSTEM_PROMPT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Load the system prompt from `~/.kaiju/system_prompt.md` if it exists,
/// otherwise fall back to the built-in constant.
fn load_system_prompt() -> &'static str {
    LOADED_SYSTEM_PROMPT.get_or_init(|| {
        if let Some(home) = std::env::var_os("HOME") {
            let path = std::path::Path::new(&home).join(".kaiju").join("system_prompt.md");
            if let Ok(content) = std::fs::read_to_string(&path) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
        SYSTEM_PROMPT.to_string()
    })
}

// ─── Agent ───────────────────────────────────────────────────────────────────

pub struct Agent {
    backend: Box<dyn LlmBackend>,
    tools: Vec<crate::llm::ToolDefinition>,
    history: Vec<LlmMessage>,
    event_tx: Option<mpsc::UnboundedSender<AgentEvent>>,
}

impl Agent {
    pub fn new(backend: Box<dyn LlmBackend>) -> Self {
        Agent {
            tools: tools::all_definitions(),
            backend,
            history: Vec::new(),
            event_tx: None,
        }
    }

    /// Collect all tool results and assistant text from history as structured JSON.
    /// Intended for `--output-json` one-shot mode.
    pub fn structured_output(&self, binary_path: &str) -> serde_json::Value {
        use crate::llm::MessageContent;
        use serde_json::{json, Value};

        let mut tool_results: std::collections::HashMap<String, Vec<Value>> =
            std::collections::HashMap::new();
        let mut conversation: Vec<Value> = Vec::new();

        for msg in &self.history {
            let role = match msg.role {
                crate::llm::MessageRole::User      => "user",
                crate::llm::MessageRole::Assistant => "assistant",
            };
            for content in &msg.content {
                match content {
                    MessageContent::Text(t) if !t.trim().is_empty() => {
                        conversation.push(json!({"role": role, "text": t}));
                    }
                    MessageContent::ToolCall(tc) => {
                        conversation.push(json!({
                            "role":    "tool_call",
                            "name":    tc.name,
                            "args":    tc.args,
                        }));
                    }
                    MessageContent::ToolResult(tr) => {
                        conversation.push(json!({
                            "role":   "tool_result",
                            "name":   tr.name,
                            "output": tr.content,
                        }));
                        tool_results
                            .entry(tr.name.clone())
                            .or_default()
                            .push(json!(tr.content));
                    }
                    _ => {}
                }
            }
        }

        // Final assistant text = last non-empty text from an assistant message
        let summary = self.history.iter().rev()
            .flat_map(|m| m.texts())
            .find(|t| !t.trim().is_empty())
            .map(|t| t.to_string());

        json!({
            "binary":       binary_path,
            "backend":      self.backend.display_name(),
            "tool_results": tool_results,
            "summary":      summary,
            "conversation": conversation,
        })
    }

    /// Attach a TUI event channel.  When set the agent emits `AgentEvent`s
    /// instead of calling `ui::print_*` functions.
    pub fn with_events(mut self, tx: mpsc::UnboundedSender<AgentEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    fn emit(&self, event: AgentEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    fn tui_mode(&self) -> bool {
        self.event_tx.is_some()
    }

    /// Run one user turn through the agentic loop.
    pub async fn run(&mut self, user_input: &str) -> Result<()> {
        self.history.push(LlmMessage::user_text(user_input));

        loop {
            // ── Trim history to stay within context budget ──────────────────
            trim_history(&mut self.history);

            // ── Snapshot the context window for the Context tab ─────────────
            self.emit(AgentEvent::ContextUpdate(snapshot_context(&self.history)));

            // ── Call the LLM ────────────────────────────────────────────────
            self.emit(AgentEvent::Thinking);
            let spinner = if !self.tui_mode() {
                Some(ui::new_spinner("Thinking…"))
            } else {
                None
            };

            let result = if self.tui_mode() {
                // In TUI mode: use streaming so text chunks appear incrementally.
                // The default generate_streaming just calls generate() with no chunks.
                // Real streaming backends will send chunks through chunk_tx.
                let (chunk_tx, chunk_rx) =
                    tokio::sync::mpsc::unbounded_channel::<String>();
                let backend_ref = self.backend.as_ref();
                let system = load_system_prompt();
                let event_tx_clone = self.event_tx.clone();

                // Spawn a task to forward chunks to the TUI
                let forward_task = tokio::spawn(async move {
                    let mut rx = chunk_rx;
                    while let Some(chunk) = rx.recv().await {
                        if let Some(tx) = &event_tx_clone {
                            let _ = tx.send(AgentEvent::LlmTextChunk(chunk));
                        }
                    }
                });

                // Run the streaming call (drops chunk_tx when it returns, closing the channel)
                let stream_result = backend_ref.generate_streaming(
                    system, &self.history, &self.tools, &chunk_tx
                ).await;
                drop(chunk_tx); // ensure receiver loop terminates

                // Wait for forward task to drain any buffered chunks
                let _ = forward_task.await;

                stream_result
            } else {
                self.backend
                    .generate(load_system_prompt(), &self.history, &self.tools)
                    .await
            };

            if let Some(s) = spinner {
                s.finish_and_clear();
            }

            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("API error: {}", e);
                    self.emit(AgentEvent::Error(msg.clone()));
                    if !self.tui_mode() {
                        ui::print_error(&msg);
                    }
                    self.history.pop(); // let the user retry
                    return Ok(());
                }
            };

            // ── Emit / print any inline text ────────────────────────────────
            // In TUI mode the text was already streamed via LlmTextChunk;
            // only emit LlmText for the non-streaming (plain-text) path.
            for text in response.texts() {
                if !text.trim().is_empty() {
                    if self.tui_mode() {
                        // Only emit LlmText if there were no streaming chunks
                        // (i.e. the default non-streaming backend was used).
                        // We can tell this if the backend's generate_streaming
                        // just fell through to generate() — but since we
                        // always forward chunk events, just emit LlmText
                        // only when NOT in streaming (no chunks sent).
                        // For simplicity: emit LlmText only in non-TUI path.
                    } else {
                        ui::print_agent_response(text);
                    }
                }
            }

            let tool_calls = response.tool_calls().into_iter().cloned().collect::<Vec<_>>();
            self.history.push(response);

            if tool_calls.is_empty() {
                self.emit(AgentEvent::Done);
                break;
            }

            // ── Execute tool calls ──────────────────────────────────────────
            let mut results: Vec<ToolResult> = Vec::new();
            for tc in &tool_calls {
                let display = args_display(&tc.args);

                // Emit a Focus event so the TUI can highlight the address
                if let Some(vaddr) = extract_focus_vaddr(&tc.name, &tc.args) {
                    self.emit(AgentEvent::Focus { vaddr, tool: tc.name.clone() });
                }

                if self.tui_mode() {
                    self.emit(AgentEvent::ToolCall {
                        name: tc.name.clone(),
                        display_args: display.clone(),
                    });
                } else {
                    ui::print_tool_call(&tc.name, &display);
                }

                let tool_out = tools::dispatch(&tc.name, &tc.args);

                if self.tui_mode() {
                    self.emit(AgentEvent::ToolResult {
                        name: tc.name.clone(),
                        output: tool_out.output.clone(),
                    });
                } else {
                    ui::print_tool_output(&tool_out.output);
                }

                // After set_vuln_score, reload the project and broadcast updated scores
                if tc.name == "set_vuln_score" {
                    if let Some(path) = tc.args["path"].as_str() {
                        let p = crate::project::Project::load_for(path);
                        self.emit(AgentEvent::VulnScores(p.vuln_scores.clone()));
                    }
                }

                results.push(ToolResult {
                    call_id: tc.id.clone(),
                    name: tc.name.clone(),
                    content: tool_out.output,
                });
            }

            self.history.push(LlmMessage::tool_results(results));
        }

        Ok(())
    }

    /// Remove and return the last user message from history, for retry.
    pub fn pop_last_user_message(&mut self) -> Option<String> {
        if let Some(pos) = self.history.iter().rposition(|m| m.role == crate::llm::MessageRole::User) {
            let msg = self.history.remove(pos);
            msg.texts().first().map(|s| s.to_string())
        } else {
            None
        }
    }

    // ─── Session persistence ─────────────────────────────────────────────────

    /// Persist the current conversation history to `~/.kaiju/sessions/<slug>.json`.
    /// The slug is derived from the binary path so each binary has its own file.
    pub fn save_session(&self, binary_path: &str) -> anyhow::Result<()> {
        let path = session_path(binary_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.history)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Restore a previously saved conversation history from disk.
    /// Returns `true` if a session was loaded, `false` if none existed.
    pub fn load_session(&mut self, binary_path: &str) -> anyhow::Result<bool> {
        let path = session_path(binary_path)?;
        if !path.exists() {
            return Ok(false);
        }
        let raw = std::fs::read_to_string(&path)?;
        let history: Vec<LlmMessage> = serde_json::from_str(&raw)?;
        self.history = history;
        Ok(true)
    }

    /// True if a saved session exists for `binary_path`.
    pub fn has_session(binary_path: &str) -> bool {
        session_path(binary_path).map(|p| p.exists()).unwrap_or(false)
    }
}

fn session_path(binary_path: &str) -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let sessions_dir = std::path::PathBuf::from(home).join(".kaiju").join("sessions");
    // Derive a safe filename from the binary path
    let slug: String = binary_path
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let slug = if slug.len() > 120 { slug[slug.len() - 120..].to_string() } else { slug };
    Ok(sessions_dir.join(format!("{}.session.json", slug)))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmMessage, ToolResult};

    fn big_tool_result(chars: usize) -> LlmMessage {
        LlmMessage::tool_results(vec![ToolResult {
            call_id: "id".to_string(),
            name: "tool".to_string(),
            content: "x".repeat(chars),
        }])
    }

    fn user_msg(s: &str) -> LlmMessage {
        LlmMessage::user_text(s)
    }

    #[test]
    fn trim_does_nothing_when_under_budget() {
        let mut history = vec![
            user_msg("hello"),
            big_tool_result(100),
        ];
        let before = history.len();
        trim_history(&mut history);
        assert_eq!(history.len(), before, "nothing should be trimmed");
    }

    #[test]
    fn trim_drops_oldest_tool_result_first() {
        // Two tool results, combined > MAX_HISTORY_CHARS
        let big = MAX_HISTORY_CHARS / 2 + 1000;
        let mut history = vec![
            user_msg("task"),
            big_tool_result(big),   // oldest tool result
            big_tool_result(big),   // newer tool result
        ];
        trim_history(&mut history);
        // At least one tool result should have been removed
        let remaining_tool_results = history
            .iter()
            .filter(|m| m.is_tool_result_message())
            .count();
        assert!(remaining_tool_results < 2, "should have dropped at least one tool result");
    }

    #[test]
    fn trim_never_drops_user_text() {
        let big = MAX_HISTORY_CHARS / 2 + 1000;
        let mut history = vec![
            user_msg("important context"),
            user_msg("more context"),
            big_tool_result(big),
            big_tool_result(big),
        ];
        trim_history(&mut history);
        // Both user messages must survive
        let user_texts: Vec<_> = history
            .iter()
            .flat_map(|m| m.texts())
            .collect();
        assert!(user_texts.contains(&"important context"));
        assert!(user_texts.contains(&"more context"));
    }

    #[test]
    fn trim_stops_when_under_budget() {
        // The huge result is oldest; once it's dropped the budget is satisfied
        // and the small result (newer) should survive.
        let mut history = vec![
            user_msg("q"),
            big_tool_result(MAX_HISTORY_CHARS + 1000), // huge — oldest, dropped first
            big_tool_result(100),                      // small — newer, survives
        ];
        trim_history(&mut history);
        assert!(
            history.iter().any(|m| m.is_tool_result_message()),
            "the small (newer) tool result should survive after the huge one is dropped"
        );
    }

    #[test]
    fn trim_handles_empty_history() {
        let mut history: Vec<LlmMessage> = vec![];
        trim_history(&mut history); // must not panic
        assert!(history.is_empty());
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a virtual address from tool arguments, if the tool operates on one.
/// Used to drive the Focus event for active highlighting in the TUI.
fn extract_focus_vaddr(tool: &str, args: &serde_json::Value) -> Option<u64> {
    match tool {
        "disassemble" | "decompile" | "xrefs_to" | "cfg_view" | "explain_function"
        | "rename_function" | "rename_variable"
        | "set_return_type" | "set_param_type" | "set_param_name" | "set_vuln_score" => {
            args["vaddr"].as_u64().or_else(|| args["fn_vaddr"].as_u64())
        }
        _ => None,
    }
}

/// Build a lightweight snapshot of the current history for the Context tab.
fn snapshot_context(history: &[crate::llm::LlmMessage]) -> Vec<ContextEntry> {
    use crate::llm::MessageContent;

    let mut entries = Vec::new();
    for msg in history {
        let role = match msg.role {
            crate::llm::MessageRole::User      => "user",
            crate::llm::MessageRole::Assistant => "assistant",
        };
        for content in &msg.content {
            let entry = match content {
                MessageContent::Text(t) => ContextEntry {
                    role,
                    kind: "text",
                    tool_name: None,
                    char_count: t.len(),
                    preview: truncate_preview(t, 100),
                },
                MessageContent::ToolCall(tc) => ContextEntry {
                    role,
                    kind: "tool_call",
                    tool_name: Some(tc.name.clone()),
                    char_count: tc.args.to_string().len(),
                    preview: truncate_preview(&tc.args.to_string(), 100),
                },
                MessageContent::ToolResult(tr) => ContextEntry {
                    role,
                    kind: "tool_result",
                    tool_name: Some(tr.name.clone()),
                    char_count: tr.content.len(),
                    preview: truncate_preview(&tr.content, 100),
                },
            };
            entries.push(entry);
        }
    }
    entries
}

fn truncate_preview(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

fn args_display(args: &serde_json::Value) -> String {
    match args.as_object() {
        None => args.to_string(),
        Some(map) => map
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => {
                    let s = if s.len() > 50 {
                        format!("{}…", &s[..50])
                    } else {
                        s.clone()
                    };
                    format!("{}=\"{}\"", k, s)
                }
                _ => format!("{}={}", k, v),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}
