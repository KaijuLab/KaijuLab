use anyhow::Result;
use tokio::sync::mpsc;

use crate::llm::{LlmBackend, LlmMessage, ToolResult};
use crate::tools;
use crate::ui;

// ─── Events sent to the TUI ──────────────────────────────────────────────────

/// Events the agent emits so the TUI can update its panels in real time.
/// When no channel is attached (one-shot / plain-text mode) these are never
/// created — the agent falls back to the `ui::print_*` functions instead.
#[derive(Debug)]
pub enum AgentEvent {
    /// LLM is generating a response.
    Thinking,
    /// LLM issued a tool call.
    ToolCall { name: String, display_args: String },
    /// Tool finished; `output` is the full result string.
    ToolResult { name: String, output: String },
    /// LLM produced a final text response.
    LlmText(String),
    /// Agent turn is complete.
    Done,
    /// API or tool error.
    Error(String),
}

/// Estimated character budget before we start trimming old tool-result messages.
/// ~80 K chars ≈ 20 K tokens, comfortable headroom under typical 128 K limits.
const MAX_HISTORY_CHARS: usize = 80_000;

/// Drop the oldest tool-result messages from `history` until the total estimated
/// character count falls below `MAX_HISTORY_CHARS`.  Plain user/assistant text is
/// never dropped so the conversation thread stays coherent.
fn trim_history(history: &mut Vec<crate::llm::LlmMessage>) {
    loop {
        let total: usize = history.iter().map(|m| m.estimated_chars()).sum();
        if total <= MAX_HISTORY_CHARS {
            break;
        }
        // Find the earliest tool-result message and remove it
        if let Some(pos) = history.iter().position(|m| m.is_tool_result_message()) {
            history.remove(pos);
        } else {
            break; // nothing left to drop
        }
    }
}

const SYSTEM_PROMPT: &str = "\
You are KaijuLab, an expert reverse-engineering assistant. \
You analyse binary files using the tools available to you. \
Start with file_info to understand the file format, then use other tools \
to dig deeper as needed. Be precise, technical, and explain your reasoning \
step by step. When you encounter addresses or offsets, prefer the \
disassemble tool to verify what the code actually does.";

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

            // ── Call the LLM ────────────────────────────────────────────────
            self.emit(AgentEvent::Thinking);
            let spinner = if !self.tui_mode() {
                Some(ui::new_spinner("Thinking…"))
            } else {
                None
            };

            let result = self
                .backend
                .generate(SYSTEM_PROMPT, &self.history, &self.tools)
                .await;

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
            for text in response.texts() {
                if !text.trim().is_empty() {
                    if self.tui_mode() {
                        self.emit(AgentEvent::LlmText(text.to_string()));
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
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
