//! LLM backend abstraction.
//!
//! All backends translate between the universal types defined here and their
//! own wire formats.  `agent.rs` only depends on this module.

pub mod anthropic;
pub mod gemini;
pub mod openai;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

// ─── Global request timeout ──────────────────────────────────────────────────

static REQUEST_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(120);

/// Read the current per-request HTTP timeout (default: 120 s).
pub fn get_timeout_secs() -> u64 {
    REQUEST_TIMEOUT_SECS.load(Ordering::Relaxed)
}

/// Update the per-request HTTP timeout.  Takes effect on the next LLM call.
pub fn set_timeout_secs(secs: u64) {
    REQUEST_TIMEOUT_SECS.store(secs, Ordering::Relaxed);
}

// ─── Universal message types ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
}

/// A single tool invocation inside a model response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Provider-assigned call ID (Gemini: function name; OpenAI/Anthropic: UUID).
    /// Sent back verbatim in `ToolResult.call_id`.
    pub id: String,
    pub name: String,
    pub args: serde_json::Value,
}

/// Result of executing a tool, to be fed back to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub name: String,
    /// Plain-text output shown to the model (same string shown in the UI).
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: MessageRole,
    pub content: Vec<MessageContent>,
}

impl LlmMessage {
    pub fn user_text(text: impl Into<String>) -> Self {
        LlmMessage {
            role: MessageRole::User,
            content: vec![MessageContent::Text(text.into())],
        }
    }

    pub fn tool_results(results: Vec<ToolResult>) -> Self {
        LlmMessage {
            role: MessageRole::User,
            content: results.into_iter().map(MessageContent::ToolResult).collect(),
        }
    }

    /// Collect all ToolCall items from this message.
    pub fn tool_calls(&self) -> Vec<&ToolCall> {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::ToolCall(tc) => Some(tc),
                _ => None,
            })
            .collect()
    }

    /// Collect all text parts from this message.
    pub fn texts(&self) -> Vec<&str> {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Rough character count across all content items (used for context-window budgeting).
    pub fn estimated_chars(&self) -> usize {
        self.content
            .iter()
            .map(|c| match c {
                MessageContent::Text(t) => t.len(),
                MessageContent::ToolCall(tc) => tc.name.len() + tc.args.to_string().len() + 16,
                MessageContent::ToolResult(tr) => tr.content.len() + 16,
            })
            .sum()
    }

    /// True when this message consists entirely of tool results (safe to drop when trimming).
    pub fn is_tool_result_message(&self) -> bool {
        !self.content.is_empty()
            && self
                .content
                .iter()
                .all(|c| matches!(c, MessageContent::ToolResult(_)))
    }
}

// ─── Universal tool definition ────────────────────────────────────────────────

/// Schema-agnostic tool definition.  Use standard JSON Schema types
/// (lowercase: "object", "string", "integer", "boolean", "array").
/// Each backend translates to its own wire format.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema, standard lowercase types.
    pub parameters: serde_json::Value,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn text_msg(s: &str) -> LlmMessage {
        LlmMessage::user_text(s)
    }

    fn tool_result_msg(content: &str) -> LlmMessage {
        LlmMessage::tool_results(vec![ToolResult {
            call_id: "id1".to_string(),
            name: "some_tool".to_string(),
            content: content.to_string(),
        }])
    }

    fn mixed_msg() -> LlmMessage {
        // A message with both text and a tool result (unusual but possible)
        LlmMessage {
            role: MessageRole::User,
            content: vec![
                MessageContent::Text("context".to_string()),
                MessageContent::ToolResult(ToolResult {
                    call_id: "id2".to_string(),
                    name: "tool".to_string(),
                    content: "output".to_string(),
                }),
            ],
        }
    }

    #[test]
    fn estimated_chars_text() {
        let m = text_msg("hello world"); // 11 chars
        assert_eq!(m.estimated_chars(), 11);
    }

    #[test]
    fn estimated_chars_tool_result() {
        let m = tool_result_msg("abc"); // 3 + 16 overhead
        assert_eq!(m.estimated_chars(), 3 + 16);
    }

    #[test]
    fn estimated_chars_empty() {
        let m = LlmMessage { role: MessageRole::User, content: vec![] };
        assert_eq!(m.estimated_chars(), 0);
    }

    #[test]
    fn is_tool_result_message_true() {
        let m = tool_result_msg("output");
        assert!(m.is_tool_result_message());
    }

    #[test]
    fn is_tool_result_message_false_for_text() {
        let m = text_msg("hello");
        assert!(!m.is_tool_result_message());
    }

    #[test]
    fn is_tool_result_message_false_for_empty() {
        let m = LlmMessage { role: MessageRole::User, content: vec![] };
        assert!(!m.is_tool_result_message());
    }

    #[test]
    fn is_tool_result_message_false_for_mixed() {
        // A message with both text and tool_result is not purely tool results
        assert!(!mixed_msg().is_tool_result_message());
    }

    #[test]
    fn tool_calls_returns_only_tool_calls() {
        let m = LlmMessage {
            role: MessageRole::Assistant,
            content: vec![
                MessageContent::Text("thinking...".to_string()),
                MessageContent::ToolCall(ToolCall {
                    id: "c1".to_string(),
                    name: "file_info".to_string(),
                    args: serde_json::json!({"path": "/bin/ls"}),
                }),
            ],
        };
        let calls = m.tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "file_info");
    }

    #[test]
    fn texts_returns_only_text() {
        let m = LlmMessage {
            role: MessageRole::Assistant,
            content: vec![
                MessageContent::Text("hello".to_string()),
                MessageContent::ToolCall(ToolCall {
                    id: "c1".to_string(),
                    name: "file_info".to_string(),
                    args: serde_json::json!({}),
                }),
                MessageContent::Text(" world".to_string()),
            ],
        };
        assert_eq!(m.texts(), vec!["hello", " world"]);
    }

    // ── constructor helpers ───────────────────────────────────────────────────

    #[test]
    fn user_text_sets_role() {
        let m = LlmMessage::user_text("hi");
        assert_eq!(m.role, MessageRole::User);
        assert_eq!(m.texts(), vec!["hi"]);
    }

    #[test]
    fn tool_results_constructor_role_is_user() {
        // Tool results are submitted as user messages per OpenAI/Anthropic convention
        let m = tool_result_msg("data");
        assert_eq!(m.role, MessageRole::User);
    }

    #[test]
    fn tool_results_constructor_has_tool_result_content() {
        let tr = ToolResult {
            call_id: "abc".to_string(),
            name: "my_tool".to_string(),
            content: "output".to_string(),
        };
        let m = LlmMessage::tool_results(vec![tr]);
        assert!(m.is_tool_result_message());
        // texts() should return nothing — only ToolResult content, not Text
        assert!(m.texts().is_empty());
    }

    #[test]
    fn tool_results_multiple_results_all_present() {
        let results = vec![
            ToolResult { call_id: "1".to_string(), name: "a".to_string(), content: "out_a".to_string() },
            ToolResult { call_id: "2".to_string(), name: "b".to_string(), content: "out_b".to_string() },
        ];
        let m = LlmMessage::tool_results(results);
        assert_eq!(m.content.len(), 2);
        assert!(m.is_tool_result_message());
    }

    #[test]
    fn estimated_chars_tool_call() {
        let m = LlmMessage {
            role: MessageRole::Assistant,
            content: vec![MessageContent::ToolCall(ToolCall {
                id: "id".to_string(),
                name: "fn".to_string(),          // 2 chars
                args: serde_json::json!({"k":"v"}), // {"k":"v"} = 9 chars
            })],
        };
        // name.len() + args.to_string().len() + 16 overhead
        let expected = 2 + serde_json::json!({"k":"v"}).to_string().len() + 16;
        assert_eq!(m.estimated_chars(), expected);
    }

    #[test]
    fn is_tool_result_message_empty_content_is_false() {
        let m = LlmMessage { role: MessageRole::User, content: vec![] };
        assert!(!m.is_tool_result_message(), "empty content should not be a tool result message");
    }

    // ── serde roundtrip ───────────────────────────────────────────────────────

    #[test]
    fn llm_message_serde_roundtrip() {
        let original = LlmMessage::user_text("roundtrip test");
        let json = serde_json::to_string(&original).unwrap();
        let restored: LlmMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.role, original.role);
        assert_eq!(restored.texts(), original.texts());
    }

    #[test]
    fn tool_result_serde_roundtrip() {
        let tr = ToolResult {
            call_id: "xyz".to_string(),
            name: "my_tool".to_string(),
            content: "the output".to_string(),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let restored: ToolResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.call_id, "xyz");
        assert_eq!(restored.name, "my_tool");
        assert_eq!(restored.content, "the output");
    }

    #[test]
    fn message_role_serde_roundtrip() {
        for role in [MessageRole::User, MessageRole::Assistant] {
            let json = serde_json::to_string(&role).unwrap();
            let restored: MessageRole = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, role);
        }
    }
}

// ─── Backend trait ────────────────────────────────────────────────────────────

#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Send `history` + available `tools` and return the model's next message.
    async fn generate(
        &self,
        system: &str,
        history: &[LlmMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmMessage>;

    /// Streaming variant: same as `generate` but sends text chunks via `chunk_tx`
    /// as they arrive.  Returns the full assembled `LlmMessage` at the end.
    /// Default implementation: no streaming — delegates to `generate`.
    async fn generate_streaming(
        &self,
        system: &str,
        history: &[LlmMessage],
        tools: &[ToolDefinition],
        _chunk_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Result<LlmMessage> {
        self.generate(system, history, tools).await
    }

    /// Short human-readable label shown in the banner, e.g. "Gemini 2.5 Flash (Vertex AI)".
    fn display_name(&self) -> String;
}
