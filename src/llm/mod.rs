//! LLM backend abstraction.
//!
//! All backends translate between the universal types defined here and their
//! own wire formats.  `agent.rs` only depends on this module.

pub mod anthropic;
pub mod gemini;
pub mod openai;

use anyhow::Result;
use async_trait::async_trait;

// ─── Universal message types ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MessageRole {
    User,
    Assistant,
}

/// A single tool invocation inside a model response.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// Provider-assigned call ID (Gemini: function name; OpenAI/Anthropic: UUID).
    /// Sent back verbatim in `ToolResult.call_id`.
    pub id: String,
    pub name: String,
    pub args: serde_json::Value,
}

/// Result of executing a tool, to be fed back to the LLM.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub call_id: String,
    pub name: String,
    /// Plain-text output shown to the model (same string shown in the UI).
    pub content: String,
}

#[derive(Debug, Clone)]
pub enum MessageContent {
    Text(String),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
}

#[derive(Debug, Clone)]
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

    /// Short human-readable label shown in the banner, e.g. "Gemini 2.5 Flash (Vertex AI)".
    fn display_name(&self) -> String;
}
