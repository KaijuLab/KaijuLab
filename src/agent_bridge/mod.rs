//! Local CLI bridges to the user's existing Claude Code and Codex installs.
//!
//! Scope: schema-bound, non-interactive jobs only.  Interactive analysis is
//! the user's primary Claude Code session driving KaijuLab through MCP.

pub mod claude;
pub mod codex;
pub mod prompts;
pub mod scope;

pub use scope::{ContextPack, WritePolicy};
