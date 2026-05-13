//! Frame types for the daemon ↔ shim IPC channel.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcOp {
    /// Liveness check.
    Ping,
    /// Return workspace info.
    WorkspaceInfo,
    /// List MCP tool definitions (server-side fixed schema).
    ListTools,
    /// Invoke a tool by name with arbitrary JSON args.  Returns the tool's
    /// raw text output.
    CallTool { name: String, args: Value },
    /// Read a resource by URI.
    ReadResource { uri: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: String,
    #[serde(flatten)]
    pub op: IpcOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcResponse {
    pub fn ok(id: String, data: Value) -> Self {
        IpcResponse {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn err(id: String, msg: impl Into<String>) -> Self {
        IpcResponse {
            id,
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}
