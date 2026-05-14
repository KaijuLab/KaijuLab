//! MCP JSON-RPC server over stdio.
//!
//! Implements the small slice of the spec we need: `initialize`, `tools/list`,
//! `tools/call`, `resources/list`, `resources/read`, `ping`.  Notifications
//! (`notifications/initialized`) are accepted and ignored.
//!
//! Routing pluggable through `McpBackend`: local in-process (no daemon) or
//! proxied via Unix socket to a running `serve` daemon.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::core::workspace::Workspace;
use crate::ipc::{socket::IpcClient, IpcOp};

#[async_trait]
pub trait McpBackend {
    async fn list_tools(&self) -> Result<Value>;
    async fn call_tool(&self, name: &str, args: Value) -> Result<String>;
    async fn list_resources(&self) -> Result<Value>;
    async fn read_resource(&self, uri: &str) -> Result<String>;
    async fn workspace_info(&self) -> Result<Value>;
}

// ─── Local (no daemon) ──────────────────────────────────────────────────────

pub struct LocalBackend {
    workspace: Workspace,
}

impl LocalBackend {
    pub fn new(workspace: Workspace) -> Self {
        LocalBackend { workspace }
    }
}

#[async_trait]
impl McpBackend for LocalBackend {
    async fn list_tools(&self) -> Result<Value> {
        Ok(super::tools::tool_definitions())
    }
    async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        let ws = self.workspace.clone();
        let nm = name.to_string();
        tokio::task::spawn_blocking(move || super::tools::dispatch_mcp(&ws, None, &nm, &args))
            .await?
    }
    async fn list_resources(&self) -> Result<Value> {
        Ok(super::resources::list())
    }
    async fn read_resource(&self, uri: &str) -> Result<String> {
        super::resources::read(&self.workspace, uri)
    }
    async fn workspace_info(&self) -> Result<Value> {
        Ok(serde_json::to_value(self.workspace.info())?)
    }
}

// ─── Proxy to daemon ────────────────────────────────────────────────────────

pub struct ProxyBackend {
    client: IpcClient,
    /// Workspace kept around so we can answer trivial questions if the daemon
    /// is briefly unreachable.
    workspace: Option<Workspace>,
}

impl ProxyBackend {
    pub fn new(client: IpcClient, workspace: Workspace) -> Self {
        ProxyBackend {
            client,
            workspace: Some(workspace),
        }
    }

    pub fn active(client: IpcClient) -> Self {
        ProxyBackend {
            client,
            workspace: None,
        }
    }
}

#[async_trait]
impl McpBackend for ProxyBackend {
    async fn list_tools(&self) -> Result<Value> {
        self.client.request(IpcOp::ListTools).await
    }
    async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        let v = self
            .client
            .request(IpcOp::CallTool {
                name: name.to_string(),
                args,
            })
            .await?;
        Ok(v.as_str().unwrap_or("").to_string())
    }
    async fn list_resources(&self) -> Result<Value> {
        Ok(super::resources::list())
    }
    async fn read_resource(&self, uri: &str) -> Result<String> {
        let v = self
            .client
            .request(IpcOp::ReadResource {
                uri: uri.to_string(),
            })
            .await?;
        Ok(v.as_str().unwrap_or("").to_string())
    }
    async fn workspace_info(&self) -> Result<Value> {
        // Prefer the daemon's view; fall back to local on error.
        match self.client.request(IpcOp::WorkspaceInfo).await {
            Ok(v) => Ok(v),
            Err(e) => {
                if let Some(workspace) = &self.workspace {
                    Ok(serde_json::to_value(workspace.info())?)
                } else {
                    Err(e)
                }
            }
        }
    }
}

// ─── JSON-RPC framing over stdio ─────────────────────────────────────────────

pub async fn run_stdio(backend: Box<dyn McpBackend + Send + Sync>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = jsonrpc_error(Value::Null, -32700, &format!("parse error: {}", e));
                write_message(&mut stdout, &err).await?;
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        // Notifications: no `id` field (or absent).  Accept and ignore.
        if id.is_null() && !method.is_empty() {
            // notifications/initialized etc.
            continue;
        }

        let resp = handle_request(&*backend, &id, method, params).await;
        write_message(&mut stdout, &resp).await?;
    }

    Ok(())
}

async fn handle_request(
    backend: &(dyn McpBackend + Send + Sync),
    id: &Value,
    method: &str,
    params: Value,
) -> Value {
    match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": "kaijulab",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        }),
        "ping" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        "tools/list" => match backend.list_tools().await {
            Ok(tools) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tools }
            }),
            Err(e) => jsonrpc_error(id.clone(), -32603, &e.to_string()),
        },
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            match backend.call_tool(name, args).await {
                Ok(text) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": format!("Error: {}", e) }],
                        "isError": true
                    }
                }),
            }
        }
        "resources/list" => match backend.list_resources().await {
            Ok(resources) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "resources": resources }
            }),
            Err(e) => jsonrpc_error(id.clone(), -32603, &e.to_string()),
        },
        "resources/read" => {
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            match backend.read_resource(uri).await {
                Ok(text) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": text
                        }]
                    }
                }),
                Err(e) => jsonrpc_error(id.clone(), -32603, &e.to_string()),
            }
        }
        _ => jsonrpc_error(id.clone(), -32601, &format!("method not found: {}", method)),
    }
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

async fn write_message<W: tokio::io::AsyncWrite + Unpin>(
    stdout: &mut W,
    msg: &Value,
) -> Result<()> {
    let s = serde_json::to_string(msg)?;
    stdout.write_all(s.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

// Silence the unused-import lint when both helpers below aren't called from
// this module directly.
#[allow(dead_code)]
fn _backend_assert(_: &dyn McpBackend) {}
