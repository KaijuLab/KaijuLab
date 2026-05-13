//! Unix-socket server (in daemon) and client (in mcp shim).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::core::{
    analysis,
    events::{now_ts, Event, Source},
    EventBus, Workspace,
};

use super::protocol::{IpcOp, IpcRequest, IpcResponse};

/// Spawn an async task that listens on a per-workspace Unix socket and serves
/// IPC requests forever.  Removes any stale socket file first.
pub fn spawn_server(socket_path: PathBuf, workspace: Workspace, bus: EventBus) -> Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind unix socket {}", socket_path.display()))?;
    tracing::info!("ipc: listening on {}", socket_path.display());

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let ws = workspace.clone();
                    let b = bus.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, ws, b).await {
                            tracing::warn!("ipc client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("ipc accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

async fn handle_client(stream: UnixStream, workspace: Workspace, bus: EventBus) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let req: IpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = IpcResponse::err(String::new(), format!("bad request: {}", e));
                let s = serde_json::to_string(&resp)? + "\n";
                writer.write_all(s.as_bytes()).await?;
                continue;
            }
        };

        let resp = handle_op(&workspace, &bus, &req).await;
        let s = serde_json::to_string(&resp)? + "\n";
        writer.write_all(s.as_bytes()).await?;
    }
    Ok(())
}

async fn handle_op(workspace: &Workspace, bus: &EventBus, req: &IpcRequest) -> IpcResponse {
    let id = req.id.clone();
    match &req.op {
        IpcOp::Ping => IpcResponse::ok(id, Value::String("pong".into())),
        IpcOp::WorkspaceInfo => IpcResponse::ok(id, serde_json::to_value(workspace.info()).unwrap()),
        IpcOp::ListTools => IpcResponse::ok(id, crate::mcp::tools::tool_definitions()),
        IpcOp::CallTool { name, args } => {
            let call_id = uuid::Uuid::new_v4().simple().to_string();
            bus.emit(Event::ToolCall {
                id: call_id.clone(),
                job_id: None,
                name: name.clone(),
                source: Source::Claude,
                ts: now_ts(),
            });
            match crate::mcp::tools::dispatch_mcp(workspace, Some(bus), name, args) {
                Ok(text) => {
                    bus.emit(Event::ToolResult {
                        id: call_id,
                        name: name.clone(),
                        ok: true,
                        bytes: text.len(),
                        ts: now_ts(),
                    });
                    IpcResponse::ok(id, Value::String(text))
                }
                Err(e) => {
                    bus.emit(Event::ToolResult {
                        id: call_id,
                        name: name.clone(),
                        ok: false,
                        bytes: e.to_string().len(),
                        ts: now_ts(),
                    });
                    IpcResponse::err(id, e.to_string())
                }
            }
        }
        IpcOp::ReadResource { uri } => match crate::mcp::resources::read(workspace, uri) {
            Ok(text) => IpcResponse::ok(id, Value::String(text)),
            Err(e) => IpcResponse::err(id, e.to_string()),
        },
    }
}

// ─── Client ──────────────────────────────────────────────────────────────────

/// Stdio shim's client connection to a running daemon.
pub struct IpcClient {
    writer: Mutex<tokio::net::unix::OwnedWriteHalf>,
    reader: Mutex<BufReader<tokio::net::unix::OwnedReadHalf>>,
}

impl IpcClient {
    pub async fn connect(path: &std::path::Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .await
            .with_context(|| format!("connect {}", path.display()))?;
        let (reader, writer) = stream.into_split();
        Ok(IpcClient {
            writer: Mutex::new(writer),
            reader: Mutex::new(BufReader::new(reader)),
        })
    }

    pub async fn request(&self, op: IpcOp) -> Result<Value> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let req = IpcRequest { id: id.clone(), op };
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');

        let mut w = self.writer.lock().await;
        w.write_all(line.as_bytes()).await?;
        drop(w);

        let mut r = self.reader.lock().await;
        let mut buf = String::new();
        r.read_line(&mut buf).await?;
        let resp: IpcResponse = serde_json::from_str(buf.trim())?;
        if !resp.ok {
            anyhow::bail!(resp.error.unwrap_or_default());
        }
        Ok(resp.data.unwrap_or(Value::Null))
    }
}

/// Convenience: run a workspace-info request directly without daemon.  Used by
/// the MCP shim when no daemon is available — falls back to in-process state.
#[allow(dead_code)]
pub fn fallback_info(workspace: &Workspace) -> Value {
    serde_json::to_value(workspace.info()).unwrap_or(Value::Null)
}

#[allow(dead_code)]
pub fn fallback_dispatch(workspace: &Workspace, name: &str, args: &Value) -> Result<String> {
    crate::mcp::tools::dispatch_mcp(workspace, None, name, args)
}

#[allow(dead_code)]
pub fn fallback_resource(workspace: &Workspace, uri: &str) -> Result<String> {
    crate::mcp::resources::read(workspace, uri)
}

#[allow(dead_code)]
pub fn fallback_analysis(workspace: &Workspace) -> Result<String> {
    analysis::file_info(workspace)
}
