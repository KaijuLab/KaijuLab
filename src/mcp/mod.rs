//! MCP stdio shim.
//!
//! Implements a minimal subset of the Model Context Protocol over stdio
//! (JSON-RPC 2.0): `initialize`, `tools/list`, `tools/call`, `resources/list`,
//! `resources/read`.
//!
//! On startup the shim looks for a running `kaijulab serve` daemon for the
//! same workspace (Unix socket under `~/.kaiju/run/<hash>.sock`).  If found,
//! all calls are proxied to the daemon so the browser UI sees them live.  If
//! no daemon is present, the shim runs against an in-process Workspace.

pub mod resources;
pub mod server;
pub mod tools;

use std::path::PathBuf;

use anyhow::Result;

use crate::core::workspace::{socket_path_for, WritePolicy, Workspace};

pub async fn run(binary_path: PathBuf, policy: WritePolicy) -> Result<()> {
    let workspace = Workspace::open(&binary_path, policy)?;
    let socket = socket_path_for(workspace.workspace_hash())?;

    let backend: Box<dyn server::McpBackend + Send + Sync> = if socket.exists() {
        match crate::ipc::socket::IpcClient::connect(&socket).await {
            Ok(client) => {
                tracing::info!("mcp: connected to daemon at {}", socket.display());
                Box::new(server::ProxyBackend::new(client, workspace.clone()))
            }
            Err(e) => {
                tracing::warn!(
                    "mcp: daemon socket exists but connect failed ({}); running standalone",
                    e
                );
                Box::new(server::LocalBackend::new(workspace))
            }
        }
    } else {
        tracing::info!("mcp: no daemon found at {}; running standalone", socket.display());
        Box::new(server::LocalBackend::new(workspace))
    };

    server::run_stdio(backend).await
}
