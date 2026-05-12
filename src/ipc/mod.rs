//! Unix-socket IPC between the `serve` daemon and the `mcp` stdio shim.
//!
//! Wire protocol: newline-delimited JSON requests / responses.  Each request
//! is `{"id": "...", "op": "...", "args": {...}}`; each response is
//! `{"id": "...", "ok": true, "data": ...}` or `{"id": "...", "ok": false,
//! "error": "..."}`.

pub mod protocol;
pub mod socket;

pub use protocol::{IpcOp, IpcRequest, IpcResponse};
pub use socket::{spawn_server, IpcClient};
