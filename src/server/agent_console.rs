//! Browser-backed PTY sessions for interactive Claude/Codex terminals.
//!
//! The terminal stream is intentionally separate from project truth.  MCP
//! calls, findings, renames, notes, and comments still flow through the
//! daemon event bus and project database.

use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{FromRawFd, RawFd},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

pub fn router() -> Router {
    Router::new().route("/api/agent-console/:agent", get(console_handler))
}

async fn console_handler(ws: WebSocketUpgrade, Path(agent): Path<String>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, agent))
}

async fn handle_socket(socket: WebSocket, agent: String) {
    let program = match agent.as_str() {
        "claude" => "claude",
        "codex" => "codex",
        _ => {
            let (mut sender, _) = socket.split();
            let _ = send_json(
                &mut sender,
                "error",
                format!("unsupported agent console: {agent}"),
            )
            .await;
            return;
        }
    };

    let (mut sender, mut receiver) = socket.split();
    let mut session = match AgentPty::spawn(program, 120, 32) {
        Ok(session) => session,
        Err(e) => {
            let _ = send_json(&mut sender, "error", format!("{program} failed: {e}")).await;
            return;
        }
    };

    let _ = send_json(
        &mut sender,
        "status",
        format!("started {program}; MCP events appear in the KaijuLab timeline"),
    )
    .await;

    loop {
        tokio::select! {
            Some(output) = session.output_rx.recv() => {
                if send_json(&mut sender, "output", output).await.is_err() {
                    break;
                }
            }
            msg = receiver.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Input { data }) => {
                            if let Err(e) = session.write_input(data.as_bytes()) {
                                let _ = send_json(&mut sender, "error", e.to_string()).await;
                            }
                        }
                        Ok(ClientMessage::Resize { cols, rows }) => {
                            if let Err(e) = session.resize(cols, rows) {
                                let _ = send_json(&mut sender, "error", e.to_string()).await;
                            }
                        }
                        Ok(ClientMessage::Interrupt) => {
                            let _ = session.write_input(&[3]);
                        }
                        Ok(ClientMessage::Terminate) => break,
                        Err(e) => {
                            let _ = send_json(&mut sender, "error", format!("bad console message: {e}")).await;
                        }
                    }
                }
                Some(Ok(Message::Binary(bytes))) => {
                    if let Err(e) = session.write_input(&bytes) {
                        let _ = send_json(&mut sender, "error", e.to_string()).await;
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(p))) => {
                    let _ = sender.send(Message::Pong(p)).await;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            }
        }
    }

    session.terminate();
}

async fn send_json(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    kind: &str,
    data: String,
) -> Result<(), axum::Error> {
    let text = serde_json::json!({ "type": kind, "data": data }).to_string();
    sender.send(Message::Text(text)).await
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "input")]
    Input { data: String },
    #[serde(rename = "resize")]
    Resize { cols: u16, rows: u16 },
    #[serde(rename = "interrupt")]
    Interrupt,
    #[serde(rename = "terminate")]
    Terminate,
}

struct AgentPty {
    master: File,
    child_pid: libc::pid_t,
    output_rx: mpsc::UnboundedReceiver<String>,
}

impl AgentPty {
    fn spawn(program: &str, cols: u16, rows: u16) -> Result<Self> {
        let mut master_fd: libc::c_int = -1;
        let mut win = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pid = unsafe {
            forkpty(
                &mut master_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut win,
            )
        };
        if pid < 0 {
            return Err(anyhow!(
                "forkpty failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        if pid == 0 {
            child_exec(program);
        }

        let master = unsafe { File::from_raw_fd(master_fd as RawFd) };
        let mut reader = master.try_clone().context("clone PTY master for reader")?;
        let (tx, output_rx) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send("\r\n[agent exited]\r\n".into());
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        if tx.send(text).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(format!("\r\n[agent read error: {e}]\r\n"));
                        break;
                    }
                }
            }
        });

        Ok(Self {
            master,
            child_pid: pid,
            output_rx,
        })
    }

    fn write_input(&mut self, bytes: &[u8]) -> Result<()> {
        self.master.write_all(bytes).context("write to agent PTY")?;
        self.master.flush().ok();
        Ok(())
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let win = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let rc = unsafe { libc::ioctl(self.master_fd(), libc::TIOCSWINSZ, &win) };
        if rc == -1 {
            return Err(anyhow!(
                "resize PTY failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn terminate(&self) {
        unsafe {
            libc::kill(self.child_pid, libc::SIGHUP);
        }
    }

    fn master_fd(&self) -> libc::c_int {
        use std::os::fd::AsRawFd;
        self.master.as_raw_fd()
    }
}

impl Drop for AgentPty {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn child_exec(program: &str) -> ! {
    let prog = CString::new(program).unwrap();
    let term = CString::new("TERM").unwrap();
    let term_value = CString::new("xterm-256color").unwrap();
    unsafe {
        libc::setenv(term.as_ptr(), term_value.as_ptr(), 1);
        libc::execlp(
            prog.as_ptr(),
            prog.as_ptr(),
            std::ptr::null::<libc::c_char>(),
        );
        libc::_exit(127);
    }
}

#[cfg(unix)]
#[link(name = "util")]
extern "C" {
    fn forkpty(
        amaster: *mut libc::c_int,
        name: *mut libc::c_char,
        termp: *const libc::termios,
        winp: *const libc::winsize,
    ) -> libc::pid_t;
}
