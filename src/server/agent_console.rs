//! Browser-backed PTY sessions for interactive Claude/Codex terminals.
//!
//! Agent console sessions are daemon-owned and reconnectable.  The terminal
//! stream is not project truth: MCP calls, findings, renames, notes, and
//! comments still flow through the daemon event bus and project database.

use std::{
    collections::HashMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::{FromRawFd, RawFd},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::AppState;

const TRANSCRIPT_LIMIT: usize = 96 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/agent-console", get(list_sessions))
        .route("/api/agent-console/:agent", get(console_handler))
        .with_state(state)
}

#[derive(Clone, Default)]
pub struct AgentConsoleManager {
    sessions: Arc<Mutex<HashMap<String, Arc<AgentSession>>>>,
}

impl AgentConsoleManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_or_spawn(&self, agent: &str) -> Result<Arc<AgentSession>> {
        let program = agent_program(agent)?;
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(agent) {
            if session.is_running() {
                return Ok(session.clone());
            }
        }
        let session = Arc::new(AgentSession::spawn(agent, &program, 120, 32)?);
        sessions.insert(agent.to_string(), session.clone());
        Ok(session)
    }

    fn list(&self) -> Vec<AgentConsoleSessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().map(|session| session.info()).collect()
    }
}

async fn list_sessions(State(state): State<AppState>) -> Json<Vec<AgentConsoleSessionInfo>> {
    Json(state.agent_console.list())
}

async fn console_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(agent): Path<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, agent))
}

async fn handle_socket(socket: WebSocket, state: AppState, agent: String) {
    let session = match state.agent_console.get_or_spawn(&agent) {
        Ok(session) => session,
        Err(e) => {
            let (mut sender, _) = socket.split();
            let _ = send_json(&mut sender, ServerMessage::Error(e.to_string())).await;
            return;
        }
    };

    let (mut sender, mut receiver) = socket.split();
    let mut events = session.subscribe();
    let _ = send_json(&mut sender, ServerMessage::Status(session.info())).await;
    let transcript = session.transcript_tail();
    if !transcript.is_empty() {
        let _ = send_json(&mut sender, ServerMessage::Output(transcript)).await;
    }

    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(frame) => {
                    if send_json(&mut sender, frame).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let _ = send_json(&mut sender, ServerMessage::Error("agent console stream lagged; transcript tail resent".into())).await;
                    let _ = send_json(&mut sender, ServerMessage::Output(session.transcript_tail())).await;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            msg = receiver.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Input { data }) => {
                            if let Err(e) = session.write_input(data.as_bytes()) {
                                let _ = send_json(&mut sender, ServerMessage::Error(e.to_string())).await;
                            }
                        }
                        Ok(ClientMessage::Resize { cols, rows }) => {
                            if let Err(e) = session.resize(cols, rows) {
                                let _ = send_json(&mut sender, ServerMessage::Error(e.to_string())).await;
                            }
                        }
                        Ok(ClientMessage::Interrupt) => {
                            let _ = session.write_input(&[3]);
                        }
                        Ok(ClientMessage::Terminate) => {
                            session.terminate();
                            break;
                        }
                        Err(e) => {
                            let _ = send_json(&mut sender, ServerMessage::Error(format!("bad console message: {e}"))).await;
                        }
                    }
                }
                Some(Ok(Message::Binary(bytes))) => {
                    if let Err(e) = session.write_input(&bytes) {
                        let _ = send_json(&mut sender, ServerMessage::Error(e.to_string())).await;
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
}

async fn send_json(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: ServerMessage,
) -> Result<(), axum::Error> {
    sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await
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

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
enum ServerMessage {
    #[serde(rename = "output")]
    Output(String),
    #[serde(rename = "status")]
    Status(AgentConsoleSessionInfo),
    #[serde(rename = "error")]
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentConsoleSessionInfo {
    pub agent: String,
    pub command: String,
    pub running: bool,
    pub started_at: i64,
    pub transcript_path: String,
}

struct AgentSession {
    agent: String,
    command: AgentCommand,
    master: Mutex<File>,
    child_pid: libc::pid_t,
    started_at: i64,
    running: Arc<AtomicBool>,
    transcript: Arc<Mutex<String>>,
    transcript_path: PathBuf,
    tx: broadcast::Sender<ServerMessage>,
}

impl AgentSession {
    fn spawn(agent: &str, command: &AgentCommand, cols: u16, rows: u16) -> Result<Self> {
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
            child_exec(command);
        }

        let master = unsafe { File::from_raw_fd(master_fd as RawFd) };
        let mut reader = master.try_clone().context("clone PTY master for reader")?;
        let started_at = crate::core::events::now_ts();
        let transcript_path = transcript_path(agent, started_at)?;
        let transcript_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&transcript_path)
            .with_context(|| format!("open transcript {}", transcript_path.display()))?;
        let (tx, _) = broadcast::channel(512);

        let session = Self {
            agent: agent.to_string(),
            command: command.clone(),
            master: Mutex::new(master),
            child_pid: pid,
            started_at,
            running: Arc::new(AtomicBool::new(true)),
            transcript: Arc::new(Mutex::new(String::new())),
            transcript_path,
            tx,
        };

        session.spawn_reader(&mut reader, transcript_file);
        Ok(session)
    }

    fn spawn_reader(&self, reader: &mut File, mut transcript_file: File) {
        let mut reader = reader.try_clone().expect("clone PTY reader");
        let tx = self.tx.clone();
        let running = self.running.clone();
        let transcript = self.transcript.clone();
        let agent = self.agent.clone();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        running.store(false, Ordering::SeqCst);
                        let msg = format!("\r\n[{agent} exited]\r\n");
                        append_transcript(&transcript, &mut transcript_file, &msg);
                        let _ = tx.send(ServerMessage::Output(msg));
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        append_transcript(&transcript, &mut transcript_file, &text);
                        let _ = tx.send(ServerMessage::Output(text));
                    }
                    Err(e) => {
                        running.store(false, Ordering::SeqCst);
                        let msg = format!("\r\n[{agent} read error: {e}]\r\n");
                        append_transcript(&transcript, &mut transcript_file, &msg);
                        let _ = tx.send(ServerMessage::Error(msg));
                        break;
                    }
                }
            }
        });
    }

    fn write_input(&self, bytes: &[u8]) -> Result<()> {
        let mut master = self.master.lock().unwrap();
        master.write_all(bytes).context("write to agent PTY")?;
        master.flush().ok();
        Ok(())
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let win = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let master = self.master.lock().unwrap();
        let rc = unsafe { libc::ioctl(master_fd(&master), libc::TIOCSWINSZ, &win) };
        if rc == -1 {
            return Err(anyhow!(
                "resize PTY failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn terminate(&self) {
        self.running.store(false, Ordering::SeqCst);
        unsafe {
            libc::kill(self.child_pid, libc::SIGHUP);
        }
        let _ = self.tx.send(ServerMessage::Status(self.info()));
    }

    fn subscribe(&self) -> broadcast::Receiver<ServerMessage> {
        self.tx.subscribe()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn info(&self) -> AgentConsoleSessionInfo {
        AgentConsoleSessionInfo {
            agent: self.agent.clone(),
            command: self.command.display(),
            running: self.is_running(),
            started_at: self.started_at,
            transcript_path: self.transcript_path.to_string_lossy().into_owned(),
        }
    }

    fn transcript_tail(&self) -> String {
        self.transcript.lock().unwrap().clone()
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn append_transcript(transcript: &Arc<Mutex<String>>, file: &mut File, text: &str) {
    let _ = file.write_all(text.as_bytes());
    let _ = file.flush();
    let mut t = transcript.lock().unwrap();
    t.push_str(text);
    if t.len() > TRANSCRIPT_LIMIT {
        let keep_from = t.len().saturating_sub(TRANSCRIPT_LIMIT);
        let trimmed = t[keep_from..].to_string();
        *t = trimmed;
    }
}

#[derive(Debug, Clone)]
struct AgentCommand {
    program: String,
    args: Vec<String>,
}

impl AgentCommand {
    fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn agent_program(agent: &str) -> Result<AgentCommand> {
    let env_key = match agent {
        "claude" => "KAIJULAB_AGENT_CONSOLE_CLAUDE_CMD",
        "codex" => "KAIJULAB_AGENT_CONSOLE_CODEX_CMD",
        _ => return Err(anyhow!("unsupported agent console: {agent}")),
    };
    if let Ok(command) = std::env::var(env_key) {
        if !command.trim().is_empty() {
            return Ok(AgentCommand {
                program: "/bin/sh".into(),
                args: vec!["-lc".into(), command],
            });
        }
    }
    Ok(AgentCommand {
        program: agent.to_string(),
        args: Vec::new(),
    })
}

fn child_exec(command: &AgentCommand) -> ! {
    let program = CString::new(command.program.as_str()).unwrap();
    let mut cstrings = Vec::with_capacity(command.args.len() + 1);
    cstrings.push(CString::new(command.program.as_str()).unwrap());
    for arg in &command.args {
        cstrings.push(CString::new(arg.as_str()).unwrap());
    }
    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    let term = CString::new("TERM").unwrap();
    let term_value = CString::new("xterm-256color").unwrap();
    unsafe {
        libc::setenv(term.as_ptr(), term_value.as_ptr(), 1);
        libc::execvp(program.as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

fn transcript_path(agent: &str, started_at: i64) -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = PathBuf::from(home).join(".kaiju").join("agent-console");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{agent}-{started_at}.log")))
}

fn master_fd(master: &File) -> libc::c_int {
    use std::os::fd::AsRawFd;
    master.as_raw_fd()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_program_uses_default_binary() {
        std::env::remove_var("KAIJULAB_AGENT_CONSOLE_CLAUDE_CMD");
        let cmd = agent_program("claude").unwrap();
        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.is_empty());
    }
}
