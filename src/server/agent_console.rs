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
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::{delete, get},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::AppState;

const TRANSCRIPT_LIMIT: usize = 96 * 1024;
const DEFAULT_IDLE_SECS: u64 = 60 * 60;
const DEFAULT_MAX_RUNTIME_SECS: u64 = 6 * 60 * 60;
const DEFAULT_TRANSCRIPT_BYTES: u64 = 5 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/agent-console", get(list_sessions))
        .route("/api/agent-console/:agent", get(console_handler).delete(terminate_session))
        .route(
            "/api/agent-console/:agent/transcript",
            delete(delete_transcript),
        )
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
        let mut sessions = lock_or_recover(&self.sessions);
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
        let sessions = lock_or_recover(&self.sessions);
        sessions.values().map(|session| session.info()).collect()
    }

    fn delete_transcript(&self, agent: &str) -> Result<()> {
        let sessions = lock_or_recover(&self.sessions);
        let Some(session) = sessions.get(agent) else {
            return Err(anyhow!("no agent console session for {agent}"));
        };
        session.clear_transcript()
    }

    fn terminate(&self, agent: &str) -> Result<AgentConsoleSessionInfo> {
        let mut sessions = lock_or_recover(&self.sessions);
        let Some(session) = sessions.remove(agent) else {
            return Err(anyhow!("no agent console session for {agent}"));
        };
        session.terminate();
        Ok(session.info())
    }
}

async fn list_sessions(State(state): State<AppState>) -> Json<Vec<AgentConsoleSessionInfo>> {
    Json(state.agent_console.list())
}

async fn delete_transcript(
    State(state): State<AppState>,
    Path(agent): Path<String>,
) -> Result<Json<AgentConsoleSessionInfo>, (axum::http::StatusCode, String)> {
    state
        .agent_console
        .delete_transcript(&agent)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let info = {
        let sessions = lock_or_recover(&state.agent_console.sessions);
        sessions
            .get(&agent)
            .map(|session| session.info())
            .ok_or_else(|| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("no agent console session for {agent}"),
                )
            })?
    };
    Ok(Json(info))
}

async fn terminate_session(
    State(state): State<AppState>,
    Path(agent): Path<String>,
) -> Result<Json<AgentConsoleSessionInfo>, (axum::http::StatusCode, String)> {
    let info = state
        .agent_console
        .terminate(&agent)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(info))
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
    let json = serde_json::to_string(&msg).unwrap_or_else(|_| {
        "{\"type\":\"error\",\"data\":\"serialize console message failed\"}".into()
    });
    sender.send(Message::Text(json)).await
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
    transcript_bytes: Arc<AtomicU64>,
    transcript_limit: u64,
    last_activity: Arc<AtomicI64>,
    max_runtime_secs: u64,
    idle_secs: u64,
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
            transcript_bytes: Arc::new(AtomicU64::new(0)),
            transcript_limit: env_u64(
                "KAIJULAB_AGENT_CONSOLE_TRANSCRIPT_BYTES",
                DEFAULT_TRANSCRIPT_BYTES,
            ),
            last_activity: Arc::new(AtomicI64::new(started_at)),
            max_runtime_secs: env_u64(
                "KAIJULAB_AGENT_CONSOLE_MAX_RUNTIME_SECS",
                DEFAULT_MAX_RUNTIME_SECS,
            ),
            idle_secs: env_u64("KAIJULAB_AGENT_CONSOLE_IDLE_SECS", DEFAULT_IDLE_SECS),
            tx,
        };

        session.spawn_reader(&mut reader, transcript_file);
        session.spawn_guard();
        Ok(session)
    }

    fn spawn_reader(&self, reader: &mut File, mut transcript_file: File) {
        let mut reader = reader.try_clone().expect("clone PTY reader");
        let tx = self.tx.clone();
        let running = self.running.clone();
        let transcript = self.transcript.clone();
        let transcript_bytes = self.transcript_bytes.clone();
        let transcript_limit = self.transcript_limit;
        let agent = self.agent.clone();
        let child_pid = self.child_pid;
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        running.store(false, Ordering::SeqCst);
                        reap_child(child_pid);
                        let msg = format!("\r\n[{agent} exited]\r\n");
                        append_transcript(
                            &transcript,
                            &transcript_bytes,
                            transcript_limit,
                            &mut transcript_file,
                            &msg,
                        );
                        let _ = tx.send(ServerMessage::Output(msg));
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        append_transcript(
                            &transcript,
                            &transcript_bytes,
                            transcript_limit,
                            &mut transcript_file,
                            &text,
                        );
                        let _ = tx.send(ServerMessage::Output(text));
                    }
                    Err(e) => {
                        running.store(false, Ordering::SeqCst);
                        reap_child(child_pid);
                        let msg = format!("\r\n[{agent} read error: {e}]\r\n");
                        append_transcript(
                            &transcript,
                            &transcript_bytes,
                            transcript_limit,
                            &mut transcript_file,
                            &msg,
                        );
                        let _ = tx.send(ServerMessage::Error(msg));
                        break;
                    }
                }
            }
        });
    }

    fn spawn_guard(&self) {
        let running = self.running.clone();
        let last_activity = self.last_activity.clone();
        let started_at = self.started_at;
        let idle_secs = self.idle_secs;
        let max_runtime_secs = self.max_runtime_secs;
        let child_pid = self.child_pid;
        let tx = self.tx.clone();
        let info = self.info();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(30));
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                let now = crate::core::events::now_ts();
                let idle_expired = idle_secs > 0
                    && now.saturating_sub(last_activity.load(Ordering::SeqCst)) as u64 > idle_secs;
                let runtime_expired = max_runtime_secs > 0
                    && now.saturating_sub(started_at) as u64 > max_runtime_secs;
                if idle_expired || runtime_expired {
                    running.store(false, Ordering::SeqCst);
                    unsafe {
                        libc::kill(child_pid, libc::SIGHUP);
                    }
                    let reason = if idle_expired {
                        "idle timeout"
                    } else {
                        "runtime limit"
                    };
                    let _ = tx.send(ServerMessage::Error(format!(
                        "agent console stopped by {reason}"
                    )));
                    let mut stopped = info.clone();
                    stopped.running = false;
                    let _ = tx.send(ServerMessage::Status(stopped));
                    break;
                }
            }
        });
    }

    fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.last_activity
            .store(crate::core::events::now_ts(), Ordering::SeqCst);
        let mut master = lock_or_recover(&self.master);
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
        let master = lock_or_recover(&self.master);
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
        reap_child(self.child_pid);
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
        lock_or_recover(&self.transcript).clone()
    }

    fn clear_transcript(&self) -> Result<()> {
        *lock_or_recover(&self.transcript) = String::new();
        self.transcript_bytes.store(0, Ordering::SeqCst);
        File::create(&self.transcript_path)
            .with_context(|| format!("truncate transcript {}", self.transcript_path.display()))?;
        let _ = self.tx.send(ServerMessage::Output(
            "\r\n[transcript cleared from KaijuLab]\r\n".into(),
        ));
        Ok(())
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn append_transcript(
    transcript: &Arc<Mutex<String>>,
    transcript_bytes: &Arc<AtomicU64>,
    transcript_limit: u64,
    file: &mut File,
    text: &str,
) {
    let current = transcript_bytes.load(Ordering::SeqCst);
    if transcript_limit == 0 || current < transcript_limit {
        let remaining = transcript_limit.saturating_sub(current);
        let bytes = text.as_bytes();
        let to_write = if transcript_limit == 0 {
            bytes
        } else {
            &bytes[..bytes.len().min(remaining as usize)]
        };
        let _ = file.write_all(to_write);
        let _ = file.flush();
        transcript_bytes.fetch_add(to_write.len() as u64, Ordering::SeqCst);
    }
    let mut t = lock_or_recover(transcript);
    t.push_str(text);
    if t.len() > TRANSCRIPT_LIMIT {
        let mut keep_from = t.len().saturating_sub(TRANSCRIPT_LIMIT);
        while keep_from < t.len() && !t.is_char_boundary(keep_from) {
            keep_from += 1;
        }
        let trimmed = t[keep_from..].to_string();
        *t = trimmed;
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    let mcp_hint = CString::new("KAIJULAB_AGENT_CONSOLE").unwrap();
    let mcp_hint_value = CString::new("1").unwrap();
    unsafe {
        libc::setenv(term.as_ptr(), term_value.as_ptr(), 1);
        libc::setenv(mcp_hint.as_ptr(), mcp_hint_value.as_ptr(), 1);
        libc::execvp(program.as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

fn transcript_path(agent: &str, started_at: i64) -> Result<PathBuf> {
    let dir = if let Ok(root) = std::env::var("KAIJULAB_AGENT_CONSOLE_TRANSCRIPT_DIR") {
        PathBuf::from(root)
    } else {
        let home = std::env::var("HOME").context("HOME not set")?;
        PathBuf::from(home).join(".kaiju").join("agent-console")
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{agent}-{started_at}.log")))
}

fn master_fd(master: &File) -> libc::c_int {
    use std::os::fd::AsRawFd;
    master.as_raw_fd()
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn reap_child(pid: libc::pid_t) {
    unsafe {
        let mut status = 0;
        let _ = libc::waitpid(pid, &mut status, libc::WNOHANG);
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

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn agent_program_uses_default_binary() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("KAIJULAB_AGENT_CONSOLE_CLAUDE_CMD");
        let cmd = agent_program("claude").unwrap();
        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn agent_program_uses_command_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("KAIJULAB_AGENT_CONSOLE_CLAUDE_CMD", "printf ready");
        let cmd = agent_program("claude").unwrap();
        std::env::remove_var("KAIJULAB_AGENT_CONSOLE_CLAUDE_CMD");
        assert_eq!(cmd.program, "/bin/sh");
        assert_eq!(cmd.args, vec!["-lc", "printf ready"]);
    }

    #[test]
    fn pty_smoke_test_with_shell_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let transcript_dir = tempfile::tempdir().unwrap();
        std::env::set_var(
            "KAIJULAB_AGENT_CONSOLE_TRANSCRIPT_DIR",
            transcript_dir.path(),
        );
        let cmd = AgentCommand {
            program: "/bin/sh".into(),
            args: vec!["-lc".into(), "printf kaijulab-pty-ok".into()],
        };
        let session = AgentSession::spawn("test", &cmd, 80, 24).unwrap();
        std::env::remove_var("KAIJULAB_AGENT_CONSOLE_TRANSCRIPT_DIR");
        std::thread::sleep(Duration::from_millis(200));
        let transcript = session.transcript_tail();
        session.terminate();
        assert!(transcript.contains("kaijulab-pty-ok"), "{transcript:?}");
    }

    #[test]
    fn transcript_trim_keeps_utf8_boundary() {
        let transcript = Arc::new(Mutex::new(String::new()));
        let transcript_bytes = Arc::new(AtomicU64::new(0));
        let mut file = tempfile::tempfile().unwrap();
        let text = "✶ Concocting…\n".repeat(16_000);
        append_transcript(&transcript, &transcript_bytes, 0, &mut file, &text);
        let tail = transcript.lock().unwrap();
        assert!(tail.is_char_boundary(0));
        assert!(tail.len() <= TRANSCRIPT_LIMIT);
    }
}
