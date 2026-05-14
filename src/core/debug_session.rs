//! Live debugger session manager.
//!
//! Sessions are daemon-owned `gdb` / `gdb-multiarch` subprocesses. Foreign ELF
//! targets are launched under qemu-user's gdbstub (`qemu-ARCH -g PORT`) and
//! then controlled through gdb. Each command result is returned as structured
//! JSON and appended to the target evidence log.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use goblin::elf::header::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::evidence;

#[derive(Clone, Default)]
pub struct DebugSessionManager {
    sessions: Arc<Mutex<HashMap<String, DebugSession>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSessionInfo {
    pub id: String,
    pub binary_path: String,
    pub arch: String,
    pub mode: String,
    pub gdb: String,
    pub qemu: Option<String>,
    pub remote: Option<String>,
    pub created_at: String,
    pub last_summary: Option<String>,
    pub breakpoints: Vec<String>,
}

struct DebugSession {
    info: DebugSessionInfo,
    gdb: Child,
    gdb_stdin: ChildStdin,
    gdb_stdout: mpsc::Receiver<u8>,
    qemu: Option<Child>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StartDebugSession {
    pub args: Option<Vec<String>>,
    pub sysroot: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DebugAction {
    pub action: String,
    pub address: Option<String>,
    pub length: Option<usize>,
    pub command: Option<String>,
}

impl DebugSessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&self, binary: &Path, req: StartDebugSession) -> Result<Value> {
        let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
        let arch = elf_arch(&data).unwrap_or_else(|| std::env::consts::ARCH.to_string());
        let host = host_arch();
        let foreign = arch != host;
        let id = format!("dbg_{}", &Uuid::new_v4().simple().to_string()[..8]);
        let args = req.args.unwrap_or_default();

        let mut qemu_child = None;
        let mut remote = None;
        let (gdb_path, mode) = if foreign {
            let qemu = qemu_for_arch(&arch)
                .ok_or_else(|| anyhow::anyhow!("missing qemu-user runner for {arch}"))?;
            let gdb = find_in_path("gdb-multiarch")
                .ok_or_else(|| anyhow::anyhow!("missing gdb-multiarch for foreign target"))?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);

            let mut qemu_cmd = Command::new(&qemu);
            qemu_cmd.arg("-g").arg(port.to_string());
            if let Some(sysroot) = req.sysroot.as_deref() {
                qemu_cmd.arg("-L").arg(sysroot);
            } else if has_missing_interpreter(&data) {
                anyhow::bail!("target dynamic loader/sysroot is missing; pass sysroot");
            }
            qemu_cmd
                .arg(binary)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                qemu_cmd.process_group(0);
            }
            qemu_child = Some(qemu_cmd.spawn()?);
            remote = Some(format!("127.0.0.1:{port}"));
            (gdb, "qemu-gdbstub".to_string())
        } else {
            let gdb = find_in_path("gdb").ok_or_else(|| anyhow::anyhow!("missing gdb"))?;
            (gdb, "native-gdb".to_string())
        };

        let mut gdb_cmd = Command::new(&gdb_path);
        gdb_cmd
            .arg("--quiet")
            .arg("--nx")
            .arg(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            gdb_cmd.process_group(0);
        }
        let mut gdb = gdb_cmd.spawn()?;
        let gdb_stdin = gdb.stdin.take().context("gdb stdin missing")?;
        let gdb_stdout = spawn_stdout_reader(gdb.stdout.take().context("gdb stdout missing")?);
        let mut session = DebugSession {
            info: DebugSessionInfo {
                id: id.clone(),
                binary_path: binary.to_string_lossy().into_owned(),
                arch,
                mode,
                gdb: gdb_path,
                qemu: qemu_child.as_ref().map(|_| "qemu-user".to_string()),
                remote: remote.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                last_summary: None,
                breakpoints: Vec::new(),
            },
            gdb,
            gdb_stdin,
            gdb_stdout,
            qemu: qemu_child,
        };

        let _ = session.read_until_prompt(Duration::from_secs(3));
        session.cmd("set pagination off", Duration::from_secs(3))?;
        session.cmd("set confirm off", Duration::from_secs(3))?;
        session.cmd("set debuginfod enabled off", Duration::from_secs(3))?;
        session.cmd("set disassembly-flavor intel", Duration::from_secs(3))?;
        if let Some(remote) = &remote {
            session.cmd(&format!("target remote {remote}"), Duration::from_secs(8))?;
        } else {
            if !args.is_empty() {
                session.cmd(
                    &format!("set args {}", args.join(" ")),
                    Duration::from_secs(3),
                )?;
            }
            session.cmd("starti", Duration::from_secs(8))?;
        }

        let snapshot = session.snapshot_json("start", "");
        evidence::append(
            binary,
            "debug_session",
            format!("debug session {id} started"),
            vec!["debug-session".into(), "start".into()],
            snapshot.clone(),
        )?;
        let info = session.info.clone();
        self.sessions
            .lock()
            .expect("debug sessions poisoned")
            .insert(id, session);
        Ok(json!({ "session": info, "snapshot": snapshot }))
    }

    pub fn list(&self) -> Vec<DebugSessionInfo> {
        let mut out: Vec<_> = self
            .sessions
            .lock()
            .expect("debug sessions poisoned")
            .values()
            .map(|s| s.info.clone())
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out
    }

    pub fn get(&self, id: &str) -> Option<DebugSessionInfo> {
        self.sessions
            .lock()
            .expect("debug sessions poisoned")
            .get(id)
            .map(|s| s.info.clone())
    }

    pub fn action(&self, id: &str, action: DebugAction) -> Result<Value> {
        let mut sessions = self.sessions.lock().expect("debug sessions poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("debug session not found: {id}"))?;
        let command = gdb_command(&action)?;
        let mut raw = session.cmd(&command, Duration::from_secs(20))?;
        if matches!(action.action.as_str(), "continue" | "step" | "stepi") {
            raw.push_str(&session.cmd("info registers", Duration::from_secs(5))?);
            raw.push_str(&session.cmd("x/16i $pc", Duration::from_secs(5))?);
        }
        if action.action == "break" {
            if let Some(address) = action.address.as_deref() {
                session.info.breakpoints.push(address.to_string());
            }
        }
        let result = session.snapshot_json(&action.action, &raw);
        let summary = summarize_action(&action.action, &result);
        session.info.last_summary = Some(summary.clone());
        evidence::append(
            Path::new(&session.info.binary_path),
            "debug_session_action",
            summary,
            vec!["debug-session".into(), action.action.clone()],
            result.clone(),
        )?;
        Ok(result)
    }

    pub fn stop(&self, id: &str) -> Result<Option<Value>> {
        let Some(mut session) = self
            .sessions
            .lock()
            .expect("debug sessions poisoned")
            .remove(id)
        else {
            return Ok(None);
        };
        let _ = session.cmd("quit", Duration::from_secs(2));
        let _ = session.gdb.kill();
        if let Some(mut qemu) = session.qemu.take() {
            let _ = qemu.kill();
        }
        let result = json!({ "stopped": session.info, "ts": chrono::Utc::now().to_rfc3339() });
        evidence::append(
            Path::new(&session.info.binary_path),
            "debug_session",
            format!("debug session {id} stopped"),
            vec!["debug-session".into(), "stop".into()],
            result.clone(),
        )?;
        Ok(Some(result))
    }
}

impl Drop for DebugSession {
    fn drop(&mut self) {
        let _ = self.gdb.kill();
        if let Some(qemu) = self.qemu.as_mut() {
            let _ = qemu.kill();
        }
    }
}

impl DebugSession {
    fn cmd(&mut self, command: &str, timeout: Duration) -> Result<String> {
        writeln!(self.gdb_stdin, "{command}")?;
        self.gdb_stdin.flush()?;
        self.read_until_prompt(timeout)
    }

    fn read_until_prompt(&mut self, timeout: Duration) -> Result<String> {
        let start = Instant::now();
        let mut out = Vec::new();
        loop {
            if start.elapsed() > timeout {
                out.extend_from_slice(b"\n[kaijulab] gdb command timed out\n");
                break;
            }
            match self.gdb_stdout.recv_timeout(Duration::from_millis(50)) {
                Ok(byte) => {
                    out.push(byte);
                    if out.ends_with(b"(gdb) ") || out.ends_with(b"(gdb)\n") {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    fn snapshot_json(&self, action: &str, raw: &str) -> Value {
        json!({
            "kind": "debug_session_action",
            "session": self.info,
            "action": action,
            "raw": raw,
            "registers": parse_registers(raw),
            "signals": extract_signals(raw),
            "backtrace": parse_backtrace(raw),
            "disassembly": parse_disassembly(raw),
            "ts": chrono::Utc::now().to_rfc3339(),
        })
    }
}

fn gdb_command(action: &DebugAction) -> Result<String> {
    Ok(match action.action.as_str() {
        "break" => {
            let address = action
                .address
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("break requires address"))?;
            if address.starts_with("0x") || address.chars().all(|c| c.is_ascii_hexdigit()) {
                format!("break *{address}")
            } else {
                format!("break {address}")
            }
        }
        "continue" => "continue".to_string(),
        "stepi" | "step" => "stepi".to_string(),
        "registers" => "info registers".to_string(),
        "backtrace" => "bt".to_string(),
        "disassemble_pc" => {
            let len = action.length.unwrap_or(16).clamp(1, 128);
            format!("x/{len}i $pc")
        }
        "memory" => {
            let address = action
                .address
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("memory requires address"))?;
            let len = action.length.unwrap_or(64).clamp(1, 4096);
            format!("x/{len}xb {address}")
        }
        "snapshot" => "info registers\nbt\nx/16i $pc".to_string(),
        "raw" => action
            .command
            .clone()
            .ok_or_else(|| anyhow::anyhow!("raw requires command"))?,
        other => anyhow::bail!("unsupported debug action: {other}"),
    })
}

fn spawn_stdout_reader(mut stdout: ChildStdout) -> mpsc::Receiver<u8> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0_u8; 1024];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for byte in &buf[..n] {
                        if tx.send(*byte).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn summarize_action(action: &str, result: &Value) -> String {
    let pc = result
        .get("registers")
        .and_then(|r| {
            r.get("rip")
                .or_else(|| r.get("eip"))
                .or_else(|| r.get("pc"))
        })
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let signals = result
        .get("signals")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    format!("debug-session action={action} pc={pc} signals={signals}")
}

fn elf_arch(data: &[u8]) -> Option<String> {
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return None;
    };
    Some(match (elf.header.e_machine, elf.is_64) {
        (EM_X86_64, _) => "x86_64".to_string(),
        (EM_386, _) => "i386".to_string(),
        (EM_AARCH64, _) => "aarch64".to_string(),
        (EM_ARM, _) => "arm".to_string(),
        (_, true) => format!("machine:{}-64", elf.header.e_machine),
        _ => format!("machine:{}-32", elf.header.e_machine),
    })
}

fn has_missing_interpreter(data: &[u8]) -> bool {
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return false;
    };
    elf.interpreter
        .is_some_and(|interpreter| !Path::new(interpreter).exists())
}

fn host_arch() -> String {
    match std::env::consts::ARCH {
        "x86" | "i386" | "i586" | "i686" => "i386".to_string(),
        other => other.to_string(),
    }
}

fn qemu_for_arch(arch: &str) -> Option<String> {
    let names: &[&str] = match arch {
        "i386" => &["qemu-i386-static", "qemu-i386"],
        "x86_64" => &["qemu-x86_64-static", "qemu-x86_64"],
        "aarch64" => &["qemu-aarch64-static", "qemu-aarch64"],
        "arm" => &["qemu-arm-static", "qemu-arm"],
        _ => &[],
    };
    names.iter().find_map(|name| find_in_path(name))
}

fn find_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn parse_registers(text: &str) -> Value {
    let mut out = serde_json::Map::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if is_register_name(name) && value.starts_with("0x") {
            out.insert(name.to_string(), json!(value));
        }
    }
    Value::Object(out)
}

fn is_register_name(name: &str) -> bool {
    matches!(
        name,
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "eip"
            | "eflags"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "x0"
            | "x1"
            | "x2"
            | "x3"
            | "x4"
            | "x5"
            | "x6"
            | "x7"
            | "sp"
            | "pc"
            | "lr"
            | "cpsr"
    )
}

fn extract_signals(text: &str) -> Vec<String> {
    [
        "SIGSEGV", "SIGILL", "SIGABRT", "SIGBUS", "SIGFPE", "SIGTRAP",
    ]
    .iter()
    .filter(|sig| text.contains(**sig))
    .map(|sig| (*sig).to_string())
    .collect()
}

fn parse_backtrace(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|line| line.trim_start().starts_with('#'))
        .map(|line| json!({ "text": line }))
        .collect()
}

fn parse_disassembly(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|line| line.contains("=>") || line.trim_start().starts_with("0x"))
        .map(|line| json!({ "text": line }))
        .collect()
}
