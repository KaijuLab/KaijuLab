mod agent_bridge;
pub mod arch;
pub mod core;
pub mod decompiler;
pub mod dwarf;
pub mod hashdb;
mod ipc;
mod mcp;
pub mod plugin;
pub mod project;
mod server;
mod tools;

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use core::workspace::{socket_path_for, Workspace, WorkspaceRegistry, WritePolicy};

#[derive(Parser)]
#[command(
    name = "kaijulab",
    about = "KaijuLab — local reverse-engineering workbench driven by your own Claude Code / Codex via MCP",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the local web workbench daemon.  Opens a browser-driven RE
    /// workspace and exposes a Unix socket for the `mcp` shim.  If no FILE
    /// is given the daemon comes up empty — open a binary from the browser
    /// via the path picker or drag-drop.
    Serve {
        /// Binary to auto-open on startup (optional).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,

        /// Address to bind.  Default: 127.0.0.1:7878.  Use `0.0.0.0` only
        /// alongside `--token` for remote access.
        #[arg(long, default_value = "127.0.0.1:7878")]
        bind: String,

        /// Bearer token required by all API calls and WebSocket upgrades when
        /// bound to a non-loopback interface.
        #[arg(long)]
        token: Option<String>,

        /// Enable the `patch_bytes` MCP tool.
        #[arg(long)]
        allow_patch: bool,

        /// Enable the `run_binary` MCP tool.
        #[arg(long)]
        allow_exec: bool,
    },

    /// Run an MCP stdio shim that attaches to a running `serve` daemon for
    /// the same binary, or runs standalone if none is found.
    Mcp {
        /// Binary identifying the workspace. If omitted, attach to the active
        /// workspace most recently opened by the web daemon.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },

    /// One-shot analysis: load the binary, emit a JSON summary to stdout,
    /// and exit.
    Analyze {
        /// Binary to analyse.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Run a Rhai plugin script and exit.  Pass an absolute path to a `.rhai`
    /// file, or just the name of a plugin found in `~/.kaiju/plugins/`.
    Plugin {
        /// Plugin name or path.
        #[arg(value_name = "PLUGIN")]
        name: String,

        /// Binary path the plugin operates on.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },

    /// Install local hooks/config snippets for external tools.
    Hook {
        #[command(subcommand)]
        command: HookCommands,
    },

    /// Script the running web daemon over its REST API.
    Api {
        /// Base URL of `kaijulab serve`.
        #[arg(long, default_value = "http://127.0.0.1:7878")]
        base_url: String,

        /// Bearer token. Defaults to KAIJULAB_API_TOKEN when set.
        #[arg(long)]
        token: Option<String>,

        #[command(subcommand)]
        command: ApiCommands,
    },
}

#[derive(Subcommand)]
enum HookCommands {
    /// Create or update .mcp.json in the current directory for Claude/Codex.
    Setup {
        /// Output path. Defaults to ./.mcp.json.
        #[arg(long, default_value = ".mcp.json")]
        output: PathBuf,

        /// Command path to write. Defaults to this kaijulab executable.
        #[arg(long)]
        command: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ApiCommands {
    /// Raw GET against an /api path, e.g. /api/functions?json=true.
    Get {
        #[arg(value_name = "PATH")]
        path: String,
    },

    /// Raw POST with optional JSON body. Prefix body with @ to read a file.
    Post {
        #[arg(value_name = "PATH")]
        path: String,

        #[arg(long)]
        data: Option<String>,
    },

    /// Raw PATCH with optional JSON body. Prefix body with @ to read a file.
    Patch {
        #[arg(value_name = "PATH")]
        path: String,

        #[arg(long)]
        data: Option<String>,
    },

    /// Raw DELETE against an /api path.
    Delete {
        #[arg(value_name = "PATH")]
        path: String,
    },

    /// Open a binary in the daemon and make it active.
    Open {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Run one deterministic playbook and print the full JSON result.
    RunPlaybook {
        #[arg(value_name = "ID")]
        id: String,

        #[arg(long, default_value_t = 120)]
        max_functions: u32,

        #[arg(long)]
        no_create_findings: bool,
    },

    /// Ask the local Claude/Codex bridge to work on one function.
    AgentRun {
        #[arg(value_name = "AGENT")]
        agent: String,

        #[arg(long, default_value = "triage")]
        kind: String,

        #[arg(long)]
        vaddr: String,

        #[arg(long, default_value = "suggest")]
        write_policy: String,
    },

    /// Attach to the daemon-owned Claude/Codex PTY Agent Console.
    Console {
        #[arg(value_name = "AGENT")]
        agent: String,

        /// Send this prompt once after attaching, then keep streaming output.
        #[arg(long)]
        prompt: Option<String>,

        /// Send trailing Enter after --prompt.
        #[arg(long, default_value_t = true)]
        enter: bool,

        /// Exit after this many seconds without new output. Requires --prompt.
        #[arg(long)]
        idle_timeout_secs: Option<u64>,

        /// Hard cap for prompt mode, independent of terminal spinner output.
        #[arg(long)]
        timeout_secs: Option<u64>,

        /// Delay before sending --prompt so newly spawned terminal UIs can finish booting.
        #[arg(long, default_value_t = 800)]
        input_delay_ms: u64,

        /// Send Ctrl-C before exiting after idle timeout.
        #[arg(long)]
        interrupt_on_idle: bool,

        /// Initial terminal columns reported to the daemon PTY.
        #[arg(long, default_value_t = 120)]
        cols: u16,

        /// Initial terminal rows reported to the daemon PTY.
        #[arg(long, default_value_t = 32)]
        rows: u16,
    },

    /// Poll one async job until it reaches a terminal status.
    WaitJob {
        #[arg(value_name = "JOB_ID")]
        id: String,

        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,

        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve {
            file,
            bind,
            token,
            allow_patch,
            allow_exec,
        } => run_serve(file, bind, token, allow_patch, allow_exec).await,
        Commands::Mcp { file } => run_mcp(file).await,
        Commands::Analyze { file } => run_analyze(file).await,
        Commands::Plugin { name, file } => run_plugin(name, file),
        Commands::Hook { command } => run_hook(command),
        Commands::Api {
            base_url,
            token,
            command,
        } => run_api(base_url, token, command).await,
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

async fn run_serve(
    file: Option<PathBuf>,
    bind: String,
    token: Option<String>,
    allow_patch: bool,
    allow_exec: bool,
) -> Result<()> {
    let policy = WritePolicy {
        allow_patch,
        allow_exec,
    };
    let bus = core::EventBus::new(1024);
    let registry = WorkspaceRegistry::new(bus.clone(), policy);

    if let Some(path) = file {
        match registry.open(&path) {
            Ok(ws) => {
                let socket = socket_path_for(ws.workspace_hash())?;
                if let Err(e) = ipc::spawn_server(socket, ws.clone(), bus.clone()) {
                    tracing::warn!("ipc socket disabled: {}", e);
                }
            }
            Err(e) => tracing::warn!("could not auto-open {}: {}", path.display(), e),
        }
    }

    let addr: std::net::SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --bind '{}': {}", bind, e))?;

    server::serve(registry, bus, addr, token).await
}

async fn run_mcp(file: Option<PathBuf>) -> Result<()> {
    let Some(file) = file else {
        return mcp::run_active().await;
    };
    // Standalone MCP defaults to deny for binary-mutating tools.  When the
    // shim attaches to a daemon, the daemon's WritePolicy applies instead.
    let policy = WritePolicy {
        allow_patch: false,
        allow_exec: false,
    };
    mcp::run(file, policy).await
}

async fn run_analyze(file: PathBuf) -> Result<()> {
    let workspace = Workspace::open(&file, WritePolicy::default())?;
    let info = core::analysis::file_info(&workspace).unwrap_or_default();
    let functions = core::analysis::list_functions(&workspace, true).unwrap_or_default();
    let parsed_fns: serde_json::Value =
        serde_json::from_str(&functions).unwrap_or(serde_json::Value::String(functions));
    let out = serde_json::json!({
        "workspace": workspace.info(),
        "file_info": info,
        "functions": parsed_fns,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_plugin(name: String, file: Option<PathBuf>) -> Result<()> {
    let binary_path = file
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Tools that read $KAIJU_BINARY (e.g. run_python) pick this up automatically.
    if let Some(p) = &file {
        std::env::set_var("KAIJU_BINARY", p.to_string_lossy().as_ref());
    }
    let out = if name.ends_with(".rhai") && std::path::Path::new(&name).exists() {
        plugin::run_file(std::path::Path::new(&name), &binary_path)
    } else {
        plugin::run_named(&name, &binary_path)
    };
    if let Some(err) = &out.error {
        eprintln!("Plugin error: {}", err);
    }
    if !out.text.is_empty() {
        print!("{}", out.text);
    }
    Ok(())
}

fn run_hook(command: HookCommands) -> Result<()> {
    match command {
        HookCommands::Setup { output, command } => setup_mcp_hook(&output, command),
    }
}

async fn run_api(base_url: String, token: Option<String>, command: ApiCommands) -> Result<()> {
    let client = reqwest::Client::new();
    let token = token.or_else(|| std::env::var("KAIJULAB_API_TOKEN").ok());
    let value = match command {
        ApiCommands::Get { path } => {
            api_request(&client, &base_url, token.as_deref(), "GET", &path, None).await?
        }
        ApiCommands::Post { path, data } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                &path,
                Some(parse_api_json_body(data)?),
            )
            .await?
        }
        ApiCommands::Patch { path, data } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "PATCH",
                &path,
                Some(parse_api_json_body(data)?),
            )
            .await?
        }
        ApiCommands::Delete { path } => {
            api_request(&client, &base_url, token.as_deref(), "DELETE", &path, None).await?
        }
        ApiCommands::Open { file } => {
            let path = file
                .canonicalize()
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                "/api/workspaces/open",
                Some(serde_json::json!({ "path": path })),
            )
            .await?
        }
        ApiCommands::RunPlaybook {
            id,
            max_functions,
            no_create_findings,
        } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                &format!("/api/playbooks/{}/run", id),
                Some(serde_json::json!({
                    "max_functions": max_functions,
                    "create_findings": !no_create_findings,
                })),
            )
            .await?
        }
        ApiCommands::AgentRun {
            agent,
            kind,
            vaddr,
            write_policy,
        } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                &format!("/api/agents/{}/run", agent),
                Some(serde_json::json!({
                    "kind": kind,
                    "vaddr": vaddr,
                    "write_policy": write_policy,
                })),
            )
            .await?
        }
        ApiCommands::Console {
            agent,
            prompt,
            enter,
            idle_timeout_secs,
            timeout_secs,
            input_delay_ms,
            interrupt_on_idle,
            cols,
            rows,
        } => {
            run_agent_console(
                &base_url,
                token.as_deref(),
                &agent,
                prompt,
                enter,
                idle_timeout_secs,
                timeout_secs,
                input_delay_ms,
                interrupt_on_idle,
                cols,
                rows,
            )
            .await?;
            return Ok(());
        }
        ApiCommands::WaitJob {
            id,
            timeout_secs,
            interval_ms,
        } => {
            wait_api_job(
                &client,
                &base_url,
                token.as_deref(),
                &id,
                timeout_secs,
                interval_ms,
            )
            .await?
        }
    };
    print_api_value(&value)?;
    Ok(())
}

async fn api_request(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let url = api_url(base_url, path);
    let method = reqwest::Method::from_bytes(method.as_bytes())?;
    let mut req = client.request(method, &url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    if let Some(body) = body {
        req = req.json(&body);
    }
    let response = req.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "{} -> {}{}",
            url,
            status,
            if text.is_empty() {
                String::new()
            } else {
                format!(": {}", text)
            }
        );
    }
    if text.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    Ok(serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::String(text)))
}

fn api_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base = base_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/api/{}", path)
    };
    format!("{}{}", base, path)
}

fn parse_api_json_body(data: Option<String>) -> Result<serde_json::Value> {
    let Some(data) = data else {
        return Ok(serde_json::json!({}));
    };
    let text = if let Some(path) = data.strip_prefix('@') {
        std::fs::read_to_string(path)?
    } else {
        data
    };
    serde_json::from_str(&text).map_err(Into::into)
}

async fn wait_api_job(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    id: &str,
    timeout_secs: u64,
    interval_ms: u64,
) -> Result<serde_json::Value> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let interval = Duration::from_millis(interval_ms.max(50));
    loop {
        let job = api_request(
            client,
            base_url,
            token,
            "GET",
            &format!("/api/jobs/{}", id),
            None,
        )
        .await?;
        let status = job
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if matches!(status, "ok" | "failed" | "cancelled") {
            return Ok(job);
        }
        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for job {}", id);
        }
        tokio::time::sleep(interval).await;
    }
}

fn print_api_value(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

async fn run_agent_console(
    base_url: &str,
    token: Option<&str>,
    agent: &str,
    prompt: Option<String>,
    enter: bool,
    idle_timeout_secs: Option<u64>,
    timeout_secs: Option<u64>,
    input_delay_ms: u64,
    interrupt_on_idle: bool,
    cols: u16,
    rows: u16,
) -> Result<()> {
    let url = agent_console_url(base_url, token, agent);
    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut sink, mut stream) = ws.split();

    sink.send(WsMessage::Text(
        serde_json::json!({ "type": "resize", "cols": cols, "rows": rows }).to_string(),
    ))
    .await?;

    if let Some(prompt) = prompt {
        let mut saw_status = false;
        let status_deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(status_deadline);
        while !saw_status {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            saw_status = handle_console_message(msg)?;
                            std::io::stdout().flush()?;
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => break,
                    }
                }
                _ = &mut status_deadline => break,
            }
        }
        if input_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(input_delay_ms)).await;
        }

        let needs_enter = enter;
        sink.send(WsMessage::Text(
            serde_json::json!({ "type": "input", "data": prompt }).to_string(),
        ))
        .await?;
        if needs_enter {
            tokio::time::sleep(Duration::from_millis(150)).await;
            sink.send(WsMessage::Text(
                serde_json::json!({ "type": "input", "data": "\r" }).to_string(),
            ))
            .await?;
        }
        let idle = Duration::from_secs(idle_timeout_secs.unwrap_or(20));
        let mut idle_timer = Box::pin(tokio::time::sleep(idle));
        let max_runtime = Duration::from_secs(timeout_secs.unwrap_or(300));
        let mut runtime_timer = Box::pin(tokio::time::sleep(max_runtime));
        loop {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            if handle_console_message(msg)? {
                                std::io::stdout().flush()?;
                                idle_timer.as_mut().reset(tokio::time::Instant::now() + idle);
                            }
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => break,
                    }
                }
                _ = &mut idle_timer => {
                    if interrupt_on_idle {
                        sink.send(WsMessage::Text(serde_json::json!({ "type": "interrupt" }).to_string())).await?;
                    }
                    break;
                }
                _ = &mut runtime_timer => {
                    if interrupt_on_idle {
                        sink.send(WsMessage::Text(serde_json::json!({ "type": "interrupt" }).to_string())).await?;
                    }
                    eprintln!("[kaijulab] agent console timeout after {}s", max_runtime.as_secs());
                    break;
                }
            }
        }
        return Ok(());
    }

    let stdin_task = tokio::spawn(async move {
        let mut input = tokio::io::stdin();
        let mut buf = [0_u8; 4096];
        loop {
            match input.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if sink
                        .send(WsMessage::Text(
                            serde_json::json!({ "type": "input", "data": data }).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    while let Some(msg) = stream.next().await {
        handle_console_message(msg?)?;
        std::io::stdout().flush()?;
    }
    stdin_task.abort();
    Ok(())
}

fn handle_console_message(msg: WsMessage) -> Result<bool> {
    match msg {
        WsMessage::Text(text) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                match value.get("type").and_then(|v| v.as_str()) {
                    Some("output") => {
                        if let Some(data) = value.get("data").and_then(|v| v.as_str()) {
                            print!("{data}");
                            return Ok(!data.is_empty());
                        }
                    }
                    Some("error") => {
                        if let Some(data) = value.get("data").and_then(|v| v.as_str()) {
                            eprintln!("[kaijulab] agent console error: {data}");
                            return Ok(true);
                        }
                    }
                    Some("status") => {
                        if let Some(data) = value.get("data") {
                            let agent = data
                                .get("agent")
                                .and_then(|v| v.as_str())
                                .unwrap_or("agent");
                            let command =
                                data.get("command").and_then(|v| v.as_str()).unwrap_or("");
                            let running = data
                                .get("running")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            eprintln!(
                                "[kaijulab] {agent} console {}: {command}",
                                if running { "running" } else { "stopped" }
                            );
                            return Ok(true);
                        }
                    }
                    _ => {}
                }
            } else {
                print!("{text}");
                return Ok(!text.is_empty());
            }
        }
        WsMessage::Binary(bytes) => {
            std::io::stdout().write_all(&bytes)?;
            return Ok(!bytes.is_empty());
        }
        WsMessage::Close(_) => return Ok(false),
        _ => {}
    }
    Ok(false)
}

fn agent_console_url(base_url: &str, token: Option<&str>, agent: &str) -> String {
    let mut base = base_url.trim_end_matches('/').to_string();
    if let Some(rest) = base.strip_prefix("https://") {
        base = format!("wss://{rest}");
    } else if let Some(rest) = base.strip_prefix("http://") {
        base = format!("ws://{rest}");
    }
    let mut url = format!("{base}/api/agent-console/{agent}");
    if let Some(token) = token {
        let encoded = token
            .bytes()
            .flat_map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    vec![b as char]
                }
                _ => format!("%{b:02X}").chars().collect(),
            })
            .collect::<String>();
        url.push_str("?token=");
        url.push_str(&encoded);
    }
    url
}

fn setup_mcp_hook(output: &Path, command: Option<PathBuf>) -> Result<()> {
    let raw_command = command.unwrap_or(std::env::current_exe()?);
    let command = raw_command
        .canonicalize()
        .unwrap_or_else(|_| raw_command.clone());

    let mut root = if output.exists() {
        let text = std::fs::read_to_string(output)?;
        serde_json::from_str::<serde_json::Value>(&text)?
    } else {
        serde_json::json!({})
    };

    if !root.is_object() {
        anyhow::bail!("{} exists but is not a JSON object", output.display());
    }
    let obj = root.as_object_mut().expect("checked object");
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        anyhow::bail!("{}.mcpServers exists but is not a JSON object", output.display());
    }
    servers
        .as_object_mut()
        .expect("checked object")
        .insert(
            "kaijulab".to_string(),
            serde_json::json!({
                "command": command.to_string_lossy(),
                "args": ["mcp"],
            }),
        );

    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
    println!(
        "Wrote {} with kaijulab MCP command: {} mcp",
        output.display(),
        command.display()
    );
    Ok(())
}
