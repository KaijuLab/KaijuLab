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

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use core::workspace::{socket_path_for, WorkspaceRegistry, WritePolicy, Workspace};

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
