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
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use object::{Object, ObjectSection};
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

    /// Build an exploit-workbench context bundle for the active binary.
    ExploitContext {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum matches per gadget pattern.
        #[arg(long, default_value_t = 8)]
        max_gadgets: usize,
    },

    /// Execute a candidate PoC script and evaluate simple success predicates.
    ExploitVerify {
        #[arg(value_name = "SCRIPT")]
        script: PathBuf,

        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Script wall-clock timeout.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,

        /// Expected process exit code.
        #[arg(long)]
        expect_exit: Option<i32>,

        /// Expected target exit code printed by the PoC as returncode=<N>.
        #[arg(long)]
        expect_target_exit: Option<i32>,

        /// Expected substring in stdout or stderr.
        #[arg(long)]
        expect_output: Option<String>,

        /// Append verifier output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,

        /// Arguments passed to the script after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Send a bounded exploit-development loop prompt into Agent Console.
    ExploitLoop {
        #[arg(value_name = "AGENT")]
        agent: String,

        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Candidate PoC path the agent should create.
        #[arg(long, default_value = "/tmp/kaijulab-poc.py")]
        output: PathBuf,

        /// Goal for the generated PoC.
        #[arg(
            long,
            default_value = "Create a Python stdlib PoC and prove local code execution with exit(42) or command output."
        )]
        goal: String,

        /// Maximum analysis/fix attempts the prompt should spend.
        #[arg(long, default_value_t = 3)]
        attempts: u32,

        /// Agent console hard timeout.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,

        /// Console idle timeout.
        #[arg(long, default_value_t = 30)]
        idle_timeout_secs: u64,
    },

    /// Run the target with captured stdin/stdout/stderr and runtime diagnostics.
    RuntimeRun {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Arguments passed to the target.
        #[arg(long = "arg")]
        args: Vec<String>,

        /// Environment entries as KEY=VALUE.
        #[arg(long = "env")]
        envs: Vec<String>,

        /// Stdin text to feed, or @path to read bytes from a file.
        #[arg(long)]
        stdin: Option<String>,

        /// Working directory.
        #[arg(long)]
        cwd: Option<PathBuf>,

        /// Force a runner command, e.g. qemu-i386.
        #[arg(long)]
        runner: Option<String>,

        /// qemu -L sysroot when using qemu-user.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Wall-clock timeout.
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,

        /// Append runtime output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Run a non-interactive gdb probe and return registers/backtrace/disassembly.
    DebugProbe {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Arguments passed to the target inside gdb.
        #[arg(long = "arg")]
        args: Vec<String>,

        /// Stdin text to feed, or @path to read bytes from a file.
        #[arg(long)]
        stdin: Option<String>,

        /// qemu -L sysroot when remote-debugging a foreign-architecture target.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Breakpoint address or symbol. Can be repeated.
        #[arg(long = "break")]
        breakpoints: Vec<String>,

        /// Continue after hitting breakpoints instead of stopping at first hit.
        #[arg(long)]
        continue_after_break: bool,

        /// GDB wall-clock timeout.
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        /// Append debug output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Emit exploit helper data: checksec, PLT/GOT, gadgets, cyclic patterns.
    ExploitKit {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Generate a cyclic pattern of this length.
        #[arg(long)]
        cyclic_len: Option<usize>,

        /// Find a little-endian integer/hex/text value inside the cyclic pattern.
        #[arg(long)]
        cyclic_find: Option<String>,

        /// Pattern length used by --cyclic-find.
        #[arg(long, default_value_t = 8192)]
        cyclic_search_len: usize,

        /// Maximum matches per gadget pattern.
        #[arg(long, default_value_t = 16)]
        max_gadgets: usize,
    },

    /// Query structured static-analysis data for agent workflows.
    IrQuery {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Function virtual address to inspect.
        #[arg(long)]
        function: Option<String>,

        /// Search term for function names/decompile/strings.
        #[arg(long)]
        search: Option<String>,

        /// Maximum functions/strings to include.
        #[arg(long, default_value_t = 80)]
        max: usize,
    },

    /// Emit recovery-backed decompile context for one function.
    DecompileEnhanced {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Function virtual address to inspect.
        #[arg(value_name = "VADDR")]
        vaddr: String,
    },

    /// Emit structured decompiler analysis facts for one function.
    DecompileAnalysis {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Function virtual address to inspect.
        #[arg(value_name = "VADDR")]
        vaddr: String,
    },

    /// Score decompiler quality for one binary or corpus.
    DecompilerBenchmark {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Corpus root. Used when --file is omitted.
        #[arg(long, default_value = "samples")]
        root: PathBuf,

        /// Maximum binaries to inspect in corpus mode.
        #[arg(long, default_value_t = 16)]
        max_files: usize,

        /// Maximum functions per binary.
        #[arg(long, default_value_t = 200)]
        max_functions: usize,

        /// Optional path to write the JSON artifact.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Build a stateful analysis-loop bundle for agents or automation.
    AnalysisLoop {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Current hypothesis or task goal.
        #[arg(long, default_value = "Develop and verify a local exploit PoC.")]
        goal: String,

        /// Last observation from a failed run/debug probe.
        #[arg(long)]
        observation: Option<String>,

        /// Candidate PoC path, if any.
        #[arg(long)]
        candidate: Option<PathBuf>,

        /// Maximum matches per gadget pattern.
        #[arg(long, default_value_t = 8)]
        max_gadgets: usize,
    },

    /// Emit production-workstation capability status across the seven roadmap areas.
    WorkstationStatus {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Build a normalized binary index for agents, UI panes, and benchmarks.
    IndexBuild {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions to include.
        #[arg(long, default_value_t = 120)]
        max_functions: usize,

        /// Maximum strings to include.
        #[arg(long, default_value_t = 120)]
        max_strings: usize,

        /// Optional path to write the JSON artifact.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Build the derived program knowledge graph from index/project/evidence facts.
    KnowledgeGraph {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions to include.
        #[arg(long, default_value_t = 300)]
        max_functions: usize,

        /// Maximum evidence records to link.
        #[arg(long, default_value_t = 200)]
        max_evidence: usize,

        /// Optional path to write the JSON artifact.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Emit the ranked function triage queue from the knowledge graph.
    TriageQueue {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum queue items to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Run professional recursive function/CFG/xref recovery.
    RecoveryIndex {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions to recover.
        #[arg(long, default_value_t = 1000)]
        max_functions: usize,

        /// Optional path to write the JSON artifact.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Rebuild and persist recovery facts into the project SQLite DB.
    RecoveryRebuild {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions to recover.
        #[arg(long, default_value_t = 1000)]
        max_functions: usize,
    },

    /// Load persisted recovery facts, rebuilding when missing.
    RecoveryStored {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions if rebuild is needed.
        #[arg(long, default_value_t = 1000)]
        max_functions: usize,
    },

    /// Record an analyst correction for recovered code/data/function facts.
    RecoveryCorrect {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Correction action: rename_function, mark_code, mark_data, split_function, merge_function.
        #[arg(long)]
        action: String,

        /// Address being corrected.
        #[arg(long)]
        vaddr: String,

        /// Target address for merge_function.
        #[arg(long)]
        target: Option<String>,

        /// Human note or fallback name for rename_function.
        #[arg(long)]
        note: Option<String>,

        /// Optional JSON data object.
        #[arg(long)]
        data: Option<String>,
    },

    /// Query graph-backed code xrefs to an address.
    RecoveryXrefs {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Target virtual address.
        #[arg(value_name = "VADDR")]
        vaddr: String,

        /// Maximum functions to recover before querying.
        #[arg(long, default_value_t = 1000)]
        max_functions: usize,
    },

    /// Query recovered CFG for a function start address.
    RecoveryCfg {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Function start virtual address.
        #[arg(value_name = "VADDR")]
        vaddr: String,

        /// Maximum functions to recover before querying.
        #[arg(long, default_value_t = 1000)]
        max_functions: usize,
    },

    /// Diagnose qemu/gdb/container/sysroot readiness.
    SysrootDoctor {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Emit the exploit-automation stack manifest.
    ExploitStack {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Emit a resumable agent-job plan with phases, artifacts, and stop criteria.
    AgentJobPlan {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Job goal.
        #[arg(
            long,
            default_value = "Analyze the target and produce verified artifacts."
        )]
        goal: String,
    },

    /// Emit the dense workbench UI contract.
    WorkbenchManifest,

    /// Inventory a benchmark corpus and expected grading artifacts.
    BenchmarkPlan {
        /// Corpus root.
        #[arg(long, default_value = "samples")]
        root: PathBuf,

        /// Maximum candidate binaries to inspect.
        #[arg(long, default_value_t = 64)]
        max_files: usize,
    },

    /// List immutable runtime/debug/verification evidence records for a target.
    EvidenceList {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Filter by evidence kind, e.g. runtime_run, debug_probe, exploit_verify.
        #[arg(long)]
        kind: Option<String>,

        /// Maximum records to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Emit reusable execution profiles for the target.
    ExecutionProfiles {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Emit the planned persistent debugger session contract for the target.
    DebugSessionContract {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Emit smoke-test checks for benchmark regression harnesses.
    BenchmarkSmoke {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Execute a bounded smoke benchmark corpus and print structured results.
    BenchmarkRun {
        /// Corpus root or single binary.
        #[arg(long, default_value = "samples")]
        root: PathBuf,

        /// Maximum candidate binaries to execute.
        #[arg(long, default_value_t = 8)]
        max_files: usize,

        /// Per-target runtime/debug timeout.
        #[arg(long, default_value_t = 6)]
        timeout_secs: u64,

        /// Optional path to write the JSON artifact.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Append runtime/debug observations to each target evidence log.
        #[arg(long)]
        save_evidence: bool,
    },

    /// Feed a cyclic pattern under gdb and report candidate crash offsets.
    CrashOffset {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Pattern length to feed on stdin.
        #[arg(long, default_value_t = 4096)]
        pattern_len: usize,

        /// Arguments passed to the target inside gdb.
        #[arg(long = "arg")]
        args: Vec<String>,

        /// qemu -L sysroot when remote-debugging a foreign target.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// GDB wall-clock timeout.
        #[arg(long, default_value_t = 12)]
        timeout_secs: u64,

        /// Append crash-offset output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Start a daemon-owned live debugger session for the active target.
    DebugSessionStart {
        /// Arguments passed to the debug target.
        #[arg(long = "arg")]
        args: Vec<String>,

        /// qemu -L sysroot for foreign dynamic targets.
        #[arg(long)]
        sysroot: Option<PathBuf>,
    },

    /// List daemon-owned live debugger sessions.
    DebugSessionList,

    /// Show one live debugger session.
    DebugSessionGet {
        #[arg(value_name = "SESSION_ID")]
        id: String,
    },

    /// Run one action against a live debugger session.
    DebugSessionAction {
        #[arg(value_name = "SESSION_ID")]
        id: String,

        /// Action: break, continue, stepi, registers, backtrace, disassemble_pc, memory, snapshot, raw.
        #[arg(value_name = "ACTION")]
        action: String,

        /// Address for break/memory.
        #[arg(long)]
        address: Option<String>,

        /// Length for memory/disassemble_pc.
        #[arg(long)]
        length: Option<usize>,

        /// Raw gdb command when ACTION=raw.
        #[arg(long)]
        command: Option<String>,
    },

    /// Stop one live debugger session.
    DebugSessionStop {
        #[arg(value_name = "SESSION_ID")]
        id: String,
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
        ApiCommands::ExploitContext { file, max_gadgets } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            build_exploit_context(&path, max_gadgets)?
        }
        ApiCommands::ExploitVerify {
            script,
            file,
            timeout_secs,
            expect_exit,
            expect_target_exit,
            expect_output,
            save_evidence,
            tags,
            args,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = verify_exploit_script(
                &script,
                &path,
                timeout_secs,
                expect_exit,
                expect_target_exit,
                expect_output.as_deref(),
                &args,
            )?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "exploit_verify",
                verify_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::ExploitLoop {
            agent,
            file,
            output,
            goal,
            attempts,
            timeout_secs,
            idle_timeout_secs,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let context = build_exploit_context(&path, 8)?;
            let prompt = exploit_loop_prompt(&path, &output, &goal, attempts, &context)?;
            run_agent_console(
                &base_url,
                token.as_deref(),
                &agent,
                Some(prompt),
                true,
                Some(idle_timeout_secs),
                Some(timeout_secs),
                1500,
                true,
                120,
                32,
            )
            .await?;
            return Ok(());
        }
        ApiCommands::RuntimeRun {
            file,
            args,
            envs,
            stdin,
            cwd,
            runner,
            sysroot,
            timeout_secs,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = runtime_run_json(
                &path,
                &args,
                &envs,
                stdin.as_deref(),
                cwd.as_deref(),
                runner.as_deref(),
                sysroot.as_deref(),
                timeout_secs,
            )?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "runtime_run",
                runtime_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::DebugProbe {
            file,
            args,
            stdin,
            sysroot,
            breakpoints,
            continue_after_break,
            timeout_secs,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = debug_probe_json(
                &path,
                &args,
                stdin.as_deref(),
                sysroot.as_deref(),
                &breakpoints,
                continue_after_break,
                timeout_secs,
            )?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "debug_probe",
                debug_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::ExploitKit {
            file,
            cyclic_len,
            cyclic_find,
            cyclic_search_len,
            max_gadgets,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            exploit_kit_json(
                &path,
                cyclic_len,
                cyclic_find.as_deref(),
                cyclic_search_len,
                max_gadgets,
            )?
        }
        ApiCommands::IrQuery {
            file,
            function,
            search,
            max,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            ir_query_json(&path, function.as_deref(), search.as_deref(), max)?
        }
        ApiCommands::DecompileEnhanced { file, vaddr } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let vaddr = parse_int(&vaddr)?;
            serde_json::json!({
                "kind": "decompile_enhanced",
                "binary": path,
                "vaddr": format!("0x{vaddr:x}"),
                "text": core::decompile::decompile_enhanced_path(&path, vaddr)?,
            })
        }
        ApiCommands::DecompileAnalysis { file, vaddr } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let vaddr = parse_int(&vaddr)?;
            serde_json::to_value(core::decompile::decompile_analysis_path(&path, vaddr)?)?
        }
        ApiCommands::DecompilerBenchmark {
            file,
            root,
            max_files,
            max_functions,
            output,
        } => {
            let value = if let Some(file) = file {
                let path =
                    resolve_api_binary_path(&client, &base_url, token.as_deref(), Some(file)).await?;
                serde_json::to_value(core::decompile::decompiler_quality_report_path(
                    &path,
                    max_functions,
                )?)?
            } else {
                decompiler_benchmark_json(&root, max_files, max_functions)?
            };
            if let Some(output) = output {
                write_json_artifact(&output, &value)?;
            }
            value
        }
        ApiCommands::AnalysisLoop {
            file,
            goal,
            observation,
            candidate,
            max_gadgets,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            analysis_loop_json(
                &path,
                &goal,
                observation.as_deref(),
                candidate.as_deref(),
                max_gadgets,
            )?
        }
        ApiCommands::WorkstationStatus { file } => {
            let path = resolve_optional_api_binary_path(&client, &base_url, token.as_deref(), file)
                .await?;
            core::workstation::workstation_status(path.as_deref())?
        }
        ApiCommands::IndexBuild {
            file,
            max_functions,
            max_strings,
            output,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = core::workstation::binary_index(&path, max_functions, max_strings)?;
            if let Some(output) = output {
                write_json_artifact(&output, &value)?;
            }
            value
        }
        ApiCommands::KnowledgeGraph {
            file,
            max_functions,
            max_evidence,
            output,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let ws = Workspace::open(&path, WritePolicy::default())?;
            let value = serde_json::to_value(core::knowledge::build(&ws, max_functions, max_evidence)?)?;
            if let Some(output) = output {
                write_json_artifact(&output, &value)?;
            }
            value
        }
        ApiCommands::TriageQueue { file, limit } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let ws = Workspace::open(&path, WritePolicy::default())?;
            core::knowledge::triage_queue(&ws, limit)?
        }
        ApiCommands::RecoveryIndex {
            file,
            max_functions,
            output,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = serde_json::to_value(core::recovery::recover(&path, max_functions)?)?;
            if let Some(output) = output {
                write_json_artifact(&output, &value)?;
            }
            value
        }
        ApiCommands::RecoveryRebuild {
            file,
            max_functions,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let ws = Workspace::open(&path, WritePolicy::default())?;
            serde_json::to_value(core::recovery_store::rebuild(&ws, max_functions)?)?
        }
        ApiCommands::RecoveryStored {
            file,
            max_functions,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let ws = Workspace::open(&path, WritePolicy::default())?;
            serde_json::to_value(core::recovery_store::load_or_rebuild(&ws, max_functions)?)?
        }
        ApiCommands::RecoveryCorrect {
            file,
            action,
            vaddr,
            target,
            note,
            data,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let ws = Workspace::open(&path, WritePolicy::default())?;
            let data = data
                .map(|s| serde_json::from_str::<serde_json::Value>(&s))
                .transpose()?
                .unwrap_or_else(|| serde_json::json!({}));
            core::recovery_store::correction(
                &ws,
                core::recovery_store::RecoveryCorrection {
                    action,
                    vaddr,
                    target,
                    note,
                    data,
                },
            )?
        }
        ApiCommands::RecoveryXrefs {
            file,
            vaddr,
            max_functions,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let target = parse_int(&vaddr)?;
            serde_json::json!({
                "kind": "recovery_xrefs",
                "binary": path,
                "target": format!("0x{target:x}"),
                "xrefs": core::recovery::xrefs_to(&path, target, max_functions)?,
            })
        }
        ApiCommands::RecoveryCfg {
            file,
            vaddr,
            max_functions,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let target = parse_int(&vaddr)?;
            serde_json::json!({
                "kind": "recovery_cfg",
                "binary": path,
                "target": format!("0x{target:x}"),
                "function": core::recovery::cfg_for(&path, target, max_functions)?,
            })
        }
        ApiCommands::SysrootDoctor { file } => {
            let path = resolve_optional_api_binary_path(&client, &base_url, token.as_deref(), file)
                .await?;
            core::workstation::sysroot_doctor(path.as_deref())?
        }
        ApiCommands::ExploitStack { file } => {
            let path = resolve_optional_api_binary_path(&client, &base_url, token.as_deref(), file)
                .await?;
            core::workstation::exploit_stack_manifest(path.as_deref())?
        }
        ApiCommands::AgentJobPlan { file, goal } => {
            let path = resolve_optional_api_binary_path(&client, &base_url, token.as_deref(), file)
                .await?;
            core::workstation::agent_job_plan(path.as_deref(), &goal)?
        }
        ApiCommands::WorkbenchManifest => core::workstation::workbench_manifest(),
        ApiCommands::BenchmarkPlan { root, max_files } => {
            core::workstation::benchmark_plan(&root, max_files)?
        }
        ApiCommands::EvidenceList { file, kind, limit } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            serde_json::json!({
                "kind": "evidence_list",
                "binary": path,
                "evidence_path": core::evidence::evidence_path(&path),
                "records": core::evidence::list(&path, kind.as_deref(), limit)?,
            })
        }
        ApiCommands::ExecutionProfiles { file } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let data = std::fs::read(&path)?;
            core::evidence::execution_profiles(&path, runtime_candidates(&path, &data))
        }
        ApiCommands::DebugSessionContract { file } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            core::evidence::debug_session_contract(&path)
        }
        ApiCommands::BenchmarkSmoke { file } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            core::evidence::benchmark_smoke_plan(&path)
        }
        ApiCommands::BenchmarkRun {
            root,
            max_files,
            timeout_secs,
            output,
            save_evidence,
        } => {
            let value = benchmark_run_json(&root, max_files, timeout_secs, save_evidence)?;
            if let Some(output) = output {
                write_json_artifact(&output, &value)?;
            }
            value
        }
        ApiCommands::CrashOffset {
            file,
            pattern_len,
            args,
            sysroot,
            timeout_secs,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value =
                crash_offset_json(&path, pattern_len, &args, sysroot.as_deref(), timeout_secs)?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "crash_offset",
                crash_offset_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::DebugSessionStart { args, sysroot } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                "/api/debug/sessions",
                Some(serde_json::json!({
                    "args": args,
                    "sysroot": sysroot.map(|p| p.to_string_lossy().into_owned()),
                })),
            )
            .await?
        }
        ApiCommands::DebugSessionList => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "GET",
                "/api/debug/sessions",
                None,
            )
            .await?
        }
        ApiCommands::DebugSessionGet { id } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "GET",
                &format!("/api/debug/sessions/{id}"),
                None,
            )
            .await?
        }
        ApiCommands::DebugSessionAction {
            id,
            action,
            address,
            length,
            command,
        } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "POST",
                &format!("/api/debug/sessions/{id}/action"),
                Some(serde_json::json!({
                    "action": action,
                    "address": address,
                    "length": length,
                    "command": command,
                })),
            )
            .await?
        }
        ApiCommands::DebugSessionStop { id } => {
            api_request(
                &client,
                &base_url,
                token.as_deref(),
                "DELETE",
                &format!("/api/debug/sessions/{id}"),
                None,
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

async fn resolve_api_binary_path(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    file: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(file) = file {
        return Ok(file.canonicalize().unwrap_or(file));
    }
    let workspace = api_request(client, base_url, token, "GET", "/api/workspace", None).await?;
    let path = workspace
        .get("binary_path")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no active workspace; pass --file or open a binary"))?;
    Ok(PathBuf::from(path))
}

async fn resolve_optional_api_binary_path(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    file: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    if let Some(file) = file {
        return Ok(Some(file.canonicalize().unwrap_or(file)));
    }
    let workspace = match api_request(client, base_url, token, "GET", "/api/workspace", None).await
    {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(path) = workspace
        .get("binary_path")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(PathBuf::from(path)))
}

fn write_json_artifact(path: &Path, value: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn maybe_append_evidence(
    save: bool,
    binary: &Path,
    kind: &str,
    summary: String,
    tags: Vec<String>,
    value: serde_json::Value,
) -> Result<serde_json::Value> {
    if !save {
        return Ok(value);
    }
    let record = core::evidence::append(binary, kind, summary, tags, value.clone())?;
    Ok(serde_json::json!({
        "evidence": record,
        "result": value,
    }))
}

fn runtime_summary(value: &serde_json::Value) -> String {
    let result = value.get("result").unwrap_or(value);
    if let Some(err) = result.get("spawn_error").and_then(|v| v.as_str()) {
        return format!("runtime spawn error: {err}");
    }
    let exit = result
        .get("exit_code")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let signal = result
        .get("signal")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let timed_out = result
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    format!("runtime-run exit={exit} signal={signal} timed_out={timed_out}")
}

fn debug_summary(value: &serde_json::Value) -> String {
    if value
        .get("available")
        .and_then(|v| v.as_bool())
        .is_some_and(|available| !available)
    {
        return value
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("debug probe unavailable")
            .to_string();
    }
    let mode = value
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("native");
    let signals = value
        .get("signals")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let pc = value
        .get("registers")
        .and_then(|r| {
            r.get("rip")
                .or_else(|| r.get("eip"))
                .or_else(|| r.get("pc"))
        })
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    format!("debug-probe mode={mode} pc={pc} signals={signals}")
}

fn verify_summary(value: &serde_json::Value) -> String {
    let success = value
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exit = value
        .get("exit_code")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    format!("exploit-verify success={success} exit={exit}")
}

fn crash_offset_summary(value: &serde_json::Value) -> String {
    let count = value
        .get("candidate_offsets")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let signals = value
        .pointer("/probe/signals")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    format!("crash-offset candidates={count} signals={signals}")
}

fn benchmark_run_json(
    root: &Path,
    max_files: usize,
    timeout_secs: u64,
    save_evidence: bool,
) -> Result<serde_json::Value> {
    let candidates = benchmark_binary_candidates(root, max_files.clamp(1, 256))?;
    let mut cases = Vec::new();
    for binary in candidates {
        let index = core::workstation::binary_index(&binary, 80, 80)
            .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
        let runtime = runtime_run_json(&binary, &[], &[], None, None, None, None, timeout_secs)
            .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
        if save_evidence {
            let _ = core::evidence::append(
                &binary,
                "runtime_run",
                runtime_summary(&runtime),
                vec!["benchmark".to_string()],
                runtime.clone(),
            );
        }
        let debug = debug_probe_json(&binary, &[], None, None, &[], false, timeout_secs)
            .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
        if save_evidence {
            let _ = core::evidence::append(
                &binary,
                "debug_probe",
                debug_summary(&debug),
                vec!["benchmark".to_string()],
                debug.clone(),
            );
        }
        cases.push(serde_json::json!({
            "binary": binary,
            "index_ok": index.get("error").is_none(),
            "runtime_summary": runtime_summary(&runtime),
            "debug_summary": debug_summary(&debug),
            "index": index,
            "runtime": runtime,
            "debug": debug,
        }));
    }
    Ok(serde_json::json!({
        "kind": "benchmark_run",
        "root": root,
        "timeout_secs": timeout_secs.clamp(1, 300),
        "case_count": cases.len(),
        "cases": cases,
    }))
}

fn benchmark_binary_candidates(root: &Path, max_files: usize) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_benchmark_binaries(root, max_files, &mut out)?;
    Ok(out)
}

fn decompiler_benchmark_json(
    root: &Path,
    max_files: usize,
    max_functions: usize,
) -> Result<serde_json::Value> {
    let candidates = benchmark_binary_candidates(root, max_files.clamp(1, 256))?;
    let mut reports = Vec::new();
    let mut score_sum = 0u64;
    let mut recovered_functions = 0usize;
    let mut analyzed_functions = 0usize;
    let mut legacy_ok = 0usize;
    let mut reducible = 0usize;
    let mut machine_facts = 0usize;
    let mut dataflow_facts = 0usize;
    let mut kir_facts = 0usize;
    let mut kir_ssa_facts = 0usize;
    let mut kir_expression_facts = 0usize;
    let mut kir_memory_ssa_facts = 0usize;
    let mut kir_type_facts = 0usize;
    let mut kir_render_preview_facts = 0usize;
    let mut kir_structured_preview_facts = 0usize;
    let mut kir_ops = 0usize;
    let mut kir_ssa_definitions = 0usize;
    let mut kir_ssa_uses = 0usize;
    let mut kir_phi_nodes = 0usize;
    let mut kir_expression_assignments = 0usize;
    let mut kir_memory_ssa_definitions = 0usize;
    let mut kir_memory_ssa_uses = 0usize;
    let mut kir_register_type_facts = 0usize;
    let mut kir_memory_type_facts = 0usize;
    let mut kir_render_preview_lines = 0usize;
    let mut kir_structured_preview_lines = 0usize;
    let mut phi_candidates = 0usize;
    let mut memory_accesses = 0usize;
    let mut variable_candidates = 0usize;
    let mut blockers = std::collections::BTreeSet::<String>::new();

    for binary in candidates {
        match core::decompile::decompiler_quality_report_path(&binary, max_functions) {
            Ok(report) => {
                score_sum += report.score as u64;
                recovered_functions += report.recovered_functions;
                analyzed_functions += report.analyzed_functions;
                legacy_ok += report.legacy_decompile_ok;
                reducible += report.reducible_functions;
                machine_facts += report.functions_with_machine_facts;
                dataflow_facts += report.functions_with_dataflow_facts;
                kir_facts += report.functions_with_kir;
                kir_ssa_facts += report.functions_with_kir_ssa;
                kir_expression_facts += report.functions_with_kir_expressions;
                kir_memory_ssa_facts += report.functions_with_kir_memory_ssa;
                kir_type_facts += report.functions_with_kir_type_facts;
                kir_render_preview_facts += report.functions_with_kir_render_preview;
                kir_structured_preview_facts += report.functions_with_kir_structured_preview;
                kir_ops += report.total_kir_ops;
                kir_ssa_definitions += report.total_kir_ssa_definitions;
                kir_ssa_uses += report.total_kir_ssa_uses;
                kir_phi_nodes += report.total_kir_phi_nodes;
                kir_expression_assignments += report.total_kir_expression_assignments;
                kir_memory_ssa_definitions += report.total_kir_memory_ssa_definitions;
                kir_memory_ssa_uses += report.total_kir_memory_ssa_uses;
                kir_register_type_facts += report.total_kir_register_type_facts;
                kir_memory_type_facts += report.total_kir_memory_type_facts;
                kir_render_preview_lines += report.total_kir_render_preview_lines;
                kir_structured_preview_lines += report.total_kir_structured_preview_lines;
                phi_candidates += report.total_phi_candidates;
                memory_accesses += report.total_memory_accesses;
                variable_candidates += report.total_variable_candidates;
                for blocker in &report.blockers {
                    blockers.insert(blocker.clone());
                }
                reports.push(serde_json::to_value(report)?);
            }
            Err(err) => {
                blockers.insert("one or more binaries could not be decompiler-benchmarked".to_string());
                reports.push(serde_json::json!({
                    "kind": "decompiler_quality_report",
                    "binary": binary,
                    "error": err.to_string(),
                    "score": 0,
                }));
            }
        }
    }

    let case_count = reports.len();
    let aggregate_score = if case_count == 0 {
        0
    } else {
        (score_sum / case_count as u64) as u32
    };
    Ok(serde_json::json!({
        "kind": "decompiler_benchmark",
        "root": root,
        "max_files": max_files.clamp(1, 256),
        "max_functions": max_functions.clamp(1, 5000),
        "case_count": case_count,
        "aggregate_score": aggregate_score,
        "summary": {
            "recovered_functions": recovered_functions,
            "analyzed_functions": analyzed_functions,
            "legacy_decompile_ok": legacy_ok,
            "reducible_functions": reducible,
            "functions_with_machine_facts": machine_facts,
            "functions_with_dataflow_facts": dataflow_facts,
            "functions_with_kir": kir_facts,
            "functions_with_kir_ssa": kir_ssa_facts,
            "functions_with_kir_expressions": kir_expression_facts,
            "functions_with_kir_memory_ssa": kir_memory_ssa_facts,
            "functions_with_kir_type_facts": kir_type_facts,
            "functions_with_kir_render_preview": kir_render_preview_facts,
            "functions_with_kir_structured_preview": kir_structured_preview_facts,
            "total_kir_ops": kir_ops,
            "total_kir_ssa_definitions": kir_ssa_definitions,
            "total_kir_ssa_uses": kir_ssa_uses,
            "total_kir_phi_nodes": kir_phi_nodes,
            "total_kir_expression_assignments": kir_expression_assignments,
            "total_kir_memory_ssa_definitions": kir_memory_ssa_definitions,
            "total_kir_memory_ssa_uses": kir_memory_ssa_uses,
            "total_kir_register_type_facts": kir_register_type_facts,
            "total_kir_memory_type_facts": kir_memory_type_facts,
            "total_kir_render_preview_lines": kir_render_preview_lines,
            "total_kir_structured_preview_lines": kir_structured_preview_lines,
            "total_phi_candidates": phi_candidates,
            "total_memory_accesses": memory_accesses,
            "total_variable_candidates": variable_candidates,
        },
        "blockers": blockers.into_iter().collect::<Vec<_>>(),
        "reports": reports,
    }))
}

fn collect_benchmark_binaries(path: &Path, max_files: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if out.len() >= max_files {
        return Ok(());
    }
    if path.is_file() {
        if looks_like_supported_binary(path) {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(path)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        collect_benchmark_binaries(&entry, max_files, out)?;
        if out.len() >= max_files {
            break;
        }
    }
    Ok(())
}

fn looks_like_supported_binary(path: &Path) -> bool {
    if path
        .components()
        .any(|component| component.as_os_str() == ".kaiju_scripts")
    {
        return false;
    }
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or(false, |name| name.contains(".kaiju."))
    {
        return false;
    }
    if matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("db" | "json" | "md" | "py" | "txt")
    ) {
        return false;
    }
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    goblin::Object::parse(&data).is_ok()
}

fn crash_offset_json(
    binary: &Path,
    pattern_len: usize,
    args: &[String],
    sysroot: Option<&Path>,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let pattern_len = pattern_len.clamp(32, 1024 * 1024);
    let pattern = cyclic_pattern(pattern_len);
    let probe = debug_probe_json(
        binary,
        args,
        Some(&pattern),
        sysroot,
        &[],
        false,
        timeout_secs,
    )?;
    let mut offsets = Vec::new();
    if let Some(registers) = probe.get("registers").and_then(|v| v.as_object()) {
        for (name, value) in registers {
            if let Some(text) = value.as_str() {
                if let Some(offset) = cyclic_find_offset(&pattern, text) {
                    offsets.push(serde_json::json!({
                        "register": name,
                        "value": text,
                        "offset": offset,
                    }));
                }
            }
        }
    }
    Ok(serde_json::json!({
        "kind": "crash_offset",
        "binary": binary,
        "pattern_len": pattern_len,
        "stdin": {
            "type": "cyclic",
            "preview": &pattern[..pattern.len().min(96)],
        },
        "candidate_offsets": offsets,
        "probe": probe,
        "next_action": if offsets.is_empty() {
            "No register contained the cyclic pattern. Try a longer pattern, target-specific args, or a breakpoint near the input read."
        } else {
            "Use the smallest control-flow-relevant offset in the PoC and validate with exploit-verify."
        },
    }))
}

fn build_exploit_context(path: &Path, max_gadgets: usize) -> Result<serde_json::Value> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = serde_json::json!({
        "binary_path": path,
        "size": data.len(),
        "runtime": runtime_candidates(path, &data),
        "strings_of_interest": interesting_strings(&data, 40),
    });

    match goblin::Object::parse(&data)? {
        goblin::Object::Elf(elf) => {
            let arch = elf_arch_label(&elf);
            out["format"] = serde_json::json!("ELF");
            out["arch"] = serde_json::json!(arch);
            out["entry"] = serde_json::json!(format!("0x{:x}", elf.entry));
            out["interpreter"] = elf
                .interpreter
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null);
            out["protections"] = elf_protections(&elf);
            out["imports_sample"] = serde_json::json!(elf
                .dynsyms
                .iter()
                .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
                .filter(|s| !s.is_empty())
                .take(40)
                .collect::<Vec<_>>());
            out["gadget_hints"] = serde_json::json!(gadget_hints(path, &data, &arch, max_gadgets)?);
            out["analysis_loop"] = serde_json::json!({
                "recommended_order": [
                    "1. Inspect protections/runtime and fix missing loader/sysroot before dynamic validation.",
                    "2. Use strings/prompts to locate input functions, then call function_context on those addresses.",
                    "3. Build a minimal success predicate first: exit(42), marker stdout, or local flag read.",
                    "4. Run candidate with `kaijulab api exploit-verify` after every edit.",
                    "5. Stop once exploit-verify reports success=true and script prints SCRIPT_READY."
                ],
                "verify_command_template": format!(
                    "target/debug/kaijulab api exploit-verify --file {} --expect-target-exit 42 /tmp/poc.py",
                    shell_quote(&path.to_string_lossy())
                ),
            });
        }
        other => {
            out["format"] = serde_json::json!(format!("{:?}", other));
            out["error"] =
                serde_json::json!("exploit-context currently has full support for ELF only");
        }
    }
    Ok(out)
}

fn elf_arch_label(elf: &goblin::elf::Elf<'_>) -> String {
    use goblin::elf::header::*;
    match (elf.header.e_machine, elf.is_64) {
        (EM_X86_64, _) => "x86_64".to_string(),
        (EM_386, _) => "i386".to_string(),
        (EM_AARCH64, _) => "aarch64".to_string(),
        (EM_ARM, _) => "arm".to_string(),
        (_, true) => format!("machine:{}-64", elf.header.e_machine),
        _ => format!("machine:{}-32", elf.header.e_machine),
    }
}

fn elf_protections(elf: &goblin::elf::Elf<'_>) -> serde_json::Value {
    use goblin::elf::{dynamic, program_header::*};
    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK);
    let nx = gnu_stack.map(|ph| ph.p_flags & PF_X == 0).unwrap_or(true);
    let relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().map_or(false, |dyns| {
        dyns.dyns.iter().any(|d| {
            (d.d_tag == dynamic::DT_BIND_NOW)
                || (d.d_tag == dynamic::DT_FLAGS && d.d_val & dynamic::DF_BIND_NOW != 0)
                || (d.d_tag == dynamic::DT_FLAGS_1 && d.d_val & dynamic::DF_1_NOW != 0)
        })
    });
    let canary = elf
        .dynsyms
        .iter()
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .any(|s| s == "__stack_chk_fail" || s == "__stack_chk_guard");
    serde_json::json!({
        "nx": nx,
        "pie": elf.is_lib,
        "relro": if relro && bind_now { "full" } else if relro { "partial" } else { "none" },
        "canary_import": canary,
        "static": elf.interpreter.is_none(),
    })
}

fn runtime_candidates(path: &Path, data: &[u8]) -> serde_json::Value {
    let mut candidates = Vec::new();
    let mut notes = Vec::new();
    let mut arch = "unknown".to_string();
    let mut interpreter: Option<String> = None;
    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) {
        arch = elf_arch_label(&elf);
        interpreter = elf.interpreter.map(|s| s.to_string());
    }

    candidates.push(serde_json::json!({
        "label": "native",
        "argv": [path.to_string_lossy().to_string()],
        "available": true,
    }));

    let qemu_names: &[&str] = match arch.as_str() {
        "i386" => &["qemu-i386-static", "qemu-i386"],
        "x86_64" => &["qemu-x86_64-static", "qemu-x86_64"],
        "aarch64" => &["qemu-aarch64-static", "qemu-aarch64"],
        "arm" => &["qemu-arm-static", "qemu-arm"],
        _ => &[],
    };
    for qemu in qemu_names {
        if let Some(found) = find_in_path(qemu) {
            candidates.push(serde_json::json!({
                "label": qemu,
                "argv": [found, path.to_string_lossy().to_string()],
                "available": true,
            }));
        } else {
            candidates.push(serde_json::json!({
                "label": qemu,
                "available": false,
                "install_hint": format!("install {}", qemu),
            }));
        }
    }

    if let Some(interp) = &interpreter {
        if !Path::new(interp).exists() {
            let hint = if interp.ends_with("ld-linux.so.2") {
                "missing i386 dynamic loader; install libc6:i386 or run qemu-i386 -L <i386-sysroot>"
            } else {
                "missing dynamic loader; install matching sysroot or run qemu with -L"
            };
            notes.push(serde_json::json!({
                "kind": "missing_interpreter",
                "path": interp,
                "hint": hint,
            }));
        }
    }

    serde_json::json!({
        "arch": arch,
        "interpreter": interpreter,
        "candidates": candidates,
        "notes": notes,
    })
}

fn binary_arch_from_data(data: &[u8]) -> Option<String> {
    match goblin::Object::parse(data).ok()? {
        goblin::Object::Elf(elf) => Some(elf_arch_label(&elf)),
        _ => None,
    }
}

fn host_arch_label() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "x86" | "i386" | "i586" | "i686" => "i386",
        "aarch64" => "aarch64",
        "arm" | "armv7" => "arm",
        other => other,
    }
}

fn default_runner_for_arch(arch: Option<&str>) -> Option<String> {
    let arch = arch?;
    if arch == host_arch_label() {
        return None;
    }
    let candidates: &[&str] = match arch {
        "i386" => &["qemu-i386-static", "qemu-i386"],
        "x86_64" => &["qemu-x86_64-static", "qemu-x86_64"],
        "aarch64" => &["qemu-aarch64-static", "qemu-aarch64"],
        "arm" => &["qemu-arm-static", "qemu-arm"],
        _ => &[],
    };
    candidates.iter().find_map(|name| find_in_path(name))
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

fn gadget_hints(
    path: &Path,
    data: &[u8],
    arch: &str,
    max_gadgets: usize,
) -> Result<serde_json::Value> {
    let patterns: &[(&str, &[u8])] = match arch {
        "i386" => &[
            ("pop eax; ret", b"\x58\xc3"),
            ("pop ebx; ret", b"\x5b\xc3"),
            ("pop ecx; ret", b"\x59\xc3"),
            ("pop edx; ret", b"\x5a\xc3"),
            ("int 0x80", b"\xcd\x80"),
            ("leave; ret", b"\xc9\xc3"),
        ],
        "x86_64" => &[
            ("pop rax; ret", b"\x58\xc3"),
            ("pop rdi; ret", b"\x5f\xc3"),
            ("pop rsi; ret", b"\x5e\xc3"),
            ("pop rdx; ret", b"\x5a\xc3"),
            ("syscall", b"\x0f\x05"),
            ("leave; ret", b"\xc9\xc3"),
        ],
        _ => &[],
    };

    let obj = object::File::parse(data)?;
    let mut exec_sections = Vec::new();
    for section in obj.sections() {
        let is_exec = match section.flags() {
            object::SectionFlags::Elf { sh_flags } => sh_flags & 0x4 != 0,
            object::SectionFlags::Coff { characteristics } => characteristics & 0x2000_0000 != 0,
            _ => false,
        };
        if is_exec {
            if let Ok(bytes) = section.data() {
                exec_sections.push((section.address(), bytes.to_vec()));
            }
        }
    }

    let mut result = serde_json::Map::new();
    for (name, pat) in patterns {
        let mut hits = Vec::new();
        for (base, bytes) in &exec_sections {
            let mut start = 0;
            while let Some(pos) = find_bytes(&bytes[start..], pat) {
                hits.push(format!("0x{:x}", base + (start + pos) as u64));
                if hits.len() >= max_gadgets {
                    break;
                }
                start += pos + 1;
            }
            if hits.len() >= max_gadgets {
                break;
            }
        }
        result.insert((*name).to_string(), serde_json::json!(hits));
    }
    result.insert(
        "note".to_string(),
        serde_json::json!(format!(
            "Byte-pattern gadget hints for {}; confirm semantics before use.",
            path.display()
        )),
    );
    Ok(serde_json::Value::Object(result))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn interesting_strings(data: &[u8], limit: usize) -> Vec<serde_json::Value> {
    let keywords = [
        "addr", "data", "flag", "/bin/sh", "/tmp", "read", "write", "open", "shell", "name",
        "password", "input", "welcome", "ctf",
    ];
    let mut out = Vec::new();
    let mut start = None;
    for (i, b) in data.iter().copied().enumerate() {
        let printable = b.is_ascii_graphic() || b == b' ';
        match (start, printable) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                if i.saturating_sub(s) >= 4 {
                    push_interesting_string(data, s, i, &keywords, &mut out, limit);
                    if out.len() >= limit {
                        return out;
                    }
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        push_interesting_string(data, s, data.len(), &keywords, &mut out, limit);
    }
    out
}

fn push_interesting_string(
    data: &[u8],
    start: usize,
    end: usize,
    keywords: &[&str],
    out: &mut Vec<serde_json::Value>,
    limit: usize,
) {
    if out.len() >= limit {
        return;
    }
    let s = String::from_utf8_lossy(&data[start..end]).into_owned();
    let low = s.to_ascii_lowercase();
    if keywords.iter().any(|kw| low.contains(kw)) {
        out.push(serde_json::json!({
            "file_offset": format!("0x{:x}", start),
            "text": s,
        }));
    }
}

fn verify_exploit_script(
    script: &Path,
    binary: &Path,
    timeout_secs: u64,
    expect_exit: Option<i32>,
    expect_target_exit: Option<i32>,
    expect_output: Option<&str>,
    args: &[String],
) -> Result<serde_json::Value> {
    let script = script
        .canonicalize()
        .with_context(|| format!("script not found: {}", script.display()))?;
    let binary = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 300));
    let mut cmd = Command::new("python3");
    cmd.arg(&script)
        .args(args)
        .env("KAIJU_BINARY", &binary)
        .env("KAIJULAB_BINARY", &binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    if let Some(qemu) = find_in_path("qemu-i386-static").or_else(|| find_in_path("qemu-i386")) {
        cmd.env("QEMU_I386", qemu);
    }
    if let Some(qemu) = find_in_path("qemu-x86_64-static").or_else(|| find_in_path("qemu-x86_64")) {
        cmd.env("QEMU_X86_64", qemu);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let start = Instant::now();
    let program = format!("{:?}", cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Ok(serde_json::json!({
                "command": program,
                "spawn_error": e.to_string(),
                "timed_out": false,
                "duration_ms": start.elapsed().as_millis(),
                "exit_code": null,
                "signal": null,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": false,
                "stderr_truncated": false,
            }));
        }
    };
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let stdout_thread = std::thread::spawn(move || read_limited(stdout, 256 * 1024));
    let stderr_thread = std::thread::spawn(move || read_limited(stderr, 256 * 1024));

    let timed_out = loop {
        if child.try_wait()?.is_some() {
            break false;
        }
        if start.elapsed() >= timeout {
            #[cfg(unix)]
            unsafe {
                libc::killpg(child.id() as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }
            let _ = child.wait();
            break true;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let status = child.try_wait()?.or_else(|| child.wait().ok());
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    let stdout_text = String::from_utf8_lossy(&stdout).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr).into_owned();
    let exit_code = status.and_then(|s| s.code());
    let combined = format!("{}{}", stdout_text, stderr_text);

    let exit_ok = expect_exit.map_or(true, |code| exit_code == Some(code));
    let target_exit_ok = expect_target_exit.map_or(true, |code| {
        combined.contains(&format!("returncode={code}"))
            || combined.contains(&format!("returncode: {code}"))
            || combined.contains(&format!("return code {code}"))
            || combined.contains(&format!("exit({code})"))
            || combined.contains(&format!("exit code: {code}"))
            || combined.contains(&format!("Exit code: {code}"))
    });
    let output_ok = expect_output.map_or(true, |needle| combined.contains(needle));
    let success = !timed_out && exit_ok && target_exit_ok && output_ok;
    Ok(serde_json::json!({
        "success": success,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "expected_exit": expect_exit,
        "expected_target_exit": expect_target_exit,
        "expected_output": expect_output,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "script": script,
        "binary": binary,
        "next_action": if success {
            "Stop. Preserve the PoC and summarize why the predicate proves execution."
        } else if timed_out {
            "Add tighter process timeouts and avoid interactive loops; rerun exploit-verify."
        } else if !exit_ok {
            "Inspect crash/exit path, adjust payload or predicate, rerun exploit-verify."
        } else if !target_exit_ok {
            "Target-exit predicate missing; print returncode=<N> from the PoC or adjust predicate."
        } else {
            "Predicate output missing; inspect stdout/stderr and rerun exploit-verify."
        },
    }))
}

fn read_limited<R: Read>(reader: R, max: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = reader.take(max).read_to_end(&mut out);
    out
}

fn runtime_run_json(
    binary: &Path,
    args: &[String],
    envs: &[String],
    stdin_spec: Option<&str>,
    cwd: Option<&Path>,
    runner: Option<&str>,
    sysroot: Option<&Path>,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let context = build_exploit_context(binary, 8)?;
    let stdin_bytes = read_input_spec(stdin_spec)?;
    let mut cmdline = Vec::new();

    let arch = binary_arch_from_data(&data);
    let effective_runner = runner
        .map(|r| r.to_string())
        .or_else(|| default_runner_for_arch(arch.as_deref()));

    if let Some(runner) = &effective_runner {
        cmdline.push(runner.to_string());
        if let Some(sysroot) = sysroot {
            cmdline.push("-L".to_string());
            cmdline.push(sysroot.to_string_lossy().into_owned());
        }
        cmdline.push(binary.to_string_lossy().into_owned());
    } else {
        cmdline.push(binary.to_string_lossy().into_owned());
    }
    cmdline.extend(args.iter().cloned());

    let mut cmd = Command::new(&cmdline[0]);
    cmd.args(&cmdline[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    for env in envs {
        let Some((key, value)) = env.split_once('=') else {
            anyhow::bail!("invalid --env '{}'; expected KEY=VALUE", env);
        };
        cmd.env(key, value);
    }
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let output = run_captured(cmd, stdin_bytes.as_deref(), timeout_secs, 512 * 1024)?;
    Ok(serde_json::json!({
        "kind": "runtime_run",
        "binary": binary,
        "cmd": cmdline,
        "runner_selected": effective_runner,
        "cwd": cwd,
        "timeout_secs": timeout_secs.clamp(1, 300),
        "elf_runtime": runtime_candidates(binary, &data),
        "context_summary": {
            "format": context.get("format"),
            "arch": context.get("arch"),
            "protections": context.get("protections"),
            "runtime_notes": context.pointer("/runtime/notes"),
        },
        "result": output,
        "next_action": runtime_next_action(&output),
    }))
}

fn debug_probe_json(
    binary: &Path,
    args: &[String],
    stdin_spec: Option<&str>,
    sysroot: Option<&Path>,
    breakpoints: &[String],
    continue_after_break: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let arch = binary_arch_from_data(&data);
    if arch.as_deref().is_some_and(|a| a != host_arch_label()) {
        return debug_probe_remote_json(
            binary,
            arch.as_deref(),
            args,
            stdin_spec,
            sysroot,
            breakpoints,
            continue_after_break,
            timeout_secs,
        );
    }

    let Some(gdb) = find_in_path("gdb") else {
        return Ok(serde_json::json!({
            "kind": "debug_probe",
            "available": false,
            "missing_tool": "gdb",
            "install_hint": "install gdb to enable register/backtrace/crash probes",
        }));
    };

    let stdin_bytes = read_input_spec(stdin_spec)?;
    let stdin_file = if let Some(bytes) = stdin_bytes {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(&bytes)?;
        Some(file)
    } else {
        None
    };

    let mut gdb_args = vec![
        "--quiet".to_string(),
        "--batch".to_string(),
        binary.to_string_lossy().into_owned(),
        "-ex".to_string(),
        "set pagination off".to_string(),
        "-ex".to_string(),
        "set confirm off".to_string(),
        "-ex".to_string(),
        "set disassembly-flavor intel".to_string(),
    ];
    if !args.is_empty() {
        gdb_args.push("-ex".to_string());
        gdb_args.push(format!(
            "set args {}",
            args.iter()
                .map(|s| gdb_quote(s))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    for bp in breakpoints {
        gdb_args.push("-ex".to_string());
        let bp = if bp.starts_with("0x") || bp.chars().all(|c| c.is_ascii_hexdigit()) {
            format!("break *{}", bp)
        } else {
            format!("break {}", bp)
        };
        gdb_args.push(bp);
    }
    gdb_args.push("-ex".to_string());
    let run_cmd = if let Some(file) = &stdin_file {
        format!("run < {}", file.path().display())
    } else {
        "run".to_string()
    };
    gdb_args.push(run_cmd);
    if continue_after_break && !breakpoints.is_empty() {
        gdb_args.push("-ex".to_string());
        gdb_args.push("continue".to_string());
    }
    let reg_command = register_command_for_arch(arch.as_deref());
    for command in [
        reg_command.as_str(),
        "bt",
        "x/16i $pc",
        "info proc mappings",
    ] {
        gdb_args.push("-ex".to_string());
        gdb_args.push(command.to_string());
    }
    let mut cmd = Command::new(&gdb);
    cmd.args(&gdb_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let output = run_captured(cmd, None, timeout_secs, 768 * 1024)?;
    let combined = format!(
        "{}{}",
        output.get("stdout").and_then(|v| v.as_str()).unwrap_or(""),
        output.get("stderr").and_then(|v| v.as_str()).unwrap_or("")
    );
    Ok(serde_json::json!({
        "kind": "debug_probe",
        "available": true,
        "gdb": gdb,
        "binary": binary,
        "args": args,
        "breakpoints": breakpoints,
        "result": output,
        "registers": parse_gdb_registers(&combined),
        "signals": extract_gdb_signals(&combined),
        "next_action": if combined.contains("SIGSEGV") || combined.contains("SIGILL") || combined.contains("SIGABRT") {
            "Use registers and $pc disassembly to compute overwrite/control-flow offset, then verify with exploit-verify."
        } else if combined.contains("No such file or directory") || combined.contains("not found") {
            "Fix loader/sysroot/library environment, then rerun debug-probe."
        } else {
            "Correlate register/backtrace output with ir-query/function-context and rerun with a narrower breakpoint."
        },
    }))
}

fn debug_probe_remote_json(
    binary: &Path,
    arch: Option<&str>,
    args: &[String],
    stdin_spec: Option<&str>,
    sysroot: Option<&Path>,
    breakpoints: &[String],
    continue_after_break: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let Some(gdb) = find_in_path("gdb-multiarch") else {
        return Ok(serde_json::json!({
            "kind": "debug_probe",
            "available": false,
            "binary": binary,
            "arch": arch,
            "host_arch": host_arch_label(),
            "missing_tool": "gdb-multiarch",
            "runtime_runner": default_runner_for_arch(arch),
            "install_hint": "install gdb-multiarch for cross-architecture debugging",
            "next_action": "Use runtime-run for qemu execution now; install gdb-multiarch to enable cross-arch debug probes.",
        }));
    };
    let Some(qemu) = default_runner_for_arch(arch) else {
        return Ok(serde_json::json!({
            "kind": "debug_probe",
            "available": false,
            "binary": binary,
            "arch": arch,
            "host_arch": host_arch_label(),
            "gdb": gdb,
            "missing_tool": format!("qemu-user for {}", arch.unwrap_or("target")),
            "install_hint": "install qemu-user or qemu-user-static for this target architecture",
        }));
    };

    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let runtime = runtime_candidates(binary, &data);
    let has_loader_blocker =
        runtime
            .get("notes")
            .and_then(|v| v.as_array())
            .map_or(false, |notes| {
                notes.iter().any(|note| {
                    note.get("kind")
                        .and_then(|v| v.as_str())
                        .is_some_and(|kind| kind == "missing_interpreter")
                })
            });
    if has_loader_blocker && sysroot.is_none() {
        return Ok(serde_json::json!({
            "kind": "debug_probe",
            "available": false,
            "binary": binary,
            "arch": arch,
            "host_arch": host_arch_label(),
            "gdb": gdb,
            "qemu": qemu,
            "runtime": runtime,
            "reason": "target dynamic loader/sysroot is missing; qemu gdbstub cannot reach target code",
            "next_action": "Install the matching loader/sysroot or rerun debug-probe with --sysroot <root>.",
        }));
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let stdin_bytes = read_input_spec(stdin_spec)?;
    let mut qemu_cmd = Command::new(&qemu);
    qemu_cmd.arg("-g").arg(port.to_string());
    if let Some(sysroot) = sysroot {
        qemu_cmd.arg("-L").arg(sysroot);
    }
    qemu_cmd
        .arg(binary)
        .args(args)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        qemu_cmd.process_group(0);
    }
    let qemu_command = format!("{:?}", qemu_cmd);
    let mut qemu_child = match qemu_cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Ok(serde_json::json!({
                "kind": "debug_probe",
                "available": false,
                "binary": binary,
                "arch": arch,
                "gdb": gdb,
                "qemu": qemu,
                "spawn_error": e.to_string(),
            }));
        }
    };
    if let Some(input) = stdin_bytes {
        if let Some(mut stdin) = qemu_child.stdin.take() {
            let _ = stdin.write_all(&input);
        }
    }
    let qemu_stdout = qemu_child.stdout.take().expect("qemu stdout piped");
    let qemu_stderr = qemu_child.stderr.take().expect("qemu stderr piped");
    let qemu_stdout_thread = std::thread::spawn(move || read_limited(qemu_stdout, 512 * 1024));
    let qemu_stderr_thread = std::thread::spawn(move || read_limited(qemu_stderr, 512 * 1024));

    std::thread::sleep(Duration::from_millis(150));

    let mut gdb_args = vec![
        "--quiet".to_string(),
        "--batch".to_string(),
        binary.to_string_lossy().into_owned(),
        "-ex".to_string(),
        "set pagination off".to_string(),
        "-ex".to_string(),
        "set confirm off".to_string(),
        "-ex".to_string(),
        "set debuginfod enabled off".to_string(),
        "-ex".to_string(),
        "set disassembly-flavor intel".to_string(),
        "-ex".to_string(),
        format!("target remote 127.0.0.1:{port}"),
    ];
    for bp in breakpoints {
        gdb_args.push("-ex".to_string());
        let bp = if bp.starts_with("0x") || bp.chars().all(|c| c.is_ascii_hexdigit()) {
            format!("break *{}", bp)
        } else {
            format!("break {}", bp)
        };
        gdb_args.push(bp);
    }
    gdb_args.push("-ex".to_string());
    gdb_args.push("continue".to_string());
    if continue_after_break && !breakpoints.is_empty() {
        gdb_args.push("-ex".to_string());
        gdb_args.push("continue".to_string());
    }
    let reg_command = register_command_for_arch(arch);
    for command in [reg_command.as_str(), "bt", "x/16i $pc", "info files"] {
        gdb_args.push("-ex".to_string());
        gdb_args.push(command.to_string());
    }

    let mut gdb_cmd = Command::new(&gdb);
    gdb_cmd
        .args(&gdb_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        gdb_cmd.process_group(0);
    }

    let gdb_output = run_captured(gdb_cmd, None, timeout_secs, 768 * 1024)?;

    let _ = qemu_child.try_wait()?;
    #[cfg(unix)]
    unsafe {
        libc::killpg(qemu_child.id() as i32, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = qemu_child.kill();
    }
    let qemu_status = qemu_child.wait().ok();
    let qemu_stdout = qemu_stdout_thread.join().unwrap_or_default();
    let qemu_stderr = qemu_stderr_thread.join().unwrap_or_default();
    let qemu_stdout_text = String::from_utf8_lossy(&qemu_stdout).into_owned();
    let qemu_stderr_text = String::from_utf8_lossy(&qemu_stderr).into_owned();

    let combined = format!(
        "{}{}{}{}",
        gdb_output
            .get("stdout")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        gdb_output
            .get("stderr")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        qemu_stdout_text,
        qemu_stderr_text
    );
    Ok(serde_json::json!({
        "kind": "debug_probe",
        "available": true,
        "mode": "qemu-gdbstub",
        "binary": binary,
        "arch": arch,
        "host_arch": host_arch_label(),
        "gdb": gdb,
        "qemu": qemu,
        "qemu_command": qemu_command,
        "remote": format!("127.0.0.1:{port}"),
        "args": args,
        "breakpoints": breakpoints,
        "gdb_result": gdb_output,
        "qemu_result": {
            "exit_code": qemu_status.and_then(|s| s.code()),
            "stdout": qemu_stdout_text,
            "stderr": qemu_stderr_text,
            "stdout_truncated": qemu_stdout.len() >= 512 * 1024,
            "stderr_truncated": qemu_stderr.len() >= 512 * 1024,
        },
        "registers": parse_gdb_registers(&combined),
        "signals": extract_gdb_signals(&combined),
        "next_action": if combined.contains("SIGSEGV") || combined.contains("SIGILL") || combined.contains("SIGABRT") {
            "Use registers and $pc disassembly to compute overwrite/control-flow offset, then verify with exploit-verify."
        } else if combined.contains("No such file or directory") || combined.contains("not found") {
            "Fix loader/sysroot/library environment, then rerun debug-probe."
        } else if combined.contains("Breakpoint") {
            "Breakpoint hit; inspect registers/disassembly and rerun with --continue-after-break or a narrower breakpoint."
        } else {
            "Correlate gdb/qemu output with ir-query and rerun with target input or breakpoints."
        },
    }))
}

fn exploit_kit_json(
    binary: &Path,
    cyclic_len: Option<usize>,
    cyclic_find: Option<&str>,
    cyclic_search_len: usize,
    max_gadgets: usize,
) -> Result<serde_json::Value> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let context = build_exploit_context(binary, max_gadgets)?;
    let plt = tools::dispatch(
        "resolve_plt",
        &serde_json::json!({ "path": binary.to_string_lossy() }),
    );
    let cyclic_pattern_text = cyclic_len.map(|len| cyclic_pattern(len.min(1024 * 1024)));
    let cyclic_offset = cyclic_find.map(|needle| {
        let pattern = cyclic_pattern(cyclic_search_len.min(1024 * 1024));
        serde_json::json!({
            "needle": needle,
            "offset": cyclic_find_offset(&pattern, needle),
            "search_len": cyclic_search_len.min(1024 * 1024),
            "endianness": "little-endian integer forms and direct text are both tried",
        })
    });

    let arch = if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data) {
        elf_arch_label(&elf)
    } else {
        "unknown".to_string()
    };
    Ok(serde_json::json!({
        "kind": "exploit_kit",
        "binary": binary,
        "checksec": context.get("protections"),
        "runtime": context.get("runtime"),
        "gadget_hints": context.get("gadget_hints"),
        "plt_got": {
            "ok": !plt.output.starts_with("Error:"),
            "text": plt.output,
        },
        "cyclic": {
            "alphabet": "abcdefghijklmnopqrstuvwxyz",
            "pattern": cyclic_pattern_text,
            "find": cyclic_offset,
        },
        "recipes": exploit_recipes(&arch, context.get("protections")),
    }))
}

fn ir_query_json(
    binary: &Path,
    function: Option<&str>,
    search: Option<&str>,
    max: usize,
) -> Result<serde_json::Value> {
    let max = max.clamp(1, 500);
    let functions = match core::recovery::recover(binary, max) {
        Ok(index) => serde_json::json!({
            "source": "professional_recovery",
            "total": index.functions.len(),
            "functions": index.functions.iter().map(|function| serde_json::json!({
                "address": function.start,
                "vaddr": function.start,
                "size": function.size,
                "name": function.name,
                "confidence": function.confidence,
                "blocks": function.blocks.len(),
                "edges": function.edges.len(),
                "source": function.source,
            })).collect::<Vec<_>>(),
        }),
        Err(err) => {
            let funcs_raw = tools::dispatch(
                "list_functions",
                &serde_json::json!({
                    "path": binary.to_string_lossy(),
                    "max_results": max,
                    "json": true,
                }),
            );
            serde_json::from_str::<serde_json::Value>(&funcs_raw.output)
                .unwrap_or_else(|_| serde_json::json!({ "raw": funcs_raw.output, "recovery_error": err.to_string() }))
        }
    };
    let strings_raw = tools::dispatch(
        "strings_extract",
        &serde_json::json!({
            "path": binary.to_string_lossy(),
            "min_len": 4,
            "max_results": max,
        }),
    );

    let mut selected = serde_json::Value::Null;
    if let Some(addr) = function {
        let vaddr = parse_int(addr)?;
        let disasm = tools::dispatch(
            "disassemble",
            &serde_json::json!({
                "path": binary.to_string_lossy(),
                "vaddr": vaddr,
                "length": 320,
            }),
        );
        let decomp = core::decompile::decompile_enhanced_path(binary, vaddr)
            .unwrap_or_else(|err| format!("Error: {err}"));
        let xrefs = tools::dispatch(
            "xrefs_to",
            &serde_json::json!({ "path": binary.to_string_lossy(), "vaddr": vaddr }),
        );
        selected = serde_json::json!({
            "vaddr": format!("0x{vaddr:x}"),
            "disassembly": tool_text_json(disasm.output),
            "decompile": tool_text_json(decomp),
            "xrefs_to": tool_text_json(xrefs.output),
        });
    }

    let search_hits = search.map(|needle| {
        let needle_l = needle.to_ascii_lowercase();
        let mut hits = Vec::new();
        collect_json_text_hits("functions", &functions, &needle_l, &mut hits, 40);
        for line in strings_raw.output.lines() {
            if line.to_ascii_lowercase().contains(&needle_l) {
                hits.push(serde_json::json!({ "source": "strings", "text": line }));
                if hits.len() >= 80 {
                    break;
                }
            }
        }
        hits
    });

    Ok(serde_json::json!({
        "kind": "ir_query",
        "binary": binary,
        "functions": functions,
        "selected_function": selected,
        "strings": tool_text_json(strings_raw.output),
        "search": {
            "needle": search,
            "hits": search_hits,
        },
        "next_actions": [
            "Use --function 0xADDR on promising functions to retrieve decompile/disassembly/xrefs together.",
            "Use runtime-run/debug-probe to validate whether candidate input reaches the selected function.",
            "Promote useful names/comments through existing MCP/UI annotation tools."
        ],
    }))
}

fn analysis_loop_json(
    binary: &Path,
    goal: &str,
    observation: Option<&str>,
    candidate: Option<&Path>,
    max_gadgets: usize,
) -> Result<serde_json::Value> {
    let context = build_exploit_context(binary, max_gadgets)?;
    let kit = exploit_kit_json(binary, Some(256), None, 8192, max_gadgets)?;
    let ir = ir_query_json(binary, None, None, 40)?;
    let runtime_notes = context
        .pointer("/runtime/notes")
        .cloned()
        .unwrap_or_default();
    let candidate_status = if let Some(path) = candidate {
        serde_json::json!({
            "path": path,
            "exists": path.exists(),
            "verify_command": format!(
                "target/debug/kaijulab api exploit-verify --file {} --expect-target-exit 42 {}",
                shell_quote(&binary.to_string_lossy()),
                shell_quote(&path.to_string_lossy())
            ),
        })
    } else {
        serde_json::Value::Null
    };
    Ok(serde_json::json!({
        "kind": "analysis_loop",
        "binary": binary,
        "goal": goal,
        "observation": observation,
        "state": {
            "context": context,
            "exploit_kit": kit,
            "ir_overview": ir,
            "candidate": candidate_status,
        },
        "loop_contract": [
            "Hypothesize from context/IR.",
            "Run runtime-run or debug-probe to collect concrete behavior.",
            "Start a live debug-session when one-shot probes do not expose enough state.",
            "Use crash-offset when stdin reaches a memory-corruption path.",
            "Save useful observations as evidence and cite evidence IDs in the final result.",
            "Edit candidate PoC.",
            "Run exploit-verify with an explicit predicate.",
            "Stop only on success=true or a structured environment blocker."
        ],
        "tool_contract": {
            "one_shot_behavior": [
                format!("target/debug/kaijulab api runtime-run --file {}", shell_quote(&binary.to_string_lossy())),
                format!("target/debug/kaijulab api debug-probe --file {}", shell_quote(&binary.to_string_lossy())),
                format!("target/debug/kaijulab api crash-offset --file {}", shell_quote(&binary.to_string_lossy()))
            ],
            "live_debug": [
                "target/debug/kaijulab api debug-session-start",
                "target/debug/kaijulab api debug-session-action <id> break --address 0xADDR",
                "target/debug/kaijulab api debug-session-action <id> continue",
                "target/debug/kaijulab api debug-session-action <id> snapshot",
                "target/debug/kaijulab api debug-session-stop <id>"
            ],
            "evidence": [
                format!("target/debug/kaijulab api evidence-list --file {}", shell_quote(&binary.to_string_lossy())),
                "Prefer --save-evidence on runtime-run/debug-probe/exploit-verify/crash-offset when the observation changes the exploit hypothesis."
            ]
        },
        "recommended_next_tool": recommended_next_tool(observation, &runtime_notes, candidate),
        "agent_prompt_fragment": format!(
            "Use kaijulab api analysis-loop --file {} --candidate <poc> after each failed attempt; use runtime-run/debug-probe/debug-session/crash-offset for behavior and exploit-verify for proof.",
            shell_quote(&binary.to_string_lossy())
        ),
    }))
}

fn exploit_loop_prompt(
    binary: &Path,
    output: &Path,
    goal: &str,
    attempts: u32,
    context: &serde_json::Value,
) -> Result<String> {
    let context = serde_json::to_string_pretty(context)?;
    Ok(format!(
        r#"Use KaijuLab as an exploit workbench for this local CTF target.

Target: {binary}
Goal: {goal}
Output script: {output}
Attempt budget: {attempts}

Workbench context:
{context}

Rules:
- Write a Python stdlib-only PoC unless the context proves a dependency is required.
- Use qemu/runtime candidates from the context; handle missing dynamic loaders explicitly.
- Use `target/debug/kaijulab api exploit-context --file {binary_q}` whenever you need refreshed target/runtime/gadget facts.
- Use `target/debug/kaijulab api analysis-loop --file {binary_q} --candidate {output_q}` after failed attempts to refresh loop state.
- Use `target/debug/kaijulab api runtime-run --file {binary_q}` for stdout/stderr/exit behavior and `target/debug/kaijulab api debug-probe --file {binary_q}` for registers/backtrace/crash state.
- When one-shot probes are insufficient, use live sessions: `target/debug/kaijulab api debug-session-start`, then `debug-session-action <id> break --address 0xADDR`, `continue`, `stepi`, `registers`, `memory`, `snapshot`, and finally `debug-session-stop <id>`.
- If stdin can crash/control execution, run `target/debug/kaijulab api crash-offset --file {binary_q}` before hand-computing offsets.
- Use `target/debug/kaijulab api exploit-kit --file {binary_q}` for checksec/PLT/GOT/gadgets/cyclic helpers and `target/debug/kaijulab api ir-query --file {binary_q}` for functions/strings/decompile slices.
- Save important observations with `--save-evidence`, inspect them with `target/debug/kaijulab api evidence-list --file {binary_q}`, and cite evidence IDs in your final status.
- After every candidate edit, run `target/debug/kaijulab api exploit-verify --save-evidence --file {binary_q} {output_q}` with the right predicate (`--expect-target-exit 42`, `--expect-exit 42`, or `--expect-output MARKER`).
- If exploit-verify returns success=true, print SCRIPT_READY and stop.
- If validation is blocked by environment dependencies, make the script print the exact blocker and remediation, then print SCRIPT_READY_BLOCKED.
- Do not spin after the attempt budget; report the last structured failure.
"#,
        binary = binary.display(),
        goal = goal,
        output = output.display(),
        attempts = attempts.max(1),
        context = context,
        binary_q = shell_quote(&binary.to_string_lossy()),
        output_q = shell_quote(&output.to_string_lossy()),
    ))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn gdb_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '='))
    {
        s.to_string()
    } else {
        shell_quote(s)
    }
}

fn read_input_spec(spec: Option<&str>) -> Result<Option<Vec<u8>>> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    if let Some(path) = spec.strip_prefix('@') {
        Ok(Some(std::fs::read(path)?))
    } else {
        Ok(Some(spec.as_bytes().to_vec()))
    }
}

fn run_captured(
    mut cmd: Command,
    stdin_bytes: Option<&[u8]>,
    timeout_secs: u64,
    max_stream: u64,
) -> Result<serde_json::Value> {
    let timeout = Duration::from_secs(timeout_secs.clamp(1, 300));
    let start = Instant::now();
    let program = format!("{:?}", cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Ok(serde_json::json!({
                "command": program,
                "spawn_error": e.to_string(),
                "timed_out": false,
                "duration_ms": start.elapsed().as_millis(),
                "exit_code": null,
                "signal": null,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": false,
                "stderr_truncated": false,
            }));
        }
    };
    if let Some(input) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
    }
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let stdout_thread = std::thread::spawn(move || read_limited(stdout, max_stream));
    let stderr_thread = std::thread::spawn(move || read_limited(stderr, max_stream));

    let (timed_out, status) = loop {
        if let Some(status) = child.try_wait()? {
            break (false, Some(status));
        }
        if start.elapsed() >= timeout {
            #[cfg(unix)]
            unsafe {
                libc::killpg(child.id() as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }
            let status = child.wait().ok();
            break (true, status);
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    let stdout_text = String::from_utf8_lossy(&stdout).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr).into_owned();
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.and_then(|s| s.signal())
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    Ok(serde_json::json!({
        "command": program,
        "timed_out": timed_out,
        "duration_ms": start.elapsed().as_millis(),
        "exit_code": status.and_then(|s| s.code()),
        "signal": signal,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_truncated": stdout.len() as u64 >= max_stream,
        "stderr_truncated": stderr.len() as u64 >= max_stream,
    }))
}

fn runtime_next_action(output: &serde_json::Value) -> &'static str {
    let stderr = output.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
    if output
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        "Target timed out; add stdin/argv fixture or probe with gdb breakpoints."
    } else if stderr.contains("No such file or directory") || stderr.contains("not found") {
        "Resolve missing loader/library with exploit-context runtime notes or qemu -L sysroot."
    } else if output.get("signal").and_then(|v| v.as_i64()).is_some() {
        "Crash observed; run debug-probe with same input to capture registers/backtrace."
    } else {
        "Use observed stdout/stderr to refine IR targets or candidate PoC predicate."
    }
}

fn extract_gdb_signals(text: &str) -> Vec<String> {
    [
        "SIGSEGV", "SIGILL", "SIGABRT", "SIGBUS", "SIGFPE", "SIGTRAP",
    ]
    .iter()
    .filter(|sig| text.contains(**sig))
    .map(|sig| (*sig).to_string())
    .collect()
}

fn register_command_for_arch(arch: Option<&str>) -> String {
    let regs = match arch.unwrap_or(host_arch_label()) {
        "i386" => "eax ebx ecx edx esi edi ebp esp eip eflags",
        "x86_64" => "rax rbx rcx rdx rsi rdi rbp rsp rip eflags r8 r9 r10 r11 r12 r13 r14 r15",
        "aarch64" => "x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x29 x30 sp pc cpsr",
        "arm" => "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 sp lr pc cpsr",
        _ => "",
    };
    if regs.is_empty() {
        "info registers".to_string()
    } else {
        format!("info registers {regs}")
    }
}

fn parse_gdb_registers(text: &str) -> serde_json::Value {
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
            out.insert(name.to_string(), serde_json::json!(value));
        }
    }
    serde_json::Value::Object(out)
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
            | "x8"
            | "x9"
            | "x10"
            | "x11"
            | "x12"
            | "x13"
            | "x14"
            | "x15"
            | "x29"
            | "x30"
            | "sp"
            | "pc"
            | "lr"
            | "cpsr"
    )
}

fn parse_int(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

fn tool_text_json(output: String) -> serde_json::Value {
    serde_json::json!({
        "ok": !output.starts_with("Error:"),
        "text": output,
    })
}

fn cyclic_pattern(len: usize) -> String {
    let a = b"abcdefghijklmnopqrstuvwxyz";
    let b = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let c = b"0123456789";
    let mut out = Vec::with_capacity(len);
    'outer: for &x in a {
        for &y in b {
            for &z in c {
                for ch in [x, y, z] {
                    if out.len() >= len {
                        break 'outer;
                    }
                    out.push(ch);
                }
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn cyclic_find_offset(pattern: &str, needle: &str) -> Option<usize> {
    let mut needles = Vec::new();
    needles.push(needle.as_bytes().to_vec());
    let trimmed = needle.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if let Ok(value) = u64::from_str_radix(hex, 16) {
            needles.push((value as u32).to_le_bytes().to_vec());
            needles.push(value.to_le_bytes().to_vec());
        }
    }
    if let Ok(value) = trimmed.parse::<u64>() {
        needles.push((value as u32).to_le_bytes().to_vec());
        needles.push(value.to_le_bytes().to_vec());
    }
    let bytes = pattern.as_bytes();
    needles
        .into_iter()
        .filter(|n| !n.is_empty())
        .find_map(|needle| find_bytes(bytes, &needle))
}

fn exploit_recipes(arch: &str, protections: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    let nx = protections
        .and_then(|p| p.get("nx"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let pie = protections
        .and_then(|p| p.get("pie"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut recipes = Vec::new();
    recipes.push(serde_json::json!({
        "name": "offset discovery",
        "steps": ["send cyclic pattern", "debug-probe crash", "cyclic-find overwritten PC/register"],
    }));
    if nx {
        recipes.push(serde_json::json!({
            "name": "ROP/syscall",
            "when": "NX enabled",
            "steps": ["use gadget_hints and PLT/GOT", "control argument registers", "call system/execve/open-read-write"],
        }));
    } else {
        recipes.push(serde_json::json!({
            "name": "shellcode",
            "when": "NX disabled",
            "steps": ["place shellcode in controlled buffer", "redirect PC to buffer"],
        }));
    }
    if pie {
        recipes.push(serde_json::json!({
            "name": "PIE leak",
            "when": "PIE enabled",
            "steps": ["find address leak", "compute image base", "rebase gadgets before final payload"],
        }));
    }
    if arch == "i386" {
        recipes.push(serde_json::json!({
            "name": "i386 syscall",
            "registers": {"eax": "syscall", "ebx": "arg0", "ecx": "arg1", "edx": "arg2"},
        }));
    } else if arch == "x86_64" {
        recipes.push(serde_json::json!({
            "name": "x86_64 syscall",
            "registers": {"rax": "syscall", "rdi": "arg0", "rsi": "arg1", "rdx": "arg2"},
        }));
    }
    recipes
}

fn collect_json_text_hits(
    source: &str,
    value: &serde_json::Value,
    needle_l: &str,
    hits: &mut Vec<serde_json::Value>,
    limit: usize,
) {
    if hits.len() >= limit {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            if s.to_ascii_lowercase().contains(needle_l) {
                hits.push(serde_json::json!({ "source": source, "text": s }));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_text_hits(source, item, needle_l, hits, limit);
                if hits.len() >= limit {
                    break;
                }
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                collect_json_text_hits(source, value, needle_l, hits, limit);
                if hits.len() >= limit {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn recommended_next_tool(
    observation: Option<&str>,
    runtime_notes: &serde_json::Value,
    candidate: Option<&Path>,
) -> serde_json::Value {
    if runtime_notes.as_array().map_or(false, |a| !a.is_empty()) {
        return serde_json::json!({
            "command": "exploit-context",
            "reason": "runtime notes contain loader/sysroot blockers; fix execution environment first",
        });
    }
    if let Some(obs) = observation {
        let obs_l = obs.to_ascii_lowercase();
        if obs_l.contains("segmentation fault")
            || obs_l.contains("sigsegv")
            || obs_l.contains("crash")
        {
            return serde_json::json!({
                "command": "debug-probe",
                "reason": "last observation is a crash; capture registers/backtrace and compute control offset",
            });
        }
        if obs_l.contains("timeout") || obs_l.contains("hang") {
            return serde_json::json!({
                "command": "runtime-run",
                "reason": "last observation timed out; reduce fixture and capture stdout/stderr behavior",
            });
        }
    }
    if candidate.is_some() {
        serde_json::json!({
            "command": "exploit-verify",
            "reason": "candidate exists; validate an explicit success predicate",
        })
    } else {
        serde_json::json!({
            "command": "ir-query",
            "reason": "no candidate yet; inspect functions/strings and choose an input-to-control path",
        })
    }
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
        anyhow::bail!(
            "{}.mcpServers exists but is not a JSON object",
            output.display()
        );
    }
    servers.as_object_mut().expect("checked object").insert(
        "kaijulab".to_string(),
        serde_json::json!({
            "command": command.to_string_lossy(),
            "args": ["mcp"],
        }),
    );

    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&root)?),
    )?;
    println!(
        "Wrote {} with kaijulab MCP command: {} mcp",
        output.display(),
        command.display()
    );
    Ok(())
}
