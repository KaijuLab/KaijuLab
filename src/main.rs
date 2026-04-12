mod agent;
pub mod arch;
mod config;
pub mod decompiler;
pub mod dwarf;
pub mod hashdb;
mod llm;
pub mod plugin;
pub mod project;
mod tools;
mod tui;
mod ui;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;
use tokio::sync::mpsc;

use config::{BackendConfig, BackendKind, KaijuConfig};
use llm::LlmBackend;

#[derive(Parser)]
#[command(
    name = "kaijulab",
    about = "KaijuLab — LLM-native Reverse Engineering Lab",
    version
)]
struct Cli {
    // ── Backend selection ──────────────────────────────────────────────────────

    /// LLM backend to use: none (default), gemini, openai, anthropic, ollama
    #[arg(long, default_value = "none", value_name = "BACKEND")]
    backend: String,

    /// Model ID override (each backend has its own default)
    #[arg(long, value_name = "MODEL")]
    model: Option<String>,

    // ── Gemini-specific ────────────────────────────────────────────────────────

    /// [Gemini] Path to service-account JSON key (overrides GOOGLE_APPLICATION_CREDENTIALS)
    #[arg(long, value_name = "FILE")]
    credentials: Option<PathBuf>,

    /// [Gemini] GCP project ID (overrides GOOGLE_PROJECT_ID)
    #[arg(long, value_name = "PROJECT")]
    project: Option<String>,

    /// [Gemini] Vertex AI region (overrides GOOGLE_LOCATION; default: us-central1)
    #[arg(long, value_name = "REGION")]
    location: Option<String>,

    // ── OpenAI / Anthropic / Ollama ────────────────────────────────────────────

    /// [OpenAI/Anthropic] API key (overrides OPENAI_API_KEY / ANTHROPIC_API_KEY)
    #[arg(long, value_name = "KEY")]
    api_key: Option<String>,

    /// [OpenAI/Ollama] Base URL (overrides OPENAI_BASE_URL / OLLAMA_BASE_URL)
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,

    // ── Mode selection ─────────────────────────────────────────────────────────

    /// Analyse this binary immediately on startup, then exit (non-interactive)
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    /// Use plain-text REPL instead of the TUI (useful for scripting / pipes)
    #[arg(long)]
    no_tui: bool,

    /// [One-shot] Emit a structured JSON summary to stdout after analysis instead of plain text
    #[arg(long)]
    output_json: bool,

    /// Run commands from a script file (one command per line, same syntax as the manual REPL)
    /// and exit.  Lines starting with '#' and blank lines are ignored.
    #[arg(long, value_name = "SCRIPT")]
    script: Option<PathBuf>,

    /// Headless mode: implies --no-tui --output-json; runs analysis and prints JSON to stdout.
    #[arg(long)]
    headless: bool,

    /// Do not load or save a session file for this run.
    #[arg(long)]
    no_session: bool,

    /// Run a Rhai plugin script and exit.
    /// Pass an absolute path to a .rhai file, or just the name of a plugin
    /// found in ~/.kaiju/plugins/ (without the .rhai extension).
    #[arg(long, value_name = "PLUGIN")]
    plugin: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load (or create) ~/.kaiju/config.toml
    KaijuConfig::write_default_if_missing();
    let _kaiju_cfg = KaijuConfig::load();

    let kind: BackendKind = cli.backend.parse()?;
    let cfg = BackendConfig::load(
        kind,
        cli.model,
        cli.credentials,
        cli.project,
        cli.location,
        cli.api_key,
        cli.base_url,
    )?;

    // ── Plugin / scripting mode ──────────────────────────────────────────────
    if let Some(plugin_arg) = &cli.plugin {
        let binary_path = cli.file.as_ref()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let out = run_plugin_arg(plugin_arg, &binary_path);
        if let Some(err) = &out.error {
            eprintln!("Plugin error: {}", err);
        }
        if !out.text.is_empty() {
            print!("{}", out.text);
        }
        return Ok(());
    }

    // ── No-LLM (manual) mode ─────────────────────────────────────────────────
    if matches!(cfg, BackendConfig::None) {
        let display = "manual".to_string();

        if let Some(file) = &cli.file {
            // One-shot: just run file_info and exit
            ui::print_banner(&display);
            let result = tools::dispatch("file_info", &json!({"path": file.to_string_lossy()}));
            println!("{}", result.output);
            return Ok(());
        }

        if cli.no_tui {
            ui::print_banner(&display);
            run_manual_plain_repl().await?;
            return Ok(());
        }

        // TUI manual mode
        let (event_tx, event_rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
        let (user_tx, mut user_rx) = mpsc::channel::<String>(4);

        tokio::spawn(async move {
            while let Some(msg) = user_rx.recv().await {
                dispatch_manual_command(&msg, &event_tx);
            }
        });

        let cancel_manual = Arc::new(AtomicBool::new(false));
        tui::run_tui(event_rx, user_tx, &display, None, cancel_manual).await?;
        return Ok(());
    }

    // ── LLM mode ─────────────────────────────────────────────────────────────
    let backend: Box<dyn LlmBackend> = build_backend(&cfg)?;
    let display = backend.display_name();

    // Headless mode: --headless implies --no-tui + --output-json, requires a file
    if cli.headless {
        if let Some(file) = &cli.file {
            let mut agent = agent::Agent::new(backend);
            let task = format!("Analyse this binary: {}", file.display());
            agent.run(&task).await?;
            let out = agent.structured_output(&file.to_string_lossy());
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            eprintln!("--headless requires a FILE argument");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Script mode
    if let Some(script_path) = &cli.script {
        run_script(script_path).await?;
        return Ok(());
    }

    // One-shot mode: analyse a single file and exit
    if let Some(file) = &cli.file {
        let mut agent = agent::Agent::new(backend);
        let task = format!("Analyse this binary: {}", file.display());
        if cli.output_json {
            agent.run(&task).await?;
            let out = agent.structured_output(&file.to_string_lossy());
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            ui::print_banner(&display);
            agent.run(&task).await?;
        }
        return Ok(());
    }

    // Plain-text REPL (--no-tui)
    if cli.no_tui {
        ui::print_banner(&display);
        let mut agent = agent::Agent::new(backend);
        run_plain_repl(&mut agent).await?;
        return Ok(());
    }

    // Add --no-session CLI flag support (cli.no_session checked below)
    let no_session = cli.no_session;
    let session_key = cli.file.as_ref().map(|f| f.to_string_lossy().to_string());

    // Interactive TUI (default)
    let (event_tx, event_rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
    let (user_tx, mut user_rx) = mpsc::channel::<String>(4);

    // Keep a clone of event_tx for the plugin dispatcher (before it's moved into ag).
    let plugin_event_tx = event_tx.clone();

    // Shared cancellation token: TUI sets it true, agent loop checks it.
    let cancel_token = Arc::new(AtomicBool::new(false));
    let cancel_for_agent = cancel_token.clone();
    let cancel_for_tui   = cancel_token.clone();

    let mut ag = agent::Agent::new(backend)
        .with_events(event_tx)
        .with_cancel_token(cancel_for_agent);

    // Restore previous session if one exists for this binary
    if !no_session {
        if let Some(ref key) = session_key {
            if agent::Agent::has_session(key) {
                if let Err(e) = ag.load_session(key) {
                    eprintln!("Warning: could not load session: {}", e);
                }
            }
        }
    }

    // Save recently opened binary to ~/.kaiju/recent.json
    if let Some(ref key) = session_key {
        save_recent_file(key);
    }

    let initial_file = cli.file.as_deref();

    tokio::spawn(async move {
        while let Some(msg) = user_rx.recv().await {
            // Intercept plugin commands before sending to the LLM agent.
            if msg.trim() == "plugins" {
                let listing = plugin::format_plugin_list();
                let _ = plugin_event_tx.send(agent::AgentEvent::LlmText(listing));
                let _ = plugin_event_tx.send(agent::AgentEvent::Done);
                continue;
            }
            if let Some(rest) = msg.trim().strip_prefix("run ") {
                let mut parts = rest.splitn(2, ' ');
                let name    = parts.next().unwrap_or("").trim().to_string();
                let binary  = parts.next().unwrap_or("").trim().to_string();
                let tx = plugin_event_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let out = plugin::run_named(&name, &binary);
                    let output = format_plugin_output(&name, &out);
                    let _ = tx.send(agent::AgentEvent::PluginOutput {
                        name: name.clone(),
                        output,
                    });
                    let _ = tx.send(agent::AgentEvent::Done);
                });
                continue;
            }
            if let Err(e) = ag.run(&msg).await {
                eprintln!("agent error: {}", e);
            }
        }
        // Save session on shutdown
        if !no_session {
            if let Some(ref key) = session_key {
                if let Err(e) = ag.save_session(key) {
                    eprintln!("Warning: could not save session: {}", e);
                }
            }
        }
    });

    tui::run_tui(event_rx, user_tx, &display, initial_file, cancel_for_tui).await?;

    Ok(())
}

// ─── Manual command dispatcher ───────────────────────────────────────────────

const MANUAL_HELP: &str = "\
No LLM configured — running in manual tool mode.

Analysis:
  file_info       <path>                  Binary metadata & segment table
  hexdump         <path> [offset] [len]   Raw hex dump
  strings         <path> [min_len]        Extract printable strings
  disassemble     <path> [vaddr]          Disassemble (default: entry point)
  functions       <path> [max]            List all functions
  decompile       <path> [vaddr]          Decompile a function
  decompile_flat  <path> <base> <vaddr>   Decompile raw firmware / shellcode
  imports         <path>                  Resolve PLT / PE imports
  xrefs           <path> <vaddr>          Cross-references to an address
  callgraph       <path>                  Full static call graph
  cfg             <path> <vaddr>          Control-flow graph for a function
  dwarf           <path>                  DWARF debug info

Search & patch:
  entropy         <path>                  Section entropy — detect packers/crypto
  search          <path> <hex pattern>    Byte-pattern search (e.g.  E8 ?? ?? ?? ??)
  patch           <path> <vaddr> <hex>    Patch bytes  →  writes  <file>.patched
  yara            <path> <vaddr> [name]   Generate a YARA rule for a function

Intelligence:
  scan            <path> [max_fns]        Vulnerability scan (top N functions)
  explain         <path> <vaddr>          Explain a function
  identify        <path>                  FLIRT-style library recognition
  auto            <path> [top_n]          Full auto-analysis pass

Diff & output:
  diff            <path_a> <path_b>       Diff two binaries by function content
  report          <path>                  Export HTML analysis report
  vt              <path>                  VirusTotal hash lookup (needs VIRUSTOTAL_API_KEY)
  pdb             <binary> <pdb_file>     Load Windows PDB symbols

Project (persistent across sessions):
  rename        <path> <vaddr> <name>     Name a function
  comment       <path> <vaddr> <text>     Attach a comment to an address
  project       <path>                    Show all saved annotations
  types         <path>                    Show struct / signature definitions

Plugins / scripting:
  plugins                                 List available plugins (~/.kaiju/plugins/)
  run <name> [binary]                     Run a Rhai plugin by name (or path)

Other:
  ls            [path]                    List files in a directory
  help                                    Show this message

Example:  disassemble /bin/ls 0x5880
          entropy /path/to/suspect.exe
          search  /path/to/binary  E8 ?? ?? ?? ?? 48 89 C7
          run my_script /bin/ls";

/// Parse a user-typed command and fire AgentEvents into the TUI channel.
fn dispatch_manual_command(input: &str, tx: &mpsc::UnboundedSender<agent::AgentEvent>) {
    let parts: Vec<&str> = input.trim().splitn(5, ' ').collect();
    let cmd = parts.first().copied().unwrap_or("").to_lowercase();

    let send = |ev| { let _ = tx.send(ev); };

    match cmd.as_str() {
        "help" | "" => {
            send(agent::AgentEvent::LlmText(MANUAL_HELP.to_string()));
            send(agent::AgentEvent::Done);
        }

        "ls" => {
            let dir = parts.get(1).copied().unwrap_or(".");
            let output = cmd_ls(dir);
            send(agent::AgentEvent::LlmText(output));
            send(agent::AgentEvent::Done);
        }

        "file_info" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("file_info", json!({"path": path}), tx);
        }

        "hexdump" => {
            let path   = parts.get(1).copied().unwrap_or("");
            let offset = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let len    = parts.get(3).and_then(|s| parse_int(s)).unwrap_or(256);
            run_tool("hexdump", json!({"path": path, "offset": offset, "length": len}), tx);
        }

        "strings" => {
            let path    = parts.get(1).copied().unwrap_or("");
            let min_len = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(4);
            run_tool("strings_extract", json!({"path": path, "min_len": min_len}), tx);
        }

        "disassemble" | "disasm" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).or_else(|| {
                match infer_entry_point(path) {
                    Ok(ep) => Some(ep),
                    Err(e) => { let _ = tx.send(agent::AgentEvent::Error(e)); None }
                }
            }).unwrap_or(0);
            run_tool("disassemble", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "functions" | "funcs" => {
            let path = parts.get(1).copied().unwrap_or("");
            let max  = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(50);
            run_tool("list_functions", json!({"path": path, "max_results": max}), tx);
        }

        "decompile" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).or_else(|| {
                match infer_entry_point(path) {
                    Ok(ep) => Some(ep),
                    Err(e) => { let _ = tx.send(agent::AgentEvent::Error(e)); None }
                }
            }).unwrap_or(0);
            run_tool("decompile", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "xrefs" | "xref" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            run_tool("xrefs_to", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "dwarf" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("dwarf_info", json!({"path": path}), tx);
        }

        "rename" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let name  = parts.get(3).copied().unwrap_or("");
            run_tool("rename_function", json!({"path": path, "vaddr": vaddr, "name": name}), tx);
        }

        "comment" => {
            let path    = parts.get(1).copied().unwrap_or("");
            let vaddr   = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let comment = parts.get(3).copied().unwrap_or("");
            run_tool("add_comment", json!({"path": path, "vaddr": vaddr, "comment": comment}), tx);
        }

        "project" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("load_project", json!({"path": path}), tx);
        }

        "types" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("list_types", json!({"path": path}), tx);
        }

        "imports" | "plt" => {
            let path = parts.get(1).copied().unwrap_or("");
            // Try PE first, fall back to ELF PLT
            let data = std::fs::read(path).unwrap_or_default();
            let is_pe = matches!(
                goblin::Object::parse(&data),
                Ok(goblin::Object::PE(_))
            );
            if is_pe {
                run_tool("resolve_pe_imports", json!({"path": path}), tx);
            } else {
                run_tool("resolve_plt", json!({"path": path}), tx);
            }
        }

        "callgraph" | "call_graph" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("call_graph", json!({"path": path}), tx);
        }

        "cfg" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            run_tool("cfg_view", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "scan" => {
            let path    = parts.get(1).copied().unwrap_or("");
            let max_fns = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(5);
            run_tool("scan_vulnerabilities", json!({"path": path, "max_fns": max_fns}), tx);
        }

        "explain" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            run_tool("explain_function", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "identify" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("identify_library_functions", json!({"path": path}), tx);
        }

        "diff" => {
            let path_a = parts.get(1).copied().unwrap_or("");
            let path_b = parts.get(2).copied().unwrap_or("");
            run_tool("diff_binary", json!({"path_a": path_a, "path_b": path_b}), tx);
        }

        "auto" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let top_n = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(5);
            run_tool("auto_analyze", json!({"path": path, "top_n": top_n}), tx);
        }

        "report" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("export_report", json!({"path": path}), tx);
        }

        "vt" | "virustotal" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("virustotal_check", json!({"path": path}), tx);
        }

        "pdb" => {
            let binary = parts.get(1).copied().unwrap_or("");
            let pdb    = parts.get(2).copied().unwrap_or("");
            run_tool("load_pdb", json!({"binary_path": binary, "pdb_path": pdb}), tx);
        }

        "decompile_flat" => {
            let path      = parts.get(1).copied().unwrap_or("");
            let base_addr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let vaddr     = parts.get(3).and_then(|s| parse_int(s)).unwrap_or(0);
            let arch      = parts.get(4).copied().unwrap_or("x86_64");
            run_tool("decompile_flat",
                json!({"path": path, "base_addr": base_addr, "vaddr": vaddr, "arch": arch}), tx);
        }

        "search" | "find" => {
            let path    = parts.get(1).copied().unwrap_or("");
            let pattern = parts[2..].join(" "); // rest is the pattern
            run_tool("search_bytes", json!({"path": path, "pattern": pattern}), tx);
        }

        "patch" => {
            let path      = parts.get(1).copied().unwrap_or("");
            let vaddr     = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let hex_bytes = parts[3..].join(" ");
            run_tool("patch_bytes",
                json!({"path": path, "vaddr": vaddr, "hex_bytes": hex_bytes}), tx);
        }

        "entropy" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("section_entropy", json!({"path": path}), tx);
        }

        "yara" | "yara_rule" | "generate_yara" => {
            let path      = parts.get(1).copied().unwrap_or("");
            let vaddr     = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            let rule_name = parts.get(3).copied();
            let args = match rule_name {
                Some(name) => json!({"path": path, "vaddr": vaddr, "rule_name": name}),
                None       => json!({"path": path, "vaddr": vaddr}),
            };
            run_tool("generate_yara_rule", args, tx);
        }

        "plugins" | "plugin" => {
            let listing = plugin::format_plugin_list();
            send(agent::AgentEvent::LlmText(listing));
            send(agent::AgentEvent::Done);
        }

        "run" => {
            let name   = parts.get(1).copied().unwrap_or("").to_string();
            let binary = parts.get(2).copied().unwrap_or("").to_string();
            if name.is_empty() {
                send(agent::AgentEvent::Error(
                    "Usage: run <plugin_name> [binary_path]".to_string()
                ));
                send(agent::AgentEvent::Done);
                return;
            }
            let out = run_plugin_arg(&name, &binary);
            let output = format_plugin_output(&name, &out);
            send(agent::AgentEvent::PluginOutput { name, output: output.clone() });
            send(agent::AgentEvent::Done);
        }

        other => {
            send(agent::AgentEvent::Error(format!(
                "Unknown command '{}'. Type 'help' for usage.", other
            )));
            send(agent::AgentEvent::Done);
        }
    }
}

fn cmd_ls(dir: &str) -> String {
    match std::fs::read_dir(dir) {
        Err(e) => format!("ls: {}: {}", dir, e),
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    match e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        true  => format!("{}/", name),
                        false => name,
                    }
                })
                .collect();
            names.sort();
            if names.is_empty() {
                format!("(empty directory: {})", dir)
            } else {
                names.join("\n")
            }
        }
    }
}

fn run_tool(name: &str, args: serde_json::Value, tx: &mpsc::UnboundedSender<agent::AgentEvent>) {
    let display_args = args.to_string();
    let _ = tx.send(agent::AgentEvent::ToolCall { name: name.to_string(), display_args });
    let result = tools::dispatch(name, &args);
    let _ = tx.send(agent::AgentEvent::ToolResult {
        name: name.to_string(),
        output: result.output,
    });
    let _ = tx.send(agent::AgentEvent::Done);
}

/// Return the entry-point virtual address of a binary, or an error string.
fn infer_entry_point(path: &str) -> Result<u64, String> {
    use object::Object;
    let data = std::fs::read(path).map_err(|e| format!("cannot read '{}': {}", path, e))?;
    let obj = object::File::parse(&*data).map_err(|e| format!("parse error: {}", e))?;
    Ok(obj.entry())
}

/// Parse a number, accepting 0x… hex prefixes.
fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

// ─── Script / batch mode ─────────────────────────────────────────────────────

/// Execute every non-blank, non-comment line in `path` as a manual tool command,
/// printing results to stdout.  Identical syntax to the manual REPL.
async fn run_script(path: &std::path::PathBuf) -> Result<()> {
    use std::io::BufRead;

    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("Cannot open script '{}': {}", path.display(), e))?;

    let lines: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .collect::<std::io::Result<_>>()
        .map_err(|e| anyhow::anyhow!("Error reading script: {}", e))?;

    println!("# KaijuLab script: {}", path.display());
    println!();

    for (lineno, raw) in lines.iter().enumerate() {
        let line = raw.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        println!(">> {}", line);

        let (tx, mut rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
        dispatch_manual_command(&line, &tx);
        drop(tx); // close sender so recv() returns None when drained

        while let Some(ev) = rx.recv().await {
            match ev {
                agent::AgentEvent::ToolResult { name, output } => {
                    println!("-- {} --", name);
                    println!("{}", output);
                }
                agent::AgentEvent::LlmText(t) => println!("{}", t),
                agent::AgentEvent::Error(e) => {
                    eprintln!("Error (line {}): {}", lineno + 1, e);
                }
                _ => {}
            }
        }
        println!();
    }

    Ok(())
}

// ─── Manual plain-text REPL ──────────────────────────────────────────────────

async fn run_manual_plain_repl() -> Result<()> {
    use std::io::{BufRead, Write};

    println!("{}", MANUAL_HELP);

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("\n> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let input = line.trim().to_string();
        if input.is_empty() { continue; }
        if matches!(input.as_str(), "exit" | "quit" | "q") { break; }

        // Reuse the same parser; collect events and print them
        let (tx, mut rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
        dispatch_manual_command(&input, &tx);
        drop(tx);
        while let Some(ev) = rx.recv().await {
            match ev {
                agent::AgentEvent::ToolResult { output, .. } => println!("{output}"),
                agent::AgentEvent::LlmText(t) => println!("{t}"),
                agent::AgentEvent::Error(e) => eprintln!("Error: {e}"),
                _ => {}
            }
        }
        ui::print_separator();
    }

    println!("  Bye.");
    Ok(())
}

// ─── LLM plain-text REPL ─────────────────────────────────────────────────────

async fn run_plain_repl(agent: &mut agent::Agent) -> Result<()> {
    use std::io::{BufRead, Write};

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("\n> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break; // EOF
        }
        let input = line.trim().to_string();
        if input.is_empty() {
            continue;
        }
        if matches!(input.as_str(), "exit" | "quit" | "q") {
            break;
        }
        if let Err(e) = agent.run(&input).await {
            ui::print_error(&e.to_string());
        }
        ui::print_separator();
    }

    println!("  Bye.");
    Ok(())
}

// ─── Plugin helpers ──────────────────────────────────────────────────────────

/// Run a plugin given either a name (looked up in `~/.kaiju/plugins/`) or an
/// absolute / relative path to a `.rhai` file.  Used by `--plugin` CLI flag.
fn run_plugin_arg(arg: &str, binary_path: &str) -> plugin::PluginOutput {
    let p = std::path::Path::new(arg);
    if p.exists() {
        plugin::run_file(p, binary_path)
    } else if arg.ends_with(".rhai") {
        plugin::PluginOutput::error(format!("File not found: {}", arg))
    } else {
        plugin::run_named(arg, binary_path)
    }
}

/// Format a `PluginOutput` into a human-readable string for TUI display.
fn format_plugin_output(name: &str, out: &plugin::PluginOutput) -> String {
    let mut s = format!("── Plugin: {} ──\n", name);
    if !out.text.is_empty() {
        s.push_str(&out.text);
        if !out.text.ends_with('\n') {
            s.push('\n');
        }
    }
    if let Some(err) = &out.error {
        s.push_str(&format!("\nError: {}\n", err));
    }
    s
}

// ─── Recent files ────────────────────────────────────────────────────────────

/// Path to the recent-files list.
fn recent_files_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(std::path::PathBuf::from(home).join(".kaiju").join("recent.json"))
}

/// Load the list of recently opened binaries (most recent first).
pub fn load_recent_files() -> Vec<String> {
    let path = match recent_files_path() {
        Some(p) => p,
        None => return vec![],
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    serde_json::from_str::<Vec<String>>(&text).unwrap_or_default()
}

/// Prepend `path` to the recent-files list (up to 10 entries, deduped).
pub fn save_recent_file(path: &str) {
    let rp = match recent_files_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = rp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut list = load_recent_files();
    list.retain(|p| p != path);
    list.insert(0, path.to_string());
    list.truncate(10);
    let _ = std::fs::write(&rp, serde_json::to_string_pretty(&list).unwrap_or_default());
}

// ─── Backend factory ──────────────────────────────────────────────────────────

fn build_backend(cfg: &BackendConfig) -> Result<Box<dyn LlmBackend>> {
    match cfg {
        BackendConfig::None => unreachable!("build_backend called with None backend"),
        BackendConfig::Gemini { credentials_path, project_id, location, model_id } => {
            let b = llm::gemini::GeminiBackend::new(
                credentials_path,
                project_id,
                location,
                model_id,
            )?;
            Ok(Box::new(b))
        }
        BackendConfig::OpenAi { api_key, base_url, model_id } => {
            let b = llm::openai::OpenAiBackend::new(api_key, base_url, model_id);
            Ok(Box::new(b))
        }
        BackendConfig::Anthropic { api_key, model_id } => {
            let b = llm::anthropic::AnthropicBackend::new(api_key, model_id);
            Ok(Box::new(b))
        }
        BackendConfig::Ollama { base_url, model_id } => {
            let b = llm::openai::OpenAiBackend::new("", base_url, model_id);
            Ok(Box::new(b))
        }
    }
}
