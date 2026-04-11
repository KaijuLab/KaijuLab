mod agent;
mod config;
pub mod decompiler;
mod llm;
mod tools;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;
use tokio::sync::mpsc;

use config::{BackendConfig, BackendKind};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

        tui::run_tui(event_rx, user_tx, &display, None).await?;
        return Ok(());
    }

    // ── LLM mode ─────────────────────────────────────────────────────────────
    let backend: Box<dyn LlmBackend> = build_backend(&cfg)?;
    let display = backend.display_name();

    // One-shot mode: analyse a single file and exit
    if let Some(file) = &cli.file {
        ui::print_banner(&display);
        let mut agent = agent::Agent::new(backend);
        let task = format!("Analyse this binary: {}", file.display());
        agent.run(&task).await?;
        return Ok(());
    }

    // Plain-text REPL (--no-tui)
    if cli.no_tui {
        ui::print_banner(&display);
        let mut agent = agent::Agent::new(backend);
        run_plain_repl(&mut agent).await?;
        return Ok(());
    }

    // Interactive TUI (default)
    let (event_tx, event_rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
    let (user_tx, mut user_rx) = mpsc::channel::<String>(4);

    let mut ag = agent::Agent::new(backend).with_events(event_tx);

    tokio::spawn(async move {
        while let Some(msg) = user_rx.recv().await {
            if let Err(e) = ag.run(&msg).await {
                eprintln!("agent error: {}", e);
            }
        }
    });

    tui::run_tui(event_rx, user_tx, &display, None).await?;

    Ok(())
}

// ─── Manual command dispatcher ───────────────────────────────────────────────

const MANUAL_HELP: &str = "\
No LLM configured — running in manual tool mode.

Available commands:
  file_info   <path>                  Binary metadata
  hexdump     <path> [offset] [len]   Hex dump
  strings     <path> [min_len]        Extract strings
  disassemble <path> <vaddr>          Disassemble at virtual address
  functions   <path> [max]            List functions
  imports     <path>                  Resolve PLT imports
  decompile   <path> <vaddr>          Decompile function at virtual address
  help                                Show this message

Example:  disassemble /bin/ls 0x5880";

/// Parse a user-typed command and fire AgentEvents into the TUI channel.
fn dispatch_manual_command(input: &str, tx: &mpsc::UnboundedSender<agent::AgentEvent>) {
    let parts: Vec<&str> = input.trim().splitn(4, ' ').collect();
    let cmd = parts.first().copied().unwrap_or("").to_lowercase();

    let send = |ev| { let _ = tx.send(ev); };

    match cmd.as_str() {
        "help" | "" => {
            send(agent::AgentEvent::LlmText(MANUAL_HELP.to_string()));
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
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            run_tool("disassemble", json!({"path": path, "vaddr": vaddr}), tx);
        }

        "functions" | "funcs" => {
            let path = parts.get(1).copied().unwrap_or("");
            let max  = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(50);
            run_tool("list_functions", json!({"path": path, "max_results": max}), tx);
        }

        "imports" | "plt" => {
            let path = parts.get(1).copied().unwrap_or("");
            run_tool("resolve_plt", json!({"path": path}), tx);
        }

        "decompile" => {
            let path  = parts.get(1).copied().unwrap_or("");
            let vaddr = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(0);
            run_tool("decompile", json!({"path": path, "vaddr": vaddr}), tx);
        }

        other => {
            send(agent::AgentEvent::Error(format!(
                "Unknown command '{}'. Type 'help' for usage.", other
            )));
            send(agent::AgentEvent::Done);
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

/// Parse a number, accepting 0x… hex prefixes.
fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
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
