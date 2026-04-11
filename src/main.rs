mod agent;
mod config;
mod llm;
mod tools;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
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

    /// LLM backend to use: gemini (default), openai, anthropic, ollama
    #[arg(long, default_value = "gemini", value_name = "BACKEND")]
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

    let backend: Box<dyn LlmBackend> = build_backend(&cfg)?;
    let display = backend.display_name();

    // ── One-shot mode: analyse a single file and exit ─────────────────────────
    if let Some(file) = &cli.file {
        ui::print_banner(&display);
        let mut agent = agent::Agent::new(backend);
        let task = format!("Analyse this binary: {}", file.display());
        agent.run(&task).await?;
        return Ok(());
    }

    // ── Plain-text REPL (--no-tui) ────────────────────────────────────────────
    if cli.no_tui {
        ui::print_banner(&display);
        let mut agent = agent::Agent::new(backend);
        run_plain_repl(&mut agent).await?;
        return Ok(());
    }

    // ── Interactive TUI (default) ─────────────────────────────────────────────
    let (event_tx, event_rx) = mpsc::unbounded_channel::<agent::AgentEvent>();
    let (user_tx, mut user_rx) = mpsc::channel::<String>(4);

    let mut ag = agent::Agent::new(backend).with_events(event_tx);

    // Run the agent loop in a background task; it blocks on incoming messages.
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

// ─── Plain-text REPL ─────────────────────────────────────────────────────────

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
