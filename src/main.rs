mod agent;
mod config;
mod llm;
mod tools;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "kaijulab",
    about = "KaijuLab — LLM-native Reverse Engineering Lab",
    version
)]
struct Cli {
    /// Path to Google service-account JSON key file
    /// (overrides GOOGLE_APPLICATION_CREDENTIALS)
    #[arg(long, value_name = "FILE")]
    credentials: Option<PathBuf>,

    /// GCP project ID (overrides GOOGLE_PROJECT_ID)
    #[arg(long, value_name = "PROJECT")]
    project: Option<String>,

    /// Vertex AI location (overrides GOOGLE_LOCATION; default: us-central1)
    #[arg(long, value_name = "REGION")]
    location: Option<String>,

    /// Gemini model ID (overrides KAIJULAB_MODEL; default: gemini-2.5-flash)
    #[arg(long, value_name = "MODEL")]
    model: Option<String>,

    /// Analyse this file immediately on startup (non-interactive)
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Load configuration ────────────────────────────────────────────────────
    let cfg = config::Config::load(
        cli.credentials,
        cli.project,
        cli.location,
        cli.model,
    )?;

    // ── Build Gemini client & agent ───────────────────────────────────────────
    let gemini = llm::GeminiClient::new(
        &cfg.credentials_path,
        cfg.project_id.clone(),
        cfg.location.clone(),
        cfg.model_id.clone(),
    )?;

    ui::print_banner(&cfg.model_id, &cfg.project_id);

    let mut agent = agent::Agent::new(gemini);

    // ── Non-interactive one-shot mode ─────────────────────────────────────────
    if let Some(file) = &cli.file {
        let task = format!("Analyse this binary: {}", file.display());
        agent.run(&task).await?;
        return Ok(());
    }

    // ── Interactive REPL ──────────────────────────────────────────────────────
    let mut rl = rustyline::DefaultEditor::new()?;

    loop {
        match ui::readline(&mut rl) {
            None => break, // Ctrl-C or Ctrl-D
            Some(input) if input.is_empty() => continue,
            Some(input) if matches!(input.as_str(), "exit" | "quit" | "q") => break,
            Some(input) => {
                if let Err(e) = agent.run(&input).await {
                    ui::print_error(&e.to_string());
                }
                ui::print_separator();
            }
        }
    }

    println!("  Bye.");
    Ok(())
}
