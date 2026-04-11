use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Banner ──────────────────────────────────────────────────────────────────

pub fn print_banner(backend_display: &str) {
    let width = 54usize;
    let top    = format!("╭{}╮", "─".repeat(width));
    let bot    = format!("╰{}╯", "─".repeat(width));
    let mid = |s: &str| format!("│  {:<width$}│", s, width = width - 2);

    println!();
    println!("  {}", top.magenta().bold());
    println!("  {}", mid(&format!("KaijuLab  v{}", VERSION)).magenta().bold());
    println!("  {}", mid("LLM-native Reverse Engineering Lab").magenta());
    println!("  {}", mid("").magenta());
    println!("  {}", mid(backend_display).magenta());
    println!("  {}", bot.magenta().bold());
    println!();
    println!(
        "  {}  {}",
        "Type your analysis task below.".dimmed(),
        "Ctrl-C / 'exit' to quit.".dimmed()
    );
    println!();
}

// ─── Spinner ─────────────────────────────────────────────────────────────────

pub fn new_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg.to_string().dimmed().to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

// ─── Tool call display ───────────────────────────────────────────────────────

pub fn print_tool_call(name: &str, display_args: &str) {
    println!(
        "\n  {} {}{}{}{}",
        "⏺".cyan().bold(),
        name.cyan().bold(),
        "(".dimmed(),
        display_args.dimmed(),
        ")".dimmed(),
    );
}

pub fn print_tool_output(output: &str) {
    const MAX_LINES: usize = 30;
    let lines: Vec<&str> = output.lines().collect();
    let truncated = lines.len() > MAX_LINES;
    let visible = if truncated { &lines[..MAX_LINES] } else { &lines[..] };

    println!("  {}", "┌─────────────────────────────────────────────────────────┐".dimmed());
    for line in visible {
        println!("  {} {}", "│".dimmed(), line);
    }
    if truncated {
        println!(
            "  {} {} {} {}",
            "│".dimmed(),
            "…".yellow(),
            (lines.len() - MAX_LINES).to_string().yellow(),
            "more lines (shown to LLM, truncated here)".dimmed()
        );
    }
    println!("  {}", "└─────────────────────────────────────────────────────────┘".dimmed());
}

// ─── Agent response ──────────────────────────────────────────────────────────

pub fn print_agent_response(text: &str) {
    println!();
    // Indent each line slightly for visual separation from tool output
    for line in text.lines() {
        println!("  {}", line);
    }
    println!();
}

// ─── Turn separator ──────────────────────────────────────────────────────────

pub fn print_separator() {
    let width = console::Term::stdout().size().1.min(80) as usize;
    println!("\n  {}\n", "─".repeat(width.saturating_sub(4)).dimmed());
}

// ─── Error ───────────────────────────────────────────────────────────────────

pub fn print_error(msg: &str) {
    eprintln!("\n  {} {}\n", "✗".red().bold(), msg.red());
}

