use std::io;

use crossterm::{
    event::{Event, EventStream, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Position, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use tokio::sync::mpsc;

use crate::agent::AgentEvent;

// ─── Tab identifiers ─────────────────────────────────────────────────────────

const TAB_NAMES: &[&str] = &["Functions", "Disasm", "Strings", "Imports", "Chat"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Functions = 0,
    Disasm    = 1,
    Strings   = 2,
    Imports   = 3,
    Chat      = 4,
}

impl Tab {
    fn from_index(n: usize) -> Option<Self> {
        match n {
            0 => Some(Tab::Functions),
            1 => Some(Tab::Disasm),
            2 => Some(Tab::Strings),
            3 => Some(Tab::Imports),
            4 => Some(Tab::Chat),
            _ => None,
        }
    }

    fn next(self) -> Self {
        Tab::from_index((self as usize + 1) % TAB_NAMES.len()).unwrap()
    }

    fn prev(self) -> Self {
        Tab::from_index((self as usize + TAB_NAMES.len() - 1) % TAB_NAMES.len()).unwrap()
    }

    /// Which tool populates this tab's dedicated view.
    fn from_tool(name: &str) -> Option<Self> {
        match name {
            "list_functions"  => Some(Tab::Functions),
            "disassemble"     => Some(Tab::Disasm),
            "strings_extract" => Some(Tab::Strings),
            "resolve_plt"     => Some(Tab::Imports),
            _ => None,
        }
    }
}

// ─── Chat messages ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub enum ChatMsg {
    User(String),
    Assistant(String),
    ToolCall { name: String, args: String },
    ToolResult { name: String, lines: Vec<String> },
    Error(String),
}

// ─── Application state ───────────────────────────────────────────────────────

pub struct App {
    pub active_tab: Tab,
    /// Latest content for each dedicated panel (indexed by Tab as usize).
    pub tab_lines: [Vec<String>; 5],
    /// Whether each tab has unseen content (shows a dot indicator).
    pub tab_dirty: [bool; 5],
    pub chat: Vec<ChatMsg>,
    /// Scroll offsets for each tab (lines from top for panels; lines from bottom for chat).
    pub scroll: [u16; 5],
    pub input: String,
    pub input_cursor: usize,
    pub status: String,
    pub is_loading: bool,
    pub backend_name: String,
    pub binary_path: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(backend_name: String) -> Self {
        App {
            active_tab: Tab::Chat,
            tab_lines: Default::default(),
            tab_dirty: [false; 5],
            chat: Vec::new(),
            scroll: [0u16; 5],
            input: String::new(),
            input_cursor: 0,
            status: "Ready — type a task and press Enter".to_string(),
            is_loading: false,
            backend_name,
            binary_path: None,
            should_quit: false,
        }
    }

    pub fn apply_event(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::Thinking => {
                self.is_loading = true;
                self.status = "Thinking…".to_string();
            }
            AgentEvent::ToolCall { name, display_args } => {
                self.chat.push(ChatMsg::ToolCall { name: name.clone(), args: display_args });
                self.status = format!("⏺ {}(…)", name);
                self.is_loading = true;
                // Scroll chat to bottom so the call is visible
                self.scroll[Tab::Chat as usize] = 0;
            }
            AgentEvent::ToolResult { name, output } => {
                let lines: Vec<String> = output.lines().map(|l| l.to_string()).collect();
                self.chat.push(ChatMsg::ToolResult { name: name.clone(), lines: lines.clone() });
                // Populate dedicated tab
                if let Some(tab) = Tab::from_tool(&name) {
                    self.tab_lines[tab as usize] = lines;
                    self.scroll[tab as usize] = 0;
                    self.tab_dirty[tab as usize] = true;
                }
                self.scroll[Tab::Chat as usize] = 0;
                self.status = format!("{} done", name);
                self.is_loading = false;
            }
            AgentEvent::LlmText(text) => {
                self.chat.push(ChatMsg::Assistant(text));
                self.active_tab = Tab::Chat;
                self.scroll[Tab::Chat as usize] = 0;
                self.is_loading = false;
                self.status = "Ready".to_string();
            }
            AgentEvent::Done => {
                self.is_loading = false;
                self.status = "Ready".to_string();
            }
            AgentEvent::Error(e) => {
                self.chat.push(ChatMsg::Error(e.clone()));
                self.scroll[Tab::Chat as usize] = 0;
                self.is_loading = false;
                self.status = format!("Error: {}", e);
            }
        }
    }

    /// Returns a user message to send to the agent, or None.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Option<String> {
        match key.code {
            // Quit on Ctrl-C when input is empty
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.input.is_empty() {
                    self.should_quit = true;
                } else {
                    self.input.clear();
                    self.input_cursor = 0;
                }
                None
            }

            // Tab cycling
            KeyCode::Tab => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.active_tab = self.active_tab.prev();
                } else {
                    self.active_tab = self.active_tab.next();
                }
                self.tab_dirty[self.active_tab as usize] = false;
                None
            }
            KeyCode::BackTab => {
                self.active_tab = self.active_tab.prev();
                self.tab_dirty[self.active_tab as usize] = false;
                None
            }

            // Number keys to jump to a tab (only when input field is empty)
            KeyCode::Char(c @ '1'..='5') if self.input.is_empty() && key.modifiers.is_empty() => {
                let idx = (c as usize) - ('1' as usize);
                if let Some(t) = Tab::from_index(idx) {
                    self.active_tab = t;
                    self.tab_dirty[t as usize] = false;
                }
                None
            }

            // Scrolling
            KeyCode::Up => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_add(3);
                None
            }
            KeyCode::Down => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_sub(3);
                None
            }
            KeyCode::PageUp => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_add(20);
                None
            }
            KeyCode::PageDown => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_sub(20);
                None
            }

            // Submit
            KeyCode::Enter => {
                let msg = self.input.trim().to_string();
                if msg.is_empty() || self.is_loading {
                    return None;
                }
                self.chat.push(ChatMsg::User(msg.clone()));
                self.input.clear();
                self.input_cursor = 0;
                self.is_loading = true;
                self.status = "Sending…".to_string();
                self.active_tab = Tab::Chat;
                self.scroll[Tab::Chat as usize] = 0;
                Some(msg)
            }

            // Text editing
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor -= 1;
                    self.input.remove(self.input_cursor);
                }
                None
            }
            KeyCode::Delete => {
                if self.input_cursor < self.input.len() {
                    self.input.remove(self.input_cursor);
                }
                None
            }
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
                None
            }
            KeyCode::Right => {
                if self.input_cursor < self.input.len() {
                    self.input_cursor += 1;
                }
                None
            }
            KeyCode::Home => {
                self.input_cursor = 0;
                None
            }
            KeyCode::End => {
                self.input_cursor = self.input.len();
                None
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.insert(self.input_cursor, c);
                self.input_cursor += 1;
                None
            }
            _ => None,
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub async fn run_tui(
    mut event_rx: mpsc::UnboundedReceiver<AgentEvent>,
    user_tx: mpsc::Sender<String>,
    backend_name: &str,
    initial_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    // Enter alternate screen
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(backend_name.to_string());

    // If a file was supplied, kick off the analysis immediately
    if let Some(path) = initial_file {
        let task = format!("Analyse this binary: {}", path.display());
        app.binary_path = Some(path.to_string_lossy().to_string());
        app.chat.push(ChatMsg::User(task.clone()));
        app.is_loading = true;
        app.status = "Analysing…".to_string();
        user_tx.send(task).await?;
    }

    // Panic hook: restore terminal even on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let mut event_stream = EventStream::new();
    terminal.draw(|f| render(f, &app))?;

    loop {
        tokio::select! {
            // Agent events
            maybe = event_rx.recv() => {
                match maybe {
                    Some(ev) => app.apply_event(ev),
                    None     => break, // agent task dropped the sender
                }
            }
            // Terminal input events
            maybe = event_stream.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) => {
                        if let Some(msg) = app.handle_key(key) {
                            user_tx.send(msg).await?;
                        }
                    }
                    Some(Ok(Event::Resize(_, _))) => {
                        terminal.autoresize()?;
                    }
                    Some(Err(e)) => {
                        app.status = format!("Input error: {}", e);
                    }
                    _ => {}
                }
            }
        }

        terminal.draw(|f| render(f, &app))?;

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

// ─── Top-level render ────────────────────────────────────────────────────────

fn render(f: &mut Frame, app: &App) {
    let area = f.area();

    if area.width < 40 || area.height < 8 {
        f.render_widget(
            Paragraph::new(" Terminal too small — please resize (min 40×8) ")
                .style(Style::new().fg(Color::Red).bold()),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Length(1), // tab bar
            Constraint::Min(4),    // content
            Constraint::Length(1), // status bar
            Constraint::Length(2), // input  (border-top + text line)
        ])
        .split(area);

    render_title(f, chunks[0], app);
    render_tabbar(f, chunks[1], app);
    render_content(f, chunks[2], app);
    render_statusbar(f, chunks[3], app);
    render_input(f, chunks[4], app);
}

// ─── Title bar ───────────────────────────────────────────────────────────────

fn render_title(f: &mut Frame, area: Rect, app: &App) {
    let binary = app
        .binary_path
        .as_deref()
        .map(|p| {
            // Show only the filename, not the full path
            std::path::Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(p)
                .to_string()
        })
        .map(|name| format!("  ·  {}", name))
        .unwrap_or_default();

    let title = format!(
        " KaijuLab v{}  ·  {}{}",
        env!("CARGO_PKG_VERSION"),
        app.backend_name,
        binary,
    );

    f.render_widget(
        Paragraph::new(title).style(Style::new().fg(Color::Magenta).bold()),
        area,
    );
}

// ─── Tab bar ─────────────────────────────────────────────────────────────────

fn render_tabbar(f: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = TAB_NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let dirty = app.tab_dirty[i];
            let dot = if dirty { "● " } else { "" };
            Line::from(vec![
                Span::styled(
                    format!(" [{}] ", i + 1),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::raw(format!("{}{} ", dot, name)),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.active_tab as usize)
        .style(Style::new().fg(Color::DarkGray))
        .highlight_style(Style::new().fg(Color::Cyan).bold())
        .divider(Span::styled("│", Style::new().fg(Color::DarkGray)));

    f.render_widget(tabs, area);
}

// ─── Content area ────────────────────────────────────────────────────────────

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    match app.active_tab {
        Tab::Chat => render_chat(f, area, app),
        tab       => render_panel(f, area, app, tab),
    }
}

// ─ Chat panel ─────────────────────────────────────────────────────────────────

fn render_chat(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" Chat ", Style::new().fg(Color::Cyan).bold()))
        .border_style(Style::new().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Build styled lines from chat history
    let mut all_lines: Vec<Line> = Vec::new();

    for msg in &app.chat {
        match msg {
            ChatMsg::User(text) => {
                // "╭── You ──"
                all_lines.push(Line::from(vec![
                    Span::styled(" ╭── ", Style::new().fg(Color::DarkGray)),
                    Span::styled("You", Style::new().fg(Color::Cyan).bold()),
                    Span::styled(" ──", Style::new().fg(Color::DarkGray)),
                ]));
                for l in text.lines() {
                    all_lines.push(Line::from(vec![
                        Span::styled(" │  ", Style::new().fg(Color::DarkGray)),
                        Span::styled(l.to_string(), Style::new().fg(Color::White)),
                    ]));
                }
                all_lines.push(Line::raw(""));
            }

            ChatMsg::Assistant(text) => {
                all_lines.push(Line::from(vec![
                    Span::styled(" ╭── ", Style::new().fg(Color::DarkGray)),
                    Span::styled("KaijuLab", Style::new().fg(Color::Magenta).bold()),
                    Span::styled(" ──", Style::new().fg(Color::DarkGray)),
                ]));
                for l in text.lines() {
                    all_lines.push(Line::from(vec![
                        Span::styled(" │  ", Style::new().fg(Color::DarkGray)),
                        Span::raw(l.to_string()),
                    ]));
                }
                all_lines.push(Line::raw(""));
            }

            ChatMsg::ToolCall { name, args } => {
                all_lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled("⏺ ", Style::new().fg(Color::Cyan).bold()),
                    Span::styled(name.clone(), Style::new().fg(Color::Cyan).bold()),
                    Span::styled(format!("({})", args), Style::new().fg(Color::DarkGray)),
                ]));
            }

            ChatMsg::ToolResult { name, lines } => {
                let preview_n = 6.min(lines.len());
                let border_w =
                    inner.width.saturating_sub(4) as usize;
                let sep = "─".repeat(border_w.min(50));

                all_lines.push(Line::from(vec![
                    Span::styled(format!("  ┌{}┐", sep), Style::new().fg(Color::DarkGray)),
                ]));
                for l in lines.iter().take(preview_n) {
                    let display = if l.len() + 4 > border_w + 2 {
                        format!("{}…", &l[..l.len().min(border_w.saturating_sub(1))])
                    } else {
                        l.clone()
                    };
                    all_lines.push(Line::from(vec![
                        Span::styled("  │ ", Style::new().fg(Color::DarkGray)),
                        Span::raw(display),
                    ]));
                }
                if lines.len() > preview_n {
                    let tab_hint = Tab::from_tool(name)
                        .map(|t| format!(" → [{}] tab", TAB_NAMES[t as usize]))
                        .unwrap_or_default();
                    all_lines.push(Line::from(vec![
                        Span::styled("  │ ", Style::new().fg(Color::DarkGray)),
                        Span::styled(
                            format!("… {} more lines{}", lines.len() - preview_n, tab_hint),
                            Style::new().fg(Color::Yellow).italic(),
                        ),
                    ]));
                }
                all_lines.push(Line::from(vec![
                    Span::styled(format!("  └{}┘", sep), Style::new().fg(Color::DarkGray)),
                ]));
                all_lines.push(Line::raw(""));
            }

            ChatMsg::Error(e) => {
                all_lines.push(Line::from(vec![
                    Span::styled("  ✗ Error: ", Style::new().fg(Color::Red).bold()),
                    Span::styled(e.clone(), Style::new().fg(Color::Red)),
                ]));
                all_lines.push(Line::raw(""));
            }
        }
    }

    // Loading indicator
    if app.is_loading {
        all_lines.push(Line::from(vec![
            Span::styled("  ⠋ ", Style::new().fg(Color::Cyan)),
            Span::styled(app.status.clone(), Style::new().fg(Color::DarkGray).italic()),
        ]));
    }

    // Scroll: 0 = bottom. Positive = scrolled up.
    let total = all_lines.len() as u16;
    let visible = inner.height;
    let at_bottom = total.saturating_sub(visible);
    let scroll_up = app.scroll[Tab::Chat as usize];
    let from_top = at_bottom.saturating_sub(scroll_up);

    let text = Text::from(all_lines);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((from_top, 0)),
        inner,
    );
}

// ─ Dedicated panels (Functions / Disasm / Strings / Imports) ─────────────────

fn render_panel(f: &mut Frame, area: Rect, app: &App, tab: Tab) {
    let tab_name = TAB_NAMES[tab as usize];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            format!(" {} ", tab_name),
            Style::new().fg(Color::Cyan).bold(),
        ))
        .border_style(Style::new().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let raw = &app.tab_lines[tab as usize];

    if raw.is_empty() {
        let hint = match tab {
            Tab::Functions => "Say \"list all functions\" or \"what functions are in this binary?\"",
            Tab::Disasm    => "Say \"disassemble the entry point\" or \"show me the main function\"",
            Tab::Strings   => "Say \"extract strings\" or \"show strings in .rodata\"",
            Tab::Imports   => "Say \"what does this binary import?\" or \"resolve the PLT\"",
            Tab::Chat      => unreachable!(),
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("  (no data yet — {})", hint),
                Style::new().fg(Color::DarkGray).italic(),
            )),
            inner,
        );
        return;
    }

    let lines: Vec<Line> = match tab {
        Tab::Disasm    => raw.iter().map(|l| highlight_disasm(l)).collect(),
        Tab::Functions => raw.iter().map(|l| highlight_addr_table(l)).collect(),
        Tab::Imports   => raw.iter().map(|l| highlight_addr_table(l)).collect(),
        Tab::Strings   => raw.iter().map(|l| highlight_strings(l)).collect(),
        Tab::Chat      => unreachable!(),
    };

    let scroll = app.scroll[tab as usize];
    f.render_widget(
        Paragraph::new(Text::from(lines)).scroll((scroll, 0)),
        inner,
    );
}

// ─── Status bar ──────────────────────────────────────────────────────────────

fn render_statusbar(f: &mut Frame, area: Rect, app: &App) {
    let (icon, color) = if app.is_loading {
        ("⠋", Color::Cyan)
    } else if app.status.starts_with("Error") {
        ("✗", Color::Red)
    } else {
        ("●", Color::Green)
    };

    let keybinds = "Tab:next  1-5:tab  ↑↓:scroll  Ctrl+C:quit";
    let status = format!(" {} {}", icon, app.status);

    // Right-align the keybind hint
    let pad = area
        .width
        .saturating_sub(status.len() as u16 + keybinds.len() as u16 + 2);
    let line = Line::from(vec![
        Span::styled(format!(" {} ", icon), Style::new().fg(color)),
        Span::styled(app.status.clone(), Style::new().fg(Color::Gray)),
        Span::raw(" ".repeat(pad as usize)),
        Span::styled(keybinds, Style::new().fg(Color::DarkGray)),
        Span::raw(" "),
    ]);

    f.render_widget(Paragraph::new(line), area);
}

// ─── Input box ───────────────────────────────────────────────────────────────

fn render_input(f: &mut Frame, area: Rect, app: &App) {
    let (border_color, text_color) = if app.is_loading {
        (Color::DarkGray, Color::DarkGray)
    } else {
        (Color::Cyan, Color::White)
    };

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::new().fg(border_color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let display = if app.input.is_empty() && !app.is_loading {
        Span::styled(
            " Type a task and press Enter…",
            Style::new().fg(Color::DarkGray).italic(),
        )
    } else {
        Span::styled(
            format!(" {}", app.input),
            Style::new().fg(text_color),
        )
    };

    f.render_widget(Paragraph::new(display), inner);

    // Show cursor only when not loading
    if !app.is_loading {
        f.set_cursor_position(Position {
            x: inner.x + 1 + app.input_cursor as u16,
            y: inner.y,
        });
    }
}

// ─── Syntax highlighting ─────────────────────────────────────────────────────

/// Highlight a single disassembly line.
/// Expected format from our tool:
///   `  AAAAAAAAAAAAAAAA  BB BB BB…             MNEMONIC  OPERANDS`
/// where A = 16 hex address digits, B = instruction bytes (≤24 chars wide).
fn highlight_disasm(line: &str) -> Line<'static> {
    // Header / empty / error lines
    if line.trim().is_empty() {
        return Line::raw("");
    }
    if line.trim_start().starts_with("Disassembly") || line.trim_start().starts_with("Error:") {
        return Line::styled(line.to_string(), Style::new().fg(Color::DarkGray));
    }
    if line.trim_start().starts_with('…') {
        return Line::styled(line.to_string(), Style::new().fg(Color::Yellow));
    }

    // Must start with "  " then 16 hex chars
    if line.len() < 18 || &line[..2] != "  " {
        return Line::styled(line.to_string(), Style::new().fg(Color::DarkGray));
    }
    let addr_part = &line[2..18];
    if !addr_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Line::styled(line.to_string(), Style::new().fg(Color::DarkGray));
    }

    // After address: "  " then up to 24 chars of bytes, then "  " then mnemonic+operands
    let after_addr = &line[18..]; // starts with "  BYTES  MNEMONIC…"
    if after_addr.len() < 2 {
        return Line::from(vec![
            Span::raw("  "),
            Span::styled(addr_part.to_string(), Style::new().fg(Color::Yellow)),
        ]);
    }
    // Strip the leading "  "
    let after_sep = &after_addr[2..];

    // Bytes field is {:<24}, so take up to 24 chars, then skip "  "
    let bytes_field_end = 24.min(after_sep.len());
    let bytes_str = after_sep[..bytes_field_end].trim_end();
    let rest = if after_sep.len() > 26 {
        after_sep[26..].trim_start()
    } else {
        ""
    };

    // Split mnemonic from operands (mnemonic is first token)
    let (mnemonic, operands) = first_token(rest);

    let mut spans: Vec<Span> = vec![
        Span::raw("  "),
        Span::styled(addr_part.to_string(), Style::new().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(
            format!("{:<24}", bytes_str),
            Style::new().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled(mnemonic.to_string(), Style::new().fg(Color::Cyan).bold()),
    ];

    if !operands.is_empty() {
        spans.push(Span::raw("  "));
        spans.extend(highlight_operands(operands));
    }

    Line::from(spans)
}

/// Highlight a line of the form `  0x<addr>  <name>` (functions / PLT table).
fn highlight_addr_table(line: &str) -> Line<'static> {
    let t = line.trim_start_matches("  ");
    if t.starts_with("0x") {
        if let Some(sp) = t.find(|c: char| c.is_whitespace()) {
            let addr = &t[..sp];
            let name = t[sp..].trim_start();
            return Line::from(vec![
                Span::raw("  "),
                Span::styled(addr.to_string(), Style::new().fg(Color::Yellow)),
                Span::raw("  "),
                Span::styled(name.to_string(), Style::new().fg(Color::Green)),
            ]);
        }
    }
    Line::styled(line.to_string(), Style::new().fg(Color::DarkGray))
}

/// Highlight a strings-extract line of the form `  0x<offset>  <string>`.
fn highlight_strings(line: &str) -> Line<'static> {
    if line.starts_with("  0x") {
        if let Some(sp) = line[4..].find(|c: char| c.is_whitespace()) {
            let addr_end = 4 + sp;
            let offset = &line[2..addr_end];
            let s = line[addr_end..].trim_start();
            return Line::from(vec![
                Span::raw("  "),
                Span::styled(offset.to_string(), Style::new().fg(Color::Yellow).dim()),
                Span::raw("  "),
                Span::styled(s.to_string(), Style::new().fg(Color::LightGreen)),
            ]);
        }
    }
    Line::styled(line.to_string(), Style::new().fg(Color::DarkGray))
}

// ─── Operand tokenizer ───────────────────────────────────────────────────────

/// Known x86 / x86-64 registers (lowercase).
const X86_REGS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d",
    "ax",  "bx",  "cx",  "dx",  "si",  "di",  "bp",  "sp",
    "al",  "bl",  "cl",  "dl",  "sil", "dil", "bpl", "spl",
    "ah",  "bh",  "ch",  "dh",
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
    "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
    "cs", "ds", "es", "fs", "gs", "ss",
    "st0","st1","st2","st3","st4","st5","st6","st7",
];

const SIZE_KEYWORDS: &[&str] = &[
    "byte", "word", "dword", "qword", "xmmword", "ymmword", "ptr", "short", "near", "far",
];

fn is_register(s: &str) -> bool {
    X86_REGS.contains(&s.to_ascii_lowercase().as_str())
}

fn is_immediate(s: &str) -> bool {
    let s = s.trim_end_matches('h');
    s.starts_with("0x") || s.starts_with('-') || s.parse::<i64>().is_ok() || {
        // Hex without 0x prefix (iced-x86 uses uppercase H suffix, e.g. "0FFFFFFFFh")
        !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// Color each operand token in a comma-separated operand list.
fn highlight_operands(operands: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let parts: Vec<&str> = operands.split(", ").collect();

    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(", ", Style::new().fg(Color::DarkGray)));
        }

        let p = part.trim();
        let lower = p.to_ascii_lowercase();

        if is_register(p) {
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::Green)));
        } else if is_immediate(p) {
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::Magenta)));
        } else if p.contains('[') {
            // Memory reference, e.g. "qword ptr [rsp+10h]"
            spans.extend(highlight_mem_ref(p));
        } else if SIZE_KEYWORDS.contains(&lower.as_str()) {
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::DarkGray)));
        } else {
            // Labels / symbols / addresses
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::LightYellow)));
        }
    }
    spans
}

/// Color a memory reference like `qword ptr [rbp-8]`.
fn highlight_mem_ref(s: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    if let (Some(open), Some(close)) = (s.find('['), s.rfind(']')) {
        let prefix = s[..open].trim();
        let inner  = &s[open + 1..close];
        let suffix = s[close + 1..].trim();

        if !prefix.is_empty() {
            spans.push(Span::styled(format!("{} ", prefix), Style::new().fg(Color::DarkGray)));
        }
        spans.push(Span::styled("[", Style::new().fg(Color::White)));

        // Tokenise inner expression: register+immediate, e.g. "rbp-8" or "rip+0x12345"
        spans.extend(highlight_mem_inner(inner));

        spans.push(Span::styled("]", Style::new().fg(Color::White)));
        if !suffix.is_empty() {
            spans.push(Span::raw(suffix.to_string()));
        }
    } else {
        spans.push(Span::raw(s.to_string()));
    }
    spans
}

fn highlight_mem_inner(s: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    // Split on + and -, keeping the delimiter
    let mut cur = String::new();
    let mut delim = String::new();
    for ch in s.chars() {
        if (ch == '+' || ch == '-') && !cur.is_empty() {
            let token = cur.trim().to_string();
            if !delim.is_empty() {
                spans.push(Span::styled(delim.clone(), Style::new().fg(Color::DarkGray)));
                delim.clear();
            }
            if is_register(&token) {
                spans.push(Span::styled(token, Style::new().fg(Color::Green)));
            } else {
                spans.push(Span::styled(token, Style::new().fg(Color::Magenta)));
            }
            cur.clear();
            delim.push(ch);
        } else {
            cur.push(ch);
        }
    }
    if !delim.is_empty() {
        spans.push(Span::styled(delim, Style::new().fg(Color::DarkGray)));
    }
    if !cur.is_empty() {
        let token = cur.trim().to_string();
        if is_register(&token) {
            spans.push(Span::styled(token, Style::new().fg(Color::Green)));
        } else {
            spans.push(Span::styled(token, Style::new().fg(Color::Magenta)));
        }
    }
    spans
}

// ─── Small helpers ───────────────────────────────────────────────────────────

/// Split `"xor       ebp, ebp"` → `("xor", "ebp, ebp")`.
fn first_token(s: &str) -> (&str, &str) {
    let s = s.trim();
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None    => (s, ""),
    }
}
