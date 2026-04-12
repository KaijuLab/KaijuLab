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

const TAB_NAMES: &[&str] = &["Functions", "Disasm", "Decompile", "Strings", "Imports", "Chat", "Context"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Functions  = 0,
    Disasm     = 1,
    Decompile  = 2,
    Strings    = 3,
    Imports    = 4,
    Chat       = 5,
    Context    = 6,
}

impl Tab {
    fn from_index(n: usize) -> Option<Self> {
        match n {
            0 => Some(Tab::Functions),
            1 => Some(Tab::Disasm),
            2 => Some(Tab::Decompile),
            3 => Some(Tab::Strings),
            4 => Some(Tab::Imports),
            5 => Some(Tab::Chat),
            6 => Some(Tab::Context),
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
            "decompile"       => Some(Tab::Decompile),
            "strings_extract" => Some(Tab::Strings),
            "resolve_plt"     => Some(Tab::Imports),
            _ => None,
        }
    }
}

// ─── Navigation history ───────────────────────────────────────────────────────

/// A saved position in the TUI (tab + scroll offset).
#[derive(Clone, Debug)]
pub struct NavState {
    pub tab:    Tab,
    pub scroll: u16,
}

// ─── Bookmarks ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Bookmark {
    pub vaddr: u64,
    pub label: String,
}

// ─── Popup overlay ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum Popup {
    /// Session bookmarks list.
    Bookmarks,
    /// Cross-references to an address (lines from xrefs_to).
    Xref { title: String, lines: Vec<String> },
}

// ─── Context entries (mirrors agent::ContextEntry) ────────────────────────────

#[derive(Clone, Debug)]
pub struct ContextEntry {
    pub role: String,
    pub kind: String,
    pub tool_name: Option<String>,
    pub char_count: usize,
    pub preview: String,
}

// ─── Chat messages ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub enum ChatMsg {
    Welcome,
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
    pub tab_lines: [Vec<String>; 7],
    /// Whether each tab has unseen content (shows a dot indicator).
    pub tab_dirty: [bool; 7],
    pub chat: Vec<ChatMsg>,
    /// Scroll offsets for each tab (lines from top for panels; lines from bottom for chat).
    pub scroll: [u16; 7],
    pub input: String,
    pub input_cursor: usize,
    pub status: String,
    pub is_loading: bool,
    pub backend_name: String,
    pub binary_path: Option<String>,
    pub should_quit: bool,
    /// The virtual address the agent is currently analysing (drives active highlighting).
    pub focused_addr: Option<u64>,
    /// Live snapshot of the LLM context window.
    pub context_entries: Vec<ContextEntry>,
    /// Messages the user has sent (most recent last), for ↑↓ history navigation.
    pub input_history: Vec<String>,
    /// Current position in `input_history` while navigating; `None` when at the live input.
    pub history_cursor: Option<usize>,
    /// Saved live input while the user is browsing history.
    pub input_saved: String,
    /// fn_vaddr → vulnerability score (0–10), drives [!] / [!!] badges.
    pub fn_vuln_scores: std::collections::HashMap<u64, u8>,
    /// Active search pattern (set by `/pattern` command).
    pub search_pattern: Option<String>,
    /// Which match we are currently sitting on (0-based index into matches list).
    pub search_hit_idx: usize,
    /// Back-navigation stack (positions we can return to with `[`).
    pub nav_back: Vec<NavState>,
    /// Forward-navigation stack (positions we can revisit with `]`).
    pub nav_forward: Vec<NavState>,
    /// Line cursor position in each panel (0-based line index).
    pub panel_cursor: [usize; 7],
    /// Session bookmarks (vaddr + user label).
    pub bookmarks: Vec<Bookmark>,
    /// Active popup overlay, if any.
    pub popup: Option<Popup>,
    /// Detected binary architecture string (e.g. "x86_64", "aarch64").
    pub binary_arch: Option<String>,
}


impl App {
    pub fn new(backend_name: String) -> Self {
        let mut app = App {
            active_tab: Tab::Chat,
            tab_lines: Default::default(),
            tab_dirty: [false; 7],
            chat: Vec::new(),
            scroll: {
                // Start the chat panel scrolled all the way to the top so the
                // welcome logo is the first thing the user sees.  Any incoming
                // agent event resets this to 0 (scroll-to-bottom) automatically.
                let mut s = [0u16; 7];
                s[Tab::Chat as usize] = u16::MAX;
                s
            },
            input: String::new(),
            input_cursor: 0,
            status: "Ready — type a task and press Enter".to_string(),
            is_loading: false,
            backend_name,
            binary_path: None,
            should_quit: false,
            focused_addr: None,
            context_entries: Vec::new(),
            input_history: Vec::new(),
            history_cursor: None,
            input_saved: String::new(),
            fn_vuln_scores: std::collections::HashMap::new(),
            search_pattern: None,
            search_hit_idx: 0,
            nav_back: Vec::new(),
            nav_forward: Vec::new(),
            panel_cursor: [0usize; 7],
            bookmarks: Vec::new(),
            popup: None,
            binary_arch: None,
        };
        app.chat.push(ChatMsg::Welcome);
        app
    }

    // ─── Navigation helpers ──────────────────────────────────────────────────

    /// Save the current position onto the back-stack before jumping elsewhere.
    fn nav_push(&mut self) {
        let state = NavState {
            tab:    self.active_tab,
            scroll: self.scroll[self.active_tab as usize],
        };
        self.nav_back.push(state);
        self.nav_forward.clear(); // branching clears forward history
    }

    /// Jump back one step in navigation history.
    fn nav_go_back(&mut self) {
        if let Some(prev) = self.nav_back.pop() {
            let current = NavState {
                tab:    self.active_tab,
                scroll: self.scroll[self.active_tab as usize],
            };
            self.nav_forward.push(current);
            self.active_tab = prev.tab;
            self.scroll[prev.tab as usize] = prev.scroll;
            self.tab_dirty[prev.tab as usize] = false;
            self.status = format!("← back to {:?}", prev.tab);
        } else {
            self.status = "Already at earliest position".to_string();
        }
    }

    /// Jump forward one step in navigation history.
    fn nav_go_forward(&mut self) {
        if let Some(next) = self.nav_forward.pop() {
            let current = NavState {
                tab:    self.active_tab,
                scroll: self.scroll[self.active_tab as usize],
            };
            self.nav_back.push(current);
            self.active_tab = next.tab;
            self.scroll[next.tab as usize] = next.scroll;
            self.tab_dirty[next.tab as usize] = false;
            self.status = format!("→ forward to {:?}", next.tab);
        } else {
            self.status = "Already at latest position".to_string();
        }
    }

    // ─── Panel cursor helpers ────────────────────────────────────────────────

    /// Move the line cursor in the active panel by `delta` (clamped to bounds).
    fn move_panel_cursor(&mut self, delta: i32) {
        let tab = self.active_tab;
        if matches!(tab, Tab::Chat | Tab::Context) { return; }
        let len = self.tab_lines[tab as usize].len();
        if len == 0 { return; }
        let cur = self.panel_cursor[tab as usize] as i32;
        let new = (cur + delta).clamp(0, (len as i32) - 1) as usize;
        self.panel_cursor[tab as usize] = new;
        // Scroll the panel to keep the cursor visible
        let scroll = &mut self.scroll[tab as usize];
        // scroll is "lines from bottom"; we need the line visible in the window.
        // Convert: visible_line = total - scroll - visible_height
        // Simple heuristic: ensure scroll puts cursor near the middle.
        let total = len as u16;
        let cur16 = new as u16;
        // from_bottom = total - cursor - 1 (cursor at very bottom)
        // Clamp so cursor stays in view: if cursor > total - scroll, shrink scroll
        let from_bottom = total.saturating_sub(cur16 + 3);
        *scroll = (*scroll).min(from_bottom); // don't let cursor go above visible area
        if total.saturating_sub(*scroll) <= cur16 {
            *scroll = from_bottom; // scroll up to show cursor
        }
    }

    /// Extract a virtual address from the line at the current panel cursor, if any.
    fn addr_at_cursor(&self) -> Option<u64> {
        let tab = self.active_tab;
        if matches!(tab, Tab::Chat | Tab::Context) { return None; }
        let line = self.tab_lines[tab as usize].get(self.panel_cursor[tab as usize])?;
        // Try to parse the first hex token that looks like an address.
        for token in line.split_whitespace() {
            let stripped = token.trim_start_matches("0x").trim_start_matches("0X");
            if stripped.len() >= 4 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(addr) = u64::from_str_radix(stripped, 16) {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Bookmark the currently focused address (or cursor address).
    fn bookmark_current(&mut self) {
        let vaddr = self.focused_addr.or_else(|| self.addr_at_cursor());
        if let Some(addr) = vaddr {
            // Avoid duplicates
            if self.bookmarks.iter().any(|b| b.vaddr == addr) {
                self.status = format!("Already bookmarked: 0x{:x}", addr);
                return;
            }
            let label = format!("0x{:x}", addr);
            self.bookmarks.push(Bookmark { vaddr: addr, label });
            self.status = format!("Bookmarked 0x{:x} ({} total)", addr, self.bookmarks.len());
        } else {
            self.status = "No address to bookmark — navigate to an address first".to_string();
        }
    }

    /// Jump to a bookmarked address by index.
    fn jump_to_bookmark(&mut self, idx: usize) {
        if let Some(bm) = self.bookmarks.get(idx).cloned() {
            self.nav_push();
            self.goto_address(bm.vaddr);
            self.popup = None;
        }
    }

    /// Trigger an xref popup for the address at the current cursor / focused addr.
    fn show_xref_popup(&mut self) {
        let vaddr = self.addr_at_cursor().or(self.focused_addr);
        if let Some(addr) = vaddr {
            let args = serde_json::json!({ "vaddr": addr });
            let result = crate::tools::dispatch("xrefs_to", &args);
            let lines: Vec<String> = result.output.lines().map(|l| l.to_string()).collect();
            self.popup = Some(Popup::Xref {
                title: format!("XRefs to 0x{:x}", addr),
                lines,
            });
        } else {
            self.status = "No address at cursor — navigate to an address first".to_string();
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
                    self.tab_lines[tab as usize] = lines.clone();
                    self.scroll[tab as usize] = 0;
                    self.panel_cursor[tab as usize] = 0;
                    self.tab_dirty[tab as usize] = true;
                }
                // Sniff architecture from file_info output
                if name == "file_info" {
                    for line in &lines {
                        let l = line.to_lowercase();
                        if l.contains("x86_64") || l.contains("amd64") || l.contains("x86-64") {
                            self.binary_arch = Some("x86_64".to_string());
                        } else if l.contains("aarch64") || l.contains("arm64") {
                            self.binary_arch = Some("aarch64".to_string());
                        } else if l.contains("arm") {
                            self.binary_arch = Some("arm".to_string());
                        } else if l.contains("mips") {
                            self.binary_arch = Some("mips".to_string());
                        } else if l.contains("riscv") || l.contains("risc-v") {
                            self.binary_arch = Some("riscv".to_string());
                        }
                    }
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

            AgentEvent::Focus { vaddr, tool } => {
                self.focused_addr = Some(vaddr);
                self.status = format!("● Analysing 0x{:x} ({})", vaddr, tool);
                // Auto-switch to and scroll the relevant tab
                let focus_tab = match tool.as_str() {
                    "decompile" => Tab::Decompile,
                    "disassemble" => Tab::Disasm,
                    _ => return, // other tools don't have a dedicated panel to scroll
                };
                // Auto-scroll to the focused address in the relevant panel
                if let Some(line_idx) = self.find_addr_line(focus_tab, vaddr) {
                    self.scroll[focus_tab as usize] = 0; // reset first
                    // Scroll so the line is near the top (offset from bottom of content)
                    let total = self.tab_lines[focus_tab as usize].len() as u16;
                    let from_bottom = total.saturating_sub(line_idx as u16 + 3);
                    self.scroll[focus_tab as usize] = from_bottom;
                }
                self.tab_dirty[focus_tab as usize] = true;
            }

            AgentEvent::ContextUpdate(entries) => {
                // Convert agent::ContextEntry → tui::ContextEntry
                self.context_entries = entries
                    .into_iter()
                    .map(|e| ContextEntry {
                        role: e.role.to_string(),
                        kind: e.kind.to_string(),
                        tool_name: e.tool_name,
                        char_count: e.char_count,
                        preview: e.preview,
                    })
                    .collect();
                self.tab_dirty[Tab::Context as usize] = true;
            }

            AgentEvent::VulnScores(scores) => {
                self.fn_vuln_scores.extend(scores);
                // Re-mark Functions tab dirty so badges render immediately
                self.tab_dirty[Tab::Functions as usize] = true;
            }
        }
    }

    /// Find the line index in a tab's content that displays a given virtual address.
    fn find_addr_line(&self, tab: Tab, vaddr: u64) -> Option<usize> {
        let target = format!("{:016x}", vaddr);
        self.tab_lines[tab as usize]
            .iter()
            .position(|line| line.contains(&target))
    }

    /// Scroll the active (or best-fit) panel to the given virtual address.
    pub fn goto_address(&mut self, addr: u64) {
        let hex16 = format!("{:016x}", addr);
        let hex_short = format!("{:x}", addr);

        // Prefer current tab if it's a panel, else try Disasm first
        let panel_order: &[Tab] = &[
            self.active_tab,
            Tab::Disasm, Tab::Decompile, Tab::Functions, Tab::Strings, Tab::Imports,
        ];
        for &tab in panel_order {
            if matches!(tab, Tab::Chat | Tab::Context) { continue; }
            let found = self.tab_lines[tab as usize]
                .iter()
                .position(|l| l.contains(&hex16) || l.to_lowercase().contains(&hex_short));
            if let Some(idx) = found {
                self.active_tab = tab;
                self.tab_dirty[tab as usize] = false;
                let total = self.tab_lines[tab as usize].len() as u16;
                self.scroll[tab as usize] = total.saturating_sub(idx as u16 + 3);
                self.status = format!("Jumped to 0x{:x}", addr);
                return;
            }
        }
        self.status = format!("0x{:x} not found in any panel — ask the agent to disassemble it first", addr);
    }

    /// Collect matching line indices in the active panel for the current search pattern.
    fn search_matches(&self) -> Vec<usize> {
        let pattern = match &self.search_pattern {
            Some(p) if !p.is_empty() => p.to_lowercase(),
            _ => return Vec::new(),
        };
        let tab = self.active_tab;
        if matches!(tab, Tab::Chat | Tab::Context) { return Vec::new(); }
        self.tab_lines[tab as usize]
            .iter()
            .enumerate()
            .filter(|(_, l)| l.to_lowercase().contains(&pattern))
            .map(|(i, _)| i)
            .collect()
    }

    /// Start a search and scroll to the first match.
    pub fn search_panel(&mut self, pattern: &str) {
        self.search_pattern = if pattern.is_empty() { None } else { Some(pattern.to_string()) };
        self.search_hit_idx = 0;
        self.scroll_to_search_hit();
    }

    /// Advance to the next (or previous) search match and scroll to it.
    pub fn search_next(&mut self, forward: bool) {
        let matches = self.search_matches();
        if matches.is_empty() {
            self.status = format!(
                "'{}' not found",
                self.search_pattern.as_deref().unwrap_or("")
            );
            return;
        }
        let n = matches.len();
        self.search_hit_idx = if forward {
            (self.search_hit_idx + 1) % n
        } else {
            self.search_hit_idx.checked_sub(1).unwrap_or(n - 1)
        };
        self.scroll_to_search_hit();
    }

    /// Copy `text` to the system clipboard; update status with result.
    fn copy_to_clipboard(&mut self, text: String) {
        if text.is_empty() {
            self.status = "Nothing to copy — panel is empty".to_string();
            return;
        }
        let line_count = text.lines().count();
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(text)) {
            Ok(_)  => self.status = format!("Copied {} lines to clipboard", line_count),
            Err(e) => self.status = format!("Clipboard error: {}", e),
        }
    }

    /// Build a plain-text copy of the active tab's content.
    fn copyable_content(&self) -> String {
        match self.active_tab {
            Tab::Chat => {
                // Copy the last assistant text response
                self.chat.iter().rev().find_map(|m| {
                    if let ChatMsg::Assistant(t) = m { Some(t.clone()) } else { None }
                }).unwrap_or_default()
            }
            Tab::Context => {
                // Render context entries as plain text
                self.context_entries.iter().map(|e| {
                    format!("{:<9}  {:<10}  {:>6}c  {}{}",
                        e.role, e.kind, e.char_count,
                        e.tool_name.as_deref().map(|n| format!("[{}] ", n)).unwrap_or_default(),
                        e.preview)
                }).collect::<Vec<_>>().join("\n")
            }
            tab => self.tab_lines[tab as usize].join("\n"),
        }
    }

    fn scroll_to_search_hit(&mut self) {
        let matches = self.search_matches();
        if matches.is_empty() {
            self.status = format!(
                "'{}' not found in this panel",
                self.search_pattern.as_deref().unwrap_or("")
            );
            return;
        }
        let idx = self.search_hit_idx % matches.len();
        let line_idx = matches[idx];
        let tab = self.active_tab;
        let total = self.tab_lines[tab as usize].len() as u16;
        self.scroll[tab as usize] = total.saturating_sub(line_idx as u16 + 3);
        self.status = format!(
            "Search '{}': match {} / {}",
            self.search_pattern.as_deref().unwrap_or(""),
            idx + 1, matches.len()
        );
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
            KeyCode::Char(c @ '1'..='7') if self.input.is_empty() && key.modifiers.is_empty() => {
                let idx = (c as usize) - ('1' as usize);
                if let Some(t) = Tab::from_index(idx) {
                    self.active_tab = t;
                    self.tab_dirty[t as usize] = false;
                }
                None
            }

            // g — prefill goto prompt when input is empty
            KeyCode::Char('g') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.input = "g ".to_string();
                self.input_cursor = 2;
                None
            }

            // / — prefill search prompt when input is empty
            KeyCode::Char('/') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.input = "/".to_string();
                self.input_cursor = 1;
                None
            }

            // n / N — search next / previous when search is active and input is empty
            KeyCode::Char('n') if self.input.is_empty() && key.modifiers.is_empty()
                && self.search_pattern.is_some() => {
                self.search_next(true);
                None
            }
            KeyCode::Char('N') if self.input.is_empty()
                && key.modifiers.contains(KeyModifiers::SHIFT)
                && self.search_pattern.is_some() => {
                self.search_next(false);
                None
            }

            // Esc — dismiss popup first, then clear search
            KeyCode::Esc if self.popup.is_some() => {
                self.popup = None;
                self.status = "Popup closed".to_string();
                None
            }
            KeyCode::Esc if self.search_pattern.is_some() => {
                self.search_pattern = None;
                self.status = "Search cleared".to_string();
                None
            }

            // y — copy active panel content to system clipboard
            KeyCode::Char('y') if self.input.is_empty() && key.modifiers.is_empty() => {
                let text = self.copyable_content();
                self.copy_to_clipboard(text);
                None
            }

            // [ / ] — back / forward navigation
            KeyCode::Char('[') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.nav_go_back();
                None
            }
            KeyCode::Char(']') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.nav_go_forward();
                None
            }

            // j / k — line cursor down / up in panels
            KeyCode::Char('j') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.move_panel_cursor(1);
                None
            }
            KeyCode::Char('k') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.move_panel_cursor(-1);
                None
            }

            // m — bookmark current address
            KeyCode::Char('m') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.bookmark_current();
                None
            }
            // B — toggle bookmark list popup
            KeyCode::Char('B') if self.input.is_empty()
                && key.modifiers.contains(KeyModifiers::SHIFT) => {
                if matches!(self.popup, Some(Popup::Bookmarks)) {
                    self.popup = None;
                } else {
                    self.popup = Some(Popup::Bookmarks);
                }
                None
            }

            // x — xref popup for address at cursor / focused addr
            KeyCode::Char('x') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.show_xref_popup();
                None
            }

            // 0-9 in bookmark popup — jump to bookmark by index
            KeyCode::Char(c @ '0'..='9')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.popup, Some(Popup::Bookmarks)) =>
            {
                let idx = (c as usize) - ('0' as usize);
                self.jump_to_bookmark(idx);
                None
            }

            // ↑↓ — command history navigation
            KeyCode::Up => {
                if self.input_history.is_empty() {
                    return None;
                }
                let new_cursor = match self.history_cursor {
                    None => {
                        self.input_saved = self.input.clone();
                        self.input_history.len() - 1
                    }
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i, // already at oldest entry
                };
                self.history_cursor = Some(new_cursor);
                self.input = self.input_history[new_cursor].clone();
                self.input_cursor = self.input.len();
                None
            }
            KeyCode::Down => {
                match self.history_cursor {
                    None => {} // not in history mode
                    Some(i) if i + 1 < self.input_history.len() => {
                        let next = i + 1;
                        self.history_cursor = Some(next);
                        self.input = self.input_history[next].clone();
                        self.input_cursor = self.input.len();
                    }
                    Some(_) => {
                        // Past the newest entry — return to live input
                        self.history_cursor = None;
                        self.input = self.input_saved.clone();
                        self.input_cursor = self.input.len();
                    }
                }
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

            // Submit / go-to-definition
            KeyCode::Enter => {
                // Go-to-definition: Enter with empty input while cursor is in a panel
                if self.input.is_empty()
                    && !matches!(self.active_tab, Tab::Chat | Tab::Context)
                {
                    if let Some(addr) = self.addr_at_cursor() {
                        self.nav_push();
                        self.goto_address(addr);
                        return None;
                    }
                    return None;
                }
                // Bookmark popup: Enter selects bookmark at cursor line
                if self.input.is_empty() {
                    if let Some(Popup::Bookmarks) = &self.popup {
                        let idx = self.panel_cursor[self.active_tab as usize];
                        self.jump_to_bookmark(idx);
                        return None;
                    }
                }

                let msg = self.input.trim().to_string();
                if msg.is_empty() {
                    return None;
                }

                // ── Local TUI commands (never sent to LLM) ──────────────────
                // goto: "g 0x401234" or "goto 0x401234"
                let goto_arg = msg.strip_prefix("g ")
                    .or_else(|| msg.strip_prefix("goto "));
                if let Some(addr_str) = goto_arg {
                    if let Some(addr) = parse_addr(addr_str.trim()) {
                        self.goto_address(addr);
                    } else {
                        self.status = format!("Cannot parse address: '{}'", addr_str.trim());
                    }
                    self.input.clear();
                    self.input_cursor = 0;
                    self.history_cursor = None;
                    return None;
                }
                // search: "/pattern"
                if let Some(pattern) = msg.strip_prefix('/') {
                    self.search_panel(pattern.trim());
                    self.input.clear();
                    self.input_cursor = 0;
                    self.history_cursor = None;
                    return None;
                }

                if self.is_loading {
                    return None;
                }

                // Record in history (skip consecutive duplicates)
                if self.input_history.last().map_or(true, |last| last != &msg) {
                    self.input_history.push(msg.clone());
                }
                self.history_cursor = None;
                self.input_saved = String::new();
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
                    // Step back to the previous char boundary
                    let prev = self.input[..self.input_cursor]
                        .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                    self.input.remove(prev);
                    self.input_cursor = prev;
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
                if self.input_cursor > 0 {
                    self.input_cursor = self.input[..self.input_cursor]
                        .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                }
                None
            }
            KeyCode::Right => {
                if self.input_cursor < self.input.len() {
                    if let Some(ch) = self.input[self.input_cursor..].chars().next() {
                        self.input_cursor += ch.len_utf8();
                    }
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
                // Typing a character exits history-navigation mode
                self.history_cursor = None;
                self.input_saved = String::new();
                self.input.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
                None
            }
            _ => None,
        }
    }

}

// ─── Address parser ──────────────────────────────────────────────────────────

/// Parse a user-supplied address string. Accepts "0x…" hex, plain hex, or decimal.
fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 4 {
        // looks like a bare hex address (e.g. 401234)
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub async fn run_tui(
    mut event_rx: mpsc::UnboundedReceiver<AgentEvent>,
    user_tx: mpsc::Sender<String>,
    backend_name: &str,
    initial_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
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
    terminal.draw(|f| render(f, &mut app))?;

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

        terminal.draw(|f| render(f, &mut app))?;

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

fn render(f: &mut Frame, app: &mut App) {
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
    // Popup overlay (drawn on top of everything)
    if app.popup.is_some() {
        render_popup(f, area, app);
    }
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

fn render_content(f: &mut Frame, area: Rect, app: &mut App) {
    match app.active_tab {
        Tab::Chat    => render_chat(f, area, app),
        Tab::Context => render_context(f, area, app),
        tab          => render_panel(f, area, app, tab),
    }
}

// ─── Welcome screen lines ────────────────────────────────────────────────────
//
// Structure (top → bottom):  commands reference  ·  robot art  ·  title/hint
// The chat panel scrolls to the BOTTOM on load, so the robot + title are
// visible immediately; users scroll up to see the full command reference.

fn welcome_lines() -> Vec<Line<'static>> {
    use ratatui::style::Modifier;

    // ── Palette ───────────────────────────────────────────────────────────────
    let cyb = Style::new().fg(Color::Cyan).bold();
    let yeb = Style::new().fg(Color::Yellow).bold();
    let grb = Style::new().fg(Color::Green).bold();
    let mgb = Style::new().fg(Color::Magenta).bold();
    let mg  = Style::new().fg(Color::Magenta);
    let wh  = Style::new().fg(Color::White);
    let gy  = Style::new().fg(Color::Gray);
    let dg  = Style::new().fg(Color::DarkGray);
    let it  = Style::new().fg(Color::Gray).add_modifier(Modifier::ITALIC);

    let blank = || Line::raw("");
    let div   = || Line::from(Span::styled(
        "  ────────────────────────────────────────────────────────",
        dg,
    ));
    let sec = |s: &'static str| Line::from(vec![
        Span::raw("  "),
        Span::styled(s, yeb),
    ]);
    let kb = |key: &'static str, desc: &'static str| Line::from(vec![
        Span::raw("    "),
        Span::styled(key,  cyb),
        Span::raw("  "),
        Span::styled(desc, wh),
    ]);
    let cmd = |name: &'static str, args: &'static str, desc: &'static str| Line::from(vec![
        Span::raw("    "),
        Span::styled(name, grb),
        Span::raw(" "),
        Span::styled(args, gy),
        Span::raw("  "),
        Span::styled(desc, gy),
    ]);

    // ── Pixel-art logo ────────────────────────────────────────────────────────
    // Colors:
    //   ██ blocks   → magenta bold
    //   ▀  (eyes)   → yellow bold  (upper-half block = "pupils")
    //   ▄  (mouth)  → yellow bold  (lower-half block = "smile")
    let lo = |parts: Vec<(&'static str, Style)>| {
        Line::from(parts.into_iter().map(|(s, st)| Span::styled(s, st)).collect::<Vec<_>>())
    };

    let lines: Vec<Line<'static>> = vec![
        blank(),
        lo(vec![("       ██   ██                 ", mgb)]),
        lo(vec![("    ███████████                ", mgb)]),
        lo(vec![("████ ", mgb), ("▀", yeb), ("   ", mgb), ("▀", yeb), (" ███████           ", mgb)]),
        lo(vec![("████   ", mgb), ("▄", yeb), ("   ███████████          ", mgb)]),
        lo(vec![("██████████████████████         ", mgb)]),
        lo(vec![("   ███████████████████         ", mgb)]),
        lo(vec![("       █████████████           ", mgb)]),
        lo(vec![("           ██████              ", mgb)]),
        blank(),
        // Title
        Line::from(vec![
            Span::styled("  KaijuLab ", mgb),
            Span::styled(concat!("v", env!("CARGO_PKG_VERSION")), mg),
            Span::styled("  ·  AI-powered reverse engineering", dg),
        ]),
        blank(),
        // AI prompt hints
        Line::from(vec![
            Span::styled("  Ask: ", yeb),
            Span::styled("\"Analyse /path/to/binary and tell me what it does\"", it),
        ]),
        Line::from(vec![
            Span::raw("       "),
            Span::styled("\"What does function 0x401234 do? Is it vulnerable?\"", it),
        ]),
        blank(),
        // Scroll-down hint
        Line::from(vec![
            Span::styled("  ↓ scroll down for the full command reference  ·  type  ", dg),
            Span::styled("help", grb),
            Span::styled("  for all commands", dg),
        ]),
        blank(),
        div(),
        blank(),
        // ── Commands reference ────────────────────────────────────────────────
        sec("Quick Commands  (type in the input box, no AI needed)"),
        div(),
        cmd("help",      "",                      "Full command list"),
        cmd("entropy",   "<path>",                "Section entropy  ·  detect packers & crypto"),
        cmd("search",    "<path> <hex…>",         "Byte-pattern search  (e.g. E8 ?? ?? ?? ??)"),
        cmd("patch",     "<path> <vaddr> <hex>",  "Patch bytes  →  writes  <file>.patched"),
        cmd("disasm",    "<path> [vaddr]",         "Disassemble at address"),
        cmd("functions", "<path>",                "List all functions"),
        cmd("decompile", "<path> [vaddr]",         "Decompile a function"),
        cmd("imports",   "<path>",                "Resolve PLT / PE imports"),
        cmd("scan",      "<path>",                "Vulnerability scan"),
        cmd("auto",      "<path>",                "Full auto-analysis pass"),
        cmd("diff",      "<a> <b>",               "Diff two binaries by content"),
        cmd("report",    "<path>",                "Export HTML analysis report"),
        cmd("cfg",       "<path> <vaddr>",         "Control-flow graph for a function"),
        cmd("callgraph", "<path>",                "Full call graph"),
        blank(),
        sec("TUI Shortcuts  (when the input field is empty)"),
        div(),
        kb("g 0xADDR",   "Jump to address in current panel"),
        kb("/pattern",   "Search panel  ·  n = next  ·  N = prev  ·  Esc = clear"),
        kb("y",          "Copy panel content to system clipboard"),
        kb("1 – 7",      "Switch tab directly"),
        kb("Tab",        "Cycle to next tab"),
        kb("↑  ↓",       "Browse sent-message history"),
        kb("PgUp  PgDn", "Scroll active panel  ·  drag to select text"),
        kb("j  k",       "Move line cursor in panel"),
        kb("Enter",      "Go-to-definition for address at cursor line"),
        kb("[  ]",       "Navigate back / forward (address history)"),
        kb("m",          "Bookmark current address"),
        kb("B",          "Open bookmarks popup  (0-9 to jump · Esc to close)"),
        kb("x",          "Xref popup — callers of address at cursor"),
        kb("Ctrl+C",     "Clear input  ·  quit when input is empty"),
        blank(),
    ];

    lines
}

// ─ Chat panel ─────────────────────────────────────────────────────────────────

fn render_chat(f: &mut Frame, area: Rect, app: &mut App) {
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
            ChatMsg::Welcome => {
                all_lines.extend(welcome_lines());
                all_lines.push(Line::raw(""));
            }

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
                    let display = if l.chars().count() + 4 > border_w + 2 {
                        let limit = border_w.saturating_sub(1);
                        let truncated: String = l.chars().take(limit).collect();
                        format!("{}…", truncated)
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
    // Clamp stored scroll to the real maximum so PgDn/mouse-scroll work
    // immediately even when the initial value was set to u16::MAX.
    app.scroll[Tab::Chat as usize] = app.scroll[Tab::Chat as usize].min(at_bottom);
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
            Tab::Decompile => "Say \"decompile 0x<addr>\" or \"decompile the main function\"",
            Tab::Strings   => "Say \"extract strings\" or \"show strings in .rodata\"",
            Tab::Imports   => "Say \"what does this binary import?\" or \"resolve the PLT\"",
            Tab::Chat | Tab::Context => "",
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

    // Pre-compute focused address string for highlight matching (Disasm only)
    let focused_hex = if tab == Tab::Disasm {
        app.focused_addr.map(|a| format!("{:016x}", a))
    } else {
        None
    };

    // Search-match set for this tab
    let search_lower = app.search_pattern.as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| p.to_lowercase());

    let lines: Vec<Line> = match tab {
        Tab::Disasm => raw
            .iter()
            .map(|l| {
                let line = highlight_disasm(l);
                let line = if focused_hex.as_deref().map_or(false, |h| l.contains(h)) {
                    apply_focus_highlight(line)
                } else {
                    line
                };
                if search_lower.as_deref().map_or(false, |p| l.to_lowercase().contains(p)) {
                    apply_search_highlight(line)
                } else {
                    line
                }
            })
            .collect(),
        Tab::Functions => raw
            .iter()
            .map(|l| {
                let line = highlight_fn_line(l, &app.fn_vuln_scores);
                if search_lower.as_deref().map_or(false, |p| l.to_lowercase().contains(p)) {
                    apply_search_highlight(line)
                } else {
                    line
                }
            })
            .collect(),
        Tab::Imports => raw.iter().map(|l| {
            let line = highlight_addr_table(l);
            if search_lower.as_deref().map_or(false, |p| l.to_lowercase().contains(p)) {
                apply_search_highlight(line)
            } else { line }
        }).collect(),
        Tab::Strings => raw.iter().map(|l| {
            let line = highlight_strings(l);
            if search_lower.as_deref().map_or(false, |p| l.to_lowercase().contains(p)) {
                apply_search_highlight(line)
            } else { line }
        }).collect(),
        Tab::Decompile => raw.iter().map(|l| {
            let line = highlight_decompile(l);
            if search_lower.as_deref().map_or(false, |p| l.to_lowercase().contains(p)) {
                apply_search_highlight(line)
            } else { line }
        }).collect(),
        Tab::Chat | Tab::Context => raw.iter().map(|l| Line::raw(l.clone())).collect(),
    };

    // Apply cursor highlight to the panel cursor line
    let cursor_idx = app.panel_cursor[tab as usize];
    let lines: Vec<Line> = lines
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            if i == cursor_idx {
                let spans: Vec<Span<'static>> = line
                    .spans
                    .into_iter()
                    .map(|s| Span::styled(s.content, s.style.bg(Color::Rgb(40, 40, 80)).fg(Color::White)))
                    .collect();
                Line::from(spans)
            } else {
                line
            }
        })
        .collect();

    let scroll = app.scroll[tab as usize];
    f.render_widget(
        Paragraph::new(Text::from(lines)).scroll((scroll, 0)),
        inner,
    );
}

// ─── Popup overlay ────────────────────────────────────────────────────────────

fn render_popup(f: &mut Frame, area: Rect, app: &App) {
    use ratatui::layout::Alignment;

    let popup = match &app.popup {
        Some(p) => p,
        None => return,
    };

    // Centre a box: 70% wide, 60% tall
    let pw = (area.width * 7 / 10).max(40).min(area.width.saturating_sub(4));
    let ph = (area.height * 6 / 10).max(10).min(area.height.saturating_sub(4));
    let px = area.x + (area.width.saturating_sub(pw)) / 2;
    let py = area.y + (area.height.saturating_sub(ph)) / 2;
    let popup_area = Rect { x: px, y: py, width: pw, height: ph };

    // Clear background under popup
    f.render_widget(ratatui::widgets::Clear, popup_area);

    match popup {
        Popup::Bookmarks => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " Bookmarks  (0-9 to jump · Esc to close) ",
                    Style::new().fg(Color::Yellow).bold(),
                ))
                .border_style(Style::new().fg(Color::Yellow));
            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            if app.bookmarks.is_empty() {
                f.render_widget(
                    Paragraph::new(Span::styled(
                        "  (no bookmarks yet — press m to bookmark an address)",
                        Style::new().fg(Color::DarkGray).italic(),
                    )),
                    inner,
                );
                return;
            }

            let lines: Vec<Line> = app.bookmarks
                .iter()
                .enumerate()
                .map(|(i, bm)| {
                    Line::from(vec![
                        Span::styled(
                            format!("  [{}]  ", i),
                            Style::new().fg(Color::Yellow).bold(),
                        ),
                        Span::styled(bm.label.clone(), Style::new().fg(Color::White)),
                    ])
                })
                .collect();

            f.render_widget(
                Paragraph::new(Text::from(lines)).alignment(Alignment::Left),
                inner,
            );
        }

        Popup::Xref { title, lines } => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" {} (Esc to close) ", title),
                    Style::new().fg(Color::Cyan).bold(),
                ))
                .border_style(Style::new().fg(Color::Cyan));
            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            if lines.is_empty() {
                f.render_widget(
                    Paragraph::new(Span::styled(
                        "  (no cross-references found)",
                        Style::new().fg(Color::DarkGray).italic(),
                    )),
                    inner,
                );
                return;
            }

            let styled: Vec<Line> = lines
                .iter()
                .map(|l| {
                    let t = l.trim_start_matches("  ");
                    if t.starts_with("0x") {
                        highlight_addr_table(l)
                    } else {
                        Line::styled(l.clone(), Style::new().fg(Color::Gray))
                    }
                })
                .collect();

            f.render_widget(Paragraph::new(Text::from(styled)), inner);
        }
    }
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

    let keybinds = if app.popup.is_some() {
        "Esc:close  0-9:jump"
    } else if app.search_pattern.is_some() {
        "n:next  N:prev  Esc:clear  y:copy  Tab:tab  ↑↓:history  PgUpDn:scroll"
    } else {
        "Tab  1-7:tab  g:goto  /:search  j/k:cursor  [/]:nav  m:mark  B:marks  x:xref  y:copy"
    };

    // Right-side info: arch · focused addr · token estimate
    let arch_part = app.binary_arch.as_deref()
        .map(|a| format!("{}  ·  ", a))
        .unwrap_or_default();
    let addr_part = app.focused_addr
        .map(|a| format!("@ 0x{:x}  ·  ", a))
        .unwrap_or_default();
    let token_est = if app.context_entries.is_empty() {
        String::new()
    } else {
        let chars: usize = app.context_entries.iter().map(|e| e.char_count).sum();
        format!("~{}k ctx", chars / 1000)
    };
    let info = format!("{}{}{}", arch_part, addr_part, token_est);

    // Build the status line: icon + status | keybinds … info
    let left = format!(" {} {}", icon, app.status);
    let left_len = left.chars().count() as u16;
    let right = format!("{}  {} ", keybinds, info);
    let right_len = right.chars().count() as u16;
    let pad = area.width.saturating_sub(left_len + right_len);

    let line = Line::from(vec![
        Span::styled(format!(" {} ", icon), Style::new().fg(color)),
        Span::styled(app.status.clone(), Style::new().fg(Color::Gray)),
        Span::raw(" ".repeat(pad as usize)),
        Span::styled(keybinds, Style::new().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(info, Style::new().fg(Color::Cyan)),
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
        // Count chars (not bytes) so the cursor lands on the right visual column
        // even when the input contains multi-byte characters.
        let col = app.input[..app.input_cursor].chars().count() as u16;
        f.set_cursor_position(Position {
            x: inner.x.saturating_add(1).saturating_add(col),
            y: inner.y,
        });
    }
}

// ─ Context panel ──────────────────────────────────────────────────────────────

fn render_context(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " Context ",
            Style::new().fg(Color::Cyan).bold(),
        ))
        .border_style(Style::new().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.context_entries.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "  (no context yet — send a message to start an agent turn)",
                Style::new().fg(Color::DarkGray).italic(),
            )),
            inner,
        );
        return;
    }

    let total_chars: usize = app.context_entries.iter().map(|e| e.char_count).sum();
    const BAR_W: usize = 10;

    let mut lines: Vec<Line> = Vec::new();

    // ── Summary header ──────────────────────────────────────────────────────
    lines.push(Line::from(vec![
        Span::styled("  Context window  ", Style::new().fg(Color::DarkGray)),
        Span::styled(
            format!("{} chars", total_chars),
            Style::new().fg(Color::Yellow),
        ),
        Span::styled("  in  ", Style::new().fg(Color::DarkGray)),
        Span::styled(
            format!("{} entries", app.context_entries.len()),
            Style::new().fg(Color::Yellow),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "  ─────────────────────────────────────────────────────────────",
        Style::new().fg(Color::DarkGray),
    )));

    // ── Per-entry rows ──────────────────────────────────────────────────────
    for entry in &app.context_entries {
        let role_style = match entry.role.as_str() {
            "user"      => Style::new().fg(Color::Cyan),
            "assistant" => Style::new().fg(Color::Magenta),
            _           => Style::new().fg(Color::Gray),
        };

        let (kind_label, kind_style) = match entry.kind.as_str() {
            "text"        => ("text      ", Style::new().fg(Color::White)),
            "tool_call"   => ("tool_call ", Style::new().fg(Color::Yellow)),
            "tool_result" => ("tool_res  ", Style::new().fg(Color::Green)),
            other         => (other,        Style::new().fg(Color::DarkGray)),
        };

        // Proportional bar (at least 1 block if nonzero)
        let filled = if total_chars > 0 {
            ((entry.char_count * BAR_W) / total_chars).max(if entry.char_count > 0 { 1 } else { 0 })
        } else {
            0
        };
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "░".repeat(BAR_W.saturating_sub(filled))
        );

        // Tool name badge (shown instead of blank when present)
        let tool_badge = entry
            .tool_name
            .as_deref()
            .map(|n| format!("[{}] ", n))
            .unwrap_or_default();

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<9}", entry.role), role_style),
            Span::raw("  "),
            Span::styled(kind_label.to_string(), kind_style),
            Span::raw("  "),
            Span::styled(bar, Style::new().fg(Color::Blue)),
            Span::raw(" "),
            Span::styled(
                format!("{:>6}c", entry.char_count),
                Style::new().fg(Color::DarkGray),
            ),
            Span::raw("  "),
            Span::styled(tool_badge, Style::new().fg(Color::Yellow)),
            Span::styled(entry.preview.clone(), Style::new().fg(Color::Gray).italic()),
        ]));
    }

    let scroll = app.scroll[Tab::Context as usize];
    f.render_widget(
        Paragraph::new(Text::from(lines)).scroll((scroll, 0)),
        inner,
    );
}

// ─── Active-highlight helper ──────────────────────────────────────────────────

/// Apply a dark-gray background to every span in a line (active-address focus).
fn apply_focus_highlight(line: Line<'static>) -> Line<'static> {
    let spans: Vec<Span<'static>> = line
        .spans
        .into_iter()
        .map(|s| Span::styled(s.content, s.style.bg(Color::DarkGray)))
        .collect();
    Line::from(spans)
}

/// Apply a dark-blue background to every span in a line (search match).
fn apply_search_highlight(line: Line<'static>) -> Line<'static> {
    let spans: Vec<Span<'static>> = line
        .spans
        .into_iter()
        .map(|s| Span::styled(s.content, s.style.bg(Color::Blue)))
        .collect();
    Line::from(spans)
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
    // Use char-boundary-safe get() — disasm output is ASCII in practice, but
    // be defensive against any non-ASCII that might slip through.
    let bytes_end = (0..=24.min(after_sep.len())).rev()
        .find(|&i| after_sep.is_char_boundary(i))
        .unwrap_or(0);
    let bytes_str = after_sep[..bytes_end].trim_end();
    let rest_start = (26..=after_sep.len())
        .find(|&i| after_sep.is_char_boundary(i))
        .unwrap_or(after_sep.len());
    let rest = if after_sep.len() > 26 {
        after_sep[rest_start..].trim_start()
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

/// Highlight a Functions-tab line, injecting a [!] or [!!] badge when a
/// vulnerability score is known for the address on that line.
fn highlight_fn_line(
    line: &str,
    scores: &std::collections::HashMap<u64, u8>,
) -> Line<'static> {
    let t = line.trim_start_matches("  ");
    if t.starts_with("0x") {
        if let Some(sp) = t.find(|c: char| c.is_whitespace()) {
            let addr_str = &t[..sp];
            let name     = t[sp..].trim_start();
            let vaddr    = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .unwrap_or(0);

            let badge: Option<Span<'static>> = scores.get(&vaddr).and_then(|&s| {
                if s >= 7 {
                    Some(Span::styled(" [!!]", Style::new().fg(Color::Red).bold()))
                } else if s >= 4 {
                    Some(Span::styled(" [!]", Style::new().fg(Color::Yellow).bold()))
                } else if s > 0 {
                    Some(Span::styled(" [·]", Style::new().fg(Color::DarkGray)))
                } else {
                    None
                }
            });

            let mut spans: Vec<Span<'static>> = vec![
                Span::raw("  "),
                Span::styled(addr_str.to_string(), Style::new().fg(Color::Yellow)),
                Span::raw("  "),
                Span::styled(name.to_string(), Style::new().fg(Color::Green)),
            ];
            if let Some(b) = badge {
                spans.push(b);
            }
            return Line::from(spans);
        }
    }
    Line::styled(line.to_string(), Style::new().fg(Color::DarkGray))
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

/// Syntax-highlight a single line of pseudo-C decompiler output.
fn highlight_decompile(line: &str) -> Line<'static> {
    const KEYWORDS: &[&str] = &[
        "void", "int", "char", "unsigned", "long", "short", "return",
        "if", "else", "while", "for", "do", "break", "continue",
        "struct", "typedef", "static", "const",
    ];

    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];

    // Tokenise by whitespace while preserving separators
    let mut rest = trimmed;
    while !rest.is_empty() {
        // Numeric literal (0x… or decimal)
        if let Some(end) = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != 'x') {
            let tok = &rest[..end.max(1)];
            let is_num = tok.starts_with("0x") || tok.starts_with("0X")
                || tok.parse::<i64>().is_ok();
            let is_kw = KEYWORDS.contains(&tok);
            let style = if is_kw {
                Style::new().fg(Color::Cyan).bold()
            } else if is_num {
                Style::new().fg(Color::Magenta)
            } else if tok.starts_with("FUN_") || tok.starts_with("DAT_") {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new().fg(Color::White)
            };
            spans.push(Span::styled(tok.to_string(), style));
            let sep_end = end.max(1);
            // separator chars (punctuation/spaces)
            let sep = &rest[sep_end..];
            let sep_len = sep.find(|c: char| c.is_alphanumeric() || c == '_').unwrap_or(sep.len());
            if sep_len > 0 {
                spans.push(Span::styled(
                    sep[..sep_len].to_string(),
                    Style::new().fg(Color::DarkGray),
                ));
            }
            rest = &rest[sep_end + sep_len..];
        } else {
            // remaining token to end of line
            let is_kw = KEYWORDS.contains(&rest);
            let style = if is_kw {
                Style::new().fg(Color::Cyan).bold()
            } else if rest.starts_with("FUN_") || rest.starts_with("DAT_") {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new().fg(Color::White)
            };
            spans.push(Span::styled(rest.to_string(), style));
            break;
        }
    }

    Line::from(spans)
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
