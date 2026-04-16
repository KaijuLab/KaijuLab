use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossterm::{
    event::{
        Event, EventStream, KeyCode, KeyModifiers,
        MouseEvent, MouseEventKind,
    },
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

const TAB_NAMES: &[&str] = &["Functions", "Disasm", "Decompile", "Strings", "Imports", "Chat", "Context", "Notes"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Functions  = 0,
    Disasm     = 1,
    Decompile  = 2,
    Strings    = 3,
    Imports    = 4,
    Chat       = 5,
    Context    = 6,
    Notes      = 7,
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
            7 => Some(Tab::Notes),
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
            "list_functions"    => Some(Tab::Functions),
            "disassemble"       => Some(Tab::Disasm),
            "decompile"         => Some(Tab::Decompile),
            "strings_extract"   => Some(Tab::Strings),
            "resolve_plt"
            | "resolve_pe_imports" => Some(Tab::Imports),
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

// ─── Function entry (parsed from list_functions output) ──────────────────────

#[derive(Clone, Debug)]
pub struct FnEntry {
    pub vaddr: u64,
    pub name:  String,
}

impl FnEntry {
    /// Try to parse one line from `list_functions` output.
    /// Expected format: `  0x<hex>  <name>…`
    fn parse(line: &str) -> Option<Self> {
        let t = line.trim_start();
        if !t.starts_with("0x") { return None; }
        let sp = t.find(|c: char| c.is_whitespace())?;
        let addr_str = &t[..sp];
        let name = t[sp..].trim_start().split_whitespace().next()?.to_string();
        let vaddr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).ok()?;
        Some(FnEntry { vaddr, name })
    }
}

// ─── Note display entry ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NoteEntry {
    pub id:        i64,
    pub vaddr:     Option<u64>,
    pub text:      String,
    pub timestamp: String,
}

// ─── Popup overlay ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum Popup {
    /// Session bookmarks list.
    Bookmarks,
    /// Cross-references to an address (lines from xrefs_to).
    Xref { title: String, lines: Vec<String> },
    /// Keyboard cheat-sheet.
    Help,
    /// Inline rename function at `addr` (current name shown as placeholder).
    Rename { addr: u64, current: String },
    /// Inline add/edit comment at `addr`.
    Comment { addr: u64, current: String },
    /// Add analyst note, optionally anchored to a virtual address.
    NoteEdit { addr: Option<u64> },
    /// Confirm deletion of a note (shows note preview, y/Enter=delete, n/Esc=cancel).
    ConfirmDeleteNote { idx: usize, preview: String },
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
    pub tab_lines: [Vec<String>; 8],
    /// Whether each tab has unseen content (shows a dot indicator).
    pub tab_dirty: [bool; 8],
    pub chat: Vec<ChatMsg>,
    /// Scroll offsets for each tab (lines from top for panels; lines from bottom for chat).
    pub scroll: [u16; 8],
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
    pub panel_cursor: [usize; 8],
    /// Session bookmarks (vaddr + user label).
    pub bookmarks: Vec<Bookmark>,
    /// Active popup overlay, if any.
    pub popup: Option<Popup>,
    /// Text typed inside a popup input box (Rename / Comment / NoteEdit).
    pub popup_input: String,
    /// Detected binary architecture string (e.g. "x86_64", "aarch64").
    pub binary_arch: Option<String>,
    /// Split-pane mode: show Disasm (left) and Decompile (right) side-by-side.
    pub split_pane: bool,
    /// In split-pane mode: which half has focus (false=left/Disasm, true=right/Decompile).
    pub split_focus_right: bool,
    /// Pending retry: re-send the last user message on the next event-loop tick.
    pub retry_pending: bool,
    /// Set to true when a large content change requires a full terminal clear
    /// before the next draw to prevent stale differential-render artifacts.
    pub needs_full_redraw: bool,
    /// Parsed function entries (mirrors tab_lines[Functions] but structured).
    pub fn_entries: Vec<FnEntry>,
    /// Active fuzzy-filter string for the Functions tab.
    pub fn_filter: String,
    /// Whether the function filter input is active (f key toggles).
    pub fn_filter_active: bool,
    /// Progress of the current multi-tool agent turn: (step, total, label).
    pub progress: Option<(usize, usize, String)>,
    /// Shared cancellation token: set to true by Ctrl+X to stop the agent.
    pub cancel_token: Arc<AtomicBool>,
    /// Recently opened binaries (loaded from ~/.kaiju/recent.json).
    pub recent_files: Vec<String>,
    /// Analyst notes for the current binary (shown in Notes tab).
    pub notes: Vec<NoteEntry>,
    /// Last decompile args so write tools can auto-refresh the Decompile tab.
    pub last_decompile_path: String,
    pub last_decompile_vaddr: u64,
    /// Autocomplete candidates (populated on first Tab press with non-empty input).
    pub completions: Vec<String>,
    /// Which candidate is currently selected (cycles with Tab).
    pub completion_idx: usize,
    /// The part of `input` that precedes the token being completed.
    /// Applying a completion writes `completion_prefix + completions[idx]` → `input`.
    pub completion_prefix: String,
    /// Scroll offset for the Help popup (PgUp/PgDn while popup is open).
    pub help_scroll: u16,
}


impl App {
    pub fn new(backend_name: String, cancel_token: Arc<AtomicBool>) -> Self {
        let recent = load_recent_files();
        let mut app = App {
            active_tab: Tab::Chat,
            tab_lines: Default::default(),
            tab_dirty: [false; 8],
            chat: Vec::new(),
            scroll: {
                let mut s = [0u16; 8];
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
            panel_cursor: [0usize; 8],
            bookmarks: Vec::new(),
            popup: None,
            popup_input: String::new(),
            binary_arch: None,
            split_pane: false,
            split_focus_right: false,
            retry_pending: false,
            needs_full_redraw: false,
            fn_entries: Vec::new(),
            fn_filter: String::new(),
            fn_filter_active: false,
            progress: None,
            cancel_token,
            recent_files: recent,
            notes: Vec::new(),
            last_decompile_path: String::new(),
            last_decompile_vaddr: 0,
            completions: Vec::new(),
            completion_idx: 0,
            completion_prefix: String::new(),
            help_scroll: 0,
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
            let path = self.binary_path.as_deref().unwrap_or("");
            let args = serde_json::json!({ "path": path, "vaddr": addr });
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
                // Track decompile args so write tools can refresh the Decompile tab later.
                if name == "decompile" {
                    if let Ok(args) = serde_json::from_str::<serde_json::Value>(&display_args) {
                        if let Some(path) = args["path"].as_str() {
                            self.last_decompile_path = path.to_string();
                        }
                        if let Some(vaddr) = args["vaddr"].as_u64() {
                            self.last_decompile_vaddr = vaddr;
                        }
                    }
                }
                self.chat.push(ChatMsg::ToolCall { name: name.clone(), args: display_args });
                self.status = format!("⏺ {}(…)", name);
                self.is_loading = true;
                // scroll=0 means "pinned to bottom"; render_chat tracks new content automatically.
                // Do NOT reset scroll here so the user's manual scroll position is preserved.
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
                // Auto-refresh the Decompile tab after write tools that affect decompile output.
                const DECOMPILE_WRITE_TOOLS: &[&str] = &[
                    "rename_function", "rename_variable", "add_comment",
                    "set_return_type", "set_param_type", "set_param_name",
                ];
                if DECOMPILE_WRITE_TOOLS.contains(&name.as_str())
                    && self.last_decompile_vaddr != 0
                    && !self.tab_lines[Tab::Decompile as usize].is_empty()
                {
                    let args = serde_json::json!({
                        "path": self.last_decompile_path,
                        "vaddr": self.last_decompile_vaddr,
                    });
                    let result = crate::tools::dispatch("decompile", &args);
                    let new_lines: Vec<String> = result.output.lines().map(|l| l.to_string()).collect();
                    self.tab_lines[Tab::Decompile as usize] = new_lines;
                    self.tab_dirty[Tab::Decompile as usize] = true;
                }
                // Parse structured function entries for the Functions tab
                if name == "list_functions" {
                    self.fn_entries = lines.iter()
                        .filter_map(|l| FnEntry::parse(l))
                        .collect();
                }
                // Clear progress after each tool result
                self.progress = None;
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
            AgentEvent::LlmTextChunk(chunk) => {
                // Append to last Assistant message or start a new one
                match self.chat.last_mut() {
                    Some(ChatMsg::Assistant(text)) => text.push_str(&chunk),
                    _ => self.chat.push(ChatMsg::Assistant(chunk)),
                }
                // Do NOT force active_tab or scroll — let the user stay wherever they are.
                // scroll=0 already means "bottom" and naturally tracks new content.
                self.is_loading = true;
            }
            AgentEvent::LlmText(text) => {
                self.chat.push(ChatMsg::Assistant(text));
                // Do NOT force active_tab — let the user stay on the tab they chose.
                self.is_loading = false;
                self.status = "Ready".to_string();
                self.needs_full_redraw = true;
            }
            AgentEvent::Done => {
                self.is_loading = false;
                self.status = "Ready".to_string();
                self.needs_full_redraw = true;
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
                self.tab_dirty[Tab::Functions as usize] = true;
            }

            AgentEvent::Progress { step, total, label } => {
                self.progress = Some((step, total, label.clone()));
                self.status = format!("⏺ step {}/{} — {}", step, total, label);
                self.is_loading = true;
            }

            AgentEvent::Cancelled => {
                self.progress = None;
                self.is_loading = false;
                self.status = "Cancelled".to_string();
                self.cancel_token.store(false, Ordering::Relaxed);
                self.chat.push(ChatMsg::Error("Turn cancelled by user".to_string()));
                self.scroll[Tab::Chat as usize] = 0;
            }

            AgentEvent::NotesUpdate(notes) => {
                self.notes = notes.into_iter().map(|n| NoteEntry {
                    id:        n.id,
                    vaddr:     n.vaddr,
                    text:      n.text,
                    timestamp: n.timestamp,
                }).collect();
                self.tab_dirty[Tab::Notes as usize] = true;
                self.status = format!("Notes updated ({} total)", self.notes.len());
            }
            AgentEvent::PluginOutput { name, output } => {
                // Display plugin output in the Chat tab as an assistant-style message.
                self.chat.push(ChatMsg::Assistant(
                    format!("Plugin: {}\n\n{}", name, output)
                ));
                self.active_tab = Tab::Chat;
                self.scroll[Tab::Chat as usize] = 0;
                self.is_loading = false;
                self.status = format!("Plugin '{}' finished", name);
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

    // ─── Autocomplete ────────────────────────────────────────────────────────────

    /// Split `input` into (prefix, token): `prefix` is everything up to the last
    /// whitespace-delimited token that we are completing; `token` is the tail being matched.
    /// Path-like tokens (containing `/` or starting with `~`) are completed in-place;
    /// everything else treats the whole input as the phrase being completed.
    fn split_completion(&self) -> (String, String) {
        let input = &self.input;
        // If the last space-delimited word looks like a filesystem path, split there.
        if let Some(sp) = input.rfind(' ') {
            let last = &input[sp + 1..];
            if last.starts_with('/') || last.starts_with("~/") || last.starts_with("./")
                || (last.contains('/') && !last.is_empty())
            {
                return (input[..sp + 1].to_string(), last.to_string());
            }
        }
        // Otherwise complete the whole input as a phrase.
        (String::new(), input.clone())
    }

    /// Build a list of completion candidates for the current input.
    fn compute_completions(&self) -> (String, Vec<String>) {
        let (prefix, token) = self.split_completion();
        let token_lower = token.to_lowercase();
        let mut cands: Vec<String> = Vec::new();

        // ── 1. Filesystem path completion ──────────────────────────────────────
        let is_path = token.starts_with('/')
            || token.starts_with("~/")
            || token.starts_with("./")
            || (token.contains('/') && !token.is_empty());
        if is_path {
            let expanded = if token.starts_with("~/") {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("{}{}", home, &token[1..])
            } else {
                token.clone()
            };
            let (dir, file_prefix) = if expanded.ends_with('/') {
                (expanded.as_str().to_owned(), String::new())
            } else {
                match expanded.rfind('/') {
                    Some(i) => (expanded[..i + 1].to_string(), expanded[i + 1..].to_string()),
                    None    => ("./".to_string(), expanded.clone()),
                }
            };
            let fp_lower = file_prefix.to_lowercase();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !name.starts_with('.') && name.to_lowercase().starts_with(&fp_lower) {
                        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        let full = format!("{}{}{}", dir, name, if is_dir { "/" } else { "" });
                        // Restore tilde form if input started with ~/
                        let display = if token.starts_with("~/") {
                            let home = std::env::var("HOME").unwrap_or_default();
                            if full.starts_with(&home) {
                                format!("~{}", &full[home.len()..])
                            } else {
                                full
                            }
                        } else {
                            full
                        };
                        cands.push(display);
                    }
                }
            }
            cands.sort();
            return (prefix, cands);
        }

        // ── 2. Function address completion ─────────────────────────────────────
        // Trigger when the prefix (command portion) contains an RE verb, or when
        // the token itself looks like the start of a hex address.
        let prefix_lower = prefix.trim_end().to_lowercase();
        let fn_verbs = [
            "disassemble", "decompile", "explain", "rename",
            "xref", "cfg", "call graph", "at 0x", "address",
        ];
        let fn_context = fn_verbs.iter().any(|v| prefix_lower.contains(v))
            || token_lower.starts_with("0x");
        if fn_context && !self.fn_entries.is_empty() {
            for fe in &self.fn_entries {
                let addr = format!("0x{:x}", fe.vaddr);
                if token_lower.is_empty()
                    || addr.contains(&token_lower)
                    || fe.name.to_lowercase().contains(&token_lower)
                {
                    cands.push(format!("{}  ; {}", addr, fe.name));
                }
            }
            if !cands.is_empty() {
                return (prefix, cands);
            }
        }

        // ── 3. Keyword / phrase completion ─────────────────────────────────────
        const PHRASES: &[&str] = &[
            // TUI commands (/ prefix)
            "/auto",
            "/goto ",
            "/g ",
            "/plugins",
            "/python ",
            "/run ",
            "/timeout ",
            // LLM prompts (natural language — no prefix)
            "analyse ",
            "disassemble the entry point",
            "disassemble function at 0x",
            "decompile the main function",
            "decompile function at 0x",
            "list all functions",
            "list strings",
            "show file info",
            "explain function at 0x",
            "rename function at 0x",
            "add comment at 0x",
            "show imports",
            "find vulnerabilities",
            "auto analyze",
            "write a python script to ",
            "decrypt the payload using python",
            "solve this ctf challenge",
            "describe what you can do",
            "search for bytes ",
            "show call graph",
            "show cfg for 0x",
            "show xrefs to 0x",
            "generate yara rule for 0x",
            "export report",
        ];
        for phrase in PHRASES {
            if phrase.to_lowercase().starts_with(&token_lower) {
                cands.push(phrase.to_string());
            }
        }

        (prefix, cands)
    }

    /// Apply `completions[completion_idx]` to `self.input`.
    fn apply_completion(&mut self) {
        if let Some(c) = self.completions.get(self.completion_idx) {
            self.input = format!("{}{}", self.completion_prefix, c);
            self.input_cursor = self.input.len();
        }
    }

    /// Trigger or cycle forward through completions.
    fn complete_forward(&mut self) {
        if self.completions.is_empty() {
            // First Tab: compute completions.
            let (prefix, cands) = self.compute_completions();
            if cands.is_empty() {
                self.status = "No completions".to_string();
                return;
            }
            self.completion_prefix = prefix;
            self.completions = cands;
            self.completion_idx = 0;
        } else {
            self.completion_idx = (self.completion_idx + 1) % self.completions.len();
        }
        self.apply_completion();
        self.status = format!(
            "Tab: {}/{} completions — Shift+Tab: back — Esc: dismiss",
            self.completion_idx + 1,
            self.completions.len()
        );
    }

    /// Cycle backwards through completions.
    fn complete_backward(&mut self) {
        if self.completions.is_empty() { return; }
        let n = self.completions.len();
        self.completion_idx = (self.completion_idx + n - 1) % n;
        self.apply_completion();
        self.status = format!(
            "Tab: {}/{} completions — Shift+Tab: back — Esc: dismiss",
            self.completion_idx + 1,
            n,
        );
    }

    /// Dismiss the completion popup without changing the input.
    fn clear_completions(&mut self) {
        self.completions.clear();
        self.completion_idx = 0;
        self.completion_prefix.clear();
    }

    /// Copy `text` to the system clipboard; update status with result.
    /// Tries arboard first, then falls back to CLI tools (xclip, wl-copy, xsel, clip.exe).
    fn copy_to_clipboard(&mut self, text: String) {
        if text.is_empty() {
            self.status = "Nothing to copy — panel is empty".to_string();
            return;
        }
        let line_count = text.lines().count();

        // Primary: arboard (works on native Linux/macOS/Windows)
        if arboard::Clipboard::new()
            .and_then(|mut cb| cb.set_text(text.clone()))
            .is_ok()
        {
            self.status = format!("Copied {} lines to clipboard", line_count);
            return;
        }

        // Fallback: CLI clipboard tools (WSL, headless X, Wayland, etc.)
        let tools: &[(&str, &[&str])] = &[
            ("xclip",    &["-selection", "clipboard"]),
            ("wl-copy",  &[]),
            ("xsel",     &["--clipboard", "--input"]),
            ("clip.exe", &[]),
        ];
        for (cmd, args) in tools {
            use std::io::Write;
            let ok = std::process::Command::new(cmd)
                .args(*args)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(text.as_bytes());
                    }
                    child.wait()
                })
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                self.status = format!("Copied {} lines to clipboard ({})", line_count, cmd);
                return;
            }
        }

        self.status = "Clipboard error: no clipboard tool available (arboard, xclip, wl-copy, xsel, clip.exe)".to_string();
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

    // ─── Popup text-input helpers ────────────────────────────────────────────

    /// Handle a key while a text-entry popup (Rename / Comment / NoteEdit) is open.
    fn handle_popup_input_key(&mut self, key: crossterm::event::KeyEvent) -> Option<String> {
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                self.popup_input.clear();
                self.status = "Cancelled".to_string();
            }
            KeyCode::Enter => {
                self.confirm_popup();
            }
            KeyCode::Backspace => {
                self.popup_input.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.popup_input.push(c);
            }
            _ => {}
        }
        None
    }

    /// Commit the current popup_input value for the active popup.
    fn confirm_popup(&mut self) {
        let input = std::mem::take(&mut self.popup_input);
        let popup = self.popup.take();
        match popup {
            Some(Popup::Rename { addr, .. }) => {
                if !input.is_empty() {
                    if let Some(path) = self.binary_path.clone() {
                        let args = serde_json::json!({
                            "path": path, "vaddr": addr, "name": input
                        });
                        let result = crate::tools::dispatch("rename_function", &args);
                        self.status = if result.output.starts_with("Error") {
                            format!("Rename failed: {}", result.output)
                        } else {
                            format!("Renamed 0x{:x} → {}", addr, input)
                        };
                    }
                } else {
                    self.status = "Rename cancelled (empty input)".to_string();
                }
            }
            Some(Popup::Comment { addr, .. }) => {
                if !input.is_empty() {
                    if let Some(path) = self.binary_path.clone() {
                        let args = serde_json::json!({
                            "path": path, "vaddr": addr, "comment": input
                        });
                        let result = crate::tools::dispatch("add_comment", &args);
                        self.status = if result.output.starts_with("Error") {
                            format!("Comment failed: {}", result.output)
                        } else {
                            format!("Comment added at 0x{:x}", addr)
                        };
                    }
                } else {
                    self.status = "Comment cancelled (empty input)".to_string();
                }
            }
            Some(Popup::NoteEdit { addr }) => {
                if !input.is_empty() {
                    let id = (self.notes.len() as i64) + 1;
                    let timestamp = {
                        use std::time::{SystemTime, UNIX_EPOCH};
                        let secs = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs()).unwrap_or(0);
                        format!("t={}", secs)
                    };
                    self.notes.push(NoteEntry { id, vaddr: addr, text: input.clone(), timestamp });
                    self.tab_dirty[Tab::Notes as usize] = true;
                    self.status = format!("Note saved ({} total)", self.notes.len());
                } else {
                    self.status = "Note cancelled (empty)".to_string();
                }
            }
            _ => {}
        }
    }

    // ─── Markdown export ────────────────────────────────────────────────────────

    /// Build a markdown summary of the current session and copy to clipboard.
    fn export_markdown(&mut self) {
        let binary = self.binary_path.as_deref().unwrap_or("unknown");
        let mut md = format!("# KaijuLab Analysis — {}\n\n", binary);

        // Append functions if available
        if !self.tab_lines[Tab::Functions as usize].is_empty() {
            md.push_str("## Functions\n\n```\n");
            for l in &self.tab_lines[Tab::Functions as usize] {
                md.push_str(l);
                md.push('\n');
            }
            md.push_str("```\n\n");
        }

        // Append the last assistant message
        for msg in self.chat.iter().rev() {
            if let ChatMsg::Assistant(text) = msg {
                md.push_str("## Analysis\n\n");
                md.push_str(text);
                md.push_str("\n\n");
                break;
            }
        }

        // Append notes
        if !self.notes.is_empty() {
            md.push_str("## Analyst Notes\n\n");
            for note in &self.notes {
                let addr = note.vaddr.map(|a| format!(" @ 0x{:x}", a)).unwrap_or_default();
                md.push_str(&format!("- **[{}]{}** {}\n", note.id, addr, note.text));
            }
            md.push('\n');
        }

        self.copy_to_clipboard(md);
        self.status = "Markdown exported to clipboard".to_string();
    }

    /// Returns a user message to send to the agent, or None.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Option<String> {
        // Route key to popup text-input when a text-entry popup is open
        if matches!(
            self.popup,
            Some(Popup::Rename { .. }) | Some(Popup::Comment { .. }) | Some(Popup::NoteEdit { .. })
        ) {
            return self.handle_popup_input_key(key);
        }

        // ConfirmDeleteNote: y/Enter=confirm, n/Esc=cancel
        if let Some(Popup::ConfirmDeleteNote { idx, .. }) = self.popup.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.popup = None;
                    if idx < self.notes.len() {
                        let removed = self.notes.remove(idx);
                        if self.panel_cursor[Tab::Notes as usize] > 0
                            && self.panel_cursor[Tab::Notes as usize] >= self.notes.len()
                        {
                            self.panel_cursor[Tab::Notes as usize] =
                                self.notes.len().saturating_sub(1);
                        }
                        self.status = format!("Deleted note [{}]", removed.id);
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.popup = None;
                    self.status = "Delete cancelled".to_string();
                }
                _ => {}
            }
            return None;
        }

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

            // Tab — autocomplete when input is non-empty, otherwise cycle panels
            KeyCode::Tab => {
                if !self.input.is_empty() && !self.is_loading {
                    // Autocomplete forward
                    if key.modifiers.contains(KeyModifiers::SHIFT) {
                        self.complete_backward();
                    } else {
                        self.complete_forward();
                    }
                } else if self.split_pane && self.input.is_empty() {
                    // In split-pane mode: Tab alternates focus between left and right
                    self.split_focus_right = !self.split_focus_right;
                    self.status = if self.split_focus_right {
                        "Split-pane: focus → Decompile (right)".to_string()
                    } else {
                        "Split-pane: focus → Disasm (left)".to_string()
                    };
                } else if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.active_tab = self.active_tab.prev();
                    self.tab_dirty[self.active_tab as usize] = false;
                } else {
                    self.active_tab = self.active_tab.next();
                    self.tab_dirty[self.active_tab as usize] = false;
                }
                None
            }
            KeyCode::BackTab => {
                if !self.input.is_empty() && !self.is_loading {
                    self.complete_backward();
                } else {
                    self.active_tab = self.active_tab.prev();
                    self.tab_dirty[self.active_tab as usize] = false;
                }
                None
            }

            // Number keys to jump to a tab (only when input field is empty)
            KeyCode::Char(c @ '1'..='8') if self.input.is_empty() && key.modifiers.is_empty() => {
                let idx = (c as usize) - ('1' as usize);
                if let Some(t) = Tab::from_index(idx) {
                    self.active_tab = t;
                    self.tab_dirty[t as usize] = false;
                }
                None
            }

            // Ctrl+X — cancel current agent turn
            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cancel_token.store(true, Ordering::Relaxed);
                self.status = "Cancelling…".to_string();
                None
            }

            // Ctrl+E — export markdown summary to clipboard
            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.export_markdown();
                None
            }

            // R — rename function at cursor address
            KeyCode::Char('R') if self.input.is_empty()
                && key.modifiers.contains(KeyModifiers::SHIFT)
                && !matches!(self.active_tab, Tab::Chat | Tab::Context | Tab::Notes) =>
            {
                let addr = self.addr_at_cursor().or(self.focused_addr);
                if let Some(a) = addr {
                    let current = self.fn_entries.iter()
                        .find(|e| e.vaddr == a)
                        .map(|e| e.name.clone())
                        .unwrap_or_default();
                    self.popup = Some(Popup::Rename { addr: a, current });
                    self.popup_input.clear();
                    self.status = format!("Rename 0x{:x} — type new name, Enter to confirm", a);
                } else {
                    self.status = "No address at cursor — navigate to a function first".to_string();
                }
                None
            }

            // c — add/edit comment at cursor address
            KeyCode::Char('c') if self.input.is_empty()
                && key.modifiers.is_empty()
                && !matches!(self.active_tab, Tab::Chat | Tab::Context | Tab::Notes) =>
            {
                let addr = self.addr_at_cursor().or(self.focused_addr);
                if let Some(a) = addr {
                    self.popup = Some(Popup::Comment { addr: a, current: String::new() });
                    self.popup_input.clear();
                    self.status = format!("Comment at 0x{:x} — type text, Enter to save", a);
                } else {
                    self.status = "No address at cursor — navigate to an address first".to_string();
                }
                None
            }

            // a — add analyst note (optionally anchored to cursor address)
            // Excluded from Chat tab so users can start a message with 'a'.
            KeyCode::Char('a')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && !matches!(self.active_tab, Tab::Chat) =>
            {
                let addr = self.addr_at_cursor().or(self.focused_addr);
                self.popup = Some(Popup::NoteEdit { addr });
                self.popup_input.clear();
                let hint = addr.map(|a| format!(" anchored to 0x{:x}", a)).unwrap_or_default();
                self.status = format!("New note{} — type text, Enter to save", hint);
                None
            }

            // d — confirm-delete note at cursor line (Notes tab only)
            KeyCode::Char('d') if self.input.is_empty()
                && key.modifiers.is_empty()
                && self.active_tab == Tab::Notes =>
            {
                let idx = self.panel_cursor[Tab::Notes as usize];
                if idx < self.notes.len() {
                    let note = &self.notes[idx];
                    let addr_part = note.vaddr
                        .map(|a| format!(" @ 0x{:x}", a))
                        .unwrap_or_default();
                    let preview: String = note.text.chars().take(60).collect();
                    let preview = if note.text.len() > 60 {
                        format!("[{}{}] {}…", note.id, addr_part, preview)
                    } else {
                        format!("[{}{}] {}", note.id, addr_part, preview)
                    };
                    self.popup = Some(Popup::ConfirmDeleteNote { idx, preview });
                    self.status = "Delete note? (y/Enter=yes · n/Esc=cancel)".to_string();
                } else {
                    self.status = "No note at cursor".to_string();
                }
                None
            }

            // f — toggle fuzzy filter for Functions tab
            KeyCode::Char('f') if self.input.is_empty()
                && key.modifiers.is_empty()
                && self.active_tab == Tab::Functions =>
            {
                self.fn_filter_active = !self.fn_filter_active;
                if self.fn_filter_active {
                    self.fn_filter.clear();
                    self.status = "Function filter active — type to filter, Esc to clear".to_string();
                    // Redirect typing to fn_filter by pre-filling the input with a marker
                    self.input = "/fn:".to_string();
                    self.input_cursor = 4;
                } else {
                    self.fn_filter.clear();
                    self.input.clear();
                    self.input_cursor = 0;
                    self.status = "Function filter cleared".to_string();
                }
                None
            }

            // g — prefill /goto prompt when input is empty
            KeyCode::Char('g') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.input = "/g ".to_string();
                self.input_cursor = 3;
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

            // Esc — dismiss completions first, then popup, then search
            KeyCode::Esc if !self.completions.is_empty() => {
                self.clear_completions();
                self.status = "Completions dismissed".to_string();
                None
            }
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
            // Only fires on panel tabs (not Chat/Context/Notes) so typing "y..." still works there
            KeyCode::Char('y')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && !matches!(
                        self.active_tab,
                        Tab::Chat | Tab::Context | Tab::Notes
                    ) =>
            {
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

            // j / k — line cursor down / up in panels (removed as standalone shortcuts;
            // use ↑/↓ arrow keys instead, which work regardless of input state)

            // m — bookmark current address (only when an address is actually in scope)
            KeyCode::Char('m')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && (self.focused_addr.is_some() || self.addr_at_cursor().is_some()) =>
            {
                self.bookmark_current();
                None
            }
            // B — toggle bookmark list popup (only on non-text tabs so "B..." can be typed in Chat)
            KeyCode::Char('B')
                if self.input.is_empty()
                    && key.modifiers.contains(KeyModifiers::SHIFT)
                    && !matches!(
                        self.active_tab,
                        Tab::Chat | Tab::Context | Tab::Notes
                    ) =>
            {
                if matches!(self.popup, Some(Popup::Bookmarks)) {
                    self.popup = None;
                } else {
                    self.popup = Some(Popup::Bookmarks);
                }
                None
            }

            // x — xref popup (only when an address is in scope so "x..." can be typed otherwise)
            KeyCode::Char('x')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && (self.focused_addr.is_some() || self.addr_at_cursor().is_some()) =>
            {
                self.show_xref_popup();
                None
            }

            // ? — toggle keyboard help popup
            KeyCode::Char('?') if self.input.is_empty() && key.modifiers.is_empty() => {
                if matches!(self.popup, Some(Popup::Help)) {
                    self.popup = None;
                } else {
                    self.popup = Some(Popup::Help);
                    self.help_scroll = 0;
                }
                None
            }

            // s — toggle split-pane view (only on panel tabs)
            KeyCode::Char('s')
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && !matches!(
                        self.active_tab,
                        Tab::Chat | Tab::Context | Tab::Notes
                    ) =>
            {
                self.split_pane = !self.split_pane;
                self.status = if self.split_pane {
                    "Split-pane: Disasm | Decompile (Tab to switch focus)".to_string()
                } else {
                    "Split-pane off".to_string()
                };
                None
            }

            // r — retry last message on error
            KeyCode::Char('r') if self.input.is_empty()
                && key.modifiers.is_empty()
                && self.status.starts_with("Error") =>
            {
                self.retry_pending = true;
                self.status = "Retrying…".to_string();
                None
            }

            // Ctrl+R — fill input with last history entry (cycle on repeated press)
            KeyCode::Char('r') if self.input.is_empty()
                && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if !self.input_history.is_empty() {
                    let new_cursor = match self.history_cursor {
                        None => self.input_history.len() - 1,
                        Some(0) => 0,
                        Some(i) => i - 1,
                    };
                    self.history_cursor = Some(new_cursor);
                    self.input = self.input_history[new_cursor].clone();
                    self.input_cursor = self.input.len();
                }
                None
            }

            // : — activate command palette prefix
            KeyCode::Char(':') if self.input.is_empty() && key.modifiers.is_empty() => {
                self.input = ":".to_string();
                self.input_cursor = 1;
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

            // ↑↓ — panel cursor when input empty and no history; command history otherwise
            KeyCode::Up if self.input.is_empty() && self.input_history.is_empty() && key.modifiers.is_empty() => {
                self.move_panel_cursor(-1);
                None
            }
            KeyCode::Down if self.input.is_empty() && self.history_cursor.is_none() && key.modifiers.is_empty() => {
                self.move_panel_cursor(1);
                None
            }
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
                if matches!(self.popup, Some(Popup::Help)) {
                    self.help_scroll = self.help_scroll.saturating_add(10);
                } else {
                    let s = &mut self.scroll[self.active_tab as usize];
                    *s = s.saturating_add(20);
                }
                None
            }
            KeyCode::PageDown => {
                if matches!(self.popup, Some(Popup::Help)) {
                    self.help_scroll = self.help_scroll.saturating_sub(10);
                } else {
                    let s = &mut self.scroll[self.active_tab as usize];
                    *s = s.saturating_sub(20);
                }
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

                // ── Local TUI commands — all begin with '/' ─────────────────
                //
                // /goto <addr>  or  /g <addr>      — jump to address
                // /auto [path]                      — run auto-analysis
                // /timeout <n>                      — set HTTP timeout
                // /plugins                          — list installed plugins
                // /run <name> [path]                — run a plugin
                // /pattern                          — search current panel
                //   (any other /word falls through to panel search)
                //
                // `:cmd args` (colon prefix) pre-fills a natural-language LLM
                // prompt for review — a different concept; left unchanged.
                if let Some(rest) = msg.strip_prefix('/') {
                    let rest = rest.trim();

                    // /goto <addr>  or  /g <addr>
                    let goto_arg = rest.strip_prefix("goto ")
                        .or_else(|| rest.strip_prefix("g "));
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

                    // /auto [path] — structured auto-analysis prompt → forwarded to LLM
                    let auto_path = if rest == "auto" {
                        Some(self.binary_path.clone().unwrap_or_default())
                    } else if let Some(p) = rest.strip_prefix("auto ") {
                        Some(p.trim().to_string())
                    } else {
                        None
                    };
                    if let Some(path) = auto_path {
                        let prompt = if path.is_empty() {
                            "Run a full auto-analysis on the loaded binary: (1) file_info, (2) list_functions, (3) strings_extract, (4) scan_vulnerabilities. Summarise the top findings.".to_string()
                        } else {
                            format!("Run a full auto-analysis on {}: (1) file_info, (2) list_functions, (3) strings_extract, (4) scan_vulnerabilities. Summarise the top findings.", path)
                        };
                        if self.is_loading { return None; }
                        if self.input_history.last().map_or(true, |last| last != &msg) {
                            self.input_history.push(msg.clone());
                        }
                        self.history_cursor = None;
                        self.input_saved = String::new();
                        self.chat.push(ChatMsg::User(msg.clone()));
                        self.input.clear();
                        self.input_cursor = 0;
                        self.is_loading = true;
                        self.status = "Running auto-analysis…".to_string();
                        self.active_tab = Tab::Chat;
                        self.scroll[Tab::Chat as usize] = 0;
                        return Some(prompt);
                    }

                    // /timeout <n> — update per-request HTTP timeout
                    if let Some(t_rest) = rest.strip_prefix("timeout ") {
                        let t_rest = t_rest.trim();
                        match t_rest.parse::<u64>() {
                            Ok(secs) if secs > 0 => {
                                crate::llm::set_timeout_secs(secs);
                                self.status = format!("Timeout set to {}s", secs);
                            }
                            _ => {
                                self.status = format!(
                                    "Invalid timeout: '{}' (must be a positive integer)", t_rest
                                );
                            }
                        }
                        self.input.clear();
                        self.input_cursor = 0;
                        self.clear_completions();
                        return None;
                    }

                    // /help — toggle keyboard help popup
                    if rest == "help" {
                        if matches!(self.popup, Some(Popup::Help)) {
                            self.popup = None;
                        } else {
                            self.popup = Some(Popup::Help);
                            self.help_scroll = 0;
                        }
                        self.input.clear();
                        self.input_cursor = 0;
                        self.clear_completions();
                        return None;
                    }

                    // /plugins  and  /run <name> [path]
                    // These are intercepted in the main.rs message loop before reaching
                    // the LLM agent.  We show the user-typed form in the chat and forward
                    // the bare form (without '/') so the interceptor recognises it.
                    if rest == "plugins" || rest.starts_with("run ") {
                        // Auto-inject binary path for /run when none given
                        let forwarded = if let Some(plugin_rest) = rest.strip_prefix("run ") {
                            let parts: Vec<&str> = plugin_rest.splitn(2, ' ').collect();
                            let plugin_name = parts[0].trim();
                            let has_binary = parts.get(1)
                                .map_or(false, |s| !s.trim().is_empty());
                            if !has_binary {
                                if let Some(ref bp) = self.binary_path.clone() {
                                    format!("run {} {}", plugin_name, bp)
                                } else {
                                    rest.to_string()
                                }
                            } else {
                                rest.to_string()
                            }
                        } else {
                            rest.to_string() // "plugins"
                        };
                        if self.is_loading { return None; }
                        if self.input_history.last().map_or(true, |last| last != &msg) {
                            self.input_history.push(msg.clone());
                        }
                        self.history_cursor = None;
                        self.input_saved = String::new();
                        self.chat.push(ChatMsg::User(msg.clone()));
                        self.input.clear();
                        self.input_cursor = 0;
                        self.is_loading = true;
                        self.status = "Running…".to_string();
                        self.active_tab = Tab::Chat;
                        self.scroll[Tab::Chat as usize] = 0;
                        return Some(forwarded);
                    }

                    // Fallthrough:
                    //   /pattern          (no spaces) → search current panel
                    //   /cmd arg1 arg2    (has spaces) → direct tool command,
                    //                     forwarded to the pipeline for dispatch
                    if rest.contains(' ') {
                        // Direct command — show in chat, forward with '/' intact so
                        // main.rs routes it to dispatch_manual_command, not the LLM.
                        if self.is_loading { return None; }
                        if self.input_history.last().map_or(true, |last| last != &msg) {
                            self.input_history.push(msg.clone());
                        }
                        self.history_cursor = None;
                        self.input_saved = String::new();
                        self.chat.push(ChatMsg::User(msg.clone()));
                        self.input.clear();
                        self.input_cursor = 0;
                        self.is_loading = true;
                        self.status = "Running command…".to_string();
                        self.active_tab = Tab::Chat;
                        self.scroll[Tab::Chat as usize] = 0;
                        return Some(msg.clone()); // forwarded with '/' so main.rs dispatches it
                    } else {
                        // No args — treat as panel search pattern
                        self.search_panel(rest);
                        self.input.clear();
                        self.input_cursor = 0;
                        self.history_cursor = None;
                        return None;
                    }
                }

                // `:cmd args` — command palette shortcut: strip `:` and pre-fill input.
                // The user sees the expanded command in the input box and presses Enter to send.
                if let Some(cmd_rest) = msg.strip_prefix(':') {
                    let cmd_rest = cmd_rest.trim();
                    if cmd_rest.is_empty() {
                        self.input.clear();
                        self.input_cursor = 0;
                        self.history_cursor = None;
                        return None;
                    }
                    // Pre-fill with the raw command (minus the `:` prefix) and let the user
                    // review / edit before pressing Enter to send.
                    self.input = cmd_rest.to_string();
                    self.input_cursor = self.input.len();
                    self.history_cursor = None;
                    self.status = "Press Enter to send, or edit first".to_string();
                    return None;
                }

                let msg = msg;

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

            // Text editing — any edit dismisses the completion popup
            KeyCode::Backspace => {
                self.clear_completions();
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
                self.clear_completions();
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
                // Typing a character exits history-navigation mode and clears completions
                self.history_cursor = None;
                self.input_saved = String::new();
                self.clear_completions();
                self.input.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
                None
            }
            _ => None,
        }
    }

    // ─── Mouse input ────────────────────────────────────────────────────────────

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_add(3);
            }
            MouseEventKind::ScrollDown => {
                let s = &mut self.scroll[self.active_tab as usize];
                *s = s.saturating_sub(3);
            }
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                let col = mouse.column;
                let row = mouse.row;
                // Row 1 is the tab bar
                if row == 1 {
                    let n = TAB_NAMES.len() as u16;
                    let tab_w = (120u16 / n).max(1);
                    let idx = (col / tab_w) as usize;
                    if let Some(t) = Tab::from_index(idx.min(n as usize - 1)) {
                        self.active_tab = t;
                        self.tab_dirty[t as usize] = false;
                    }
                    return;
                }
                // Content rows: map clicked row → panel cursor line
                let content_start_row = 2u16;
                let tab = self.active_tab;
                if row >= content_start_row && !matches!(tab, Tab::Chat | Tab::Context | Tab::Notes) {
                    let clicked_line = row.saturating_sub(content_start_row) as usize;
                    let total = self.tab_lines[tab as usize].len();
                    if total > 0 {
                        self.panel_cursor[tab as usize] = clicked_line.min(total - 1);
                    }
                }
            }
            _ => {}
        }
    }
}

// ─── Recent files (TUI-local helper) ─────────────────────────────────────────

fn load_recent_files() -> Vec<String> {
    let home = match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(h) => h,
        None => return vec![],
    };
    let path = std::path::PathBuf::from(home).join(".kaiju").join("recent.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    serde_json::from_str::<Vec<String>>(&text).unwrap_or_default()
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
    cancel_token: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(backend_name.to_string(), cancel_token);

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
        // Check for pending retry before waiting for events
        if app.retry_pending {
            app.retry_pending = false;
            if let Some(msg) = app.input_history.last().cloned() {
                app.chat.push(ChatMsg::User(format!("[retry] {}", msg)));
                app.is_loading = true;
                app.active_tab = Tab::Chat;
                app.scroll[Tab::Chat as usize] = 0;
                user_tx.send(msg).await?;
            }
        }

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
                    Some(Ok(Event::Mouse(mouse))) => {
                        app.handle_mouse(mouse);
                    }
                    Some(Ok(Event::Resize(_, _))) => {
                        terminal.autoresize()?;
                        terminal.clear()?;
                    }
                    Some(Err(e)) => {
                        app.status = format!("Input error: {}", e);
                    }
                    _ => {}
                }
            }
        }

        if app.needs_full_redraw {
            app.needs_full_redraw = false;
            terminal.clear()?;
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
    // Completion popup (drawn just above the input bar)
    if !app.completions.is_empty() {
        render_completions(f, area, app);
    }
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
    if app.split_pane {
        let halves = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left: Disasm, Right: Decompile
        // Temporarily adjust border style based on focus
        let _left_focused = !app.split_focus_right;
        let _right_focused = app.split_focus_right;

        render_panel_split(f, halves[0], app, Tab::Disasm, !app.split_focus_right);
        render_panel_split(f, halves[1], app, Tab::Decompile, app.split_focus_right);
        return;
    }
    match app.active_tab {
        Tab::Chat    => render_chat(f, area, app),
        Tab::Context => render_context(f, area, app),
        Tab::Notes   => render_notes(f, area, app),
        tab          => render_panel(f, area, app, tab),
    }
}

/// Render a panel in split-pane mode, optionally highlighting border as focused.
fn render_panel_split(f: &mut Frame, area: Rect, app: &App, tab: Tab, focused: bool) {
    let border_color = if focused { Color::Cyan } else { Color::DarkGray };
    let tab_name = TAB_NAMES[tab as usize];
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .title(Span::styled(
            format!(" {} ", tab_name),
            Style::new().fg(if focused { Color::Cyan } else { Color::DarkGray }).bold(),
        ))
        .border_style(Style::new().fg(border_color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let raw = &app.tab_lines[tab as usize];
    if raw.is_empty() {
        let hint = match tab {
            Tab::Disasm    => "Say \"disassemble the entry point\"",
            Tab::Decompile => "Say \"decompile 0x<addr>\"",
            _ => "",
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

    let focused_hex = if tab == Tab::Disasm {
        app.focused_addr.map(|a| format!("{:016x}", a))
    } else {
        None
    };

    let arch_str = app.binary_arch.as_deref();
    let lines: Vec<Line> = match tab {
        Tab::Disasm => raw.iter().map(|l| {
            let line = highlight_disasm_arch(l, arch_str);
            if focused_hex.as_deref().map_or(false, |h| l.contains(h)) {
                apply_focus_highlight(line)
            } else { line }
        }).collect(),
        Tab::Decompile => raw.iter().map(|l| highlight_decompile(l)).collect(),
        _ => raw.iter().map(|l| Line::raw(l.clone())).collect(),
    };

    let scroll = app.scroll[tab as usize];
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
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
        lo(vec![("  ██████    ██████            ", mgb)]),
        lo(vec![("  ██████   █████              ", mgb)]),
        lo(vec![("  ██████  █████               ", mgb)]),
        lo(vec![("  ████████████                ", mgb)]),
        lo(vec![("  ██████  █████               ", mgb)]),
        lo(vec![("  ██████   █████              ", mgb)]),
        lo(vec![("  ██████    ██████            ", mgb)]),
        blank(),
        // Title
        Line::from(vec![
            Span::styled("  KaijuLab ", mgb),
            Span::styled(concat!("v", env!("CARGO_PKG_VERSION")), mg),
            Span::styled("  ·  AI-powered reverse engineering", dg),
        ]),
        blank(),
        // AI prompt examples
        Line::from(vec![
            Span::styled("  Ask the AI: ", yeb),
            Span::styled("\"Analyse /path/to/binary — what does it do?\"", it),
        ]),
        Line::from(vec![
            Span::raw("              "),
            Span::styled("\"What does function 0x401234 do? Is it vulnerable?\"", it),
        ]),
        Line::from(vec![
            Span::raw("              "),
            Span::styled("\"Solve this CTF — find the flag check and bypass it\"", it),
        ]),
        Line::from(vec![
            Span::raw("              "),
            Span::styled("\"Write a Python script to decrypt the embedded payload\"", it),
        ]),
        blank(),
        // Scroll-down hint
        Line::from(vec![
            Span::styled("  ↓ scroll for command reference  ·  ", dg),
            Span::styled("?", grb),
            Span::styled(" or ", dg),
            Span::styled("/help", grb),
            Span::styled(" for key bindings", dg),
        ]),
        blank(),
        div(),
        blank(),
        // ── Tabs ──────────────────────────────────────────────────────────────
        sec("Tabs  (press 1–8 or Tab to switch)"),
        div(),
        kb("1  Functions", "All functions — symbol names, prologue scan, vuln scores [!]"),
        kb("2  Disasm",    "Disassembly — syntax-highlighted, inline comments, go-to-def"),
        kb("3  Decompile", "Pseudo-C decompiler — applies project renames & types"),
        kb("4  Strings",   "Extracted printable strings from the binary"),
        kb("5  Imports",   "PLT / PE import table — stub addresses → symbol names"),
        kb("6  Chat",      "LLM conversation — tool calls, streaming output"),
        kb("7  Context",   "Token budget breakdown — per-message char counts"),
        kb("8  Notes",     "Persistent analyst notes — add with  a  delete with  d"),
        blank(),
        div(),
        blank(),
        // ── Most-used commands ────────────────────────────────────────────────
        sec("Most Used  (prefix  /  to call tools directly, no AI round-trip)"),
        div(),
        cmd("/disasm",    "<path> [vaddr]",         "Disassemble — auto-resolves vaddr to file offset"),
        cmd("/decompile", "<path> [vaddr]",         "Decompile a function  →  pseudo-C with annotations"),
        cmd("/functions", "<path>",                 "List all functions (symbols + prologue scan)"),
        cmd("/scan",      "<path> [n]",             "Vulnerability heuristic scan — top N functions"),
        cmd("/auto",      "<path> [n]",             "Full auto-analysis: info + funcs + strings + vuln"),
        cmd("/python",    "<script.py> [timeout]",  "Run a Python 3 file  (LLM uses run_python tool)"),
        blank(),
        // ── Disasm & decompile ────────────────────────────────────────────────
        sec("Disasm & Decompile"),
        div(),
        cmd("/hexdump",       "<path> [offset] [len]", "Raw hex dump at a file offset"),
        cmd("/cfg",           "<path> <vaddr>",         "Control-flow graph for a function"),
        cmd("/callgraph",     "<path> [depth]",          "Full static call graph (default depth 2)"),
        cmd("/xrefs",         "<path> <vaddr>",         "All CALL/JMP sites targeting an address"),
        cmd("/dwarf",         "<path>",                 "DWARF debug-info: function names & sizes"),
        cmd("/decompile_flat","<path> <base> <vaddr>",  "Decompile raw firmware/shellcode (no ELF/PE)"),
        blank(),
        // ── Search & patch ────────────────────────────────────────────────────
        sec("Search & Patch"),
        div(),
        cmd("/search",    "<path> <hex…>",          "Byte-pattern search  (?? = wildcard byte)"),
        cmd("/patch",     "<path> <vaddr> <hex>",   "Patch bytes  →  writes  <file>.patched"),
        cmd("/entropy",   "<path>",                 "Shannon entropy per section — detect packers"),
        cmd("/yara",      "<path> <vaddr> [name]",  "YARA rule (auto-wildcards reloc bytes)"),
        blank(),
        // ── Intelligence ──────────────────────────────────────────────────────
        sec("Intelligence"),
        div(),
        cmd("/imports",   "<path>",                 "Resolve PLT / PE imports → symbol names"),
        cmd("/strings",   "<path> [min_len]",       "Extract printable strings"),
        cmd("/identify",  "<path>",                 "FLIRT-style library function recognition"),
        cmd("/explain",   "<path> <vaddr>",         "Decompile + prompt you for interpretation"),
        cmd("/diff",      "<path_a> <path_b>",      "Diff two binaries by function content hash"),
        cmd("/vt",        "<path>",                 "VirusTotal SHA-256 lookup (needs API key)"),
        cmd("/report",    "<path>",                 "Export self-contained HTML analysis report"),
        blank(),
        // ── Project annotations ───────────────────────────────────────────────
        sec("Project Annotations  (persistent per binary, stored in <file>.kaiju.db)"),
        div(),
        cmd("/rename",    "<path> <vaddr> <name>",  "Name a function"),
        cmd("/comment",   "<path> <vaddr> <text>",  "Attach a comment to an address"),
        cmd("/project",   "<path>",                 "Show all saved renames, comments, notes"),
        cmd("/types",     "<path>",                 "Show struct & signature definitions"),
        blank(),
        // ── Plugins ───────────────────────────────────────────────────────────
        sec("Plugins & Scripting  (~/.kaiju/plugins/)"),
        div(),
        cmd("/plugins",   "",                       "List installed Rhai plugins"),
        cmd("/run",       "<name> [binary]",        "Run a Rhai plugin by name or path"),
        cmd("/python",    "<script.py> [timeout]",  "Run a Python 3 script directly"),
        blank(),
        // ── TUI navigation ────────────────────────────────────────────────────
        sec("TUI Navigation & Keys"),
        div(),
        kb("/goto 0xADDR", "Jump to address in current panel  (also /g 0xADDR)"),
        kb("/pattern",     "Search panel  ·  n=next  N=prev  Esc=clear"),
        kb("/timeout <n>", "Set per-request HTTP timeout (seconds)"),
        kb("1–8",          "Jump to tab directly"),
        kb("Tab",          "Cycle tab  ·  in split-pane: switch focus left↔right"),
        kb("s",            "Toggle split-pane (Disasm left, Decompile right)"),
        kb("j  k",         "Move line cursor in panel"),
        kb("Enter",        "Go-to-definition for address at cursor line"),
        kb("[  ]",         "Navigate back / forward (address history)"),
        kb("PgUp  PgDn",   "Scroll active panel"),
        kb("m",            "Bookmark current address"),
        kb("B",            "Open bookmarks popup  (0-9 to jump · Esc to close)"),
        kb("x",            "Xref popup — callers of address at cursor"),
        kb("R",            "Rename function at cursor (opens inline popup)"),
        kb("c",            "Add comment at cursor address"),
        kb("a",            "Add analyst note (optionally anchored to cursor)"),
        kb("d",            "Delete note at cursor  (Notes tab — asks for confirm)"),
        kb("f",            "Fuzzy filter Functions tab  (Esc to clear)"),
        kb("y",            "Copy panel content to system clipboard"),
        kb("Ctrl+E",       "Export markdown summary to clipboard"),
        kb("Ctrl+R",       "Cycle through sent-message history into input"),
        kb("Ctrl+X",       "Cancel current agent turn"),
        kb("r",            "Retry last message  (when status starts with Error)"),
        kb("↑  ↓",         "Browse sent-message history in input"),
        kb("?  /help",     "Toggle keyboard help popup"),
        kb("Ctrl+C",       "Clear input  ·  quit when input is empty"),
        blank(),
    ];

    lines
}

// ─ Chat panel ─────────────────────────────────────────────────────────────────

fn render_chat(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
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
                // Show recent files if any
                if !app.recent_files.is_empty() {
                    all_lines.push(Line::from(vec![
                        Span::styled(
                            "  Recent files  (copy path and type: analyse <path>)",
                            Style::new().fg(Color::Yellow).bold(),
                        ),
                    ]));
                    all_lines.push(Line::from(Span::styled(
                        "  ────────────────────────────────────────────────────────",
                        Style::new().fg(Color::DarkGray),
                    )));
                    for (i, rf) in app.recent_files.iter().enumerate().take(10) {
                        all_lines.push(Line::from(vec![
                            Span::styled(
                                format!("    [{}] ", i + 1),
                                Style::new().fg(Color::DarkGray),
                            ),
                            Span::styled(rf.clone(), Style::new().fg(Color::Cyan)),
                        ]));
                    }
                    all_lines.push(Line::raw(""));
                }
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
                        Span::raw("    "),
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
                        Span::raw("    "),
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
    //
    // Use Paragraph::line_count() to get the exact visual row count after
    // word-wrap — this is the only way to be accurate (manual ceil(cols/width)
    // underestimates at word boundaries and causes the last few lines to be
    // hidden until the next render).
    //
    // Use u32 throughout to prevent wraparound overflow for long conversations.
    let text = Text::from(all_lines);
    let visual_total = Paragraph::new(text.clone())
        .wrap(Wrap { trim: false })
        .line_count(inner.width) as u32;
    let visual_total = visual_total.max(1);

    let visible = inner.height as u32;
    let at_bottom_u32 = visual_total.saturating_sub(visible);
    // Clamp to u16 for ratatui's scroll interface.
    let at_bottom = at_bottom_u32.min(u16::MAX as u32) as u16;
    // Clamp stored scroll to the real maximum so PgDn/mouse-scroll work
    // immediately even when the initial value was set to u16::MAX.
    app.scroll[Tab::Chat as usize] = app.scroll[Tab::Chat as usize].min(at_bottom);
    let scroll_up = app.scroll[Tab::Chat as usize] as u32;
    let from_top = (at_bottom_u32.saturating_sub(scroll_up)).min(u16::MAX as u32) as u16;

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
        .borders(Borders::TOP | Borders::BOTTOM)
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
            Tab::Chat | Tab::Context | Tab::Notes => "",
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

    let arch_str = app.binary_arch.as_deref();
    let lines: Vec<Line> = match tab {
        Tab::Disasm => raw
            .iter()
            .map(|l| {
                let line = highlight_disasm_arch(l, arch_str);
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
        Tab::Chat | Tab::Context | Tab::Notes => raw.iter().map(|l| Line::raw(l.clone())).collect(),
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
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}

// ─── Completion popup ─────────────────────────────────────────────────────────

fn render_completions(f: &mut Frame, area: Rect, app: &App) {
    const MAX_ROWS: usize = 8;
    let total = app.completions.len();
    let show = total.min(MAX_ROWS);

    // Window of completions to display, centred around the selected index.
    let half = show / 2;
    let start = if app.completion_idx >= half {
        (app.completion_idx - half).min(total.saturating_sub(show))
    } else {
        0
    };
    let window = &app.completions[start..start + show];

    // Build lines
    let lines: Vec<Line> = window
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let global_idx = start + i;
            let is_sel = global_idx == app.completion_idx;
            if is_sel {
                Line::from(vec![
                    Span::styled(" ▶ ", Style::new().fg(Color::Cyan).bold()),
                    Span::styled(c.clone(), Style::new().fg(Color::White).bold()
                        .bg(Color::Rgb(30, 30, 60))),
                    Span::raw(" "),
                ])
            } else {
                Line::from(vec![
                    Span::styled("   ", Style::new()),
                    Span::styled(c.clone(), Style::new().fg(Color::Rgb(180, 180, 200))),
                ])
            }
        })
        .collect();

    // Position: just above the input row, right-aligned hint, fixed width
    let popup_h = show as u16 + 2; // border top + bottom
    let popup_w = area.width.min(70);
    let popup_x = area.x;
    let popup_y = area.height.saturating_sub(popup_h + 1); // 1 = input row

    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };

    let count_hint = if total > MAX_ROWS {
        format!(" {}/{} — Tab/Shift+Tab to cycle · Esc to dismiss ", app.completion_idx + 1, total)
    } else {
        format!(" Tab/Shift+Tab to cycle · Esc to dismiss ")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(count_hint, Style::new().fg(Color::DarkGray).italic()))
        .border_style(Style::new().fg(Color::Cyan));

    let inner = block.inner(popup_area);
    f.render_widget(ratatui::widgets::Clear, popup_area);
    f.render_widget(block, popup_area);
    f.render_widget(Paragraph::new(Text::from(lines)), inner);
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

        Popup::Rename { addr, current } => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" Rename  0x{:x}  (Enter=confirm · Esc=cancel) ", addr),
                    Style::new().fg(Color::Green).bold(),
                ))
                .border_style(Style::new().fg(Color::Green));
            // Smaller popup: 60% wide, 5 rows tall
            let pw2 = (area.width * 6 / 10).max(40).min(area.width.saturating_sub(4));
            let popup_area2 = Rect { x: area.x + (area.width.saturating_sub(pw2)) / 2,
                                    y: area.y + (area.height / 2).saturating_sub(3),
                                    width: pw2, height: 5 };
            f.render_widget(ratatui::widgets::Clear, popup_area2);
            let inner = block.inner(popup_area2);
            f.render_widget(block, popup_area2);
            let placeholder = if app.popup_input.is_empty() {
                current.as_str()
            } else {
                app.popup_input.as_str()
            };
            let display = if app.popup_input.is_empty() {
                Line::from(vec![
                    Span::styled(format!(" {}", placeholder), Style::new().fg(Color::DarkGray).italic()),
                ])
            } else {
                Line::from(vec![
                    Span::styled(format!(" {}_", app.popup_input), Style::new().fg(Color::White)),
                ])
            };
            f.render_widget(Paragraph::new(display), inner);
            let _ = placeholder;
        }

        Popup::Comment { addr, current } => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" Add Comment  0x{:x}  (Enter=confirm · Esc=cancel) ", addr),
                    Style::new().fg(Color::Yellow).bold(),
                ))
                .border_style(Style::new().fg(Color::Yellow));
            let pw2 = (area.width * 6 / 10).max(40).min(area.width.saturating_sub(4));
            let popup_area2 = Rect { x: area.x + (area.width.saturating_sub(pw2)) / 2,
                                    y: area.y + (area.height / 2).saturating_sub(3),
                                    width: pw2, height: 5 };
            f.render_widget(ratatui::widgets::Clear, popup_area2);
            let inner = block.inner(popup_area2);
            f.render_widget(block, popup_area2);
            let placeholder = current.as_str();
            let display = if app.popup_input.is_empty() {
                Line::from(vec![
                    Span::styled(format!(" {}", placeholder), Style::new().fg(Color::DarkGray).italic()),
                ])
            } else {
                Line::from(vec![
                    Span::styled(format!(" {}_", app.popup_input), Style::new().fg(Color::White)),
                ])
            };
            f.render_widget(Paragraph::new(display), inner);
            let _ = placeholder;
        }

        Popup::NoteEdit { addr } => {
            let title = match addr {
                Some(a) => format!(" New Note  @ 0x{:x}  (Enter=save · Esc=cancel) ", a),
                None    => " New Note  (Enter=save · Esc=cancel) ".to_string(),
            };
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(title, Style::new().fg(Color::Magenta).bold()))
                .border_style(Style::new().fg(Color::Magenta));
            let pw2 = (area.width * 7 / 10).max(40).min(area.width.saturating_sub(4));
            let popup_area2 = Rect { x: area.x + (area.width.saturating_sub(pw2)) / 2,
                                    y: area.y + (area.height / 2).saturating_sub(3),
                                    width: pw2, height: 5 };
            f.render_widget(ratatui::widgets::Clear, popup_area2);
            let inner = block.inner(popup_area2);
            f.render_widget(block, popup_area2);
            let display = if app.popup_input.is_empty() {
                Line::from(Span::styled(" Type note text…", Style::new().fg(Color::DarkGray).italic()))
            } else {
                Line::from(Span::styled(format!(" {}_", app.popup_input), Style::new().fg(Color::White)))
            };
            f.render_widget(Paragraph::new(display), inner);
        }

        Popup::ConfirmDeleteNote { preview, .. } => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " Delete Note?  (y/Enter=yes · n/Esc=cancel) ",
                    Style::new().fg(Color::Red).bold(),
                ))
                .border_style(Style::new().fg(Color::Red));
            let pw2 = (area.width * 7 / 10).max(44).min(area.width.saturating_sub(4));
            let popup_area2 = Rect {
                x: area.x + (area.width.saturating_sub(pw2)) / 2,
                y: area.y + (area.height / 2).saturating_sub(3),
                width: pw2,
                height: 5,
            };
            f.render_widget(ratatui::widgets::Clear, popup_area2);
            let inner = block.inner(popup_area2);
            f.render_widget(block, popup_area2);
            let lines = vec![
                Line::from(Span::styled(preview.clone(), Style::new().fg(Color::Yellow))),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  y / Enter", Style::new().fg(Color::Red).bold()),
                    Span::styled(" = delete     ", Style::new().fg(Color::Gray)),
                    Span::styled("n / Esc", Style::new().fg(Color::Green).bold()),
                    Span::styled(" = cancel", Style::new().fg(Color::Gray)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }

        Popup::Help => {
            // Give Help a larger popup than other dialogs: 88% wide, 90% tall
            let hw = (area.width * 88 / 100).max(60).min(area.width.saturating_sub(2));
            let hh = (area.height * 90 / 100).max(20).min(area.height.saturating_sub(2));
            let hx = area.x + (area.width.saturating_sub(hw)) / 2;
            let hy = area.y + (area.height.saturating_sub(hh)) / 2;
            let help_area = Rect { x: hx, y: hy, width: hw, height: hh };
            f.render_widget(ratatui::widgets::Clear, help_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " KaijuLab — Commands & Key Bindings  (Esc / ? to close) ",
                    Style::new().fg(Color::Yellow).bold(),
                ))
                .border_style(Style::new().fg(Color::Yellow));
            let inner = block.inner(help_area);
            f.render_widget(block, help_area);

            let cyb = Style::new().fg(Color::Cyan).bold();
            let wh  = Style::new().fg(Color::White);
            let yeb = Style::new().fg(Color::Yellow).bold();
            let dg  = Style::new().fg(Color::DarkGray);

            let kb = |key: &'static str, desc: &'static str| -> Line<'static> {
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{:<18}", key), cyb),
                    Span::styled(desc, wh),
                ])
            };
            let sec = |s: &'static str| -> Line<'static> {
                Line::from(vec![Span::raw("  "), Span::styled(s, yeb)])
            };
            let div = || -> Line<'static> {
                Line::from(Span::styled("  ──────────────────────────────────────────", dg))
            };

            let lines: Vec<Line<'static>> = vec![
                sec("Tabs  (1–8 or Tab to switch)"),
                div(),
                kb("1  Functions",    "Functions list — vuln scores [!][!!]"),
                kb("2  Disasm",       "Disassembly — syntax highlighted"),
                kb("3  Decompile",    "Pseudo-C decompiler + annotations"),
                kb("4  Strings",      "Extracted printable strings"),
                kb("5  Imports",      "PLT / PE import table"),
                kb("6  Chat",         "LLM conversation + tool calls"),
                kb("7  Context",      "Token budget per-message breakdown"),
                kb("8  Notes",        "Persistent analyst notes"),
                Line::raw(""),
                sec("Navigation"),
                div(),
                kb("Tab / Shift+Tab", "Cycle tabs  ·  split-pane: switch focus L↔R"),
                kb("s",               "Toggle split-pane (Disasm left | Decompile right)"),
                kb("/goto 0xADDR",    "Jump to address  (also /g ADDR)"),
                kb("[  ]",            "Navigate back / forward (address history)"),
                kb("j  k",            "Move line cursor in panel"),
                kb("Enter",           "Go-to-definition for address at cursor"),
                kb("PgUp  PgDn",      "Scroll active panel"),
                Line::raw(""),
                sec("Slash Commands  (type then Enter — no AI round-trip)"),
                div(),
                kb("/disasm <path>",  "Disassemble  (+ optional vaddr)"),
                kb("/decompile",      "Decompile  (+ path vaddr)"),
                kb("/functions",      "List all functions"),
                kb("/scan <path>",    "Vulnerability scan"),
                kb("/auto <path>",    "Full auto-analysis + AI summary"),
                kb("/search <hex>",   "Byte-pattern search  (?? = wildcard)"),
                kb("/entropy",        "Section entropy — detect packers"),
                kb("/imports",        "Resolve PLT / PE imports"),
                kb("/cfg  /callgraph","Control-flow / call graph"),
                kb("/yara <vaddr>",   "Generate YARA detection rule"),
                kb("/patch <vaddr>",  "Patch bytes → <file>.patched"),
                kb("/report",         "Export HTML analysis report"),
                kb("/diff <a> <b>",   "Diff two binaries by content hash"),
                kb("/python <file>",  "Run a Python 3 script"),
                kb("/run <plugin>",   "Run a Rhai plugin by name"),
                kb("/plugins",        "List installed plugins"),
                kb("/timeout <n>",    "Set HTTP request timeout (seconds)"),
                kb("/pattern",        "Search panel  ·  n=next  N=prev  Esc=clear"),
                kb("/help",           "Toggle this popup"),
                Line::raw(""),
                sec("Annotations  (persistent in <binary>.kaiju.db)"),
                div(),
                kb("R",               "Rename function at cursor address"),
                kb("c",               "Add comment at cursor address"),
                kb("a",               "Add analyst note (anchors to cursor if set)"),
                kb("d",               "Delete note at cursor  (confirms first)"),
                kb("f",               "Fuzzy-filter Functions tab  (Esc to clear)"),
                Line::raw(""),
                sec("Bookmarks & Xrefs"),
                div(),
                kb("m",               "Bookmark current address"),
                kb("B",               "Bookmarks popup  (0-9 jump · Esc close)"),
                kb("x",               "Xref popup — all CALL/JMP sites to cursor addr"),
                Line::raw(""),
                sec("Input, History & Export"),
                div(),
                kb("↑  ↓",            "Browse sent-message history"),
                kb("Ctrl+R",          "Cycle history into input field"),
                kb("Ctrl+X",          "Cancel current agent turn"),
                kb("Ctrl+E",          "Export markdown summary to clipboard"),
                kb("r",               "Retry last message  (when status: Error)"),
                kb("y",               "Copy panel content to clipboard"),
                kb("Ctrl+C",          "Clear input  ·  quit when input is empty"),
            ];

            // Scrollable: PgUp scrolls down (towards end), PgDn scrolls back up.
            // We render from `help_scroll` lines from the top.
            let text = Text::from(lines);
            let total_lines = Paragraph::new(text.clone())
                .wrap(Wrap { trim: false })
                .line_count(inner.width) as u16;
            let max_scroll = total_lines.saturating_sub(inner.height);
            let scroll = app.help_scroll.min(max_scroll);
            f.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0)),
                inner,
            );
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
    } else if app.is_loading {
        "Ctrl+X:cancel  Tab:tab  ?:help"
    } else {
        "Tab  1-8:tab  s:split  R:rename  c:comment  a:note  ?:help  /:cmd  Ctrl+E:export"
    };

    // Right-side info: arch · focused addr · token budget bar
    let arch_part = app.binary_arch.as_deref()
        .map(|a| format!("{}  ·  ", a))
        .unwrap_or_default();
    let addr_part = app.focused_addr
        .map(|a| format!("@ 0x{:x}  ·  ", a))
        .unwrap_or_default();

    // Token budget visual: [████░░░░░░] XX%
    const MAX_HISTORY_CHARS: usize = 80_000;
    const BAR_BLOCKS: usize = 10;
    let token_part = if !app.context_entries.is_empty() {
        let chars: usize = app.context_entries.iter().map(|e| e.char_count).sum();
        let pct = (chars * 100) / MAX_HISTORY_CHARS.max(1);
        let pct_clamped = pct.min(100);
        let filled = (pct_clamped * BAR_BLOCKS) / 100;
        let bar = format!("{}{}",
            "█".repeat(filled),
            "░".repeat(BAR_BLOCKS.saturating_sub(filled)),
        );
        format!("[{}] {}%", bar, pct_clamped)
    } else {
        String::new()
    };

    let info = format!("{}{}{}", arch_part, addr_part, token_part);

    // Determine token bar colour
    let token_chars: usize = app.context_entries.iter().map(|e| e.char_count).sum();
    let token_pct = if MAX_HISTORY_CHARS > 0 { (token_chars * 100) / MAX_HISTORY_CHARS } else { 0 };
    let info_color = if token_pct >= 80 {
        Color::Red
    } else if token_pct >= 50 {
        Color::Yellow
    } else {
        Color::Cyan
    };

    // Progress bar for multi-tool turns: [■■■□□□□] step/total
    let progress_part = if let Some((step, total, ref label)) = app.progress {
        const PBAR_W: usize = 8;
        let filled = if total > 0 { (step * PBAR_W) / total } else { 0 };
        let bar = format!("{}{}",
            "■".repeat(filled),
            "□".repeat(PBAR_W.saturating_sub(filled)),
        );
        format!("  [{bar}] {step}/{total} {label}")
    } else {
        String::new()
    };

    // Build the status line: icon + status | keybinds … info
    let left = format!(" {} {}{}", icon, app.status, progress_part);
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
        Span::styled(info, Style::new().fg(info_color)),
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
        .borders(Borders::TOP | Borders::BOTTOM)
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

// ─ Notes panel ────────────────────────────────────────────────────────────────

fn render_notes(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .title(Span::styled(
            " Notes  (a=add · d=delete · j/k=navigate) ",
            Style::new().fg(Color::Magenta).bold(),
        ))
        .border_style(Style::new().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.notes.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "  (no notes yet)",
                    Style::new().fg(Color::DarkGray).italic(),
                )),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  a", Style::new().fg(Color::Cyan).bold()),
                    Span::styled("  Add a new analyst note (optionally anchored to cursor address)", Style::new().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("  d", Style::new().fg(Color::Cyan).bold()),
                    Span::styled("  Delete the note at the cursor line", Style::new().fg(Color::Gray)),
                ]),
            ])
            .wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    let cursor_idx = app.panel_cursor[Tab::Notes as usize];
    let mut lines: Vec<Line> = Vec::new();

    for (i, note) in app.notes.iter().enumerate() {
        let addr_part = note.vaddr
            .map(|a| format!(" @ 0x{:x}", a))
            .unwrap_or_default();

        let header = Line::from(vec![
            Span::styled(
                format!("  [{:>3}]", note.id),
                if i == cursor_idx {
                    Style::new().fg(Color::Cyan).bold().bg(Color::Rgb(20, 20, 60))
                } else {
                    Style::new().fg(Color::DarkGray)
                },
            ),
            Span::styled(
                addr_part,
                Style::new().fg(Color::Yellow),
            ),
            Span::styled(
                format!("  {}", note.timestamp),
                Style::new().fg(Color::DarkGray).italic(),
            ),
        ]);
        lines.push(header);

        // Note text — indent with a vertical bar
        for text_line in note.text.lines() {
            lines.push(Line::from(vec![
                Span::styled(
                    "    │  ",
                    if i == cursor_idx {
                        Style::new().fg(Color::Magenta).bg(Color::Rgb(20, 20, 60))
                    } else {
                        Style::new().fg(Color::DarkGray)
                    },
                ),
                Span::styled(
                    text_line.to_string(),
                    if i == cursor_idx {
                        Style::new().fg(Color::White).bg(Color::Rgb(20, 20, 60))
                    } else {
                        Style::new().fg(Color::White)
                    },
                ),
            ]));
        }
        lines.push(Line::raw(""));
    }

    let scroll = app.scroll[Tab::Notes as usize];
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
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
fn highlight_disasm_arch(line: &str, arch: Option<&str>) -> Line<'static> {
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

    // Split operands from inline comment ("; comment") produced by the disasm tool
    // when a call target has a known name or the tool appended a DWARF annotation.
    let (operands_part, comment_part) = if let Some(sc) = operands.find(';') {
        (operands[..sc].trim_end(), Some(operands[sc..].trim()))
    } else {
        (operands, None)
    };

    if !operands_part.is_empty() {
        spans.push(Span::raw("  "));
        spans.extend(highlight_operands_arch(operands_part, arch));
    }

    // Inline comment — muted but readable against a dark background
    if let Some(comment) = comment_part {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            comment.to_string(),
            Style::new().fg(Color::Rgb(160, 160, 180)).italic(),
        ));
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

fn is_register_for_arch(s: &str, arch: Option<&str>) -> bool {
    let lower = s.to_ascii_lowercase();
    let sl = lower.as_str();
    if X86_REGS.contains(&sl) { return true; }
    if let Some(a) = arch {
        if let Some(extra) = crate::arch::regs_for_arch(a) {
            return extra.contains(&sl);
        }
    }
    false
}

fn is_immediate(s: &str) -> bool {
    let s = s.trim_end_matches('h');
    s.starts_with("0x") || s.starts_with('-') || s.parse::<i64>().is_ok() || {
        // Hex without 0x prefix (iced-x86 uses uppercase H suffix, e.g. "0FFFFFFFFh")
        !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// Color each operand token in a comma-separated operand list.
fn highlight_operands_arch(operands: &str, arch: Option<&str>) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let parts: Vec<&str> = operands.split(", ").collect();

    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(", ", Style::new().fg(Color::DarkGray)));
        }

        let p = part.trim();
        let lower = p.to_ascii_lowercase();

        if is_register_for_arch(p, arch) {
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::Green)));
        } else if is_immediate(p) {
            spans.push(Span::styled(p.to_string(), Style::new().fg(Color::Magenta)));
        } else if p.contains('[') {
            // Memory reference, e.g. "qword ptr [rsp+10h]"
            spans.extend(highlight_mem_ref_arch(p, arch));
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
fn highlight_mem_ref_arch(s: &str, arch: Option<&str>) -> Vec<Span<'static>> {
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
        spans.extend(highlight_mem_inner_arch(inner, arch));

        spans.push(Span::styled("]", Style::new().fg(Color::White)));
        if !suffix.is_empty() {
            spans.push(Span::raw(suffix.to_string()));
        }
    } else {
        spans.push(Span::raw(s.to_string()));
    }
    spans
}

fn highlight_mem_inner_arch(s: &str, arch: Option<&str>) -> Vec<Span<'static>> {
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
            if is_register_for_arch(&token, arch) {
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
        if is_register_for_arch(&token, arch) {
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
