//! Rhai-based plugin / scripting engine for KaijuLab.
//!
//! Scripts are `.rhai` files stored in `~/.kaiju/plugins/`.
//! Every RE tool available to the LLM is also callable from scripts as a
//! top-level function.  A `binary` global variable holds the path of the
//! binary currently loaded in the TUI (passed in by the caller).
//!
//! ## Quick example
//!
//! ```rhai
//! // ~/.kaiju/plugins/vuln_annotate.rhai
//! // Scan every function and attach a note to those with score >= 7.
//! let report = scan_vulnerabilities(binary);
//! print(report);
//! ```
//!
//! ## Available functions
//!
//! **Analysis (read-only)**
//! - `file_info(path)` → String
//! - `disassemble(path, vaddr)` → String   (default length 128 bytes)
//! - `disassemble_at(path, vaddr, length)` → String
//! - `list_functions(path)` → String
//! - `strings_extract(path)` → String
//! - `decompile(path, vaddr)` → String
//! - `scan_vulnerabilities(path)` → String
//! - `xrefs_to(path, vaddr)` → String
//! - `cfg_view(path, vaddr)` → String
//! - `call_graph(path)` → String
//! - `hexdump(path, offset, length)` → String
//! - `section_entropy(path)` → String
//! - `load_project(path)` → String
//! - `list_notes(path)` → String
//! - `get_vuln_scores(path)` → String
//! - `dwarf_info(path)` → String
//! - `search_bytes(path, pattern)` → String  (e.g. `"E8 ?? ?? ?? ??"`)
//! - `generate_yara(path, vaddr)` → String
//!
//! **Annotation (write)**
//! - `rename_function(path, vaddr, name)` → String
//! - `add_comment(path, vaddr, text)` → String
//! - `add_note(path, text)` → String
//! - `add_note_at(path, text, vaddr)` → String
//! - `set_vuln_score(path, vaddr, score)` → String
//! - `rename_variable(path, fn_vaddr, old_name, new_name)` → String
//!
//! **Utility**
//! - `hex(n)` → String  (formats an integer as `"0x…"`)
//! - `parse_addr(s)` → i64  (parses `"0x401000"` or `"4198400"`)
//! - `plugins_dir()` → String  (path to the plugins directory)

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rhai::{Engine, Scope};
use serde_json::json;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Result of executing a plugin script.
#[derive(Debug, Clone)]
pub struct PluginOutput {
    /// All text written via `print()` / `debug()` inside the script.
    pub text:  String,
    /// Non-empty when the script raised an uncaught Rhai error.
    pub error: Option<String>,
}

impl PluginOutput {
    fn ok(text: String) -> Self {
        PluginOutput { text, error: None }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        PluginOutput { text: String::new(), error: Some(msg.into()) }
    }
}

/// Metadata scraped from a plugin file.
#[derive(Debug, Clone)]
pub struct PluginMeta {
    /// File stem (e.g. `"vuln_annotate"` for `vuln_annotate.rhai`).
    pub name: String,
    /// Absolute path to the `.rhai` file.
    pub path: PathBuf,
    /// First comment line in the file, if any (after stripping `//`).
    pub description: Option<String>,
}

// ─── Plugin directory ─────────────────────────────────────────────────────────

/// Returns `~/.kaiju/plugins`, creating it if it does not exist.
pub fn plugins_dir() -> PathBuf {
    let dir = home_dir().join(".kaiju").join("plugins");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// List all `.rhai` files in the plugins directory, sorted by name.
pub fn list_plugins() -> Vec<PluginMeta> {
    let dir = plugins_dir();
    let mut out: Vec<PluginMeta> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rhai"))
            .map(|e| {
                let path = e.path();
                let name = path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string();
                let description = first_comment(&path);
                PluginMeta { name, path, description }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Find a named plugin (file stem match) in the plugins directory.
pub fn find_plugin(name: &str) -> Option<PluginMeta> {
    list_plugins().into_iter().find(|m| m.name == name)
}

/// Read the first `//` comment line from a `.rhai` file as a description.
fn first_comment(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("//") {
            let desc = rest.trim().to_string();
            if !desc.is_empty() {
                return Some(desc);
            }
        }
        if !t.is_empty() && !t.starts_with("//") {
            break;
        }
    }
    None
}

// ─── Plugin engine ────────────────────────────────────────────────────────────

/// Build a Rhai `Engine` with all KaijuLab RE tools registered as functions.
/// The returned engine is ready for use with `run_source()` / `run_file()`.
///
/// The `print_buf` accumulates everything the script sends to `print()`.
pub fn build_engine(print_buf: Arc<Mutex<String>>) -> Engine {
    let mut engine = Engine::new();

    // ── Capture print() output ────────────────────────────────────────────────
    {
        let buf = print_buf.clone();
        engine.on_print(move |s| {
            let mut b = buf.lock().unwrap();
            b.push_str(s);
            b.push('\n');
        });
    }
    {
        // debug() also captured
        let buf = print_buf.clone();
        engine.on_debug(move |s, src, pos| {
            let mut b = buf.lock().unwrap();
            if let Some(src) = src {
                b.push_str(&format!("[{}@{}] {}\n", src, pos, s));
            } else {
                b.push_str(&format!("[debug] {}\n", s));
            }
        });
    }

    // ── Analysis tools ────────────────────────────────────────────────────────

    engine.register_fn("file_info", |path: &str| -> String {
        call("file_info", json!({"path": path}))
    });

    engine.register_fn("disassemble", |path: &str, vaddr: i64| -> String {
        call("disassemble", json!({"path": path, "vaddr": vaddr as u64, "length": 128}))
    });

    engine.register_fn("disassemble_at", |path: &str, vaddr: i64, length: i64| -> String {
        call("disassemble", json!({"path": path, "vaddr": vaddr as u64, "length": length as usize}))
    });

    engine.register_fn("list_functions", |path: &str| -> String {
        call("list_functions", json!({"path": path, "max_results": 500}))
    });

    engine.register_fn("strings_extract", |path: &str| -> String {
        call("strings_extract", json!({"path": path, "min_len": 4, "max_results": 200}))
    });

    engine.register_fn("decompile", |path: &str, vaddr: i64| -> String {
        call("decompile", json!({"path": path, "vaddr": vaddr as u64}))
    });

    engine.register_fn("scan_vulnerabilities", |path: &str| -> String {
        call("scan_vulnerabilities", json!({"path": path, "max_fns": 50}))
    });

    engine.register_fn("xrefs_to", |path: &str, vaddr: i64| -> String {
        call("xrefs_to", json!({"path": path, "vaddr": vaddr as u64}))
    });

    engine.register_fn("cfg_view", |path: &str, vaddr: i64| -> String {
        call("cfg_view", json!({"path": path, "vaddr": vaddr as u64}))
    });

    engine.register_fn("call_graph", |path: &str| -> String {
        call("call_graph", json!({"path": path, "max_depth": 5}))
    });

    engine.register_fn("hexdump", |path: &str, offset: i64, length: i64| -> String {
        call("hexdump", json!({"path": path, "offset": offset as usize, "length": length as usize}))
    });

    engine.register_fn("section_entropy", |path: &str| -> String {
        call("section_entropy", json!({"path": path}))
    });

    engine.register_fn("load_project", |path: &str| -> String {
        call("load_project", json!({"path": path}))
    });

    engine.register_fn("list_notes", |path: &str| -> String {
        call("list_notes", json!({"path": path}))
    });

    engine.register_fn("get_vuln_scores", |path: &str| -> String {
        call("get_vuln_scores", json!({"path": path}))
    });

    engine.register_fn("dwarf_info", |path: &str| -> String {
        call("dwarf_info", json!({"path": path}))
    });

    engine.register_fn("search_bytes", |path: &str, pattern: &str| -> String {
        call("search_bytes", json!({"path": path, "pattern": pattern}))
    });

    engine.register_fn("generate_yara", |path: &str, vaddr: i64| -> String {
        call("generate_yara_rule", json!({"path": path, "vaddr": vaddr as u64}))
    });

    engine.register_fn("identify_library_functions", |path: &str| -> String {
        call("identify_library_functions", json!({"path": path}))
    });

    engine.register_fn("diff_binary", |path_a: &str, path_b: &str| -> String {
        call("diff_binary", json!({"path_a": path_a, "path_b": path_b}))
    });

    engine.register_fn("explain_function", |path: &str, vaddr: i64| -> String {
        call("explain_function", json!({"path": path, "vaddr": vaddr as u64}))
    });

    // ── Annotation tools (write) ──────────────────────────────────────────────

    engine.register_fn("rename_function", |path: &str, vaddr: i64, name: &str| -> String {
        call("rename_function", json!({"path": path, "vaddr": vaddr as u64, "name": name}))
    });

    engine.register_fn("add_comment", |path: &str, vaddr: i64, text: &str| -> String {
        call("add_comment", json!({"path": path, "vaddr": vaddr as u64, "text": text}))
    });

    engine.register_fn("add_note", |path: &str, text: &str| -> String {
        call("add_note", json!({"path": path, "text": text}))
    });

    engine.register_fn("add_note_at", |path: &str, text: &str, vaddr: i64| -> String {
        call("add_note", json!({"path": path, "text": text, "vaddr": vaddr as u64}))
    });

    engine.register_fn("set_vuln_score", |path: &str, vaddr: i64, score: i64| -> String {
        call("set_vuln_score", json!({"path": path, "vaddr": vaddr as u64, "score": score as u8}))
    });

    engine.register_fn("rename_variable", |path: &str, fn_vaddr: i64, old: &str, new: &str| -> String {
        call("rename_variable", json!({"path": path, "fn_vaddr": fn_vaddr as u64, "old_name": old, "new_name": new}))
    });

    engine.register_fn("set_return_type", |path: &str, vaddr: i64, ty: &str| -> String {
        call("set_return_type", json!({"path": path, "vaddr": vaddr as u64, "return_type": ty}))
    });

    engine.register_fn("set_param_type", |path: &str, vaddr: i64, n: i64, ty: &str| -> String {
        call("set_param_type", json!({"path": path, "vaddr": vaddr as u64, "param_index": n, "param_type": ty}))
    });

    engine.register_fn("set_param_name", |path: &str, vaddr: i64, n: i64, name: &str| -> String {
        call("set_param_name", json!({"path": path, "vaddr": vaddr as u64, "param_index": n, "param_name": name}))
    });

    engine.register_fn("delete_note", |path: &str, id: i64| -> String {
        call("delete_note", json!({"path": path, "id": id}))
    });

    // ── Utility functions ─────────────────────────────────────────────────────

    // Format an integer as a hex string: hex(0x401000) → "0x401000"
    engine.register_fn("hex", |n: i64| -> String {
        format!("0x{:x}", n as u64)
    });

    // Parse a hex or decimal address string: parse_addr("0x401000") → 4198400i64
    engine.register_fn("parse_addr", |s: &str| -> i64 {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).unwrap_or(0)
        } else {
            s.parse::<i64>().unwrap_or(0)
        }
    });

    // Returns the path to the plugins directory
    engine.register_fn("plugins_dir", || -> String {
        plugins_dir().to_string_lossy().into_owned()
    });

    engine
}

/// Internal: call a tool and return its output string.
fn call(name: &str, args: serde_json::Value) -> String {
    crate::tools::dispatch(name, &args).output
}

// ─── Public run helpers ───────────────────────────────────────────────────────

/// Run a Rhai source string with `binary` set to `binary_path`.
pub fn run_source(source: &str, binary_path: &str) -> PluginOutput {
    let print_buf = Arc::new(Mutex::new(String::new()));
    let engine = build_engine(print_buf.clone());
    let mut scope = Scope::new();
    scope.push("binary", binary_path.to_string());

    match engine.eval_with_scope::<rhai::Dynamic>(&mut scope, source) {
        Ok(_) => {
            let text = print_buf.lock().unwrap().clone();
            PluginOutput::ok(text)
        }
        Err(e) => {
            let text = print_buf.lock().unwrap().clone();
            PluginOutput { text, error: Some(e.to_string()) }
        }
    }
}

/// Run a `.rhai` file from `path` with `binary` set to `binary_path`.
pub fn run_file(script_path: &Path, binary_path: &str) -> PluginOutput {
    let source = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => return PluginOutput::error(format!(
            "Cannot read '{}': {}", script_path.display(), e
        )),
    };
    run_source(&source, binary_path)
}

/// Find a plugin by name (file stem) in `~/.kaiju/plugins/` and run it.
pub fn run_named(name: &str, binary_path: &str) -> PluginOutput {
    match find_plugin(name) {
        Some(meta) => run_file(&meta.path, binary_path),
        None => PluginOutput::error(format!(
            "Plugin '{}' not found in {}",
            name,
            plugins_dir().display()
        )),
    }
}

// ─── Formatted listing ────────────────────────────────────────────────────────

/// Human-readable list of all plugins, suitable for TUI display.
pub fn format_plugin_list() -> String {
    let metas = list_plugins();
    if metas.is_empty() {
        return format!(
            "No plugins found.\n\nCreate .rhai scripts in: {}\n\nSee `help plugins` for the scripting API.",
            plugins_dir().display()
        );
    }
    let mut out = format!("Plugins ({}):\n\n", metas.len());
    out.push_str(&format!("  {:<30}  {}\n  {}\n", "Name", "Description", "─".repeat(60)));
    for m in &metas {
        let desc = m.description.as_deref().unwrap_or("—");
        out.push_str(&format!("  {:<30}  {}\n", m.name, desc));
    }
    out.push_str(&format!("\nPlugins directory: {}\n", plugins_dir().display()));
    out.push_str("Run a plugin:  run <name>  or  run <name> /path/to/binary\n");
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_simple_print() {
        let out = run_source(r#"print("hello from rhai");"#, "");
        assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
        assert!(out.text.contains("hello from rhai"), "got: {}", out.text);
    }

    #[test]
    fn hex_utility_fn() {
        let out = run_source(r#"print(hex(0x401000));"#, "");
        assert!(out.text.contains("0x401000"), "got: {}", out.text);
    }

    #[test]
    fn parse_addr_hex() {
        let out = run_source(r#"print(parse_addr("0x401000"));"#, "");
        assert!(out.text.contains("4198400"), "got: {}", out.text);
    }

    #[test]
    fn binary_global_set() {
        let out = run_source(r#"print(binary);"#, "/bin/ls");
        assert!(out.text.contains("/bin/ls"), "got: {}", out.text);
    }

    #[test]
    fn syntax_error_reported() {
        let out = run_source("let x = ;", "");
        assert!(out.error.is_some(), "should have reported error");
    }

    #[test]
    fn file_info_reachable() {
        // Pass a non-existent path — we just verify the function exists and
        // returns an error string rather than panicking.
        let out = run_source(r#"let r = file_info("/nonexistent_kaijulab_test"); print(r);"#, "");
        assert!(out.error.is_none(), "Rhai error: {:?}", out.error);
        // Should mention an error from the tool itself
        assert!(!out.text.is_empty(), "should have produced output");
    }
}
