//! MCP tool definitions + dispatch.
//!
//! The MCP surface is intentionally smaller than `crate::tools::all_definitions()`:
//! analyst-oriented composite tools (`auto_analyze`, `explain_function`) are
//! removed in favour of letting the LLM client orchestrate primitives.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::core::{analysis, events::Source, project_store, workspace::Workspace, EventBus};

/// Return the JSON Schema list of all MCP tools.  Shape mirrors what
/// `tools/list` returns to the MCP client.
pub fn tool_definitions() -> Value {
    json!([
        // ── read tools ────────────────────────────────────────────────
        def(
            "file_info",
            "Format, arch, entry point, sections, imports.",
            obj_no_args()
        ),
        def("sections", "List binary sections.", obj_no_args()),
        def(
            "imports",
            "List imported symbols (ELF PLT or PE imports).",
            obj_no_args()
        ),
        def(
            "list_functions",
            "Symbol table or prologue-scan function list.",
            json!({ "type": "object", "properties": { "as_json": { "type": "boolean" } } })
        ),
        def(
            "disassemble",
            "Disassemble at a virtual address until ret.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string", "description": "0x-prefixed hex vaddr" },
                    "length": { "type": "integer" }
                },
                "required": ["vaddr"]
            })
        ),
        def(
            "decompile",
            "Lift a function to pseudo-C.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "function_context",
            "Disassembly + decompile + xrefs for one function.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "xrefs_to",
            "Find all call/jmp sites that target a vaddr.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "xrefs_data",
            "Find every instruction that reads or writes a vaddr.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "strings_extract",
            "Extract printable strings from the binary.",
            json!({
                "type": "object",
                "properties": {
                    "section": { "type": "string" },
                    "min_len": { "type": "integer" }
                }
            })
        ),
        def(
            "cfg_view",
            "Control-flow graph for a function.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "callgraph",
            "Static call graph up to max_depth levels.",
            json!({
                "type": "object",
                "properties": { "max_depth": { "type": "integer" } }
            })
        ),
        def(
            "scan_vulnerabilities",
            "Heuristic scan for dangerous patterns.",
            json!({
                "type": "object",
                "properties": { "max_fns": { "type": "integer" } }
            })
        ),
        def(
            "match_all_functions",
            "Match function fingerprints against the local hash database.",
            json!({
                "type": "object",
                "properties": { "max_results": { "type": "integer" } }
            })
        ),
        def(
            "lookup_function_hash",
            "Lookup known names for a function fingerprint.",
            json!({
                "type": "object",
                "properties": { "vaddr": { "type": "string" } },
                "required": ["vaddr"]
            })
        ),
        def(
            "register_function_hash",
            "Register a function fingerprint under a known name.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string" },
                    "name": { "type": "string" }
                },
                "required": ["vaddr", "name"]
            })
        ),
        def(
            "search_bytes",
            "Hex byte-pattern search with `??` wildcards.",
            json!({
                "type": "object",
                "properties": { "pattern": { "type": "string" } },
                "required": ["pattern"]
            })
        ),
        // ── write tools (carry implicit source=claude/codex) ──────────
        def(
            "rename_function",
            "Assign a name to a function vaddr.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string" },
                    "name": { "type": "string" }
                },
                "required": ["vaddr", "name"]
            })
        ),
        def(
            "add_comment",
            "Attach a comment to an address.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string" },
                    "comment": { "type": "string" }
                },
                "required": ["vaddr", "comment"]
            })
        ),
        def(
            "add_note",
            "Save a free-form analyst note, optionally anchored to a vaddr.",
            json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "vaddr": { "type": "string" }
                },
                "required": ["text"]
            })
        ),
        def(
            "set_vuln_score",
            "Assign a 0-10 vulnerability score to a function.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string" },
                    "score": { "type": "integer", "minimum": 0, "maximum": 10 }
                },
                "required": ["vaddr", "score"]
            })
        ),
        def(
            "patch_bytes",
            "Write bytes at a file offset or vaddr. Requires --allow-patch on serve.",
            json!({
                "type": "object",
                "properties": {
                    "vaddr": { "type": "string" },
                    "bytes_hex": { "type": "string" }
                },
                "required": ["vaddr", "bytes_hex"]
            })
        ),
        def(
            "run_binary",
            "Execute the active binary with optional argv/stdin. Requires --allow-exec on serve.",
            json!({
                "type": "object",
                "properties": {
                    "args": { "type": "array", "items": { "type": "string" } },
                    "stdin": { "type": "string" },
                    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 30 }
                }
            })
        ),
    ])
}

/// Helper to assemble one tool entry.
fn def(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
    })
}

fn obj_no_args() -> Value {
    json!({ "type": "object", "properties": {} })
}

/// Dispatch an MCP tool call against a Workspace.  Writes from MCP carry
/// `source: Claude` so the UI can attribute them.  Pass `bus` when running
/// inside the daemon so writes publish events; pass None for standalone
/// shim mode (writes still persist but no live events fire).
pub fn dispatch_mcp(
    workspace: &Workspace,
    bus: Option<&EventBus>,
    name: &str,
    args: &Value,
) -> Result<String> {
    match name {
        // ── read ──────────────────────────────────────────────────────
        "file_info" => analysis::file_info(workspace),
        "sections" => analysis::sections(workspace),
        "imports" => analysis::imports(workspace),
        "list_functions" => {
            let as_json = args
                .get("as_json")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            analysis::list_functions(workspace, as_json)
        }
        "disassemble" => {
            let v = vaddr_arg(args, "vaddr")?;
            let len = args
                .get("length")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);
            analysis::disassemble(workspace, v, len)
        }
        "decompile" => {
            let v = vaddr_arg(args, "vaddr")?;
            analysis::decompile(workspace, v)
        }
        "function_context" => {
            let v = vaddr_arg(args, "vaddr")?;
            analysis::function_context(workspace, v)
        }
        "xrefs_to" => {
            let v = vaddr_arg(args, "vaddr")?;
            analysis::xrefs_to(workspace, v)
        }
        "xrefs_data" => {
            let v = vaddr_arg(args, "vaddr")?;
            analysis::xrefs_data(workspace, v)
        }
        "strings_extract" => {
            let section = args.get("section").and_then(|v| v.as_str());
            let min_len = args
                .get("min_len")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);
            analysis::strings_extract(workspace, section, min_len)
        }
        "cfg_view" => {
            let v = vaddr_arg(args, "vaddr")?;
            analysis::cfg_view(workspace, v)
        }
        "callgraph" => {
            let d = args
                .get("max_depth")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);
            analysis::call_graph(workspace, d)
        }
        "scan_vulnerabilities" => {
            let m = args
                .get("max_fns")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);
            analysis::scan_vulnerabilities(workspace, m)
        }
        "match_all_functions" => {
            let max_results = args
                .get("max_results")
                .and_then(|v| v.as_u64())
                .unwrap_or(50)
                .min(500) as usize;
            let result = crate::tools::dispatch(
                "match_all_functions",
                &json!({ "path": workspace.binary_path_str(), "max_results": max_results }),
            );
            Ok(result.output)
        }
        "lookup_function_hash" => {
            let v = vaddr_arg(args, "vaddr")?;
            let result = crate::tools::dispatch(
                "lookup_function_hash",
                &json!({ "path": workspace.binary_path_str(), "vaddr": v }),
            );
            Ok(result.output)
        }
        "register_function_hash" => {
            let v = vaddr_arg(args, "vaddr")?;
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing name"))?;
            let result = crate::tools::dispatch(
                "register_function_hash",
                &json!({ "path": workspace.binary_path_str(), "vaddr": v, "name": name }),
            );
            Ok(result.output)
        }
        "search_bytes" => {
            let p = args
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing pattern"))?;
            analysis::search_bytes(workspace, p)
        }

        // ── write ─────────────────────────────────────────────────────
        "rename_function" => {
            let v = vaddr_arg(args, "vaddr")?;
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing name"))?;
            if let Some(bus) = bus {
                project_store::rename_function(workspace, bus, v, name, Source::Claude)?;
            } else {
                // Standalone shim: persist directly without an event.
                workspace.with_project(|p| p.renames.insert(v, name.to_string()));
                workspace.save_project()?;
            }
            Ok(format!("renamed 0x{:x} → {}", v, name))
        }
        "add_comment" => {
            let v = vaddr_arg(args, "vaddr")?;
            let text = args
                .get("comment")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing comment"))?;
            if let Some(bus) = bus {
                project_store::add_comment(workspace, bus, v, text, Source::Claude)?;
            } else {
                workspace.with_project(|p| p.comments.insert(v, text.to_string()));
                workspace.save_project()?;
            }
            Ok(format!("comment @ 0x{:x}", v))
        }
        "add_note" => {
            let text = args
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing text"))?;
            let v = args
                .get("vaddr")
                .and_then(|v| v.as_str())
                .and_then(parse_vaddr);
            let note_id = if let Some(bus) = bus {
                project_store::add_note(workspace, bus, text, v, Source::Claude)?.id
            } else {
                let n = workspace.with_project(|p| {
                    let new_id = (p.notes.iter().map(|n| n.id).max().unwrap_or(0)) + 1;
                    let note = crate::project::Note {
                        id: new_id,
                        vaddr: v,
                        text: text.to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    p.notes.push(note);
                    new_id
                });
                workspace.save_project()?;
                n
            };
            Ok(format!("note #{}", note_id))
        }
        "set_vuln_score" => {
            let v = vaddr_arg(args, "vaddr")?;
            let score = args
                .get("score")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing score"))? as u8;
            if let Some(bus) = bus {
                project_store::set_vuln_score(workspace, bus, v, score, Source::Claude)?;
            } else {
                workspace.with_project(|p| p.vuln_scores.insert(v, score.min(10)));
                workspace.save_project()?;
            }
            Ok(format!("vuln_score 0x{:x} = {}", v, score))
        }
        "patch_bytes" => {
            if !workspace.policy().allow_patch {
                anyhow::bail!("patch_bytes blocked: daemon was started without --allow-patch");
            }
            let v = vaddr_arg(args, "vaddr")?;
            let bytes = args
                .get("bytes_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing bytes_hex"))?;
            let result = crate::tools::dispatch(
                "patch_bytes",
                &json!({
                    "path": workspace.binary_path_str(),
                    "vaddr": v,
                    "hex_bytes": bytes,
                }),
            );
            Ok(result.output)
        }
        "run_binary" => {
            if !workspace.policy().allow_exec {
                anyhow::bail!("run_binary blocked: daemon was started without --allow-exec");
            }
            let argv: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let result = crate::tools::dispatch(
                "run_binary",
                &json!({
                    "path": workspace.binary_path_str(),
                    "args": argv,
                    "stdin": args.get("stdin").and_then(|v| v.as_str()),
                    "timeout_secs": args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(10),
                }),
            );
            Ok(result.output)
        }
        other => Err(anyhow!("unknown MCP tool: {}", other)),
    }
}

fn vaddr_arg(args: &Value, key: &str) -> Result<u64> {
    let s = args
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing {}", key))?;
    parse_vaddr(s).ok_or_else(|| anyhow!("invalid vaddr: {}", s))
}

fn parse_vaddr(s: &str) -> Option<u64> {
    let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).ok()
}
