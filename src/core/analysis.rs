//! Typed wrappers around `crate::tools::dispatch`.  Each public function
//! constructs the JSON-arg shape the inner tool expects, dispatches, and
//! returns the raw output string (tools return human-readable text — the
//! browser renders it; we only normalise error paths here).

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::tools;

use super::{decompile as enhanced_decompile, recovery, workspace::Workspace};

fn raw(name: &str, args: Value) -> Result<String> {
    let r = tools::dispatch(name, &args);
    if r.output.starts_with("Error:") {
        Err(anyhow!(r.output))
    } else {
        Ok(r.output)
    }
}

pub fn file_info(ws: &Workspace) -> Result<String> {
    raw("file_info", json!({ "path": ws.binary_path_str() }))
}

pub fn sections(ws: &Workspace) -> Result<String> {
    // `file_info` already lists sections; expose a section_entropy summary
    // here so the section pane has dedicated data.  Falls back to file_info
    // if the binary is too small to compute entropy.
    raw("section_entropy", json!({ "path": ws.binary_path_str() })).or_else(|_| file_info(ws))
}

pub fn imports(ws: &Workspace) -> Result<String> {
    // Try ELF first, then PE; whichever applies returns content, the other errors.
    if let Ok(out) = raw("resolve_plt", json!({ "path": ws.binary_path_str() })) {
        return Ok(out);
    }
    raw(
        "resolve_pe_imports",
        json!({ "path": ws.binary_path_str() }),
    )
}

pub fn strings_extract(
    ws: &Workspace,
    section: Option<&str>,
    min_len: Option<u32>,
) -> Result<String> {
    let mut args = json!({ "path": ws.binary_path_str() });
    if let Some(s) = section {
        args["section"] = json!(s);
    }
    if let Some(m) = min_len {
        args["min_len"] = json!(m);
    }
    raw("strings_extract", args)
}

pub fn list_functions(ws: &Workspace, as_json: bool) -> Result<String> {
    if as_json {
        if let Ok(index) = recovery::recover(ws.binary_path(), 1000) {
            return Ok(serde_json::to_string(&serde_json::json!({
                "source": "professional_recovery",
                "total": index.functions.len(),
                "functions": index.functions.iter().map(|f| serde_json::json!({
                    "address": f.start,
                    "vaddr": f.start,
                    "size": f.size,
                    "name": f.name,
                    "confidence": f.confidence,
                    "blocks": f.blocks.len(),
                    "edges": f.edges.len(),
                    "source": f.source,
                })).collect::<Vec<_>>(),
            }))?);
        }
    }
    raw(
        "list_functions",
        json!({ "path": ws.binary_path_str(), "json": as_json }),
    )
}

pub fn disassemble(ws: &Workspace, vaddr: u64, length: Option<u32>) -> Result<String> {
    let mut args = json!({ "path": ws.binary_path_str(), "vaddr": vaddr });
    if let Some(l) = length {
        args["length"] = json!(l);
    }
    raw("disassemble", args)
}

pub fn decompile(ws: &Workspace, vaddr: u64) -> Result<String> {
    enhanced_decompile::decompile_enhanced_path(ws.binary_path(), vaddr).or_else(|_| {
        raw(
            "decompile",
            json!({ "path": ws.binary_path_str(), "vaddr": vaddr }),
        )
    })
}

pub fn xrefs_to(ws: &Workspace, vaddr: u64) -> Result<String> {
    if let Ok(xrefs) = recovery::xrefs_to(ws.binary_path(), vaddr, 2000) {
        if !xrefs.is_empty() {
            return Ok(serde_json::to_string_pretty(&serde_json::json!({
                "source": "professional_recovery",
                "target": format!("0x{vaddr:x}"),
                "xrefs": xrefs,
            }))?);
        }
    }
    raw(
        "xrefs_to",
        json!({ "path": ws.binary_path_str(), "vaddr": vaddr }),
    )
}

pub fn xrefs_data(ws: &Workspace, vaddr: u64) -> Result<String> {
    raw(
        "xrefs_data",
        json!({ "path": ws.binary_path_str(), "vaddr": vaddr }),
    )
}

pub fn cfg_view(ws: &Workspace, vaddr: u64) -> Result<String> {
    if let Ok(Some(function)) = recovery::cfg_for(ws.binary_path(), vaddr, 2000) {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "source": "professional_recovery",
            "function": function,
        }))?);
    }
    raw(
        "cfg_view",
        json!({ "path": ws.binary_path_str(), "vaddr": vaddr }),
    )
}

pub fn call_graph(ws: &Workspace, max_depth: Option<u32>) -> Result<String> {
    let mut args = json!({ "path": ws.binary_path_str() });
    if let Some(d) = max_depth {
        args["max_depth"] = json!(d);
    }
    raw("call_graph", args)
}

pub fn function_context(ws: &Workspace, vaddr: u64) -> Result<String> {
    // Compose disassemble + decompile + xrefs_to into one block.  This is a
    // common Claude-Code workflow primitive.
    let mut out = String::new();
    out.push_str("# function context\n");
    if let Ok(d) = disassemble(ws, vaddr, Some(256)) {
        out.push_str("\n## disassembly\n");
        out.push_str(&d);
    }
    if let Ok(d) = decompile(ws, vaddr) {
        out.push_str("\n## decompile\n");
        out.push_str(&d);
    }
    if let Ok(x) = xrefs_to(ws, vaddr) {
        out.push_str("\n## xrefs to\n");
        out.push_str(&x);
    }
    Ok(out)
}

pub fn scan_vulnerabilities(ws: &Workspace, max_fns: Option<u32>) -> Result<String> {
    let mut args = json!({ "path": ws.binary_path_str() });
    if let Some(m) = max_fns {
        args["max_fns"] = json!(m);
    }
    raw("scan_vulnerabilities", args)
}

pub fn search_bytes(ws: &Workspace, pattern: &str) -> Result<String> {
    raw(
        "search_bytes",
        json!({ "path": ws.binary_path_str(), "pattern": pattern }),
    )
}

pub fn section_entropy(ws: &Workspace) -> Result<String> {
    raw("section_entropy", json!({ "path": ws.binary_path_str() }))
}

pub fn export_report(ws: &Workspace, format: &str) -> Result<String> {
    raw(
        "export_report",
        json!({ "path": ws.binary_path_str(), "format": format }),
    )
}
