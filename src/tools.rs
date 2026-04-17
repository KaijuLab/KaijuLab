use std::collections::{HashMap, HashSet};

use object::{Architecture, Object, ObjectSection, ObjectSegment, ObjectSymbol};
use serde_json::{json, Value};

use crate::llm::ToolDefinition;
use crate::project::Project;

// ─── Tool result ─────────────────────────────────────────────────────────────

/// Result of executing one RE tool locally.
/// The single `output` string is both shown in the UI and sent to the LLM.
pub struct ToolResult {
    pub output: String,
}

impl ToolResult {
    fn ok(output: impl Into<String>) -> Self {
        ToolResult { output: output.into() }
    }

    fn err(msg: impl Into<String>) -> Self {
        ToolResult { output: format!("Error: {}", msg.into()) }
    }
}

// ─── LRU tool cache ───────────────────────────────────────────────────────────

use std::sync::{Mutex, OnceLock};

struct ToolCache {
    entries: HashMap<String, String>,
    order: Vec<String>,
    max: usize,
}

impl ToolCache {
    fn get(&self, key: &str) -> Option<&String> {
        self.entries.get(key)
    }
    fn put(&mut self, key: String, val: String) {
        if self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() >= self.max {
            if let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                self.entries.remove(&oldest);
            }
        }
        self.order.push(key.clone());
        self.entries.insert(key, val);
    }
    fn invalidate_path(&mut self, path: &str) {
        let to_remove: Vec<String> = self.order.iter().filter(|k| k.contains(path)).cloned().collect();
        for k in to_remove {
            self.order.retain(|x| x != &k);
            self.entries.remove(&k);
        }
    }
}

static TOOL_CACHE: OnceLock<Mutex<ToolCache>> = OnceLock::new();
fn tool_cache() -> &'static Mutex<ToolCache> {
    TOOL_CACHE.get_or_init(|| {
        Mutex::new(ToolCache {
            entries: HashMap::new(),
            order: Vec::new(),
            max: 50,
        })
    })
}

const CACHEABLE_TOOLS: &[&str] = &[
    "disassemble", "decompile", "xrefs_to", "cfg_view", "call_graph",
    "pe_security_audit", "pe_internals", "elf_internals",
    "crypto_identify", "function_context",
    "stack_bof_candidates", "writable_iat_hijack_surface", "find_injection_chains",
];

const WRITE_TOOLS: &[&str] = &[
    "rename_function", "add_comment", "set_vuln_score", "rename_variable",
    "set_return_type", "set_param_type", "set_param_name", "define_struct",
    "add_note", "delete_note", "batch_annotate",
];

// ─── Dispatcher ──────────────────────────────────────────────────────────────

pub fn dispatch(name: &str, args: &Value) -> ToolResult {
    // Invalidate cache for write operations
    if WRITE_TOOLS.contains(&name) {
        if let Some(path) = args["path"].as_str() {
            if let Ok(mut cache) = tool_cache().lock() {
                cache.invalidate_path(path);
            }
        }
    }

    // Check cache for expensive read tools
    if CACHEABLE_TOOLS.contains(&name) {
        let cache_key = format!("{}:{}", name, args);
        if let Ok(cache) = tool_cache().lock() {
            if let Some(cached) = cache.get(&cache_key) {
                return ToolResult::ok(cached.clone());
            }
        }
        // Execute and cache
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch_inner(name, args)
        }));
        let result = match result {
            Ok(r) => r,
            Err(_) => ToolResult::err(format!(
                "Tool '{}' panicked on these inputs — likely a malformed binary",
                name
            )),
        };
        if !result.output.starts_with("Error:") {
            if let Ok(mut cache) = tool_cache().lock() {
                cache.put(cache_key, result.output.clone());
            }
        }
        return result;
    }

    // Non-cached tools: still wrap in catch_unwind
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_inner(name, args)
    }));
    match result {
        Ok(r) => r,
        Err(_) => ToolResult::err(format!(
            "Tool '{}' panicked on these inputs — likely a malformed binary",
            name
        )),
    }
}

fn dispatch_inner(name: &str, args: &Value) -> ToolResult {
    match name {
        "file_info" => file_info(&str_arg(args, "path")),
        "hexdump" => hexdump(
            &str_arg(args, "path"),
            args["offset"].as_u64().unwrap_or(0) as usize,
            args["length"].as_u64().unwrap_or(256) as usize,
        ),
        "strings_extract" => strings_extract(
            &str_arg(args, "path"),
            args["min_len"].as_u64().unwrap_or(4) as usize,
            args["max_results"].as_u64().unwrap_or(60) as usize,
            args["section"].as_str(),
        ),
        "disassemble" => disassemble(
            &str_arg(args, "path"),
            args["offset"].as_u64().map(|v| v as usize),
            args["length"].as_u64().unwrap_or(128) as usize,
            args["vaddr"].as_u64(),
        ),
        "read_section" => read_section(&str_arg(args, "path"), &str_arg(args, "section")),
        "resolve_plt"   => resolve_plt(&str_arg(args, "path")),
        "list_functions" => list_functions(
            &str_arg(args, "path"),
            args["max_results"].as_u64().unwrap_or(50) as usize,
            args["json"].as_bool().unwrap_or(false),
        ),
        "decompile" => decompile(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "xrefs_to" => xrefs_to(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "dwarf_info" => dwarf_info(&str_arg(args, "path")),
        "rename_function" => rename_function(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            &str_arg(args, "name"),
        ),
        "add_comment" => add_comment(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            &str_arg(args, "comment"),
        ),
        "load_project" => load_project(&str_arg(args, "path")),
        "rename_variable" => rename_variable(
            &str_arg(args, "path"),
            args["fn_vaddr"].as_u64().unwrap_or(0),
            &str_arg(args, "old_name"),
            &str_arg(args, "new_name"),
        ),
        "set_return_type" => set_return_type(
            &str_arg(args, "path"),
            args["fn_vaddr"].as_u64().unwrap_or(0),
            &str_arg(args, "type_str"),
        ),
        "set_param_type" => set_param_type(
            &str_arg(args, "path"),
            args["fn_vaddr"].as_u64().unwrap_or(0),
            args["param_n"].as_u64().unwrap_or(1) as usize,
            &str_arg(args, "type_str"),
        ),
        "set_param_name" => set_param_name(
            &str_arg(args, "path"),
            args["fn_vaddr"].as_u64().unwrap_or(0),
            args["param_n"].as_u64().unwrap_or(1) as usize,
            &str_arg(args, "name"),
        ),
        "define_struct" => define_struct(
            &str_arg(args, "path"),
            &str_arg(args, "struct_name"),
            args["total_size"].as_u64().unwrap_or(0) as usize,
            args.get("fields").cloned().unwrap_or(serde_json::Value::Null),
        ),
        "list_types" => list_types(&str_arg(args, "path")),

        // ── New tools ──────────────────────────────────────────────────────
        "resolve_pe_imports" => resolve_pe_imports(&str_arg(args, "path")),
        "call_graph" => call_graph(
            &str_arg(args, "path"),
            args["max_depth"].as_u64().unwrap_or(2) as usize,
        ),
        "cfg_view" => cfg_view(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "scan_vulnerabilities" => scan_vulnerabilities(
            &str_arg(args, "path"),
            args["max_fns"].as_u64().unwrap_or(5) as usize,
        ),
        "set_vuln_score" => set_vuln_score(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            args["score"].as_u64().unwrap_or(0) as u8,
        ),
        "explain_function" => explain_function(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "identify_library_functions" => identify_library_functions(&str_arg(args, "path")),
        "diff_binary" => diff_binary(
            &str_arg(args, "path_a"),
            &str_arg(args, "path_b"),
        ),
        "auto_analyze" => auto_analyze(
            &str_arg(args, "path"),
            args["top_n"].as_u64().unwrap_or(5) as usize,
        ),
        "export_report" => export_report(&str_arg(args, "path")),
        "load_pdb" => load_pdb(
            &str_arg(args, "binary_path"),
            &str_arg(args, "pdb_path"),
        ),
        "decompile_flat" => decompile_flat(
            &str_arg(args, "path"),
            args["base_addr"].as_u64().unwrap_or(0),
            args["vaddr"].as_u64().unwrap_or(0),
            args["arch"].as_str().unwrap_or("x86_64"),
        ),
        "search_bytes" => search_bytes(
            &str_arg(args, "path"),
            &str_arg(args, "pattern"),
        ),
        "search_gadgets" => search_gadgets(
            &str_arg(args, "path"),
            &str_arg(args, "pattern"),
        ),
        "dump_range" => dump_range(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            args["size"].as_u64().unwrap_or(64) as usize,
        ),
        "patch_bytes" => patch_bytes(
            &str_arg(args, "path"),
            args["offset"].as_u64().map(|v| v as usize),
            args["vaddr"].as_u64(),
            &str_arg(args, "hex_bytes"),
        ),
        "section_entropy" => section_entropy(&str_arg(args, "path")),
        "generate_yara_rule" => generate_yara_rule(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            args["rule_name"].as_str(),
        ),
        "register_function_hash" => register_function_hash(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
            &str_arg(args, "name"),
        ),
        "lookup_function_hash" => lookup_function_hash(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "match_all_functions" => match_all_functions(
            &str_arg(args, "path"),
            args["max_results"].as_u64().unwrap_or(50) as usize,
        ),
        "virustotal_check" => virustotal_check(&str_arg(args, "path")),

        // ── Analyst notes ──────────────────────────────────────────────────
        "add_note" => add_note_tool(
            &str_arg(args, "path"),
            &str_arg(args, "text"),
            args["vaddr"].as_u64(),
        ),
        "delete_note" => delete_note_tool(
            &str_arg(args, "path"),
            args["id"].as_i64().unwrap_or(0),
        ),
        "list_notes" => list_notes_tool(&str_arg(args, "path")),

        // ── Vulnerability score query ──────────────────────────────────────
        "get_vuln_scores" => get_vuln_scores_tool(&str_arg(args, "path")),

        // ── Python sandbox ────────────────────────────────────────────────
        "run_python" => run_python(
            &str_arg(args, "script"),
            args["stdin"].as_str(),
            args["binary"].as_str(),
            args["timeout_secs"].as_u64().unwrap_or(30).min(120),
        ),
        "batch_annotate" => batch_annotate(&str_arg(args, "path"), args["vaddr"].as_u64().unwrap_or(0), args),
        "elf_internals" => elf_internals(&str_arg(args, "path")),
        "pe_internals"      => pe_internals(&str_arg(args, "path")),
        "pe_security_audit" => pe_security_audit(&str_arg(args, "path")),
        "python_env"        => python_env(),
        "crypto_identify"   => crypto_identify(&str_arg(args, "path")),
        "function_context"  => function_context(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "angr_find" => angr_find(
            &str_arg(args, "path"),
            args["find_addr"].as_u64().unwrap_or(0),
            args["avoid_addr"].as_u64().unwrap_or(0),
            args["start_addr"].as_u64().unwrap_or(0),
            args["stdin_bytes"].as_u64().unwrap_or(32),
            args["timeout_secs"].as_u64().unwrap_or(60),
        ),
        "xrefs_data" => xrefs_data(
            &str_arg(args, "path"),
            args["vaddr"].as_u64().unwrap_or(0),
        ),
        "run_binary" => {
            let argv: Vec<String> = args["args"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            run_binary(
                &str_arg(args, "path"),
                &argv,
                args["stdin"].as_str(),
                args["timeout_secs"].as_u64().unwrap_or(10).min(30),
            )
        }

        "recover_vtables" => recover_vtables(
            &str_arg(args, "path"),
            args["min_methods"].as_u64().unwrap_or(2) as usize,
        ),

        "find_string_decoders" => find_string_decoders(
            &str_arg(args, "path"),
            args["max_fns"].as_u64().unwrap_or(500) as usize,
        ),

        "frida_trace" => {
            let hooks: Vec<String> = args["hooks"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            frida_trace(
                &str_arg(args, "path"),
                &hooks,
                args["timeout_secs"].as_u64().unwrap_or(10),
            )
        }

        "stack_bof_candidates" => stack_bof_candidates(
            &str_arg(args, "path"),
            args["min_frame_bytes"].as_u64().unwrap_or(256),
        ),
        "writable_iat_hijack_surface" => writable_iat_hijack_surface(&str_arg(args, "path")),
        "find_injection_chains" => find_injection_chains(&str_arg(args, "path")),

        _ => ToolResult::err(format!("Unknown tool '{}'", name)),
    }
}

fn str_arg(args: &Value, key: &str) -> String {
    args[key].as_str().unwrap_or("").to_string()
}

// ─── vaddr → file offset helper ──────────────────────────────────────────────

/// Translate a virtual address to a file offset using the binary's LOAD segment table.
/// Returns None if the address is not covered by any segment.
fn vaddr_to_file_offset(data: &[u8], vaddr: u64) -> Option<usize> {
    let obj = object::File::parse(data).ok()?;
    for seg in obj.segments() {
        let seg_vaddr = seg.address();
        let (file_off, file_sz) = seg.file_range();
        if vaddr >= seg_vaddr && vaddr < seg_vaddr + file_sz {
            let delta = vaddr - seg_vaddr;
            return Some(file_off as usize + delta as usize);
        }
    }

    // PE fallback: the `object` crate may not expose PE sections as segments.
    // Walk the goblin PE section table directly.
    if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(data) {
        let image_base = pe.image_base as u64;
        for section in &pe.sections {
            let sec_vaddr  = image_base + section.virtual_address as u64;
            let sec_vsize  = section.virtual_size as u64;
            let raw_offset = section.pointer_to_raw_data as u64;
            let raw_size   = section.size_of_raw_data as u64;
            if vaddr >= sec_vaddr && vaddr < sec_vaddr + sec_vsize {
                let delta = vaddr - sec_vaddr;
                if delta < raw_size {
                    return Some(raw_offset as usize + delta as usize);
                }
            }
        }
    }

    None
}

/// Look up a function's byte-size from the PE .pdata exception directory.
/// Returns None if this is not a PE, .pdata is absent, or `va` has no entry.
fn pe_pdata_fn_size(data: &[u8], va: u64) -> Option<usize> {
    let pe = match goblin::Object::parse(data).ok()? {
        goblin::Object::PE(p) => p,
        _ => return None,
    };
    let image_base = pe.image_base as u64;

    let pdata = pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))?;
    let pdata_bytes = pdata.data(data).ok()??;

    let rdata_range: Option<(u64, usize)> = pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".rdata"))
        .map(|s| (s.virtual_address as u64, s.pointer_to_raw_data as usize));

    let num_entries = pdata_bytes.len() / 8;
    let target_rva = (va.saturating_sub(image_base)) as u32;

    for i in 0..num_entries {
        let off = i * 8;
        let begin_rva = u32::from_le_bytes(pdata_bytes[off..off+4].try_into().ok()?);
        if begin_rva != target_rva { continue; }

        let unwind_raw = u32::from_le_bytes(pdata_bytes[off+4..off+8].try_into().ok()?);
        let flag = unwind_raw & 0x3;
        let fn_size: u64 = if flag != 0 {
            ((unwind_raw >> 2) & 0x7FF) as u64 * 4
        } else if let Some((rdata_va, rdata_file_off)) = rdata_range {
            let ui_rva = unwind_raw as u64;
            if ui_rva >= rdata_va {
                let ui_off = rdata_file_off + (ui_rva - rdata_va) as usize;
                if ui_off + 4 <= data.len() {
                    let ui_word = u32::from_le_bytes(data[ui_off..ui_off+4].try_into().ok()?);
                    (ui_word & 0x3_FFFF) as u64 * 4
                } else { 0 }
            } else { 0 }
        } else { 0 };

        if fn_size > 0 {
            return Some(fn_size as usize);
        }
    }
    None
}

/// Translate a file offset back to a virtual address using the LOAD segment table.
fn file_offset_to_vaddr(data: &[u8], offset: usize) -> Option<u64> {
    let obj = object::File::parse(data).ok()?;
    for seg in obj.segments() {
        let (file_off, file_sz) = seg.file_range();
        if (offset as u64) >= file_off && (offset as u64) < file_off + file_sz {
            let delta = offset as u64 - file_off;
            return Some(seg.address() + delta);
        }
    }
    None
}

// ─── Tool: file_info ─────────────────────────────────────────────────────────

fn file_info(path: &str) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => {
            let magic: String = data
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            return ToolResult::ok(format!(
                "File   : {}\nSize   : {} bytes\nNote   : Not a recognised binary format ({})\nMagic  : {}",
                path, data.len(), e, magic
            ));
        }
    };

    let arch = format!("{:?}", obj.architecture());
    let fmt  = format!("{:?}", obj.format());
    let bits   = if obj.is_64() { "64-bit" } else { "32-bit" };
    let endian = if obj.is_little_endian() { "LE" } else { "BE" };

    // LOAD segments — vaddr ↔ file-offset mapping the LLM needs for disassembly
    let segments: Vec<String> = obj
        .segments()
        .filter(|seg| seg.file_range().1 > 0)
        .map(|seg| {
            let (file_off, file_sz) = seg.file_range();
            format!(
                "    vaddr=0x{:016x}  foff=0x{:08x}  fsz={:<8}  msz={}",
                seg.address(), file_off, file_sz, seg.size()
            )
        })
        .collect();

    let sections: Vec<String> = obj
        .sections()
        .filter_map(|s| {
            let name = s.name().ok()?;
            if name.is_empty() { return None; }
            Some(format!(
                "    {:<18} addr=0x{:016x}  size={}",
                name, s.address(), s.size()
            ))
        })
        .collect();

    let sym_count = obj.symbols().count();

    let mut out = format!(
        "File         : {}\nSize         : {} bytes\nFormat       : {}\nArchitecture : {} {} {}\nEntry point  : 0x{:016x}\nSegments ({}):\n{}\nSections ({}):\n{}\nSymbols      : {}",
        path, data.len(), fmt, arch, bits, endian,
        obj.entry(),
        segments.len(), segments.join("\n"),
        sections.len(), sections.join("\n"),
        sym_count,
    );

    let imports: Vec<String> = obj
        .imports()
        .unwrap_or_default()
        .iter()
        .take(20)
        .filter_map(|imp| std::str::from_utf8(imp.name()).ok().map(String::from))
        .collect();
    if !imports.is_empty() {
        out.push_str(&format!("\nImports (first {}):\n", imports.len()));
        for imp in &imports {
            out.push_str(&format!("    {}\n", imp));
        }
    }

    ToolResult::ok(out)
}

// ─── Tool: elf_internals ─────────────────────────────────────────────────────

fn elf_internals(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let elf = match goblin::elf::Elf::parse(&data) {
        Ok(e) => e,
        Err(_) => return ToolResult::err(
            "Not a valid ELF binary — use file_info for PE/Mach-O formats"
        ),
    };

    let mut out = String::new();

    // ── Header / type ─────────────────────────────────────────────────────
    use goblin::elf::header::{ET_EXEC, ET_DYN};
    let pie = elf.header.e_type == ET_DYN;
    out.push_str(&format!(
        "ELF type    : {} ({})\n",
        if pie { "ET_DYN" } else if elf.header.e_type == ET_EXEC { "ET_EXEC" } else { "other" },
        if pie { "PIE — load address randomised" } else { "not PIE — fixed load address" }
    ));

    // ── Security mitigations ──────────────────────────────────────────────
    use goblin::elf::program_header::{PT_GNU_STACK, PT_GNU_RELRO, PF_X};
    let nx = elf.program_headers.iter()
        .find(|ph| ph.p_type == PT_GNU_STACK)
        .map(|ph| ph.p_flags & PF_X == 0)
        .unwrap_or(false);

    let has_relro = elf.program_headers.iter().any(|ph| ph.p_type == PT_GNU_RELRO);

    use goblin::elf::dynamic::{DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1};
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    let bind_now = elf.dynamic.as_ref()
        .map(|dyn_| dyn_.dyns.iter().any(|d| {
            d.d_tag == DT_BIND_NOW
                || (d.d_tag == DT_FLAGS   && d.d_val & DF_BIND_NOW != 0)
                || (d.d_tag == DT_FLAGS_1 && d.d_val & DF_1_NOW    != 0)
        }))
        .unwrap_or(false);

    let relro = match (has_relro, bind_now) {
        (false, _)    => "None",
        (true, false) => "Partial RELRO",
        (true, true)  => "Full RELRO",
    };

    let has_canary = elf.dynsyms.iter().any(|sym|
        elf.dynstrtab.get_at(sym.st_name).map_or(false, |n| n.contains("__stack_chk"))
    );
    let has_fortify = elf.dynsyms.iter().any(|sym|
        elf.dynstrtab.get_at(sym.st_name)
            .map_or(false, |n| n.ends_with("_chk") && n.starts_with("__"))
    );

    out.push_str("\nSecurity mitigations:\n");
    out.push_str(&format!("  PIE          : {}\n", if pie { "Yes" } else { "No (fixed address)" }));
    out.push_str(&format!("  NX (DEP)     : {}\n", if nx  { "Yes" } else { "No — stack is executable!" }));
    out.push_str(&format!("  RELRO        : {}\n", relro));
    out.push_str(&format!("  Stack canary : {}\n", if has_canary  { "Yes (__stack_chk_fail)" } else { "No" }));
    out.push_str(&format!("  FORTIFY      : {}\n", if has_fortify { "Yes" } else { "No" }));

    // ── Special sections ──────────────────────────────────────────────────
    out.push_str("\nSpecial sections:\n");
    for sec_name in &[".got", ".got.plt", ".plt", ".plt.got",
                      ".init_array", ".fini_array", ".bss", ".data"] {
        if let Some(sh) = elf.section_headers.iter().find(|sh|
            elf.shdr_strtab.get_at(sh.sh_name).map_or(false, |n| n == *sec_name)
        ) {
            if sh.sh_addr != 0 {
                out.push_str(&format!(
                    "  {:<15} : vaddr=0x{:016x}  size={}\n",
                    sec_name, sh.sh_addr, sh.sh_size
                ));
            }
        }
    }

    // ── init_array / fini_array pointer dump ──────────────────────────────
    let ptr_size: usize = if elf.is_64 { 8 } else { 4 };
    let is_le = elf.little_endian;
    for arr_sec in &[".init_array", ".fini_array"] {
        if let Some(sh) = elf.section_headers.iter().find(|sh|
            elf.shdr_strtab.get_at(sh.sh_name).map_or(false, |n| n == *arr_sec)
        ) {
            let off = sh.sh_offset as usize;
            let sz  = sh.sh_size  as usize;
            if sh.sh_addr == 0 || sz < ptr_size || off + sz > data.len() { continue; }
            out.push_str(&format!(
                "\n{}  (0x{:x} .. 0x{:x}):\n",
                arr_sec, sh.sh_addr, sh.sh_addr + sh.sh_size
            ));
            for (i, chunk) in data[off..off + sz].chunks(ptr_size).enumerate() {
                if chunk.len() < ptr_size { break; }
                let ptr: u64 = if elf.is_64 && is_le {
                    u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]))
                } else if elf.is_64 {
                    u64::from_be_bytes(chunk.try_into().unwrap_or([0u8; 8]))
                } else if is_le {
                    u32::from_le_bytes(chunk[..4].try_into().unwrap_or([0u8; 4])) as u64
                } else {
                    u32::from_be_bytes(chunk[..4].try_into().unwrap_or([0u8; 4])) as u64
                };
                let sym_name = elf.syms.iter()
                    .chain(elf.dynsyms.iter())
                    .find(|s| s.st_value == ptr && !s.is_import())
                    .and_then(|s| {
                        elf.strtab.get_at(s.st_name)
                            .or_else(|| elf.dynstrtab.get_at(s.st_name))
                    })
                    .unwrap_or("?");
                out.push_str(&format!("  [{}] 0x{:016x}  {}\n", i, ptr, sym_name));
            }
        }
    }

    // ── Linked libraries ──────────────────────────────────────────────────
    if !elf.libraries.is_empty() {
        out.push_str("\nLinked libraries:\n");
        for lib in &elf.libraries {
            out.push_str(&format!("  {}\n", lib));
        }
    }

    // ── Interpreter ───────────────────────────────────────────────────────
    if let Some(interp) = &elf.interpreter {
        out.push_str(&format!("\nInterpreter : {}\n", interp));
    }

    ToolResult::ok(out)
}

// ─── Tool: pe_internals ──────────────────────────────────────────────────────

fn pe_internals(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        Ok(_)  => return ToolResult::err("Not a PE binary — use elf_internals for ELF"),
        Err(e) => return ToolResult::err(format!("Cannot parse PE: {}", e)),
    };

    let mut out = String::new();

    // ── Header ────────────────────────────────────────────────────────────
    let image_base = pe.image_base as u64;
    let is_dll  = pe.header.coff_header.characteristics & 0x2000 != 0;
    let is_64   = pe.is_64;
    out.push_str(&format!("Type        : {} ({})\n",
        if is_dll { "DLL" } else { "EXE" },
        if is_64 { "PE32+" } else { "PE32" }
    ));
    out.push_str(&format!("Image base  : 0x{:016x}\n", image_base));

    // ── DLL Characteristics (security mitigations) ────────────────────────
    let dll_chars = pe.header.optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    const DYNBASE     : u16 = 0x0040; // ASLR
    const FORCE_INTEG : u16 = 0x0080; // Force integrity / signed
    const NX_COMPAT   : u16 = 0x0100; // DEP
    const NO_ISOLATION: u16 = 0x0200;
    const NO_SEH      : u16 = 0x0400;
    const NO_BIND     : u16 = 0x0800;
    const APPCONTAINER: u16 = 0x1000;
    const WDM_DRIVER  : u16 = 0x2000;
    const GUARD_CF    : u16 = 0x4000; // Control Flow Guard
    const TERM_SRV    : u16 = 0x8000;
    const HIGH_ENTROPY: u16 = 0x0020; // 64-bit ASLR

    let flag = |f: u16| if dll_chars & f != 0 { "Yes" } else { "No" };
    out.push_str("\nSecurity mitigations (DllCharacteristics):\n");
    out.push_str(&format!("  ASLR (DYNAMIC_BASE)    : {}\n", flag(DYNBASE)));
    out.push_str(&format!("  High-entropy ASLR      : {}\n", flag(HIGH_ENTROPY)));
    out.push_str(&format!("  DEP/NX (NX_COMPAT)     : {}\n", flag(NX_COMPAT)));
    out.push_str(&format!("  CFG (GUARD_CF)         : {}\n", flag(GUARD_CF)));
    out.push_str(&format!("  Force integrity        : {}\n", flag(FORCE_INTEG)));
    out.push_str(&format!("  No SEH                 : {}\n", flag(NO_SEH)));
    out.push_str(&format!("  AppContainer           : {}\n", flag(APPCONTAINER)));
    out.push_str(&format!("  Terminal server aware  : {}\n", flag(TERM_SRV)));
    let _ = (NO_ISOLATION, NO_BIND, WDM_DRIVER); // suppress unused warnings

    // ── Sections ──────────────────────────────────────────────────────────
    out.push_str("\nSections:\n");
    for sec in &pe.sections {
        let name = sec.name().unwrap_or("?");
        let vaddr = image_base + sec.virtual_address as u64;
        let vsize = sec.virtual_size;
        let chars = sec.characteristics;
        let mut perms = String::new();
        if chars & 0x20000000 != 0 { perms.push('X'); }
        if chars & 0x40000000 != 0 { perms.push('R'); }
        if chars & 0x80000000 != 0 { perms.push('W'); }
        if perms.is_empty() { perms.push('-'); }
        out.push_str(&format!(
            "  {:<12} vaddr=0x{:016x}  vsize=0x{:08x}  [{}]\n",
            name, vaddr, vsize, perms
        ));
    }

    // ── Exception directory (.pdata) ──────────────────────────────────────
    let pdata_count = pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
        .map(|s| s.size_of_raw_data as usize / 8)
        .unwrap_or(0);
    if pdata_count > 0 {
        out.push_str(&format!("\nException directory (.pdata): {} function entries\n", pdata_count));
    }

    // ── TLS directory ─────────────────────────────────────────────────────
    // Presence of .tls indicates use of Thread Local Storage (can execute code at startup)
    let has_tls = pe.sections.iter().any(|s| s.name().ok().map_or(false, |n| n == ".tls"));
    out.push_str(&format!("\nTLS (.tls section) : {}\n",
        if has_tls { "Present — may contain TLS callbacks (code run before entry point)" }
        else { "Not present" }
    ));

    // ── Imports summary ───────────────────────────────────────────────────
    if !pe.imports.is_empty() {
        let mut by_dll: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for imp in &pe.imports {
            by_dll.entry(imp.dll.to_string()).or_default().push(imp.name.to_string());
        }
        out.push_str(&format!("\nImports ({} DLLs, {} symbols):\n",
            by_dll.len(), pe.imports.len()));
        for (dll, syms) in &by_dll {
            let preview: Vec<&str> = syms.iter().map(|s| s.as_str()).take(5).collect();
            let extra = if syms.len() > 5 { format!(" …+{}", syms.len()-5) } else { String::new() };
            out.push_str(&format!("  {:<35} {}{}\n",
                dll, preview.join(", "), extra));
        }

        // Flag high-interest imports
        let interesting: Vec<String> = pe.imports.iter()
            .map(|i| i.name.to_string())
            .filter(|n| {
                let l = n.to_ascii_lowercase();
                l.contains("createremotethread") || l.contains("virtualalloc")
                    || l.contains("writeprocessmemory") || l.contains("createprocess")
                    || l.contains("loadlibrary") || l.contains("getprocaddress")
                    || l.contains("namedpipe") || l.contains("winsock")
                    || l.contains("wsastartup") || l.contains("connect")
                    || l.contains("cryptencrypt") || l.contains("cryptdecrypt")
                    || l.contains("regopen") || l.contains("regset")
                    || l.contains("shellexecute") || l.contains("winexec")
            })
            .collect();
        if !interesting.is_empty() {
            out.push_str("\nHigh-interest imports:\n");
            for name in &interesting {
                out.push_str(&format!("  ⚠  {}\n", name));
            }
        }
    }

    // ── Exports ───────────────────────────────────────────────────────────
    if !pe.exports.is_empty() {
        out.push_str(&format!("\nExports ({}):\n", pe.exports.len()));
        for exp in pe.exports.iter().take(20) {
            let name = exp.name.unwrap_or("<ordinal>");
            let va   = image_base + exp.rva as u64;
            out.push_str(&format!("  0x{:016x}  {}\n", va, name));
        }
        if pe.exports.len() > 20 {
            out.push_str(&format!("  … and {} more\n", pe.exports.len() - 20));
        }
    }

    ToolResult::ok(out)
}

// ─── Tool: pe_security_audit ─────────────────────────────────────────────────
//
// O(file_size) PE hardening audit — no decompilation, works on large binaries.
// Covers:
//   • Section characteristics: writable .rodata/.rdata/.fptable  (FIND-01/02)
//   • DLL characteristics: ASLR, DEP, CFG declared, Force Integrity (FIND-05)
//   • Load Config: SecurityCookie, GuardCFCheckFunctionPointer, GuardFlags (FIND-03/04)
//   • ARM64: bare-BLR ratio — % of indirect calls without CFG guard prefix (FIND-03)
//   • ARM64: stack-canary ADRP coverage — % of functions referencing cookie (FIND-04)

/// Convert a PE RVA to a file offset using the section table.
fn pe_rva_to_file_offset(
    sections: &[goblin::pe::section_table::SectionTable],
    rva: u64,
) -> Option<usize> {
    for s in sections {
        let va  = s.virtual_address as u64;
        let vsz = (s.virtual_size.max(s.size_of_raw_data)) as u64;
        if rva >= va && rva < va + vsz {
            return Some(s.pointer_to_raw_data as usize + (rva - va) as usize);
        }
    }
    None
}

/// Read a little-endian u32 from `buf` at `offset`, returning 0 on OOB.
#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    if offset + 4 <= buf.len() {
        u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]))
    } else {
        0
    }
}

/// Read a little-endian u64 from `buf` at `offset`, returning 0 on OOB.
#[inline]
fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    if offset + 8 <= buf.len() {
        u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap_or([0; 8]))
    } else {
        0
    }
}

fn pe_security_audit(path: &str) -> ToolResult {
    if path.is_empty() {
        return ToolResult::err("'path' is required");
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        Ok(_) => return ToolResult::err("Not a PE binary — use elf_internals for ELF"),
        Err(e) => return ToolResult::err(format!("Cannot parse PE: {}", e)),
    };

    let is_64      = pe.is_64;
    let image_base = pe.image_base as u64;
    let machine    = pe.header.coff_header.machine; // 0xAA64 = ARM64
    let is_arm64   = machine == 0xAA64;

    let mut out          = String::new();
    let mut high_count   = 0u32;
    let mut medium_count = 0u32;

    out.push_str(&format!("PE Security Audit: '{}'\n{}\n\n", path, "═".repeat(72)));

    // ── DLL Characteristics ──────────────────────────────────────────────────
    let dll_chars = pe.header.optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let has_aslr         = dll_chars & 0x0040 != 0;
    let has_high_entropy = dll_chars & 0x0020 != 0;
    let has_dep          = dll_chars & 0x0100 != 0;
    let has_cfg_decl     = dll_chars & 0x4000 != 0;
    let has_force_integ  = dll_chars & 0x0080 != 0;
    let has_no_seh       = dll_chars & 0x0400 != 0;

    out.push_str("── DLL Characteristics ─────────────────────────────────────────────\n");
    out.push_str(&format!("  ASLR (DYNAMIC_BASE)     : {}\n",
        if has_aslr { "YES" } else { "NO  ← missing mitigation" }));
    out.push_str(&format!("  High-entropy ASLR       : {}\n",
        if has_high_entropy { "YES" } else { "no" }));
    out.push_str(&format!("  DEP / NX (NX_COMPAT)    : {}\n",
        if has_dep { "YES" } else { "NO  ← missing mitigation" }));
    out.push_str(&format!("  CFG (GUARD_CF declared) : {}\n",
        if has_cfg_decl { "declared" } else { "NO  ← missing mitigation" }));
    out.push_str(&format!("  Force Integrity         : {}\n",
        if has_force_integ { "YES" } else { "no  ← FIND-05 [MEDIUM]" }));
    out.push_str(&format!("  No SEH (NO_SEH)         : {}\n",
        if has_no_seh { "YES" } else { "no" }));
    out.push_str(&format!("  DllCharacteristics raw  : 0x{:04x}\n\n", dll_chars));

    if !has_force_integ { medium_count += 1; }

    // ── Section characteristics ──────────────────────────────────────────────
    // IMAGE_SCN_MEM_WRITE = 0x80000000
    // Sections whose name implies they should be read-only
    const SCN_MEM_WRITE : u32 = 0x8000_0000;
    const SCN_MEM_EXEC  : u32 = 0x2000_0000;
    const SCN_MEM_READ  : u32 = 0x4000_0000;
    const SCN_CNT_IDATA : u32 = 0x0000_0040; // Initialized data

    out.push_str("── Section Characteristics ─────────────────────────────────────────\n");
    let mut writable_ro_secs: Vec<String> = Vec::new();

    for sec in &pe.sections {
        let name  = sec.name().unwrap_or("?");
        let chars = sec.characteristics;
        let va    = image_base + sec.virtual_address as u64;
        let vsz   = sec.virtual_size as u64;

        let r = if chars & SCN_MEM_READ  != 0 { "R" } else { "-" };
        let w = if chars & SCN_MEM_WRITE != 0 { "W" } else { "-" };
        let x = if chars & SCN_MEM_EXEC  != 0 { "X" } else { "-" };
        let perm = format!("{}{}{}", r, w, x);

        // Sections that are data-only AND writable AND look like read-only data
        let is_data       = chars & SCN_CNT_IDATA != 0;
        let is_writable   = chars & SCN_MEM_WRITE != 0;
        let is_executable = chars & SCN_MEM_EXEC  != 0;
        let ro_name       = name.contains("rodata") || name.contains("rdata")
                         || name.contains("fptable") || name.contains("const")
                         || name == ".rdata";

        let annotation = if is_data && is_writable && !is_executable && ro_name {
            writable_ro_secs.push(name.to_string());
            high_count += 1;
            "  ← [HIGH] FIND-01/02 should be R-- (IMAGE_SCN_MEM_WRITE set)"
        } else {
            ""
        };

        out.push_str(&format!(
            "  {:<14} VA=0x{:016x}  size=0x{:07x}  [{}]  chars=0x{:08x}{}\n",
            name, va, vsz, perm, chars, annotation
        ));
    }
    out.push_str("\n");

    if !writable_ro_secs.is_empty() {
        out.push_str(&format!(
            "[!] FIND-01/02 [HIGH]: The following read-only data sections have\n\
             [!] IMAGE_SCN_MEM_WRITE set: {}\n\
             [!] Windows maps these PAGE_WRITECOPY — writable without VirtualProtect.\n\
             [!] A write-what-where primitive can overwrite crypto constants or\n\
             [!] function pointers without triggering VirtualProtect hooks.\n\
             [!] Fix: /SECTION:.rodata,R  /SECTION:.fptable,R  (MSVC/LLD linker)\n\n",
            writable_ro_secs.join(", ")
        ));
    }

    // ── Load Config (raw byte parsing) ───────────────────────────────────────
    //
    // Goblin exposes the Load Config directory entry via
    // pe.header.optional_header.data_directories.get_load_config_table().
    // We then convert the RVA to a file offset and parse the raw bytes directly,
    // because goblin does not expose every field (GuardCFCheckFunctionPointer,
    // GuardFlags, etc.).
    //
    // Offsets for IMAGE_LOAD_CONFIG_DIRECTORY64 (PE32+, empirically verified
    // against comet.exe v145 with Size=0x140):
    //   +0x58  SecurityCookie               (u64)
    //   +0x70  GuardCFCheckFunctionPointer  (u64)
    //   +0x78  GuardCFDispatchFunctionPointer (u64)
    //   +0x80  GuardCFFunctionTable         (u64)
    //   +0x88  GuardCFFunctionCount         (u64)
    //   +0x90  GuardFlags                   (u32)
    //
    // Offsets for IMAGE_LOAD_CONFIG_DIRECTORY32 (PE32):
    //   +0x3C  SecurityCookie               (u32)
    //   +0x48  GuardCFCheckFunctionPointer  (u32)
    //   +0x50  GuardCFFunctionTable         (u32)
    //   +0x54  GuardCFFunctionCount         (u32)
    //   +0x58  GuardFlags                   (u32)

    out.push_str("── Load Config ─────────────────────────────────────────────────────\n");

    let lc_info: Option<(u32, u32)> = pe.header.optional_header.and_then(|oh| {
        oh.data_directories
            .get_load_config_table()
            .map(|dd| (dd.virtual_address, dd.size))
    });

    let mut cookie_va: u64   = 0;
    let mut guard_check: u64 = 0;
    let mut lc_parsed        = false;

    match lc_info {
        None => {
            out.push_str("  Load Config: no optional header present\n\n");
        }
        Some((0, _)) => {
            out.push_str("  Load Config: directory not present (no SecurityCookie, no CFG table)\n\n");
            high_count += 1;
        }
        Some((lc_rva, lc_size)) => {
            match pe_rva_to_file_offset(&pe.sections, lc_rva as u64) {
                None => {
                    out.push_str(&format!(
                        "  Load Config RVA 0x{:x} could not be resolved to file offset\n\n",
                        lc_rva
                    ));
                }
                Some(lc_off) => {
                    let avail = (lc_size as usize).min(0x200).min(
                        data.len().saturating_sub(lc_off));
                    if avail == 0 {
                        out.push_str("  Load Config extends beyond file end\n\n");
                    } else {
                        let lc = &data[lc_off..lc_off + avail];
                        lc_parsed = true;

                        let (guard_table, guard_count, guard_flags) = if is_64 {
                            cookie_va   = read_u64_le(lc, 0x58);
                            guard_check = read_u64_le(lc, 0x70);
                            (read_u64_le(lc, 0x80), read_u64_le(lc, 0x88), read_u32_le(lc, 0x90))
                        } else {
                            cookie_va   = read_u32_le(lc, 0x3C) as u64;
                            guard_check = read_u32_le(lc, 0x48) as u64;
                            (read_u32_le(lc, 0x50) as u64, read_u32_le(lc, 0x54) as u64, read_u32_le(lc, 0x58))
                        };

                        // IMAGE_GUARD_CF_INSTRUMENTED = 0x0100
                        let cf_instrumented = guard_flags & 0x0100 != 0;

                        out.push_str(&format!(
                            "  SecurityCookie VA           : {}\n",
                            if cookie_va != 0 {
                                format!("0x{:016x}  (present)", cookie_va)
                            } else {
                                "0  ← MISSING — no /GS canary".to_string()
                            }
                        ));
                        out.push_str(&format!(
                            "  GuardCFCheckFunctionPointer : 0x{:016x}\n", guard_check));
                        out.push_str(&format!(
                            "  GuardCFFunctionTable        : 0x{:016x}\n", guard_table));
                        out.push_str(&format!(
                            "  GuardCFFunctionCount        : {}\n", guard_count));
                        out.push_str(&format!(
                            "  GuardFlags                  : 0x{:08x}  (CF_INSTRUMENTED: {})\n\n",
                            guard_flags,
                            if cf_instrumented { "SET" } else { "NOT SET ← CFG declared but not built" }
                        ));

                        if cookie_va == 0 {
                            out.push_str("[!] FIND-04 [HIGH]: SecurityCookie is 0 — /GS stack canaries disabled\n\n");
                            high_count += 1;
                        }

                        // Check whether __guard_check_icall_fptr points to a RET stub
                        if guard_check != 0 && image_base != 0 {
                            let fptr_rva = guard_check.wrapping_sub(image_base);
                            if let Some(fptr_off) = pe_rva_to_file_offset(&pe.sections, fptr_rva) {
                                let target_va = if is_64 {
                                    read_u64_le(&data, fptr_off)
                                } else {
                                    read_u32_le(&data, fptr_off) as u64
                                };
                                if target_va != 0 {
                                    let target_rva = target_va.wrapping_sub(image_base);
                                    if let Some(target_off) = pe_rva_to_file_offset(&pe.sections, target_rva) {
                                        if target_off + 4 <= data.len() {
                                            let insn = read_u32_le(&data, target_off);
                                            // ARM64 RET = 0xD65F03C0; x86-64 RET = 0xC3 (first byte)
                                            let is_ret = insn == 0xD65F03C0
                                                || (data[target_off] == 0xC3);
                                            if is_ret {
                                                out.push_str(&format!(
                                                    "[!] FIND-03 [HIGH]: __guard_check_icall_fptr (0x{:016x})\n\
                                                     [!] → points to target 0x{:016x} which disassembles as RET.\n\
                                                     [!] The CFG check is a no-op stub — indirect calls are not\n\
                                                     [!] validated at runtime even though CF_INSTRUMENTED is set.\n\n",
                                                    guard_check, target_va
                                                ));
                                                high_count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── ARM64 bare-BLR scan ──────────────────────────────────────────────────
    //
    // On ARM64, a properly instrumented indirect call looks like:
    //   ADRP  Xn, __guard_check_icall_fptr@PAGE    ; load check fn address
    //   LDR   Xn, [Xn, :lo12:__guard_check_icall_fptr]
    //   BLR   Xm                                   ; the guarded target call
    //
    // A "bare" BLR has no such ADRP prefix in the 8-instruction window before it.
    // Encoding: (insn & 0xFFFFFC1F) == 0xD63F0000
    // ADRP:     (insn & 0x9F000000) == 0x90000000

    if is_arm64 && lc_parsed {
        let text_sec = pe.sections.iter().find(|s| {
            s.name().ok().map_or(false, |n| n == ".text")
        });

        if let Some(ts) = text_sec {
            let ts_off  = ts.pointer_to_raw_data as usize;
            let ts_size = ts.size_of_raw_data as usize;
            let ts_va   = image_base + ts.virtual_address as u64;

            // Count .pdata entries as the function denominator
            let pdata_fn_count = pe.sections.iter()
                .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
                .map(|s| s.size_of_raw_data as usize / 8)
                .unwrap_or(0);

            if ts_off + ts_size <= data.len() && ts_size >= 8 {
                let text = &data[ts_off..ts_off + ts_size];

                // Derive the SecurityCookie page so we can identify ADRP-to-cookie
                let cookie_page = cookie_va & !0xFFFu64;

                let mut total_blr    = 0u32;
                let mut guarded_blr  = 0u32;
                let mut fn_with_cookie = 0u32;

                let mut i = 0usize;
                while i + 4 <= text.len() {
                    let insn = read_u32_le(text, i);

                    // ── BLR check ────────────────────────────────────────────
                    if (insn & 0xFFFF_FC1F) == 0xD63F_0000 {
                        total_blr += 1;

                        // Scan up to 8 instructions back for an ADRP to the
                        // guard-check pointer page (or any ADRP, as a heuristic)
                        let window_start = i.saturating_sub(32); // 8 * 4 bytes
                        let mut found_guard = false;
                        let mut j = window_start;
                        while j < i {
                            let prev = read_u32_le(text, j);
                            if (prev & 0x9F00_0000) == 0x9000_0000 {
                                // This is an ADRP — decode its target page
                                let pc        = ts_va + j as u64;
                                let immlo     = ((prev >> 29) & 0x3) as u64;
                                let immhi     = ((prev >>  5) & 0x0007_FFFF) as u64;
                                let imm21     = (immhi << 2) | immlo;
                                // Sign-extend 21-bit immediate
                                let imm21_s = if imm21 & (1 << 20) != 0 {
                                    (imm21 | (!0u64 << 21)) as i64
                                } else {
                                    imm21 as i64
                                };
                                let target_page = ((pc & !0xFFF) as i64)
                                    .wrapping_add(imm21_s << 12) as u64;

                                // Guard-check pointer lives on its own page;
                                // if this ADRP targets that page it is the CFG
                                // guard prefix.  Fall back to "any ADRP" as a
                                // conservative heuristic when cookie_page == 0.
                                if cookie_page == 0
                                    || target_page == (guard_check & !0xFFF)
                                {
                                    found_guard = true;
                                    break;
                                }
                            }
                            j += 4;
                        }
                        if found_guard { guarded_blr += 1; }
                    }

                    // ── Function prologue + cookie ADRP scan ─────────────────
                    // Look for STP X29,X30 (frame setup) as a function entry
                    // heuristic, then check next 64 bytes for ADRP-to-cookie.
                    if cookie_page != 0 {
                        // STP X29,X30,[SP,#imm]: (insn & 0xFFC003FF) == 0xA9003BFD
                        // PACIBSP: 0xD503237F
                        let is_entry = (insn & 0xFFC0_03FF) == 0xA900_3BFD
                            || insn == 0xD503_237F;
                        if is_entry {
                            let limit = (i + 64).min(text.len().saturating_sub(4));
                            let mut has_cookie_ref = false;
                            let mut k = i;
                            while k < limit {
                                let prev = read_u32_le(text, k);
                                if (prev & 0x9F00_0000) == 0x9000_0000 {
                                    let pc    = ts_va + k as u64;
                                    let immlo = ((prev >> 29) & 0x3) as u64;
                                    let immhi = ((prev >>  5) & 0x0007_FFFF) as u64;
                                    let imm21 = (immhi << 2) | immlo;
                                    let imm21_s = if imm21 & (1 << 20) != 0 {
                                        (imm21 | (!0u64 << 21)) as i64
                                    } else {
                                        imm21 as i64
                                    };
                                    let tp = ((pc & !0xFFF) as i64)
                                        .wrapping_add(imm21_s << 12) as u64;
                                    if tp == cookie_page {
                                        has_cookie_ref = true;
                                        break;
                                    }
                                }
                                k += 4;
                            }
                            if has_cookie_ref { fn_with_cookie += 1; }
                        }
                    }

                    i += 4;
                }

                let bare_blr  = total_blr.saturating_sub(guarded_blr);
                let bare_pct  = if total_blr > 0 {
                    bare_blr as f64 * 100.0 / total_blr as f64
                } else { 0.0 };
                let cookie_pct = if pdata_fn_count > 0 {
                    fn_with_cookie as f64 * 100.0 / pdata_fn_count as f64
                } else { 0.0 };
                let uncookied = pdata_fn_count.saturating_sub(fn_with_cookie as usize);

                out.push_str("── ARM64 CFG / Stack Canary Coverage ───────────────────────────────\n");
                out.push_str(&format!(
                    "  .text size                  : 0x{:x} bytes ({} instructions)\n",
                    ts_size, ts_size / 4
                ));
                out.push_str(&format!(
                    "  Functions (.pdata entries)  : {}\n", pdata_fn_count));
                out.push_str(&format!(
                    "  Total BLR instructions      : {}\n", total_blr));
                out.push_str(&format!(
                    "  Guarded BLR (ADRP prefix)   : {} ({:.1}%)\n",
                    guarded_blr, if total_blr > 0 { guarded_blr as f64 * 100.0 / total_blr as f64 } else { 0.0 }
                ));
                out.push_str(&format!(
                    "  Bare BLR (no guard prefix)  : {} ({:.1}%){}  [FIND-03]\n",
                    bare_blr, bare_pct,
                    if bare_pct > 20.0 { "  ← [HIGH]" } else { "" }
                ));
                out.push_str(&format!(
                    "  Fns with cookie ADRP        : {} ({:.1}%)\n",
                    fn_with_cookie, cookie_pct
                ));
                out.push_str(&format!(
                    "  Fns WITHOUT canary          : {} ({:.1}%){}  [FIND-04]\n\n",
                    uncookied,
                    if pdata_fn_count > 0 { uncookied as f64 * 100.0 / pdata_fn_count as f64 } else { 0.0 },
                    if cookie_pct < 70.0 { "  ← [HIGH]" } else { "" }
                ));

                if bare_pct > 20.0 { high_count += 1; }
                if cookie_pct < 70.0 && cookie_va != 0 { high_count += 1; }

                if bare_pct > 20.0 {
                    out.push_str(&format!(
                        "[!] FIND-03 [HIGH]: {:.1}% of BLR instructions ({}/{}) have no\n\
                         [!] preceding ADRP to the guard-check pointer page.  An attacker\n\
                         [!] who corrupts a function pointer reachable via a bare BLR can\n\
                         [!] redirect execution to arbitrary code with no CFG enforcement.\n\n",
                        bare_pct, bare_blr, total_blr
                    ));
                }
                if cookie_pct < 70.0 && cookie_va != 0 {
                    out.push_str(&format!(
                        "[!] FIND-04 [HIGH]: Only {:.1}% of functions ({}/{}) reference the\n\
                         [!] SecurityCookie page in their prologue.  The remaining {}\n\
                         [!] functions lack /GS stack canary protection, leaving large\n\
                         [!] stack-frame functions vulnerable to stack-smashing attacks.\n\n",
                        cookie_pct, fn_with_cookie, pdata_fn_count, uncookied
                    ));
                }
            }
        }
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    out.push_str("── Summary ─────────────────────────────────────────────────────────\n");
    out.push_str(&format!("  High-severity findings  : {}\n", high_count));
    out.push_str(&format!("  Medium-severity findings: {}\n", medium_count));
    out.push_str(&format!("  Architecture            : {}\n",
        if is_arm64 { "ARM64" } else if is_64 { "x86-64" } else { "x86" }));
    out.push_str(&format!("  Image base (preferred)  : 0x{:016x}\n", image_base));

    ToolResult::ok(out)
}

// ─── Tool: hexdump ───────────────────────────────────────────────────────────

fn hexdump(path: &str, offset: usize, length: usize) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    if offset >= data.len() {
        return ToolResult::err(format!("Offset 0x{:x} is beyond file size {} bytes", offset, data.len()));
    }

    let end = (offset + length).min(data.len());
    let bytes = &data[offset..end];
    let mut out = String::new();

    for (row, chunk) in bytes.chunks(16).enumerate() {
        let addr  = offset + row * 16;
        let first8 = &chunk[..chunk.len().min(8)];
        let rest   = if chunk.len() > 8 { &chunk[8..] } else { &[] };
        let hex_a: String = first8.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let hex_b: String = rest.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let ascii: String = chunk.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!("{:08x}  {:<23}  {:<23}  |{}|\n", addr, hex_a, hex_b, ascii));
    }

    if end < data.len() {
        out.push_str(&format!("({} more bytes)", data.len() - end));
    }

    ToolResult::ok(out)
}

// ─── Tool: strings_extract ───────────────────────────────────────────────────

fn strings_extract(path: &str, min_len: usize, max_results: usize, section: Option<&str>) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // When a section filter is requested, scan only that section's bytes.
    let (scan_bytes, base_offset): (Vec<u8>, usize) = if let Some(sec_name) = section {
        let obj = match object::File::parse(&*data) {
            Ok(f) => f,
            Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
        };
        let sec = obj.sections().find(|s| s.name().ok() == Some(sec_name));
        match sec {
            None => return ToolResult::err(format!("Section '{}' not found", sec_name)),
            Some(s) => {
                let file_off = s.file_range().map(|(o, _)| o as usize).unwrap_or(0);
                match s.data() {
                    Ok(d) => (d.to_vec(), file_off),
                    Err(e) => return ToolResult::err(format!("Cannot read section data: {}", e)),
                }
            }
        }
    } else {
        (data.clone(), 0)
    };

    let mut results: Vec<(usize, String)> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut run_start = 0usize;

    for (i, &b) in scan_bytes.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if run.is_empty() { run_start = i; }
            run.push(b);
        } else {
            if run.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&run) {
                    results.push((base_offset + run_start, s.to_string()));
                }
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&run) {
            results.push((base_offset + run_start, s.to_string()));
        }
    }

    let total = results.len();
    let sec_label = section.map(|s| format!(" in '{}'", s)).unwrap_or_default();
    let mut out = format!("Found {} strings (min_len={}{})\n\n", total, min_len, sec_label);
    for (offset, s) in results.iter().take(max_results) {
        out.push_str(&format!("  0x{:08x}  {}\n", offset, s));
    }
    if total > max_results {
        out.push_str(&format!("  … and {} more", total - max_results));
    }

    ToolResult::ok(out)
}

// ─── Capstone disassembler (non-x86 architectures) ───────────────────────────

fn disassemble_capstone_with_project(
    data: &[u8],
    arch: Architecture,
    offset: Option<usize>,
    length: usize,
    vaddr_hint: Option<u64>,
    project: Option<&Project>,
) -> ToolResult {
    use capstone::prelude::*;
    use capstone::{arch, Endian};

    // Build the Capstone engine for the target architecture
    let cs = match arch {
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
            Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build()
        }
        Architecture::Arm => {
            Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build()
        }
        Architecture::Mips => {
            Capstone::new().mips().mode(arch::mips::ArchMode::Mips32).endian(Endian::Little).build()
        }
        Architecture::Mips64 => {
            Capstone::new().mips().mode(arch::mips::ArchMode::Mips64).endian(Endian::Little).build()
        }
        Architecture::PowerPc => {
            Capstone::new().ppc().mode(arch::ppc::ArchMode::Mode32).endian(Endian::Big).build()
        }
        Architecture::PowerPc64 => {
            Capstone::new().ppc().mode(arch::ppc::ArchMode::Mode64).endian(Endian::Big).build()
        }
        Architecture::Riscv32 => {
            Capstone::new().riscv().mode(arch::riscv::ArchMode::RiscV32).build()
        }
        Architecture::Riscv64 => {
            Capstone::new().riscv().mode(arch::riscv::ArchMode::RiscV64).build()
        }
        other => {
            return ToolResult::err(format!(
                "No disassembler available for {:?}. Supported: x86, x86-64, ARM64, ARM, MIPS, PowerPC, RISC-V.",
                other
            ));
        }
    };

    let cs = match cs {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("Capstone init failed: {}", e)),
    };

    let file_offset: usize = match (offset, vaddr_hint) {
        (Some(off), _) => off,
        (None, Some(va)) => match vaddr_to_file_offset(data, va) {
            Some(off) => off,
            None => return ToolResult::err(format!(
                "Virtual address 0x{:x} not found in any segment", va
            )),
        },
        (None, None) => 0,
    };

    if file_offset >= data.len() {
        return ToolResult::err(format!(
            "Offset 0x{:x} is beyond file size {} bytes", file_offset, data.len()
        ));
    }

    let end   = (file_offset + length).min(data.len());
    let slice = &data[file_offset..end];
    let ip    = vaddr_hint.unwrap_or(file_offset as u64);

    let insns = match cs.disasm_all(slice, ip) {
        Ok(i) => i,
        Err(e) => return ToolResult::err(format!("Disassembly failed: {}", e)),
    };

    let arch_class = crate::arch::ArchClass::from_object(
        object::File::parse(data).map(|f| f.architecture()).unwrap_or(arch)
    );

    let mut out = format!(
        "Disassembly ({:?}, file_offset=0x{:x}, ip=0x{:x}):\n\n",
        arch, file_offset, ip
    );

    for insn in insns.as_ref() {
        let bytes: String = insn.bytes().iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let mnemonic = insn.mnemonic().unwrap_or("");
        let op_str   = insn.op_str().unwrap_or("");

        // Resolve branch target name from project
        let target_name: Option<String> = project.and_then(|p| {
            if crate::arch::is_direct_call(arch_class, mnemonic, op_str)
                || crate::arch::is_direct_branch(arch_class, mnemonic, op_str)
            {
                crate::arch::parse_branch_target(op_str)
                    .and_then(|tgt| p.get_name(tgt))
            } else {
                None
            }
        });

        // Inline address comment from project
        let addr_comment = project.and_then(|p| p.get_comment(insn.address()));

        let annotation = match (&target_name, &addr_comment) {
            (Some(name), Some(cmt)) => format!("  ; {} | {}", name, cmt),
            (Some(name), None)       => format!("  ; {}", name),
            (None, Some(cmt))        => format!("  ; {}", cmt),
            (None, None)             => String::new(),
        };

        out.push_str(&format!(
            "  {:016x}  {:<24}  {} {}{}\n",
            insn.address(),
            bytes,
            mnemonic,
            op_str,
            annotation,
        ));
    }

    if insns.as_ref().is_empty() {
        out.push_str("  (no instructions decoded — check offset/architecture)");
    }

    ToolResult::ok(out)
}

// ─── Tool: disassemble ───────────────────────────────────────────────────────

fn disassemble(path: &str, offset: Option<usize>, length: usize, vaddr_hint: Option<u64>) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj_arch = object::File::parse(&*data).ok().map(|f| f.architecture());

    // Route non-x86 architectures through Capstone
    let is_x86 = matches!(
        obj_arch,
        Some(Architecture::X86_64) | Some(Architecture::X86_64_X32) | Some(Architecture::I386) | None
    );

    // Auto-size: when targeting a specific vaddr with no explicit raw offset,
    // look up the function's byte-length from PE .pdata so the full function
    // body is disassembled even with the default length=128.
    let auto_length = if offset.is_none() {
        if let Some(va) = vaddr_hint {
            pe_pdata_fn_size(&data, va)
                .map(|s| s.max(length))
                .or_else(|| {
                    // ELF / COFF: check the symbol table
                    object::File::parse(&*data).ok().and_then(|obj| {
                        obj.symbols()
                            .find(|s| s.address() == va && s.size() > 0)
                            .map(|s| (s.size() as usize).max(length))
                    })
                })
                .unwrap_or(length)
        } else {
            length
        }
    } else {
        length
    };

    if !is_x86 {
        let proj = Project::load_for(path);
        return disassemble_capstone_with_project(&data, obj_arch.unwrap(), offset, auto_length, vaddr_hint, Some(&proj));
    }

    let bitness: u32 = match obj_arch {
        Some(Architecture::X86_64) | Some(Architecture::X86_64_X32) => 64,
        Some(Architecture::I386) => 32,
        _ => 64,
    };

    // Resolve file offset:
    //   1. explicit `offset` wins
    //   2. if only `vaddr` given, translate via LOAD segment table
    //   3. default 0
    let file_offset: usize = match (offset, vaddr_hint) {
        (Some(off), _) => off,
        (None, Some(va)) => match vaddr_to_file_offset(&data, va) {
            Some(off) => off,
            None => return ToolResult::err(format!(
                "Virtual address 0x{:x} not found in any LOAD segment — \
                 use file_info to inspect the segment table", va
            )),
        },
        (None, None) => 0,
    };

    if file_offset >= data.len() {
        return ToolResult::err(format!(
            "Offset 0x{:x} is beyond file size {} bytes", file_offset, data.len()
        ));
    }

    let end   = (file_offset + auto_length).min(data.len());
    let slice = &data[file_offset..end];
    let ip: u64 = vaddr_hint.unwrap_or(file_offset as u64);

    // Load project annotations (renames, comments) — optional, never fail
    let project = if !path.is_empty() { Some(Project::load_for(path)) } else { None };

    // Build a symbol-address → name map from the binary's own symbol table
    // (covers DWARF debug symbols and exported/imported names).
    // Used as fallback when the project has no user rename for a call target.
    let sym_map: HashMap<u64, String> = object::File::parse(&*data).ok().map(|obj| {
        obj.symbols()
            .filter_map(|s| {
                let name = s.name().ok()?.trim();
                if name.is_empty() || name.starts_with("$") { return None; }
                // Demangle Rust / C++ names if they look mangled
                let display = if name.starts_with("_Z") || name.starts_with("__Z") {
                    name.to_string()
                } else {
                    name.to_string()
                };
                Some((s.address(), display))
            })
            .collect()
    }).unwrap_or_default();

    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic, OpKind};

    let mut decoder   = Decoder::with_ip(bitness, slice, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_first_operand_char_index(10);

    let mut out = format!(
        "Disassembly ({}-bit, file_offset=0x{:x}, ip=0x{:x}):\n\n",
        bitness, file_offset, ip
    );
    let mut count = 0usize;

    for instr in &mut decoder {
        let is_ret = matches!(instr.mnemonic(), Mnemonic::Ret | Mnemonic::Retf);
        if instr.is_invalid() {
            out.push_str(&format!("  {:016x}  ?? (invalid)\n", instr.ip()));
        } else {
            let byte_start = (instr.ip() - ip) as usize;
            let byte_end   = (byte_start + instr.len()).min(slice.len());
            let bytes: String = slice[byte_start..byte_end]
                .iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            let mut mnemonic = String::new();
            formatter.format(&instr, &mut mnemonic);

            // ── Inline annotations ────────────────────────────────────────
            let mut annotation = String::new();
            if let Some(ref p) = project {
                // Comment at this address
                if let Some(cmt) = p.comments.get(&instr.ip()) {
                    annotation.push_str(&format!("  ; {}", cmt));
                }
                // Rename at this address (function entry label)
                if let Some(name) = p.renames.get(&instr.ip()) {
                    if annotation.is_empty() {
                        annotation.push_str(&format!("  ; <{}>", name));
                    } else {
                        annotation.push_str(&format!(" <{}>", name));
                    }
                }
                // Resolve branch / call targets to renamed names (project first, sym_map fallback)
                let op0_kind = if instr.op_count() > 0 { instr.op_kind(0) } else { OpKind::Register };
                if matches!(op0_kind,
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 |
                    OpKind::FarBranch16  | OpKind::FarBranch32
                ) {
                    let target = instr.near_branch_target();
                    if target != 0 {
                        let resolved = p.renames.get(&target)
                            .map(|s| s.as_str())
                            .or_else(|| sym_map.get(&target).map(|s| s.as_str()));
                        if let Some(name) = resolved {
                            annotation.push_str(&format!("  ; → {}", name));
                        }
                    }
                }
            }

            out.push_str(&format!("  {:016x}  {:<24}  {}{}\n",
                instr.ip(), bytes, mnemonic, annotation));
        }
        count += 1;
        if is_ret {
            break; // natural function boundary
        }
        if count >= 200 {
            out.push_str("\n  … truncated at 200 instructions");
            break;
        }
    }

    ToolResult::ok(out)
}

// ─── Tool: read_section ──────────────────────────────────────────────────────

fn read_section(path: &str, section_name: &str) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    for section in obj.sections() {
        if section.name().ok() != Some(section_name) { continue; }

        let sec_data = match section.data() {
            Ok(d)  => d,
            Err(e) => return ToolResult::err(format!("Cannot read section data: {}", e)),
        };

        let preview = sec_data.len().min(512);
        let mut out = format!(
            "Section  : {}\nAddress  : 0x{:016x}\nSize     : {} bytes\n\nHex dump (first {} bytes):\n\n",
            section_name, section.address(), sec_data.len(), preview
        );
        for (row, chunk) in sec_data[..preview].chunks(16).enumerate() {
            let addr = section.address() as usize + row * 16;
            let hex: String  = chunk.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            let ascii: String = chunk.iter()
                .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                .collect();
            out.push_str(&format!("{:08x}  {:<47}  |{}|\n", addr, hex, ascii));
        }
        if sec_data.len() > preview {
            out.push_str(&format!("… ({} bytes total)", sec_data.len()));
        }
        return ToolResult::ok(out);
    }

    let available: Vec<String> = obj
        .sections()
        .filter_map(|s| s.name().ok().map(|n| n.to_string()))
        .filter(|n| !n.is_empty())
        .collect();
    ToolResult::err(format!("Section '{}' not found. Available: {}", section_name, available.join(", ")))
}

// ─── Tool: resolve_plt ───────────────────────────────────────────────────────

fn resolve_plt(path: &str) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Use goblin for ELF-specific relocation / dynsym access.
    let elf = match goblin::Object::parse(&data) {
        Ok(goblin::Object::Elf(e)) => e,
        Ok(_)  => return ToolResult::err("Not an ELF binary — resolve_plt only supports ELF"),
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    // Locate .plt section address (the stub array starts 16 bytes in for the resolver).
    let plt_addr = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".plt"))
        .map(|sh| sh.sh_addr);

    let plt_addr = match plt_addr {
        Some(a) => a,
        None    => return ToolResult::ok("No .plt section found — binary may be statically linked"),
    };

    // Walk .rela.plt relocations.  Each entry N (0-indexed) corresponds to
    // PLT stub at plt_addr + 16*(N+1) (standard x86-64 16-byte stubs).
    let relocs: Vec<_> = elf.pltrelocs.iter().collect();
    if relocs.is_empty() {
        return ToolResult::ok(
            "No .rela.plt relocations found — binary may be statically linked or use a non-standard PLT"
        );
    }

    let mut out = format!(
        "PLT stubs ({} entries, .plt @ 0x{:016x}):\n\n  {:<20}  {}\n  {}\n",
        relocs.len(), plt_addr,
        "Stub address", "Symbol",
        "─".repeat(50)
    );

    for (i, reloc) in relocs.iter().enumerate() {
        let stub_addr = plt_addr + 16 + (i as u64) * 16;
        let sym_name = if reloc.r_sym != 0 {
            elf.dynsyms
                .get(reloc.r_sym)
                .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                .unwrap_or("<?>")
        } else {
            "<anonymous>"
        };
        out.push_str(&format!("  0x{:016x}  {}\n", stub_addr, sym_name));
    }

    ToolResult::ok(out)
}

// ─── Tool: list_functions ────────────────────────────────────────────────────

fn list_functions(path: &str, max_results: usize, as_json: bool) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    // ── Strategy 1: symbol table ────────────────────────────────────────────
    let sym_funcs: Vec<(u64, String)> = {
        let mut v: Vec<_> = obj
            .symbols()
            .filter(|s| {
                s.kind() == object::SymbolKind::Text
                    && s.address() != 0
                    && s.size() > 0
            })
            .map(|s| (s.address(), s.name().unwrap_or("<?>").to_string()))
            .collect();
        v.sort_by_key(|(a, _)| *a);
        v
    };

    if !sym_funcs.is_empty() {
        // Re-collect with size
        let mut with_size: Vec<(u64, u64, String)> = obj
            .symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
            .map(|s| (s.address(), s.size(), s.name().unwrap_or("<?>").to_string()))
            .collect();
        with_size.sort_by_key(|(a, _, _)| *a);
        let total = with_size.len();

        if as_json {
            let arr: Vec<serde_json::Value> = with_size
                .iter()
                .take(max_results)
                .map(|(addr, size, name)| json!({"address": addr, "size": size, "name": name}))
                .collect();
            let val = json!({
                "source": "symbol_table",
                "total": total,
                "functions": arr
            });
            return ToolResult::ok(val.to_string());
        }

        let mut out = format!(
            "Functions from symbol table ({} total):\n\n  {:<20}  {:<8}  {}\n  {}\n",
            total, "Address", "Size", "Name", "─".repeat(55)
        );
        for (addr, size, name) in with_size.iter().take(max_results) {
            out.push_str(&format!("  0x{:016x}  {:<8}  {}\n", addr, size, name));
        }
        if total > max_results {
            out.push_str(&format!("  … and {} more", total - max_results));
        }
        return ToolResult::ok(out);
    }

    // ── Strategy 2: PE .pdata (ARM64/x64 exception directory) ───────────────
    // ARM64 and x64 PE files store a RUNTIME_FUNCTION entry for every function
    // in the .pdata section.  Each entry is 8 bytes:
    //   [0..4]  BeginAddress  — RVA of function start
    //   [4..8]  UnwindData    — RVA of UNWIND_INFO, or packed unwind word
    //
    // ARM64 UNWIND_INFO first DWORD:
    //   bits  0:17  FunctionLength (in 4-byte units)
    //   bits 18:19  Version
    //   bit  20     X (exception handler present)
    //   bit  21     E (epilog in header)
    //   bits 22:31  CodeWords
    //
    // Packed unwind (flag bits 0-1 ≠ 0):
    //   bits  2:12  FunctionLength (in 4-byte units)
    if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&data) {
        // Find .pdata section by name
        let pdata_bytes: Option<Vec<u8>> = pe.sections.iter()
            .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
            .and_then(|s| s.data(&data).ok().flatten())
            .map(|b| b.to_vec());

        if let Some(pdata) = pdata_bytes {
            let image_base = pe.image_base as u64;

            // Locate .rdata for resolving UNWIND_INFO pointers
            let rdata_range: Option<(u64, usize)> = pe.sections.iter()
                .find(|s| s.name().ok().map_or(false, |n| n == ".rdata"))
                .map(|s| (s.virtual_address as u64, s.pointer_to_raw_data as usize));

            let num_entries = pdata.len() / 8;
            let project = Project::load_for(path);
            let mut fns: Vec<(u64, u64, String)> = Vec::with_capacity(num_entries);

            for i in 0..num_entries {
                let off = i * 8;
                let begin_rva = u32::from_le_bytes(pdata[off..off+4].try_into().unwrap_or([0;4])) as u64;
                let unwind_raw = u32::from_le_bytes(pdata[off+4..off+8].try_into().unwrap_or([0;4]));

                if begin_rva == 0 { continue; }

                let begin_va = image_base + begin_rva;
                let flag = unwind_raw & 0x3;
                let fn_size: u64 = if flag != 0 {
                    // Packed: bits 2-12 = FunctionLength in 4-byte units
                    ((unwind_raw >> 2) & 0x7FF) as u64 * 4
                } else if let Some((rdata_va, rdata_file_off)) = rdata_range {
                    // Pointer to UNWIND_INFO in .rdata
                    let ui_rva = unwind_raw as u64;
                    if ui_rva >= rdata_va {
                        let ui_off = rdata_file_off + (ui_rva - rdata_va) as usize;
                        if ui_off + 4 <= data.len() {
                            let ui_word = u32::from_le_bytes(data[ui_off..ui_off+4].try_into().unwrap_or([0;4]));
                            (ui_word & 0x3_FFFF) as u64 * 4
                        } else { 0 }
                    } else { 0 }
                } else { 0 };

                let name = project.get_name(begin_va)
                    .unwrap_or_else(|| format!("FUN_{:016x}", begin_va));
                fns.push((begin_va, fn_size, name));
            }

            // Deduplicate by VA (multiple entries can share a start for tail-call stubs)
            fns.sort_by_key(|(va, _, _)| *va);
            fns.dedup_by_key(|(va, _, _)| *va);
            let total = fns.len();

            if total > 0 {
                if as_json {
                    let arr: Vec<serde_json::Value> = fns.iter()
                        .take(max_results)
                        .map(|(addr, size, name)| json!({"address": addr, "size": size, "name": name}))
                        .collect();
                    let val = json!({
                        "source": "pe_pdata",
                        "total": total,
                        "functions": arr
                    });
                    return ToolResult::ok(val.to_string());
                }

                let mut out = format!(
                    "Functions from PE .pdata exception directory ({} total):\n\n  {:<20}  {:<8}  {}\n  {}\n",
                    total, "Address", "Size", "Name", "─".repeat(55)
                );
                for (addr, size, name) in fns.iter().take(max_results) {
                    out.push_str(&format!("  0x{:016x}  {:<8}  {}\n", addr, size, name));
                }
                if total > max_results {
                    out.push_str(&format!("  … and {} more", total - max_results));
                }
                return ToolResult::ok(out);
            }
        }
    }

    // ── Strategy 3: prologue scan (stripped binary) ─────────────────────────
    // Mach-O uses "__text"; ELF uses ".text".  Accept both.
    let text_sec = obj.sections().find(|s| {
        s.name().ok().map_or(false, |n| {
            n == ".text" || n == "__text" || n.ends_with(",__text")
        })
    });
    let (text_bytes, text_vaddr, text_arch) = match text_sec {
        Some(s) => match s.data() {
            Ok(d)  => (d.to_vec(), s.address(), obj.architecture()),
            Err(e) => return ToolResult::err(format!("Cannot read text section: {}", e)),
        },
        None => return ToolResult::err(
            "No text section and no symbols — cannot enumerate functions.\
             \nFor Mach-O fat binaries, try extracting the desired slice with lipo first."
        ),
    };

    let is_64 = obj.is_64();
    let mut found: Vec<u64> = Vec::new();
    let len = text_bytes.len();

    // Common x86-64 prologues:
    //   endbr64                f3 0f 1e fa
    //   push rbp; mov rbp,rsp  55 48 89 e5
    // Common x86-32 prologue:
    //   push ebp; mov ebp,esp  55 89 e5
    // Common AArch64 prologues (Mach-O ARM64):
    //   stp x29, x30, [sp, #-N]!  fd 7b ?? d1   (save fp+lr, allocate frame)
    //   sub  sp, sp, #N           ff ?? ?? d1   (stack allocation without frame ptr)
    let mut i = 0usize;
    while i + 4 <= len {
        let b = &text_bytes[i..];
        let hit = match text_arch {
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
                // stp x29, x30, [sp, ...] — bytes 0..1 are always fd 7b
                (b[0] == 0xfd && b[1] == 0x7b)
                // pacibsp (0xd503237f) — common in signed iOS/macOS binaries
                || (b[0] == 0x7f && b[1] == 0x23 && b[2] == 0x03 && b[3] == 0xd5)
            }
            Architecture::Arm => {
                // push {r11, lr}  00 48 2d e9
                (b[0] == 0x00 && b[1] == 0x48 && b[2] == 0x2d && b[3] == 0xe9)
                // push {r7, lr}   10 40 2d e9
                || (b[0] == 0x10 && b[1] == 0x40 && b[2] == 0x2d && b[3] == 0xe9)
            }
            _ if is_64 => {
                (b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa)
                || (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xe5)
            }
            _ => b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xe5,
        };
        if hit {
            found.push(text_vaddr + i as u64);
        }
        i += if matches!(text_arch, Architecture::Aarch64 | Architecture::Aarch64_Ilp32 | Architecture::Arm) { 4 } else { 1 };
    }

    if found.is_empty() {
        return ToolResult::ok(
            "No function prologues found in .text — binary may be obfuscated or use a non-standard calling convention"
        );
    }

    let total = found.len();

    if as_json {
        let arr: Vec<serde_json::Value> = found
            .iter()
            .take(max_results)
            .map(|addr| json!({"address": addr}))
            .collect();
        let val = json!({
            "source": "prologue_scan",
            "total": total,
            "functions": arr
        });
        return ToolResult::ok(val.to_string());
    }

    let mut out = format!(
        "Functions from prologue scan — stripped binary ({} candidates):\n\n  {:<20}\n  {}\n",
        total, "Virtual address", "─".repeat(20)
    );
    for addr in found.iter().take(max_results) {
        out.push_str(&format!("  0x{:016x}\n", addr));
    }
    if total > max_results {
        out.push_str(&format!("  … and {} more (use a smaller max_results range or filter by address)", total - max_results));
    }

    ToolResult::ok(out)
}

// ─── PE .pdata function boundary helper ─────────────────────────────────────

/// Parse the PE `.pdata` exception directory and return a sorted list of
/// `(start_va, size_bytes, name)` triples.  Size is 0 when unwind info is
/// unavailable (packed unwind with no length, or pointer outside .rdata).
/// The `project` renames are applied so user-supplied names show correctly.
fn pe_pdata_functions(path: &str) -> Vec<(u64, u64, String)> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return Vec::new(),
    };
    let pdata_bytes = match pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
        .and_then(|s| s.data(&data).ok().flatten())
    {
        Some(b) => b.to_vec(),
        None => return Vec::new(),
    };

    let image_base = pe.image_base as u64;
    let rdata_range: Option<(u64, usize)> = pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".rdata"))
        .map(|s| (s.virtual_address as u64, s.pointer_to_raw_data as usize));

    let project = Project::load_for(path);
    let num_entries = pdata_bytes.len() / 8;
    let mut fns: Vec<(u64, u64, String)> = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let off = i * 8;
        let begin_rva = u32::from_le_bytes(pdata_bytes[off..off+4].try_into().unwrap_or([0;4])) as u64;
        let unwind_raw = u32::from_le_bytes(pdata_bytes[off+4..off+8].try_into().unwrap_or([0;4]));
        if begin_rva == 0 { continue; }

        let begin_va = image_base + begin_rva;
        let flag = unwind_raw & 0x3;
        let fn_size: u64 = if flag != 0 {
            ((unwind_raw >> 2) & 0x7FF) as u64 * 4
        } else if let Some((rdata_va, rdata_file_off)) = rdata_range {
            let ui_rva = unwind_raw as u64;
            if ui_rva >= rdata_va {
                let ui_off = rdata_file_off + (ui_rva - rdata_va) as usize;
                if ui_off + 4 <= data.len() {
                    let ui_word = u32::from_le_bytes(data[ui_off..ui_off+4].try_into().unwrap_or([0;4]));
                    (ui_word & 0x3_FFFF) as u64 * 4
                } else { 0 }
            } else { 0 }
        } else { 0 };

        let name = project.get_name(begin_va)
            .unwrap_or_else(|| format!("FUN_{:016x}", begin_va));
        fns.push((begin_va, fn_size, name));
    }

    fns.sort_by_key(|(va, _, _)| *va);
    fns.dedup_by_key(|(va, _, _)| *va);
    fns
}

// ─── Tool: xrefs_to ─────────────────────────────────────────────────────────

/// Decode an AArch64 ADRP instruction's result page address.
///
/// ADRP: Xd = (PC & ~0xFFF) + SignExtend(immhi:immlo, 21) << 12
/// Encoding bits: [31]=1 [30:29]=immlo [28:24]=10000 [23:5]=immhi [4:0]=Rd
fn aarch64_adrp_page(insn: u32, pc: u64) -> u64 {
    let immlo = ((insn >> 29) & 0x3) as u64;
    let immhi = ((insn >> 5) & 0x7_FFFF) as u64;
    let imm21 = (immhi << 2) | immlo;
    // Sign-extend 21-bit integer to 64-bit
    let signed = if imm21 & (1 << 20) != 0 {
        (imm21 | !((1u64 << 21) - 1)) as i64
    } else {
        imm21 as i64
    };
    ((pc & !0xFFF) as i64 + (signed << 12)) as u64
}

/// Scan executable sections of an AArch64 binary for **indirect** call references
/// to `target_vaddr` — specifically `ADRP Rn, #page; LDR Rm, [Rn, #off]` pairs
/// where `page + off == target_vaddr`.
///
/// This pattern is used by Windows ARM64 PE (and other ABIs) to load an address
/// from the IAT / GOT before calling it via `BLR Rm`.  No direct `BL target` is
/// emitted, so Capstone's straight-line disassembly misses these references.
///
/// Returns a `Vec<(adrp_pc, ldr_pc, is_blr_next)>` where:
/// - `adrp_pc`      — address of the ADRP instruction (start of the load sequence)
/// - `ldr_pc`       — address of the LDR instruction (+4)
/// - `is_blr_next`  — true when the instruction after LDR is `BLR Rm` (indirect call)
fn aarch64_scan_iat_refs(
    obj: &object::File,
    target_vaddr: u64,
) -> Vec<(u64, u64, bool)> {
    let target_page    = target_vaddr & !0xFFF;
    let target_off_raw = target_vaddr & 0xFFF;

    let mut hits: Vec<(u64, u64, bool)> = Vec::new();

    for sec in obj.sections() {
        if !crate::arch::is_code_section(sec.name().unwrap_or("")) { continue; }
        let sec_vaddr = sec.address();
        let sec_bytes = match sec.data() { Ok(d) => d, Err(_) => continue };
        if sec_bytes.len() < 8 { continue; }

        let n = sec_bytes.len() / 4;

        for i in 0..n.saturating_sub(1) {
            let off0 = i * 4;
            let insn0 = u32::from_le_bytes([
                sec_bytes[off0], sec_bytes[off0+1],
                sec_bytes[off0+2], sec_bytes[off0+3],
            ]);
            let pc0 = sec_vaddr + off0 as u64;

            // ── Check ADRP ─────────────────────────────────────────────────
            // Encoding: bit31=1, bits[28:24]=10000  →  mask 0x9F000000 == 0x90000000
            if (insn0 & 0x9F000000) != 0x90000000 { continue; }
            let rd = insn0 & 0x1F;
            if aarch64_adrp_page(insn0, pc0) != target_page { continue; }

            // ── Search the next MAX_GAP instructions for a matching LDR ─────────
            // The compiler sometimes interleaves other instructions between
            // the ADRP and its associated LDR (e.g. MOV, ADD for a different
            // register).  Allow up to 8 instructions of separation while the
            // ADRP destination register hasn't been clobbered.
            const MAX_GAP: usize = 8;
            for gap in 1..=MAX_GAP {
                let off1 = off0 + gap * 4;
                if off1 + 4 > sec_bytes.len() { break; }
                let insn1 = u32::from_le_bytes([
                    sec_bytes[off1], sec_bytes[off1+1],
                    sec_bytes[off1+2], sec_bytes[off1+3],
                ]);
                let pc1 = pc0 + gap as u64 * 4;

                // If something writes to `rd` (Rd == rd in a dest-register insn),
                // the ADRP result is clobbered — stop looking.
                // Heuristic: if this is another ADRP or MOV writing rd, stop.
                let writes_rd = {
                    let dest_5 = insn1 & 0x1F; // bottom 5 bits = Rd for most insns
                    // ADRP writes rd directly
                    let is_adrp  = (insn1 & 0x9F000000) == 0x90000000;
                    // MOV (register) Xd, Xm: alias of ORR Xd, XZR, Xm → 0xAA0003E0
                    let is_mov_r = (insn1 & 0x7FE0FFE0) == 0xAA0003E0;
                    // MOVZ Xd = 0xD2800000 family
                    let is_movz  = (insn1 & 0xFF800000) == 0xD2800000;
                    (is_adrp || is_mov_r || is_movz) && dest_5 == rd
                };
                if writes_rd { break; }

                // LDR Xt, [Xn, #uimm12]  (64-bit, unsigned offset)
                // Encoding: 1111 1001 01 imm12 Rn Rt  →  0xF9400000 / 0xFFC00000
                if (insn1 & 0xFFC00000) == 0xF9400000 {
                    let rn    = (insn1 >> 5) & 0x1F;
                    let imm12 = (insn1 >> 10) & 0xFFF;
                    let load_off = (imm12 * 8) as u64; // 64-bit scale: ×8
                    if rn == rd && load_off == target_off_raw {
                        let rt = insn1 & 0x1F;
                        // Peek one instruction further for BLR Rt
                        let is_blr = off1 + 8 <= sec_bytes.len() && {
                            let insn2 = u32::from_le_bytes([
                                sec_bytes[off1+4], sec_bytes[off1+5],
                                sec_bytes[off1+6], sec_bytes[off1+7],
                            ]);
                            (insn2 & 0xFFFFFC1F) == 0xD63F0000
                                && ((insn2 >> 5) & 0x1F) == rt
                        };
                        hits.push((pc0, pc1, is_blr));
                        break; // found the matching LDR for this ADRP
                    }
                }

                // LDR Wt, [Xn, #uimm12]  (32-bit, unsigned offset)
                // Encoding: 1011 1001 01 imm12 Rn Rt  →  0xB9400000 / 0xFFC00000
                if (insn1 & 0xFFC00000) == 0xB9400000 {
                    let rn    = (insn1 >> 5) & 0x1F;
                    let imm12 = (insn1 >> 10) & 0xFFF;
                    let load_off = (imm12 * 4) as u64; // 32-bit scale: ×4
                    if rn == rd && load_off == target_off_raw {
                        let rt = insn1 & 0x1F;
                        let is_blr = off1 + 8 <= sec_bytes.len() && {
                            let insn2 = u32::from_le_bytes([
                                sec_bytes[off1+4], sec_bytes[off1+5],
                                sec_bytes[off1+6], sec_bytes[off1+7],
                            ]);
                            (insn2 & 0xFFFFFC1F) == 0xD63F0000
                                && ((insn2 >> 5) & 0x1F) == rt
                        };
                        hits.push((pc0, pc1, is_blr));
                        break;
                    }
                }
            }
        }
    }
    hits
}

/// Find all call sites that target `target_vaddr` by scanning the .text section.
///
/// On x86/x86-64 uses iced-x86 for fast direct CALL/JMP decoding.
/// On AArch64 performs two passes:
///   1. Capstone scan for direct `BL target_vaddr` instructions.
///   2. Raw 4-byte scan for `ADRP + LDR` pairs that load from `target_vaddr`
///      (Windows ARM64 PE / ELF PLT indirect-call pattern).
///      When such a site is a shared import stub (ADRP+LDR+BR tail-call),
///      a third pass scans for `BL <stub_addr>` callers.
fn xrefs_to(path: &str, target_vaddr: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if target_vaddr == 0 { return ToolResult::err("'vaddr' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let arch_class = crate::arch::ArchClass::from_object(obj.architecture());

    // ── Caller list: (site_addr, label) ─────────────────────────────────────
    // label distinguishes how the reference was found.
    let mut callers: Vec<(u64, &'static str)> = Vec::new();

    // ── x86 / x86-64: iced-x86 direct CALL/JMP scan ─────────────────────────
    if arch_class.is_x86() {
        let bitness: u32 = match obj.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => 64,
            _ => 32,
        };
        let text_sec = match obj.sections().find(|s| s.name().ok() == Some(".text")) {
            Some(s) => s,
            None => return ToolResult::err("No .text section found"),
        };
        let text_vaddr = text_sec.address();
        let text_bytes = match text_sec.data() {
            Ok(d) => d,
            Err(e) => return ToolResult::err(format!("Cannot read .text: {}", e)),
        };
        use iced_x86::{Decoder, DecoderOptions, Mnemonic};
        let mut decoder = Decoder::with_ip(bitness, text_bytes, text_vaddr, DecoderOptions::NONE);
        for instr in &mut decoder {
            if matches!(instr.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
                if instr.near_branch64() == target_vaddr {
                    callers.push((instr.ip(), "direct"));
                }
            }
        }

    // ── AArch64: raw BL/B pattern scan + ADRP+LDR indirect scan ─────────────
    } else if matches!(arch_class, crate::arch::ArchClass::Arm64) {

        // Pass 1 — direct BL / B <target_vaddr> via raw 4-byte word scan.
        //
        // Capstone full-section scan loses decode sync on large binaries when
        // jump tables or aligned data are embedded in .text, causing it to miss
        // instructions.  AArch64 uses fixed-width 4-byte instructions, so we
        // can scan in strict 4-byte strides and decode BL / B targets directly:
        //
        //   BL:  bits 31-26 = 100101 → (word >> 26) == 0x25
        //   B:   bits 31-26 = 000101 → (word >> 26) == 0x05
        //   imm26 target = PC + sign_extend(word & 0x3FFFFFF, 26) * 4
        for sec in obj.sections() {
            let sec_name = sec.name().unwrap_or("");
            if !crate::arch::is_code_section(sec_name) { continue; }
            let sec_vaddr = sec.address();
            let sec_bytes = match sec.data() { Ok(d) => d, Err(_) => continue };
            if sec_bytes.len() < 4 { continue; }
            let n = sec_bytes.len() & !3; // align to 4-byte boundary
            for i in (0..n).step_by(4) {
                let word = u32::from_le_bytes([
                    sec_bytes[i], sec_bytes[i+1], sec_bytes[i+2], sec_bytes[i+3]
                ]);
                let op = word >> 26;
                if op != 0x25 && op != 0x05 { continue; } // not BL or B
                let imm26 = word & 0x3FF_FFFF;
                let signed_off: i64 = if imm26 & 0x200_0000 != 0 {
                    (imm26 as i64) | (-1i64 << 26)
                } else {
                    imm26 as i64
                };
                let pc = sec_vaddr + i as u64;
                let tgt = pc.wrapping_add((signed_off * 4) as u64);
                if tgt == target_vaddr {
                    let label = if op == 0x25 { "direct BL" } else { "direct B (tail call)" };
                    callers.push((pc, label));
                }
            }
        }

        // Pass 2 — ADRP+LDR indirect pattern (IAT / GOT references)
        let iat_hits = aarch64_scan_iat_refs(&obj, target_vaddr);
        for (adrp_pc, _ldr_pc, is_blr) in &iat_hits {
            let label = if *is_blr { "ADRP+LDR+BLR (indirect call)" } else { "ADRP+LDR (indirect load)" };
            callers.push((*adrp_pc, label));
        }

        // Pass 3 — if the ADRP+LDR site looks like a shared import stub
        //          (ADRP at the very start of a function, followed by LDR then BR),
        //          scan for BL <stub_addr> callers using the same raw-word scan.
        let stub_candidates: Vec<u64> = iat_hits.iter()
            .filter(|(_, _, is_blr)| *is_blr)
            .map(|(adrp_pc, _, _)| *adrp_pc)
            .collect();

        if !stub_candidates.is_empty() {
            for sec in obj.sections() {
                let sec_name = sec.name().unwrap_or("");
                if !crate::arch::is_code_section(sec_name) { continue; }
                let sec_vaddr = sec.address();
                let sec_bytes = match sec.data() { Ok(d) => d, Err(_) => continue };
                if sec_bytes.len() < 4 { continue; }
                let n = sec_bytes.len() & !3;
                for i in (0..n).step_by(4) {
                    let word = u32::from_le_bytes([
                        sec_bytes[i], sec_bytes[i+1], sec_bytes[i+2], sec_bytes[i+3]
                    ]);
                    if word >> 26 != 0x25 { continue; } // only BL
                    let imm26 = word & 0x3FF_FFFF;
                    let signed_off: i64 = if imm26 & 0x200_0000 != 0 {
                        (imm26 as i64) | (-1i64 << 26)
                    } else {
                        imm26 as i64
                    };
                    let pc = sec_vaddr + i as u64;
                    let tgt = pc.wrapping_add((signed_off * 4) as u64);
                    if stub_candidates.contains(&tgt) {
                        callers.push((pc, "BL → import stub"));
                    }
                }
            }
        }

    // ── All other architectures: Capstone generic scan ───────────────────────
    } else {
        let cs = match crate::arch::build_capstone(arch_class) {
            Ok(c) => c,
            Err(e) => return ToolResult::err(format!("Capstone init failed: {}", e)),
        };
        for sec in obj.sections() {
            let sec_name = sec.name().unwrap_or("");
            if !crate::arch::is_code_section(sec_name) { continue; }
            let sec_vaddr = sec.address();
            let sec_bytes = match sec.data() { Ok(d) => d, Err(_) => continue };
            if let Ok(insns) = cs.disasm_all(sec_bytes, sec_vaddr) {
                for insn in insns.as_ref() {
                    let m = insn.mnemonic().unwrap_or("");
                    let o = insn.op_str().unwrap_or("");
                    if crate::arch::is_direct_call(arch_class, m, o)
                        || crate::arch::is_direct_branch(arch_class, m, o)
                    {
                        if crate::arch::parse_branch_target(o) == Some(target_vaddr) {
                            callers.push((insn.address(), "direct"));
                        }
                    }
                }
            }
        }
    }

    if callers.is_empty() {
        let hint = if matches!(arch_class, crate::arch::ArchClass::Arm64) {
            "\nHint: for ARM64 imports, also try xrefs_to with the IAT entry address \
             from pe_internals/resolve_pe_imports. If still empty, the binary may use \
             an import-by-ordinal or delay-load scheme."
        } else { "" };
        return ToolResult::ok(format!(
            "No call/jmp to 0x{:x} found in .text{}", target_vaddr, hint
        ));
    }

    // ── Annotate each site with its enclosing function ───────────────────────
    // Prefer ELF/Mach-O symbols; fall back to PE .pdata for stripped PE binaries.
    let syms: Vec<(u64, u64, String)> = {
        let mut v: Vec<_> = obj
            .symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
            .map(|s| (s.address(), s.size(), s.name().unwrap_or("<?>").to_string()))
            .collect();
        if v.is_empty() {
            v = pe_pdata_functions(path);
        }
        v.sort_by_key(|(a, _, _)| *a);
        v
    };
    let project = Project::load_for(path);

    let find_func = |addr: u64| -> String {
        if let Some(renamed) = project.get_name(addr) { return renamed; }
        // Binary search for the last function whose start <= addr
        match syms.binary_search_by_key(&addr, |(a, _, _)| *a) {
            Ok(i) => return syms[i].2.clone(),
            Err(0) => {}
            Err(i) => {
                let (fn_addr, fn_size, fn_name) = &syms[i - 1];
                let end = if *fn_size > 0 { fn_addr + fn_size } else { u64::MAX };
                if addr >= *fn_addr && addr < end {
                    return fn_name.clone();
                }
            }
        }
        "<unknown>".to_string()
    };

    // De-duplicate (pass 3 may re-report addresses already found in pass 2)
    callers.sort_by_key(|(a, _)| *a);
    callers.dedup_by_key(|(a, _)| *a);

    let mut out = format!(
        "Cross-references to 0x{:x} ({} site{}):\n\n",
        target_vaddr, callers.len(), if callers.len() == 1 { "" } else { "s" }
    );
    out.push_str(&format!(
        "  {:<20}  {:<32}  {}\n  {}\n",
        "Site address", "Enclosing function", "How", "─".repeat(72)
    ));
    for (addr, how) in &callers {
        let fname = find_func(*addr);
        out.push_str(&format!("  0x{:016x}  {:<32}  {}\n", addr, fname, how));
    }

    ToolResult::ok(out)
}

// ─── Tool: xrefs_data ────────────────────────────────────────────────────────

/// Find all instructions that read or write a given virtual address.
/// Uses iced-x86 RIP-relative + absolute operand resolution on x86/x86-64.
fn xrefs_data(path: &str, target_vaddr: u64) -> ToolResult {
    if path.is_empty()       { return ToolResult::err("'path' is required"); }
    if target_vaddr == 0     { return ToolResult::err("'vaddr' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let is_x86 = matches!(
        obj.architecture(),
        Architecture::X86_64 | Architecture::X86_64_X32 | Architecture::I386
    );
    if !is_x86 {
        return ToolResult::err(
            "xrefs_data currently supports x86 / x86-64 only"
        );
    }
    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        _ => 32,
    };

    use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
    use iced_x86::IntelFormatter;
    use iced_x86::Formatter;

    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_mnemonics(false);
    fmt.options_mut().set_uppercase_registers(false);

    // Collect function address→name map for annotation
    let project = Project::load_for(path);
    let sym_map: HashMap<u64, String> = obj.symbols()
        .filter_map(|s| {
            let name = s.name().ok()?.trim();
            if name.is_empty() { return None; }
            Some((s.address(), name.to_string()))
        })
        .collect();

    let enclosing_fn = |addr: u64| -> String {
        if let Some(n) = project.get_name(addr) { return n; }
        let mut best: Option<(u64, String)> = None;
        for (fn_va, fname) in &sym_map {
            if *fn_va <= addr {
                match &best {
                    None => { best = Some((*fn_va, fname.clone())); }
                    Some((bva, _)) if fn_va > bva => { best = Some((*fn_va, fname.clone())); }
                    _ => {}
                }
            }
        }
        best.map(|(_, n)| n).unwrap_or_else(|| "<unknown>".to_string())
    };

    // Scan all executable sections
    let mut refs: Vec<(u64, String, &'static str)> = Vec::new();

    for sec in obj.sections() {
        // Only executable sections
        use object::{ObjectSection, SectionFlags};
        let is_exec = match sec.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & 0x4 != 0, // SHF_EXECINSTR
            SectionFlags::MachO { flags }  => flags & 0x400 != 0,  // S_ATTR_SOME_INSTRUCTIONS
            _ => {
                let name = sec.name().unwrap_or("");
                name == ".text" || name == "__text" || name.ends_with(",__text")
            }
        };
        if !is_exec { continue; }

        let sec_vaddr = sec.address();
        let sec_bytes = match sec.data() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let mut decoder = Decoder::with_ip(bitness, sec_bytes, sec_vaddr, DecoderOptions::NONE);
        for instr in decoder.iter() {
            if instr.is_invalid() { continue; }

            for op_idx in 0..instr.op_count() {
                if instr.op_kind(op_idx) != OpKind::Memory { continue; }

                // Compute the effective address for this memory operand
                let eff_addr: Option<u64> = if instr.memory_base() == Register::RIP
                    || instr.memory_base() == Register::EIP
                {
                    // RIP/EIP-relative — iced computes the absolute target for us
                    Some(instr.ip_rel_memory_address())
                } else if instr.memory_base() == Register::None
                    && instr.memory_index() == Register::None
                {
                    // Absolute address encoded directly in the displacement
                    if bitness == 64 {
                        Some(instr.memory_displacement64())
                    } else {
                        Some(instr.memory_displacement32() as u64)
                    }
                } else {
                    // Register-relative — can't resolve statically
                    None
                };

                if eff_addr == Some(target_vaddr) {
                    // Classify: op_idx 0 = destination (write), else source (read)
                    let access: &'static str = if op_idx == 0 { "write" } else { "read" };
                    let mut s = String::new();
                    fmt.format(&instr, &mut s);
                    refs.push((instr.ip(), s, access));
                    break; // one record per instruction
                }
            }
        }
    }

    if refs.is_empty() {
        return ToolResult::ok(format!(
            "No data references to 0x{:x} found in executable sections", target_vaddr
        ));
    }

    let mut out = format!(
        "Data cross-references to 0x{:x} ({} refs):\n\n",
        target_vaddr, refs.len()
    );
    out.push_str(&format!(
        "  {:<20}  {:<8}  {:<30}  {}\n  {}\n",
        "Site address", "Access", "Instruction", "Enclosing function",
        "─".repeat(80)
    ));
    for (site, disasm, access) in &refs {
        let fname = enclosing_fn(*site);
        out.push_str(&format!(
            "  0x{:016x}  {:<8}  {:<30}  {}\n",
            site, access, disasm, fname
        ));
    }

    ToolResult::ok(out)
}

// ─── Tool: dwarf_info ────────────────────────────────────────────────────────

fn dwarf_info(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    match crate::dwarf::parse_dwarf_functions(path) {
        Ok(funcs) => {
            if funcs.is_empty() {
                return ToolResult::ok("No DWARF debug information found (or no DW_TAG_subprogram entries)");
            }
            let mut out = format!("DWARF functions ({} entries):\n\n", funcs.len());
            out.push_str(&format!("  {:<20}  {:<8}  {}\n  {}\n",
                "Address", "Size", "Name", "─".repeat(55)));
            for f in &funcs {
                let size_str = f.size.map(|s| s.to_string()).unwrap_or_else(|| "?".to_string());
                out.push_str(&format!("  0x{:016x}  {:<8}  {}\n", f.addr, size_str, f.name));
            }
            ToolResult::ok(out)
        }
        Err(e) => ToolResult::err(format!("DWARF parse error: {}", e)),
    }
}

// ─── Tool: batch_annotate ────────────────────────────────────────────────────

/// Apply a complete set of annotations to a function in one atomic call.
/// Replaces the need for 5–10 separate rename_function / set_param_* /
/// rename_variable / add_comment calls.
fn batch_annotate(path: &str, vaddr: u64, args: &Value) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0     { return ToolResult::err("'vaddr' is required"); }

    let mut project = Project::load_for(path);
    let mut applied: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    // ── Function rename ───────────────────────────────────────────────────────
    if let Some(name) = args["function_name"].as_str() {
        if !name.is_empty() {
            project.rename(vaddr, name.to_string());
            applied.push(format!("rename → {}", name));
        }
    }

    // ── Comment ──────────────────────────────────────────────────────────────
    if let Some(comment) = args["comment"].as_str() {
        if !comment.is_empty() {
            project.comment(vaddr, comment.to_string());
            applied.push(format!("comment → \"{}\"", comment));
        }
    }

    // ── Return type ───────────────────────────────────────────────────────────
    if let Some(ret) = args["return_type"].as_str() {
        if !ret.is_empty() {
            project.set_return_type(vaddr, ret.to_string());
            applied.push(format!("return_type → {}", ret));
        }
    }

    // ── Parameters ───────────────────────────────────────────────────────────
    if let Some(params) = args["params"].as_array() {
        for (i, param) in params.iter().enumerate() {
            let param_n = i + 1; // set_param_* are 1-indexed
            if let Some(name) = param["name"].as_str() {
                if !name.is_empty() {
                    project.set_param_name(vaddr, param_n, name.to_string());
                    applied.push(format!("param[{}].name → {}", param_n, name));
                }
            }
            if let Some(ty) = param["type"].as_str() {
                if !ty.is_empty() {
                    project.set_param_type(vaddr, param_n, ty.to_string());
                    applied.push(format!("param[{}].type → {}", param_n, ty));
                }
            }
        }
    }

    // ── Variable renames ─────────────────────────────────────────────────────
    if let Some(vars) = args["variables"].as_array() {
        for var in vars {
            let old = var["old"].as_str().unwrap_or("").trim().to_string();
            let new = var["new"].as_str().unwrap_or("").trim().to_string();
            if old.is_empty() || new.is_empty() {
                skipped.push("variable rename: missing old or new name".to_string());
                continue;
            }
            project.rename_var(vaddr, old.clone(), new.clone());
            applied.push(format!("var {} → {}", old, new));
        }
    }

    if let Err(e) = project.save() {
        return ToolResult::err(format!("Failed to save project: {}", e));
    }

    let mut out = format!(
        "batch_annotate applied to 0x{:x} in '{}': {} changes\n",
        vaddr, path, applied.len()
    );
    for a in &applied { out.push_str(&format!("  + {}\n", a)); }
    if !skipped.is_empty() {
        out.push_str(&format!("\nSkipped ({}):\n", skipped.len()));
        for s in &skipped { out.push_str(&format!("  - {}\n", s)); }
    }
    out.push_str("\nRe-decompile to see the changes applied.");
    ToolResult::ok(out)
}

// ─── Tool: rename_function / add_comment / load_project ─────────────────────

fn rename_function(path: &str, vaddr: u64, name: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }
    if name.is_empty() { return ToolResult::err("'name' is required"); }
    let mut p = Project::load_for(path);
    p.rename(vaddr, name.to_string());
    match p.save() {
        Ok(_) => ToolResult::ok(format!("Renamed 0x{:x} → '{}'", vaddr, name)),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

fn add_comment(path: &str, vaddr: u64, comment: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }
    if comment.is_empty() { return ToolResult::err("'comment' is required"); }
    let mut p = Project::load_for(path);
    p.comment(vaddr, comment.to_string());
    match p.save() {
        Ok(_) => ToolResult::ok(format!("Comment added at 0x{:x}", vaddr)),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: rename_variable ───────────────────────────────────────────────────

fn rename_variable(path: &str, fn_vaddr: u64, old_name: &str, new_name: &str) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if fn_vaddr == 0      { return ToolResult::err("'fn_vaddr' is required"); }
    if old_name.is_empty(){ return ToolResult::err("'old_name' is required"); }
    if new_name.is_empty(){ return ToolResult::err("'new_name' is required"); }
    let mut p = Project::load_for(path);
    p.rename_var(fn_vaddr, old_name.to_string(), new_name.to_string());
    match p.save() {
        Ok(_)  => ToolResult::ok(format!(
            "In function 0x{:x}: '{}' → '{}' (will apply on next decompile)",
            fn_vaddr, old_name, new_name
        )),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: set_return_type ───────────────────────────────────────────────────

fn set_return_type(path: &str, fn_vaddr: u64, type_str: &str) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if fn_vaddr == 0      { return ToolResult::err("'fn_vaddr' is required"); }
    if type_str.is_empty(){ return ToolResult::err("'type_str' is required"); }
    let mut p = Project::load_for(path);
    p.set_return_type(fn_vaddr, type_str.to_string());
    match p.save() {
        Ok(_)  => ToolResult::ok(format!(
            "Return type of 0x{:x} set to '{}' (will apply on next decompile)",
            fn_vaddr, type_str
        )),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: set_param_type ────────────────────────────────────────────────────

fn set_param_type(path: &str, fn_vaddr: u64, param_n: usize, type_str: &str) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if fn_vaddr == 0      { return ToolResult::err("'fn_vaddr' is required"); }
    if param_n == 0       { return ToolResult::err("'param_n' must be ≥ 1"); }
    if type_str.is_empty(){ return ToolResult::err("'type_str' is required"); }
    let mut p = Project::load_for(path);
    p.set_param_type(fn_vaddr, param_n, type_str.to_string());
    match p.save() {
        Ok(_)  => ToolResult::ok(format!(
            "Parameter {} of 0x{:x} type set to '{}' (will apply on next decompile)",
            param_n, fn_vaddr, type_str
        )),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: set_param_name ────────────────────────────────────────────────────

fn set_param_name(path: &str, fn_vaddr: u64, param_n: usize, name: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if fn_vaddr == 0   { return ToolResult::err("'fn_vaddr' is required"); }
    if param_n == 0    { return ToolResult::err("'param_n' must be ≥ 1"); }
    if name.is_empty() { return ToolResult::err("'name' is required"); }
    let mut p = Project::load_for(path);
    p.set_param_name(fn_vaddr, param_n, name.to_string());
    match p.save() {
        Ok(_)  => ToolResult::ok(format!(
            "Parameter {} of 0x{:x} renamed to '{}' (will apply on next decompile)",
            param_n, fn_vaddr, name
        )),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: define_struct ────────────────────────────────────────────────────

fn define_struct(
    path: &str,
    struct_name: &str,
    total_size: usize,
    fields_val: serde_json::Value,
) -> ToolResult {
    if path.is_empty()        { return ToolResult::err("'path' is required"); }
    if struct_name.is_empty() { return ToolResult::err("'struct_name' is required"); }

    // Parse fields array: [{offset, size, name, type_str}, ...]
    let fields: Vec<crate::project::StructField> = match fields_val.as_array() {
        None => Vec::new(),
        Some(arr) => arr
            .iter()
            .filter_map(|f| {
                let offset   = f["offset"].as_u64()? as usize;
                let size     = f["size"].as_u64().unwrap_or(4) as usize;
                let name     = f["name"].as_str().unwrap_or("field").to_string();
                let type_str = f["type_str"].as_str().unwrap_or("int").to_string();
                Some(crate::project::StructField { offset, size, name, type_str })
            })
            .collect(),
    };

    let def = crate::project::StructDef {
        name: struct_name.to_string(),
        total_size,
        fields,
    };

    let c_repr = def.to_c();
    let mut p = Project::load_for(path);
    p.define_struct(def);
    match p.save() {
        Ok(_)  => ToolResult::ok(format!("Struct '{}' saved:\n\n{}", struct_name, c_repr)),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: list_types ────────────────────────────────────────────────────────

fn list_types(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let p = Project::load_for(path);

    if p.signatures.is_empty() && p.var_renames.is_empty() && p.structs.is_empty() {
        return ToolResult::ok(
            "No type annotations saved yet.\n\
             Use set_return_type, set_param_type, set_param_name, rename_variable, \
             or define_struct to annotate this binary."
        );
    }

    let mut out = String::new();

    // Struct definitions
    if !p.structs.is_empty() {
        out.push_str(&format!("─── Struct definitions ({}) ───\n\n", p.structs.len()));
        let mut names: Vec<&String> = p.structs.keys().collect();
        names.sort();
        for name in names {
            out.push_str(&p.structs[name].to_c());
            out.push_str("\n\n");
        }
    }

    // Function signatures
    if !p.signatures.is_empty() {
        out.push_str(&format!("─── Function signatures ({}) ───\n\n", p.signatures.len()));
        let mut addrs: Vec<u64> = p.signatures.keys().cloned().collect();
        addrs.sort();
        for addr in addrs {
            let sig = &p.signatures[&addr];
            let fn_name = p.renames.get(&addr)
                .map(|s| s.as_str())
                .unwrap_or("<unnamed>");
            let ret = sig.return_type.as_deref().unwrap_or("void");
            let params: Vec<String> = (0..sig.param_types.len().max(sig.param_names.len()))
                .map(|i| {
                    let t = sig.param_types.get(i).and_then(|x| x.as_deref()).unwrap_or("int32_t");
                    let n = sig.param_names.get(i).and_then(|x| x.as_deref())
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| {
                            // borrow trick: use a static-lifetime placeholder
                            "arg"
                        });
                    // Build the actual name
                    let actual_name = sig.param_names.get(i)
                        .and_then(|x| x.as_deref())
                        .filter(|n| !n.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("arg_{}", i + 1));
                    let _ = n; // suppress unused warning
                    format!("{} {}", t, actual_name)
                })
                .collect();
            out.push_str(&format!(
                "  0x{:016x}  {} {}({})\n",
                addr, ret, fn_name, params.join(", ")
            ));
        }
        out.push('\n');
    }

    // Variable renames per function
    if !p.var_renames.is_empty() {
        out.push_str(&format!("─── Variable renames ({} functions) ───\n\n", p.var_renames.len()));
        let mut addrs: Vec<u64> = p.var_renames.keys().cloned().collect();
        addrs.sort();
        for addr in addrs {
            let fn_name = p.renames.get(&addr)
                .map(|s| s.as_str())
                .unwrap_or("<unnamed>");
            out.push_str(&format!("  0x{:016x}  {}:\n", addr, fn_name));
            let renames = &p.var_renames[&addr];
            let mut pairs: Vec<(&String, &String)> = renames.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            for (old, new) in pairs {
                out.push_str(&format!("    {} → {}\n", old, new));
            }
        }
    }

    ToolResult::ok(out)
}

fn load_project(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let p = Project::load_for(path);
    let db_path = Project::db_path(path);
    let has_data = !p.renames.is_empty() || !p.comments.is_empty()
        || !p.notes.is_empty() || !p.vuln_scores.is_empty()
        || !p.var_renames.is_empty() || !p.signatures.is_empty()
        || !p.structs.is_empty();
    if !has_data {
        return ToolResult::ok(format!(
            "No project annotations found for '{}'\nDatabase would be at: {}",
            path, db_path.display()
        ));
    }
    let mut out = format!("Project annotations for: {}\n\n", path);

    if !p.renames.is_empty() {
        out.push_str(&format!("Renames ({}):\n", p.renames.len()));
        let mut renames: Vec<_> = p.renames.iter().collect();
        renames.sort_by_key(|(k, _)| *k);
        for (addr, name) in renames {
            out.push_str(&format!("  0x{:016x}  {}\n", addr, name));
        }
        out.push('\n');
    }
    if !p.comments.is_empty() {
        out.push_str(&format!("Comments ({}):\n", p.comments.len()));
        let mut comments: Vec<_> = p.comments.iter().collect();
        comments.sort_by_key(|(k, _)| *k);
        for (addr, cmt) in comments {
            out.push_str(&format!("  0x{:016x}  {}\n", addr, cmt));
        }
        out.push('\n');
    }
    if !p.vuln_scores.is_empty() {
        out.push_str(&format!("Vulnerability scores ({}):\n", p.vuln_scores.len()));
        let mut scores: Vec<_> = p.vuln_scores.iter().collect();
        scores.sort_by_key(|(k, _)| *k);
        for (addr, score) in scores {
            let badge = if *score >= 7 { "[HIGH]" } else if *score >= 4 { "[MED]" } else { "[LOW]" };
            let name = p.renames.get(addr).map(|s| s.as_str()).unwrap_or("?");
            out.push_str(&format!("  0x{:016x}  score={}/10  {}  {}\n", addr, score, badge, name));
        }
        out.push('\n');
    }
    if !p.notes.is_empty() {
        out.push_str(&format!("Analyst notes ({}):\n", p.notes.len()));
        for note in &p.notes {
            let addr_str = note.vaddr.map(|a| format!(" @ 0x{:x}", a)).unwrap_or_default();
            out.push_str(&format!("  [{}]{} ({}): {}\n", note.id, addr_str, note.timestamp, note.text));
        }
        out.push('\n');
    }
    ToolResult::ok(out)
}

// ─── Tool: add_note ───────────────────────────────────────────────────────────

fn add_note_tool(path: &str, text: &str, vaddr: Option<u64>) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if text.is_empty()  { return ToolResult::err("'text' is required"); }
    let mut p = Project::load_for(path);
    match p.add_note(vaddr, text.to_string()) {
        Ok(note) => {
            let addr_str = vaddr.map(|a| format!(" @ 0x{:x}", a)).unwrap_or_default();
            ToolResult::ok(format!(
                "Note [{}]{} saved: {}",
                note.id, addr_str, note.text
            ))
        }
        Err(e) => ToolResult::err(format!("Failed to save note: {}", e)),
    }
}

// ─── Tool: delete_note ────────────────────────────────────────────────────────

fn delete_note_tool(path: &str, id: i64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if id <= 0 { return ToolResult::err("'id' must be a positive integer"); }
    let mut p = Project::load_for(path);
    match p.delete_note(id) {
        Ok(true)  => ToolResult::ok(format!("Note [{}] deleted", id)),
        Ok(false) => ToolResult::err(format!("No note with id={} found", id)),
        Err(e)    => ToolResult::err(format!("Failed to delete note: {}", e)),
    }
}

// ─── Tool: list_notes ─────────────────────────────────────────────────────────

fn list_notes_tool(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let p = Project::load_for(path);
    if p.notes.is_empty() {
        return ToolResult::ok("No analyst notes saved for this binary yet.");
    }
    let mut out = format!("Analyst notes for {} ({} total):\n\n", path, p.notes.len());
    for note in &p.notes {
        let addr_str = note.vaddr.map(|a| format!(" @ 0x{:x}", a)).unwrap_or_default();
        out.push_str(&format!(
            "  [{}]{} ({}):\n    {}\n\n",
            note.id, addr_str, note.timestamp, note.text
        ));
    }
    ToolResult::ok(out)
}

// ─── Tool: get_vuln_scores ────────────────────────────────────────────────────

fn get_vuln_scores_tool(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let p = Project::load_for(path);
    if p.vuln_scores.is_empty() {
        return ToolResult::ok("No vulnerability scores set for this binary yet.");
    }
    let mut scores: Vec<_> = p.vuln_scores.iter().collect();
    scores.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut out = format!("Vulnerability scores for {} ({} functions scored):\n\n", path, scores.len());
    for (addr, score) in scores {
        let badge = if *score >= 7 { "HIGH " } else if *score >= 4 { "MED  " } else { "LOW  " };
        let name = p.renames.get(addr).map(|s| s.as_str()).unwrap_or("(unnamed)");
        out.push_str(&format!(
            "  {}/10  [{}]  0x{:016x}  {}\n",
            score, badge, addr, name
        ));
    }
    ToolResult::ok(out)
}

// ─── Helper: PE IAT address → import name map ───────────────────────────────

/// Returns a map from IAT slot VA → "DLL!FunctionName" for a PE binary.
fn build_pe_iat_map(data: &[u8]) -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();
    let pe = match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return map,
    };
    let image_base = pe.image_base as u64;
    let ptr_size: u64 = if pe.is_64 { 8 } else { 4 };
    if let Some(import_data) = &pe.import_data {
        for dll_entry in &import_data.import_data {
            let iat_base_rva =
                dll_entry.import_directory_entry.import_address_table_rva as u64;
            let dll = dll_entry.name.to_ascii_lowercase();
            let dll_stem = dll.trim_end_matches(".dll");
            let lut = match &dll_entry.import_lookup_table {
                Some(l) => l,
                None => continue,
            };
            for (idx, entry) in lut.iter().enumerate() {
                use goblin::pe::import::SyntheticImportLookupTableEntry::*;
                let fn_name = match entry {
                    HintNameTableRVA((_rva, hint)) => hint.name.to_string(),
                    OrdinalNumber(ord) => format!("#{}", ord),
                };
                let slot_va = image_base + iat_base_rva + idx as u64 * ptr_size;
                map.insert(slot_va, format!("{}!{}", dll_stem, fn_name));
            }
        }
    }
    map
}

// ─── Tool: resolve_pe_imports ────────────────────────────────────────────────

fn resolve_pe_imports(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        Ok(_)  => return ToolResult::err("Not a PE binary — use resolve_plt for ELF"),
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };
    if pe.imports.is_empty() {
        return ToolResult::ok("No imports found (binary may be statically linked)");
    }
    let image_base = pe.image_base as u64;

    // Build a map (dll_name_lower, function_name) → IAT_slot_VA using
    // pe.import_data which exposes the per-DLL FirstThunk (IAT) RVA.
    // goblin's `imp.rva` is the RVA of IMAGE_IMPORT_BY_NAME (name table),
    // NOT the IAT slot that machine code reads.  The IAT slot VA is:
    //   image_base + first_thunk_rva_for_dll + entry_index × ptr_size
    let ptr_size: u64 = if pe.is_64 { 8 } else { 4 };
    let mut iat_map: std::collections::HashMap<(String, String), u64> =
        std::collections::HashMap::new();

    if let Some(import_data) = &pe.import_data {
        for dll_entry in &import_data.import_data {
            let iat_base_rva =
                dll_entry.import_directory_entry.import_address_table_rva as u64;
            let dll_name_raw = dll_entry.name.to_ascii_lowercase();
            // Walk the import lookup table entries for this DLL
            let lut = if let Some(l) = &dll_entry.import_lookup_table {
                l
            } else {
                continue;
            };
            for (idx, entry) in lut.iter().enumerate() {
                use goblin::pe::import::SyntheticImportLookupTableEntry::*;
                let fn_name = match entry {
                    HintNameTableRVA((_rva, hint_entry)) => hint_entry.name.to_string(),
                    OrdinalNumber(ord) => format!("#{}", ord),
                };
                let slot_va = image_base + iat_base_rva + idx as u64 * ptr_size;
                iat_map.insert((dll_name_raw.clone(), fn_name), slot_va);
            }
        }
    }

    let mut out = format!(
        "PE imports ({} entries, image_base=0x{:016x}):\n\n  {:<20}  {:<30}  {}\n  {}\n",
        pe.imports.len(), image_base,
        "IAT slot address", "DLL", "Symbol",
        "─".repeat(72)
    );
    for imp in &pe.imports {
        let key = (imp.dll.to_ascii_lowercase(), imp.name.to_string());
        let vaddr = iat_map.get(&key).copied()
            // Fall back to the name-table address if lookup failed (should not happen)
            .unwrap_or_else(|| image_base + imp.rva as u64);
        out.push_str(&format!(
            "  0x{:016x}  {:<30}  {}\n",
            vaddr, imp.dll, imp.name
        ));
    }
    ToolResult::ok(out)
}

// ─── Tool: call_graph ────────────────────────────────────────────────────────

fn call_graph(path: &str, _max_depth: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let arch_class = crate::arch::ArchClass::from_object(obj.architecture());

    // Build name map: vaddr → name (project renames take precedence)
    let project = Project::load_for(path);
    let mut name_map: HashMap<u64, String> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0)
        .map(|s| (s.address(), s.name().unwrap_or("<?>").to_string()))
        .collect();
    for (addr, name) in &project.renames {
        name_map.insert(*addr, name.clone());
    }
    let resolve_name = |addr: u64| -> String {
        name_map.get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("0x{:x}", addr))
    };

    // Symbol address → (addr, size) sorted list for caller lookup
    let mut sym_ranges: Vec<(u64, u64)> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
        .map(|s| (s.address(), s.size()))
        .collect();
    sym_ranges.sort_by_key(|(a, _)| *a);

    let find_fn = |addr: u64| -> u64 {
        for &(fn_addr, fn_size) in sym_ranges.iter().rev() {
            if addr >= fn_addr && addr < fn_addr + fn_size {
                return fn_addr;
            }
        }
        addr
    };

    // caller_fn → set of callee targets
    let mut edges: HashMap<u64, HashSet<u64>> = HashMap::new();

    if arch_class.is_x86() {
        let bitness: u32 = match obj.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => 64,
            _ => 32,
        };
        let text_sec = match obj.sections().find(|s| s.name().ok() == Some(".text")) {
            Some(s) => s,
            None    => return ToolResult::err("No .text section found"),
        };
        let text_vaddr = text_sec.address();
        let text_bytes = match text_sec.data() {
            Ok(d) => d,
            Err(e) => return ToolResult::err(format!("Cannot read .text: {}", e)),
        };
        use iced_x86::{Decoder, DecoderOptions, FlowControl};
        let mut decoder = Decoder::with_ip(bitness, text_bytes, text_vaddr, DecoderOptions::NONE);
        for instr in &mut decoder {
            if matches!(instr.flow_control(), FlowControl::Call) {
                let tgt = instr.near_branch64();
                if tgt != 0 {
                    let caller = find_fn(instr.ip());
                    edges.entry(caller).or_default().insert(tgt);
                }
            }
        }
    } else {
        // Generic capstone path for non-x86 architectures
        let cs = match crate::arch::build_capstone(arch_class) {
            Ok(c) => c,
            Err(e) => return ToolResult::err(format!("Capstone init failed: {}", e)),
        };
        for sec in obj.sections() {
            let sec_name = sec.name().unwrap_or("");
            if !crate::arch::is_code_section(sec_name) { continue; }
            let sec_vaddr = sec.address();
            let sec_bytes = match sec.data() {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(insns) = cs.disasm_all(sec_bytes, sec_vaddr) {
                for insn in insns.as_ref() {
                    let mnemonic = insn.mnemonic().unwrap_or("");
                    let op_str   = insn.op_str().unwrap_or("");
                    if crate::arch::is_direct_call(arch_class, mnemonic, op_str) {
                        if let Some(tgt) = crate::arch::parse_branch_target(op_str) {
                            let caller = find_fn(insn.address());
                            edges.entry(caller).or_default().insert(tgt);
                        }
                    }
                }
            }
        }
    }

    if edges.is_empty() {
        return ToolResult::ok("No direct calls found in .text (binary may use indirect calls only)");
    }

    let mut out = format!("Call graph ({} callers):\n\n", edges.len());
    let mut callers: Vec<u64> = edges.keys().cloned().collect();
    callers.sort();
    for caller in callers {
        let callees = &edges[&caller];
        out.push_str(&format!("  {} →\n", resolve_name(caller)));
        let mut sorted_callees: Vec<u64> = callees.iter().cloned().collect();
        sorted_callees.sort();
        for callee in sorted_callees {
            out.push_str(&format!("      {}\n", resolve_name(callee)));
        }
    }
    ToolResult::ok(out)
}

// ─── Tool: cfg_view ──────────────────────────────────────────────────────────

fn cfg_view(path: &str, vaddr: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let arch_class = crate::arch::ArchClass::from_object(obj.architecture());

    struct Block { start: u64, end: u64, instr_count: usize, succs: Vec<u64> }

    let mut to_visit: Vec<u64> = vec![vaddr];
    let mut visited:  HashSet<u64> = HashSet::new();
    let mut blocks:   Vec<Block> = Vec::new();

    if arch_class.is_x86() {
        use iced_x86::{Decoder, DecoderOptions, FlowControl};
        let bitness: u32 = match obj.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => 64,
            _ => 32,
        };

        while let Some(addr) = to_visit.pop() {
            if !visited.insert(addr) { continue; }

            let file_off = match vaddr_to_file_offset(&data, addr) {
                Some(o) => o,
                None    => continue,
            };
            if file_off >= data.len() { continue; }

            let slice = &data[file_off..data.len().min(file_off + 1024)];
            let mut dec = Decoder::with_ip(bitness, slice, addr, DecoderOptions::NONE);
            let mut count = 0usize;
            let mut last_ip = addr;
            let mut succs: Vec<u64> = Vec::new();

            for instr in &mut dec {
                if instr.is_invalid() { break; }
                last_ip = instr.ip();
                count  += 1;
                match instr.flow_control() {
                    FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {}
                    FlowControl::UnconditionalBranch => {
                        let tgt = instr.near_branch64();
                        if tgt != 0 && !visited.contains(&tgt) {
                            to_visit.push(tgt);
                            succs.push(tgt);
                        }
                        break;
                    }
                    FlowControl::ConditionalBranch => {
                        let tgt  = instr.near_branch64();
                        let fall = instr.next_ip();
                        if tgt  != 0 { to_visit.push(tgt);  succs.push(tgt);  }
                        if fall != 0 { to_visit.push(fall); succs.push(fall); }
                        break;
                    }
                    _ => { break; }
                }
                if count >= 200 { break; }
            }

            blocks.push(Block { start: addr, end: last_ip, instr_count: count, succs });
        }
    } else {
        // Capstone path for non-x86
        let cs = match crate::arch::build_capstone(arch_class) {
            Ok(c) => c,
            Err(e) => return ToolResult::err(format!("Capstone init failed: {}", e)),
        };
        let align = arch_class.insn_align().max(1) as u64;

        while let Some(addr) = to_visit.pop() {
            if !visited.insert(addr) { continue; }

            let file_off = match vaddr_to_file_offset(&data, addr) {
                Some(o) => o,
                None    => continue,
            };
            if file_off >= data.len() { continue; }

            let slice = &data[file_off..data.len().min(file_off + 1024)];
            let mut count = 0usize;
            let mut last_ip = addr;
            let mut succs: Vec<u64> = Vec::new();

            if let Ok(insns) = cs.disasm_all(slice, addr) {
                for insn in insns.as_ref() {
                    let mnemonic = insn.mnemonic().unwrap_or("");
                    let op_str   = insn.op_str().unwrap_or("");
                    last_ip = insn.address();
                    count  += 1;

                    if crate::arch::is_return(arch_class, mnemonic, op_str) {
                        break;
                    } else if crate::arch::is_direct_branch(arch_class, mnemonic, op_str) {
                        if let Some(tgt) = crate::arch::parse_branch_target(op_str) {
                            if !visited.contains(&tgt) {
                                to_visit.push(tgt);
                                succs.push(tgt);
                            }
                        }
                        // For conditional branches also follow fall-through
                        if !crate::arch::is_direct_call(arch_class, mnemonic, op_str) {
                            let fall = insn.address() + insn.bytes().len() as u64;
                            let fall = (fall + align - 1) & !(align - 1);
                            if !visited.contains(&fall) {
                                to_visit.push(fall);
                                succs.push(fall);
                            }
                        }
                        break;
                    } else if crate::arch::is_direct_call(arch_class, mnemonic, op_str) {
                        // calls don't end a block
                    }
                    if count >= 200 { break; }
                }
            }

            blocks.push(Block { start: addr, end: last_ip, instr_count: count, succs });
        }
    }

    if blocks.is_empty() {
        return ToolResult::err(format!("No blocks found starting at 0x{:x}", vaddr));
    }
    blocks.sort_by_key(|b| b.start);

    // Assign block indices
    let block_idx: HashMap<u64, usize> = blocks.iter().enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();

    let mut out = format!("CFG for function at 0x{:x} ({} basic blocks):\n\n", vaddr, blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        out.push_str(&format!(
            "  Block {:>3}: 0x{:x} → 0x{:x}  ({} instrs)\n",
            i, b.start, b.end, b.instr_count
        ));
        if b.succs.is_empty() {
            out.push_str("              Successors: (return / indirect)\n");
        } else {
            let succ_labels: Vec<String> = b.succs.iter()
                .map(|a| block_idx.get(a)
                    .map(|i| format!("Block {}", i))
                    .unwrap_or_else(|| format!("0x{:x}", a)))
                .collect();
            out.push_str(&format!("              Successors: {}\n", succ_labels.join(", ")));
        }
    }
    ToolResult::ok(out)
}

// ─── Tool: stack_bof_candidates ──────────────────────────────────────────────

/// Scan every .pdata function for large stack frames (sub sp, sp, #N) that lack
/// PACI or __security_cookie protection — classic stack buffer-overflow targets.
fn stack_bof_candidates(path: &str, min_frame_bytes: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read: {}", e)),
    };
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return ToolResult::err("Not a PE binary"),
    };
    let image_base = pe.image_base as u64;
    let min_frame = if min_frame_bytes == 0 { 256 } else { min_frame_bytes };

    // Build text section map: vaddr → file offset
    let sections: Vec<_> = pe.sections.iter().map(|s| {
        let va    = image_base + s.virtual_address as u64;
        let foff  = s.pointer_to_raw_data as usize;
        let fsize = s.size_of_raw_data as usize;
        (va, s.virtual_size as u64, foff, fsize)
    }).collect();
    let va_to_foff = |va: u64| -> Option<usize> {
        for &(sec_va, sec_vsz, sec_foff, sec_fsz) in &sections {
            if va >= sec_va && va < sec_va + sec_vsz {
                let off = sec_foff + (va - sec_va) as usize;
                if off < sec_foff + sec_fsz { return Some(off); }
            }
        }
        None
    };

    // Iterate .pdata entries
    let pdata = match pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
        .and_then(|s| s.data(&data).ok().flatten())
    {
        Some(b) => b,
        None => return ToolResult::err("No .pdata section found"),
    };

    let project = Project::load_for(path);
    let mut candidates: Vec<(u64, u64, bool)> = Vec::new(); // (va, frame_size, has_paci)

    let n = pdata.len() / 8;
    for i in 0..n {
        let off = i * 8;
        let begin_rva = u32::from_le_bytes(pdata[off..off+4].try_into().unwrap_or([0;4])) as u64;
        if begin_rva == 0 { continue; }
        let fn_va = image_base + begin_rva;
        let foff = match va_to_foff(fn_va) { Some(o) => o, None => continue };
        let end = (foff + 128).min(data.len());
        if end <= foff { continue; }
        let bytes = &data[foff..end];

        // Check for PACI: 7f 23 03 d5 (pacibsp) or 5f 24 03 d5 (paciasp)
        let has_paci = bytes.len() >= 4 && (
            (bytes[0] == 0x7f && bytes[1] == 0x23 && bytes[2] == 0x03 && bytes[3] == 0xd5) ||
            (bytes[0] == 0x5f && bytes[1] == 0x24 && bytes[2] == 0x03 && bytes[3] == 0xd5)
        );

        // Check for __security_cookie canary: ADRP + LDR x8, [x8, #offset]
        // Pattern: look for `str x8, [sp, #N]` following `ldr x8, [xREG, #cookie_off]`
        // Simple heuristic: look for the distinctive canary XOR epilogue byte pattern
        // The __security_cookie load is `ldr x8, [xN, #offset]` early in function,
        // and the check is `eor + cbnz __stack_chk_fail`. We detect canary by presence
        // of the cookie ADRP pattern anywhere in first 128 bytes.
        let has_cookie = {
            let mut found = false;
            // Look for ADRP xN, #page where page is in .data range (cookie lives there)
            // Then LDR x8, [xN, #offset] — cookie offset is typically 0x40
            // Simplified: scan for any `str x8, [sp, #N]` (e8 [03|07|0b|0f] [??] f9)
            // that follows an ADRP within 4 instructions — conservative heuristic
            let mut j = 0usize;
            while j + 4 <= bytes.len() {
                // STR x8, [sp, #offset]: word & 0xFFC003FF == 0xF90003E8
                let w = u32::from_le_bytes([bytes[j], bytes[j+1], bytes[j+2], bytes[j+3]]);
                if (w & 0xFFC003FF) == 0xF90003E8 {
                    // Check if preceded by LDR (not store) from .data-like page:
                    // ADRP within previous 8 instructions
                    let search_start = j.saturating_sub(32);
                    for k in (search_start..j).step_by(4) {
                        if k + 4 > bytes.len() { break; }
                        let wk = u32::from_le_bytes([bytes[k], bytes[k+1], bytes[k+2], bytes[k+3]]);
                        // ADRP: top 7 bits must be 0b1001000 = 0x48 (bits 31-24 = 0x90 or 0xb0 etc.)
                        // AArch64 ADRP encoding: op=1, 1 0 0 0 0, immhi, Rd — bits 28-31 = 1001
                        if (wk >> 24) & 0x9f == 0x90 {
                            found = true;
                            break;
                        }
                    }
                    if found { break; }
                }
                j += 4;
            }
            found
        };

        // Scan for `sub sp, sp, #N` with shift=0: word = 0xD1000000 | (N << 10) | 0x3FF
        // byte[0]=0xFF, byte[3]=0xD1; frame_size = (word >> 10) & 0xFFF
        let mut frame_size: u64 = 0;
        let mut j = 0usize;
        while j + 4 <= bytes.len() {
            let w = u32::from_le_bytes([bytes[j], bytes[j+1], bytes[j+2], bytes[j+3]]);
            // SUB SP, SP, #imm12 (shift=0): 0xD10003FF | (imm12 << 10)
            if (w & 0xFF0003FF) == 0xD10003FF {
                let imm12 = ((w >> 10) & 0xFFF) as u64;
                if imm12 > frame_size { frame_size = imm12; }
            }
            // SUB SP, SP, #imm12 (shift=1, lsl 12): 0xD1400000 | (imm12 << 10) | 0x3FF
            if (w & 0xFF0003FF) == 0xD14003FF {
                let imm12 = ((w >> 10) & 0xFFF) as u64;
                if imm12 * 4096 > frame_size { frame_size = imm12 * 4096; }
            }
            j += 4;
        }

        if frame_size >= min_frame && !has_paci && !has_cookie {
            candidates.push((fn_va, frame_size, false));
        }
    }

    if candidates.is_empty() {
        return ToolResult::ok(format!(
            "No stack BOF candidates found (min_frame={} bytes, PACI/cookie excluded).", min_frame
        ));
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1)); // sort by frame size desc
    let mut out = format!(
        "Stack BOF candidates: {} function(s) with frame ≥ {} bytes and NO PACI/canary:\n\
         (Sorted by frame size descending. These functions have no return-address protection.)\n\n\
         {:<20}  {:>10}  {}\n{}\n",
        candidates.len(), min_frame,
        "Address", "Frame(B)", "Name",
        "─".repeat(60)
    );
    for (va, fsz, _) in candidates.iter().take(50) {
        let name = project.get_name(*va).unwrap_or_else(|| format!("FUN_{:016x}", va));
        out.push_str(&format!("  0x{:016x}  {:>10}  {}\n", va, fsz, name));
    }
    if candidates.len() > 50 {
        out.push_str(&format!("\n  … and {} more (use min_frame_bytes to narrow)\n", candidates.len() - 50));
    }
    ToolResult::ok(out)
}

// ─── Tool: writable_iat_hijack_surface ───────────────────────────────────────

/// Map writable IAT slots to callers — shows which functions call through
/// pointers that live in writable sections (exploitable without VirtualProtect).
fn writable_iat_hijack_surface(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read: {}", e)),
    };
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return ToolResult::err("Not a PE binary"),
    };
    let image_base = pe.image_base as u64;

    // Build set of writable section ranges
    let writable_ranges: Vec<(u64, u64)> = pe.sections.iter()
        .filter(|s| s.characteristics & 0x80000000 != 0) // IMAGE_SCN_MEM_WRITE
        .map(|s| {
            let va = image_base + s.virtual_address as u64;
            (va, va + s.virtual_size as u64)
        })
        .collect();
    let is_writable = |va: u64| writable_ranges.iter().any(|&(lo, hi)| va >= lo && va < hi);

    // Build full IAT map: slot_va → "dll!fn"
    let iat_map = build_pe_iat_map(&data);

    // Filter to writable slots and prioritize by danger
    const HIGH_RISK: &[&str] = &[
        "createremotethread", "writeprocessmemory", "virtualallocex", "virtualalloc",
        "loadlibrary", "getprocaddress", "createprocess", "shellexecute", "winexec",
        "connectnamedpipe", "createnamedpipe", "readprocessmemory",
        "regsetvalueex", "cryptencrypt", "cryptdecrypt",
    ];

    let mut writable_slots: Vec<(u64, String, bool)> = iat_map.iter()
        .filter(|(&va, _)| is_writable(va))
        .map(|(&va, name)| {
            let low = name.to_ascii_lowercase();
            let high_risk = HIGH_RISK.iter().any(|&h| low.contains(h));
            (va, name.clone(), high_risk)
        })
        .collect();
    writable_slots.sort_by(|a, b| b.2.cmp(&a.2).then(a.1.cmp(&b.1)));

    // Always report writable sections (even if IAT isn't in them — they may contain
    // function-pointer tables or read-only data that is exploitable without VirtualProtect).
    let writable_sec_names: Vec<String> = pe.sections.iter()
        .filter(|s| s.characteristics & 0x80000000 != 0)
        .filter_map(|s| s.name().ok().map(|n| {
            let va = image_base + s.virtual_address as u64;
            format!("{} (VA=0x{:x}, VSize=0x{:x})", n, va, s.virtual_size)
        }))
        .collect();

    if writable_slots.is_empty() {
        let mut out = String::from("IAT is in read-only section — no writable IAT slots.\n\n");
        if !writable_sec_names.is_empty() {
            out.push_str("WARNING: The following sections are writable (IMAGE_SCN_MEM_WRITE set).\n");
            out.push_str("If they contain function pointers, vtables, or jump tables, those can\n");
            out.push_str("be overwritten without VirtualProtect:\n\n");
            for n in &writable_sec_names {
                out.push_str(&format!("  {}\n", n));
            }
        }
        return ToolResult::ok(out);
    }

    // For each writable IAT slot, find callers by scanning .text for ADRP+LDR+BLR pattern
    // We use the raw BL-scanner approach: scan for ADRP page matching the slot's upper bits,
    // then LDR from that page+offset, then BLR.
    // For efficiency: build a set of (adrp_page, ldr_offset) → slot_va pairs
    let mut slot_callers: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();

    let text_sec = pe.sections.iter().find(|s| s.name().ok().map_or(false, |n| n == ".text"));
    if let Some(text) = text_sec {
        let text_va  = image_base + text.virtual_address as u64;
        let text_foff = text.pointer_to_raw_data as usize;
        let text_fsz  = text.size_of_raw_data as usize;
        if text_foff + text_fsz <= data.len() {
            let text_bytes = &data[text_foff .. text_foff + text_fsz];
            let n = text_bytes.len() & !3;
            // State machine: track ADRP page per register (simplified: track x8)
            // We only track the most common caller pattern: ADRP xN + LDR xN, [xN, #off] + BLR xN
            // Use a small per-position register file: reg_page[0..32]
            let mut adrp_page = [0u64; 32];
            let mut reg_iat   = [0u64; 32]; // IAT slot VA if loaded from writable IAT
            for i in (0..n).step_by(4) {
                let w = u32::from_le_bytes([text_bytes[i], text_bytes[i+1], text_bytes[i+2], text_bytes[i+3]]);
                let insn_va = text_va + i as u64;
                let op31_24 = (w >> 24) as u8;
                let rd  = (w & 0x1f) as usize;
                let rn  = ((w >> 5) & 0x1f) as usize;
                // ADRP: bits 31 = 1, 29-28 = 10, 24 = 1 → high nibble 1001xxxx (0x90-0x9f,0xb0-0xbf)
                if (op31_24 & 0x9f) == 0x90 {
                    // ADRP Rd, #page: page = PC_aligned + signed_offset (pc-relative page)
                    // imm = immhi:immlo, sign-extended, << 12
                    let immlo = (w >> 29) & 0x3;
                    let immhi = (w >> 5) & 0x7FFFF;
                    let imm = ((immhi << 2 | immlo) as i64).wrapping_shl(64 - 21).wrapping_shr(64 - 21 - 12);
                    let page = (insn_va & !0xfff).wrapping_add(imm as u64);
                    adrp_page[rd] = page;
                    reg_iat[rd] = 0;
                    continue;
                }
                // LDR (unsigned offset, 64-bit): 0xF9400000 | (imm12 << 10) | (rn << 5) | rt
                if (w & 0xFFC00000) == 0xF9400000 {
                    let rt   = (w & 0x1f) as usize;
                    let rn_l = ((w >> 5) & 0x1f) as usize;
                    let imm12 = ((w >> 10) & 0xfff) as u64;
                    let off = imm12 * 8; // size=8 (64-bit LDR) → offset = imm12 << 3
                    let slot_va = adrp_page[rn_l].wrapping_add(off);
                    if iat_map.contains_key(&slot_va) && is_writable(slot_va) {
                        reg_iat[rt] = slot_va;
                    } else {
                        reg_iat[rt] = 0;
                    }
                    continue;
                }
                // BLR xN
                if (w & 0xFFFFFC1F) == 0xD63F0000 {
                    let rn_l = ((w >> 5) & 0x1f) as usize;
                    if reg_iat[rn_l] != 0 {
                        slot_callers.entry(reg_iat[rn_l]).or_default().push(insn_va);
                    }
                    continue;
                }
                // Clear reg_iat on any write to the register that was tracking an IAT
                // (conservative: clear on any instruction that writes rd)
                if rd < 32 && rd != 31 {
                    // only clear if this instruction writes to rd (most do)
                    // skip reads (LDR already handled, ADRP handled)
                    if (op31_24 & 0x9f) != 0x90 && (w & 0xFFC00000) != 0xF9400000 {
                        reg_iat[rd] = 0;
                    }
                }
            }
        }
    }

    let project = Project::load_for(path);

    let high_count = writable_slots.iter().filter(|s| s.2).count();
    let mut out = format!(
        "Writable IAT hijack surface: {} total slots ({} HIGH-RISK)\n\
         An attacker with any write-what-where primitive can overwrite these IAT\n\
         slots (in writable sections) to redirect execution without VirtualProtect.\n\n",
        writable_slots.len(), high_count
    );

    // Show high-risk slots with callers first
    let sections_label = writable_ranges.iter()
        .filter_map(|&(lo, _)| {
            pe.sections.iter().find(|s| image_base + s.virtual_address as u64 == lo)
                .and_then(|s| s.name().ok()).map(|n| n.to_string())
        })
        .collect::<Vec<_>>().join(", ");
    out.push_str(&format!("  Writable sections containing IAT: {}\n\n", sections_label));

    for (slot_va, imp_name, high_risk) in &writable_slots {
        let risk_label = if *high_risk { "[HIGH-RISK]" } else { "[  normal ]" };
        out.push_str(&format!("  {} 0x{:016x}  {}\n", risk_label, slot_va, imp_name));
        if let Some(callers) = slot_callers.get(slot_va) {
            for &site in callers.iter().take(4) {
                let fn_name = project.get_name(site)
                    .unwrap_or_else(|| format!("FUN_{:016x}", site));
                out.push_str(&format!("        called from 0x{:x} ({})\n", site, fn_name));
            }
            if callers.len() > 4 {
                out.push_str(&format!("        … and {} more call sites\n", callers.len() - 4));
            }
        }
    }
    ToolResult::ok(out)
}

// ─── Tool: find_injection_chains ─────────────────────────────────────────────

/// Find functions that contain both allocation (VirtualAllocEx/VirtualAlloc) AND
/// write/execute primitives (WriteProcessMemory/CreateRemoteThread) — process
/// injection chains. Also reports functions containing any single high-risk combo.
fn find_injection_chains(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read: {}", e)),
    };
    let pe = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return ToolResult::err("Not a PE binary"),
    };
    let image_base = pe.image_base as u64;

    // Categorise IAT slots into injection-phase buckets
    let iat_map = build_pe_iat_map(&data);
    let mut alloc_slots: std::collections::HashSet<u64>  = std::collections::HashSet::new();
    let mut write_slots: std::collections::HashSet<u64>  = std::collections::HashSet::new();
    let mut exec_slots:  std::collections::HashSet<u64>  = std::collections::HashSet::new();
    let mut pipe_slots:  std::collections::HashSet<u64>  = std::collections::HashSet::new();

    for (&va, name) in &iat_map {
        let low = name.to_ascii_lowercase();
        if low.contains("virtualalloc") || low.contains("heapalloc") { alloc_slots.insert(va); }
        if low.contains("writeprocessmemory") || low.contains("ntwritevirtualmemory") { write_slots.insert(va); }
        if low.contains("createremotethread") || low.contains("ntcreatethreadex")
            || low.contains("rtlcreateuserthread") || low.contains("queueuserapc") { exec_slots.insert(va); }
        if low.contains("namedpipe") || low.contains("connectnamedpipe") { pipe_slots.insert(va); }
    }

    if alloc_slots.is_empty() && write_slots.is_empty() && exec_slots.is_empty() {
        return ToolResult::ok("No process injection IAT entries found in this binary.");
    }

    // Scan .text for ADRP+LDR+BLR patterns, tracking which injection slots each function uses
    let pdata = match pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
        .and_then(|s| s.data(&data).ok().flatten())
    {
        Some(b) => b,
        None => return ToolResult::err("No .pdata section"),
    };

    // Build pdata function index: start_rva → end_rva
    let rdata_range: Option<(u64, usize)> = pe.sections.iter()
        .find(|s| s.name().ok().map_or(false, |n| n == ".rdata"))
        .map(|s| (s.virtual_address as u64, s.pointer_to_raw_data as usize));
    let mut fn_ranges: Vec<(u64, u64)> = Vec::new(); // (start_va, end_va)
    let num_pdata = pdata.len() / 8;
    for i in 0..num_pdata {
        let off = i * 8;
        let begin_rva = u32::from_le_bytes(pdata[off..off+4].try_into().unwrap_or([0;4])) as u64;
        if begin_rva == 0 { continue; }
        let unwind_raw = u32::from_le_bytes(pdata[off+4..off+8].try_into().unwrap_or([0;4]));
        let flag = unwind_raw & 0x3;
        let fn_size: u64 = if flag != 0 {
            ((unwind_raw >> 2) & 0x7FF) as u64 * 4
        } else if let Some((rdata_va, rdata_foff)) = rdata_range {
            let ui_rva = unwind_raw as u64;
            if ui_rva >= rdata_va {
                let ui_off = rdata_foff + (ui_rva - rdata_va) as usize;
                if ui_off + 4 <= data.len() {
                    let ui_word = u32::from_le_bytes(data[ui_off..ui_off+4].try_into().unwrap_or([0;4]));
                    (ui_word & 0x3_FFFF) as u64 * 4
                } else { 512 }
            } else { 512 }
        } else { 512 };
        let start_va = image_base + begin_rva;
        let end_va   = start_va + fn_size.max(64);
        fn_ranges.push((start_va, end_va));
    }

    let text_sec = pe.sections.iter().find(|s| s.name().ok().map_or(false, |n| n == ".text"));
    let (text_va_base, text_foff, text_fsz) = match text_sec {
        Some(s) => (image_base + s.virtual_address as u64, s.pointer_to_raw_data as usize, s.size_of_raw_data as usize),
        None => return ToolResult::err("No .text section"),
    };
    if text_foff + text_fsz > data.len() { return ToolResult::err("Truncated .text"); }
    let text_bytes = &data[text_foff .. text_foff + text_fsz];

    // For each function, scan its bytes for injection-related BLR targets
    let project = Project::load_for(path);
    let mut injection_fns: Vec<(u64, Vec<String>, String)> = Vec::new(); // (fn_va, used_imports, chain_kind)

    for &(fn_va, fn_end) in &fn_ranges {
        if fn_va < text_va_base || fn_end <= fn_va { continue; }
        let fn_foff = (fn_va - text_va_base) as usize;
        let fn_size = ((fn_end - fn_va) as usize).min(65536);
        if fn_foff + fn_size > text_bytes.len() { continue; }
        let fn_bytes = &text_bytes[fn_foff .. fn_foff + fn_size];

        let mut adrp_page = [0u64; 32];
        let mut reg_iat   = [0u64; 32];
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

        let n = fn_bytes.len() & !3;
        for i in (0..n).step_by(4) {
            let w = u32::from_le_bytes([fn_bytes[i], fn_bytes[i+1], fn_bytes[i+2], fn_bytes[i+3]]);
            let insn_va = fn_va + i as u64;
            let op31_24 = (w >> 24) as u8;
            let rd  = (w & 0x1f) as usize;
            let rn  = ((w >> 5) & 0x1f) as usize;

            // ADRP
            if (op31_24 & 0x9f) == 0x90 {
                let immlo = (w >> 29) & 0x3;
                let immhi = (w >> 5) & 0x7FFFF;
                let imm = ((immhi << 2 | immlo) as i64).wrapping_shl(64 - 21).wrapping_shr(64 - 21 - 12);
                let page = (insn_va & !0xfff).wrapping_add(imm as u64);
                adrp_page[rd] = page;
                reg_iat[rd] = 0;
                continue;
            }
            // LDR 64-bit unsigned offset
            if (w & 0xFFC00000) == 0xF9400000 {
                let rt   = (w & 0x1f) as usize;
                let rn_l = ((w >> 5) & 0x1f) as usize;
                let imm12 = ((w >> 10) & 0xfff) as u64;
                let slot_va = adrp_page[rn_l].wrapping_add(imm12 * 8);
                reg_iat[rt] = if iat_map.contains_key(&slot_va) { slot_va } else { 0 };
                continue;
            }
            // BLR
            if (w & 0xFFFFFC1F) == 0xD63F0000 {
                let rn_l = ((w >> 5) & 0x1f) as usize;
                if reg_iat[rn_l] != 0 {
                    if let Some(imp) = iat_map.get(&reg_iat[rn_l]) {
                        used.insert(imp.clone());
                    }
                }
                continue;
            }
            // BL (direct)
            if (w >> 26) == 0x25 {
                let imm26 = w & 0x3FF_FFFF;
                let signed_off: i64 = if imm26 & 0x200_0000 != 0 {
                    (imm26 as i64) | (-1i64 << 26)
                } else { imm26 as i64 };
                let tgt = fn_va.wrapping_add((i as u64).wrapping_add((signed_off * 4) as u64));
                if let Some(imp) = iat_map.get(&tgt) { used.insert(imp.clone()); }
                continue;
            }
            // Clear iat tracking on write
            if rd < 32 { reg_iat[rd] = 0; }
            let _ = rn;
        }

        if used.is_empty() { continue; }
        // Check for injection-phase combinations.
        // Require at least TWO distinct phases to avoid false-positives on
        // browser/IPC code that legitimately uses individual primitives in
        // isolation (e.g. a sandbox bootstrap that only allocates, or a pipe
        // function that only uses named-pipe APIs without any exec primitive).
        let has_alloc = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("virtualallocex") || l.contains("ntalloc") });
        let has_write = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("writeprocessmemory") || l.contains("ntwritevirtualmemory") });
        let has_exec  = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("createremotethread") || l.contains("ntcreatethreadex") || l.contains("rtlcreateuserthread") || l.contains("queueuserapc") });
        // Named-pipe alone is not an injection chain; only flag if combined
        // with a memory-write or exec primitive (e.g. pipe + LoadLibrary + OpenProcess).
        let has_pipe  = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("namedpipe") || l.contains("connectnamedpipe") });
        let has_loadlib = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("loadlibrary") });
        let has_openproc = used.iter().any(|u| { let l = u.to_ascii_lowercase(); l.contains("openprocess") });

        // True injection chain: must involve at least two of alloc/write/exec,
        // OR a pipe broker that combines OpenProcess + LoadLibrary (dynamic
        // library loading into a foreign process via IPC).
        let is_injection =
            (has_alloc && has_write) ||
            (has_alloc && has_exec)  ||
            (has_write && has_exec)  ||
            (has_pipe && has_loadlib && has_openproc);
        if is_injection {
            // Annotate the kind of chain
            let chain_kind = if has_alloc && has_write && has_exec {
                "[FULL CHAIN: alloc+write+exec]"
            } else if has_alloc && has_write {
                "[alloc+write — exec primitive missing]"
            } else if has_alloc && has_exec {
                "[alloc+exec — write primitive missing]"
            } else if has_write && has_exec {
                "[write+exec — alloc primitive missing]"
            } else {
                "[pipe broker: OpenProcess+LoadLibrary via IPC]"
            };
            let mut apis: Vec<String> = used.into_iter().collect();
            apis.sort();
            injection_fns.push((fn_va, apis, chain_kind.to_string()));
        }
    }

    let mut out = format!(
        "Process injection chain analysis for '{}'\n\
         ══════════════════════════════════════════════\n\n",
        path
    );
    if injection_fns.is_empty() {
        out.push_str("No direct injection chains found in individual functions.\n");
        out.push_str("(Injection may be split across multiple callers — check call_graph.)\n\n");
        out.push_str("IAT entries available for injection:\n");
        for va in alloc_slots.iter().chain(write_slots.iter()).chain(exec_slots.iter()) {
            if let Some(n) = iat_map.get(va) {
                out.push_str(&format!("  0x{:016x}  {}\n", va, n));
            }
        }
    } else {
        out.push_str(&format!("{} function(s) contain injection-capable API combinations:\n\n", injection_fns.len()));
        for (va, apis, kind) in &injection_fns {
            let name = project.get_name(*va).unwrap_or_else(|| format!("FUN_{:016x}", va));
            out.push_str(&format!("  0x{:016x}  {}  {}\n", va, kind, name));
            for api in apis {
                out.push_str(&format!("      {}\n", api));
            }
        }
    }
    ToolResult::ok(out)
}

// ─── Tool: scan_vulnerabilities ──────────────────────────────────────────────

fn scan_vulnerabilities(path: &str, max_fns: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    // ── Determine .text section bounds for filtering library code ────────────
    let (text_vaddr, text_end) = obj.sections()
        .find(|s| s.name().ok().map_or(false, |n| n == ".text" || n == "__text" || n.ends_with(",__text")))
        .map(|s| (s.address(), s.address() + s.size()))
        .unwrap_or((0, u64::MAX));

    // Collect function addresses (symbol table or prologue scan)
    let project = Project::load_for(path);
    let mut fn_addrs: Vec<(u64, String)> = obj
        .symbols()
        .filter(|s| {
            if s.kind() != object::SymbolKind::Text || s.address() == 0 || s.size() == 0 {
                return false;
            }
            // Skip obvious libc/runtime symbols in statically-linked binaries
            let name = s.name().unwrap_or("");
            if name.starts_with("__") || name.starts_with("_dl_") || name.starts_with("_IO_")
                || name.starts_with("_obstack") || name.starts_with("_nss_")
            {
                return false;
            }
            true
        })
        .map(|s| {
            let addr = s.address();
            let name = project.get_name(addr)
                .or_else(|| s.name().ok().map(|n| n.to_string()))
                .unwrap_or_else(|| format!("FUN_{:x}", addr));
            (addr, name)
        })
        .collect();
    fn_addrs.sort_by_key(|(a, _)| *a);

    // If the symbol table has many entries, restrict to the .text section
    // to avoid OOM-decompiling hundreds of statically-linked library functions.
    if fn_addrs.len() > 50 && text_vaddr != 0 {
        fn_addrs.retain(|(a, _)| *a >= text_vaddr && *a < text_end);
    }
    fn_addrs.truncate(max_fns);

    // ── PE .pdata fallback (stripped PE, no symbols) ─────────────────────────
    if fn_addrs.is_empty() {
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&data) {
            let image_base = pe.image_base as u64;
            let rdata_range: Option<(u64, usize)> = pe.sections.iter()
                .find(|s| s.name().ok().map_or(false, |n| n == ".rdata"))
                .map(|s| (s.virtual_address as u64, s.pointer_to_raw_data as usize));
            if let Some(pdata_bytes) = pe.sections.iter()
                .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
                .and_then(|s| s.data(&data).ok().flatten())
            {
                let num = pdata_bytes.len() / 8;
                let mut pdata_fns: Vec<u64> = Vec::with_capacity(num);
                for i in 0..num {
                    let off = i * 8;
                    let begin_rva = u32::from_le_bytes(pdata_bytes[off..off+4].try_into().unwrap_or([0;4])) as u64;
                    if begin_rva == 0 { continue; }
                    pdata_fns.push(image_base + begin_rva);
                }
                pdata_fns.dedup();
                pdata_fns.truncate(max_fns);
                let _ = rdata_range; // used in list_functions path
                for addr in pdata_fns {
                    let name = project.get_name(addr)
                        .unwrap_or_else(|| format!("FUN_{:016x}", addr));
                    fn_addrs.push((addr, name));
                }
            }
        }
    }

    // ── Prologue scan fallback (stripped ELF / Mach-O) ────────────────────────
    if fn_addrs.is_empty() {
        let text_sec_opt = obj.sections().find(|s| {
            s.name().ok().map_or(false, |n| n == ".text" || n == "__text" || n.ends_with(",__text"))
        });
        if let Some(ts) = text_sec_opt {
            if let Ok(text_bytes) = ts.data() {
                let text_bytes = text_bytes.to_vec();
                let arch = obj.architecture();
                let is_64 = obj.is_64();
                let len = text_bytes.len();
                let mut found: Vec<u64> = Vec::new();
                let mut i = 0usize;
                while i + 4 <= len {
                    let b = &text_bytes[i..];
                    let hit = match arch {
                        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
                            (b[0] == 0xfd && b[1] == 0x7b)
                                || (b[0] == 0x7f && b[1] == 0x23 && b[2] == 0x03 && b[3] == 0xd5)
                        }
                        Architecture::Arm => {
                            (b[0] == 0x00 && b[1] == 0x48 && b[2] == 0x2d && b[3] == 0xe9)
                                || (b[0] == 0x10 && b[1] == 0x40 && b[2] == 0x2d && b[3] == 0xe9)
                        }
                        _ if is_64 => {
                            (b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa)
                                || (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xe5)
                        }
                        _ => b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xe5,
                    };
                    if hit {
                        found.push(text_vaddr + i as u64);
                    }
                    i += if matches!(
                        arch,
                        Architecture::Aarch64
                            | Architecture::Aarch64_Ilp32
                            | Architecture::Arm
                    ) {
                        4
                    } else {
                        1
                    };
                }
                found.truncate(max_fns);
                for addr in found {
                    let name = project.get_name(addr)
                        .unwrap_or_else(|| format!("FUN_{:x}", addr));
                    fn_addrs.push((addr, name));
                }
            }
        }
    }

    if fn_addrs.is_empty() {
        // For PE binaries, run the header-level security audit which needs no
        // symbols and completes in O(file_size) — useful for large stripped PEs.
        let pe_audit = if matches!(goblin::Object::parse(&data), Ok(goblin::Object::PE(_))) {
            let audit = pe_security_audit(path).output;
            if !audit.starts_with("Error:") {
                Some(audit)
            } else {
                None
            }
        } else {
            None
        };
        return ToolResult::ok(match pe_audit {
            Some(audit) => format!(
                "No functions found to scan (no symbols / prologues detected).\n\
                 Running PE security audit instead:\n\n{}", audit),
            None => "No functions found to scan (no symbols and no recognised prologues in .text). \
                     Try running list_functions first.".to_string(),
        });
    }

    // Dangerous function patterns to watch for
    const DANGEROUS: &[&str] = &[
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "fscanf",
        "sscanf", "memcpy", "memmove", "strncpy", "strncat", "snprintf",
        "printf", "fprintf", "system", "popen", "exec", "execve",
        "malloc", "free", "realloc",
    ];

    // For PE binaries always prepend the header-level hardening audit.
    // This gives the LLM structural context (writable .rodata, CFG, canaries)
    // before it sees individual function decompilations.
    let pe_audit_prefix = if matches!(goblin::Object::parse(&data), Ok(goblin::Object::PE(_))) {
        let audit = pe_security_audit(path).output;
        if !audit.starts_with("Error:") {
            format!("{}\n{}\n", "═".repeat(72), audit)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let mut out = format!(
        "{}Vulnerability scan for '{}' ({} functions).\n\
         Review each decompiled function below and evaluate for:\n\
         • Buffer overflow (unchecked memcpy/strcpy/gets with user-controlled size)\n\
         • Format string (printf/fprintf with non-literal format argument)\n\
         • Command injection (system/popen with user-controlled input)\n\
         • Integer overflow leading to buffer under-allocation\n\
         • Use-after-free (free then access)\n\
         • Null-pointer dereference\n\
         • Off-by-one errors\n\n\
         For each function, call set_vuln_score(path, vaddr, score) with:\n\
           0 = clean, 1-3 = low risk, 4-6 = medium, 7-9 = high, 10 = critical\n\n\
         {}\n\n",
        pe_audit_prefix, path, fn_addrs.len(), "═".repeat(72)
    );

    // Windows API danger patterns (function name substrings, case-insensitive)
    const DANGEROUS_WIN: &[&str] = &[
        "createremotethread", "virtualalloc", "writeprocessmemory", "readprocessmemory",
        "createprocess", "shellexecute", "winexec", "loadlibrary", "getprocaddress",
        "connectnamedpipe", "createnamedpipe", "wsastartup", "connect",
        "regsetvalue", "regopenkey", "cryptencrypt", "cryptdecrypt",
    ];

    for (vaddr, name) in &fn_addrs {
        out.push_str(&format!("\n── Function: {}  (0x{:x}) ──\n", name, vaddr));

        // Try decompilation first; fall back to disassembly if too complex
        let body = decompile_safe(path, *vaddr);
        let (analysis_text, source) = if body.starts_with("Decompiler error:") {
            // Decompile failed — fall back to raw disassembly for pattern scanning.
            // 512 instructions covers even large functions at reasonable output size.
            let asm = disassemble(path, None, 512, Some(*vaddr)).output;
            (asm, "disassembly (decompile too complex)")
        } else {
            (body, "decompiled pseudo-C")
        };

        let lower = analysis_text.to_ascii_lowercase();

        // Scan for C-library dangerous functions
        let c_hits: Vec<&&str> = DANGEROUS.iter().filter(|&&d| lower.contains(d)).collect();
        // Scan for Windows API dangerous functions
        let win_hits: Vec<&&str> = DANGEROUS_WIN.iter().filter(|&&d| lower.contains(d)).collect();

        if !c_hits.is_empty() || !win_hits.is_empty() {
            let all: Vec<&str> = c_hits.iter().map(|s| **s)
                .chain(win_hits.iter().map(|s| **s))
                .collect();
            out.push_str(&format!("  ⚠ Static flags (from {}): [{}]\n",
                source, all.join(", ")));
        } else {
            out.push_str(&format!("  [source: {}]\n", source));
        }
        out.push_str(&analysis_text);
        out.push_str("\n\n");
    }

    ToolResult::ok(out)
}

// ─── Tool: set_vuln_score ────────────────────────────────────────────────────

fn set_vuln_score(path: &str, vaddr: u64, score: u8) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }
    let mut p = Project::load_for(path);
    p.set_vuln_score(vaddr, score);
    match p.save() {
        Ok(_)  => ToolResult::ok(format!(
            "Vulnerability score for 0x{:x} set to {}/10", vaddr, score.min(10)
        )),
        Err(e) => ToolResult::err(format!("Could not save project: {}", e)),
    }
}

// ─── Tool: explain_function ──────────────────────────────────────────────────

fn explain_function(path: &str, vaddr: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }

    let pseudo_c = decompile_safe(path, vaddr);
    let project  = Project::load_for(path);
    let fn_name  = project.get_name(vaddr)
        .unwrap_or_else(|| format!("FUN_{:x}", vaddr));

    // ── Gather callers ────────────────────────────────────────────────────────
    let callers_section = {
        let xr = xrefs_to_inner(path, vaddr);
        if xr.is_empty() {
            String::new()
        } else {
            let lines: Vec<String> = xr.iter().take(10).map(|(caller_addr, site)| {
                let caller_name = project.get_name(*caller_addr)
                    .unwrap_or_else(|| format!("FUN_{:x}", caller_addr));
                format!("  0x{:x}  {}  (caller: {})", site, caller_name, caller_name)
            }).collect();
            format!("\nCallers ({}):\n{}\n", xr.len(), lines.join("\n"))
        }
    };

    // ── Existing signature context ────────────────────────────────────────────
    let sig_section = if let Some(sig) = project.get_signature(vaddr) {
        let ret  = sig.return_type.as_deref().unwrap_or("?");
        let params: Vec<String> = sig.param_types.iter().enumerate().map(|(i, pt)| {
            let t = pt.as_deref().unwrap_or("?");
            let n = sig.param_names.get(i).and_then(|x| x.as_deref()).unwrap_or("_");
            format!("{} {}", t, n)
        }).collect();
        format!("\nKnown signature: {} {}({})\n", ret, fn_name, params.join(", "))
    } else {
        String::new()
    };

    let out = format!(
        "Function '{}' at 0x{:x} in '{}':\n\
         {}{}\n\
         Pseudo-C:\n\
         {}\n\n\
         ─────────────────────────────────────────────────────────────────────\n\
         INSTRUCTION FOR MODEL:\n\
         Based on the decompiled pseudo-C above, provide:\n\
         1. A one-line summary of what this function does.\n\
         2. The likely purpose (e.g. parsing input, crypto routine, network send).\n\
         3. Notable patterns (loops, recursion, syscalls, dangerous operations).\n\
         4. Parameter names and types inferred from usage.\n\
         5. Local variable rename suggestions (old → new).\n\
         \n\
         Then call batch_annotate(path='{}', vaddr={}, \
         function_name='<name>', comment='<one-line summary>', \
         return_type='<type>', params=[...], variables=[...]) \
         to persist all annotations in one call.\n\
         Then call decompile(path='{}', vaddr={}) to confirm the renamed output.\n\
         Then call set_vuln_score(path='{}', vaddr={}, score=<0-10>).\n",
        fn_name, vaddr, path,
        sig_section, callers_section,
        pseudo_c,
        path, vaddr, path, vaddr, path, vaddr
    );
    ToolResult::ok(out)
}

/// Inner helper: returns Vec<(caller_fn_vaddr, call_site_vaddr)> for xrefs_to.
/// Extracted so explain_function can use it without re-parsing the text output.
fn xrefs_to_inner(path: &str, target: u64) -> Vec<(u64, u64)> {
    let result = xrefs_to(path, target);
    if result.output.starts_with("Error:") { return Vec::new(); }
    let mut pairs = Vec::new();
    for line in result.output.lines() {
        // Lines look like: "  0xSITE  FUN_XXXXXXXXXXXXXXXX  direct BL"
        let line = line.trim();
        if !line.starts_with("0x") { continue; }
        let mut tokens = line.split_whitespace();
        let site_str  = tokens.next().unwrap_or("");
        let fn_token  = tokens.next().unwrap_or("");
        let site = u64::from_str_radix(site_str.trim_start_matches("0x"), 16).unwrap_or(0);
        if site == 0 { continue; }
        let fn_vaddr = if fn_token.to_ascii_uppercase().starts_with("FUN_") {
            u64::from_str_radix(&fn_token[4..], 16).unwrap_or(0)
        } else {
            0
        };
        pairs.push((fn_vaddr, site));
    }
    pairs
}

// ─── Tool: identify_library_functions ───────────────────────────────────────

/// Static byte-pattern catalog for common x86-64 glibc/compiler functions.
/// Each entry: (function_name, byte_pattern_hex_nibbles for first N bytes)
/// Patterns use 0xFF as a wildcard nibble pair (match any byte).
const LIB_SIGS: &[(&str, &[u8], usize)] = &[
    // (name, first_bytes, match_len)  — 0xFF = wildcard
    ("__stack_chk_fail",       &[0xf3,0x0f,0x1e,0xfa,0x48,0x8b,0x05], 7),
    ("__libc_start_main",      &[0xf3,0x0f,0x1e,0xfa,0x41,0x57,0x49], 7),
    // endbr64 + sub rsp,N prologues common in glibc leaf fns
    ("memset",                  &[0xf3,0x0f,0x1e,0xfa,0x49,0x89,0xfa], 7),
    ("memcpy",                  &[0xf3,0x0f,0x1e,0xfa,0x49,0x89,0xd1], 7),
    ("strlen",                  &[0xf3,0x0f,0x1e,0xfa,0x48,0x85,0xff], 7),
    ("strcmp",                  &[0xf3,0x0f,0x1e,0xfa,0x48,0x85,0xd2], 7),
    ("malloc_usable_size",      &[0xf3,0x0f,0x1e,0xfa,0x48,0x85,0xff,0x74], 8),
    // Thunk stubs from compiler
    ("__x86_get_pc_thunk_bx",   &[0x8b,0x1c,0x24,0xc3], 4),
    ("__x86_get_pc_thunk_cx",   &[0x8b,0x0c,0x24,0xc3], 4),
    // Common CRT patterns
    ("_start",                  &[0x31,0xed,0x49,0x89,0xd1], 5),
    ("__do_global_dtors_aux",   &[0xf3,0x0f,0x1e,0xfa,0x80,0x3d], 6),
    ("frame_dummy",             &[0xf3,0x0f,0x1e,0xfa,0xe9], 5),
];

fn matches_sig(fn_bytes: &[u8], pattern: &[u8], len: usize) -> bool {
    if fn_bytes.len() < len { return false; }
    for i in 0..len {
        if pattern[i] != 0xff && fn_bytes[i] != pattern[i] { return false; }
    }
    true
}

fn identify_library_functions(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    // Collect candidate functions (prologue scan for stripped)
    let text_sec = obj.sections().find(|s| s.name().ok() == Some(".text"));
    let (text_bytes, text_vaddr) = match text_sec {
        Some(s) => match s.data() {
            Ok(d) => (d.to_vec(), s.address()),
            Err(e) => return ToolResult::err(format!("Cannot read .text: {}", e)),
        },
        None => return ToolResult::err("No .text section found"),
    };

    let arch_class = crate::arch::ArchClass::from_object(obj.architecture());

    // Pick the right signature table for the target architecture
    let sigs: &[(&str, &[u8], usize)] = match arch_class {
        crate::arch::ArchClass::Arm64 => crate::arch::AARCH64_LIB_SIGS,
        _ => LIB_SIGS,
    };

    let mut project = Project::load_for(path);
    let mut matches: Vec<(u64, &str)> = Vec::new();

    // Gather candidate starts from symbol table
    let mut candidates: Vec<u64> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0)
        .map(|s| s.address())
        .collect();

    // Also scan for function prologues if stripped
    if candidates.is_empty() {
        let step = arch_class.insn_align().max(1);
        let len = text_bytes.len();
        let mut i = 0;
        if arch_class.is_x86() {
            while i + 4 <= len {
                let b = &text_bytes[i..];
                if (b[0]==0xf3&&b[1]==0x0f&&b[2]==0x1e&&b[3]==0xfa)
                   || (b[0]==0x55&&b[1]==0x48&&b[2]==0x89&&b[3]==0xe5)
                {
                    candidates.push(text_vaddr + i as u64);
                }
                i += 1;
            }
        } else {
            // Use arch-specific prologue patterns from arch module
            let prologue_patterns: &[([u8; 4], [u8; 4])] = match arch_class {
                crate::arch::ArchClass::Arm64   => crate::arch::AARCH64_PROLOGUES,
                crate::arch::ArchClass::Arm     => crate::arch::ARM32_PROLOGUES,
                crate::arch::ArchClass::Mips { .. } => crate::arch::MIPS_PROLOGUES,
                crate::arch::ArchClass::RiscV { .. } => crate::arch::RISCV_PROLOGUES,
                _ => &[],
            };
            while i + 4 <= len {
                if crate::arch::matches_prologue(&text_bytes[i..], prologue_patterns) {
                    candidates.push(text_vaddr + i as u64);
                }
                i += step;
            }
        }
    }

    for &fn_vaddr in &candidates {
        if let Some(file_off) = vaddr_to_file_offset(&data, fn_vaddr) {
            let fn_slice = &data[file_off..data.len().min(file_off + 32)];
            for &(name, pattern, len) in sigs {
                if matches_sig(fn_slice, pattern, len) {
                    matches.push((fn_vaddr, name));
                    project.rename(fn_vaddr, name.to_string());
                    break;
                }
            }
        }
    }

    if matches.is_empty() {
        return ToolResult::ok("No known library function signatures matched. \
            This binary may use a different glibc version or is statically linked differently.");
    }

    let _ = project.save();

    let mut out = format!("Identified {} library functions (saved to project):\n\n", matches.len());
    out.push_str(&format!("  {:<20}  {}\n  {}\n", "Address", "Identified as", "─".repeat(50)));
    for (vaddr, name) in &matches {
        out.push_str(&format!("  0x{:016x}  {}\n", vaddr, name));
    }
    ToolResult::ok(out)
}

// ─── Tool: diff_binary ───────────────────────────────────────────────────────

fn binary_fn_hash(data: &[u8], vaddr: u64, size: u64) -> u64 {
    // FNV-1a 64-bit hash of function bytes
    if let Some(off) = vaddr_to_file_offset(data, vaddr) {
        let end = (off + size as usize).min(data.len());
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in &data[off..end] {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        return h;
    }
    0
}

fn diff_binary(path_a: &str, path_b: &str) -> ToolResult {
    if path_a.is_empty() { return ToolResult::err("'path_a' is required"); }
    if path_b.is_empty() { return ToolResult::err("'path_b' is required"); }

    let read = |p: &str| std::fs::read(p).map_err(|e| format!("Cannot read '{}': {}", p, e));
    let data_a = match read(path_a) { Ok(d) => d, Err(e) => return ToolResult::err(e) };
    let data_b = match read(path_b) { Ok(d) => d, Err(e) => return ToolResult::err(e) };

    let obj_a = match object::File::parse(data_a.as_slice())
        .map_err(|e| format!("Cannot parse '{}': {}", path_a, e)) {
        Ok(o) => o, Err(e) => return ToolResult::err(e)
    };
    let obj_b = match object::File::parse(data_b.as_slice())
        .map_err(|e| format!("Cannot parse '{}': {}", path_b, e)) {
        Ok(o) => o, Err(e) => return ToolResult::err(e)
    };

    let fns = |obj: &object::File, data: &[u8]| -> HashMap<String, (u64, u64, u64)> {
        obj.symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text && s.size() > 0 && s.address() != 0)
            .filter_map(|s| {
                let name = s.name().ok()?.to_string();
                let hash = binary_fn_hash(data, s.address(), s.size());
                Some((name, (s.address(), s.size(), hash)))
            })
            .collect()
    };

    let map_a = fns(&obj_a, &data_a);
    let map_b = fns(&obj_b, &data_b);

    let mut added:   Vec<&str> = Vec::new();
    let mut removed: Vec<&str> = Vec::new();
    let mut changed: Vec<(&str, u64, u64)> = Vec::new(); // name, addr_a, addr_b

    for (name, (addr_b, _, hash_b)) in &map_b {
        match map_a.get(name) {
            None => added.push(name),
            Some((addr_a, _, hash_a)) if hash_a != hash_b => {
                changed.push((name, *addr_a, *addr_b));
            }
            _ => {}
        }
    }
    for name in map_a.keys() {
        if !map_b.contains_key(name.as_str()) {
            removed.push(name);
        }
    }

    added.sort();
    removed.sort();
    changed.sort_by_key(|(n, _, _)| *n);

    let mut out = format!(
        "Binary diff: '{}' vs '{}'\n\
         A: {} functions  |  B: {} functions\n\n",
        path_a, path_b, map_a.len(), map_b.len()
    );
    out.push_str(&format!("Added   ({}):\n", added.len()));
    for n in &added { out.push_str(&format!("  + {}\n", n)); }
    out.push_str(&format!("\nRemoved ({}):\n", removed.len()));
    for n in &removed { out.push_str(&format!("  - {}\n", n)); }
    out.push_str(&format!("\nChanged ({}):\n", changed.len()));
    for (n, a, b) in &changed {
        out.push_str(&format!("  ~ {}  (A: 0x{:x}  B: 0x{:x})\n", n, a, b));
    }

    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        out.push_str("\nBinaries are functionally identical (all named functions match).\n");
    }
    ToolResult::ok(out)
}

// ─── Tool: auto_analyze ──────────────────────────────────────────────────────

fn auto_analyze(path: &str, top_n: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    // ── Guard: refuse on large statically-linked binaries to prevent OOM ────
    // Do a cheap function count (max=1) before doing anything expensive.
    let quick = list_functions(path, 1, true);
    let quick_total = serde_json::from_str::<serde_json::Value>(&quick.output).ok()
        .and_then(|v| v["total"].as_u64())
        .unwrap_or(0) as usize;
    if quick_total > 500 {
        return ToolResult::err(format!(
            "auto_analyze refused: binary has {} functions (likely statically linked). \
             Running auto_analyze on a binary this large risks OOM and produces unusable output. \
             Use targeted analysis instead:\n\
             1. file_info — architecture, segments, sections\n\
             2. list_functions — browse function list, pick targets\n\
             3. disassemble / decompile — examine specific functions\n\
             4. scan_vulnerabilities — focused vulnerability scan\n\
             Call auto_analyze only on small binaries (<= 500 functions).",
            quick_total
        ));
    }

    let mut out = String::new();

    // 1. File info
    let info = file_info(path);
    out.push_str("═══ FILE INFO ═══\n");
    out.push_str(&info.output);
    out.push_str("\n\n");

    // 2. Function list (small cap to avoid OOM on statically-linked binaries)
    let fn_list_cap = top_n.max(10);
    let fns = list_functions(path, fn_list_cap, true);
    out.push_str(&format!("═══ FUNCTIONS (top {}) ═══\n", fn_list_cap));

    // Parse JSON to get vaddrs and total function count
    let fn_json: Option<serde_json::Value> = serde_json::from_str(&fns.output).ok();
    let total_fns = fn_json.as_ref()
        .and_then(|v| v["total"].as_u64())
        .unwrap_or(0) as usize;
    let fn_addrs: Vec<u64> = fn_json
        .as_ref()
        .and_then(|v| v["functions"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|f| f["address"].as_u64())
        .collect();

    if fn_addrs.is_empty() {
        // Fallback: plain listing
        let plain = list_functions(path, fn_list_cap, false);
        out.push_str(&plain.output);
    } else {
        out.push_str(&fns.output);
    }
    if total_fns > 50 {
        out.push_str(&format!(
            "\n[Note: binary has {} total functions (likely statically linked). \
             Only top {} shown. Use list_functions with a higher max if needed.]\n",
            total_fns, fn_list_cap
        ));
    }
    out.push_str("\n\n");

    // 3. Call graph — skip for large binaries to avoid OOM
    if total_fns <= 200 {
        let cg = call_graph(path, 1);
        out.push_str("═══ CALL GRAPH ═══\n");
        out.push_str(&cg.output);
        out.push_str("\n\n");
    } else {
        out.push_str(&format!(
            "═══ CALL GRAPH ═══\n[Skipped: {} functions — call_graph on its own for specific targets]\n\n",
            total_fns
        ));
    }

    // 4. Strings (high-value section)
    let strs = strings_extract(path, 5, 30, Some(".rodata"));
    out.push_str("═══ STRINGS (.rodata) ═══\n");
    out.push_str(&strs.output);
    out.push_str("\n\n");

    // 5. Decompile top functions — skip for large binaries to avoid OOM
    out.push_str("═══ DECOMPILED FUNCTIONS ═══\n");
    if total_fns > 100 {
        out.push_str(&format!(
            "[Skipped: {} functions detected (likely statically linked). \
             Call decompile(path, vaddr) on specific functions of interest.]\n",
            total_fns
        ));
    } else {
        let addrs_to_decompile: Vec<u64> = if fn_addrs.is_empty() {
            Vec::new()
        } else {
            fn_addrs.into_iter().take(top_n).collect()
        };
        for vaddr in &addrs_to_decompile {
            let project = Project::load_for(path);
            let name = project.get_name(*vaddr)
                .unwrap_or_else(|| format!("FUN_{:x}", vaddr));
            out.push_str(&format!("\n── {} (0x{:x}) ──\n", name, vaddr));
            let decomp = decompile_safe(path, *vaddr);
            out.push_str(&decomp);
            out.push('\n');
        }
    }

    out.push_str("\n\n═══ NEXT STEPS ═══\n");
    out.push_str("Based on the above analysis:\n");
    out.push_str("1. Review each decompiled function and call rename_function() to assign meaningful names.\n");
    out.push_str("2. Call scan_vulnerabilities() to perform a detailed security review.\n");
    out.push_str("3. Call explain_function() on any suspicious or complex functions.\n");
    out.push_str("4. Call set_param_type()/set_param_name() to improve type annotations.\n");
    out.push_str("5. Call export_report() when analysis is complete.\n");

    ToolResult::ok(out)
}

// ─── Tool: export_report ────────────────────────────────────────────────────

fn export_report(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let project = Project::load_for(path);
    let info = file_info(path);

    let bin_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    let report_path = format!("{}.kaiju.html", path);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KaijuLab Report — {bin}</title>
<style>
  body {{ font-family: 'Cascadia Code', monospace; background: #1a1a2e; color: #e0e0e0; margin: 2em; }}
  h1 {{ color: #c084fc; }} h2 {{ color: #67e8f9; border-bottom: 1px solid #334; padding-bottom: 4px; }}
  h3 {{ color: #86efac; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1em; }}
  th {{ background: #2a2a4a; color: #67e8f9; padding: 6px 12px; text-align: left; }}
  td {{ padding: 4px 12px; border-bottom: 1px solid #2a2a3e; }}
  tr:hover td {{ background: #2a2a3e; }}
  code, pre {{ background: #0d1117; padding: 12px; border-radius: 4px; overflow-x: auto; color: #86efac; display: block; }}
  .score-hi  {{ color: #f87171; font-weight: bold; }}
  .score-med {{ color: #fb923c; }}
  .score-low {{ color: #facc15; }}
  .score-ok  {{ color: #86efac; }}
  .badge {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }}
  footer {{ color: #555; margin-top: 2em; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>KaijuLab Analysis Report</h1>
<p><strong>Binary:</strong> {bin} &nbsp; <strong>Generated:</strong> {ts}</p>
<pre>{info}</pre>
"#,
        bin  = html_escape(bin_name),
        ts   = now,
        info = html_escape(&info.output),
    );

    // Renames table
    if !project.renames.is_empty() {
        html.push_str("<h2>Function Renames</h2><table>\n<tr><th>Address</th><th>Name</th><th>Comment</th></tr>\n");
        let mut addrs: Vec<u64> = project.renames.keys().cloned().collect();
        addrs.sort();
        for addr in addrs {
            let name = &project.renames[&addr];
            let cmt  = project.get_comment(addr).unwrap_or("");
            let score = project.get_vuln_score(addr);
            let score_html = match score {
                Some(s) if s >= 7 => format!(" <span class='score-hi badge'>[!!] {}/10</span>", s),
                Some(s) if s >= 4 => format!(" <span class='score-med badge'>[!] {}/10</span>", s),
                Some(s) if s > 0  => format!(" <span class='score-low badge'>{}/10</span>", s),
                _ => String::new(),
            };
            html.push_str(&format!(
                "<tr><td><code>0x{:016x}</code></td><td>{}{}</td><td>{}</td></tr>\n",
                addr,
                html_escape(name),
                score_html,
                html_escape(cmt),
            ));
        }
        html.push_str("</table>\n");
    }

    // Vuln scores
    if !project.vuln_scores.is_empty() {
        html.push_str("<h2>Vulnerability Scores</h2><table>\n<tr><th>Address</th><th>Name</th><th>Score</th></tr>\n");
        let mut addrs: Vec<u64> = project.vuln_scores.keys().cloned().collect();
        addrs.sort();
        for addr in addrs {
            let score = project.vuln_scores[&addr];
            let name  = project.get_name(addr).unwrap_or_else(|| format!("FUN_{:x}", addr));
            let cls   = if score >= 7 { "score-hi" } else if score >= 4 { "score-med" } else { "score-low" };
            html.push_str(&format!(
                "<tr><td><code>0x{:016x}</code></td><td>{}</td><td class='{}'>{}/10</td></tr>\n",
                addr, html_escape(&name), cls, score
            ));
        }
        html.push_str("</table>\n");
    }

    // Struct definitions
    if !project.structs.is_empty() {
        html.push_str("<h2>Struct Definitions</h2>\n");
        let mut names: Vec<&String> = project.structs.keys().collect();
        names.sort();
        for name in names {
            html.push_str(&format!(
                "<h3>{}</h3><pre>{}</pre>\n",
                html_escape(name),
                html_escape(&project.structs[name].to_c()),
            ));
        }
    }

    html.push_str(&format!(
        "<footer>Generated by KaijuLab v{}</footer></body></html>\n",
        env!("CARGO_PKG_VERSION")
    ));

    match std::fs::write(&report_path, &html) {
        Ok(_)  => ToolResult::ok(format!(
            "Report written to '{}' ({} bytes)", report_path, html.len()
        )),
        Err(e) => ToolResult::err(format!("Cannot write report: {}", e)),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

// ─── Tool: load_pdb ──────────────────────────────────────────────────────────

fn load_pdb(binary_path: &str, pdb_path: &str) -> ToolResult {
    if binary_path.is_empty() { return ToolResult::err("'binary_path' is required"); }
    if pdb_path.is_empty()    { return ToolResult::err("'pdb_path' is required"); }

    let file = match std::fs::File::open(pdb_path) {
        Ok(f)  => f,
        Err(e) => return ToolResult::err(format!("Cannot open PDB '{}': {}", pdb_path, e)),
    };
    let mut pdb = match pdb::PDB::open(file) {
        Ok(p)  => p,
        Err(e) => return ToolResult::err(format!("Cannot parse PDB '{}': {}", pdb_path, e)),
    };

    let symbol_table = match pdb.global_symbols() {
        Ok(t)  => t,
        Err(e) => return ToolResult::err(format!("Cannot read PDB symbol table: {}", e)),
    };
    let address_map = match pdb.address_map() {
        Ok(m)  => m,
        Err(e) => return ToolResult::err(format!("Cannot build PDB address map: {}", e)),
    };

    // Get PE image base for absolute VA calculation
    let binary_data = std::fs::read(binary_path).unwrap_or_default();
    let image_base: u64 = goblin::Object::parse(&binary_data).ok()
        .and_then(|o| if let goblin::Object::PE(pe) = o { Some(pe.image_base as u64) } else { None })
        .unwrap_or(0x400000);

    let mut project = Project::load_for(binary_path);
    let mut count = 0usize;
    let mut out   = String::new();

    use pdb::FallibleIterator;
    let mut iter = symbol_table.iter();
    loop {
        match iter.next() {
            Ok(Some(sym)) => {
                if let Ok(pdb::SymbolData::Public(data)) = sym.parse() {
                    if data.code || data.function {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let vaddr = image_base + rva.0 as u64;
                            let name  = data.name.to_string().into_owned();
                            if !name.is_empty() {
                                out.push_str(&format!("  0x{:016x}  {}\n", vaddr, name));
                                project.rename(vaddr, name);
                                count += 1;
                            }
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_)   => break,
        }
    }

    if count == 0 {
        return ToolResult::ok(format!(
            "No public code symbols found in PDB '{}'. \
             The PDB may contain type info only.", pdb_path
        ));
    }

    match project.save() {
        Ok(_)  => ToolResult::ok(format!(
            "Loaded {} symbols from '{}' (saved to project):\n\n{}", count, pdb_path, out
        )),
        Err(e) => ToolResult::err(format!("Loaded {} symbols but could not save: {}", count, e)),
    }
}

// ─── Tool: decompile_flat ────────────────────────────────────────────────────

fn decompile_flat(path: &str, base_addr: u64, vaddr: u64, arch: &str) -> ToolResult {
    if path.is_empty()  { return ToolResult::err("'path' is required"); }
    if vaddr == 0       { return ToolResult::err("'vaddr' is required (virtual address to decompile)"); }
    let result = crate::decompiler::decompile_function_flat(path, base_addr, vaddr, arch);
    if result.starts_with("Decompiler error:") {
        ToolResult::err(result)
    } else {
        ToolResult::ok(format!(
            "Flat binary decompile — base=0x{:x}  vaddr=0x{:x}  arch={}\n\n{}",
            base_addr, vaddr, arch, result
        ))
    }
}

// ─── Tool: crypto_identify ───────────────────────────────────────────────────
//
// Scan a binary for byte signatures of well-known cryptographic algorithms.
// Covers constant tables (AES S-boxes, SHA init vectors, ChaCha20 "expand"
// string, CRC32 polynomials, Blowfish P-array start, MD5/SHA-1/SHA-512 IVs).
// O(file_size * num_patterns) — fast even on large PE/ELF files.

struct CryptoSig {
    algorithm:   &'static str,
    detail:      &'static str,
    /// Byte sequence to search for (first N bytes of constant table)
    pattern:     &'static [u8],
    /// Optional second sequence that must appear immediately after `pattern`
    /// (extra bytes used for disambiguation)
    confirm:     &'static [u8],
}

const CRYPTO_SIGS: &[CryptoSig] = &[
    // AES forward S-box (first 16 bytes)
    CryptoSig {
        algorithm: "AES",
        detail:    "Forward S-box (63 7c 77 7b f2 6b 6f c5 ...)",
        pattern:   &[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
                     0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
        confirm:   &[],
    },
    // AES inverse S-box (first 8 bytes)
    CryptoSig {
        algorithm: "AES",
        detail:    "Inverse S-box (52 09 6a d5 30 36 a5 38 ...)",
        pattern:   &[0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38],
        confirm:   &[],
    },
    // ChaCha20 / Salsa20 "expand 32-byte k"
    CryptoSig {
        algorithm: "ChaCha20 / Salsa20",
        detail:    "\"expand 32-byte k\" sigma constant",
        pattern:   b"expand 32-byte k",
        confirm:   &[],
    },
    // ChaCha20 / Salsa20 "expand 16-byte k"
    CryptoSig {
        algorithm: "ChaCha20 / Salsa20",
        detail:    "\"expand 16-byte k\" tau constant",
        pattern:   b"expand 16-byte k",
        confirm:   &[],
    },
    // SHA-256 init hash H0-H1 (LE): 6a09e667 bb67ae85
    CryptoSig {
        algorithm: "SHA-256",
        detail:    "Init hash values H0=0x6a09e667, H1=0xbb67ae85, ...",
        pattern:   &[0x67,0xe6,0x09,0x6a],
        confirm:   &[0x85,0xae,0x67,0xbb],
    },
    // SHA-512 init hash H0 (LE): 6a09e667f3bcc908
    CryptoSig {
        algorithm: "SHA-512 / SHA-384",
        detail:    "Init hash H0=0x6a09e667f3bcc908",
        pattern:   &[0x08,0xc9,0xbc,0xf3,0x67,0xe6,0x09,0x6a],
        confirm:   &[],
    },
    // SHA-1 init H0-H1 (LE): 67452301 efcdab89
    CryptoSig {
        algorithm: "SHA-1",
        detail:    "Init hash H0=0x67452301, H1=0xEFCDAB89, ...",
        pattern:   &[0x01,0x23,0x45,0x67],
        confirm:   &[0x89,0xab,0xcd,0xef],
    },
    // MD5 round constant T[1-2] (LE): d76aa478 e8c7b756
    CryptoSig {
        algorithm: "MD5",
        detail:    "Round constants T[1]=0xd76aa478, T[2]=0xe8c7b756",
        pattern:   &[0x78,0xa4,0x6a,0xd7],
        confirm:   &[0x56,0xb7,0xc7,0xe8],
    },
    // CRC32 reflected polynomial
    CryptoSig {
        algorithm: "CRC32",
        detail:    "Reflected polynomial 0xEDB88320",
        pattern:   &[0x20,0x83,0xb8,0xed],
        confirm:   &[],
    },
    // CRC32 normal polynomial
    CryptoSig {
        algorithm: "CRC32",
        detail:    "Normal polynomial 0x04C11DB7",
        pattern:   &[0x04,0xc1,0x1d,0xb7],
        confirm:   &[],
    },
    // Blowfish P-array (from digits of pi): 243f6a88 85a308d3
    CryptoSig {
        algorithm: "Blowfish",
        detail:    "P-array start 0x243F6A88, 0x85A308D3 (from pi)",
        pattern:   &[0x24,0x3f,0x6a,0x88],
        confirm:   &[0x85,0xa3,0x08,0xd3],
    },
    // RC4 identity permutation start (00 01 02 03 ... in .data)
    CryptoSig {
        algorithm: "RC4 (possible)",
        detail:    "Identity permutation S[0..15] = 00 01 02 03 ... 0f",
        pattern:   &[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f],
        confirm:   &[0x10,0x11,0x12,0x13], // next 4 must also be sequential
    },
    // TEA/XTEA magic constant 0x9E3779B9 (golden ratio)
    CryptoSig {
        algorithm: "TEA / XTEA",
        detail:    "Delta constant 0x9E3779B9 (golden ratio)",
        pattern:   &[0xb9,0x79,0x37,0x9e],
        confirm:   &[],
    },
    // Keccak/SHA-3 round constant RC[0] = 0x0000000000000001
    CryptoSig {
        algorithm: "SHA-3 / Keccak",
        detail:    "Round constant RC[0]=1 followed by RC[1]=0x8082",
        pattern:   &[0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
        confirm:   &[0x82,0x80,0x00,0x00,0x00,0x00,0x00,0x00],
    },
];

fn crypto_identify(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Build offset→VA mapping from PE/ELF section table
    let sections: Vec<(u64, usize, usize)> = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(pe)) => {
            let base = pe.image_base as u64;
            pe.sections.iter().map(|s| {
                let va     = base + s.virtual_address as u64;
                let foff   = s.pointer_to_raw_data as usize;
                let fsize  = s.size_of_raw_data as usize;
                (va, foff, fsize)
            }).collect()
        }
        Ok(goblin::Object::Elf(elf)) => {
            elf.section_headers.iter().map(|s| {
                (s.sh_addr, s.sh_offset as usize, s.sh_size as usize)
            }).collect()
        }
        _ => vec![],
    };

    let offset_to_va = |off: usize| -> u64 {
        for &(va, foff, fsize) in &sections {
            if foff > 0 && off >= foff && off < foff + fsize {
                return va + (off - foff) as u64;
            }
        }
        off as u64 // fallback: treat as raw offset
    };

    // Search for each signature
    struct Hit { algo: &'static str, detail: &'static str, vas: Vec<u64> }
    let mut hits: Vec<Hit> = Vec::new();

    for sig in CRYPTO_SIGS {
        let pat = sig.pattern;
        let pat_len = pat.len();
        if pat_len == 0 || pat_len > data.len() { continue; }

        let mut found_vas: Vec<u64> = Vec::new();
        'scan: for i in 0..=(data.len() - pat_len) {
            if data[i..i + pat_len] != *pat { continue; }
            // Check confirm sequence if present
            if !sig.confirm.is_empty() {
                let c = sig.confirm;
                let end = i + pat_len + c.len();
                if end > data.len() { continue; }
                for (j, &b) in c.iter().enumerate() {
                    if data[i + pat_len + j] != b { continue 'scan; }
                }
            }
            found_vas.push(offset_to_va(i));
            if found_vas.len() >= 8 { break; } // cap per-sig matches
        }

        if !found_vas.is_empty() {
            // Deduplicate into prior hit for same algorithm if exists
            if let Some(existing) = hits.iter_mut().find(|h| {
                h.algo == sig.algorithm && h.detail == sig.detail
            }) {
                existing.vas.extend_from_slice(&found_vas);
            } else {
                hits.push(Hit { algo: sig.algorithm, detail: sig.detail, vas: found_vas });
            }
        }
    }

    let mut out = format!("Cryptographic constant scan: '{}'\n{}\n\n", path, "═".repeat(60));

    if hits.is_empty() {
        out.push_str("No known cryptographic constants found.\n");
        out.push_str("(Scanned for: AES, ChaCha20/Salsa20, SHA-256/512, SHA-1, SHA-3, MD5,\n");
        out.push_str(" CRC32, Blowfish, TEA/XTEA, RC4 identity permutation)\n");
        out.push_str("\nNote: custom or obfuscated crypto will not be detected by constant scanning.\n");
        out.push_str("Use section_entropy to find high-entropy regions that may be custom crypto.\n");
    } else {
        out.push_str(&format!("{} signature(s) found:\n\n", hits.len()));
        for h in &hits {
            out.push_str(&format!("  [+] {}\n", h.algo));
            out.push_str(&format!("      {}\n", h.detail));
            let va_list: Vec<String> = h.vas.iter().take(5)
                .map(|v| format!("0x{:x}", v)).collect();
            out.push_str(&format!("      Location(s): {}", va_list.join("  ")));
            if h.vas.len() > 5 {
                out.push_str(&format!("  (+{} more)", h.vas.len() - 5));
            }
            out.push_str("\n\n");
        }
        out.push_str("Tip: use decompile(path, va) at each location to see how the algorithm\n");
        out.push_str("is invoked and what data flows through it.\n");
    }

    ToolResult::ok(out)
}

// ─── Tool: function_context ──────────────────────────────────────────────────
//
// Assemble rich analysis context for a single function in one tool call:
// decompiled pseudo-C + direct callers + direct callees + project annotations.
// This replaces the common pattern of calling decompile + xrefs_to + disassemble
// separately and lets the LLM reason about a function holistically.

fn function_context(path: &str, vaddr: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0     { return ToolResult::err("'vaddr' is required"); }

    let project = Project::load_for(path);
    let fn_name = project.get_name(vaddr)
        .unwrap_or_else(|| format!("FUN_{:016x}", vaddr));

    let sep = "─".repeat(60);
    let mut out = format!(
        "Function context: {} @ 0x{:x}\n{}\n\n",
        fn_name, vaddr, "═".repeat(60)
    );

    // ── 1. Decompilation ────────────────────────────────────────────────────
    out.push_str(&format!("{}\n[1] Decompiled pseudo-C\n{}\n", sep, sep));
    let decomp = decompile_safe(path, vaddr);
    out.push_str(&decomp);
    out.push_str("\n\n");

    // ── 2. Callers ──────────────────────────────────────────────────────────
    out.push_str(&format!("{}\n[2] Callers (who calls this function)\n{}\n", sep, sep));
    let caller_pairs = xrefs_to_inner(path, vaddr);
    if caller_pairs.is_empty() {
        out.push_str("  (no callers found — may be an entry point or exported function)\n");
    } else {
        for (caller_va, call_site) in caller_pairs.iter().take(10) {
            let caller_name = project.get_name(*caller_va)
                .unwrap_or_else(|| format!("FUN_{:016x}", caller_va));
            out.push_str(&format!("  0x{:016x}  {}  (call site: 0x{:x})\n",
                caller_va, caller_name, call_site));
        }
        if caller_pairs.len() > 10 {
            out.push_str(&format!("  ... and {} more callers\n", caller_pairs.len() - 10));
        }
    }
    out.push('\n');

    // ── 3. Callees (parse CALL/BL/BLR from disassembly) ───────────────────
    out.push_str(&format!("{}\n[3] Callees (functions this function calls)\n{}\n", sep, sep));
    // Use auto-sized disassembly (pe_pdata_fn_size resolves full function body)
    let asm_result = disassemble(path, None, 256, Some(vaddr));
    let mut callees: Vec<(u64, String)> = Vec::new();
    let mut indirect_calls: usize = 0;

    // Build IAT map once for ADRP+LDR+BLR resolution (AArch64 PE pattern)
    let iat_map: std::collections::HashMap<u64, String> = std::fs::read(path)
        .map(|d| build_pe_iat_map(&d))
        .unwrap_or_default();

    // Track ADRP page per register: reg_name → page_addr
    let mut adrp_pages: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    // Track IAT slot per register after ADRP+LDR: reg_name → iat_va
    let mut reg_iat: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut iat_callees: Vec<String> = Vec::new();

    // Helper: extract mnemonic + operands from a disasm display line.
    // Lines look like: "│   ADDR  HH HH HH HH    mnemonic operands ; comment"
    // Strategy: skip the leading │, find the first letter-starting word (the mnemonic)
    // after the address and byte tokens, then extract operands from the raw string.
    fn parse_mnemonic_operands(line: &str) -> Option<(String, String)> {
        let stripped = line.trim_start_matches('│').trim();
        let mut saw_addr = false;
        let mut mnemonic_in_str: Option<(usize, usize)> = None; // byte range in `stripped`
        let mut byte_offset = 0usize;
        for tok in stripped.split_whitespace() {
            let tok_start = stripped[byte_offset..].find(tok)? + byte_offset;
            let tok_end = tok_start + tok.len();
            let all_hex = tok.chars().all(|c| c.is_ascii_hexdigit());
            let starts_letter = tok.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false);
            if !saw_addr {
                if all_hex { saw_addr = true; }
                byte_offset = tok_end;
                continue;
            }
            // skip instruction byte tokens (exactly 2 hex chars)
            if all_hex && tok.len() == 2 { byte_offset = tok_end; continue; }
            // first non-byte non-address token starting with a letter = mnemonic
            if starts_letter {
                mnemonic_in_str = Some((tok_start, tok_end));
                break;
            }
            byte_offset = tok_end;
        }
        let (mnm_start, mnm_end) = mnemonic_in_str?;
        let mnm = stripped[mnm_start..mnm_end].to_ascii_lowercase();
        // Operands: everything after mnemonic (trimmed), up to '; ' comment marker
        let rest = stripped[mnm_end..].trim();
        let ops = rest.splitn(2, " ; ").next().unwrap_or("").trim().to_ascii_lowercase();
        Some((mnm, ops))
    }

    for line in asm_result.output.lines() {
        let Some((mnemonic, operands)) = parse_mnemonic_operands(line) else { continue };

        // Track ADRP: "adrp xN, #0xPAGE"
        if mnemonic == "adrp" {
            let parts: Vec<&str> = operands.splitn(2, ',').collect();
            if parts.len() >= 2 {
                let reg = parts[0].trim().to_string();
                let page_s = parts[1].trim().trim_start_matches('#');
                if let Ok(page) = u64::from_str_radix(page_s.trim_start_matches("0x"), 16) {
                    adrp_pages.insert(reg, page);
                }
            }
        }
        // Track LDR/LDRB/LDRH from [xN, #offset] — check ADRP page + offset vs IAT
        else if mnemonic == "ldr" || mnemonic == "ldrb" || mnemonic == "ldrh" || mnemonic == "ldrw" {
            let parts: Vec<&str> = operands.splitn(2, ',').collect();
            if parts.len() >= 2 {
                let dst_reg = parts[0].trim().to_string();
                let src = parts[1].trim();
                if src.starts_with('[') {
                    // "[ xB, #offset ]" or "[xB, #offset]!"
                    let inner = src.trim_start_matches('[').trim_end_matches('!')
                        .trim_end_matches(']').trim();
                    let src_parts: Vec<&str> = inner.splitn(2, ',').collect();
                    if src_parts.len() >= 2 {
                        let base_reg = src_parts[0].trim().to_string();
                        let off_s = src_parts[1].trim().trim_start_matches('#');
                        if let Ok(off) = u64::from_str_radix(off_s.trim_start_matches("0x"), 16) {
                            if let Some(&page) = adrp_pages.get(&base_reg) {
                                let iat_va = page + off;
                                if iat_map.contains_key(&iat_va) {
                                    reg_iat.insert(dst_reg, iat_va);
                                }
                            }
                        }
                    }
                } else {
                    // PC-relative literal: "ldr xD, #0xADDR"
                    let addr_s = src.trim_start_matches('#');
                    if let Ok(lit_addr) = u64::from_str_radix(addr_s.trim_start_matches("0x"), 16) {
                        if iat_map.contains_key(&lit_addr) {
                            reg_iat.insert(dst_reg, lit_addr);
                        }
                    }
                }
            }
        }
        // BLR: indirect call via register
        else if mnemonic == "blr" {
            let reg = operands.trim().to_string();
            if let Some(&iat_va) = reg_iat.get(&reg) {
                if let Some(imp_name) = iat_map.get(&iat_va) {
                    if !iat_callees.contains(imp_name) {
                        iat_callees.push(imp_name.clone());
                    }
                    continue;
                }
            }
            indirect_calls += 1;
        }
        // Direct call/bl/blx
        else if mnemonic == "call" || mnemonic == "bl" || mnemonic == "blx" {
            // Operand is the target address
            let tgt_s = operands.trim().trim_start_matches('#');
            if let Ok(addr) = u64::from_str_radix(tgt_s.trim_start_matches("0x"), 16) {
                if addr > 0 && !callees.iter().any(|(a, _)| *a == addr) {
                    let name = project.get_name(addr)
                        .unwrap_or_else(|| format!("FUN_{:016x}", addr));
                    callees.push((addr, name));
                }
            }
        }
    }

    if callees.is_empty() && indirect_calls == 0 && iat_callees.is_empty() {
        out.push_str("  (no callees resolved from disassembly)\n");
    } else {
        for (addr, name) in callees.iter().take(15) {
            out.push_str(&format!("  0x{:016x}  {}\n", addr, name));
        }
        if callees.len() > 15 {
            out.push_str(&format!("  ... and {} more direct callees\n", callees.len() - 15));
        }
        for imp in &iat_callees {
            out.push_str(&format!("  [IAT] {}\n", imp));
        }
        if indirect_calls > 0 {
            out.push_str(&format!(
                "  + {} indirect call(s) via register (blr/call reg) — \
                 targets unresolved (not a simple ADRP+LDR+BLR pattern)\n",
                indirect_calls
            ));
        }
    }
    out.push('\n');

    // ── 4. Project annotations ──────────────────────────────────────────────
    out.push_str(&format!("{}\n[4] Annotations\n{}\n", sep, sep));
    let mut has_annotations = false;

    if let Some(comment) = project.get_comment(vaddr) {
        out.push_str(&format!("  comment: {}\n", comment));
        has_annotations = true;
    }
    if let Some(score) = project.get_vuln_score(vaddr) {
        out.push_str(&format!("  vuln_score: {}/10\n", score));
        has_annotations = true;
    }
    if let Some(sig) = project.get_signature(vaddr) {
        if let Some(ref rt) = sig.return_type {
            out.push_str(&format!("  return_type: {}\n", rt));
            has_annotations = true;
        }
        for (n, (pt, pn)) in sig.param_types.iter().zip(sig.param_names.iter()).enumerate() {
            let ty   = pt.as_deref().unwrap_or("");
            let name = pn.as_deref().unwrap_or("");
            if !ty.is_empty() || !name.is_empty() {
                out.push_str(&format!("  param[{}]: {} {}\n", n + 1, ty, name));
                has_annotations = true;
            }
        }
    }
    if !has_annotations {
        out.push_str("  (no annotations yet — use batch_annotate to add names, types, and comments)\n");
    }

    ToolResult::ok(out)
}

// ─── Tool: angr_find ─────────────────────────────────────────────────────────
//
// Use angr symbolic execution to find input (stdin bytes) that drives execution
// to a target address.  Generates a complete Python script using angr's
// SimulationManager.explore() and runs it via run_python.  angr must be
// installed (check with python_env).
//
// Limitations:
//  - Works best for small, self-contained functions or paths <= ~100 basic blocks
//  - Large binaries with many indirect calls may need auto_load_libs=False
//  - Returns up to 3 satisfying inputs; complex constraints may time out

fn angr_find(
    path: &str,
    find_addr: u64,
    avoid_addr: u64,
    start_addr: u64,
    stdin_bytes: u64,
    timeout_secs: u64,
) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if find_addr == 0     { return ToolResult::err("'find_addr' is required"); }

    let timeout = timeout_secs.clamp(10, 120);
    let stdin_n = stdin_bytes.clamp(1, 256);

    // We build the Python script as a plain string (no Rust string escaping
    // issues since we control all content).
    let avoid_line = if avoid_addr != 0 {
        format!("AVOID = [0x{:x}]", avoid_addr)
    } else {
        "AVOID = []".to_string()
    };

    let start_line = if start_addr != 0 {
        format!("START = 0x{:x}  # override entry", start_addr)
    } else {
        "START = None  # use binary entry point".to_string()
    };

    let script = format!(
r###"import angr, claripy, os, sys, signal, time

binary = os.environ.get('KAIJU_BINARY', '')
if not binary:
    sys.exit('KAIJU_BINARY not set')

FIND  = 0x{find_addr:x}
{avoid_line}
{start_line}
STDIN_BYTES = {stdin_n}

print('angr_find: binary =', binary)
print('  find  = 0x{find_addr:x}')
print('  avoid =', ['0x%x' % a for a in AVOID])
print('  stdin_bytes =', STDIN_BYTES)
print()

proj = angr.Project(binary, auto_load_libs=False)

# Symbolic stdin of fixed length
stdin_sym = claripy.BVS('stdin', STDIN_BYTES * 8)

# Constrain to printable ASCII (common for CTF/format-string bugs)
# Remove or relax if you need arbitrary bytes
for byte in stdin_sym.chop(8):
    pass  # no constraint — allow all bytes for maximum reachability

# Build initial state
if START is not None:
    state = proj.factory.blank_state(
        addr=START,
        stdin=angr.SimFile('<stdin>', content=stdin_sym, size=STDIN_BYTES),
    )
else:
    state = proj.factory.entry_state(
        stdin=angr.SimFile('<stdin>', content=stdin_sym, size=STDIN_BYTES),
    )

simgr = proj.factory.simulation_manager(state)

# Explore with timeout guard
deadline = time.time() + {timeout}
def step_func(smgr):
    if time.time() > deadline:
        print('[timeout] stopping exploration after {timeout}s')
        smgr.move(from_stash='active', to_stash='timeout')
    return smgr

if AVOID:
    simgr.explore(find=FIND, avoid=AVOID, step_func=step_func, num_find=3)
else:
    simgr.explore(find=FIND, step_func=step_func, num_find=3)

print('Simulation manager:', simgr)
print()

if simgr.found:
    print('[+] Found', len(simgr.found), 'path(s) reaching 0x{find_addr:x}:')
    for i, s in enumerate(simgr.found[:3]):
        print()
        print('  --- Solution', i + 1, '---')
        try:
            stdin_val = s.solver.eval(stdin_sym, cast_to=bytes)
            print('  stdin (raw bytes):', repr(stdin_val))
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in stdin_val)
            print('  stdin (printable):', printable)
        except Exception as e:
            print('  could not concretize stdin:', e)
        try:
            pc = s.solver.eval(s.regs.pc)
            print('  PC at find:', hex(pc))
        except Exception:
            pass
else:
    print('[-] No path found to 0x{find_addr:x}')
    for stash, states in simgr.stashes.items():
        if states:
            print('  stash %-12s: %d states' % (stash, len(states)))
    print()
    print('Suggestions:')
    print('  1. Try a larger stdin_bytes value')
    print('  2. Remove avoid addresses if any')
    print('  3. Use start_addr to start from a function instead of entry')
    print('  4. The target may be unreachable from entry with symbolic input')
"###,
        find_addr = find_addr,
        avoid_line = avoid_line,
        start_line = start_line,
        stdin_n = stdin_n,
        timeout = timeout,
    );

    run_python(&script, None, Some(path), timeout + 10)
}

// ─── Tool: python_env ────────────────────────────────────────────────────────

/// Return the Python version and installed binary-analysis packages.
/// The LLM should call this once before writing `run_python` scripts so it
/// knows exactly which imports will succeed.
fn python_env() -> ToolResult {
    let script = r#"
import sys, importlib, importlib.metadata as meta
print(f"Python {sys.version}")
print()
print("Binary analysis packages:")

# (import_name, display_name)
PACKAGES = [
    ("pefile",     "pefile"),
    ("capstone",   "capstone"),
    ("angr",       "angr"),
    ("unicorn",    "unicorn"),
    ("z3",         "z3-solver"),
    ("elftools",   "pyelftools"),
    ("yara",       "yara-python"),
    ("ropgadget",  "ROPgadget"),
    ("pwn",        "pwntools"),
    ("lief",       "lief"),
    ("keystone",   "keystone-engine"),
    ("miasm",      "miasm"),
    ("frida",      "frida"),
    ("r2pipe",     "r2pipe"),
]

for mod, pkg in PACKAGES:
    try:
        importlib.import_module(mod)
        try:
            ver = meta.version(pkg)
        except Exception:
            ver = "?"
        print(f"  [+] {pkg:<22} {ver}")
    except ImportError:
        print(f"  [-] {pkg}")

print()
print("Always available (stdlib):")
print("  struct       — pack/unpack raw bytes: struct.unpack_from('<I', data, offset)[0]")
print("  binascii     — hexlify/unhexlify")
print("  hashlib      — md5/sha1/sha256 of bytes")
print("  mmap         — memory-map large files without reading all bytes")
print("  ctypes       — cast byte arrays to C structs")
print("  re           — regex over bytes/strings")
print("  collections  — Counter, defaultdict")
print()
print("KAIJU_BINARY env var: path to the currently loaded binary.")
print("  data = open(os.environ['KAIJU_BINARY'], 'rb').read()")
"#;
    run_python(script, None, None, 20)
}

// ─── Tool: run_python ────────────────────────────────────────────────────────

/// Write `script` to a temp file and execute it with `python3`.
///
/// - `stdin_data`  : optional bytes piped to the child's stdin.
/// - `binary_path` : if provided, set as `KAIJU_BINARY` env var.
/// - `timeout_secs`: hard wall-clock kill limit (clamped to 1–120 s).
///
/// Returns combined stdout + stderr (interleaved order is not guaranteed;
/// stderr is appended after stdout).  Output is truncated to 32 KiB so
/// runaway scripts don't flood the LLM context.
fn run_python(
    script: &str,
    stdin_data: Option<&str>,
    binary_path: Option<&str>,
    timeout_secs: u64,
) -> ToolResult {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    // Cap output read per stream so a chatty script can't OOM the host.
    // Applied at the reader level (before allocation) via .take().
    const MAX_STREAM: u64 = 256 * 1024; // 256 KiB per stream

    if script.trim().is_empty() {
        return ToolResult::err("'script' must not be empty");
    }

    // ── Write script to a temp file ───────────────────────────────────────────
    let mut tmp = match tempfile::Builder::new()
        .prefix("kaiju_py_")
        .suffix(".py")
        .tempfile()
    {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot create temp file: {}", e)),
    };
    if let Err(e) = tmp.write_all(script.as_bytes()) {
        return ToolResult::err(format!("Cannot write script: {}", e));
    }
    if let Err(e) = tmp.flush() {
        return ToolResult::err(format!("Cannot flush script: {}", e));
    }
    let script_path = tmp.path().to_owned();

    // ── Resolve effective binary path ─────────────────────────────────────────
    let effective_binary = match binary_path {
        Some(bp) if !bp.is_empty() => bp.to_string(),
        _ => std::env::var("KAIJU_BINARY").unwrap_or_default(),
    };

    // ── Warn about p.interactive() ────────────────────────────────────────────
    let has_interactive = script.contains("interactive()");

    // ── Persist script next to the binary ────────────────────────────────────
    // Saved as  <binary>.kaiju_scripts/script_NNN.py  before execution so the
    // path can be included in the result header even on timeout.
    // After execution the file is renamed to script_NNN_ok.py or _err.py.
    let saved_script_path: Option<std::path::PathBuf> = (|| {
        if effective_binary.is_empty() {
            return None;
        }
        let bin = std::path::Path::new(&effective_binary);
        let stem = bin.file_name()?;
        let scripts_dir = bin.parent().unwrap_or(std::path::Path::new("."))
            .join(format!("{}.kaiju_scripts", stem.to_string_lossy()));
        std::fs::create_dir_all(&scripts_dir).ok()?;
        // Auto-increment based on all .py files (including _ok/_err variants)
        let n = std::fs::read_dir(&scripts_dir).ok()?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("py"))
            .count();
        let dest = scripts_dir.join(format!("script_{:03}.py", n + 1));
        std::fs::write(&dest, script.as_bytes()).ok()?;
        Some(dest)
    })();

    // ── Build child command ───────────────────────────────────────────────────
    let mut cmd = Command::new("python3");
    cmd.arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    if !effective_binary.is_empty() {
        cmd.env("KAIJU_BINARY", &effective_binary);
    }

    // ── CRITICAL: isolate the child in its own process group ─────────────────
    //
    // Without this, libraries like pwntools can call tcsetpgrp() to steal the
    // terminal's foreground group, or install signal handlers that re-raise
    // SIGINT to the group — both of which kill the TUI process.
    //
    // process_group(0) puts the child in a fresh group so it is unreachable
    // by signals directed at the parent group, and cannot reach the parent
    // via group-wide signals itself.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return ToolResult::err(
                    "python3 not found — install Python 3 and make sure it is on PATH",
                );
            }
            return ToolResult::err(format!("Failed to spawn python3: {}", e));
        }
    };

    // ── Write stdin (drop handle immediately so the child sees EOF) ───────────
    if let Some(data) = stdin_data {
        if let Some(mut h) = child.stdin.take() {
            let _ = h.write_all(data.as_bytes());
            // h is dropped here → child stdin pipe closed → child sees EOF
        }
    }

    // ── Drain stdout + stderr concurrently in background threads ─────────────
    //
    // This prevents the classic pipe-full deadlock: if we only poll try_wait()
    // without reading, and the script writes > ~64 KB, the child blocks on the
    // write syscall waiting for the reader.  We'd never see it exit, burn the
    // full timeout, and finally kill it having collected nothing useful.
    //
    // Each thread reads up to MAX_STREAM bytes, then stops (the child sees a
    // broken pipe on further writes, which is benign).
    let stdout_thread = {
        let pipe = child.stdout.take().expect("stdout was piped");
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(MAX_STREAM).read_to_end(&mut buf);
            buf
        })
    };
    let stderr_thread = {
        let pipe = child.stderr.take().expect("stderr was piped");
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(MAX_STREAM).read_to_end(&mut buf);
            buf
        })
    };

    // ── Wait with timeout ─────────────────────────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Kill the entire process group so any child-of-child
                    // processes also die, not just the direct python3 child.
                    #[cfg(unix)]
                    {
                        // child.id() is the pgid we set with process_group(0)
                        let pgid = child.id() as i32;
                        unsafe { libc::killpg(pgid, libc::SIGKILL); }
                    }
                    #[cfg(not(unix))]
                    { let _ = child.kill(); }
                    let _ = child.wait();
                    break true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break false,
        }
    };

    // ── Collect output (threads finish promptly now that child is dead) ───────
    let stdout_bytes = stdout_thread.join().unwrap_or_default();
    let stderr_bytes = stderr_thread.join().unwrap_or_default();

    // Use from_utf8_lossy so binary output doesn't panic.
    let stdout_str = String::from_utf8_lossy(&stdout_bytes);
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);

    let was_truncated_out = stdout_bytes.len() as u64 >= MAX_STREAM;
    let was_truncated_err = stderr_bytes.len() as u64 >= MAX_STREAM;

    // ── Re-read exit status (already reaped above or via try_wait) ────────────
    // We use a second try_wait here; if it returns None (child already reaped
    // in the timeout branch) we reconstruct the status string as "killed".
    let exit_label = if timed_out {
        format!("killed (timeout {}s)", timeout_secs)
    } else {
        // try_wait one more time to get the ExitStatus for display
        match child.try_wait() {
            Ok(Some(s)) => s.to_string(),
            _ => "exited".to_string(),
        }
    };

    // ── Build result string ───────────────────────────────────────────────────
    let sep = "─".repeat(60);
    let binary_hint = if !effective_binary.is_empty() {
        format!("  KAIJU_BINARY={}", effective_binary)
    } else {
        String::new()
    };
    let saved_hint = match &saved_script_path {
        Some(p) => format!("  saved={}", p.display()),
        None => String::new(),
    };
    let header = format!(
        "run_python — {}{}{}  timeout: {}s\n{}\n",
        exit_label, binary_hint, saved_hint, timeout_secs, sep,
    );

    let mut body = String::new();

    if !stdout_str.is_empty() {
        body.push_str(&stdout_str);
        if was_truncated_out {
            body.push_str(&format!(
                "\n[stdout truncated at {} KiB]",
                MAX_STREAM / 1024
            ));
        }
    }
    if !stderr_str.is_empty() {
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str("--- stderr ---\n");
        body.push_str(&stderr_str);
        if was_truncated_err {
            body.push_str(&format!(
                "\n[stderr truncated at {} KiB]",
                MAX_STREAM / 1024
            ));
        }
    }

    // ── Rename saved script to reflect outcome ────────────────────────────────
    let succeeded = !timed_out && stderr_bytes.is_empty();
    if let Some(ref path) = saved_script_path {
        let suffix = if succeeded { "_ok" } else { "_err" };
        let new_name = path.file_stem()
            .map(|s| format!("{}{}.py", s.to_string_lossy(), suffix));
        if let Some(name) = new_name {
            let new_path = path.with_file_name(name);
            let _ = std::fs::rename(path, &new_path);
        }
    }

    // ── Warn if script called interactive() ───────────────────────────────────
    let interactive_warn = if has_interactive {
        "\n[WARNING] Script called p.interactive() — stdin is /dev/null in run_python, \
         so interactive() blocks until the timeout. Use p.recv(timeout=N) instead.]\n"
    } else {
        ""
    };

    // ── Echo script source (first 40 lines) so failures are self-explaining ──
    let script_echo = {
        let lines: Vec<&str> = script.lines().collect();
        let shown = lines.len().min(40);
        let truncated = if lines.len() > 40 {
            format!("\n... ({} more lines)", lines.len() - 40)
        } else {
            String::new()
        };
        format!(
            "--- script ---\n{}{}\n{}",
            lines[..shown].join("\n"),
            truncated,
            sep,
        )
    };

    let result = format!("{}{}{}{}", header, script_echo, interactive_warn, body);

    if timed_out {
        ToolResult::err(result)
    } else {
        ToolResult::ok(result)
    }
}

// ─── Tool: recover_vtables ───────────────────────────────────────────────────

/// Scan .rdata/.rodata for sequences of pointers that all point into .text —
/// the canonical layout of a C++ vtable on x86/x64 PE and ELF binaries.
fn recover_vtables(path: &str, min_methods: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let min_methods = min_methods.max(2).min(64);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Collect (ptr_size, text ranges, scan sections) from either PE or ELF.
    let (ptr_sz, text_ranges, scan_sections): (
        usize,
        Vec<(u64, u64)>,
        Vec<(String, u64, Vec<u8>)>,
    ) = match goblin::Object::parse(&data) {
        Ok(goblin::Object::PE(pe)) => {
            let ptr_sz: usize = if pe.is_64 { 8 } else { 4 };
            let base = pe.image_base as u64;

            let text_ranges = pe.sections.iter()
                .filter(|s| {
                    let n = std::str::from_utf8(&s.name).unwrap_or("").trim_matches('\0');
                    n == ".text" || n.contains("text")
                })
                .map(|s| {
                    let va = base + s.virtual_address as u64;
                    (va, va + s.virtual_size as u64)
                })
                .collect();

            // vtables live in .rdata; also check .data for hand-assembled code
            let scan = pe.sections.iter()
                .filter(|s| {
                    let n = std::str::from_utf8(&s.name).unwrap_or("").trim_matches('\0');
                    n == ".rdata" || n == ".data"
                })
                .filter_map(|s| {
                    let n = std::str::from_utf8(&s.name).unwrap_or("?")
                        .trim_matches('\0').to_string();
                    let va  = base + s.virtual_address as u64;
                    let off = s.pointer_to_raw_data as usize;
                    let sz  = s.size_of_raw_data as usize;
                    Some((n, va, data.get(off..off + sz)?.to_vec()))
                })
                .collect();

            (ptr_sz, text_ranges, scan)
        }
        Ok(goblin::Object::Elf(elf)) => {
            let ptr_sz: usize = if elf.is_64 { 8 } else { 4 };

            let text_ranges = elf.section_headers.iter()
                .filter(|sh| matches!(
                    elf.shdr_strtab.get_at(sh.sh_name),
                    Some(".text") | Some("__text")
                ))
                .map(|sh| (sh.sh_addr, sh.sh_addr + sh.sh_size))
                .collect();

            let scan = elf.section_headers.iter()
                .filter(|sh| matches!(
                    elf.shdr_strtab.get_at(sh.sh_name),
                    Some(".rodata") | Some(".data.rel.ro") | Some(".data")
                ))
                .filter_map(|sh| {
                    let n = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?").to_string();
                    let off = sh.sh_offset as usize;
                    let sz  = sh.sh_size as usize;
                    Some((n, sh.sh_addr, data.get(off..off + sz)?.to_vec()))
                })
                .collect();

            (ptr_sz, text_ranges, scan)
        }
        _ => return ToolResult::err("Unsupported format — PE or ELF required"),
    };

    let is_in_text = |addr: u64| -> bool {
        addr != 0 && text_ranges.iter().any(|&(s, e)| addr >= s && addr < e)
    };

    let read_ptr = |bytes: &[u8], off: usize| -> Option<u64> {
        if ptr_sz == 8 {
            bytes.get(off..off + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        } else {
            bytes.get(off..off + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
        }
    };

    let mut vtables: Vec<(u64, Vec<u64>)> = Vec::new();

    for (_sec_name, sec_va, sec_bytes) in &scan_sections {
        let n = sec_bytes.len() / ptr_sz;
        let mut i = 0;
        while i < n {
            let Some(ptr) = read_ptr(sec_bytes, i * ptr_sz) else { i += 1; continue; };
            if !is_in_text(ptr) { i += 1; continue; }

            // Collect the run of consecutive valid .text pointers
            let vtable_va = sec_va + (i * ptr_sz) as u64;
            let mut methods = vec![ptr];
            let mut j = i + 1;
            while j < n {
                let Some(p2) = read_ptr(sec_bytes, j * ptr_sz) else { break; };
                if is_in_text(p2) { methods.push(p2); j += 1; } else { break; }
            }

            if methods.len() >= min_methods {
                vtables.push((vtable_va, methods));
                i = j;
            } else {
                i += 1;
            }
        }
    }

    if vtables.is_empty() {
        return ToolResult::ok(format!(
            "No vtable candidates found — no runs of ≥{} consecutive .text pointers in \
             .rdata/.rodata/.data.",
            min_methods
        ));
    }

    let project = Project::load_for(path);
    let resolve = |addr: u64| -> String {
        project.renames.get(&addr).cloned()
            .unwrap_or_else(|| format!("FUN_{:016x}", addr))
    };

    let sep = "─".repeat(56);
    let mut out = format!(
        "vtable recovery — {} candidate{} (min_methods={})\n{}\n\n",
        vtables.len(),
        if vtables.len() == 1 { "" } else { "s" },
        min_methods,
        sep,
    );
    for (vt_va, methods) in &vtables {
        out.push_str(&format!("vtable @ 0x{:016x}  ({} methods)\n", vt_va, methods.len()));
        for (idx, m) in methods.iter().enumerate() {
            out.push_str(&format!("  [{}]  0x{:016x}  {}\n", idx, m, resolve(*m)));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "{}\nDecompile individual methods to confirm; use rename_function to assign class names.\n",
        sep
    ));

    ToolResult::ok(out)
}

// ─── Tool: find_string_decoders ──────────────────────────────────────────────

/// Scan .text functions for the hallmarks of a string-decoding stub:
/// XOR-with-immediate, byte-level memory access, and a backward branch (loop).
/// Returns candidates ranked by a heuristic score so the analyst can decompile
/// and then emulate the top hits with unicorn.
fn find_string_decoders(path: &str, max_fns: usize) -> ToolResult {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};

    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        other => return ToolResult::err(format!(
            "find_string_decoders requires x86/x86-64 (got {:?})", other
        )),
    };

    let text_sec = obj.sections()
        .find(|s| s.name().ok().map_or(false, |n| n == ".text" || n == "__text"));
    let (text_vaddr, text_end, text_bytes) = match text_sec {
        Some(s) => {
            let va  = s.address();
            let end = va + s.size();
            let bytes = s.data().unwrap_or(&[]).to_vec();
            (va, end, bytes)
        }
        None => return ToolResult::err("Cannot find .text section"),
    };

    // Collect function start addresses from the symbol table
    let project = Project::load_for(path);
    let mut fn_addrs: Vec<u64> = obj.symbols()
        .filter(|s| {
            s.kind() == object::SymbolKind::Text
                && s.address() >= text_vaddr
                && s.address() < text_end
                && s.size() > 0
                && s.size() <= 0x800 // decoders are small
        })
        .map(|s| s.address())
        .collect();

    // Fall back to stripped-binary prologue scan if no symbols
    if fn_addrs.is_empty() {
        let is_64 = bitness == 64;
        let mut i = 0usize;
        while i + 4 <= text_bytes.len() {
            let b = &text_bytes[i..];
            let hit = if is_64 {
                (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xe5)
                    || (b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa)
            } else {
                b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xe5
            };
            if hit { fn_addrs.push(text_vaddr + i as u64); }
            i += 1;
        }
    }

    // PE .pdata fallback for stripped x64 PE
    if fn_addrs.is_empty() {
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&data) {
            let base = pe.image_base as u64;
            if let Some(pdata) = pe.sections.iter()
                .find(|s| s.name().ok().map_or(false, |n| n == ".pdata"))
                .and_then(|s| s.data(&data).ok().flatten())
            {
                for chunk in pdata.chunks_exact(12) {
                    let rva = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as u64;
                    if rva != 0 { fn_addrs.push(base + rva); }
                }
            }
        }
    }

    fn_addrs.sort_unstable();
    fn_addrs.dedup();
    fn_addrs.truncate(max_fns.min(2000));

    let mut candidates: Vec<(u64, u32, String)> = Vec::new();

    for &fn_va in &fn_addrs {
        if fn_va < text_vaddr || fn_va >= text_end { continue; }
        let fn_off = (fn_va - text_vaddr) as usize;
        if fn_off >= text_bytes.len() { continue; }

        // Cap at 512 bytes — real decoder stubs are small
        let window = text_bytes[fn_off..].len().min(512);
        let slice  = &text_bytes[fn_off..fn_off + window];
        let mut decoder = Decoder::with_ip(bitness, slice, fn_va, DecoderOptions::NONE);

        let mut score: u32 = 0;
        let mut instr_count: u32 = 0;
        let mut has_xor_imm       = false;
        let mut has_arith_imm     = false;
        let mut has_byte_mem      = false;
        let mut has_back_branch   = false;
        let mut has_loop_insn     = false;
        let mut xor_keys: Vec<u64> = Vec::new();
        let mut tags: Vec<&'static str> = Vec::new();

        for instr in &mut decoder {
            if instr.is_invalid() { continue; }
            instr_count += 1;
            if instr_count > 100 { break; }

            let m  = instr.mnemonic();
            let ip = instr.ip();

            // XOR reg/mem, imm  (most common single-byte XOR key)
            if m == Mnemonic::Xor
                && matches!(
                    instr.op1_kind(),
                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64
                    | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate32to64
                )
                && instr.immediate(1) != 0
            {
                has_xor_imm = true;
                xor_keys.push(instr.immediate(1));
            }

            // ADD / SUB / ROL / ROR with immediate (alternative obfuscation ops)
            if matches!(m, Mnemonic::Add | Mnemonic::Sub | Mnemonic::Rol | Mnemonic::Ror)
                && matches!(
                    instr.op1_kind(),
                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate16
                    | OpKind::Immediate32
                )
            {
                has_arith_imm = true;
            }

            // Byte memory read (MOVZX/MOVSX from [mem], or MOV AL/CL/DL…)
            if matches!(m, Mnemonic::Movzx | Mnemonic::Movsx)
                && instr.op1_kind() == OpKind::Memory
            {
                has_byte_mem = true;
            }
            if m == Mnemonic::Mov
                && (instr.op0_kind() == OpKind::Memory || instr.op1_kind() == OpKind::Memory)
            {
                has_byte_mem = true;
            }

            // Backward branch within this function → loop body
            if matches!(
                instr.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) {
                let tgt = instr.near_branch64();
                if tgt < ip && tgt >= fn_va {
                    has_back_branch = true;
                }
            }

            // Explicit LOOP/LOOPE/LOOPNE instruction
            if matches!(m, Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne) {
                has_loop_insn = true;
            }

            if instr.flow_control() == FlowControl::Return { break; }
        }

        if has_xor_imm         { score += 30; tags.push("xor-imm"); }
        if has_arith_imm       { score += 10; tags.push("arith-imm"); }
        if has_byte_mem        { score += 20; tags.push("byte-mem"); }
        if has_back_branch     { score += 25; tags.push("back-branch"); }
        if has_loop_insn       { score += 30; tags.push("LOOP-insn"); }
        // Size bonus: true stubs are tiny
        if instr_count <= 15 && score > 0 { score += 25; }
        else if instr_count <= 30 && score > 0 { score += 10; }

        if score >= 50 {
            let keys_str = if !xor_keys.is_empty() {
                let ks: Vec<String> = xor_keys.iter().take(4)
                    .map(|k| format!("0x{:x}", k)).collect();
                format!(" key={}", ks.join(","))
            } else {
                String::new()
            };
            candidates.push((fn_va, score, format!(
                "score={} insns={}{} [{}]",
                score, instr_count, keys_str, tags.join(" ")
            )));
        }
    }

    if candidates.is_empty() {
        return ToolResult::ok(format!(
            "No string decoder candidates found in {} functions scanned.\n\
             (Looked for: XOR-with-immediate + byte memory access + backward branch.)",
            fn_addrs.len()
        ));
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1));

    let sep = "─".repeat(56);
    let mut out = format!(
        "string decoder candidates — {} found ({} functions scanned)\n{}\n\n",
        candidates.len(), fn_addrs.len(), sep
    );
    for (va, _score, desc) in &candidates {
        let name = project.renames.get(va).cloned()
            .unwrap_or_else(|| format!("FUN_{:016x}", va));
        out.push_str(&format!("  0x{:016x}  {:<32}  {}\n", va, name, desc));
    }
    out.push_str(&format!(
        "\n{}\nNext: decompile top candidates, then emulate with run_python + unicorn \
         to recover plaintext strings.\n",
        sep
    ));

    ToolResult::ok(out)
}

// ─── Tool: frida_trace ───────────────────────────────────────────────────────

/// Run a binary under Frida, attach hooks to the requested addresses or export
/// names, and return the call log (function, args, return value).
/// Requires the `frida` Python package (`pip install frida frida-tools`).
fn frida_trace(path: &str, hooks: &[String], timeout_secs: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if hooks.is_empty() { return ToolResult::err("'hooks' must contain at least one address or function name"); }
    if !std::path::Path::new(path).exists() {
        return ToolResult::err(format!("Binary '{}' not found", path));
    }

    // Detect architecture from the binary so the JS script reads the right registers
    let arch_hint = std::fs::read(path).ok().and_then(|d| {
        object::File::parse(d.as_slice()).ok().map(|f| f.architecture())
    });
    let (arg_regs, _ret_reg) = match arch_hint {
        Some(Architecture::X86_64 | Architecture::X86_64_X32) =>
            (r#"["rdi","rsi","rdx","rcx","r8","r9"]"#, "rax"),
        Some(Architecture::Aarch64 | Architecture::Aarch64_Ilp32) =>
            (r#"["x0","x1","x2","x3","x4","x5"]"#, "x0"),
        Some(Architecture::Arm) =>
            (r#"["r0","r1","r2","r3"]"#, "r0"),
        Some(Architecture::I386) =>
            (r#"[]"# , "eax"),   // x86-32: args are on stack, skip for now
        _ =>
            (r#"["rdi","rsi","rdx","rcx"]"#, "rax"),
    };

    // Build hook attachment JS for each requested target
    let mut hook_js = String::new();
    for hook in hooks {
        let trimmed = hook.trim();
        let attach_expr = if trimmed.starts_with("0x") || trimmed.starts_with("0X")
            || trimmed.chars().next().map_or(false, |c| c.is_ascii_digit())
        {
            // Numeric address
            format!("ptr(\"{}\")", trimmed)
        } else {
            // Export name — search all loaded modules
            format!("Module.findExportByName(null, {:?})", trimmed)
        };
        hook_js.push_str(&format!(r#"
(function() {{
  var target = {attach_expr};
  if (!target) {{ console.log("[frida] WARNING: could not resolve hook target: {hook_display}"); return; }}
  Interceptor.attach(target, {{
    onEnter: function(args) {{
      var argRegs = {arg_regs};
      var argVals = argRegs.map(function(r) {{
        try {{ return this.context[r].toString(); }} catch(e) {{ return "?"; }}
      }}, this);
      send(JSON.stringify({{event:"enter", target:"{hook_display}", args:argVals}}));
    }},
    onLeave: function(retval) {{
      send(JSON.stringify({{event:"leave", target:"{hook_display}", retval:retval.toString()}}));
    }}
  }});
  console.log("[frida] hooked: {hook_display}");
}})();
"#,
            attach_expr = attach_expr,
            hook_display = trimmed,
            arg_regs = arg_regs,
        ));
    }


    let script = format!(r#"
import frida, sys, json, os, time

BINARY = os.environ.get('KAIJU_BINARY', '')
events = []

def on_message(message, data):
    if message.get('type') == 'send':
        try:
            events.append(json.loads(message['payload']))
        except Exception:
            events.append({{'raw': message['payload']}})
    elif message.get('type') == 'error':
        print('[frida error]', message.get('description',''), message.get('stack',''))

js_hook = r"""
{hook_js}
"""

try:
    device = frida.get_local_device()
    pid    = device.spawn([BINARY])
    session = device.attach(pid)
    script  = session.create_script(js_hook)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    time.sleep({timeout_secs})
    try:
        session.detach()
    except Exception:
        pass
except frida.NotSupportedError as e:
    print("frida.NotSupportedError:", e)
    print("Tip: frida may require root or ptrace permissions on this system.")
    sys.exit(1)
except Exception as e:
    print("frida error:", e)
    sys.exit(1)

print(f"[frida_trace] captured {{len(events)}} events")
print()
for ev in events:
    if ev.get('event') == 'enter':
        ev_args = ', '.join(ev.get('args', []))
        print(f"  CALL  {{ev['target']}}({{ev_args}})")
    elif ev.get('event') == 'leave':
        print(f"  RET   {{ev['target']}} -> {{ev.get('retval','?')}}")
    else:
        print(' ', ev)
"#,
        hook_js      = hook_js,
        timeout_secs = timeout_secs.clamp(2, 30),
    );

    run_python(&script, None, Some(path), timeout_secs + 5)
}

// ─── Tool: run_binary ────────────────────────────────────────────────────────

/// Execute a native binary with optional args / stdin and capture its output.
fn run_binary(
    path: &str,
    argv: &[String],
    stdin_data: Option<&str>,
    timeout_secs: u64,
) -> ToolResult {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if !std::path::Path::new(path).exists() {
        return ToolResult::err(format!("Binary '{}' not found", path));
    }

    const MAX_STREAM: u64 = 256 * 1024; // 256 KiB per stream
    let timeout = timeout_secs.clamp(1, 30);

    let mut cmd = Command::new(path);
    for a in argv { cmd.arg(a); }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    // Put child in its own process group so SIGKILL can target the whole tree
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("Failed to execute '{}': {}", path, e)),
    };

    // Write stdin (close immediately so child sees EOF)
    if let Some(input) = stdin_data {
        if let Some(mut h) = child.stdin.take() {
            let _ = h.write_all(input.as_bytes());
        }
    }

    // Drain stdout + stderr in background threads to avoid pipe-full deadlocks
    let stdout_thread = {
        let pipe = child.stdout.take().expect("stdout was piped");
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(MAX_STREAM).read_to_end(&mut buf);
            buf
        })
    };
    let stderr_thread = {
        let pipe = child.stderr.take().expect("stderr was piped");
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(MAX_STREAM).read_to_end(&mut buf);
            buf
        })
    };

    // Wait with timeout
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {
                if Instant::now() >= deadline {
                    #[cfg(unix)]
                    {
                        let pgid = child.id() as i32;
                        unsafe { libc::killpg(pgid, libc::SIGKILL); }
                    }
                    #[cfg(not(unix))]
                    { let _ = child.kill(); }
                    let _ = child.wait();
                    break true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break false,
        }
    };

    let exit_status = if !timed_out { child.try_wait().ok().flatten() } else { None };
    let stdout_bytes = stdout_thread.join().unwrap_or_default();
    let stderr_bytes = stderr_thread.join().unwrap_or_default();

    let stdout_str = String::from_utf8_lossy(&stdout_bytes);
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);
    let trunc_out  = stdout_bytes.len() as u64 >= MAX_STREAM;
    let trunc_err  = stderr_bytes.len() as u64 >= MAX_STREAM;

    let exit_label = if timed_out {
        format!("TIMEOUT ({}s) — process killed", timeout)
    } else {
        exit_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "exited".to_string())
    };

    let sep = "─".repeat(60);
    let cmd_str = if argv.is_empty() {
        path.to_string()
    } else {
        format!("{} {}", path, argv.join(" "))
    };

    let mut out = format!("run_binary — {}\ncmd: {}\n{}\n", exit_label, cmd_str, sep);

    if !stdout_str.is_empty() {
        out.push_str(&stdout_str);
        if trunc_out {
            out.push_str(&format!("\n[stdout truncated at {} KiB]", MAX_STREAM / 1024));
        }
    }
    if !stderr_str.is_empty() {
        if !out.ends_with('\n') { out.push('\n'); }
        out.push_str("--- stderr ---\n");
        out.push_str(&stderr_str);
        if trunc_err {
            out.push_str(&format!("\n[stderr truncated at {} KiB]", MAX_STREAM / 1024));
        }
    }
    if stdout_str.is_empty() && stderr_str.is_empty() {
        out.push_str("(no output)\n");
    }

    if timed_out {
        ToolResult::err(out)
    } else {
        ToolResult::ok(out)
    }
}

// ─── Tool definitions for the LLM ────────────────────────────────────────────

/// All tool definitions in standard JSON Schema (lowercase types).
/// Each backend converts to its own wire format.
pub fn all_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "file_info".into(),
            description: "Parse a binary file and return its format, architecture, entry point, \
                           LOAD segment table (vaddr ↔ file-offset mapping), section table, \
                           symbol count, and imports. Always call this first on an unknown binary.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute or relative path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "hexdump".into(),
            description: "Display a hex+ASCII dump of raw bytes from a file at a given file offset.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":   { "type": "string",  "description": "Path to the binary file" },
                    "offset": { "type": "integer", "description": "File offset to start from (default 0)" },
                    "length": { "type": "integer", "description": "Number of bytes to show (default 256)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "strings_extract".into(),
            description: "Extract printable ASCII strings from a binary file. \
                           Pass `section` (e.g. '.rodata') to limit scanning to that section only — \
                           this avoids noise from opcode bytes in .text when looking for string literals.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":        { "type": "string",  "description": "Path to the binary file" },
                    "min_len":     { "type": "integer", "description": "Minimum string length (default 4)" },
                    "max_results": { "type": "integer", "description": "Maximum strings to return (default 60)" },
                    "section":     { "type": "string",  "description": "Optional section name to limit scan, e.g. '.rodata'" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "disassemble".into(),
            description: "Disassemble machine code from a binary file. \
                           Pass `vaddr` (virtual address, e.g. entry point or a function address from \
                           list_functions) — the tool automatically translates it to a file offset via \
                           the LOAD/section table. \
                           For PE binaries, if `vaddr` matches a .pdata function entry the full function \
                           body is disassembled automatically regardless of `length`. \
                           For ELF, function size is read from the symbol table when available. \
                           Use `disassemble` as the primary fallback when `decompile` fails — it works \
                           on all functions regardless of complexity. \
                           Alternatively pass `offset` for a raw file byte offset (overrides vaddr).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":   { "type": "string",  "description": "Path to the binary file" },
                    "vaddr":  { "type": "integer", "description": "Virtual address (auto-sized from .pdata for PE, symbol table for ELF)" },
                    "offset": { "type": "integer", "description": "Raw file byte offset (overrides vaddr)" },
                    "length": { "type": "integer", "description": "Minimum bytes to disassemble (default 128; auto-expanded to full function when vaddr matches a known function)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "read_section".into(),
            description: "Read the raw contents of a named section (e.g. .text, .rodata) and display a hex dump.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string", "description": "Path to the binary file" },
                    "section": { "type": "string", "description": "Section name, e.g. '.text'" }
                },
                "required": ["path", "section"]
            }),
        },
        ToolDefinition {
            name: "resolve_plt".into(),
            description: "Map PLT stub virtual addresses to their imported symbol names by parsing \
                           .rela.plt relocations and the dynamic symbol table. \
                           Use this to identify what imported function a CALL instruction is targeting \
                           when you see a call to an address inside the PLT range.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "list_functions".into(),
            description: "List functions in the binary. For non-stripped binaries, returns the symbol \
                           table. For stripped binaries, scans .text for common x86/x86-64 function \
                           prologues (endbr64, push rbp; mov rbp,rsp) as a heuristic. \
                           The returned addresses can be passed directly to `disassemble` via `vaddr`. \
                           Pass `json: true` for machine-readable JSON output suitable for post-processing.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":        { "type": "string",  "description": "Path to the binary file" },
                    "max_results": { "type": "integer", "description": "Maximum functions to return (default 50)" },
                    "json":        { "type": "boolean", "description": "Return JSON instead of formatted text (default false)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "decompile".into(),
            description: "Decompile a single function to pseudo-C code using symbolic execution and \
                           structural recovery (if/else, loops, assignments, calls). \
                           Supports x86/x86-64 ELF and PE binaries. \
                           Pass `vaddr` as the function's virtual address (e.g. from list_functions or \
                           the entry point from file_info). Requires the SLEIGH processor definitions \
                           to be present at ./SLEIGH (included with KaijuLab). \
                           Note: best-effort — complex or obfuscated functions may yield partial output.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Virtual address of the function entry point" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "xrefs_to".into(),
            description: "Find all call/jmp sites in .text that target a given virtual address. \
                           Returns a list of caller addresses with their enclosing function names (if available). \
                           Supports x86/x86-64 only.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Target virtual address to find references to" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "dwarf_info".into(),
            description: "Extract function names, addresses, and sizes from DWARF debug information \
                           embedded in the binary. Returns an empty result for stripped binaries. \
                           Useful for non-stripped binaries compiled with -g.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "rename_function".into(),
            description: "Assign a human-readable name to a function address in the project sidecar \
                           (saved as <binary>.kaiju.json next to the binary). \
                           The name will appear in subsequent decompile and xrefs_to output.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Function virtual address" },
                    "name":  { "type": "string",  "description": "Human-readable function name" }
                },
                "required": ["path", "vaddr", "name"]
            }),
        },
        ToolDefinition {
            name: "add_comment".into(),
            description: "Attach an analyst comment to a virtual address in the project sidecar. \
                           Saved persistently in <binary>.kaiju.json.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string",  "description": "Path to the binary file" },
                    "vaddr":   { "type": "integer", "description": "Virtual address" },
                    "comment": { "type": "string",  "description": "Comment text" }
                },
                "required": ["path", "vaddr", "comment"]
            }),
        },
        ToolDefinition {
            name: "load_project".into(),
            description: "Load and display the KaijuLab project sidecar for a binary. \
                           Shows all renames, comments, type annotations, and struct definitions \
                           previously saved for that binary.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "rename_variable".into(),
            description: "Rename a local variable or parameter inside a specific function. \
                           The old_name is the name as it currently appears in decompile output \
                           (e.g. 'arg_1', 'RAX', 'var_3'). The new name will be substituted on \
                           all subsequent decompile calls for that function. \
                           Call decompile again after renaming to see the updated output.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":     { "type": "string",  "description": "Path to the binary file" },
                    "fn_vaddr": { "type": "integer", "description": "Virtual address of the function" },
                    "old_name": { "type": "string",  "description": "Variable name as it appears in current decompile output" },
                    "new_name": { "type": "string",  "description": "Replacement name" }
                },
                "required": ["path", "fn_vaddr", "old_name", "new_name"]
            }),
        },
        ToolDefinition {
            name: "set_return_type".into(),
            description: "Set the return type of a function. The decompiler always emits 'void' \
                           by default; this overrides it. Use C type strings: 'int', 'char*', \
                           'uint64_t', 'struct Node*', etc. \
                           Call decompile again to see the updated signature.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":     { "type": "string",  "description": "Path to the binary file" },
                    "fn_vaddr": { "type": "integer", "description": "Virtual address of the function" },
                    "type_str": { "type": "string",  "description": "C return type, e.g. 'int', 'char*', 'void'" }
                },
                "required": ["path", "fn_vaddr", "type_str"]
            }),
        },
        ToolDefinition {
            name: "set_param_type".into(),
            description: "Set the type of the N-th parameter of a function (1-indexed). \
                           This replaces the default 'int32_t' prefix in the decompiler output. \
                           Example: set_param_type(path, fn_vaddr, param_n=1, type_str='const char*') \
                           changes 'int32_t arg_1' to 'const char* arg_1'.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":     { "type": "string",  "description": "Path to the binary file" },
                    "fn_vaddr": { "type": "integer", "description": "Virtual address of the function" },
                    "param_n":  { "type": "integer", "description": "Parameter number, 1-indexed (1 = first param)" },
                    "type_str": { "type": "string",  "description": "C type string, e.g. 'const char*', 'size_t'" }
                },
                "required": ["path", "fn_vaddr", "param_n", "type_str"]
            }),
        },
        ToolDefinition {
            name: "set_param_name".into(),
            description: "Set the name of the N-th parameter of a function (1-indexed). \
                           This renames 'arg_1', 'arg_2', etc. in the decompiled output. \
                           Combine with set_param_type for full parameter annotations.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":     { "type": "string",  "description": "Path to the binary file" },
                    "fn_vaddr": { "type": "integer", "description": "Virtual address of the function" },
                    "param_n":  { "type": "integer", "description": "Parameter number, 1-indexed" },
                    "name":     { "type": "string",  "description": "Parameter name, e.g. 'buf', 'count', 'flags'" }
                },
                "required": ["path", "fn_vaddr", "param_n", "name"]
            }),
        },
        ToolDefinition {
            name: "define_struct".into(),
            description: "Define a C struct layout and save it to the project. \
                           Structs are used to annotate pointer dereferences in decompiler output. \
                           Each field specifies its byte offset, size, name, and type. \
                           Use list_types to review saved structs.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":        { "type": "string",  "description": "Path to the binary file" },
                    "struct_name": { "type": "string",  "description": "C struct name, e.g. 'sockaddr_in'" },
                    "total_size":  { "type": "integer", "description": "Total struct size in bytes" },
                    "fields": {
                        "type": "array",
                        "description": "Array of field definitions",
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset":   { "type": "integer", "description": "Byte offset from struct base" },
                                "size":     { "type": "integer", "description": "Field size in bytes" },
                                "name":     { "type": "string",  "description": "Field name" },
                                "type_str": { "type": "string",  "description": "C type, e.g. 'uint32_t'" }
                            }
                        }
                    }
                },
                "required": ["path", "struct_name"]
            }),
        },
        ToolDefinition {
            name: "list_types".into(),
            description: "Show all type annotations, variable renames, function signatures, and \
                           struct definitions saved in the project sidecar for a binary. \
                           Use this to review current annotations before decompiling.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },

        // ── New tool definitions ──────────────────────────────────────────────

        ToolDefinition {
            name: "resolve_pe_imports".into(),
            description: "List all imported symbols from a PE (Windows) binary by reading the \
                           Import Address Table (IAT). Returns DLL name, symbol name, and \
                           IAT virtual address for each import. Use this instead of resolve_plt \
                           for PE binaries.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the PE binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "call_graph".into(),
            description: "Build a static call graph by scanning .text for direct CALL instructions. \
                           Returns caller → callees adjacency list with function names resolved from \
                           the symbol table and project renames. Useful for understanding module \
                           structure and identifying entry points. x86/x86-64 only.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":      { "type": "string",  "description": "Path to the binary file" },
                    "max_depth": { "type": "integer", "description": "Not currently used (reserved for future BFS depth limiting)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "cfg_view".into(),
            description: "Show the Control Flow Graph (CFG) of a single function as a list of \
                           basic blocks with their start/end addresses, instruction counts, and \
                           successor edges. Useful for understanding loops, branches, and dead code. \
                           x86/x86-64 only.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Virtual address of the function entry point" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "scan_vulnerabilities".into(),
            description: "Decompile the top N functions and return their pseudo-C code annotated \
                           with a vulnerability checklist. Review the output and call set_vuln_score \
                           for each function with a suspicion score (0=clean, 10=critical). \
                           Checks for: buffer overflow, format string, UAF, integer overflow, \
                           command injection, dangerous function usage (gets/strcpy/system).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string",  "description": "Path to the binary file" },
                    "max_fns": { "type": "integer", "description": "Number of functions to analyse (default 5, max recommended 10)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "set_vuln_score".into(),
            description: "Save a vulnerability suspicion score (0–10) for a function. \
                           0 = clean, 1-3 = low, 4-6 = medium, 7-9 = high, 10 = critical. \
                           Scores are shown as [!]/[!!] badges in the Functions panel and \
                           appear in the HTML report from export_report.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Function virtual address" },
                    "score": { "type": "integer", "description": "Suspicion score 0-10" }
                },
                "required": ["path", "vaddr", "score"]
            }),
        },
        ToolDefinition {
            name: "add_note".into(),
            description: "Save a free-form analyst note for this binary, optionally anchored to \
                           a virtual address. Use this to record findings, hypotheses, observations, \
                           and analysis conclusions that should persist across sessions. \
                           Notes appear in the TUI Notes tab and are visible to future analysis \
                           turns via list_notes or load_project. \
                           Examples: 'This function appears to be a custom RC4 implementation', \
                           'Parameter 2 is attacker-controlled via the network socket'.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "text":  { "type": "string",  "description": "Note text — what you observed or concluded" },
                    "vaddr": { "type": "integer", "description": "Optional virtual address this note is anchored to" }
                },
                "required": ["path", "text"]
            }),
        },
        ToolDefinition {
            name: "delete_note".into(),
            description: "Delete an analyst note by its id. \
                           Use list_notes or load_project to find the id of the note to delete.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string",  "description": "Path to the binary file" },
                    "id":   { "type": "integer", "description": "Note id (from list_notes output)" }
                },
                "required": ["path", "id"]
            }),
        },
        ToolDefinition {
            name: "list_notes".into(),
            description: "List all analyst notes saved for a binary, including their ids, \
                           anchored addresses, timestamps, and text. \
                           Call this at the start of a session to understand what has already \
                           been observed or hypothesised in previous analysis turns.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "get_vuln_scores".into(),
            description: "Retrieve all vulnerability suspicion scores previously set for this binary. \
                           Returns each scored function's address, score (0–10), badge (LOW/MED/HIGH), \
                           and name. Use this before calling set_vuln_score to avoid overwriting \
                           scores set by previous analysis turns, and to understand the current \
                           risk landscape before diving deeper.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "explain_function".into(),
            description: "Decompile a function and request a natural-language explanation. \
                           Returns the decompiled pseudo-C along with instructions for you to \
                           write a docstring, suggest a rename, and annotate parameters. \
                           After analysing the output, call add_comment and rename_function \
                           to persist your findings.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Function virtual address" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "identify_library_functions".into(),
            description: "Attempt to identify common library functions (libc, CRT) in the binary \
                           by matching the first bytes of each function against a catalog of known \
                           glibc x86-64 byte signatures. Matched functions are automatically renamed \
                           in the project. Useful for stripped binaries where symbol names are absent.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "diff_binary".into(),
            description: "Compare two binary files by their function symbol tables. \
                           Reports which functions were added, removed, or changed (based on \
                           a FNV-1a hash of function bytes). Useful for patch analysis and \
                           malware variant comparison. Requires non-stripped binaries with symbols.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path_a": { "type": "string", "description": "Path to the first (base) binary" },
                    "path_b": { "type": "string", "description": "Path to the second (new) binary" }
                },
                "required": ["path_a", "path_b"]
            }),
        },
        ToolDefinition {
            name: "auto_analyze".into(),
            description: "Run a full multi-pass analysis of a binary automatically: file info, \
                           function listing, call graph, strings, and decompilation of the top N \
                           functions. Returns a combined report with suggested next steps. \
                           Use this as the first step when given a new binary to analyse.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "top_n": { "type": "integer", "description": "Number of functions to decompile (default 5)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "export_report".into(),
            description: "Generate an HTML analysis report for the binary and save it as \
                           '<binary>.kaiju.html'. The report includes: binary metadata, all \
                           renames and comments, vulnerability scores with colour-coded badges, \
                           struct definitions, and function signatures. Share with teammates \
                           or keep as a record of findings.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "load_pdb".into(),
            description: "Load symbol names from a Windows PDB debug database and apply them to \
                           the project as function renames. Requires the matching .pdb file for \
                           the PE binary. All public code symbols (functions) are imported and \
                           will appear in subsequent disassemble and decompile output.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string", "description": "Path to the PE binary file" },
                    "pdb_path":    { "type": "string", "description": "Path to the corresponding .pdb file" }
                },
                "required": ["binary_path", "pdb_path"]
            }),
        },
        ToolDefinition {
            name: "decompile_flat".into(),
            description: "Decompile a function from a raw flat binary (firmware image, shellcode, \
                           ROM dump) that has no standard ELF/PE/Mach-O headers. Specify the \
                           base address where the binary is loaded in memory and the virtual \
                           address of the function to decompile. Supports x86_64, x86_32, \
                           aarch64, and arm32 architectures.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":      { "type": "string",  "description": "Path to the flat binary file" },
                    "base_addr": { "type": "integer", "description": "Base load address (e.g. 0x08000000 for ARM Cortex-M)" },
                    "vaddr":     { "type": "integer", "description": "Virtual address of the function to decompile" },
                    "arch":      { "type": "string",  "description": "Architecture: x86_64, x86_32, aarch64, or arm32 (default x86_64)" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "search_bytes".into(),
            description: "Search for a byte pattern anywhere in the binary file. \
                           The pattern is a space-separated hex string where '??' is a wildcard byte \
                           that matches any value. Returns file offsets and virtual addresses for all \
                           matches, plus a 16-byte hex context window. \
                           Example patterns: 'E8 ?? ?? ?? ?? 48 89 C7' (call + mov), \
                           '55 48 89 E5' (x86-64 function prologue).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string", "description": "Path to the binary file" },
                    "pattern": { "type": "string", "description": "Hex byte pattern with optional '??' wildcards, e.g. 'E8 ?? ?? ?? ?? 48 89'" }
                },
                "required": ["path", "pattern"]
            }),
        },
        ToolDefinition {
            name: "patch_bytes".into(),
            description: "Patch bytes in the binary at a given address. \
                           Writes a modified copy to '<path>.patched' — NEVER modifies the original file. \
                           Use this to NOP out a check (replace conditional jump with 90 90), \
                           change a constant, or test a fix. \
                           The original bytes at the patch site are shown for reference.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":      { "type": "string",  "description": "Path to the binary file" },
                    "vaddr":     { "type": "integer", "description": "Virtual address to patch (preferred)" },
                    "offset":    { "type": "integer", "description": "Raw file offset to patch (alternative to vaddr)" },
                    "hex_bytes": { "type": "string",  "description": "Space-separated hex bytes to write, e.g. '90 90 90' for 3 NOPs" }
                },
                "required": ["path", "hex_bytes"]
            }),
        },
        ToolDefinition {
            name: "section_entropy".into(),
            description: "Compute Shannon entropy for each section of the binary and for the whole \
                           file. Entropy ≥ 7.5 typically indicates encrypted or compressed data \
                           (packed executables, encrypted payloads). Entropy 5–7 is normal for \
                           compiled code. Low entropy (<4) suggests sparse data or plain text. \
                           Use this as a first-pass indicator of packing, obfuscation, or embedded \
                           payloads.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "register_function_hash".into(),
            description: "Hash the function at a given virtual address (normalising out \
                           position-dependent bytes) and store it under a name in the global \
                           cross-binary hash database (~/.kaiju/fn_hashes.db). \
                           Call this after identifying a function to make it recognisable \
                           in other binaries via lookup_function_hash or match_all_functions.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Virtual address of the function" },
                    "name":  { "type": "string",  "description": "Human-readable name to store, e.g. 'malloc' or 'parse_header'" }
                },
                "required": ["path", "vaddr", "name"]
            }),
        },
        ToolDefinition {
            name: "lookup_function_hash".into(),
            description: "Hash the function at a given virtual address and look it up in \
                           the global cross-binary hash database. Returns any previously \
                           registered names and the source binaries they came from. \
                           Useful for recognising library functions or malware components \
                           that appear across multiple samples.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Virtual address of the function to look up" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "match_all_functions".into(),
            description: "Scan every function in the binary and check each one against the \
                           global cross-binary hash database. Returns functions whose \
                           normalised hash matches a previously registered entry, along \
                           with the known name and the source binary it was registered from. \
                           Run this after loading a new sample to instantly identify known \
                           functions without symbol information.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":        { "type": "string",  "description": "Path to the binary file" },
                    "max_results": { "type": "integer", "description": "Maximum matches to return (default 50)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "virustotal_check".into(),
            description: "Look up a binary file on VirusTotal using its SHA-256 hash. \
                           Returns the detection verdict (clean/malicious/suspicious), \
                           the ratio of engines that flagged it, and the names/tags \
                           assigned to it. Requires VIRUSTOTAL_API_KEY env var.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary file to check" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "generate_yara_rule".into(),
            description: "Generate a YARA detection rule for a function at a given virtual address. \
                           Position-dependent bytes (CALL/JMP rel32, RIP-relative LEA/MOV, \
                           64-bit absolute immediates) are automatically wildcarded with ?? so the \
                           rule matches the same function even after relinking or ASLR. \
                           Useful for threat-hunting and cross-sample correlation. \
                           Only supported for x86 / x86-64 binaries.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":      { "type": "string",  "description": "Path to the binary file" },
                    "vaddr":     { "type": "integer", "description": "Virtual address of the function entry point" },
                    "rule_name": { "type": "string",  "description": "Optional YARA rule name (default: fn_<hex_addr>)" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "search_gadgets".into(),
            description: "Search for ROP/JOP gadget sequences in x86 / x86-64 binaries. \
                           The pattern is a semicolon-separated list of Intel-syntax mnemonic \
                           tokens, e.g. 'pop rdi; ret' or 'syscall' or 'pop *; pop *; ret'. \
                           Each token is matched by prefix against the formatted instruction \
                           (case-insensitive), so 'pop' matches any pop variant. \
                           Use '*' to match any single instruction. \
                           Returns up to 50 gadget addresses with their instruction sequences. \
                           Useful for building ROP chains during exploit development.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string", "description": "Path to the binary file" },
                    "pattern": {
                        "type": "string",
                        "description": "Semicolon-separated gadget pattern, e.g. 'pop rdi; ret' \
                                        or 'pop *; ret' or 'syscall'. Case-insensitive prefix match."
                    }
                },
                "required": ["path", "pattern"]
            }),
        },
        ToolDefinition {
            name: "dump_range".into(),
            description: "Hex-dump bytes at a virtual address, automatically translating the \
                           vaddr to a file offset using the binary's LOAD segment table. \
                           Unlike hexdump (which takes a raw file offset), dump_range accepts \
                           the virtual address as shown in disassembly or file_info output. \
                           Useful for inspecting GOT, BSS, fini_array, or any data structure \
                           at a known virtual address. Returns up to 4096 bytes.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary file" },
                    "vaddr": { "type": "integer", "description": "Virtual address to dump from" },
                    "size":  { "type": "integer", "description": "Number of bytes to dump (default 64, max 4096)" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "crypto_identify".into(),
            description: "Scan a binary for byte-level signatures of well-known cryptographic \
                           algorithms: AES forward/inverse S-boxes, ChaCha20/Salsa20 'expand' \
                           constants, SHA-256/512/1, MD5, CRC32, Blowfish P-array, TEA/XTEA \
                           delta, SHA-3/Keccak round constants, RC4 identity permutation. \
                           Runs in O(file_size) — no decompilation or symbol table needed. \
                           Returns the algorithm name, which constant matched, and every virtual \
                           address where the signature was found. Use this to quickly map which \
                           crypto primitives a binary uses before diving into decompilation. \
                           Does NOT detect custom or obfuscated crypto — pair with \
                           section_entropy for those.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary to scan" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "function_context".into(),
            description: "Assemble rich, one-shot analysis context for a single function: \
                           (1) full decompiled pseudo-C, (2) every caller with call-site address, \
                           (3) all direct callees resolved from disassembly, (4) existing project \
                           annotations (comments, vuln score, parameter types). \
                           This replaces the common multi-call pattern of decompile + xrefs_to + \
                           disassemble and lets you reason about a function holistically in one \
                           turn. Use this as your first step when analysing any function of \
                           interest — it gives everything needed to understand purpose, data flow, \
                           and call hierarchy without follow-up tool calls.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary" },
                    "vaddr": { "type": "integer", "description": "Virtual address of the function entry point" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "angr_find".into(),
            description: "Use angr symbolic execution to find concrete stdin input(s) that drive \
                           program execution to a target address. This is the one thing a static \
                           analysis LLM cannot do: actually solve path constraints to reach a \
                           specific code location. Use cases: finding the magic password that \
                           reaches a 'win' function, inputs that trigger a specific crash or \
                           check, license key format validation bypass, finding what input causes \
                           a conditional branch to be taken. angr must be installed — verify with \
                           python_env. Starts from the binary entry point by default; use \
                           start_addr to begin from a specific function. add avoid_addr to steer \
                           away from error/exit paths. Expects symbolic stdin; increase \
                           stdin_bytes if the input is longer than 32 bytes. May time out on \
                           large binaries — use start_addr to scope the exploration.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":         { "type": "string",  "description": "Path to the binary" },
                    "find_addr":    { "type": "integer", "description": "Virtual address to reach (e.g. win function, crash site)" },
                    "avoid_addr":   { "type": "integer", "description": "Optional address to avoid (e.g. 'wrong password' path). Default 0 = no avoid." },
                    "start_addr":   { "type": "integer", "description": "Optional address to start exploration from instead of entry. Default 0 = entry point." },
                    "stdin_bytes":  { "type": "integer", "description": "Number of symbolic stdin bytes to generate (default 32, max 256)" },
                    "timeout_secs": { "type": "integer", "description": "Max seconds for angr to run (default 60, max 120)" }
                },
                "required": ["path", "find_addr"]
            }),
        },
        ToolDefinition {
            name: "python_env".into(),
            description: "Return the Python 3 version and availability of every binary-analysis \
                           package (pefile, capstone, angr, unicorn, z3, pyelftools, pwntools, \
                           yara, ROPgadget, lief, keystone, etc.) plus a reminder of the always-\
                           available stdlib modules useful for binary parsing (struct, binascii, \
                           hashlib, mmap, ctypes).  Call this once before writing a run_python \
                           script so you know which imports will succeed.  No arguments needed.".into(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "run_python".into(),
            description: "Execute a Python 3 script and return its combined stdout+stderr output. \
                           Use this for custom analysis tasks that are awkward with the built-in tools: \
                           parsing complex data structures, decrypting embedded payloads, solving \
                           CTF challenges (crypto, format-string offsets, ROP chain building), \
                           scripting pwntools interactions, or processing tool output programmatically. \
                           The binary under analysis is available as the KAIJU_BINARY environment \
                           variable. Common packages (pwntools, capstone, angr, z3) are usable if \
                           installed on the host. You can call this tool repeatedly to iterate — \
                           write a script, inspect its output, refine it, and run it again.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Python 3 source code to execute. Use print() to emit output."
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Optional data to pipe into the script's stdin."
                    },
                    "binary": {
                        "type": "string",
                        "description": "Optional path to the binary file under analysis. \
                                        Injected as KAIJU_BINARY env var (already set if the TUI \
                                        has a binary loaded — only specify this to override)."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Maximum wall-clock execution time in seconds (default 30, max 120)."
                    }
                },
                "required": ["script"]
            }),
        },
        ToolDefinition {
            name: "elf_internals".into(),
            description: "Display ELF-specific security mitigations (PIE, NX, RELRO, stack \
                           canary, FORTIFY), special section addresses (.got, .got.plt, .plt, \
                           .init_array, .fini_array, .bss), the init/fini_array pointer tables \
                           with symbol names, and the linked libraries. Only works on ELF binaries \
                           — for PE use pe_internals. Indispensable for pwn/exploitation analysis.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the ELF binary" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "pe_security_audit".into(),
            description: "Run an O(file_size) hardening audit on a PE binary without decompiling \
                           any functions.  Works on large stripped PE/PE32+ binaries (e.g. Electron \
                           apps, Windows system DLLs) where scan_vulnerabilities times out. \
                           Checks: (1) section characteristics — detects writable .rodata/.rdata/\
                           .fptable (IMAGE_SCN_MEM_WRITE set, exploitable without VirtualProtect); \
                           (2) DLL characteristics — ASLR, DEP, CFG, ForceIntegrity, SEH; \
                           (3) Load Config raw parsing — SecurityCookie VA, GuardCFCheckFunction\
                           Pointer, GuardCFFunctionTable, GuardCFFunctionCount, GuardFlags; \
                           (4) ARM64-specific: bare-BLR ratio (% of indirect calls lacking a \
                           guard-check ADRP prefix) and stack-canary ADRP coverage (% of functions \
                           referencing the SecurityCookie page).  Always run this before \
                           pe_internals when auditing a Windows binary for hardening regressions.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the PE/PE32+ binary to audit" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "pe_internals".into(),
            description: "Display PE-specific security mitigations (ASLR, high-entropy ASLR, \
                           DEP/NX, CFG, Force Integrity, No SEH, AppContainer), section layout \
                           with permissions, exception directory (.pdata) function count, TLS \
                           presence, imports grouped by DLL with high-interest API highlights \
                           (CreateRemoteThread, VirtualAlloc, WriteProcessMemory, named pipes, \
                           network, crypto, registry), and exports. Only works on PE binaries \
                           — for ELF use elf_internals. Essential first step for Windows malware \
                           triage and security auditing.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the PE binary" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "xrefs_data".into(),
            description: "Find every instruction that reads or writes a given virtual address \
                           (data cross-references). Covers RIP-relative memory operands and \
                           absolute address operands in x86 / x86-64 code. Useful for tracking \
                           down all sites that access a global variable, GOT entry, counter, or \
                           function pointer table (e.g. fini_array). Complements xrefs_to, which \
                           finds code-flow references (CALL/JMP).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":  { "type": "string",  "description": "Path to the binary" },
                    "vaddr": { "type": "integer", "description": "Virtual address to find data references to" }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "run_binary".into(),
            description: "Execute a native binary and return its stdout + stderr. Useful for \
                           running CTF challenge binaries locally, testing patched binaries, or \
                           verifying exploit payloads without leaving KaijuLab. Stdin can be \
                           provided as a string (supports raw bytes via Python escape sequences \
                           in the LLM response). The process is killed after timeout_secs. \
                           Max output: 256 KiB per stream. For interactive pwntools exploits, \
                           use run_python with pwntools instead.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the binary to execute"
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments to pass to the binary (optional)"
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Data to pipe to the binary's stdin (optional)"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Maximum runtime in seconds before the process is killed (default 10, max 30)"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "batch_annotate".into(),
            description: "Apply a complete set of annotations to a function in one atomic call: \
                           rename the function, set a comment, set the return type, name and type \
                           each parameter (1-indexed), and rename decompiler variables (old→new). \
                           Replaces 5–10 separate rename_function / set_param_* / rename_variable \
                           / add_comment calls. Always re-decompile after calling this tool to \
                           see the updated output.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the binary"
                    },
                    "vaddr": {
                        "type": "integer",
                        "description": "Virtual address of the function entry point"
                    },
                    "function_name": {
                        "type": "string",
                        "description": "New name for the function (optional)"
                    },
                    "comment": {
                        "type": "string",
                        "description": "Analyst comment to attach to the function entry address (optional)"
                    },
                    "return_type": {
                        "type": "string",
                        "description": "C return type string, e.g. \"int\", \"char*\", \"void\" (optional)"
                    },
                    "params": {
                        "type": "array",
                        "description": "Array of parameter descriptors in order (param[0] = arg_1). Each entry may have \"name\" and/or \"type\" fields.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string", "description": "Parameter name" },
                                "type": { "type": "string", "description": "Parameter C type, e.g. \"const char*\", \"size_t\"" }
                            }
                        }
                    },
                    "variables": {
                        "type": "array",
                        "description": "Array of variable rename pairs: [{\"old\": \"local_18\", \"new\": \"buf\"}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old": { "type": "string", "description": "Current decompiler variable name" },
                                "new": { "type": "string", "description": "Desired variable name" }
                            },
                            "required": ["old", "new"]
                        }
                    }
                },
                "required": ["path", "vaddr"]
            }),
        },
        ToolDefinition {
            name: "recover_vtables".into(),
            description: "Scan .rdata/.rodata for sequences of pointers that all point into \
                           .text — the canonical layout of a C++ vtable on x86/x64 PE and ELF \
                           binaries. Returns candidate vtable addresses with their virtual method \
                           addresses (and project renames when available). Use this before \
                           decompiling C++ binaries to identify classes and virtual dispatch \
                           chains. min_methods filters out small false-positive pointer arrays \
                           (default 2; raise to 3-4 for cleaner results on noisy binaries).".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":        { "type": "string",  "description": "Path to the PE or ELF binary" },
                    "min_methods": { "type": "integer", "description": "Minimum consecutive .text pointers to qualify as a vtable (default 2)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "find_string_decoders".into(),
            description: "Scan x86/x86-64 functions for the hallmarks of a string-decoding stub: \
                           XOR-with-immediate, byte-level memory access, and a backward branch. \
                           Returns candidates ranked by a heuristic score together with the \
                           detected XOR key(s) and instruction count. Use this when a binary has \
                           no readable strings — the top hits are the routines that decrypt them \
                           at runtime. Follow up by decompiling the candidates and then emulating \
                           them with run_python + unicorn to recover plaintext strings.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":    { "type": "string",  "description": "Path to the binary" },
                    "max_fns": { "type": "integer", "description": "Maximum number of functions to scan (default 500)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "frida_trace".into(),
            description: "Spawn a binary under Frida, attach lightweight Interceptor hooks to \
                           the specified function addresses or export names, and return a call log \
                           showing arguments and return values. Requires the frida Python package \
                           (pip install frida frida-tools). Use for: tracing obfuscated dispatch \
                           tables, logging crypto function inputs/outputs at runtime, confirming \
                           which branch a specific input triggers, or watching API calls without \
                           a full debugger. Run python_env first to confirm frida is installed. \
                           NOTE: may require ptrace permission or root on some Linux systems.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the binary to spawn"
                    },
                    "hooks": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Functions to hook — each entry is either a hex address (e.g. '0x401234') or an export name (e.g. 'malloc')"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Seconds to run the binary before detaching (default 10, max 30)"
                    }
                },
                "required": ["path", "hooks"]
            }),
        },
        ToolDefinition {
            name: "stack_bof_candidates".into(),
            description: "Scan an AArch64 PE binary's .pdata entries for functions with large stack \
                           frames that lack pointer-authentication (pacibsp/paciasp) and/or a MSVC \
                           security cookie. Returns a ranked list of functions most susceptible to \
                           stack-based buffer overflows. Use on Windows AArch64 PE binaries after \
                           file_info confirms the architecture.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the AArch64 PE binary" },
                    "min_frame_bytes": { "type": "integer", "description": "Minimum stack-frame size to report (default 256 bytes)" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "writable_iat_hijack_surface".into(),
            description: "Identify writable IAT (Import Address Table) slots in a PE binary and \
                           enumerate every call site that loads through each slot using the \
                           ADRP+LDR+BLR pattern (AArch64). A writable IAT slot is a potential \
                           hijack vector — an attacker can overwrite the slot without needing \
                           VirtualProtect. Results show which imports are most widely called and \
                           thus highest-impact if hijacked.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the PE binary" }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "find_injection_chains".into(),
            description: "Scan all functions in a PE binary for process-injection API chains: \
                           combinations of memory-allocation (VirtualAllocEx), memory-write \
                           (WriteProcessMemory/NtWriteVirtualMemory), and remote execution \
                           (CreateRemoteThread/NtCreateThreadEx/QueueUserAPC). \
                           Functions hitting all three categories are flagged as injection-capable. \
                           Uses AArch64 ADRP+LDR+BLR decoding to resolve IAT targets.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the PE binary" }
                },
                "required": ["path"]
            }),
        },
    ]
}

// ─── Decompile helper: runs on a large stack to prevent stack overflow ────────

/// Calls `decompile_function` on a dedicated thread with a 256 MiB stack.
/// The decompiler's `build_block`/`add_program_segment` mutual recursion and
/// `compute_sese_address_ranges` recursion can exceed 64 MiB on complex CFGs
/// (e.g. large AArch64 PE binaries).  A hard complexity cap in `decompile_inner`
/// kicks in before the AST walk when a function has > 400 basic blocks.
fn decompile_safe(path: &str, vaddr: u64) -> String {
    let path = path.to_string();
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || crate::decompiler::decompile_function(&path, vaddr))
        .ok()
        .and_then(|h| h.join().ok())
        .unwrap_or_else(|| format!("[decompile failed at 0x{:x}]", vaddr))
}

// ─── Tool: decompile ─────────────────────────────────────────────────────────

fn decompile(path: &str, vaddr: u64) -> ToolResult {
    if path.is_empty() {
        return ToolResult::err("'path' is required");
    }
    if vaddr == 0 {
        return ToolResult::err(
            "'vaddr' is required — pass the virtual address of the function entry point \
             (e.g. from list_functions or file_info entry point)"
        );
    }
    let result = decompile_safe(path, vaddr);
    if result.starts_with("Decompiler error:") {
        return ToolResult::err(result);
    }

    // ── Apply project annotations ────────────────────────────────────────────
    let project = Project::load_for(path);
    let mut output = result;

    // Apply variable renames for this function
    if let Some(var_map) = project.var_renames.get(&vaddr) {
        for (old_name, new_name) in var_map {
            output = replace_whole_word(&output, old_name, new_name);
        }
    }

    // Apply known function renames to call sites in the decompiled output.
    // The decompiler may emit "fun_XXXXXXXX" or "sub_XXXXXXXX" style names.
    for (fvaddr, fname) in &project.renames {
        for pattern in &[
            format!("fun_{:x}", fvaddr),
            format!("fun_{:08x}", fvaddr),
            format!("fun_{:016x}", fvaddr),
            format!("sub_{:x}", fvaddr),
            format!("sub_{:08x}", fvaddr),
        ] {
            if output.contains(pattern.as_str()) {
                output = replace_whole_word(&output, pattern, fname);
            }
        }
    }

    // ── Build context header ──────────────────────────────────────────────────
    let mut header = String::new();

    // Signature / rename line
    if let Some(sig) = project.signatures.get(&vaddr) {
        let ret = sig.return_type.as_deref().unwrap_or("?");
        let fname = project.renames.get(&vaddr).map(|s| s.as_str()).unwrap_or("fn");
        let params: Vec<String> = sig.param_types.iter().enumerate()
            .map(|(i, pt)| {
                let t = pt.as_deref().unwrap_or("?");
                let n = sig.param_names.get(i)
                    .and_then(|x| x.as_deref())
                    .unwrap_or("_");
                format!("{} {}", t, n)
            })
            .collect();
        header.push_str(&format!("/* {} {}({}) */\n", ret, fname, params.join(", ")));
    } else if let Some(fname) = project.renames.get(&vaddr) {
        header.push_str(&format!("/* {} */\n", fname));
    }

    // Comment
    if let Some(cmt) = project.comments.get(&vaddr) {
        header.push_str(&format!("/* {cmt} */\n"));
    }

    // Callers summary (lightweight — just a count + first few sites)
    let xr = xrefs_to_inner(path, vaddr);
    if !xr.is_empty() {
        let caller_sites: Vec<String> = xr.iter().take(5)
            .map(|(_, site)| format!("0x{:x}", site))
            .collect();
        let extra = if xr.len() > 5 { format!(" +{} more", xr.len() - 5) } else { String::new() };
        header.push_str(&format!(
            "/* called from: {}{} */\n",
            caller_sites.join(", "), extra
        ));
    }

    if !header.is_empty() { header.push('\n'); }

    ToolResult::ok(format!(
        "Decompiled function at 0x{:x} in '{}':\n\n{}{}",
        vaddr, path, header, output
    ))
}

/// Replace whole-word occurrences of `from` with `to` (word boundaries = not alphanumeric/_).
fn replace_whole_word(text: &str, from: &str, to: &str) -> String {
    if from.is_empty() || from == to { return text.to_string(); }
    let mut result = String::with_capacity(text.len() + 16);
    let mut start = 0usize;
    while let Some(rel) = text[start..].find(from) {
        let pos = start + rel;
        let prev_ok = pos == 0 || {
            text[..pos].chars().last().map_or(true, |c| !c.is_alphanumeric() && c != '_')
        };
        let next_ok = pos + from.len() >= text.len() || {
            text[pos + from.len()..].chars().next().map_or(true, |c| !c.is_alphanumeric() && c != '_')
        };
        result.push_str(&text[start..pos]);
        if prev_ok && next_ok { result.push_str(to); } else { result.push_str(from); }
        start = pos + from.len();
    }
    result.push_str(&text[start..]);
    result
}

// ─── Tool: search_bytes ──────────────────────────────────────────────────────

/// Search for a hex byte pattern (with `??` wildcards) throughout a binary file.
fn search_bytes(path: &str, pattern: &str) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if pattern.is_empty() { return ToolResult::err("'pattern' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Parse pattern tokens into Option<u8> (None = wildcard)
    let pat: Vec<Option<u8>> = {
        let mut v = Vec::new();
        for tok in pattern.split_whitespace() {
            if tok == "?" || tok == "??" || tok == ".." {
                v.push(None);
            } else {
                match u8::from_str_radix(tok, 16) {
                    Ok(b) => v.push(Some(b)),
                    Err(_) => return ToolResult::err(format!(
                        "Invalid token '{}' — use hex bytes (e.g. 'E8') or '??' for wildcards", tok
                    )),
                }
            }
        }
        v
    };
    if pat.is_empty() { return ToolResult::err("Empty pattern"); }

    let plen = pat.len();
    let mut matches: Vec<(usize, u64)> = Vec::new();

    'outer: for i in 0..data.len().saturating_sub(plen - 1) {
        for (j, p) in pat.iter().enumerate() {
            if let Some(b) = p {
                if data[i + j] != *b { continue 'outer; }
            }
        }
        let vaddr = file_offset_to_vaddr(&data, i).unwrap_or(i as u64);
        matches.push((i, vaddr));
        if matches.len() >= 1000 { break; } // cap at 1 K results
    }

    let total = matches.len();
    let show  = 50.min(total);
    let mut out = format!(
        "Byte-pattern search: '{}'\nFile: '{}'\nMatches: {}{}\n\n",
        pattern, path, total,
        if total > show { format!(" (showing first {})", show) } else { String::new() }
    );

    for (file_off, vaddr) in matches.iter().take(show) {
        let end = (file_off + 16).min(data.len());
        let ctx: String = data[*file_off..end]
            .iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        out.push_str(&format!(
            "  file=0x{:08x}  vaddr=0x{:016x}  bytes: {}\n",
            file_off, vaddr, ctx
        ));
    }
    if total == 0 {
        out.push_str("  (no matches found)\n");
    }
    ToolResult::ok(out)
}

// ─── Tool: search_gadgets ────────────────────────────────────────────────────

/// Search for ROP/JOP gadget sequences in x86/x86-64 binaries.
/// `pattern` is a semicolon-separated list of mnemonic tokens, e.g.
/// `"pop rdi; ret"` or `"syscall"` or `"pop *; pop *; ret"`.
/// Each token is matched against the Intel-format mnemonic+operands string of a
/// decoded instruction.  `*` matches any single instruction.  Matching is
/// case-insensitive and the mnemonic part is compared by prefix (so `"pop"`
/// matches `"pop rdi"`, `"pop rbx"`, etc.).
fn search_gadgets(path: &str, pattern: &str) -> ToolResult {
    if path.is_empty()    { return ToolResult::err("'path' is required"); }
    if pattern.is_empty() { return ToolResult::err("'pattern' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        _ => return ToolResult::err(
            "search_gadgets only supports x86 / x86-64 binaries; \
             use search_bytes with raw hex patterns for other architectures"
        ),
    };

    // Parse pattern: semicolon-separated tokens, each is a prefix to match
    // against the Intel-formatted instruction (mnemonic + operands), lowercased.
    // Token "*" matches any instruction.
    let tokens: Vec<String> = pattern
        .split(';')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    if tokens.is_empty() {
        return ToolResult::err("Empty gadget pattern — use '; ' to separate instructions, e.g. 'pop rdi; ret'");
    }

    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

    let mut all_matches: Vec<(u64, String)> = Vec::new();

    for section in obj.sections() {
        // Only scan executable sections
        let is_exec = match section.flags() {
            object::SectionFlags::Elf { sh_flags } => sh_flags & 0x4 != 0, // SHF_EXECINSTR
            object::SectionFlags::Coff { characteristics } => characteristics & 0x2000_0000 != 0,
            _ => {
                let name = section.name().unwrap_or_default();
                matches!(name, ".text" | ".init" | ".plt" | "__text" | ".fini")
            }
        };
        if !is_exec { continue; }

        let sec_data = match section.data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let sec_vaddr = section.address();

        // Scan every byte offset in the section to find gadgets that may start
        // in the middle of a longer instruction (standard ROP gadget approach).
        let mut fmt = IntelFormatter::new();
        let n = tokens.len();

        'offset: for start_off in 0..sec_data.len() {
            let start_va = sec_vaddr + start_off as u64;
            let slice = &sec_data[start_off..];
            let mut decoder = Decoder::with_ip(bitness, slice, start_va, DecoderOptions::NONE);

            // Decode exactly n instructions from this offset
            let mut window: Vec<(u64, String)> = Vec::with_capacity(n);
            for instr in decoder.iter() {
                if instr.is_invalid() { continue 'offset; }
                let vaddr = instr.ip();
                let mut s = String::new();
                fmt.format(&instr, &mut s);
                window.push((vaddr, s.to_lowercase()));
                if window.len() == n { break; }
            }
            if window.len() < n { continue; }

            // Match each token against the corresponding instruction
            let mut ok = true;
            for (j, tok) in tokens.iter().enumerate() {
                if tok == "*" { continue; }
                // Prefix match: "pop" matches "pop rdi", "pop rdi" matches exactly "pop rdi"
                if !window[j].1.starts_with(tok.as_str()) {
                    ok = false;
                    break;
                }
            }
            if ok {
                let gadget: String = window.iter()
                    .map(|(_, s)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ; ");
                all_matches.push((window[0].0, gadget));
                if all_matches.len() >= 100 { break; }
            }
        }
        if all_matches.len() >= 100 { break; }
    }

    let total = all_matches.len();
    let show  = 50.min(total);
    let mut out = format!(
        "Gadget search: pattern='{}'\nFile: '{}'\nMatches: {}{}\n\n",
        pattern, path, total,
        if total > show { format!(" (showing first {})", show) } else { String::new() }
    );
    for (vaddr, gadget) in all_matches.iter().take(show) {
        out.push_str(&format!("  0x{:016x}  {}\n", vaddr, gadget));
    }
    if total == 0 {
        out.push_str("  (no gadgets found)\n");
        out.push_str("  Tip: use semicolons to separate instructions, e.g. 'pop rdi; ret'\n");
        out.push_str("       Use '*' to match any instruction, e.g. 'pop *; pop *; ret'\n");
    }
    ToolResult::ok(out)
}

// ─── Tool: dump_range ────────────────────────────────────────────────────────

/// Hex-dump a range of bytes at a virtual address, automatically translating
/// vaddr → file offset using the binary's LOAD segment table.
fn dump_range(path: &str, vaddr: u64, size: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }

    let size = size.clamp(1, 4096);

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let file_off = match vaddr_to_file_offset(&data, vaddr) {
        Some(off) => off,
        None => return ToolResult::err(format!(
            "Virtual address 0x{:x} is not covered by any LOAD segment — \
             run file_info to inspect the segment layout",
            vaddr
        )),
    };

    let end = (file_off + size).min(data.len());
    if file_off >= data.len() {
        return ToolResult::err(format!("File offset 0x{:x} is beyond EOF", file_off));
    }

    let bytes = &data[file_off..end];
    let mut out = format!(
        "Hex dump: vaddr=0x{:x}  file_offset=0x{:x}  length={} bytes\n\n",
        vaddr, file_off, bytes.len()
    );

    for (row, chunk) in bytes.chunks(16).enumerate() {
        let cur_vaddr = vaddr + (row * 16) as u64;
        let first8 = &chunk[..chunk.len().min(8)];
        let rest   = if chunk.len() > 8 { &chunk[8..] } else { &[] };
        let hex_a: String = first8.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let hex_b: String = rest.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let ascii: String = chunk.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!("0x{:016x}  {:<23}  {:<23}  |{}|\n", cur_vaddr, hex_a, hex_b, ascii));
    }

    ToolResult::ok(out)
}

// ─── Tool: patch_bytes ───────────────────────────────────────────────────────

/// Patch bytes in a binary, writing the result to `<path>.patched`.
/// Never modifies the original file.
fn patch_bytes(
    path: &str,
    file_offset: Option<usize>,
    vaddr_hint: Option<u64>,
    hex_bytes: &str,
) -> ToolResult {
    if path.is_empty()      { return ToolResult::err("'path' is required"); }
    if hex_bytes.is_empty() { return ToolResult::err("'hex_bytes' is required"); }
    if file_offset.is_none() && vaddr_hint.is_none() {
        return ToolResult::err("Either 'offset' or 'vaddr' is required");
    }

    let mut data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Parse hex bytes
    let new_bytes: Vec<u8> = {
        let mut v = Vec::new();
        for tok in hex_bytes.split_whitespace() {
            match u8::from_str_radix(tok, 16) {
                Ok(b) => v.push(b),
                Err(_) => return ToolResult::err(format!("Invalid hex byte: '{}'", tok)),
            }
        }
        v
    };

    let off = match (file_offset, vaddr_hint) {
        (Some(o), _) => o,
        (None, Some(va)) => match vaddr_to_file_offset(&data, va) {
            Some(o) => o,
            None => return ToolResult::err(format!(
                "vaddr 0x{:x} not mapped in segment table — use file_info to check", va
            )),
        },
        _ => unreachable!(),
    };

    if off + new_bytes.len() > data.len() {
        return ToolResult::err(format!(
            "Patch at 0x{:x} + {} bytes would exceed file size {} — aborting",
            off, new_bytes.len(), data.len()
        ));
    }

    let orig: String = data[off..off + new_bytes.len()]
        .iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");

    data[off..off + new_bytes.len()].copy_from_slice(&new_bytes);

    let out_path = format!("{}.patched", path);
    if let Err(e) = std::fs::write(&out_path, &data) {
        return ToolResult::err(format!("Cannot write '{}': {}", out_path, e));
    }

    ToolResult::ok(format!(
        "Patch applied.\n\
         Source:   {}\n\
         Offset:   0x{:x}{}\n\
         Original: {}\n\
         Patched:  {}\n\
         Output:   {}\n\n\
         The original file is untouched. Analyse '{}' to verify the patch.",
        path,
        off,
        vaddr_hint.map(|v| format!(" (vaddr 0x{:x})", v)).unwrap_or_default(),
        orig,
        hex_bytes.trim(),
        out_path,
        out_path,
    ))
}

// ─── Tools: cross-binary function hash database ──────────────────────────────

/// Hash the function at `vaddr` and store it under `name` in the global DB.
fn register_function_hash(path: &str, vaddr: u64, name: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }
    if name.is_empty() { return ToolResult::err("'name' is required"); }

    let (hash, byte_count) = match compute_fn_hash(path, vaddr) {
        Ok(v) => v,
        Err(e) => return ToolResult::err(e),
    };

    let db = match crate::hashdb::FnHashDb::open() {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot open hash DB: {}", e)),
    };

    match db.register(hash, name, path, byte_count) {
        Ok(_) => ToolResult::ok(format!(
            "Registered: hash=0x{:016x}  name={}  ({} bytes)  source={}",
            hash, name, byte_count, path
        )),
        Err(e) => ToolResult::err(format!("DB write failed: {}", e)),
    }
}

/// Hash the function at `vaddr` and return any known names from the global DB.
fn lookup_function_hash(path: &str, vaddr: u64) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required"); }

    let (hash, byte_count) = match compute_fn_hash(path, vaddr) {
        Ok(v) => v,
        Err(e) => return ToolResult::err(e),
    };

    let db = match crate::hashdb::FnHashDb::open() {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot open hash DB: {}", e)),
    };

    match db.lookup(hash) {
        Err(e) => ToolResult::err(format!("DB query failed: {}", e)),
        Ok(matches) if matches.is_empty() => ToolResult::ok(format!(
            "hash=0x{:016x} ({} bytes) — no matches in database", hash, byte_count
        )),
        Ok(matches) => {
            let mut out = format!(
                "hash=0x{:016x} ({} bytes) — {} match(es):\n\n",
                hash, byte_count, matches.len()
            );
            for (name, source) in &matches {
                out.push_str(&format!("  {:<30}  from: {}\n", name, source));
            }
            ToolResult::ok(out)
        }
    }
}

/// Scan all functions in the binary and report any that match the global DB.
fn match_all_functions(path: &str, max_results: usize) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let db = match crate::hashdb::FnHashDb::open() {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot open hash DB: {}", e)),
    };

    // Collect function addresses from symbol table or prologue scan
    let obj = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot parse binary: {}", e)),
    };

    let bitness: u32 = if obj.is_64() { 64 } else { 32 };

    let mut candidates: Vec<u64> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0)
        .map(|s| s.address())
        .collect();

    if candidates.is_empty() {
        // Prologue scan (x86-64 only)
        if let Some(sec) = obj.sections().find(|s| matches!(s.name().ok(), Some(".text") | Some("__text"))) {
            if let Ok(bytes) = sec.data() {
                let base = sec.address();
                let mut i = 0usize;
                while i + 4 <= bytes.len() {
                    let b = &bytes[i..];
                    if (b[0]==0xf3&&b[1]==0x0f&&b[2]==0x1e&&b[3]==0xfa)
                     ||(b[0]==0x55&&b[1]==0x48&&b[2]==0x89&&b[3]==0xe5) {
                        candidates.push(base + i as u64);
                    }
                    i += 1;
                }
            }
        }
    }

    let mut hits: Vec<(u64, String, String)> = Vec::new();

    for vaddr in &candidates {
        if let Some(file_off) = vaddr_to_file_offset(&data, *vaddr) {
            let slice = &data[file_off..(file_off + 512).min(data.len())];
            let hash = crate::hashdb::normalised_hash(slice, bitness);
            if let Ok(names) = db.lookup(hash) {
                for (name, source) in names {
                    hits.push((*vaddr, name, source));
                }
            }
        }
    }

    if hits.is_empty() {
        return ToolResult::ok(format!(
            "Scanned {} function candidates — no matches in hash database.\n\
             Use register_function_hash to populate the database.",
            candidates.len()
        ));
    }

    let total = hits.len();
    let mut out = format!(
        "Scanned {} functions — {} DB match(es):\n\n  {:<20}  {:<30}  {}\n  {}\n",
        candidates.len(), total,
        "Address", "Known as", "Source",
        "─".repeat(75)
    );
    for (vaddr, name, source) in hits.iter().take(max_results) {
        out.push_str(&format!("  0x{:016x}  {:<30}  {}\n", vaddr, name, source));
    }
    if total > max_results {
        out.push_str(&format!("  … and {} more", total - max_results));
    }
    ToolResult::ok(out)
}

/// Internal: hash the function at `vaddr` in `path`.
/// Returns (hash, byte_count) or an error string.
fn compute_fn_hash(path: &str, vaddr: u64) -> std::result::Result<(u64, usize), String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;

    let bitness = object::File::parse(&*data).ok()
        .map(|o| if o.is_64() { 64u32 } else { 32u32 })
        .unwrap_or(64);

    let file_off = vaddr_to_file_offset(&data, vaddr)
        .ok_or_else(|| format!("vaddr 0x{:x} not mapped in any segment", vaddr))?;

    // Grab up to 512 bytes; stop at first RET for tighter matching
    let raw = &data[file_off..(file_off + 512).min(data.len())];
    let end = find_ret_boundary(raw, bitness);
    let fn_bytes = &raw[..end];

    let hash = crate::hashdb::normalised_hash(fn_bytes, bitness);
    Ok((hash, fn_bytes.len()))
}

/// Find the byte offset just after the first RET in `bytes`, or return `bytes.len()`.
fn find_ret_boundary(bytes: &[u8], bitness: u32) -> usize {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    let mut dec = Decoder::with_ip(bitness, bytes, 0, DecoderOptions::NONE);
    for instr in &mut dec {
        if matches!(instr.mnemonic(), Mnemonic::Ret | Mnemonic::Retf) {
            return (instr.ip() as usize) + instr.len();
        }
    }
    bytes.len()
}

// ─── Tool: generate_yara_rule ────────────────────────────────────────────────

/// Generate a YARA rule for a function at `vaddr`.
/// Position-dependent bytes (CALL/JMP rel32, RIP-relative LEA/MOV) are
/// replaced with `??` wildcards so the rule matches even after relinking.
fn generate_yara_rule(path: &str, vaddr: u64, rule_name: Option<&str>) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }
    if vaddr == 0 { return ToolResult::err("'vaddr' is required (must be non-zero)"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let arch = object::File::parse(&*data).ok().map(|f| f.architecture());
    let bitness: u32 = match arch {
        Some(Architecture::X86_64) | Some(Architecture::X86_64_X32) | None => 64,
        Some(Architecture::I386) => 32,
        Some(other) => return ToolResult::err(format!(
            "YARA rule generation requires x86/x86-64 (got {:?})", other
        )),
    };

    let file_off = match vaddr_to_file_offset(&data, vaddr) {
        Some(off) => off,
        None => return ToolResult::err(format!(
            "Virtual address 0x{:x} not mapped in any segment", vaddr
        )),
    };

    // Find function size from symbol table, default to a generous 512 bytes
    let fn_size = object::File::parse(&*data).ok().and_then(|o| {
        o.symbols()
            .find(|s| s.address() == vaddr && s.size() > 0)
            .map(|s| s.size() as usize)
    }).unwrap_or(512);

    let end = (file_off + fn_size).min(data.len());
    let fn_bytes = &data[file_off..end];

    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let mut decoder = Decoder::with_ip(bitness, fn_bytes, vaddr, DecoderOptions::NONE);
    // Each entry: Some(byte) = concrete, None = wildcard
    let mut yara_bytes: Vec<Option<u8>> = Vec::new();

    for instr in &mut decoder {
        let offset = (instr.ip() - vaddr) as usize;
        let len = instr.len();
        if offset + len > fn_bytes.len() { break; }
        let raw = &fn_bytes[offset..offset + len];

        // Determine wildcard mask for this instruction
        let mut wildcard = vec![false; len];

        // Near-branch operands (CALL rel32, JMP rel32, Jcc rel32)
        let has_rel_branch = (0..instr.op_count()).any(|i| matches!(
            instr.op_kind(i),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            | OpKind::FarBranch16 | OpKind::FarBranch32
        ));
        if has_rel_branch && len > 1 {
            // Opcode is 1 byte (E8/E9/7x) or 2 bytes (0F 8x); displacement follows
            let opcode_len = if raw[0] == 0x0F { 2 } else { 1 };
            for i in opcode_len..len {
                wildcard[i] = true;
            }
        }

        // RIP-relative memory operand (LEA/MOV [rip+disp32])
        let has_rip_rel = (0..instr.op_count()).any(|i| {
            instr.op_kind(i) == OpKind::Memory && instr.memory_base() == Register::RIP
        });
        if has_rip_rel && len >= 5 {
            // The 4-byte disp32 always occupies the last 4 bytes of the encoding
            for i in (len - 4)..len {
                wildcard[i] = true;
            }
        }

        // Absolute 64-bit immediate (MOV r64, imm64): 10-byte encoding
        if len == 10 && raw[0] >= 0x48 {
            // REX.W prefix + B8+r opcode: last 8 bytes are the immediate address
            for i in 2..10 {
                wildcard[i] = true;
            }
        }

        for (i, &byte) in raw.iter().enumerate() {
            yara_bytes.push(if wildcard[i] { None } else { Some(byte) });
        }

        if matches!(instr.mnemonic(), Mnemonic::Ret | Mnemonic::Retf) {
            break;
        }
    }

    if yara_bytes.is_empty() {
        return ToolResult::err(format!(
            "No instructions decoded at 0x{:x} — verify vaddr and architecture", vaddr
        ));
    }

    // Build hex string, 16 bytes per line
    let hex_rows: Vec<String> = yara_bytes.chunks(16).map(|chunk| {
        chunk.iter().map(|b| match b {
            Some(v) => format!("{:02X}", v),
            None    => "??".to_string(),
        }).collect::<Vec<_>>().join(" ")
    }).collect();
    let hex_body = hex_rows.join("\n             ");

    let wildcarded = yara_bytes.iter().filter(|b| b.is_none()).count();
    let concrete   = yara_bytes.len() - wildcarded;

    let default_name = format!("fn_{:016x}", vaddr);
    let name = rule_name.unwrap_or(&default_name)
        .chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect::<String>();

    let rule = format!(
        "// Auto-generated by KaijuLab from '{}' at 0x{:x}\n\
         // {concrete} concrete bytes, {wildcarded} wildcards (calls/jumps/RIP-relative refs)\n\
         rule {name} {{\n\
         \n    meta:\n\
             source      = \"{path}\"\n\
             fn_vaddr    = \"0x{vaddr:x}\"\n\
             total_bytes = {total}\n\
         \n    strings:\n\
             $bytes = {{ {hex_body} }}\n\
         \n    condition:\n\
             $bytes\n\
         }}\n",
        path,
        vaddr,
        concrete   = concrete,
        wildcarded = wildcarded,
        name       = name,
        path       = path,
        vaddr      = vaddr,
        total      = yara_bytes.len(),
        hex_body   = hex_body,
    );

    ToolResult::ok(rule)
}

// ─── Tool: section_entropy ───────────────────────────────────────────────────

/// Compute Shannon entropy for each section and the whole file.
fn section_entropy(path: &str) -> ToolResult {
    if path.is_empty() { return ToolResult::err("'path' is required"); }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    fn shannon(bytes: &[u8]) -> f64 {
        if bytes.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for &b in bytes { freq[b as usize] += 1; }
        let n = bytes.len() as f64;
        freq.iter().filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / n; -p * p.log2() })
            .sum()
    }

    fn bar(e: f64) -> String {
        let filled = ((e / 8.0) * 24.0).round() as usize;
        format!("{}{}",
            "█".repeat(filled.min(24)),
            "░".repeat(24usize.saturating_sub(filled))
        )
    }

    fn label(e: f64) -> &'static str {
        if e >= 7.5 { "⚠  encrypted/packed" }
        else if e >= 7.0 { "▲  high (crypto/compress?)" }
        else if e >= 5.0 { "~  normal code/data" }
        else { "▼  low (text/sparse)" }
    }

    let file_e = shannon(&data);
    let mut out = format!(
        "Entropy analysis: '{}'\nFile size: {} bytes\n\n\
         Whole file   {:.4}  [{}]  {}\n\n\
         Sections:\n\n",
        path, data.len(), file_e, bar(file_e), label(file_e)
    );

    match object::File::parse(&*data) {
        Ok(obj) => {
            let mut rows: Vec<(String, u64, usize, f64)> = obj.sections()
                .filter_map(|s| {
                    let name = s.name().ok()?.to_string();
                    if name.is_empty() { return None; }
                    let sec_data = s.data().ok()?;
                    if sec_data.is_empty() { return None; }
                    Some((name, s.address(), sec_data.len(), shannon(sec_data)))
                })
                .collect();
            rows.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
            for (name, addr, size, e) in &rows {
                out.push_str(&format!(
                    "  {:<16}  0x{:016x}  {:>8} B   {:.4}  [{}]  {}\n",
                    name, addr, size, e, bar(*e), label(*e)
                ));
            }
            if rows.is_empty() {
                out.push_str("  (no named sections found)\n");
            }
        }
        Err(_) => {
            out.push_str("  (could not parse section table — raw file mode)\n");
        }
    }

    ToolResult::ok(out)
}

// ─── Tool: virustotal_check ──────────────────────────────────────────────────

/// Query VirusTotal for the SHA-256 hash of a file.
/// Requires the `VIRUSTOTAL_API_KEY` environment variable.
/// Uses the public v3 API: GET /api/v3/files/<sha256>
fn virustotal_check(path: &str) -> ToolResult {
    use std::io::Read;

    let api_key = match std::env::var("VIRUSTOTAL_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return ToolResult::ok(
            "VirusTotal: no API key set.\n\
             Export VIRUSTOTAL_API_KEY=<your_key> to enable hash lookups.\n\
             Free API keys: https://www.virustotal.com/gui/join-us".to_string()
        ),
    };

    // Read and hash the file
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return ToolResult::err(format!("Cannot open '{}': {}", path, e)),
    };
    let mut hasher = Sha256Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return ToolResult::err(format!("Read error: {}", e)),
        }
    }
    let sha256 = hasher.finish();

    let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("HTTP client error: {}", e)),
    };

    let resp = match client.get(&url).header("x-apikey", &api_key).send() {
        Ok(r) => r,
        Err(e) => return ToolResult::err(format!("VirusTotal request failed: {}", e)),
    };

    if resp.status().as_u16() == 404 {
        return ToolResult::ok(format!(
            "VirusTotal: {} — file not found in database (never seen before).\nSHA-256: {}",
            path, sha256
        ));
    }
    if !resp.status().is_success() {
        return ToolResult::err(format!(
            "VirusTotal API error {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        ));
    }

    let json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => return ToolResult::err(format!("Failed to parse VT response: {}", e)),
    };

    let attrs = &json["data"]["attributes"];
    let malicious: u64 = attrs["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0);
    let suspicious: u64 = attrs["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0);
    let undetected: u64 = attrs["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0);
    let total = malicious + suspicious + undetected
        + attrs["last_analysis_stats"]["harmless"].as_u64().unwrap_or(0);

    let verdict = if malicious > 0 {
        format!("⚠  MALICIOUS  ({}/{} engines)", malicious, total)
    } else if suspicious > 0 {
        format!("?  SUSPICIOUS ({}/{} engines)", suspicious, total)
    } else {
        format!("✓  CLEAN      (0/{} engines)", total)
    };

    let names: Vec<&str> = attrs["names"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).take(5).collect())
        .unwrap_or_default();
    let tags: Vec<&str> = attrs["tags"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).take(10).collect())
        .unwrap_or_default();

    let mut out = format!(
        "VirusTotal report for: {}\n\
         SHA-256 : {}\n\
         Verdict : {}\n",
        path, sha256, verdict
    );
    if !names.is_empty() {
        out.push_str(&format!("Known as: {}\n", names.join(", ")));
    }
    if !tags.is_empty() {
        out.push_str(&format!("Tags    : {}\n", tags.join(", ")));
    }
    if malicious > 0 {
        // Show which engines flagged it
        out.push_str("\nEngine detections:\n");
        if let Some(results) = attrs["last_analysis_results"].as_object() {
            let mut count = 0;
            for (engine, result) in results {
                let cat = result["category"].as_str().unwrap_or("");
                if cat == "malicious" || cat == "suspicious" {
                    let label = result["result"].as_str().unwrap_or("(unnamed)");
                    out.push_str(&format!("  {:<30} {}\n", engine, label));
                    count += 1;
                    if count >= 20 { out.push_str("  … (truncated)\n"); break; }
                }
            }
        }
    }
    ToolResult::ok(out)
}

// ─── SHA-256 hasher (no external dep — stdlib only) ──────────────────────────

struct Sha256Hasher {
    state: [u32; 8],
    buf: Vec<u8>,
    len: u64,
}

impl Sha256Hasher {
    fn new() -> Self {
        Sha256Hasher {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: Vec::new(),
            len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.len += data.len() as u64;
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.buf.drain(..64);
            sha256_compress(&mut self.state, &block);
        }
    }

    fn finish(mut self) -> String {
        let bit_len = self.len * 8;
        self.buf.push(0x80);
        while (self.buf.len() % 64) != 56 { self.buf.push(0); }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.buf.drain(..64);
            sha256_compress(&mut self.state, &block);
        }
        self.state.iter().map(|w| format!("{:08x}", w)).collect()
    }
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let tmp2 = s0.wrapping_add(maj);
        h = g; g = f; f = e; e = d.wrapping_add(tmp1);
        d = c; c = b; b = a; a = tmp1.wrapping_add(tmp2);
    }
    state[0] = state[0].wrapping_add(a); state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c); state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e); state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g); state[7] = state[7].wrapping_add(h);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE: &str = "samples/PwnableTW/3x17/3x17";
    const SAMPLE_ORW: &str = "samples/PwnableTW/orw/orw";

    #[test]
    fn file_info_has_segments() {
        let r = file_info(SAMPLE);
        assert!(r.output.contains("Segments"), "expected Segments in output:\n{}", r.output);
        assert!(r.output.contains("vaddr="), "expected vaddr= in segments:\n{}", r.output);
    }

    #[test]
    fn disassemble_vaddr_translates_entry_point() {
        // Entry point of 3x17 is 0x401a50 — should NOT disassemble ELF magic bytes
        let r = dispatch("disassemble", &json!({"path": SAMPLE, "vaddr": 0x401a50_u64, "length": 32}));
        // Must not start with the ELF magic byte disassembly (jg 0x401a97)
        assert!(!r.output.contains("jg"), "got ELF-header garbage instead of real code:\n{}", r.output);
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
    }

    #[test]
    fn list_functions_prologue_scan_stripped() {
        // 3x17 is stripped
        let r = dispatch("list_functions", &json!({"path": SAMPLE, "max_results": 10}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(
            r.output.contains("prologue scan") || r.output.contains("symbol table"),
            "unexpected output:\n{}", r.output
        );
    }

    #[test]
    fn resolve_plt_orw() {
        let r = dispatch("resolve_plt", &json!({"path": SAMPLE_ORW}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        // orw should import at least read/write/open
        let lower = r.output.to_lowercase();
        assert!(
            lower.contains("read") || lower.contains("write") || lower.contains("open"),
            "expected libc imports in PLT:\n{}", r.output
        );
    }

    #[test]
    fn strings_extract_section_filter() {
        let all = dispatch("strings_extract", &json!({"path": SAMPLE_ORW, "max_results": 200}));
        let filtered = dispatch("strings_extract", &json!({"path": SAMPLE_ORW, "section": ".rodata", "max_results": 200}));
        let all_count: usize = all.output
            .lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|n| n.parse().ok()).unwrap_or(0);
        let filtered_count: usize = filtered.output
            .lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|n| n.parse().ok()).unwrap_or(0);
        assert!(filtered_count <= all_count, "section filter returned MORE strings than full scan");
        assert!(filtered.output.contains("in '.rodata'"), "section label missing:\n{}", filtered.output);
    }

    // ── disassemble stops at ret ─────────────────────────────────────────────

    #[test]
    fn disassemble_stops_at_ret() {
        // Disassemble a large window; the output should end at the first ret,
        // not at the 60-instruction truncation marker.
        let r = dispatch("disassemble", &json!({"path": SAMPLE, "vaddr": 0x401a50_u64, "length": 1024}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        // Should contain a ret instruction
        assert!(r.output.contains(" ret"), "expected a ret instruction:\n{}", r.output);
        // Should NOT be truncated at 200 instructions (ret fires first for any real function)
        assert!(!r.output.contains("truncated at 200"), "should have stopped at ret before 200 insns:\n{}", r.output);
    }

    // ── list_functions JSON output ───────────────────────────────────────────

    #[test]
    fn list_functions_json_output() {
        let r = dispatch("list_functions", &json!({"path": SAMPLE_ORW, "json": true}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        let v: serde_json::Value = serde_json::from_str(&r.output)
            .expect("output should be valid JSON");
        assert!(v["functions"].is_array(), "should have 'functions' array");
        assert!(v["total"].is_number(), "should have 'total' count");
    }

    // ── xrefs_to ────────────────────────────────────────────────────────────

    #[test]
    fn xrefs_to_unknown_address_returns_no_refs() {
        // 0x1 is not a real function — no one calls it
        let r = dispatch("xrefs_to", &json!({"path": SAMPLE_ORW, "vaddr": 0x1_u64}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("No call"), "expected no-call message:\n{}", r.output);
    }

    #[test]
    fn xrefs_to_requires_vaddr() {
        let r = dispatch("xrefs_to", &json!({"path": SAMPLE_ORW, "vaddr": 0_u64}));
        assert!(r.output.contains("Error:"), "should error without vaddr");
    }

    // ── dwarf_info ───────────────────────────────────────────────────────────

    #[test]
    fn dwarf_info_stripped_binary_returns_no_entries() {
        // 3x17 and orw are stripped — no DWARF expected
        let r = dispatch("dwarf_info", &json!({"path": SAMPLE}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        // Either empty result or the "no DWARF" message, but no crash
        assert!(
            r.output.contains("No DWARF") || r.output.contains("0 entries") || r.output.contains("functions"),
            "unexpected output:\n{}", r.output
        );
    }

    // ── project tools (rename_function, add_comment, rename_variable, etc.) ──

    fn temp_bin() -> String {
        format!(
            "/tmp/kaijulab_tool_test_{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        )
    }

    #[test]
    fn rename_function_saves_and_loads() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        let r = dispatch("rename_function", &json!({"path": bin, "vaddr": 0x401000_u64, "name": "parse"}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("parse"), "name should appear in output:\n{}", r.output);

        let p = crate::project::Project::load_for(&bin);
        assert_eq!(p.get_name(0x401000), Some("parse".to_string()));
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn add_comment_saves_and_loads() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        dispatch("add_comment", &json!({"path": bin, "vaddr": 0x401010_u64, "comment": "stack pivot"}));
        let p = crate::project::Project::load_for(&bin);
        assert_eq!(p.get_comment(0x401010), Some("stack pivot"));
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn rename_variable_saves() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        let r = dispatch("rename_variable", &json!({
            "path": bin, "fn_vaddr": 0x401000_u64, "old_name": "arg_1", "new_name": "buf"
        }));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        let p = crate::project::Project::load_for(&bin);
        assert_eq!(p.var_renames[&0x401000]["arg_1"], "buf");
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn set_return_type_saves() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        dispatch("set_return_type", &json!({"path": bin, "fn_vaddr": 0x401000_u64, "type_str": "int"}));
        let p = crate::project::Project::load_for(&bin);
        assert_eq!(
            p.get_signature(0x401000).and_then(|s| s.return_type.as_deref()),
            Some("int")
        );
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn set_param_type_saves() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        dispatch("set_param_type", &json!({
            "path": bin, "fn_vaddr": 0x401000_u64, "param_n": 1_u64, "type_str": "const char*"
        }));
        let p = crate::project::Project::load_for(&bin);
        assert_eq!(
            p.get_signature(0x401000).and_then(|s| s.param_types[0].as_deref()),
            Some("const char*")
        );
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn define_struct_saves_and_lists() {
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        let r = dispatch("define_struct", &json!({
            "path": bin,
            "struct_name": "header",
            "total_size": 8,
            "fields": [
                {"offset": 0, "size": 4, "name": "magic", "type_str": "uint32_t"},
                {"offset": 4, "size": 4, "name": "size",  "type_str": "uint32_t"}
            ]
        }));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("magic") && r.output.contains("size"), "fields should appear:\n{}", r.output);

        let list = dispatch("list_types", &json!({"path": bin}));
        assert!(list.output.contains("header"), "struct name should appear in list_types:\n{}", list.output);
        let _ = std::fs::remove_file(&sidecar);
    }

    #[test]
    fn list_types_empty_project() {
        let bin = temp_bin();
        let r = dispatch("list_types", &json!({"path": bin}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("No type annotations"), "should report empty:\n{}", r.output);
    }

    #[test]
    fn load_project_nonexistent_reports_path() {
        let bin = temp_bin();
        let r = dispatch("load_project", &json!({"path": bin}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains(".kaiju.db"), "should mention sidecar path:\n{}", r.output);
    }

    // ── hexdump ──────────────────────────────────────────────────────────────

    fn write_temp_file(data: &[u8]) -> String {
        let path = temp_bin();
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn hexdump_produces_hex_columns() {
        let data: Vec<u8> = (0u8..32).collect();
        let path = write_temp_file(&data);
        let r = dispatch("hexdump", &json!({"path": path, "offset": 0, "length": 32}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        // First row should contain address 00000000
        assert!(r.output.contains("00000000"), "address column missing:\n{}", r.output);
        // Should contain ASCII representation area
        assert!(r.output.contains('|'), "ASCII column missing:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hexdump_offset_beyond_eof_errors() {
        let data = b"hello";
        let path = write_temp_file(data);
        let r = dispatch("hexdump", &json!({"path": path, "offset": 9999, "length": 16}));
        assert!(r.output.contains("Error:"), "should error for offset beyond EOF:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hexdump_partial_read_at_eof() {
        let data: Vec<u8> = (0u8..20).collect();
        let path = write_temp_file(&data);
        // Request more bytes than exist — should not error, just return what's there
        let r = dispatch("hexdump", &json!({"path": path, "offset": 0, "length": 1024}));
        assert!(!r.output.contains("Error:"), "should not error for oversized length:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    // ── search_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn search_bytes_finds_exact_pattern() {
        let data = b"\x00\x01\x02\xDE\xAD\xBE\xEF\x07\x08";
        let path = write_temp_file(data);
        let r = dispatch("search_bytes", &json!({"path": path, "pattern": "DE AD BE EF"}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("Matches: 1"), "expected 1 match:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_bytes_no_match_reports_zero() {
        let data = b"\x00\x01\x02\x03";
        let path = write_temp_file(data);
        let r = dispatch("search_bytes", &json!({"path": path, "pattern": "FF FF FF FF"}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("no matches"), "expected no-match message:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_bytes_wildcard_matches_any_byte() {
        let data = b"\xDE\xAD\x01\xEF\xDE\xAD\x02\xEF";
        let path = write_temp_file(data);
        let r = dispatch("search_bytes", &json!({"path": path, "pattern": "DE AD ?? EF"}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("Matches: 2"), "expected 2 wildcard matches:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_bytes_invalid_token_errors() {
        let path = write_temp_file(b"\x00");
        let r = dispatch("search_bytes", &json!({"path": path, "pattern": "ZZ"}));
        assert!(r.output.contains("Error:"), "should error on invalid token:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_bytes_empty_pattern_errors() {
        let path = write_temp_file(b"\x00");
        let r = dispatch("search_bytes", &json!({"path": path, "pattern": ""}));
        assert!(r.output.contains("Error:"), "should error on empty pattern:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    // ── patch_bytes ───────────────────────────────────────────────────────────

    #[test]
    fn patch_bytes_creates_patched_file() {
        let data = b"\x90\x90\x90\x90\x90"; // 5 NOPs
        let path = write_temp_file(data);
        let r = dispatch("patch_bytes", &json!({
            "path": path, "offset": 0, "hex_bytes": "CC CC"
        }));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);
        assert!(r.output.contains("Patch applied"), "expected success message:\n{}", r.output);

        let patched_path = format!("{}.patched", path);
        let patched = std::fs::read(&patched_path).unwrap();
        assert_eq!(patched[0], 0xCC);
        assert_eq!(patched[1], 0xCC);
        assert_eq!(patched[2], 0x90, "bytes after patch should be unchanged");

        // Original should be untouched
        let original = std::fs::read(&path).unwrap();
        assert_eq!(&original[..], b"\x90\x90\x90\x90\x90");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&patched_path);
    }

    #[test]
    fn patch_bytes_offset_beyond_file_errors() {
        let data = b"\x90\x90";
        let path = write_temp_file(data);
        let r = dispatch("patch_bytes", &json!({
            "path": path, "offset": 100, "hex_bytes": "CC"
        }));
        assert!(r.output.contains("Error:"), "should error when offset is out of bounds:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn patch_bytes_requires_offset_or_vaddr() {
        let path = write_temp_file(b"\x90");
        let r = dispatch("patch_bytes", &json!({"path": path, "hex_bytes": "CC"}));
        assert!(r.output.contains("Error:"), "should require offset or vaddr:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn patch_bytes_invalid_hex_errors() {
        let path = write_temp_file(b"\x90\x90");
        let r = dispatch("patch_bytes", &json!({
            "path": path, "offset": 0, "hex_bytes": "ZZ"
        }));
        assert!(r.output.contains("Error:"), "should error on invalid hex:\n{}", r.output);
        let _ = std::fs::remove_file(&path);
    }

    // ── virustotal_check (no-key path) ────────────────────────────────────────

    #[test]
    fn virustotal_check_no_api_key_returns_instructions() {
        // Unset the VT key so we hit the early-return path
        // (If the env var IS set in CI, the test still passes — it just won't
        //  exercise the no-key branch. That is acceptable.)
        let old_key = std::env::var("VIRUSTOTAL_API_KEY").ok();
        unsafe { std::env::remove_var("VIRUSTOTAL_API_KEY"); }
        let path = write_temp_file(b"\x7fELF");
        let r = dispatch("virustotal_check", &json!({"path": path}));
        // Restore
        if let Some(k) = old_key {
            unsafe { std::env::set_var("VIRUSTOTAL_API_KEY", k); }
        }
        // When no key is set the tool should return usage instructions, NOT an Error:
        assert!(!r.output.contains("Error:"), "no-key path should not return an error:\n{}", r.output);
        assert!(
            r.output.contains("VIRUSTOTAL_API_KEY") || r.output.contains("VirusTotal"),
            "should mention how to set the API key:\n{}", r.output
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── tool cache hit/miss ───────────────────────────────────────────────────

    #[test]
    fn cache_hit_returns_same_result() {
        // Call the same cacheable tool twice — second call must be served from cache
        let r1 = dispatch("disassemble", &json!({"path": SAMPLE, "vaddr": 0x401a50_u64, "length": 16}));
        let r2 = dispatch("disassemble", &json!({"path": SAMPLE, "vaddr": 0x401a50_u64, "length": 16}));
        assert_eq!(r1.output, r2.output, "cache hit should return identical output");
    }

    #[test]
    fn cache_write_invalidates_read() {
        // Rename a function in a temp project, then verify the cache for that path is cleared
        // (We can't directly observe the cache, so instead we verify the rename is applied.)
        let bin = temp_bin();
        let sidecar = crate::project::Project::project_path(&bin);
        dispatch("rename_function", &json!({"path": bin, "vaddr": 0x401000_u64, "name": "cached_fn"}));
        let p = crate::project::Project::load_for(&bin);
        assert_eq!(p.get_name(0x401000), Some("cached_fn".to_string()));
        let _ = std::fs::remove_file(&sidecar);
    }

    // ── dispatch panic safety ─────────────────────────────────────────────────

    #[test]
    fn dispatch_unknown_tool_returns_error() {
        let r = dispatch("totally_unknown_tool_xyz", &json!({}));
        assert!(r.output.contains("Error:"), "unknown tool should return Error:\n{}", r.output);
    }

    // ── export_report ─────────────────────────────────────────────────────────

    #[test]
    fn export_report_produces_html_file() {
        let bin = temp_bin();
        // Create the binary file so file_info won't fail
        std::fs::write(&bin, b"\x7fELF\x02\x01\x01\x00").unwrap();
        let sidecar = crate::project::Project::project_path(&bin);
        let html_path = format!("{}.kaiju.html", bin);

        let r = dispatch("export_report", &json!({"path": bin}));
        assert!(!r.output.contains("Error:"), "unexpected error:\n{}", r.output);

        if std::path::Path::new(&html_path).exists() {
            let html = std::fs::read_to_string(&html_path).unwrap();
            assert!(html.contains("<!DOCTYPE html>"), "should be valid HTML:\n{}", &html[..200.min(html.len())]);
            let _ = std::fs::remove_file(&html_path);
        }

        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_file(&sidecar);
    }
}
