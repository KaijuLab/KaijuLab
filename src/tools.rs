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
];

const WRITE_TOOLS: &[&str] = &[
    "rename_function", "add_comment", "set_vuln_score", "rename_variable",
    "set_return_type", "set_param_type", "set_param_name", "define_struct",
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

fn disassemble_capstone(
    data: &[u8],
    arch: Architecture,
    offset: Option<usize>,
    length: usize,
    vaddr_hint: Option<u64>,
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

    let mut out = format!(
        "Disassembly ({:?}, file_offset=0x{:x}, ip=0x{:x}):\n\n",
        arch, file_offset, ip
    );

    for insn in insns.as_ref() {
        let bytes: String = insn.bytes().iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!(
            "  {:016x}  {:<24}  {} {}\n",
            insn.address(),
            bytes,
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or(""),
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

    if !is_x86 {
        return disassemble_capstone(&data, obj_arch.unwrap(), offset, length, vaddr_hint);
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

    // If we have a vaddr and the binary has a symbol at that address, cap length to symbol size.
    let effective_length = if let Some(va) = vaddr_hint {
        if let Ok(obj) = object::File::parse(&*data) {
            obj.symbols()
                .find(|s| s.address() == va && s.size() > 0)
                .map(|s| (s.size() as usize).max(length))
                .unwrap_or(length)
        } else {
            length
        }
    } else {
        length
    };

    let end   = (file_offset + effective_length).min(data.len());
    let slice = &data[file_offset..end];
    let ip: u64 = vaddr_hint.unwrap_or(file_offset as u64);

    // Load project annotations (renames, comments) — optional, never fail
    let project = if !path.is_empty() { Some(Project::load_for(path)) } else { None };

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
                // Resolve branch / call targets to renamed names
                let op0_kind = if instr.op_count() > 0 { instr.op_kind(0) } else { OpKind::Register };
                if matches!(op0_kind,
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 |
                    OpKind::FarBranch16  | OpKind::FarBranch32
                ) {
                    let target = instr.near_branch_target();
                    if target != 0 {
                        if let Some(name) = p.renames.get(&target) {
                            annotation.push_str(&format!("  ; → <{}>", name));
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

    // ── Strategy 2: prologue scan (stripped binary) ─────────────────────────
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

// ─── Tool: xrefs_to ─────────────────────────────────────────────────────────

/// Find all call sites that target `target_vaddr` by scanning the .text section.
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

    // Only x86/x86-64 supported (iced-x86 is x86-only)
    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        other => return ToolResult::err(format!(
            "xrefs_to only supports x86/x86-64 (got {:?})", other
        )),
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
    let mut callers: Vec<u64> = Vec::new();

    for instr in &mut decoder {
        if matches!(instr.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
            // Direct near calls have a concrete target in near_branch64()
            let tgt = instr.near_branch64();
            if tgt == target_vaddr {
                callers.push(instr.ip());
            }
        }
    }

    if callers.is_empty() {
        return ToolResult::ok(format!(
            "No call/jmp to 0x{:x} found in .text", target_vaddr
        ));
    }

    // Annotate each caller with its enclosing function name if available
    let syms: Vec<(u64, u64, String)> = {
        let mut v: Vec<_> = obj
            .symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
            .map(|s| (s.address(), s.size(), s.name().unwrap_or("<?>").to_string()))
            .collect();
        v.sort_by_key(|(a, _, _)| *a);
        v
    };

    let find_func = |addr: u64| -> String {
        // Check project renames first
        let p = Project::load_for(path);
        if let Some(renamed) = p.get_name(addr) {
            return renamed;
        }
        for (fn_addr, fn_size, fn_name) in &syms {
            if addr >= *fn_addr && addr < fn_addr + fn_size {
                return fn_name.clone();
            }
        }
        "<unknown>".to_string()
    };

    let mut out = format!("Cross-references to 0x{:x} ({} callers):\n\n", target_vaddr, callers.len());
    out.push_str(&format!("  {:<20}  {}\n  {}\n", "Caller address", "Enclosing function", "─".repeat(55)));
    for addr in &callers {
        let fname = find_func(*addr);
        out.push_str(&format!("  0x{:016x}  {}\n", addr, fname));
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
    let proj_path = Project::project_path(path);
    if !proj_path.exists() {
        return ToolResult::ok(format!(
            "No project file found for '{}'\nWould be saved at: {}", path, proj_path.display()
        ));
    }
    let mut out = format!("Project: {}\n\n", proj_path.display());
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
    }
    ToolResult::ok(out)
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
    let mut out = format!(
        "PE imports ({} entries, image_base=0x{:016x}):\n\n  {:<20}  {:<30}  {}\n  {}\n",
        pe.imports.len(), image_base,
        "IAT address", "DLL", "Symbol",
        "─".repeat(72)
    );
    for imp in &pe.imports {
        let vaddr = image_base + imp.rva as u64;
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
    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        other => return ToolResult::err(format!(
            "call_graph only supports x86/x86-64 (got {:?})", other
        )),
    };

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

    // caller_fn → set of callee targets
    let mut edges: HashMap<u64, HashSet<u64>> = HashMap::new();

    // Symbol address → (addr, size) sorted list for caller lookup
    let mut sym_ranges: Vec<(u64, u64)> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
        .map(|s| (s.address(), s.size()))
        .collect();
    sym_ranges.sort_by_key(|(a, _)| *a);

    let find_fn = |addr: u64| -> u64 {
        // Binary search for the function containing addr
        for &(fn_addr, fn_size) in sym_ranges.iter().rev() {
            if addr >= fn_addr && addr < fn_addr + fn_size {
                return fn_addr;
            }
        }
        addr // treat as its own function if not found
    };

    for instr in &mut decoder {
        if matches!(instr.flow_control(), FlowControl::Call) {
            let tgt = instr.near_branch64();
            if tgt != 0 {
                let caller = find_fn(instr.ip());
                edges.entry(caller).or_default().insert(tgt);
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
    let bitness: u32 = match obj.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        other => return ToolResult::err(format!("cfg_view requires x86/x86-64 (got {:?})", other)),
    };

    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    struct Block { start: u64, end: u64, instr_count: usize, succs: Vec<u64> }

    let mut to_visit: Vec<u64> = vec![vaddr];
    let mut visited:  HashSet<u64> = HashSet::new();
    let mut blocks:   Vec<Block> = Vec::new();

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
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                    // continue block
                }
                FlowControl::UnconditionalBranch => {
                    let tgt = instr.near_branch64();
                    if tgt != 0 && visited.get(&tgt).is_none() {
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
                FlowControl::Return | FlowControl::Exception
                | FlowControl::XbeginXabortXend | FlowControl::IndirectBranch => { break; }
                _ => { break; }
            }
            if count >= 200 { break; } // guard against infinite loops
        }

        blocks.push(Block { start: addr, end: last_ip, instr_count: count, succs });
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

    // Collect function addresses (symbol table or prologue scan)
    let project = Project::load_for(path);
    let mut fn_addrs: Vec<(u64, String)> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0 && s.size() > 0)
        .map(|s| {
            let addr = s.address();
            let name = project.get_name(addr)
                .or_else(|| s.name().ok().map(|n| n.to_string()))
                .unwrap_or_else(|| format!("FUN_{:x}", addr));
            (addr, name)
        })
        .collect();
    fn_addrs.sort_by_key(|(a, _)| *a);
    fn_addrs.truncate(max_fns);

    if fn_addrs.is_empty() {
        return ToolResult::ok(
            "No functions found to scan. Run list_functions first to enumerate functions."
        );
    }

    // Dangerous function patterns to watch for
    const DANGEROUS: &[&str] = &[
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "fscanf",
        "sscanf", "memcpy", "memmove", "strncpy", "strncat", "snprintf",
        "printf", "fprintf", "system", "popen", "exec", "execve",
        "malloc", "free", "realloc",
    ];

    let mut out = format!(
        "Vulnerability scan for '{}' ({} functions).\n\
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
        path, fn_addrs.len(), "═".repeat(72)
    );

    for (vaddr, name) in &fn_addrs {
        out.push_str(&format!("\n── Function: {}  (0x{:x}) ──\n", name, vaddr));

        // Quick static check: scan disassembly for calls to dangerous functions
        let dis = crate::decompiler::decompile_function(path, *vaddr);
        let lower = dis.to_ascii_lowercase();
        let hits: Vec<&&str> = DANGEROUS.iter().filter(|&&d| lower.contains(d)).collect();
        if !hits.is_empty() {
            out.push_str(&format!(
                "  ⚠ Static flags: calls to [{}]\n",
                hits.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
            ));
        }
        out.push_str(&dis);
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

    let pseudo_c = crate::decompiler::decompile_function(path, vaddr);
    let project  = Project::load_for(path);
    let fn_name  = project.get_name(vaddr)
        .unwrap_or_else(|| format!("FUN_{:x}", vaddr));

    let out = format!(
        "Function '{}' at 0x{:x}:\n\n\
         {}\n\n\
         ─────────────────────────────────────────────────────────────────────\n\
         INSTRUCTION FOR MODEL:\n\
         Based on the decompiled pseudo-C above, provide:\n\
         1. A one-line summary of what this function does.\n\
         2. The likely purpose (e.g. parsing input, crypto routine, network send).\n\
         3. Notable patterns (loops, recursion, syscalls, dangerous operations).\n\
         4. Suggested rename for the function (if currently unnamed/generic).\n\
         5. Names for any parameters that can be inferred from usage.\n\
         Then call add_comment(path='{}', vaddr={}, comment='<your one-line summary>').\n\
         Then call rename_function(path='{}', vaddr={}, name='<suggested_name>') if appropriate.\n",
        fn_name, vaddr, pseudo_c, path, vaddr, path, vaddr
    );
    ToolResult::ok(out)
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
        let len = text_bytes.len();
        let mut i = 0;
        while i + 4 <= len {
            let b = &text_bytes[i..];
            if (b[0]==0xf3&&b[1]==0x0f&&b[2]==0x1e&&b[3]==0xfa)
               || (b[0]==0x55&&b[1]==0x48&&b[2]==0x89&&b[3]==0xe5)
            {
                candidates.push(text_vaddr + i as u64);
            }
            i += 1;
        }
    }

    for &fn_vaddr in &candidates {
        if let Some(file_off) = vaddr_to_file_offset(&data, fn_vaddr) {
            let fn_slice = &data[file_off..data.len().min(file_off + 32)];
            for &(name, pattern, len) in LIB_SIGS {
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

    let mut out = String::new();

    // 1. File info
    let info = file_info(path);
    out.push_str("═══ FILE INFO ═══\n");
    out.push_str(&info.output);
    out.push_str("\n\n");

    // 2. Function list
    let fns = list_functions(path, top_n, true);
    out.push_str(&format!("═══ FUNCTIONS (top {}) ═══\n", top_n));

    // Parse JSON to get vaddrs
    let fn_addrs: Vec<u64> = serde_json::from_str::<serde_json::Value>(&fns.output)
        .ok()
        .and_then(|v| v["functions"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|f| f["address"].as_u64())
        .collect();

    if fn_addrs.is_empty() {
        // Fallback: plain listing
        let plain = list_functions(path, top_n, false);
        out.push_str(&plain.output);
    } else {
        out.push_str(&fns.output);
    }
    out.push_str("\n\n");

    // 3. Call graph
    let cg = call_graph(path, 1);
    out.push_str("═══ CALL GRAPH ═══\n");
    out.push_str(&cg.output);
    out.push_str("\n\n");

    // 4. Strings (high-value section)
    let strs = strings_extract(path, 5, 30, Some(".rodata"));
    out.push_str("═══ STRINGS (.rodata) ═══\n");
    out.push_str(&strs.output);
    out.push_str("\n\n");

    // 5. Decompile top functions
    out.push_str("═══ DECOMPILED FUNCTIONS ═══\n");
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
        let decomp = crate::decompiler::decompile_function(path, *vaddr);
        out.push_str(&decomp);
        out.push('\n');
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
            description: "Disassemble x86/x86-64 machine code from a binary file. \
                           Pass `vaddr` (a virtual address, e.g. the entry point or a function address \
                           from file_info/list_functions) — the tool automatically translates it to a \
                           file offset using the LOAD segment table, no manual calculation needed. \
                           Alternatively pass `offset` for a raw file byte offset. \
                           If both are given, `offset` takes precedence.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path":   { "type": "string",  "description": "Path to the binary file" },
                    "vaddr":  { "type": "integer", "description": "Virtual address of first instruction (auto-translated to file offset)" },
                    "offset": { "type": "integer", "description": "Raw file byte offset (overrides vaddr)" },
                    "length": { "type": "integer", "description": "Number of bytes to disassemble (default 128)" }
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
    ]
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
    let result = crate::decompiler::decompile_function(path, vaddr);
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

    // Build signature comment header if we have one
    let mut header = String::new();
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
        header = format!("/* KaijuLab: {} {}({}) */\n\n", ret, fname, params.join(", "));
    } else if let Some(fname) = project.renames.get(&vaddr) {
        header = format!("/* KaijuLab: {} */\n\n", fname);
    }
    if let Some(cmt) = project.comments.get(&vaddr) {
        header.push_str(&format!("/* {} */\n\n", cmt));
    }

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
        assert!(r.output.contains(".kaiju.json"), "should mention sidecar path:\n{}", r.output);
    }
}
