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

// ─── Dispatcher ──────────────────────────────────────────────────────────────

pub fn dispatch(name: &str, args: &Value) -> ToolResult {
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

// ─── Tool: disassemble ───────────────────────────────────────────────────────

fn disassemble(path: &str, offset: Option<usize>, length: usize, vaddr_hint: Option<u64>) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let arch = object::File::parse(&*data).ok().map(|f| f.architecture());

    let bitness: u32 = match arch {
        Some(Architecture::X86_64) | Some(Architecture::X86_64_X32) => 64,
        Some(Architecture::I386) => 32,
        Some(other) => return ToolResult::err(format!(
            "Disassembly not supported for {:?} (only x86 / x86-64)", other
        )),
        None => 64,
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

    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic};

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
            out.push_str(&format!("  {:016x}  {:<24}  {}\n", instr.ip(), bytes, mnemonic));
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
    let text_sec = obj.sections().find(|s| s.name().ok() == Some(".text"));
    let (text_bytes, text_vaddr) = match text_sec {
        Some(s) => match s.data() {
            Ok(d)  => (d.to_vec(), s.address()),
            Err(e) => return ToolResult::err(format!("Cannot read .text: {}", e)),
        },
        None => return ToolResult::err(
            "No .text section and no symbols — cannot enumerate functions"
        ),
    };

    let is_64 = obj.is_64();
    let mut found: Vec<u64> = Vec::new();
    let len = text_bytes.len();

    // Common x86-64 prologues:
    //   endbr64          f3 0f 1e fa
    //   push rbp         55          (+ optional rex prefix before mov rbp,rsp)
    //   push rbp; mov rbp,rsp  55 48 89 e5
    // Common x86-32 prologue:
    //   push ebp; mov ebp,esp  55 89 e5
    let mut i = 0usize;
    while i + 4 <= len {
        let b = &text_bytes[i..];
        let hit = if is_64 {
            // endbr64
            (b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa)
            // push rbp; mov rbp,rsp
            || (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xe5)
        } else {
            // push ebp; mov ebp,esp
            b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xe5
        };
        if hit {
            found.push(text_vaddr + i as u64);
        }
        i += 1;
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
        ToolResult::err(result)
    } else {
        ToolResult::ok(format!(
            "Decompiled function at 0x{:x} in '{}':\n\n{}",
            vaddr, path, result
        ))
    }
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
