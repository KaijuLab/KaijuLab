use object::{Architecture, Object, ObjectSection};
use serde_json::{json, Value};

// ─── Tool result ─────────────────────────────────────────────────────────────

pub struct ToolResult {
    pub display: String,
    /// JSON payload sent back to the LLM as a functionResponse
    pub json: Value,
}

impl ToolResult {
    fn ok(output: impl Into<String>) -> Self {
        let s = output.into();
        ToolResult {
            json: json!({ "output": s }),
            display: s,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        let s = msg.into();
        ToolResult {
            json: json!({ "error": s }),
            display: format!("Error: {}", s),
        }
    }
}

// ─── Dispatcher ──────────────────────────────────────────────────────────────

pub fn dispatch(name: &str, args: &Value) -> ToolResult {
    match name {
        "file_info" => {
            let path = str_arg(args, "path");
            file_info(&path)
        }
        "hexdump" => {
            let path = str_arg(args, "path");
            let offset = args["offset"].as_u64().unwrap_or(0) as usize;
            let length = args["length"].as_u64().unwrap_or(256) as usize;
            hexdump(&path, offset, length)
        }
        "strings_extract" => {
            let path = str_arg(args, "path");
            let min_len = args["min_len"].as_u64().unwrap_or(4) as usize;
            let max_results = args["max_results"].as_u64().unwrap_or(60) as usize;
            strings_extract(&path, min_len, max_results)
        }
        "disassemble" => {
            let path = str_arg(args, "path");
            let offset = args["offset"].as_u64().unwrap_or(0) as usize;
            let length = args["length"].as_u64().unwrap_or(128) as usize;
            let vaddr = args["vaddr"].as_u64();
            disassemble(&path, offset, length, vaddr)
        }
        "read_section" => {
            let path = str_arg(args, "path");
            let section = str_arg(args, "section");
            read_section(&path, &section)
        }
        _ => ToolResult::err(format!("Unknown tool '{}'", name)),
    }
}

fn str_arg(args: &Value, key: &str) -> String {
    args[key].as_str().unwrap_or("").to_string()
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
                path,
                data.len(),
                e,
                magic
            ));
        }
    };

    let arch = format!("{:?}", obj.architecture());
    let fmt = format!("{:?}", obj.format());
    let bits = if obj.is_64() { "64-bit" } else { "32-bit" };
    let endian = if obj.is_little_endian() { "LE" } else { "BE" };

    let sections: Vec<String> = obj
        .sections()
        .filter_map(|s| {
            let name = s.name().ok()?;
            if name.is_empty() {
                return None;
            }
            Some(format!(
                "    {:<18} addr=0x{:016x}  size={}",
                name,
                s.address(),
                s.size()
            ))
        })
        .collect();

    let sym_count = obj.symbols().count();

    let mut out = format!(
        "File         : {}\nSize         : {} bytes\nFormat       : {}\nArchitecture : {} {} {}\nEntry point  : 0x{:016x}\nSections ({}):\n{}\nSymbols      : {}",
        path,
        data.len(),
        fmt,
        arch,
        bits,
        endian,
        obj.entry(),
        sections.len(),
        sections.join("\n"),
        sym_count,
    );

    // Show the first few imported symbols if available
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
        return ToolResult::err(format!(
            "Offset 0x{:x} is beyond file size {} bytes",
            offset,
            data.len()
        ));
    }

    let end = (offset + length).min(data.len());
    let bytes = &data[offset..end];
    let mut out = String::new();

    for (row, chunk) in bytes.chunks(16).enumerate() {
        let addr = offset + row * 16;

        let first8 = &chunk[..chunk.len().min(8)];
        let rest = if chunk.len() > 8 { &chunk[8..] } else { &[] };

        let hex_a: String = first8
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let hex_b: String = rest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();

        out.push_str(&format!(
            "{:08x}  {:<23}  {:<23}  |{}|\n",
            addr, hex_a, hex_b, ascii
        ));
    }

    if end < data.len() {
        out.push_str(&format!("({} more bytes)", data.len() - end));
    }

    ToolResult::ok(out)
}

// ─── Tool: strings_extract ───────────────────────────────────────────────────

fn strings_extract(path: &str, min_len: usize, max_results: usize) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    let mut results: Vec<(usize, String)> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut run_start = 0usize;

    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if run.is_empty() {
                run_start = i;
            }
            run.push(b);
        } else {
            if run.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&run) {
                    results.push((run_start, s.to_string()));
                }
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&run) {
            results.push((run_start, s.to_string()));
        }
    }

    let total = results.len();
    let mut out = format!("Found {} strings (min_len={})\n\n", total, min_len);
    for (offset, s) in results.iter().take(max_results) {
        out.push_str(&format!("  0x{:08x}  {}\n", offset, s));
    }
    if total > max_results {
        out.push_str(&format!("  … and {} more", total - max_results));
    }

    ToolResult::ok(out)
}

// ─── Tool: disassemble ───────────────────────────────────────────────────────

fn disassemble(path: &str, offset: usize, length: usize, vaddr_hint: Option<u64>) -> ToolResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return ToolResult::err(format!("Cannot read '{}': {}", path, e)),
    };

    // Determine architecture from the binary
    let arch = object::File::parse(&*data)
        .ok()
        .map(|f| f.architecture());

    let bitness: u32 = match arch {
        Some(Architecture::X86_64) | Some(Architecture::X86_64_X32) => 64,
        Some(Architecture::I386) => 32,
        Some(other) => {
            return ToolResult::err(format!(
                "Disassembly not supported for {:?} (only x86 / x86-64)",
                other
            ))
        }
        None => 64, // assume x86-64 if unrecognised
    };

    if offset >= data.len() {
        return ToolResult::err(format!(
            "Offset 0x{:x} is beyond file size {} bytes",
            offset,
            data.len()
        ));
    }

    let end = (offset + length).min(data.len());
    let slice = &data[offset..end];

    // Use provided vaddr or fall back to the file offset
    let ip: u64 = vaddr_hint.unwrap_or(offset as u64);

    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

    let mut decoder = Decoder::with_ip(bitness, slice, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_first_operand_char_index(10);

    let mut out = format!(
        "Disassembly ({}-bit, offset=0x{:x}, ip=0x{:x}):\n\n",
        bitness, offset, ip
    );
    let mut count = 0usize;

    for instr in &mut decoder {
        if instr.is_invalid() {
            out.push_str(&format!("  {:016x}  ?? (invalid)\n", instr.ip()));
        } else {
            // Collect byte representation
            let byte_start = (instr.ip() - ip) as usize;
            let byte_end = (byte_start + instr.len()).min(slice.len());
            let bytes: String = slice[byte_start..byte_end]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let mut mnemonic = String::new();
            formatter.format(&instr, &mut mnemonic);

            out.push_str(&format!(
                "  {:016x}  {:<24}  {}\n",
                instr.ip(),
                bytes,
                mnemonic
            ));
        }
        count += 1;
        if count >= 60 {
            out.push_str("\n  … truncated at 60 instructions");
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
        if section.name().ok() == Some(section_name) {
            let sec_data = match section.data() {
                Ok(d) => d,
                Err(e) => return ToolResult::err(format!("Cannot read section data: {}", e)),
            };

            let preview = sec_data.len().min(512);
            let mut out = format!(
                "Section  : {}\nAddress  : 0x{:016x}\nSize     : {} bytes\n\nHex dump (first {} bytes):\n\n",
                section_name,
                section.address(),
                sec_data.len(),
                preview
            );

            for (row, chunk) in sec_data[..preview].chunks(16).enumerate() {
                let addr = section.address() as usize + row * 16;
                let hex: String = chunk
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                out.push_str(&format!("{:08x}  {:<47}  |{}|\n", addr, hex, ascii));
            }

            if sec_data.len() > preview {
                out.push_str(&format!("… ({} bytes total)", sec_data.len()));
            }

            return ToolResult::ok(out);
        }
    }

    // List available sections to help the caller
    let available: Vec<String> = obj
        .sections()
        .filter_map(|s| s.name().ok().map(|n| n.to_string()))
        .filter(|n| !n.is_empty())
        .collect();
    ToolResult::err(format!(
        "Section '{}' not found. Available: {}",
        section_name,
        available.join(", ")
    ))
}

// ─── Function declarations for Gemini ────────────────────────────────────────

#[derive(serde::Serialize, Clone, Debug)]
pub struct FunctionDeclaration {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

pub fn all_declarations() -> Vec<FunctionDeclaration> {
    vec![
        FunctionDeclaration {
            name: "file_info".into(),
            description: "Parse a binary file and return its format, architecture, entry point, \
                           section table, symbol count, and imports. Use this first when analysing \
                           an unknown binary."
                .into(),
            parameters: json!({
                "type": "OBJECT",
                "properties": {
                    "path": {
                        "type": "STRING",
                        "description": "Absolute or relative path to the binary file"
                    }
                },
                "required": ["path"]
            }),
        },
        FunctionDeclaration {
            name: "hexdump".into(),
            description: "Display a hex+ASCII dump of raw bytes from a file.".into(),
            parameters: json!({
                "type": "OBJECT",
                "properties": {
                    "path": { "type": "STRING", "description": "Path to the binary file" },
                    "offset": { "type": "INTEGER", "description": "File offset to start from (default 0)" },
                    "length": { "type": "INTEGER", "description": "Number of bytes to show (default 256)" }
                },
                "required": ["path"]
            }),
        },
        FunctionDeclaration {
            name: "strings_extract".into(),
            description: "Extract printable ASCII strings from a binary file.".into(),
            parameters: json!({
                "type": "OBJECT",
                "properties": {
                    "path": { "type": "STRING", "description": "Path to the binary file" },
                    "min_len": { "type": "INTEGER", "description": "Minimum string length (default 4)" },
                    "max_results": { "type": "INTEGER", "description": "Maximum strings to return (default 60)" }
                },
                "required": ["path"]
            }),
        },
        FunctionDeclaration {
            name: "disassemble".into(),
            description: "Disassemble x86/x86-64 machine code from a file at a given file offset. \
                           Returns Intel-syntax assembly with byte encodings."
                .into(),
            parameters: json!({
                "type": "OBJECT",
                "properties": {
                    "path":   { "type": "STRING",  "description": "Path to the binary file" },
                    "offset": { "type": "INTEGER", "description": "File byte offset to start disassembling (default 0)" },
                    "length": { "type": "INTEGER", "description": "Number of bytes to disassemble (default 128)" },
                    "vaddr":  { "type": "INTEGER", "description": "Virtual address to use for the first instruction (optional; defaults to offset)" }
                },
                "required": ["path"]
            }),
        },
        FunctionDeclaration {
            name: "read_section".into(),
            description: "Read the raw contents of a named section (e.g. .text, .rodata) and \
                           display a hex dump."
                .into(),
            parameters: json!({
                "type": "OBJECT",
                "properties": {
                    "path":    { "type": "STRING", "description": "Path to the binary file" },
                    "section": { "type": "STRING", "description": "Section name, e.g. '.text'" }
                },
                "required": ["path", "section"]
            }),
        },
    ]
}
