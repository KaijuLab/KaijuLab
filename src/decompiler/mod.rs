/// Decompiler module — ported from Ouroboros (MIT/Apache-2.0)
///
/// Pipeline: binary bytes → SLEIGH PCode → BasicBlocks → HighFunction → AbstractSyntaxTree → text
pub mod ir;
pub mod memory;
pub mod symbol_resolver;

use std::borrow::Cow;

use goblin::Object;
use object::Object as _;
use ir::{
    abstract_syntax_tree::{AbstractSyntaxTree, AstStatement},
    address::Address,
    basic_block::{BlockSlot, DestinationKind},
    control_flow_graph::SingleEntrySingleExit,
    expression::{Expression, ExpressionOp, OpIdx, VariableSymbol},
    high_function::HighFunction,
};
use memory::{LiteralKind, LiteralState, Memory};

// ─── SLEIGH path ────────────────────────────────────────────────────────────

/// Return the path to the SLEIGH language definitions directory.
/// Defaults to `./SLEIGH` but can be overridden with `KAIJULAB_SLEIGH_DIR`.
fn sleigh_dir() -> std::path::PathBuf {
    std::env::var("KAIJULAB_SLEIGH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./SLEIGH"))
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Decompile the function starting at `vaddr` in the binary at `path`.
///
/// Returns a text string of pseudo-C code, or an error message.
pub fn decompile_function(path: &str, vaddr: u64) -> String {
    match decompile_inner(path, vaddr) {
        Ok(text) => text,
        Err(e) => format!("Decompiler error: {e}"),
    }
}

/// Decompile a function from a raw flat binary (firmware / shellcode) loaded
/// at `base_addr`.  `arch_str` selects the SLEIGH language:
///   "x86_64" | "x86_32" | "aarch64" | "arm32"
pub fn decompile_function_flat(path: &str, base_addr: u64, vaddr: u64, arch_str: &str) -> String {
    match decompile_flat_inner(path, base_addr, vaddr, arch_str) {
        Ok(text) => text,
        Err(e)   => format!("Decompiler error: {e}"),
    }
}

fn decompile_flat_inner(
    path: &str,
    base_addr: u64,
    vaddr: u64,
    arch_str: &str,
) -> anyhow::Result<String> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", path, e))?;

    let dir = sleigh_dir();
    let (ldefs_file, lang_id) = match arch_str {
        "x86_64" | "x86-64" => (
            dir.join("Processors/x86/data/languages/x86.ldefs"),
            "x86:LE:64:default",
        ),
        "x86_32" | "x86-32" | "x86" => (
            dir.join("Processors/x86/data/languages/x86.ldefs"),
            "x86:LE:32:default",
        ),
        "aarch64" | "arm64" => (
            dir.join("Processors/AARCH64/data/languages/AARCH64.ldefs"),
            "AARCH64:LE:64:v8A",
        ),
        "arm32" | "arm" => (
            dir.join("Processors/ARM/data/languages/ARM.ldefs"),
            "ARM:LE:32:v8",
        ),
        other => {
            return Err(anyhow::anyhow!(
                "Unknown arch '{}' — use x86_64, x86_32, aarch64, or arm32",
                other
            ))
        }
    };

    let ldefs_str = ldefs_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid SLEIGH path"))?
        .to_string();

    let lang = sleigh_compile::SleighLanguageBuilder::new(&ldefs_str, lang_id)
        .build()
        .map_err(|e| anyhow::anyhow!("SLEIGH build failed: {e:?}"))?;

    let mut memory = Memory::new(lang);

    // Load the entire file as a single flat segment at base_addr
    let literal = memory::LiteralState::from_bytes(base_addr, data.clone());
    let _ = memory.literal.insert_strict(literal.get_interval(), literal);

    let addr = Address(vaddr);
    lift_function(addr, &mut memory)
        .map_err(|e| anyhow::anyhow!("Lift failed at 0x{:x}: {e}", vaddr))?;

    let hf = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        HighFunction::from_mem(addr, &memory)
    }))
    .map_err(|e| anyhow::anyhow!("HighFunction panicked: {:?}", panic_msg(e)))?;

    hf.fill_global_symbols(&mut memory);

    let ast = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hf.build_ast(&memory)))
        .map_err(|e| anyhow::anyhow!("AST build panicked: {:?}", panic_msg(e)))?;

    let output = render_ast(&ast, &hf, &memory);
    Ok(output)
}

fn decompile_inner(path: &str, vaddr: u64) -> anyhow::Result<String> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", path, e))?;

    // Load project sidecar (may be empty if no .kaiju.json exists yet)
    let project = crate::project::Project::load_for(path);

    // Detect architecture to pick the right SLEIGH language ID
    let arch = object::File::parse(&*data)
        .ok()
        .map(|f| f.architecture());

    let (ldefs_file, lang_id) = match arch {
        Some(object::Architecture::X86_64) | Some(object::Architecture::X86_64_X32) => {
            let dir = sleigh_dir();
            (
                dir.join("Processors/x86/data/languages/x86.ldefs"),
                "x86:LE:64:default",
            )
        }
        Some(object::Architecture::I386) => {
            let dir = sleigh_dir();
            (
                dir.join("Processors/x86/data/languages/x86.ldefs"),
                "x86:LE:32:default",
            )
        }
        Some(object::Architecture::Aarch64) | Some(object::Architecture::Aarch64_Ilp32) => {
            let dir = sleigh_dir();
            (
                dir.join("Processors/AARCH64/data/languages/AARCH64.ldefs"),
                "AARCH64:LE:64:v8A",
            )
        }
        Some(object::Architecture::Arm) => {
            let dir = sleigh_dir();
            (
                dir.join("Processors/ARM/data/languages/ARM.ldefs"),
                "ARM:LE:32:v8",
            )
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unsupported architecture {:?} — decompiler supports x86/x86-64/ARM/AArch64",
                other
            ))
        }
    };

    let ldefs_str = ldefs_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid SLEIGH path"))?
        .to_string();

    let lang = sleigh_compile::SleighLanguageBuilder::new(&ldefs_str, lang_id)
        .build()
        .map_err(|e| anyhow::anyhow!("SLEIGH build failed: {e:?}"))?;

    let mut memory = Memory::new(lang);

    // Pre-populate symbol table from project renames so call-site names
    // propagate into the decompiled output (e.g. FUN_0x401234 → parse_header).
    for (addr, name) in &project.renames {
        memory.symbols.add(*addr, 8, name.clone());
    }

    // Load binary sections
    load_binary(&data, &mut memory)
        .map_err(|e| anyhow::anyhow!("Binary load failed: {e}"))?;

    // Lift the function at vaddr to IR
    let addr = Address(vaddr);
    lift_function(addr, &mut memory)
        .map_err(|e| anyhow::anyhow!("Lift failed at 0x{:x}: {e}", vaddr))?;

    // Build HighFunction (CFG + symbolic analysis)
    let hf = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        HighFunction::from_mem(addr, &memory)
    }))
    .map_err(|e| anyhow::anyhow!("HighFunction panicked: {:?}", panic_msg(e)))?;

    hf.fill_global_symbols(&mut memory);

    // Build AST
    let ast = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hf.build_ast(&memory)))
        .map_err(|e| anyhow::anyhow!("AST build panicked: {:?}", panic_msg(e)))?;

    let mut output = render_ast(&ast, &hf, &memory);
    apply_project_annotations(&mut output, &project, vaddr);
    Ok(output)
}

fn panic_msg(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = e.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "unknown panic".to_string()
    }
}

// ─── Binary loader ──────────────────────────────────────────────────────────

fn load_binary(data: &[u8], memory: &mut Memory) -> anyhow::Result<()> {
    let obj = Object::parse(data).map_err(|e| anyhow::anyhow!("{e}"))?;
    match obj {
        Object::Elf(elf) => {
            for section in &elf.section_headers {
                use goblin::elf::section_header::*;
                if matches!(section.sh_type, SHT_NULL | SHT_NOTE) {
                    continue;
                }
                if section.sh_addr == 0 || section.sh_size == 0 {
                    continue;
                }
                let section_bytes = section
                    .file_range()
                    .and_then(|r| data.get(r))
                    .unwrap_or(&[]);

                let mut raw = vec![0u8; section.sh_size as usize];
                let copy_len = section_bytes.len().min(raw.len());
                raw[..copy_len].copy_from_slice(&section_bytes[..copy_len]);

                let literal = LiteralState::from_bytes(section.sh_addr, raw);
                let _ = memory.literal.insert_strict(literal.get_interval(), literal);
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                if let Ok(Some(sec_data)) = section.data(data) {
                    let vaddr = pe.image_base as u64 + section.virtual_address as u64;
                    let literal =
                        LiteralState::from_bytes(vaddr, sec_data.to_vec());
                    let _ = memory.literal.insert_strict(literal.get_interval(), literal);
                }
            }
        }
        Object::Mach(mach) => {
            use goblin::mach::{Mach, SingleArch};
            let macho = match mach {
                Mach::Binary(m) => m,
                Mach::Fat(multi) => {
                    // Pick the first MachO arch from a fat binary
                    let mut found = None;
                    for arch_result in &multi {
                        if let Ok(SingleArch::MachO(m)) = arch_result {
                            found = Some(m);
                            break;
                        }
                    }
                    match found {
                        Some(m) => m,
                        None => return Err(anyhow::anyhow!("No MachO arch found in fat binary")),
                    }
                }
            };
            for seg in &macho.segments {
                let seg_addr = seg.vmaddr;
                let seg_data = seg.data;
                if seg_addr == 0 || seg_data.is_empty() {
                    continue;
                }
                let literal = LiteralState::from_bytes(seg_addr, seg_data.to_vec());
                let _ = memory.literal.insert_strict(literal.get_interval(), literal);
            }
        }
        _ => return Err(anyhow::anyhow!("Unsupported binary format")),
    }
    Ok(())
}

// ─── IR lifting ─────────────────────────────────────────────────────────────

/// Lift machine code at `addr` into IR blocks stored in `memory.ir`.
fn lift_function(addr: Address, memory: &mut Memory) -> anyhow::Result<()> {
    let state = memory
        .literal
        .get_at_point(addr)
        .ok_or_else(|| anyhow::anyhow!("Address 0x{:x} not mapped", addr.0))?;

    let (_section_addr, bytes_slice) = match &state.kind {
        LiteralKind::Data(items) => {
            let offset = (addr.0 - state.addr.0) as usize;
            (state.addr, &items[offset..] as *const [u8])
        }
        LiteralKind::Instruction(_, _) => {
            // Already lifted
            return Ok(());
        }
    };

    // SAFETY: we borrow the slice pointer before mutably borrowing memory
    // This is a one-time immutable read converted to owned data.
    let bytes_owned: Vec<u8> = unsafe { (*bytes_slice).to_vec() };

    let instructions = LiteralState::from_machine_code(
        Cow::Owned(bytes_owned),
        addr.0,
        &memory.lang,
    )
    .ok_or_else(|| anyhow::anyhow!("No instructions decoded at 0x{:x}", addr.0))?;

    let bs = std::mem::take(&mut memory.ir);
    let ir = ir::lift(instructions.get_instructions(), &memory.lang, Some(bs));
    memory.ir = ir;

    Ok(())
}

// ─── Text renderer ──────────────────────────────────────────────────────────

fn resolve_name<'a>(
    mem: &'a Memory,
    sym: &VariableSymbol,
    ast: &'a AbstractSyntaxTree,
    sese: SingleEntrySingleExit<BlockSlot>,
) -> Cow<'a, str> {
    // Check global symbol table first
    if let Some(def) = mem.symbols.resolve(sym) {
        return Cow::Borrowed(def.name.as_str());
    }
    // Check function-local scope
    if let Some(def) = ast.scope.get_symbol_recursive(sese, sym) {
        return Cow::Borrowed(def.name.as_str());
    }
    // Fallback: display the symbol
    Cow::Owned(format!("{sym}"))
}

fn resolve_addr_name<'a>(mem: &'a Memory, addr: Address) -> Cow<'a, str> {
    if let Some(def) = mem.symbols.map.get(&addr) {
        Cow::Borrowed(def.name.as_str())
    } else {
        Cow::Owned(format!("0x{:x}", addr.0))
    }
}

fn render_expr(
    expr: &Expression,
    pos: OpIdx,
    mem: &Memory,
    ast: &AbstractSyntaxTree,
    hf: &HighFunction,
    sese: SingleEntrySingleExit<BlockSlot>,
    is_call: bool,
) -> String {
    match &expr[pos] {
        ExpressionOp::Value(v) => {
            if is_call {
                resolve_addr_name(mem, Address(*v)).into_owned()
            } else if *v < 1024 {
                format!("{v}")
            } else {
                format!("0x{v:x}")
            }
        }
        ExpressionOp::Variable(sym) => {
            resolve_name(mem, sym, ast, sese).into_owned()
        }
        ExpressionOp::Dereference(d) => {
            // Check if the inner is a simple address or variable for clean display
            match &expr[*d] {
                ExpressionOp::Value(v) => {
                    let sym = VariableSymbol::Ram(Box::new(Expression::from(*v)), 4);
                    format!("*({})", resolve_name(mem, &sym, ast, sese))
                }
                ExpressionOp::Variable(sym) => {
                    format!("*{}", resolve_name(mem, sym, ast, sese))
                }
                _ => {
                    let inner = render_expr(expr, *d, mem, ast, hf, sese, false);
                    let sym = VariableSymbol::Ram(Box::new(expr.get_sub_expression(*d)), 4);
                    if let Cow::Borrowed(name) = resolve_name(mem, &sym, ast, sese) {
                        name.to_string()
                    } else {
                        format!("*({inner})")
                    }
                }
            }
        }
        ExpressionOp::Assign(l, r) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, false);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, false);
            format!("{lhs} = {rhs}")
        }
        ExpressionOp::Equals(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} == {rhs}")
        }
        ExpressionOp::NotEquals(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} != {rhs}")
        }
        ExpressionOp::Add(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} + {rhs}")
        }
        ExpressionOp::Sub(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} - {rhs}")
        }
        ExpressionOp::Multiply(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} * {rhs}")
        }
        ExpressionOp::And(l, r) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} & {rhs}")
        }
        ExpressionOp::Or(l, r) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} | {rhs}")
        }
        ExpressionOp::Xor(l, r) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} ^ {rhs}")
        }
        ExpressionOp::Not(l) => {
            let inner = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            format!("!{inner}")
        }
        ExpressionOp::Less(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} < {rhs}")
        }
        ExpressionOp::LessOrEquals(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} <= {rhs}")
        }
        ExpressionOp::Greater(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} > {rhs}")
        }
        ExpressionOp::GreaterOrEquals(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} >= {rhs}")
        }
        ExpressionOp::BitShiftLeft(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} << {rhs}")
        }
        ExpressionOp::BitShiftRight(l, r, _) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("{lhs} >> {rhs}")
        }
        ExpressionOp::Overflow(l, _) => {
            let inner = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            format!("overflow({inner})")
        }
        ExpressionOp::CountOnes(l) => {
            let inner = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            format!("popcount({inner})")
        }
        ExpressionOp::Interrupt(l) => {
            let inner = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            format!("interrupt({inner})")
        }
        ExpressionOp::Multiequals(l, r) => {
            let lhs = render_expr(expr, *l, mem, ast, hf, sese, is_call);
            let rhs = render_expr(expr, *r, mem, ast, hf, sese, is_call);
            format!("phi({lhs}, {rhs})")
        }
        ExpressionOp::DestinationRegister(vn) => {
            if let Some(name) = mem.lang.sleigh.name_of_varnode(*vn) {
                name.to_string()
            } else {
                format!("reg_{:x}_{}", vn.id, vn.size)
            }
        }
    }
}

fn render_dest(dest: &DestinationKind, mem: &Memory) -> String {
    match dest {
        DestinationKind::Concrete(addr) => resolve_addr_name(mem, *addr).into_owned(),
        DestinationKind::Symbolic(expr) => format!("{expr}"),
        DestinationKind::Virtual(addr, _) => format!("0x{:x}", addr.0),
    }
}

fn render_stmt(
    out: &mut String,
    stmt: &AstStatement,
    ast: &AbstractSyntaxTree,
    hf: &HighFunction,
    mem: &Memory,
    depth: usize,
) {
    let indent = "  ".repeat(depth);
    match stmt {
        AstStatement::Block(stmts) => {
            for s in stmts {
                render_stmt(out, s, ast, hf, mem, depth);
            }
        }
        AstStatement::Nop => {}
        AstStatement::Comment(c) => {
            out.push_str(&format!("{indent}// {c}\n"));
        }
        AstStatement::MultilineComment(c) => {
            out.push_str(&format!("{indent}/* {c} */\n"));
        }
        AstStatement::Function { name, args, body } => {
            let name_str = resolve_name(mem, name, ast, hf.pts.root);
            let args_str: Vec<String> = args
                .iter()
                .map(|a| {
                    format!("int32_t {}", resolve_name(mem, a, ast, hf.pts.root))
                })
                .collect();
            out.push_str(&format!(
                "{indent}void {}({}) {{\n",
                name_str,
                args_str.join(", ")
            ));
            render_stmt(out, body, ast, hf, mem, depth + 1);
            out.push_str(&format!("{indent}}}\n"));
        }
        AstStatement::Assignment { sese, destination, value } => {
            let dst = render_expr(
                destination,
                destination.get_entry_point(),
                mem, ast, hf, *sese, false,
            );
            let val = render_expr(
                value,
                value.get_entry_point(),
                mem, ast, hf, *sese, false,
            );
            out.push_str(&format!("{indent}{dst} = {val};\n"));
        }
        AstStatement::Call { destination, params, call_from, sese } => {
            let call_result = VariableSymbol::CallResult {
                call_from: *call_from,
                call_to: Box::new(destination.clone()),
            };
            let result_name = {
                let r = resolve_name(mem, &call_result, ast, *sese);
                // Only show result if it's been given a human name (not "unresolved_...")
                if r.starts_with("unresolved_") { None } else { Some(r.into_owned()) }
            };

            let dst_str = render_dest(destination, mem);
            let params_str: Vec<String> = params
                .iter()
                .map(|p| render_expr(p, p.get_entry_point(), mem, ast, hf, *sese, false))
                .collect();

            if let Some(result) = result_name {
                out.push_str(&format!(
                    "{indent}{result} = {dst_str}({});\n",
                    params_str.join(", ")
                ));
            } else {
                out.push_str(&format!(
                    "{indent}{dst_str}({});\n",
                    params_str.join(", ")
                ));
            }
        }
        AstStatement::If { sese, condition, true_statement, else_statement, .. } => {
            let cond = render_expr(
                condition,
                condition.get_entry_point(),
                mem, ast, hf, *sese, false,
            );
            out.push_str(&format!("{indent}if ({cond}) {{\n"));
            render_stmt(out, true_statement, ast, hf, mem, depth + 1);
            if !else_statement.is_nop() {
                out.push_str(&format!("{indent}}} else {{\n"));
                render_stmt(out, else_statement, ast, hf, mem, depth + 1);
            }
            out.push_str(&format!("{indent}}}\n"));
        }
        AstStatement::Loop { sese, condition, body, .. } => {
            let cond = render_expr(
                condition,
                condition.get_entry_point(),
                mem, ast, hf, *sese, false,
            );
            out.push_str(&format!("{indent}while ({cond}) {{\n"));
            render_stmt(out, body, ast, hf, mem, depth + 1);
            out.push_str(&format!("{indent}}}\n"));
        }
        AstStatement::Return { sese, result } => {
            let val = render_expr(
                result,
                result.get_entry_point(),
                mem, ast, hf, *sese, false,
            );
            out.push_str(&format!("{indent}return {val};\n"));
        }
    }
}

fn render_ast(ast: &AbstractSyntaxTree, hf: &HighFunction, mem: &Memory) -> String {
    let mut out = String::new();
    render_stmt(&mut out, ast.entry(), ast, hf, mem, 0);
    out
}

/// Apply all post-processing passes to decompiler output:
///
/// 1. Strip trivial 64-bit masks (`& 0xffffffffffffffff`)
/// 2. Rename SysV64 argument registers (RDI→arg_1, …)
/// 3. Apply function-level variable renames from the project sidecar
/// 4. Apply parameter type / name annotations from the project sidecar
/// 5. Replace the default `void` return type with the user-specified one
fn apply_project_annotations(
    out: &mut String,
    project: &crate::project::Project,
    fn_vaddr: u64,
) {
    // 1. Remove `& 0xffffffffffffffff` — meaningless 64-bit mask.
    *out = out.replace(" & 0xffffffffffffffff", "");

    // 2. Rename SysV64 argument registers → canonical arg names.
    const SYSV64_ARGS: &[(&str, &str)] = &[
        ("RDI", "arg_1"),
        ("RSI", "arg_2"),
        ("RDX", "arg_3"),
        ("RCX", "arg_4"),
        ("R8",  "arg_5"),
        ("R9",  "arg_6"),
    ];
    for (reg, name) in SYSV64_ARGS {
        *out = replace_identifier(out, reg, name);
    }

    // 3. Apply project variable renames (e.g. arg_1 → buf, var_3 → count).
    if let Some(renames) = project.var_renames.get(&fn_vaddr) {
        // Sort longest first so "arg_10" is replaced before "arg_1".
        let mut pairs: Vec<(&String, &String)> = renames.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (old, new) in pairs {
            *out = replace_identifier(out, old, new);
        }
    }

    // 4. Apply signature overrides (param names → replaces arg_N, param types,
    //    return type).
    if let Some(sig) = project.get_signature(fn_vaddr) {
        // 4a. Rename positional args: arg_1 → user_name (if set).
        for (i, maybe_name) in sig.param_names.iter().enumerate() {
            if let Some(name) = maybe_name {
                if !name.is_empty() {
                    let default_name = format!("arg_{}", i + 1);
                    *out = replace_identifier(out, &default_name, name);
                }
            }
        }

        // 4b. Add parameter type prefixes in the function signature line.
        //     The renderer emits `int32_t arg_N` for each parameter.
        for (i, maybe_type) in sig.param_types.iter().enumerate() {
            if let Some(type_str) = maybe_type {
                // The actual arg name after step 4a (may have been renamed).
                let arg_name = sig
                    .param_names
                    .get(i)
                    .and_then(|n| n.as_deref())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| {
                        // static storage trick — we build the default below
                        ""
                    });
                let effective_name = if arg_name.is_empty() {
                    format!("arg_{}", i + 1)
                } else {
                    arg_name.to_string()
                };
                let old_decl = format!("int32_t {}", effective_name);
                let new_decl = format!("{} {}", type_str, effective_name);
                *out = out.replace(&old_decl, &new_decl);
            }
        }

        // 4c. Replace return type (`void ` at the function declaration start).
        if let Some(ret) = &sig.return_type {
            // The renderer always emits `void func_name(...)`.
            // Replace only the leading `void ` on the first non-comment line.
            if let Some(line_start) = out.find("void ") {
                let prefix = &out[..line_start];
                // Make sure it's not inside a comment
                if !prefix.contains("//") && !prefix.ends_with("* ") {
                    let suffix = &out[line_start + 5..];
                    *out = format!("{}{} {}", prefix, ret, suffix);
                }
            }
        }
    }
}

/// Replace all occurrences of `from` that appear as a complete identifier
/// (not surrounded by alphanumeric chars or underscores).
fn replace_identifier(s: &str, from: &str, to: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(from) {
        let before_ok = pos == 0 || {
            let b = rest.as_bytes()[pos - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        let after_ok = {
            let end = pos + from.len();
            end >= rest.len() || {
                let b = rest.as_bytes()[end];
                !b.is_ascii_alphanumeric() && b != b'_'
            }
        };
        if before_ok && after_ok {
            result.push_str(&rest[..pos]);
            result.push_str(to);
            rest = &rest[pos + from.len()..];
        } else {
            result.push_str(&rest[..pos + 1]);
            rest = &rest[pos + 1..];
        }
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{FunctionSignature, Project, StructDef, StructField};

    // ── replace_identifier ───────────────────────────────────────────────────

    #[test]
    fn replace_identifier_simple() {
        assert_eq!(replace_identifier("RDI + 1", "RDI", "arg_1"), "arg_1 + 1");
    }

    #[test]
    fn replace_identifier_does_not_replace_partial() {
        // "RDIM" must not become "arg_1M"
        assert_eq!(replace_identifier("RDIM", "RDI", "arg_1"), "RDIM");
    }

    #[test]
    fn replace_identifier_at_start_of_string() {
        assert_eq!(replace_identifier("RDI;", "RDI", "arg_1"), "arg_1;");
    }

    #[test]
    fn replace_identifier_at_end_of_string() {
        assert_eq!(replace_identifier("foo = RDI", "RDI", "arg_1"), "foo = arg_1");
    }

    #[test]
    fn replace_identifier_multiple_occurrences() {
        let s = "if (RDI > 0) { return RDI; }";
        assert_eq!(
            replace_identifier(s, "RDI", "arg_1"),
            "if (arg_1 > 0) { return arg_1; }"
        );
    }

    #[test]
    fn replace_identifier_longer_name_first() {
        // Simulates the "arg_10 before arg_1" ordering
        let mut s = "arg_10 + arg_1".to_string();
        // Replace longer name first
        s = replace_identifier(&s, "arg_10", "count");
        s = replace_identifier(&s, "arg_1",  "buf");
        assert_eq!(s, "count + buf");
    }

    // ── apply_project_annotations ────────────────────────────────────────────

    #[test]
    fn strips_64bit_mask() {
        let mut p = Project::default();
        let mut out = "x = y & 0xffffffffffffffff;".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert_eq!(out, "x = y;");
    }

    #[test]
    fn renames_sysv64_arg_registers() {
        let p = Project::default();
        let mut out = "void FUN(int32_t RDI, int32_t RSI) { return RDI + RSI; }".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert!(out.contains("arg_1"), "RDI should become arg_1");
        assert!(out.contains("arg_2"), "RSI should become arg_2");
        assert!(!out.contains("RDI"),  "no raw RDI should remain");
        assert!(!out.contains("RSI"),  "no raw RSI should remain");
    }

    #[test]
    fn applies_var_renames_from_project() {
        let mut p = Project::default();
        p.rename_var(0x401000, "arg_1".to_string(), "buf".to_string());
        p.rename_var(0x401000, "arg_2".to_string(), "len".to_string());

        let mut out = "void f(int32_t arg_1, int32_t arg_2) { return arg_1 + arg_2; }".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert!(out.contains("buf"), "arg_1 should become buf");
        assert!(out.contains("len"), "arg_2 should become len");
    }

    #[test]
    fn var_renames_not_applied_to_wrong_function() {
        let mut p = Project::default();
        p.rename_var(0x402000, "arg_1".to_string(), "buf".to_string()); // different addr

        let mut out = "void f(int32_t arg_1) {}".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        // arg_1 was renamed to arg_1 by SysV64 pass (RDI → arg_1 stays), project rename not applied
        assert!(!out.contains("buf"));
    }

    #[test]
    fn applies_return_type_override() {
        let mut p = Project::default();
        p.set_return_type(0x401000, "int".to_string());

        let mut out = "void FUN_0x401000(int32_t arg_1) {\n  return arg_1;\n}".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert!(out.starts_with("int "), "return type should be replaced");
        assert!(!out.starts_with("void "), "void should be gone");
    }

    #[test]
    fn applies_param_type_override() {
        let mut p = Project::default();
        p.set_param_type(0x401000, 1, "const char*".to_string());

        let mut out = "void f(int32_t arg_1) {}".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert!(out.contains("const char* arg_1"));
        assert!(!out.contains("int32_t arg_1"));
    }

    #[test]
    fn applies_param_name_and_type_together() {
        let mut p = Project::default();
        p.set_param_type(0x401000, 1, "size_t".to_string());
        p.set_param_name(0x401000, 1, "count".to_string());

        let mut out = "void f(int32_t arg_1) { return arg_1; }".to_string();
        apply_project_annotations(&mut out, &p, 0x401000);
        assert!(out.contains("size_t count"), "should have typed+renamed param");
        assert!(!out.contains("arg_1"), "old name should be gone");
    }

    // ── decompile_function end-to-end (requires external binary) ────────────

    /// Compile a small x86-64 binary with:
    ///   x86_64-linux-gnu-gcc -O0 -static -o /tmp/simple_x86_64 /tmp/simple.c
    /// where simple.c contains:  int add(int a, int b) { return a + b; }
    /// nm output: 0000000000401745 T add
    #[test]
    #[ignore]
    fn test_decompile_x86_64() {
        let result = decompile_function("/tmp/simple_x86_64", 0x401745);
        assert!(!result.is_empty(), "decompile returned empty string");
        eprintln!("Decompile output:\n{result}");
    }
}
