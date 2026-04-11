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

fn decompile_inner(path: &str, vaddr: u64) -> anyhow::Result<String> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", path, e))?;

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
        other => {
            return Err(anyhow::anyhow!(
                "Unsupported architecture {:?} — decompiler supports x86/x86-64 only",
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

    Ok(render_ast(&ast, &hf, &memory))
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

    let (section_addr, bytes_slice) = match &state.kind {
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

#[cfg(test)]
mod tests {
    use super::decompile_function;

    /// Compile a small x86-64 binary with:
    ///   x86_64-linux-gnu-gcc -O0 -static -o /tmp/simple_x86_64 /tmp/simple.c
    /// where simple.c contains:  int add(int a, int b) { return a + b; }
    /// nm output: 0000000000401745 T add
    #[test]
    #[ignore] // requires /tmp/simple_x86_64 — run with: cargo test --release -- --ignored
    fn test_decompile_x86_64() {
        let result = decompile_function("/tmp/simple_x86_64", 0x401745);
        assert!(!result.is_empty(), "decompile returned empty string");
        eprintln!("Decompile output:\n{result}");
    }
}
