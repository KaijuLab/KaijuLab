//! Recovery-backed decompile context.
//!
//! The legacy pseudo-C renderer still owns expression rendering. This module
//! feeds it better recovered function facts and adds machine-level context that
//! exploit agents need: CFG blocks, stack-frame hints, calls, and syscalls.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use object::{Architecture, Object, ObjectSection};
use serde::Serialize;

use crate::tools;

use super::recovery::{self, RecoveredFunction, RecoveryIndex};

#[derive(Debug, Clone)]
struct ExecSection {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
enum KnownValue {
    Imm(u64),
    Reg(String),
    StackPointer,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecompileAnalysis {
    pub kind: String,
    pub binary: String,
    pub vaddr: String,
    pub function: RecoveredFunction,
    pub cfg: CfgDiagnostics,
    pub machine: FunctionInsights,
    pub dataflow: DataFlowFacts,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgDiagnostics {
    pub entry: String,
    pub block_count: usize,
    pub edge_count: usize,
    pub exit_blocks: Vec<String>,
    pub back_edges: Vec<String>,
    pub loop_headers: Vec<String>,
    pub strongly_connected_components: usize,
    pub irreducible_sccs: usize,
    pub reducible: bool,
    pub goto_pressure: usize,
    pub structuring_strategy: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionInsights {
    frame_size: u64,
    #[serde(skip)]
    current_stack: u64,
    stack_accesses: Vec<String>,
    calls: Vec<String>,
    syscalls: Vec<String>,
    risks: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DataFlowFacts {
    pub available: bool,
    pub architecture: String,
    pub instruction_count: usize,
    pub tracked_registers: Vec<String>,
    pub definitions: Vec<RegisterDefinition>,
    pub uses: Vec<RegisterUse>,
    pub block_inputs: Vec<BlockDataFlow>,
    pub phi_candidates: Vec<PhiCandidate>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDefinition {
    pub vaddr: String,
    pub register: String,
    pub version: u32,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterUse {
    pub vaddr: String,
    pub register: String,
    pub version: Option<u32>,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockDataFlow {
    pub block: String,
    pub predecessors: Vec<String>,
    pub live_in_registers: Vec<String>,
    pub defined_registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhiCandidate {
    pub block: String,
    pub register: String,
    pub incoming_versions: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecompilerQualityReport {
    pub kind: String,
    pub binary: String,
    pub max_functions: usize,
    pub score: u32,
    pub recovered_functions: usize,
    pub analyzed_functions: usize,
    pub legacy_decompile_ok: usize,
    pub reducible_functions: usize,
    pub functions_with_machine_facts: usize,
    pub functions_with_dataflow_facts: usize,
    pub total_phi_candidates: usize,
    pub total_blocks: usize,
    pub total_edges: usize,
    pub total_irreducible_sccs: usize,
    pub total_goto_pressure: usize,
    pub function_reports: Vec<FunctionQuality>,
    pub blockers: Vec<String>,
    pub next_engine_work: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionQuality {
    pub vaddr: String,
    pub name: String,
    pub size: u64,
    pub blocks: usize,
    pub edges: usize,
    pub reducible: bool,
    pub goto_pressure: usize,
    pub has_machine_facts: bool,
    pub has_dataflow_facts: bool,
    pub phi_candidates: usize,
    pub legacy_decompile_ok: bool,
    pub notes: Vec<String>,
}

pub fn decompiler_quality_report_path(
    path: &Path,
    max_functions: usize,
) -> Result<DecompilerQualityReport> {
    let max_functions = max_functions.clamp(1, 5000);
    let index = recovery::recover(path, max_functions)
        .with_context(|| format!("recover functions for {}", path.display()))?;
    let mut function_reports = Vec::new();
    let mut legacy_decompile_ok = 0usize;
    let mut reducible_functions = 0usize;
    let mut functions_with_machine_facts = 0usize;
    let mut functions_with_dataflow_facts = 0usize;
    let mut total_phi_candidates = 0usize;
    let mut total_blocks = 0usize;
    let mut total_edges = 0usize;
    let mut total_irreducible_sccs = 0usize;
    let mut total_goto_pressure = 0usize;

    for function in &index.functions {
        if parse_addr(&function.start).is_none() {
            continue;
        }
        let cfg = analyze_cfg(function);
        let machine = inspect_function(path, function).unwrap_or_default();
        let dataflow = analyze_dataflow(path, function).unwrap_or_else(|err| DataFlowFacts {
            notes: vec![format!("data-flow unavailable: {err}")],
            ..Default::default()
        });
        let has_machine_facts = !machine.calls.is_empty()
            || !machine.syscalls.is_empty()
            || !machine.stack_accesses.is_empty()
            || machine.frame_size > 0;
        let has_dataflow_facts = dataflow.available && !dataflow.definitions.is_empty();
        let legacy_ok = false;
        if legacy_ok {
            legacy_decompile_ok += 1;
        }
        if cfg.reducible {
            reducible_functions += 1;
        }
        if has_machine_facts {
            functions_with_machine_facts += 1;
        }
        if has_dataflow_facts {
            functions_with_dataflow_facts += 1;
        }
        total_phi_candidates += dataflow.phi_candidates.len();
        total_blocks += cfg.block_count;
        total_edges += cfg.edge_count;
        total_irreducible_sccs += cfg.irreducible_sccs;
        total_goto_pressure += cfg.goto_pressure;

        let mut notes = Vec::new();
        if !cfg.reducible {
            notes.push(
                "irreducible CFG needs SAILR/node-splitting before structured output".to_string(),
            );
        }
        if !legacy_ok {
            notes.push("legacy pseudo-C not executed by benchmark stability guard".to_string());
        }
        if !machine.risks.is_empty() {
            notes.extend(machine.risks.clone());
        }
        if !has_dataflow_facts {
            notes.push("register data-flow facts unavailable or empty".to_string());
        }
        if !dataflow.notes.is_empty() {
            notes.extend(dataflow.notes.clone());
        }
        function_reports.push(FunctionQuality {
            vaddr: function.start.clone(),
            name: function.name.clone(),
            size: function.size,
            blocks: cfg.block_count,
            edges: cfg.edge_count,
            reducible: cfg.reducible,
            goto_pressure: cfg.goto_pressure,
            has_machine_facts,
            has_dataflow_facts,
            phi_candidates: dataflow.phi_candidates.len(),
            legacy_decompile_ok: legacy_ok,
            notes,
        });
    }

    let analyzed_functions = function_reports.len();
    let score = decompiler_score(
        index.functions.len(),
        analyzed_functions,
        legacy_decompile_ok,
        reducible_functions,
        functions_with_machine_facts,
        functions_with_dataflow_facts,
        total_irreducible_sccs,
        total_goto_pressure,
    );
    let blockers = decompiler_blockers(
        index.functions.len(),
        analyzed_functions,
        legacy_decompile_ok,
        reducible_functions,
        functions_with_machine_facts,
        functions_with_dataflow_facts,
        total_irreducible_sccs,
    );

    Ok(DecompilerQualityReport {
        kind: "decompiler_quality_report".to_string(),
        binary: path.to_string_lossy().into_owned(),
        max_functions,
        score,
        recovered_functions: index.functions.len(),
        analyzed_functions,
        legacy_decompile_ok,
        reducible_functions,
        functions_with_machine_facts,
        functions_with_dataflow_facts,
        total_phi_candidates,
        total_blocks,
        total_edges,
        total_irreducible_sccs,
        total_goto_pressure,
        function_reports,
        blockers,
        next_engine_work: vec![
            "Replace text-parse machine facts with lifted IR data-flow facts".to_string(),
            "Build SSA over recovered CFG and insert phi nodes at dominance frontiers".to_string(),
            "Recover stack/global variables from memory SSA and escaped-frame analysis".to_string(),
            "Infer call signatures/calling conventions before expression rendering".to_string(),
            "Implement semantics-preserving structuring with node splitting for irreducible SCCs"
                .to_string(),
            "Add source-known regression corpus with expected CFG/AST/type facts".to_string(),
        ],
    })
}

fn decompiler_score(
    recovered_functions: usize,
    analyzed_functions: usize,
    legacy_ok: usize,
    reducible: usize,
    machine_facts: usize,
    dataflow_facts: usize,
    irreducible_sccs: usize,
    goto_pressure: usize,
) -> u32 {
    if recovered_functions == 0 || analyzed_functions == 0 {
        return 0;
    }
    let analyzed = analyzed_functions as f64;
    let recovery_score = 20.0;
    let legacy_score = 20.0 * legacy_ok as f64 / analyzed;
    let reducible_score = 20.0 * reducible as f64 / analyzed;
    let machine_score = 15.0 * machine_facts as f64 / analyzed;
    let dataflow_score = 10.0 * dataflow_facts as f64 / analyzed;
    let structuring_penalty =
        (irreducible_sccs as f64 * 5.0 + goto_pressure as f64 * 2.0).min(20.0);
    let foundation_score = 25.0;
    let surface_score = (recovery_score
        + legacy_score
        + reducible_score
        + machine_score
        + dataflow_score
        + foundation_score
        - structuring_penalty)
        .round()
        .clamp(0.0, 100.0) as u32;
    // Register SSA facts are still a first slice, not production decompiler
    // semantics. Keep the cap explicit until memory SSA and type propagation
    // are part of the scored engine.
    let cap = if dataflow_facts > 0 { 55 } else { 45 };
    surface_score.min(cap)
}

fn decompiler_blockers(
    recovered_functions: usize,
    analyzed_functions: usize,
    legacy_ok: usize,
    reducible: usize,
    machine_facts: usize,
    dataflow_facts: usize,
    irreducible_sccs: usize,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if recovered_functions == 0 {
        blockers.push("no recovered functions; scanner/recovery must improve first".to_string());
        return blockers;
    }
    if legacy_ok < analyzed_functions {
        blockers.push("legacy pseudo-C renderer is not benchmark-safe yet".to_string());
    }
    if reducible < analyzed_functions || irreducible_sccs > 0 {
        blockers.push("CFG structuring lacks irreducible-control-flow repair".to_string());
    }
    if machine_facts < analyzed_functions {
        blockers.push("machine facts are heuristic and missing for some functions".to_string());
    }
    if dataflow_facts == 0 {
        blockers.push("no data-flow quality gate yet".to_string());
        blockers.push("score is capped at 45 until SSA/data-flow/type inference land".to_string());
    } else {
        blockers.push(
            "data-flow gate is first-pass register SSA only; no memory SSA/type inference yet"
                .to_string(),
        );
        blockers.push("score is capped at 55 until memory SSA/type inference land".to_string());
    }
    blockers
}

pub fn decompile_analysis_path(path: &Path, vaddr: u64) -> Result<DecompileAnalysis> {
    if vaddr == 0 {
        return Err(anyhow!("vaddr is required"));
    }

    let index = recovery::recover(path, 2000)
        .with_context(|| format!("recover functions for {}", path.display()))?;
    let function = find_function(&index, vaddr)
        .ok_or_else(|| anyhow!("function 0x{vaddr:x} was not recovered"))?
        .clone();
    let mut insights = inspect_function(path, &function).unwrap_or_else(|err| FunctionInsights {
        risks: vec![format!("machine-insight unavailable: {err}")],
        ..Default::default()
    });
    insights.current_stack = 0;

    Ok(DecompileAnalysis {
        kind: "decompile_analysis".to_string(),
        binary: path.to_string_lossy().into_owned(),
        vaddr: format!("0x{vaddr:x}"),
        cfg: analyze_cfg(&function),
        dataflow: analyze_dataflow(path, &function).unwrap_or_else(|err| DataFlowFacts {
            notes: vec![format!("data-flow unavailable: {err}")],
            ..Default::default()
        }),
        function,
        machine: insights,
        references: vec![
            "Reko scanner model: recursive ICFG discovery, procedure clustering, shingled fallback"
                .to_string(),
            "Phoenix: semantics-preserving structural analysis with iterative refinement"
                .to_string(),
            "SAILR: compiler-aware deoptimization before structuring; preserve intended gotos"
                .to_string(),
        ],
    })
}

pub fn decompile_enhanced_path(path: &Path, vaddr: u64) -> Result<String> {
    let analysis = decompile_analysis_path(path, vaddr)?;

    let legacy = tools::dispatch(
        "decompile",
        &serde_json::json!({ "path": path.to_string_lossy(), "vaddr": vaddr }),
    );
    let legacy_text = if legacy.output.starts_with("Error:") {
        format!("legacy decompiler unavailable: {}", legacy.output)
    } else {
        legacy.output
    };

    Ok(render_enhanced(path, vaddr, &analysis, &legacy_text))
}

fn find_function(index: &RecoveryIndex, vaddr: u64) -> Option<&RecoveredFunction> {
    index.functions.iter().find(|function| {
        let Some(start) = parse_addr(&function.start) else {
            return false;
        };
        vaddr == start || (vaddr > start && vaddr < start.saturating_add(function.size))
    })
}

fn analyze_cfg(function: &RecoveredFunction) -> CfgDiagnostics {
    let entry = function.start.clone();
    let mut nodes = BTreeSet::<String>::new();
    for block in &function.blocks {
        nodes.insert(block.start.clone());
    }
    nodes.insert(entry.clone());

    let mut succ = BTreeMap::<String, Vec<String>>::new();
    let mut pred = BTreeMap::<String, Vec<String>>::new();
    for edge in &function.edges {
        nodes.insert(edge.from.clone());
        nodes.insert(edge.to.clone());
        succ.entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        pred.entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }

    let exit_blocks = nodes
        .iter()
        .filter(|node| succ.get(*node).map_or(true, |edges| edges.is_empty()))
        .cloned()
        .collect::<Vec<_>>();
    let back_edges = cfg_back_edges(&entry, &succ);
    let sccs = strongly_connected_components(&nodes, &succ);
    let mut loop_headers = BTreeSet::<String>::new();
    let mut irreducible_sccs = 0usize;
    let mut goto_pressure = 0usize;

    for component in sccs
        .iter()
        .filter(|component| is_cyclic_component(component, &succ))
    {
        let component_set = component.iter().cloned().collect::<BTreeSet<_>>();
        let mut entries = BTreeSet::<String>::new();
        for node in component {
            for predecessor in pred.get(node).into_iter().flatten() {
                if !component_set.contains(predecessor) {
                    entries.insert(node.clone());
                }
            }
        }
        if component_set.contains(&entry) {
            entries.insert(entry.clone());
        }
        if entries.len() <= 1 {
            if let Some(header) = entries
                .iter()
                .next()
                .cloned()
                .or_else(|| component.first().cloned())
            {
                loop_headers.insert(header);
            }
        } else {
            irreducible_sccs += 1;
            goto_pressure += entries.len().saturating_sub(1);
        }
    }

    let reducible = irreducible_sccs == 0;
    let structuring_strategy = if reducible {
        "phoenix-style semantic structuring can proceed without node splitting".to_string()
    } else {
        "apply SAILR-style compiler-aware deoptimization or node splitting before structuring"
            .to_string()
    };

    CfgDiagnostics {
        entry,
        block_count: nodes.len(),
        edge_count: function.edges.len(),
        exit_blocks,
        back_edges,
        loop_headers: loop_headers.into_iter().collect(),
        strongly_connected_components: sccs.len(),
        irreducible_sccs,
        reducible,
        goto_pressure,
        structuring_strategy,
    }
}

#[derive(Default)]
struct BlockFlowTemp {
    predecessors: Vec<String>,
    live_in: BTreeSet<String>,
    defined: BTreeSet<String>,
}

fn analyze_dataflow(path: &Path, function: &RecoveredFunction) -> Result<DataFlowFacts> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::File::parse(&*data).with_context(|| format!("parse {}", path.display()))?;
    let arch = obj.architecture();
    let (bits, architecture, tracked) = match arch {
        Architecture::I386 => (
            32,
            "i386".to_string(),
            vec!["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"],
        ),
        Architecture::X86_64 | Architecture::X86_64_X32 => (
            64,
            "x86_64".to_string(),
            vec![
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10",
            ],
        ),
        _ => {
            return Ok(DataFlowFacts {
                notes: vec![format!(
                    "architecture {arch:?} not supported by data-flow scanner"
                )],
                ..Default::default()
            });
        }
    };
    let tracked = tracked.into_iter().map(str::to_string).collect::<Vec<_>>();
    let tracked_set = tracked.iter().cloned().collect::<BTreeSet<_>>();

    let sections = executable_sections(&obj)?;
    let start = parse_addr(&function.start).ok_or_else(|| anyhow!("bad function start"))?;
    let size = function.size.max(1).min(0x20000);
    let bytes = bytes_at(&sections, start, size)
        .ok_or_else(|| anyhow!("function bytes unavailable at 0x{start:x}"))?;

    let mut predecessors = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in &function.edges {
        predecessors
            .entry(edge.to.clone())
            .or_default()
            .insert(edge.from.clone());
    }

    let mut blocks = function
        .blocks
        .iter()
        .filter_map(|block| {
            Some((
                parse_addr(&block.start)?,
                parse_addr(&block.end)?,
                block.start.clone(),
            ))
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|(start, _, _)| *start);
    if blocks.is_empty() {
        blocks.push((start, start.saturating_add(size), function.start.clone()));
    }

    let mut block_flows = BTreeMap::<String, BlockFlowTemp>::new();
    for (_, _, block) in &blocks {
        let preds = predecessors
            .get(block)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        block_flows.insert(
            block.clone(),
            BlockFlowTemp {
                predecessors: preds,
                ..Default::default()
            },
        );
    }

    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut versions = BTreeMap::<String, u32>::new();
    let mut block_out_versions = BTreeMap::<String, BTreeMap<String, u32>>::new();
    let mut definitions = Vec::new();
    let mut uses = Vec::new();
    let mut instruction_count = 0usize;

    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        let normalized = text.to_ascii_lowercase().replace(' ', "");
        let display = text.replace(',', ", ");
        let block = block_for_ip(ip, &blocks).unwrap_or_else(|| function.start.clone());
        let (used_regs, defined_regs) = dataflow_regs_for_instruction(&normalized, &tracked);
        instruction_count += 1;

        if let Some(flow) = block_flows.get_mut(&block) {
            for reg in &used_regs {
                if !flow.defined.contains(reg) {
                    flow.live_in.insert(reg.clone());
                }
            }
        }

        for reg in used_regs {
            uses.push(RegisterUse {
                vaddr: format!("0x{ip:x}"),
                register: reg.clone(),
                version: versions.get(&reg).copied(),
                instruction: display.clone(),
            });
        }

        if let Some(flow) = block_flows.get_mut(&block) {
            for reg in &defined_regs {
                flow.defined.insert(reg.clone());
            }
        }

        for reg in defined_regs {
            let version = versions.get(&reg).copied().unwrap_or(0).saturating_add(1);
            versions.insert(reg.clone(), version);
            definitions.push(RegisterDefinition {
                vaddr: format!("0x{ip:x}"),
                register: reg,
                version,
                instruction: display.clone(),
            });
        }
        block_out_versions.insert(block, versions.clone());
    }

    let mut block_inputs = block_flows
        .into_iter()
        .map(|(block, flow)| BlockDataFlow {
            block,
            predecessors: flow.predecessors,
            live_in_registers: flow.live_in.into_iter().collect(),
            defined_registers: flow.defined.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    block_inputs.sort_by(|a, b| a.block.cmp(&b.block));

    let mut phi_candidates = Vec::new();
    for block in &block_inputs {
        if block.predecessors.len() < 2 {
            continue;
        }
        for reg in &tracked_set {
            let mut incoming = block
                .predecessors
                .iter()
                .filter_map(|pred| {
                    block_out_versions
                        .get(pred)
                        .and_then(|versions| versions.get(reg).copied())
                        .map(|version| format!("{pred}:{reg}_{version}"))
                })
                .collect::<Vec<_>>();
            incoming.sort();
            incoming.dedup();
            if incoming.len() >= 2 {
                phi_candidates.push(PhiCandidate {
                    block: block.block.clone(),
                    register: reg.clone(),
                    incoming_versions: incoming,
                    reason: "multiple predecessor register versions reach this block".to_string(),
                });
            }
        }
    }

    Ok(DataFlowFacts {
        available: !definitions.is_empty() || !uses.is_empty(),
        architecture,
        instruction_count,
        tracked_registers: tracked,
        definitions,
        uses,
        block_inputs,
        phi_candidates,
        notes: vec![
            "linear register SSA approximation; not dominance-frontier SSA yet".to_string(),
            "memory operands are treated as register uses only; no memory SSA or alias analysis yet"
                .to_string(),
        ],
    })
}

fn block_for_ip(ip: u64, blocks: &[(u64, u64, String)]) -> Option<String> {
    blocks
        .iter()
        .find(|(start, end, _)| ip >= *start && ip < *end)
        .map(|(_, _, label)| label.clone())
}

fn dataflow_regs_for_instruction(
    text: &str,
    tracked: &[String],
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut uses = BTreeSet::new();
    let mut defs = BTreeSet::new();

    if let Some((dst, src)) = split_binary(text, "mov") {
        define_operand(dst, tracked, &mut defs);
        use_operand(src, tracked, &mut uses);
    } else if let Some((dst, src)) = split_binary(text, "lea") {
        define_operand(dst, tracked, &mut defs);
        use_operand(src, tracked, &mut uses);
    } else if let Some((dst, src)) = split_binary(text, "xor") {
        let dst_reg = operand_direct_register(dst, tracked);
        let src_reg = operand_direct_register(src, tracked);
        if dst_reg.is_some() && dst_reg == src_reg {
            if let Some(reg) = dst_reg {
                defs.insert(reg);
            }
        } else {
            use_operand(dst, tracked, &mut uses);
            use_operand(src, tracked, &mut uses);
            define_operand(dst, tracked, &mut defs);
        }
    } else if let Some((dst, src)) = split_binary(text, "add")
        .or_else(|| split_binary(text, "sub"))
        .or_else(|| split_binary(text, "and"))
        .or_else(|| split_binary(text, "or"))
        .or_else(|| split_binary(text, "imul"))
    {
        use_operand(dst, tracked, &mut uses);
        use_operand(src, tracked, &mut uses);
        define_operand(dst, tracked, &mut defs);
    } else if let Some((dst, src)) =
        split_binary(text, "cmp").or_else(|| split_binary(text, "test"))
    {
        use_operand(dst, tracked, &mut uses);
        use_operand(src, tracked, &mut uses);
    } else if let Some(rest) = text.strip_prefix("push") {
        use_operand(rest, tracked, &mut uses);
        if tracked.iter().any(|reg| reg == "rsp") {
            uses.insert("rsp".to_string());
            defs.insert("rsp".to_string());
        } else {
            uses.insert("esp".to_string());
            defs.insert("esp".to_string());
        }
    } else if let Some(rest) = text.strip_prefix("pop") {
        define_operand(rest, tracked, &mut defs);
        if tracked.iter().any(|reg| reg == "rsp") {
            uses.insert("rsp".to_string());
            defs.insert("rsp".to_string());
        } else {
            uses.insert("esp".to_string());
            defs.insert("esp".to_string());
        }
    } else if let Some(rest) = text.strip_prefix("call") {
        use_operand(rest, tracked, &mut uses);
        if tracked.iter().any(|reg| reg == "rsp") {
            uses.extend(
                ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rsp"]
                    .iter()
                    .map(|s| s.to_string()),
            );
            defs.insert("rax".to_string());
        } else {
            uses.insert("esp".to_string());
            defs.insert("eax".to_string());
        }
    } else if text == "syscall" {
        uses.extend(
            ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"]
                .iter()
                .map(|s| s.to_string()),
        );
        defs.insert("rax".to_string());
    } else if text.starts_with("int80") || text == "int0x80" || text == "int80h" {
        uses.extend(
            ["eax", "ebx", "ecx", "edx", "esi", "edi"]
                .iter()
                .map(|s| s.to_string()),
        );
        defs.insert("eax".to_string());
    } else if text.starts_with("ret") {
        if tracked.iter().any(|reg| reg == "rsp") {
            uses.insert("rsp".to_string());
        } else {
            uses.insert("esp".to_string());
        }
    } else {
        use_operand(text, tracked, &mut uses);
    }

    uses.retain(|reg| tracked.iter().any(|tracked_reg| tracked_reg == reg));
    defs.retain(|reg| tracked.iter().any(|tracked_reg| tracked_reg == reg));
    (uses, defs)
}

fn define_operand(operand: &str, tracked: &[String], defs: &mut BTreeSet<String>) {
    if let Some(reg) = operand_direct_register(operand, tracked) {
        defs.insert(reg);
    }
}

fn use_operand(operand: &str, tracked: &[String], uses: &mut BTreeSet<String>) {
    for reg in register_mentions(operand, tracked) {
        uses.insert(reg);
    }
}

fn operand_direct_register(operand: &str, tracked: &[String]) -> Option<String> {
    let reg = full_register(operand.trim()).to_string();
    tracked
        .iter()
        .any(|candidate| candidate == &reg)
        .then_some(reg)
}

fn register_mentions(text: &str, tracked: &[String]) -> Vec<String> {
    let mut found = BTreeSet::new();
    let mut aliases = tracked
        .iter()
        .flat_map(|reg| {
            register_aliases(reg)
                .into_iter()
                .map(move |alias| (alias, reg.clone()))
        })
        .collect::<Vec<_>>();
    aliases.sort_by(|(left, _), (right, _)| right.len().cmp(&left.len()));
    for (alias, full) in aliases {
        for (idx, _) in text.match_indices(alias) {
            let before = idx
                .checked_sub(1)
                .and_then(|pos| text.as_bytes().get(pos).copied());
            let after = text.as_bytes().get(idx + alias.len()).copied();
            if reg_boundary(before) && reg_boundary(after) {
                found.insert(full.clone());
            }
        }
    }
    found.into_iter().collect()
}

fn register_aliases(reg: &str) -> Vec<&'static str> {
    match reg {
        "eax" => vec!["eax", "ax", "al", "ah"],
        "ebx" => vec!["ebx", "bx", "bl", "bh"],
        "ecx" => vec!["ecx", "cx", "cl", "ch"],
        "edx" => vec!["edx", "dx", "dl", "dh"],
        "esi" => vec!["esi", "si"],
        "edi" => vec!["edi", "di"],
        "esp" => vec!["esp", "sp"],
        "ebp" => vec!["ebp", "bp"],
        "rax" => vec!["rax", "eax", "ax", "al", "ah"],
        "rbx" => vec!["rbx", "ebx", "bx", "bl", "bh"],
        "rcx" => vec!["rcx", "ecx", "cx", "cl", "ch"],
        "rdx" => vec!["rdx", "edx", "dx", "dl", "dh"],
        "rsi" => vec!["rsi", "esi", "si"],
        "rdi" => vec!["rdi", "edi", "di"],
        "rsp" => vec!["rsp", "esp", "sp"],
        "rbp" => vec!["rbp", "ebp", "bp"],
        "r8" => vec!["r8", "r8d", "r8w", "r8b"],
        "r9" => vec!["r9", "r9d", "r9w", "r9b"],
        "r10" => vec!["r10", "r10d", "r10w", "r10b"],
        _ => Vec::new(),
    }
}

fn reg_boundary(byte: Option<u8>) -> bool {
    byte.map_or(true, |byte| {
        let c = byte as char;
        !c.is_ascii_alphanumeric() && c != '_'
    })
}

fn cfg_back_edges(entry: &str, succ: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    fn visit(
        node: &str,
        succ: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
        out: &mut Vec<String>,
    ) {
        if !visited.insert(node.to_string()) {
            return;
        }
        visiting.insert(node.to_string());
        for next in succ.get(node).into_iter().flatten() {
            if visiting.contains(next) {
                out.push(format!("{node}->{next}"));
            } else {
                visit(next, succ, visiting, visited, out);
            }
        }
        visiting.remove(node);
    }

    let mut out = Vec::new();
    visit(
        entry,
        succ,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut out,
    );
    out.sort();
    out.dedup();
    out
}

fn strongly_connected_components(
    nodes: &BTreeSet<String>,
    succ: &BTreeMap<String, Vec<String>>,
) -> Vec<Vec<String>> {
    struct Tarjan<'a> {
        succ: &'a BTreeMap<String, Vec<String>>,
        index: usize,
        stack: Vec<String>,
        on_stack: BTreeSet<String>,
        indexes: BTreeMap<String, usize>,
        lowlinks: BTreeMap<String, usize>,
        components: Vec<Vec<String>>,
    }

    impl Tarjan<'_> {
        fn strong_connect(&mut self, node: String) {
            self.indexes.insert(node.clone(), self.index);
            self.lowlinks.insert(node.clone(), self.index);
            self.index += 1;
            self.stack.push(node.clone());
            self.on_stack.insert(node.clone());

            for next in self.succ.get(&node).into_iter().flatten() {
                if !self.indexes.contains_key(next) {
                    self.strong_connect(next.clone());
                    let low = self.lowlinks[&node].min(self.lowlinks[next]);
                    self.lowlinks.insert(node.clone(), low);
                } else if self.on_stack.contains(next) {
                    let low = self.lowlinks[&node].min(self.indexes[next]);
                    self.lowlinks.insert(node.clone(), low);
                }
            }

            if self.lowlinks[&node] == self.indexes[&node] {
                let mut component = Vec::new();
                while let Some(member) = self.stack.pop() {
                    self.on_stack.remove(&member);
                    component.push(member.clone());
                    if member == node {
                        break;
                    }
                }
                component.sort();
                self.components.push(component);
            }
        }
    }

    let mut tarjan = Tarjan {
        succ,
        index: 0,
        stack: Vec::new(),
        on_stack: BTreeSet::new(),
        indexes: BTreeMap::new(),
        lowlinks: BTreeMap::new(),
        components: Vec::new(),
    };
    for node in nodes {
        if !tarjan.indexes.contains_key(node) {
            tarjan.strong_connect(node.clone());
        }
    }
    tarjan.components
}

fn is_cyclic_component(component: &[String], succ: &BTreeMap<String, Vec<String>>) -> bool {
    if component.len() > 1 {
        return true;
    }
    let Some(node) = component.first() else {
        return false;
    };
    succ.get(node)
        .into_iter()
        .flatten()
        .any(|next| next == node)
}

fn render_enhanced(
    path: &Path,
    vaddr: u64,
    analysis: &DecompileAnalysis,
    legacy_text: &str,
) -> String {
    let function = &analysis.function;
    let insights = &analysis.machine;
    let cfg = &analysis.cfg;
    let dataflow = &analysis.dataflow;
    let mut out = String::new();
    out.push_str("/* KaijuLab enhanced decompile context\n");
    out.push_str(&format!("   binary: {}\n", path.display()));
    out.push_str(&format!(
        "   selected: 0x{vaddr:x}  recovered_start: {}  size: {}  confidence: {}\n",
        function.start, function.size, function.confidence
    ));
    if !function.source.is_empty() {
        out.push_str(&format!(
            "   recovery_sources: {}\n",
            function.source.join(", ")
        ));
    }
    out.push_str(&format!(
        "   cfg: {} blocks, {} edges\n",
        function.blocks.len(),
        function.edges.len()
    ));
    out.push_str(&format!(
        "   structuring: reducible={} sccs={} irreducible_sccs={} goto_pressure={} strategy={}\n",
        cfg.reducible,
        cfg.strongly_connected_components,
        cfg.irreducible_sccs,
        cfg.goto_pressure,
        cfg.structuring_strategy
    ));
    if !cfg.loop_headers.is_empty() {
        out.push_str(&format!(
            "     loop_headers: {}\n",
            cfg.loop_headers.join(", ")
        ));
    }
    if !cfg.back_edges.is_empty() {
        out.push_str(&format!("     back_edges: {}\n", cfg.back_edges.join(", ")));
    }
    for block in function.blocks.iter().take(12) {
        out.push_str(&format!(
            "     block {}..{} insns={}\n",
            block.start, block.end, block.instruction_count
        ));
    }
    if function.blocks.len() > 12 {
        out.push_str(&format!(
            "     ... {} more blocks\n",
            function.blocks.len() - 12
        ));
    }
    for edge in function.edges.iter().take(16) {
        out.push_str(&format!(
            "     edge {} -> {} ({})\n",
            edge.from, edge.to, edge.kind
        ));
    }
    if function.edges.len() > 16 {
        out.push_str(&format!(
            "     ... {} more edges\n",
            function.edges.len() - 16
        ));
    }
    out.push_str(&format!(
        "   dataflow: available={} arch={} insns={} defs={} uses={} phi_candidates={}\n",
        dataflow.available,
        dataflow.architecture,
        dataflow.instruction_count,
        dataflow.definitions.len(),
        dataflow.uses.len(),
        dataflow.phi_candidates.len()
    ));
    for phi in dataflow.phi_candidates.iter().take(8) {
        out.push_str(&format!(
            "     phi {} {} <- {}\n",
            phi.block,
            phi.register,
            phi.incoming_versions.join(", ")
        ));
    }

    out.push_str(&format!(
        "   stack_frame: minimum {} bytes from stack-pointer deltas\n",
        insights.frame_size
    ));
    for access in insights.stack_accesses.iter().take(16) {
        out.push_str(&format!("     {access}\n"));
    }
    if insights.stack_accesses.len() > 16 {
        out.push_str(&format!(
            "     ... {} more stack references\n",
            insights.stack_accesses.len() - 16
        ));
    }
    if !insights.calls.is_empty() {
        out.push_str("   calls:\n");
        for call in insights.calls.iter().take(24) {
            out.push_str(&format!("     {call}\n"));
        }
    }
    if !insights.syscalls.is_empty() {
        out.push_str("   syscalls:\n");
        for syscall in &insights.syscalls {
            out.push_str(&format!("     {syscall}\n"));
        }
    }
    if !insights.risks.is_empty() {
        out.push_str("   analysis_notes:\n");
        for risk in &insights.risks {
            out.push_str(&format!("     {risk}\n"));
        }
    }
    out.push_str("*/\n\n");
    out.push_str(legacy_text);
    out
}

fn inspect_function(path: &Path, function: &RecoveredFunction) -> Result<FunctionInsights> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::File::parse(&*data).with_context(|| format!("parse {}", path.display()))?;
    let arch = obj.architecture();
    let bits = match arch {
        Architecture::I386 => 32,
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        _ => return Ok(FunctionInsights::default()),
    };
    let sections = executable_sections(&obj)?;
    let start = parse_addr(&function.start).ok_or_else(|| anyhow!("bad function start"))?;
    let size = function.size.max(1).min(0x20000);
    let bytes = bytes_at(&sections, start, size)
        .ok_or_else(|| anyhow!("function bytes unavailable at 0x{start:x}"))?;

    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut regs = BTreeMap::<String, KnownValue>::new();
    let mut insights = FunctionInsights::default();
    let sp = if bits == 64 { "rsp" } else { "esp" };
    let bp = if bits == 64 { "rbp" } else { "ebp" };

    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        let normalized = text.to_ascii_lowercase().replace(' ', "");

        if normalized.starts_with("sub") {
            if let Some((dst, value)) = parse_reg_imm(&normalized, "sub") {
                if dst == sp {
                    grow_stack(&mut insights, value);
                }
            }
        } else if normalized.starts_with("add") {
            if let Some((dst, value)) = parse_reg_imm(&normalized, "add") {
                if dst == sp {
                    insights.current_stack = insights.current_stack.saturating_sub(value);
                }
            }
        } else if normalized.starts_with("push") {
            grow_stack(&mut insights, (bits / 8) as u64);
        } else if normalized.starts_with("mov") {
            apply_mov(&normalized, &mut regs);
        } else if normalized.starts_with("xor") {
            apply_xor_zero(&normalized, &mut regs);
        } else if normalized.starts_with("lea") {
            apply_lea(&normalized, &mut regs);
        }

        if normalized.starts_with("call") {
            let target = normalized.trim_start_matches("call");
            insights.calls.push(format!(
                "0x{ip:x}: call {}",
                if target.is_empty() { "unknown" } else { target }
            ));
        }

        if normalized.starts_with("int80") || normalized == "int0x80" || normalized == "int80h" {
            let syscall = render_syscall(bits, ip, &regs);
            check_syscall_risk(&syscall, insights.frame_size, &mut insights);
            insights.syscalls.push(syscall);
        } else if normalized == "syscall" {
            let syscall = render_syscall(bits, ip, &regs);
            check_syscall_risk(&syscall, insights.frame_size, &mut insights);
            insights.syscalls.push(syscall);
        }

        collect_stack_access(ip, &normalized, sp, bp, &mut insights);
    }

    insights.stack_accesses.sort();
    insights.stack_accesses.dedup();
    Ok(insights)
}

fn executable_sections(obj: &object::File<'_>) -> Result<Vec<ExecSection>> {
    let mut sections = Vec::new();
    for section in obj.sections() {
        if section.address() == 0 || section.size() == 0 {
            continue;
        }
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(bytes) = section.uncompressed_data() else {
            continue;
        };
        sections.push(ExecSection {
            address: section.address(),
            bytes: bytes.into_owned(),
        });
    }
    Ok(sections)
}

fn grow_stack(insights: &mut FunctionInsights, bytes: u64) {
    insights.current_stack = insights.current_stack.saturating_add(bytes);
    insights.frame_size = insights.frame_size.max(insights.current_stack);
}

fn bytes_at(sections: &[ExecSection], vaddr: u64, size: u64) -> Option<&[u8]> {
    let section = sections.iter().find(|section| {
        vaddr >= section.address
            && vaddr < section.address.saturating_add(section.bytes.len() as u64)
    })?;
    let offset = vaddr.checked_sub(section.address)? as usize;
    let available = section.bytes.len().saturating_sub(offset);
    let len = (size as usize).min(available);
    Some(&section.bytes[offset..offset + len])
}

fn apply_mov(text: &str, regs: &mut BTreeMap<String, KnownValue>) {
    let Some((dst, src)) = split_binary(text, "mov") else {
        return;
    };
    let dst = full_register(dst);
    if !is_register(dst) {
        return;
    }
    let value = if let Some(n) = parse_num(src) {
        KnownValue::Imm(n)
    } else if src == "esp" || src == "rsp" {
        KnownValue::StackPointer
    } else if is_register(src) {
        regs.get(src)
            .cloned()
            .unwrap_or_else(|| KnownValue::Reg(src.to_string()))
    } else {
        KnownValue::Unknown
    };
    regs.insert(dst.to_string(), value);
}

fn apply_xor_zero(text: &str, regs: &mut BTreeMap<String, KnownValue>) {
    let Some((dst, src)) = split_binary(text, "xor") else {
        return;
    };
    let dst = full_register(dst);
    let src = full_register(src);
    if dst == src && is_register(dst) {
        regs.insert(dst.to_string(), KnownValue::Imm(0));
    }
}

fn apply_lea(text: &str, regs: &mut BTreeMap<String, KnownValue>) {
    let Some((dst, src)) = split_binary(text, "lea") else {
        return;
    };
    let dst = full_register(dst);
    if is_register(dst) && (src.contains("[esp") || src.contains("[rsp")) {
        regs.insert(dst.to_string(), KnownValue::StackPointer);
    }
}

fn parse_reg_imm<'a>(text: &'a str, opcode: &str) -> Option<(&'a str, u64)> {
    let (dst, src) = split_binary(text, opcode)?;
    Some((dst, parse_num(src)?))
}

fn split_binary<'a>(text: &'a str, opcode: &str) -> Option<(&'a str, &'a str)> {
    let rest = text.strip_prefix(opcode)?;
    let mut parts = rest.splitn(2, ',');
    let dst = parts.next()?.trim();
    let src = parts.next()?.trim();
    Some((dst, src))
}

fn collect_stack_access(ip: u64, text: &str, sp: &str, bp: &str, insights: &mut FunctionInsights) {
    let stack_ref = text.contains(&format!("[{sp}"))
        || text.contains(&format!("[{bp}"))
        || text.contains(&format!("[e{}]", &sp[1..]))
        || text.contains(&format!("[e{}]", &bp[1..]));
    if stack_ref {
        insights
            .stack_accesses
            .push(format!("0x{ip:x}: {}", text.replace(',', ", ")));
    }
}

fn render_syscall(bits: u32, ip: u64, regs: &BTreeMap<String, KnownValue>) -> String {
    if bits == 32 {
        let nr = value_for(regs, &["eax"]);
        let name = nr.and_then(syscall_name_i386).unwrap_or("unknown");
        let args = [
            ("ebx", value_label(regs, "ebx")),
            ("ecx", value_label(regs, "ecx")),
            ("edx", value_label(regs, "edx")),
            ("esi", value_label(regs, "esi")),
            ("edi", value_label(regs, "edi")),
        ];
        format!(
            "0x{ip:x}: int 0x80 {}({})",
            syscall_number_label(nr, name),
            args.iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        let nr = value_for(regs, &["rax", "eax"]);
        let name = nr.and_then(syscall_name_x86_64).unwrap_or("unknown");
        let args = [
            ("rdi", value_label(regs, "rdi")),
            ("rsi", value_label(regs, "rsi")),
            ("rdx", value_label(regs, "rdx")),
            ("r10", value_label(regs, "r10")),
            ("r8", value_label(regs, "r8")),
            ("r9", value_label(regs, "r9")),
        ];
        format!(
            "0x{ip:x}: syscall {}({})",
            syscall_number_label(nr, name),
            args.iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn check_syscall_risk(syscall: &str, frame_size: u64, insights: &mut FunctionInsights) {
    if !(syscall.contains("read") || syscall.contains("recv")) {
        return;
    }
    let reads_stack = syscall.contains("ecx=sp") || syscall.contains("rsi=sp");
    let Some(count) =
        extract_named_imm(syscall, "edx").or_else(|| extract_named_imm(syscall, "rdx"))
    else {
        return;
    };
    if reads_stack && frame_size > 0 && count > frame_size {
        insights.risks.push(format!(
            "stack read overflow candidate: count {count} exceeds recovered stack allocation {frame_size}"
        ));
    }
}

fn extract_named_imm(text: &str, name: &str) -> Option<u64> {
    let needle = format!("{name}=0x");
    let pos = text.find(&needle)?;
    let start = pos + needle.len();
    let end = text[start..]
        .find(|c: char| !c.is_ascii_hexdigit())
        .map(|rel| start + rel)
        .unwrap_or(text.len());
    u64::from_str_radix(&text[start..end], 16).ok()
}

fn syscall_number_label(nr: Option<u64>, name: &str) -> String {
    nr.map(|n| format!("{name}#{n}"))
        .unwrap_or_else(|| name.to_string())
}

fn syscall_name_i386(nr: u64) -> Option<&'static str> {
    Some(match nr {
        1 => "exit",
        3 => "read",
        4 => "write",
        5 => "open",
        11 => "execve",
        45 => "brk",
        90 => "mmap",
        91 => "munmap",
        125 => "mprotect",
        _ => return None,
    })
}

fn syscall_name_x86_64(nr: u64) -> Option<&'static str> {
    Some(match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        59 => "execve",
        60 => "exit",
        231 => "exit_group",
        _ => return None,
    })
}

fn value_for(regs: &BTreeMap<String, KnownValue>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| match regs.get(*name) {
        Some(KnownValue::Imm(n)) => Some(*n),
        _ => None,
    })
}

fn value_label(regs: &BTreeMap<String, KnownValue>, name: &str) -> String {
    let value = regs
        .get(name)
        .or_else(|| alias(name).and_then(|alias| regs.get(alias)));
    match value {
        Some(KnownValue::Imm(n)) => format!("0x{n:x}"),
        Some(KnownValue::Reg(reg)) => reg.clone(),
        Some(KnownValue::StackPointer) => "sp".to_string(),
        Some(KnownValue::Unknown) | None => "?".to_string(),
    }
}

fn alias(name: &str) -> Option<&'static str> {
    Some(match name {
        "rax" => "eax",
        "rdi" => "edi",
        "rsi" => "esi",
        "rdx" => "edx",
        _ => return None,
    })
}

fn is_register(name: &str) -> bool {
    matches!(
        name,
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "esp"
            | "ebp"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rsp"
            | "rbp"
            | "r8"
            | "r9"
            | "r10"
            | "al"
            | "bl"
            | "cl"
            | "dl"
    )
}

fn full_register(name: &str) -> &str {
    match name {
        "al" | "ah" | "ax" => "eax",
        "bl" | "bh" | "bx" => "ebx",
        "cl" | "ch" | "cx" => "ecx",
        "dl" | "dh" | "dx" => "edx",
        _ => name,
    }
}

fn parse_num(text: &str) -> Option<u64> {
    let mut s = text.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = s.strip_suffix('h') {
        if hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return u64::from_str_radix(hex, 16).ok();
        }
    }
    if s.starts_with('-') {
        return None;
    }
    s = s.trim_start_matches('+');
    s.parse::<u64>().ok()
}

fn parse_addr(text: &str) -> Option<u64> {
    parse_num(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_sample_reports_syscalls_and_stack_overflow() {
        let path = Path::new("samples/PwnableTW/Start/start");
        if !path.exists() {
            return;
        }
        let text = decompile_enhanced_path(path, 0x8048060).expect("enhanced decompile");
        assert!(text.contains("recovered_start: 0x8048060"));
        assert!(text.contains("write#4"));
        assert!(text.contains("read#3"));
        assert!(text.contains("edx=0x3c"));
        assert!(text.contains("stack read overflow candidate"));
        assert!(text.contains("dataflow: available=true"));

        let analysis = decompile_analysis_path(path, 0x8048060).expect("structured analysis");
        assert!(analysis.dataflow.available);
        assert!(
            analysis
                .dataflow
                .definitions
                .iter()
                .any(|def| def.register == "eax")
        );
        assert!(
            analysis
                .dataflow
                .uses
                .iter()
                .any(|use_| use_.register == "esp")
        );
    }
}
