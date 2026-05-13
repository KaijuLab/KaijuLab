//! Recovery-backed decompile context.
//!
//! The legacy pseudo-C renderer still owns expression rendering. This module
//! feeds it better recovered function facts and adds machine-level context that
//! exploit agents need: CFG blocks, stack-frame hints, calls, and syscalls.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic, OpKind, Register};
use object::{Architecture, Object, ObjectSection};
use serde::Serialize;

use crate::{decompiler::ir::kir, tools};

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
    pub kir: kir::KirFunction,
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
    pub memory_accesses: Vec<MemoryAccess>,
    pub variable_candidates: Vec<VariableCandidate>,
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
pub struct MemoryAccess {
    pub vaddr: String,
    pub kind: String,
    pub access: String,
    pub location: String,
    pub base: Option<String>,
    pub offset: Option<i64>,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariableCandidate {
    pub name: String,
    pub kind: String,
    pub location: String,
    pub access_count: usize,
    pub first_seen: String,
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
    pub functions_with_kir: usize,
    pub functions_with_kir_ssa: usize,
    pub total_kir_ops: usize,
    pub total_kir_ssa_definitions: usize,
    pub total_kir_ssa_uses: usize,
    pub total_kir_phi_nodes: usize,
    pub total_phi_candidates: usize,
    pub total_memory_accesses: usize,
    pub total_variable_candidates: usize,
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
    pub has_kir: bool,
    pub has_kir_ssa: bool,
    pub kir_ops: usize,
    pub kir_ssa_definitions: usize,
    pub kir_phi_nodes: usize,
    pub memory_accesses: usize,
    pub variable_candidates: usize,
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
    let mut functions_with_kir = 0usize;
    let mut functions_with_kir_ssa = 0usize;
    let mut total_kir_ops = 0usize;
    let mut total_kir_ssa_definitions = 0usize;
    let mut total_kir_ssa_uses = 0usize;
    let mut total_kir_phi_nodes = 0usize;
    let mut total_phi_candidates = 0usize;
    let mut total_memory_accesses = 0usize;
    let mut total_variable_candidates = 0usize;
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
        let kir = lift_kir(path, function).unwrap_or_else(|err| kir::KirFunction {
            diagnostics: vec![format!("kir unavailable: {err}")],
            ..Default::default()
        });
        let has_machine_facts = !machine.calls.is_empty()
            || !machine.syscalls.is_empty()
            || !machine.stack_accesses.is_empty()
            || machine.frame_size > 0;
        let has_dataflow_facts = dataflow.available && !dataflow.definitions.is_empty();
        let has_kir = kir.available && !kir.ops.is_empty();
        let has_kir_ssa = kir.ssa.available && kir.ssa.definition_count > 0;
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
        if has_kir {
            functions_with_kir += 1;
        }
        if has_kir_ssa {
            functions_with_kir_ssa += 1;
        }
        total_kir_ops += kir.ops.len();
        total_kir_ssa_definitions += kir.ssa.definition_count;
        total_kir_ssa_uses += kir.ssa.use_count;
        total_kir_phi_nodes += kir.ssa.phi_count;
        total_phi_candidates += dataflow.phi_candidates.len();
        total_memory_accesses += dataflow.memory_accesses.len();
        total_variable_candidates += dataflow.variable_candidates.len();
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
        if !has_kir {
            notes.push("KIR unavailable or empty".to_string());
        }
        if !kir.diagnostics.is_empty() {
            notes.extend(kir.diagnostics.clone());
        }
        if !has_kir_ssa {
            notes.push("KIR SSA unavailable or empty".to_string());
        }
        if !kir.ssa.diagnostics.is_empty() {
            notes.extend(kir.ssa.diagnostics.clone());
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
            has_kir,
            has_kir_ssa,
            kir_ops: kir.ops.len(),
            kir_ssa_definitions: kir.ssa.definition_count,
            kir_phi_nodes: kir.ssa.phi_count,
            memory_accesses: dataflow.memory_accesses.len(),
            variable_candidates: dataflow.variable_candidates.len(),
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
        functions_with_kir,
        functions_with_kir_ssa,
        total_variable_candidates,
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
        functions_with_kir,
        functions_with_kir_ssa,
        total_variable_candidates,
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
        functions_with_kir,
        functions_with_kir_ssa,
        total_kir_ops,
        total_kir_ssa_definitions,
        total_kir_ssa_uses,
        total_kir_phi_nodes,
        total_phi_candidates,
        total_memory_accesses,
        total_variable_candidates,
        total_blocks,
        total_edges,
        total_irreducible_sccs,
        total_goto_pressure,
        function_reports,
        blockers,
        next_engine_work: vec![
            "Replace text-parse machine facts with lifted IR data-flow facts".to_string(),
            "Use KIR SSA versions in expression DAG rendering".to_string(),
            "Promote heuristic stack/global variable candidates into memory SSA".to_string(),
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
    kir_facts: usize,
    kir_ssa_facts: usize,
    variable_candidates: usize,
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
    let kir_score = 10.0 * kir_facts as f64 / analyzed;
    let kir_ssa_score = 10.0 * kir_ssa_facts as f64 / analyzed;
    let dataflow_score = 10.0 * dataflow_facts as f64 / analyzed;
    let variable_score = 10.0 * (variable_candidates.min(analyzed_functions) as f64) / analyzed;
    let structuring_penalty =
        (irreducible_sccs as f64 * 5.0 + goto_pressure as f64 * 2.0).min(20.0);
    let foundation_score = 25.0;
    let surface_score = (recovery_score
        + legacy_score
        + reducible_score
        + machine_score
        + kir_score
        + kir_ssa_score
        + dataflow_score
        + variable_score
        + foundation_score
        - structuring_penalty)
        .round()
        .clamp(0.0, 100.0) as u32;
    // Register and memory facts are still pre-IR facts, not production
    // decompiler semantics. Keep the cap explicit until memory SSA and type
    // propagation are part of the scored engine.
    let cap = if variable_candidates > 0 && kir_ssa_facts > 0 {
        80
    } else if variable_candidates > 0 && kir_facts > 0 {
        70
    } else if variable_candidates > 0 {
        65
    } else if dataflow_facts > 0 {
        55
    } else {
        45
    };
    surface_score.min(cap)
}

fn decompiler_blockers(
    recovered_functions: usize,
    analyzed_functions: usize,
    legacy_ok: usize,
    reducible: usize,
    machine_facts: usize,
    dataflow_facts: usize,
    kir_facts: usize,
    kir_ssa_facts: usize,
    variable_candidates: usize,
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
    if kir_facts < analyzed_functions {
        blockers.push("KIR lifter coverage is incomplete".to_string());
    }
    if kir_ssa_facts < analyzed_functions {
        blockers.push("KIR SSA coverage is incomplete".to_string());
    }
    if dataflow_facts == 0 {
        blockers.push("no data-flow quality gate yet".to_string());
        blockers.push("score is capped at 45 until SSA/data-flow/type inference land".to_string());
    } else if variable_candidates == 0 {
        blockers.push(
            "data-flow gate has register SSA but no stack/global variable candidates yet"
                .to_string(),
        );
        blockers.push("score is capped at 55 until memory facts land".to_string());
    } else {
        blockers.push(
            "memory facts are heuristic stack/global candidates only; no memory SSA/type inference yet"
                .to_string(),
        );
        if kir_ssa_facts > 0 {
            blockers.push(
                "score is capped at 80 until KIR expression rendering/memory SSA/type inference land"
                    .to_string(),
            );
        } else if kir_facts > 0 {
            blockers.push(
                "score is capped at 70 until KIR-backed SSA/memory SSA/type inference land"
                    .to_string(),
            );
        } else {
            blockers.push("score is capped at 65 until memory SSA/type inference land".to_string());
        }
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
        kir: lift_kir(path, &function).unwrap_or_else(|err| kir::KirFunction {
            diagnostics: vec![format!("kir unavailable: {err}")],
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
    if let Some(exact) = index
        .functions
        .iter()
        .find(|function| parse_addr(&function.start) == Some(vaddr))
    {
        return Some(exact);
    }

    index
        .functions
        .iter()
        .filter(|function| {
            let Some(start) = parse_addr(&function.start) else {
                return false;
            };
            vaddr > start && vaddr < start.saturating_add(function.size)
        })
        .min_by_key(|function| function.size)
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
    let mut memory_accesses = Vec::new();
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
        memory_accesses.extend(memory_accesses_for_instruction(ip, &normalized, &display));
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
    let variable_candidates = variable_candidates_from_memory(&memory_accesses);

    Ok(DataFlowFacts {
        available: !definitions.is_empty() || !uses.is_empty(),
        architecture,
        instruction_count,
        tracked_registers: tracked,
        definitions,
        uses,
        memory_accesses,
        variable_candidates,
        block_inputs,
        phi_candidates,
        notes: vec![
            "linear register SSA approximation; not dominance-frontier SSA yet".to_string(),
            "memory operands produce stack/global variable candidates; no memory SSA or alias analysis yet"
                .to_string(),
        ],
    })
}

fn lift_kir(path: &Path, function: &RecoveredFunction) -> Result<kir::KirFunction> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::File::parse(&*data).with_context(|| format!("parse {}", path.display()))?;
    let arch = obj.architecture();
    let (bits, architecture) = match arch {
        Architecture::I386 => (32, "i386".to_string()),
        Architecture::X86_64 | Architecture::X86_64_X32 => (64, "x86_64".to_string()),
        _ => {
            return Ok(kir::KirFunction {
                diagnostics: vec![format!("architecture {arch:?} not supported by KIR lifter")],
                ..Default::default()
            });
        }
    };

    let sections = executable_sections(&obj)?;
    let start = parse_addr(&function.start).ok_or_else(|| anyhow!("bad function start"))?;
    let size = function.size.max(1).min(0x20000);
    let bytes = bytes_at(&sections, start, size)
        .ok_or_else(|| anyhow!("function bytes unavailable at 0x{start:x}"))?;
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

    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut ops = Vec::new();
    let mut block_ops = BTreeMap::<String, Vec<usize>>::new();
    let mut instruction_count = 0usize;

    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        let id = ops.len();
        let block = block_for_ip(ip, &blocks).unwrap_or_else(|| function.start.clone());
        block_ops.entry(block).or_default().push(id);
        ops.push(kir_op_from_instruction(id, ip, &text, &instr));
        instruction_count += 1;
    }

    let blocks = blocks
        .into_iter()
        .map(|(_, _, start)| kir::KirBlock {
            op_ids: block_ops.remove(&start).unwrap_or_default(),
            start,
        })
        .collect::<Vec<_>>();

    let mut function_kir = kir::KirFunction {
        available: !ops.is_empty(),
        architecture,
        entry: function.start.clone(),
        instruction_count,
        op_count: ops.len(),
        blocks,
        ops,
        ssa: kir::KirSsaFacts::default(),
        diagnostics: vec![
            "KIR v0: iced-x86 semantic skeleton; flags and precise operand sizes are partial"
                .to_string(),
        ],
    };
    function_kir.ssa = analyze_kir_ssa(&function_kir, function);
    Ok(function_kir)
}

#[derive(Default)]
struct KirBlockSsaTemp {
    predecessors: Vec<String>,
    live_in: BTreeSet<String>,
    defined: BTreeSet<String>,
}

fn analyze_kir_ssa(
    kir_function: &kir::KirFunction,
    function: &RecoveredFunction,
) -> kir::KirSsaFacts {
    if kir_function.ops.is_empty() {
        return kir::KirSsaFacts {
            diagnostics: vec!["KIR SSA unavailable: no KIR ops".to_string()],
            ..Default::default()
        };
    }

    let mut block_ranges = function
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
    block_ranges.sort_by_key(|(start, _, _)| *start);

    let mut op_to_block = BTreeMap::<usize, String>::new();
    for block in &kir_function.blocks {
        for op_id in &block.op_ids {
            op_to_block.insert(*op_id, block.start.clone());
        }
    }

    let mut predecessors = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in &function.edges {
        let from = parse_addr(&edge.from)
            .and_then(|addr| block_for_ip(addr, &block_ranges))
            .unwrap_or_else(|| edge.from.clone());
        let to = parse_addr(&edge.to)
            .and_then(|addr| block_for_ip(addr, &block_ranges))
            .unwrap_or_else(|| edge.to.clone());
        predecessors.entry(to).or_default().insert(from);
    }

    let mut block_states = BTreeMap::<String, KirBlockSsaTemp>::new();
    for block in &kir_function.blocks {
        block_states.insert(
            block.start.clone(),
            KirBlockSsaTemp {
                predecessors: predecessors
                    .get(&block.start)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        );
    }
    let block_labels = kir_function
        .blocks
        .iter()
        .map(|block| block.start.clone())
        .collect::<Vec<_>>();
    let successors = kir_successors(function, &block_labels, &block_ranges);
    let dominators = kir_dominators(&block_labels, &kir_function.entry, &predecessors);
    let immediate_dominators =
        kir_immediate_dominators(&block_labels, &kir_function.entry, &dominators);
    let dominance_frontiers =
        kir_dominance_frontiers(&block_labels, &predecessors, &immediate_dominators);

    let mut op_reads = BTreeMap::<usize, BTreeSet<String>>::new();
    let mut op_writes = BTreeMap::<usize, BTreeSet<String>>::new();
    let mut block_definitions = BTreeMap::<String, BTreeSet<String>>::new();
    for op in &kir_function.ops {
        let block = op_to_block
            .get(&op.id)
            .cloned()
            .unwrap_or_else(|| kir_function.entry.clone());
        let read_regs = kir_read_registers(op, &kir_function.architecture);
        let write_regs = kir_write_registers(op, &kir_function.architecture);
        op_reads.insert(op.id, read_regs);
        block_definitions
            .entry(block)
            .or_default()
            .extend(write_regs.iter().cloned());
        op_writes.insert(op.id, write_regs);
    }
    let phi_blocks = kir_phi_blocks(&block_labels, &block_definitions, &dominance_frontiers);

    let mut versions = BTreeMap::<String, u32>::new();
    let mut block_out_versions = BTreeMap::<String, BTreeMap<String, u32>>::new();
    let mut definitions = Vec::new();
    let mut uses = Vec::new();
    let mut phi_nodes = Vec::new();
    let mut initialized_blocks = BTreeSet::<String>::new();

    for op in &kir_function.ops {
        let block = op_to_block
            .get(&op.id)
            .cloned()
            .unwrap_or_else(|| kir_function.entry.clone());
        if initialized_blocks.insert(block.clone()) {
            apply_kir_phi_definitions(
                &block,
                &phi_blocks,
                &block_states,
                &block_out_versions,
                &mut versions,
                &mut definitions,
                &mut phi_nodes,
            );
            if let (Some(candidates), Some(state)) =
                (phi_blocks.get(&block), block_states.get_mut(&block))
            {
                state.defined.extend(candidates.iter().cloned());
            }
        }
        let read_regs = op_reads.get(&op.id).cloned().unwrap_or_default();
        let write_regs = op_writes.get(&op.id).cloned().unwrap_or_default();

        if let Some(state) = block_states.get_mut(&block) {
            for reg in &read_regs {
                if !state.defined.contains(reg) {
                    state.live_in.insert(reg.clone());
                }
            }
        }

        for reg in read_regs {
            uses.push(kir::KirSsaUse {
                op_id: op.id,
                vaddr: op.vaddr.clone(),
                name: reg.clone(),
                version: versions.get(&reg).copied(),
                source: op.instruction.clone(),
            });
        }

        if let Some(state) = block_states.get_mut(&block) {
            for reg in &write_regs {
                state.defined.insert(reg.clone());
            }
        }

        for reg in write_regs {
            let version = versions.get(&reg).copied().unwrap_or(0).saturating_add(1);
            versions.insert(reg.clone(), version);
            definitions.push(kir::KirSsaDefinition {
                op_id: op.id,
                vaddr: op.vaddr.clone(),
                name: reg,
                version,
                source: op.instruction.clone(),
            });
        }
        block_out_versions.insert(block, versions.clone());
    }

    let mut block_state_facts = block_states
        .into_iter()
        .map(|(block, state)| {
            let out_versions = block_out_versions
                .get(&block)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|(name, version)| kir::KirRegisterVersion { name, version })
                .collect::<Vec<_>>();
            kir::KirBlockSsa {
                immediate_dominator: immediate_dominators.get(&block).cloned().flatten(),
                dominance_frontier: dominance_frontiers
                    .get(&block)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                block,
                predecessors: state.predecessors,
                live_in: state.live_in.into_iter().collect(),
                defined: state.defined.into_iter().collect(),
                out_versions,
            }
        })
        .collect::<Vec<_>>();
    block_state_facts.sort_by(|a, b| a.block.cmp(&b.block));

    kir::KirSsaFacts {
        available: !definitions.is_empty() || !uses.is_empty(),
        dominance_available: !dominators.is_empty()
            && successors.keys().any(|block| {
                dominance_frontiers
                    .get(block)
                    .is_some_and(|frontier| !frontier.is_empty())
            }),
        definition_count: definitions.len(),
        use_count: uses.len(),
        phi_count: phi_nodes.len(),
        definitions,
        uses,
        block_states: block_state_facts,
        phi_nodes,
        diagnostics: vec![
            "KIR SSA v2: alias-aware register rename with dominance-frontier phi definitions"
                .to_string(),
        ],
    }
}

fn apply_kir_phi_definitions(
    block: &str,
    phi_blocks: &BTreeMap<String, BTreeSet<String>>,
    block_states: &BTreeMap<String, KirBlockSsaTemp>,
    block_out_versions: &BTreeMap<String, BTreeMap<String, u32>>,
    versions: &mut BTreeMap<String, u32>,
    definitions: &mut Vec<kir::KirSsaDefinition>,
    phi_nodes: &mut Vec<kir::KirPhiNode>,
) {
    let Some(candidates) = phi_blocks.get(block) else {
        return;
    };
    let Some(state) = block_states.get(block) else {
        return;
    };
    if state.predecessors.len() < 2 {
        return;
    }

    for name in candidates {
        let mut incoming_versions = state
            .predecessors
            .iter()
            .filter_map(|predecessor| {
                block_out_versions
                    .get(predecessor)
                    .and_then(|out| out.get(name).copied())
                    .map(|version| format!("{predecessor}:{name}_{version}"))
            })
            .collect::<Vec<_>>();
        incoming_versions.sort();
        incoming_versions.dedup();
        if incoming_versions.len() < 2 {
            continue;
        }

        let version = versions.get(name).copied().unwrap_or(0).saturating_add(1);
        versions.insert(name.clone(), version);
        definitions.push(kir::KirSsaDefinition {
            op_id: usize::MAX,
            vaddr: block.to_string(),
            name: name.clone(),
            version,
            source: format!("phi({})", incoming_versions.join(", ")),
        });
        phi_nodes.push(kir::KirPhiNode {
            block: block.to_string(),
            name: name.clone(),
            version,
            incoming_versions,
            reason: "dominance-frontier KIR phi definition".to_string(),
        });
    }
}

fn kir_successors(
    function: &RecoveredFunction,
    block_labels: &[String],
    block_ranges: &[(u64, u64, String)],
) -> BTreeMap<String, BTreeSet<String>> {
    let known_blocks = block_labels.iter().cloned().collect::<BTreeSet<_>>();
    let mut successors = known_blocks
        .iter()
        .map(|block| (block.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for edge in &function.edges {
        let from = parse_addr(&edge.from)
            .and_then(|addr| block_for_ip(addr, block_ranges))
            .unwrap_or_else(|| edge.from.clone());
        let to = parse_addr(&edge.to)
            .and_then(|addr| block_for_ip(addr, block_ranges))
            .unwrap_or_else(|| edge.to.clone());
        if known_blocks.contains(&from) && known_blocks.contains(&to) {
            successors.entry(from).or_default().insert(to);
        }
    }
    successors
}

fn kir_dominators(
    block_labels: &[String],
    entry: &str,
    predecessors: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let all = block_labels.iter().cloned().collect::<BTreeSet<_>>();
    let mut dominators = block_labels
        .iter()
        .map(|block| {
            let set = if block == entry {
                BTreeSet::from([block.clone()])
            } else {
                all.clone()
            };
            (block.clone(), set)
        })
        .collect::<BTreeMap<_, _>>();

    let mut changed = true;
    while changed {
        changed = false;
        for block in block_labels {
            if block == entry {
                continue;
            }
            let preds = predecessors
                .get(block)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|pred| dominators.contains_key(pred))
                .collect::<Vec<_>>();
            let mut new_set = if preds.is_empty() {
                BTreeSet::new()
            } else {
                let mut iter = preds.iter();
                let first = iter
                    .next()
                    .and_then(|pred| dominators.get(pred))
                    .cloned()
                    .unwrap_or_default();
                iter.fold(first, |acc, pred| {
                    acc.intersection(dominators.get(pred).unwrap_or(&BTreeSet::new()))
                        .cloned()
                        .collect()
                })
            };
            new_set.insert(block.clone());
            if dominators.get(block) != Some(&new_set) {
                dominators.insert(block.clone(), new_set);
                changed = true;
            }
        }
    }
    dominators
}

fn kir_immediate_dominators(
    block_labels: &[String],
    entry: &str,
    dominators: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, Option<String>> {
    let mut out = BTreeMap::new();
    for block in block_labels {
        if block == entry {
            out.insert(block.clone(), None);
            continue;
        }
        let candidates = dominators
            .get(block)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|candidate| candidate != block)
            .collect::<Vec<_>>();
        let idom = candidates.iter().find(|candidate| {
            !candidates.iter().any(|other| {
                other != *candidate
                    && dominators
                        .get(other)
                        .is_some_and(|other_doms| other_doms.contains(*candidate))
            })
        });
        out.insert(block.clone(), idom.cloned());
    }
    out
}

fn kir_dominance_frontiers(
    block_labels: &[String],
    predecessors: &BTreeMap<String, BTreeSet<String>>,
    immediate_dominators: &BTreeMap<String, Option<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut frontiers = block_labels
        .iter()
        .map(|block| (block.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for block in block_labels {
        let preds = predecessors.get(block).cloned().unwrap_or_default();
        if preds.len() < 2 {
            continue;
        }
        let stop = immediate_dominators.get(block).cloned().flatten();
        for predecessor in preds {
            let mut runner = predecessor;
            while Some(runner.clone()) != stop {
                frontiers
                    .entry(runner.clone())
                    .or_default()
                    .insert(block.clone());
                let Some(Some(next)) = immediate_dominators.get(&runner) else {
                    break;
                };
                if *next == runner {
                    break;
                }
                runner = next.clone();
            }
        }
    }
    frontiers
}

fn kir_phi_blocks(
    block_labels: &[String],
    block_definitions: &BTreeMap<String, BTreeSet<String>>,
    dominance_frontiers: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut def_blocks_by_reg = BTreeMap::<String, BTreeSet<String>>::new();
    for (block, definitions) in block_definitions {
        for reg in definitions {
            def_blocks_by_reg
                .entry(reg.clone())
                .or_default()
                .insert(block.clone());
        }
    }

    let known_blocks = block_labels.iter().cloned().collect::<BTreeSet<_>>();
    let mut phi_blocks = BTreeMap::<String, BTreeSet<String>>::new();
    for (reg, def_blocks) in def_blocks_by_reg {
        let mut work = def_blocks.iter().cloned().collect::<Vec<_>>();
        let mut seen = def_blocks;
        let mut placed = BTreeSet::<String>::new();
        while let Some(block) = work.pop() {
            for frontier in dominance_frontiers.get(&block).cloned().unwrap_or_default() {
                if !known_blocks.contains(&frontier) || !placed.insert(frontier.clone()) {
                    continue;
                }
                phi_blocks
                    .entry(frontier.clone())
                    .or_default()
                    .insert(reg.clone());
                if seen.insert(frontier.clone()) {
                    work.push(frontier);
                }
            }
        }
    }
    phi_blocks
}

fn kir_read_registers(op: &kir::KirOp, architecture: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for value in &op.inputs {
        collect_kir_value_registers(value, architecture, &mut out);
    }
    for effect in &op.effects {
        if let kir::KirEffect::ReadRegister(name) = effect {
            out.insert(kir_canonical_register(name, architecture));
        }
    }
    out
}

fn kir_write_registers(op: &kir::KirOp, architecture: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for value in &op.outputs {
        if let kir::KirValue::Register { name, .. } = value {
            out.insert(kir_canonical_register(name, architecture));
        }
    }
    for effect in &op.effects {
        if let kir::KirEffect::WriteRegister(name) = effect {
            out.insert(kir_canonical_register(name, architecture));
        }
    }
    out
}

fn collect_kir_value_registers(
    value: &kir::KirValue,
    architecture: &str,
    out: &mut BTreeSet<String>,
) {
    match value {
        kir::KirValue::Register { name, .. } => {
            out.insert(kir_canonical_register(name, architecture));
        }
        kir::KirValue::Memory { base, index, .. } => {
            if let Some(base) = base {
                out.insert(kir_canonical_register(base, architecture));
            }
            if let Some(index) = index {
                out.insert(kir_canonical_register(index, architecture));
            }
        }
        _ => {}
    }
}

fn kir_canonical_register(name: &str, architecture: &str) -> String {
    let name = name.to_ascii_lowercase();
    let wide = architecture.contains("64");
    let canonical = match name.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => {
            if wide {
                "rax"
            } else {
                "eax"
            }
        }
        "bl" | "bh" | "bx" | "ebx" | "rbx" => {
            if wide {
                "rbx"
            } else {
                "ebx"
            }
        }
        "cl" | "ch" | "cx" | "ecx" | "rcx" => {
            if wide {
                "rcx"
            } else {
                "ecx"
            }
        }
        "dl" | "dh" | "dx" | "edx" | "rdx" => {
            if wide {
                "rdx"
            } else {
                "edx"
            }
        }
        "si" | "esi" | "rsi" => {
            if wide {
                "rsi"
            } else {
                "esi"
            }
        }
        "di" | "edi" | "rdi" => {
            if wide {
                "rdi"
            } else {
                "edi"
            }
        }
        "sp" | "esp" | "rsp" => {
            if wide {
                "rsp"
            } else {
                "esp"
            }
        }
        "bp" | "ebp" | "rbp" => {
            if wide {
                "rbp"
            } else {
                "ebp"
            }
        }
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        "r10b" | "r10w" | "r10d" | "r10" => "r10",
        "r11b" | "r11w" | "r11d" | "r11" => "r11",
        "r12b" | "r12w" | "r12d" | "r12" => "r12",
        "r13b" | "r13w" | "r13d" | "r13" => "r13",
        "r14b" | "r14w" | "r14d" | "r14" => "r14",
        "r15b" | "r15w" | "r15d" | "r15" => "r15",
        _ => name.as_str(),
    };
    canonical.to_string()
}

fn kir_op_from_instruction(
    id: usize,
    ip: u64,
    text: &str,
    instr: &iced_x86::Instruction,
) -> kir::KirOp {
    let mnemonic = instr.mnemonic();
    let opcode = kir_opcode(mnemonic, instr);
    let mut operands = (0..instr.op_count())
        .map(|index| kir_value_for_operand(instr, index, text))
        .collect::<Vec<_>>();
    let mut outputs = Vec::new();
    let mut inputs = Vec::new();
    let mut effects = Vec::new();

    match opcode {
        kir::KirOpcode::Store => {
            if let Some(dst) = operands.first().cloned() {
                outputs.push(dst);
                effects.push(kir::KirEffect::WriteMemory);
            }
            inputs.extend(operands.into_iter().skip(1));
        }
        kir::KirOpcode::Load | kir::KirOpcode::Copy | kir::KirOpcode::AddressOf => {
            if let Some(dst) = operands.first().cloned() {
                if let kir::KirValue::Register { name, .. } = &dst {
                    effects.push(kir::KirEffect::WriteRegister(name.clone()));
                }
                outputs.push(dst);
            }
            for input in operands.into_iter().skip(1) {
                collect_kir_read_effects(&input, &mut effects);
                inputs.push(input);
            }
        }
        kir::KirOpcode::IntAdd
        | kir::KirOpcode::IntSub
        | kir::KirOpcode::IntMul
        | kir::KirOpcode::IntAnd
        | kir::KirOpcode::IntOr
        | kir::KirOpcode::IntXor => {
            if let Some(dst) = operands.first().cloned() {
                collect_kir_read_effects(&dst, &mut effects);
                if let kir::KirValue::Register { name, .. } = &dst {
                    effects.push(kir::KirEffect::WriteRegister(name.clone()));
                }
                outputs.push(dst.clone());
                inputs.push(dst);
            }
            for input in operands.into_iter().skip(1) {
                collect_kir_read_effects(&input, &mut effects);
                inputs.push(input);
            }
            effects.push(kir::KirEffect::ClobberFlags);
        }
        kir::KirOpcode::Compare => {
            for input in operands {
                collect_kir_read_effects(&input, &mut effects);
                inputs.push(input);
            }
            effects.push(kir::KirEffect::ClobberFlags);
        }
        kir::KirOpcode::Call => {
            inputs.append(&mut operands);
            effects.push(kir::KirEffect::Call);
        }
        kir::KirOpcode::Branch => {
            inputs.append(&mut operands);
            effects.push(kir::KirEffect::Branch);
        }
        kir::KirOpcode::Return => {
            inputs.append(&mut operands);
            effects.push(kir::KirEffect::Return);
        }
        kir::KirOpcode::Syscall => {
            inputs.append(&mut operands);
            effects.push(kir::KirEffect::Syscall);
        }
        kir::KirOpcode::StackPush => {
            for input in operands {
                collect_kir_read_effects(&input, &mut effects);
                inputs.push(input);
            }
            outputs.push(kir::KirValue::Memory {
                base: Some("sp".to_string()),
                index: None,
                scale: 1,
                displacement: 0,
                size_bits: None,
            });
            effects.push(kir::KirEffect::ReadRegister("sp".to_string()));
            effects.push(kir::KirEffect::WriteRegister("sp".to_string()));
            effects.push(kir::KirEffect::WriteMemory);
        }
        kir::KirOpcode::StackPop => {
            if let Some(dst) = operands.first().cloned() {
                if let kir::KirValue::Register { name, .. } = &dst {
                    effects.push(kir::KirEffect::WriteRegister(name.clone()));
                }
                outputs.push(dst);
            }
            inputs.push(kir::KirValue::Memory {
                base: Some("sp".to_string()),
                index: None,
                scale: 1,
                displacement: 0,
                size_bits: None,
            });
            effects.push(kir::KirEffect::ReadRegister("sp".to_string()));
            effects.push(kir::KirEffect::WriteRegister("sp".to_string()));
            effects.push(kir::KirEffect::ReadMemory);
        }
        kir::KirOpcode::Nop => {}
        kir::KirOpcode::Unknown => {
            for input in operands {
                collect_kir_read_effects(&input, &mut effects);
                inputs.push(input);
            }
        }
    }

    effects.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    effects.dedup_by(|a, b| format!("{a:?}") == format!("{b:?}"));

    kir::KirOp {
        id,
        vaddr: format!("0x{ip:x}"),
        opcode,
        outputs,
        inputs,
        effects,
        instruction: text.replace(',', ", "),
    }
}

fn kir_opcode(mnemonic: Mnemonic, instr: &iced_x86::Instruction) -> kir::KirOpcode {
    match mnemonic {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx => {
            if instr.op0_kind() == OpKind::Memory {
                kir::KirOpcode::Store
            } else if instr.op1_kind() == OpKind::Memory {
                kir::KirOpcode::Load
            } else {
                kir::KirOpcode::Copy
            }
        }
        Mnemonic::Lea => kir::KirOpcode::AddressOf,
        Mnemonic::Add | Mnemonic::Inc => kir::KirOpcode::IntAdd,
        Mnemonic::Sub | Mnemonic::Dec | Mnemonic::Neg => kir::KirOpcode::IntSub,
        Mnemonic::Imul | Mnemonic::Mul => kir::KirOpcode::IntMul,
        Mnemonic::And => kir::KirOpcode::IntAnd,
        Mnemonic::Or => kir::KirOpcode::IntOr,
        Mnemonic::Xor => kir::KirOpcode::IntXor,
        Mnemonic::Cmp | Mnemonic::Test => kir::KirOpcode::Compare,
        Mnemonic::Push => kir::KirOpcode::StackPush,
        Mnemonic::Pop => kir::KirOpcode::StackPop,
        Mnemonic::Call => kir::KirOpcode::Call,
        Mnemonic::Jmp
        | Mnemonic::Ja
        | Mnemonic::Jae
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Je
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Jl
        | Mnemonic::Jle
        | Mnemonic::Jne
        | Mnemonic::Jno
        | Mnemonic::Jnp
        | Mnemonic::Jns
        | Mnemonic::Jo
        | Mnemonic::Jp
        | Mnemonic::Js => kir::KirOpcode::Branch,
        Mnemonic::Ret | Mnemonic::Retf => kir::KirOpcode::Return,
        Mnemonic::Syscall | Mnemonic::Int => kir::KirOpcode::Syscall,
        Mnemonic::Nop => kir::KirOpcode::Nop,
        _ => kir::KirOpcode::Unknown,
    }
}

fn kir_value_for_operand(instr: &iced_x86::Instruction, index: u32, text: &str) -> kir::KirValue {
    match instr.op_kind(index) {
        OpKind::Register => {
            let register = instr.op_register(index);
            kir::KirValue::Register {
                name: register_name(register),
                size_bits: register_size_bits(register),
            }
        }
        OpKind::Memory => kir::KirValue::Memory {
            base: optional_register_name(instr.memory_base()),
            index: optional_register_name(instr.memory_index()),
            scale: instr.memory_index_scale(),
            displacement: instr.memory_displacement64() as i64,
            size_bits: None,
        },
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => kir::KirValue::Immediate {
            value: operand_text(text, index).unwrap_or_else(|| "?".to_string()),
            size_bits: None,
        },
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            kir::KirValue::BranchTarget {
                target: format!("0x{:x}", instr.near_branch_target()),
            }
        }
        OpKind::FarBranch16 | OpKind::FarBranch32 => kir::KirValue::BranchTarget {
            target: operand_text(text, index).unwrap_or_else(|| "?".to_string()),
        },
        _ => kir::KirValue::Unknown {
            text: operand_text(text, index).unwrap_or_else(|| "?".to_string()),
        },
    }
}

fn collect_kir_read_effects(value: &kir::KirValue, effects: &mut Vec<kir::KirEffect>) {
    match value {
        kir::KirValue::Register { name, .. } => {
            effects.push(kir::KirEffect::ReadRegister(name.clone()))
        }
        kir::KirValue::Memory { .. } => effects.push(kir::KirEffect::ReadMemory),
        _ => {}
    }
}

fn operand_text(text: &str, index: u32) -> Option<String> {
    let (_, operands) = text.split_once(' ')?;
    operands
        .split(',')
        .nth(index as usize)
        .map(|operand| operand.trim().to_string())
}

fn optional_register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| register_name(register))
}

fn register_name(register: Register) -> String {
    format!("{register:?}").to_ascii_lowercase()
}

fn register_size_bits(register: Register) -> Option<u32> {
    let name = register_name(register);
    if matches!(
        name.as_str(),
        "al" | "ah" | "bl" | "bh" | "cl" | "ch" | "dl" | "dh"
    ) || name.ends_with('b')
    {
        Some(8)
    } else if matches!(
        name.as_str(),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp"
    ) || name.ends_with('w')
    {
        Some(16)
    } else if name.starts_with('e') || name.ends_with('d') {
        Some(32)
    } else if name.starts_with('r') {
        Some(64)
    } else {
        None
    }
}

fn block_for_ip(ip: u64, blocks: &[(u64, u64, String)]) -> Option<String> {
    blocks
        .iter()
        .find(|(start, end, _)| ip >= *start && ip < *end)
        .map(|(_, _, label)| label.clone())
}

fn memory_accesses_for_instruction(ip: u64, text: &str, display: &str) -> Vec<MemoryAccess> {
    let access = if text.starts_with("lea") {
        "address".to_string()
    } else if let Some((dst, src)) = instruction_operands(text) {
        match (dst.contains('['), src.contains('[')) {
            (true, false) => "write".to_string(),
            (false, true) => "read".to_string(),
            (true, true) => "readwrite".to_string(),
            (false, false) => "access".to_string(),
        }
    } else {
        "access".to_string()
    };

    bracket_operands(text)
        .into_iter()
        .map(|operand| {
            let (kind, base, offset, location) = classify_memory_operand(&operand);
            MemoryAccess {
                vaddr: format!("0x{ip:x}"),
                kind,
                access: access.clone(),
                location,
                base,
                offset,
                instruction: display.to_string(),
            }
        })
        .collect()
}

fn bracket_operands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('[') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find(']') else {
            break;
        };
        out.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    out
}

fn classify_memory_operand(operand: &str) -> (String, Option<String>, Option<i64>, String) {
    let normalized = operand.replace(' ', "");
    let base = ["rbp", "rsp", "ebp", "esp"]
        .iter()
        .find(|base| {
            normalized == **base
                || normalized.starts_with(&format!("{base}+"))
                || normalized.starts_with(&format!("{base}-"))
                || normalized.contains(&format!("+{base}"))
                || normalized.contains(&format!("-{base}"))
        })
        .map(|base| (*base).to_string());
    if let Some(base) = base {
        let offset = stack_offset(&normalized, &base);
        let location = match offset {
            Some(offset) if offset < 0 => format!("[{base}-0x{:x}]", offset.unsigned_abs()),
            Some(offset) if offset > 0 => format!("[{base}+0x{offset:x}]"),
            Some(_) | None => format!("[{base}]"),
        };
        return ("stack".to_string(), Some(base), offset, location);
    }

    if let Some(address) = absolute_memory_address(&normalized) {
        return (
            "global".to_string(),
            None,
            Some(address as i64),
            format!("[0x{address:x}]"),
        );
    }

    (
        "unknown".to_string(),
        register_mentions(
            &normalized,
            &[
                "rax".to_string(),
                "rbx".to_string(),
                "rcx".to_string(),
                "rdx".to_string(),
                "rsi".to_string(),
                "rdi".to_string(),
                "eax".to_string(),
                "ebx".to_string(),
                "ecx".to_string(),
                "edx".to_string(),
                "esi".to_string(),
                "edi".to_string(),
            ],
        )
        .into_iter()
        .next(),
        None,
        format!("[{normalized}]"),
    )
}

fn stack_offset(operand: &str, base: &str) -> Option<i64> {
    let pos = operand.find(base)?;
    let rest = &operand[pos + base.len()..];
    if let Some(hex) = rest.strip_prefix("-0x") {
        let end = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        return i64::from_str_radix(&hex[..end], 16)
            .ok()
            .map(|value| -value);
    }
    if let Some(hex) = rest.strip_prefix("+0x") {
        let end = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        return i64::from_str_radix(&hex[..end], 16).ok();
    }
    if let Some(raw) = rest.strip_prefix('-') {
        return parse_stack_offset_value(raw).map(|value| -value);
    }
    if let Some(raw) = rest.strip_prefix('+') {
        return parse_stack_offset_value(raw);
    }
    Some(0)
}

fn parse_stack_offset_value(text: &str) -> Option<i64> {
    let end = text
        .find(|c: char| !c.is_ascii_hexdigit() && c != 'h' && c != 'H')
        .unwrap_or(text.len());
    let raw = &text[..end];
    if raw.is_empty() {
        return None;
    }
    if let Some(hex) = raw.strip_suffix('h').or_else(|| raw.strip_suffix('H')) {
        return i64::from_str_radix(hex, 16).ok();
    }
    raw.parse::<i64>().ok()
}

fn absolute_memory_address(operand: &str) -> Option<u64> {
    let cleaned = operand
        .trim_start_matches("rel")
        .trim_start_matches("ds:")
        .trim_start_matches("cs:")
        .trim_start_matches("qwordptr")
        .trim_start_matches("dwordptr")
        .trim_start_matches("wordptr")
        .trim_start_matches("byteptr");
    if cleaned.contains('+') || cleaned.contains('-') || cleaned.contains('*') {
        return None;
    }
    parse_num(cleaned)
}

fn instruction_operands<'a>(text: &'a str) -> Option<(&'a str, &'a str)> {
    let opcode_end = text.find(|c: char| !c.is_ascii_alphabetic())?;
    let operands = &text[opcode_end..];
    let mut parts = operands.splitn(2, ',');
    Some((parts.next()?.trim(), parts.next()?.trim()))
}

fn variable_candidates_from_memory(memory_accesses: &[MemoryAccess]) -> Vec<VariableCandidate> {
    let mut grouped = BTreeMap::<(String, String), (usize, String)>::new();
    for access in memory_accesses
        .iter()
        .filter(|access| access.kind == "stack" || access.kind == "global")
    {
        let key = (access.kind.clone(), access.location.clone());
        grouped
            .entry(key)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, access.vaddr.clone()));
    }

    grouped
        .into_iter()
        .map(|((kind, location), (access_count, first_seen))| {
            let name = if kind == "stack" {
                let suffix = location
                    .trim_matches(['[', ']'])
                    .replace("+0x", "_p")
                    .replace("-0x", "_m")
                    .replace(['+', '-'], "_");
                format!("var_{suffix}")
            } else {
                format!("global_{}", location.trim_matches(['[', ']']))
            };
            VariableCandidate {
                name,
                kind,
                location,
                access_count,
                first_seen,
            }
        })
        .collect()
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
        "   dataflow: available={} arch={} insns={} defs={} uses={} memory={} vars={} phi_candidates={}\n",
        dataflow.available,
        dataflow.architecture,
        dataflow.instruction_count,
        dataflow.definitions.len(),
        dataflow.uses.len(),
        dataflow.memory_accesses.len(),
        dataflow.variable_candidates.len(),
        dataflow.phi_candidates.len()
    ));
    for variable in dataflow.variable_candidates.iter().take(8) {
        out.push_str(&format!(
            "     var {} {} accesses={} first_seen={}\n",
            variable.kind, variable.location, variable.access_count, variable.first_seen
        ));
    }
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
        assert!(analysis.kir.available);
        assert!(
            analysis
                .kir
                .ops
                .iter()
                .any(|op| matches!(op.opcode, kir::KirOpcode::Syscall))
        );
        assert!(analysis.kir.ssa.available);
        assert!(analysis.kir.ssa.definition_count > 0);
        assert!(
            analysis
                .kir
                .ssa
                .definitions
                .iter()
                .any(|def| def.name == "eax")
        );
        assert!(
            analysis
                .kir
                .ssa
                .definitions
                .iter()
                .all(|def| !matches!(def.name.as_str(), "al" | "bl" | "dl" | "sp"))
        );
        assert!(
            analysis
                .kir
                .ssa
                .uses
                .iter()
                .all(|use_| !matches!(use_.name.as_str(), "al" | "bl" | "dl" | "sp"))
        );
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

    #[test]
    fn calc_sample_reports_memory_variable_candidates() {
        let path = Path::new("samples/PwnableTW/calc/calc");
        if !path.exists() {
            return;
        }
        let analysis = decompile_analysis_path(path, 0x8048ee1).expect("calc eval analysis");
        assert_eq!(analysis.function.start, "0x8048ee1");
        assert!(!analysis.dataflow.memory_accesses.is_empty());
        assert!(!analysis.dataflow.variable_candidates.is_empty());
        assert!(
            analysis
                .kir
                .ops
                .iter()
                .any(|op| matches!(op.opcode, kir::KirOpcode::Load))
        );
        assert!(analysis.kir.ssa.available);
        assert!(analysis.kir.ssa.phi_count > 0);
        assert!(analysis.kir.ssa.dominance_available);
        assert!(analysis.kir.ssa.block_states.iter().any(|block| {
            !block.dominance_frontier.is_empty() || block.immediate_dominator.is_some()
        }));
        assert!(
            analysis
                .kir
                .ssa
                .phi_nodes
                .iter()
                .all(|phi| phi.reason.contains("dominance-frontier") && phi.version > 0)
        );
        assert!(analysis.kir.ssa.phi_nodes.iter().all(|phi| {
            analysis.kir.ssa.definitions.iter().any(|def| {
                def.vaddr == phi.block
                    && def.name == phi.name
                    && def.version == phi.version
                    && def.source.starts_with("phi(")
            })
        }));
        assert!(
            analysis
                .dataflow
                .variable_candidates
                .iter()
                .any(|candidate| candidate.kind == "stack" || candidate.kind == "global")
        );
    }
}
