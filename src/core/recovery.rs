//! Structured function, CFG, and xref recovery.
//!
//! This is the graph-backed recovery path used by newer CLI/REST/knowledge
//! surfaces.  It deliberately returns typed JSON-ready structures instead of
//! human text so agents and UI panes can reason over addresses, blocks, and
//! edge provenance directly.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;

use anyhow::{Context, Result};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, SectionKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryIndex {
    pub kind: String,
    pub schema_version: u32,
    pub binary: String,
    pub architecture: String,
    pub entry: Option<String>,
    pub functions: Vec<RecoveredFunction>,
    pub xrefs: Vec<RecoveredXref>,
    pub stats: RecoveryStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFunction {
    pub start: String,
    pub size: u64,
    pub name: String,
    pub confidence: String,
    pub source: Vec<String>,
    pub blocks: Vec<RecoveredBlock>,
    pub edges: Vec<RecoveredEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredBlock {
    pub start: String,
    pub end: String,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredXref {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub function: Option<String>,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStats {
    pub executable_sections: usize,
    pub function_count: usize,
    pub block_count: usize,
    pub edge_count: usize,
    pub xref_count: usize,
}

#[derive(Clone)]
struct ExecSection {
    name: String,
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Seed {
    addr: u64,
    name: Option<String>,
    source: String,
    confidence: String,
}

pub fn recover(path: &Path, max_functions: usize) -> Result<RecoveryIndex> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::File::parse(&*data).with_context(|| format!("parse {}", path.display()))?;
    let sections = executable_sections(&obj)?;
    let entry = obj.entry();
    let arch = obj.architecture();
    let mut seeds = collect_symbol_seeds(&obj, &sections);
    if entry != 0 && section_for(&sections, entry).is_some() {
        upsert_seed(
            &mut seeds,
            Seed {
                addr: entry,
                name: Some("_start".to_string()),
                source: "entry".to_string(),
                confidence: "entry".to_string(),
            },
        );
    }

    let global_xrefs = recover_xrefs(arch, &sections, None);
    for xref in &global_xrefs {
        if xref.kind == "call" && section_for(&sections, parse_hex(&xref.to).unwrap_or(0)).is_some()
        {
            upsert_seed(
                &mut seeds,
                Seed {
                    addr: parse_hex(&xref.to).unwrap_or(0),
                    name: None,
                    source: "direct_call_target".to_string(),
                    confidence: "call-target".to_string(),
                },
            );
        }
    }
    if seeds.is_empty() {
        for section in &sections {
            upsert_seed(
                &mut seeds,
                Seed {
                    addr: section.address,
                    name: Some(format!("section_{}", section.name)),
                    source: "section_start_fallback".to_string(),
                    confidence: "fallback".to_string(),
                },
            );
        }
    }

    seeds.sort_by_key(|s| (seed_priority(s), s.addr));
    seeds.dedup_by_key(|s| s.addr);
    let seeds = seeds
        .into_iter()
        .take(max_functions.max(1))
        .collect::<Vec<_>>();
    let functions = match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 | Architecture::I386 => seeds
            .iter()
            .filter_map(|seed| recover_x86_function(arch, &sections, seed).ok())
            .collect::<Vec<_>>(),
        _ => seeds
            .iter()
            .map(|seed| fallback_function(&sections, seed))
            .collect::<Vec<_>>(),
    };

    let function_by_range = functions
        .iter()
        .filter_map(|f| {
            let start = parse_hex(&f.start).ok()?;
            Some((start, start.saturating_add(f.size), f.start.clone()))
        })
        .collect::<Vec<_>>();
    let mut xrefs = global_xrefs;
    for xref in &mut xrefs {
        let from = parse_hex(&xref.from).unwrap_or(0);
        xref.function = function_by_range
            .iter()
            .find(|(start, end, _)| from >= *start && from < *end)
            .map(|(_, _, f)| f.clone());
    }
    xrefs.retain(|xref| xref.function.is_some());

    let block_count = functions.iter().map(|f| f.blocks.len()).sum();
    let edge_count = functions.iter().map(|f| f.edges.len()).sum();
    Ok(RecoveryIndex {
        kind: "recovery_index".to_string(),
        schema_version: 1,
        binary: path.to_string_lossy().into_owned(),
        architecture: format!("{arch:?}"),
        entry: (entry != 0).then(|| hex(entry)),
        stats: RecoveryStats {
            executable_sections: sections.len(),
            function_count: functions.len(),
            block_count,
            edge_count,
            xref_count: xrefs.len(),
        },
        functions,
        xrefs,
    })
}

pub fn xrefs_to(path: &Path, target: u64, max_functions: usize) -> Result<Vec<RecoveredXref>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::File::parse(&*data).with_context(|| format!("parse {}", path.display()))?;
    let sections = executable_sections(&obj)?;
    let arch = obj.architecture();
    let mut xrefs = recover_xrefs(arch, &sections, None)
        .into_iter()
        .filter(|xref| parse_hex(&xref.to).ok() == Some(target))
        .collect::<Vec<_>>();
    if !xrefs.is_empty() {
        let index = recover(path, max_functions)?;
        let function_by_range = index
            .functions
            .iter()
            .filter_map(|f| {
                let start = parse_hex(&f.start).ok()?;
                Some((start, start.saturating_add(f.size), f.start.clone()))
            })
            .collect::<Vec<_>>();
        for xref in &mut xrefs {
            let from = parse_hex(&xref.from).unwrap_or(0);
            xref.function = function_by_range
                .iter()
                .find(|(start, end, _)| from >= *start && from < *end)
                .map(|(_, _, f)| f.clone());
        }
    }
    Ok(xrefs)
}

pub fn cfg_for(
    path: &Path,
    function: u64,
    max_functions: usize,
) -> Result<Option<RecoveredFunction>> {
    let index = recover(path, max_functions)?;
    Ok(index
        .functions
        .into_iter()
        .find(|f| parse_hex(&f.start).ok() == Some(function)))
}

fn executable_sections(obj: &object::File<'_>) -> Result<Vec<ExecSection>> {
    let mut out = Vec::new();
    for section in obj.sections() {
        let is_text = matches!(section.kind(), SectionKind::Text)
            || section
                .name()
                .ok()
                .is_some_and(|n| n == ".text" || n == "__text");
        if !is_text || section.address() == 0 || section.size() == 0 {
            continue;
        }
        let Ok(bytes) = section.data() else {
            continue;
        };
        out.push(ExecSection {
            name: section.name().unwrap_or(".text").to_string(),
            address: section.address(),
            bytes: bytes.to_vec(),
        });
    }
    out.sort_by_key(|s| s.address);
    Ok(out)
}

fn collect_symbol_seeds(obj: &object::File<'_>, sections: &[ExecSection]) -> Vec<Seed> {
    let mut seeds = Vec::new();
    for symbol in obj.symbols() {
        if symbol.kind() != object::SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        if section_for(sections, symbol.address()).is_none() {
            continue;
        }
        seeds.push(Seed {
            addr: symbol.address(),
            name: symbol.name().ok().map(str::to_string),
            source: "symbol_table".to_string(),
            confidence: "symbol".to_string(),
        });
    }
    seeds
}

fn recover_x86_function(
    arch: Architecture,
    sections: &[ExecSection],
    seed: &Seed,
) -> Result<RecoveredFunction> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    let bitness = match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        _ => anyhow::bail!("unsupported x86 architecture: {arch:?}"),
    };
    let section = section_for(sections, seed.addr).context("seed outside executable section")?;
    let mut queue = VecDeque::from([seed.addr]);
    let mut queued = BTreeSet::from([seed.addr]);
    let mut visited = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut edges = Vec::new();
    let mut max_end = seed.addr;
    let mut instruction_starts = BTreeSet::new();

    while let Some(block_start) = queue.pop_front() {
        if !visited.insert(block_start) {
            continue;
        }
        let Some(offset) = section_offset(section, block_start) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            bitness,
            &section.bytes[offset..],
            block_start,
            DecoderOptions::NONE,
        );
        let mut count = 0usize;
        let mut block_end = block_start;
        while decoder.can_decode() && count < 4096 {
            let instr = decoder.decode();
            if instr.is_invalid() || instr.len() == 0 {
                break;
            }
            let ip = instr.ip();
            if count > 0 && queued.contains(&ip) {
                break;
            }
            instruction_starts.insert(ip);
            count += 1;
            block_end = instr.next_ip();
            max_end = max_end.max(block_end);

            match instr.flow_control() {
                FlowControl::Next => {}
                FlowControl::Call | FlowControl::IndirectCall => {
                    if let Some(target) = direct_branch_target(&instr, sections) {
                        edges.push(edge(ip, target, "call"));
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Some(target) = direct_branch_target(&instr, sections) {
                        edges.push(edge(ip, target, "true"));
                        enqueue_if_local(target, section, &mut queue, &mut queued);
                    }
                    edges.push(edge(ip, instr.next_ip(), "false"));
                    enqueue_if_local(instr.next_ip(), section, &mut queue, &mut queued);
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = direct_branch_target(&instr, sections) {
                        edges.push(edge(ip, target, "jump"));
                        enqueue_if_local(target, section, &mut queue, &mut queued);
                    }
                    break;
                }
                FlowControl::Interrupt => {}
                FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Exception => {
                    break;
                }
                _ => break,
            }
            if !section_contains(section, instr.next_ip()) {
                break;
            }
        }
        if count > 0 {
            blocks.push(RecoveredBlock {
                start: hex(block_start),
                end: hex(block_end),
                instruction_count: count,
            });
        }
    }

    blocks.sort_by_key(|b| parse_hex(&b.start).unwrap_or(0));
    edges.sort_by_key(|e| {
        (
            parse_hex(&e.from).unwrap_or(0),
            parse_hex(&e.to).unwrap_or(0),
        )
    });
    edges.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);

    Ok(RecoveredFunction {
        start: hex(seed.addr),
        size: max_end.saturating_sub(seed.addr).max(1),
        name: seed
            .name
            .clone()
            .unwrap_or_else(|| format!("FUN_{:x}", seed.addr)),
        confidence: if instruction_starts.is_empty() {
            "seed-only".to_string()
        } else {
            seed.confidence.clone()
        },
        source: vec![seed.source.clone(), "recursive-descent".to_string()],
        blocks,
        edges,
    })
}

fn recover_xrefs(
    arch: Architecture,
    sections: &[ExecSection],
    function: Option<String>,
) -> Vec<RecoveredXref> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter};

    let bitness = match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 => 64,
        Architecture::I386 => 32,
        _ => return Vec::new(),
    };
    let mut xrefs = Vec::new();
    for section in sections {
        let mut decoder = Decoder::with_ip(
            bitness,
            &section.bytes,
            section.address,
            DecoderOptions::NONE,
        );
        let mut formatter = IntelFormatter::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.is_invalid() || instr.len() == 0 {
                continue;
            }
            let Some(target) = direct_branch_target(&instr, sections) else {
                continue;
            };
            let kind = match instr.flow_control() {
                FlowControl::Call => "call",
                FlowControl::ConditionalBranch => "branch",
                FlowControl::UnconditionalBranch => "jump",
                _ => continue,
            };
            let mut text = String::new();
            formatter.format_mnemonic(&instr, &mut text);
            xrefs.push(RecoveredXref {
                from: hex(instr.ip()),
                to: hex(target),
                kind: kind.to_string(),
                function: function.clone(),
                mnemonic: text,
            });
        }
    }
    xrefs.sort_by_key(|x| {
        (
            parse_hex(&x.to).unwrap_or(0),
            parse_hex(&x.from).unwrap_or(0),
        )
    });
    xrefs.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    xrefs
}

fn fallback_function(sections: &[ExecSection], seed: &Seed) -> RecoveredFunction {
    let size = section_for(sections, seed.addr)
        .map(|section| section.address + section.bytes.len() as u64 - seed.addr)
        .unwrap_or(1);
    RecoveredFunction {
        start: hex(seed.addr),
        size,
        name: seed
            .name
            .clone()
            .unwrap_or_else(|| format!("FUN_{:x}", seed.addr)),
        confidence: "seed-only".to_string(),
        source: vec![seed.source.clone()],
        blocks: vec![RecoveredBlock {
            start: hex(seed.addr),
            end: hex(seed.addr.saturating_add(size)),
            instruction_count: 0,
        }],
        edges: Vec::new(),
    }
}

fn direct_branch_target(instr: &iced_x86::Instruction, sections: &[ExecSection]) -> Option<u64> {
    let target = instr.near_branch_target();
    (target != 0 && section_for(sections, target).is_some()).then_some(target)
}

fn enqueue_if_local(
    target: u64,
    section: &ExecSection,
    queue: &mut VecDeque<u64>,
    queued: &mut BTreeSet<u64>,
) {
    if section_contains(section, target) && queued.insert(target) {
        queue.push_back(target);
    }
}

fn edge(from: u64, to: u64, kind: &str) -> RecoveredEdge {
    RecoveredEdge {
        from: hex(from),
        to: hex(to),
        kind: kind.to_string(),
    }
}

fn section_for(sections: &[ExecSection], addr: u64) -> Option<&ExecSection> {
    sections
        .iter()
        .find(|section| section_contains(section, addr))
}

fn section_contains(section: &ExecSection, addr: u64) -> bool {
    addr >= section.address && addr < section.address.saturating_add(section.bytes.len() as u64)
}

fn section_offset(section: &ExecSection, addr: u64) -> Option<usize> {
    section_contains(section, addr).then_some((addr - section.address) as usize)
}

fn upsert_seed(seeds: &mut Vec<Seed>, seed: Seed) {
    if let Some(existing) = seeds.iter_mut().find(|s| s.addr == seed.addr) {
        if existing.name.is_none() {
            existing.name = seed.name;
        }
        if !existing.source.contains(&seed.source) {
            existing.source = format!("{},{}", existing.source, seed.source);
        }
        return;
    }
    seeds.push(seed);
}

fn seed_priority(seed: &Seed) -> u8 {
    if seed.source.contains("entry") {
        0
    } else if seed.source.contains("symbol") {
        1
    } else if seed.source.contains("direct_call_target") {
        2
    } else {
        3
    }
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_hex(value: &str) -> Result<u64, std::num::ParseIntError> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(hex, 16)
}
