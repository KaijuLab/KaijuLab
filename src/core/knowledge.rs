//! Derived program knowledge graph.
//!
//! This layer normalizes facts that already live in durable stores: static
//! index output, the project SQLite DB, and immutable evidence JSONL records.
//! It is intentionally rebuilt on demand so CLI, REST, UI, and agents see the
//! same current view without maintaining a second source of truth.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{evidence, recovery, workspace::Workspace, workstation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    pub kind: String,
    pub schema_version: u32,
    pub binary: String,
    pub nodes: Vec<KnowledgeNode>,
    pub edges: Vec<KnowledgeEdge>,
    pub evidence_links: Vec<EvidenceLink>,
    pub triage_queue: Vec<TriageItem>,
    pub stats: KnowledgeStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub vaddr: Option<String>,
    pub size: Option<u64>,
    pub tags: Vec<String>,
    pub facts: BTreeMap<String, Value>,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub evidence_id: String,
    pub kind: String,
    pub summary: String,
    pub target_node: Option<String>,
    pub vaddr: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageItem {
    pub rank: usize,
    pub node_id: String,
    pub vaddr: Option<String>,
    pub label: String,
    pub score: i64,
    pub reasons: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeStats {
    pub nodes: usize,
    pub edges: usize,
    pub evidence_links: usize,
    pub triage_items: usize,
}

pub fn build(ws: &Workspace, max_functions: usize, max_evidence: usize) -> Result<KnowledgeGraph> {
    let index = workstation::binary_index(ws.binary_path(), max_functions, 160)?;
    let records = evidence::list(ws.binary_path(), None, max_evidence)?;
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    nodes.push(binary_node(ws, &index));
    let mut address_to_node = BTreeMap::new();

    if let Some(sections) = index.pointer("/object/sections").and_then(|v| v.as_array()) {
        for section in sections {
            let Some(name) = section.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let id = format!("section:{name}");
            let vaddr = section
                .get("address")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let size = section.get("size").and_then(|v| v.as_u64());
            let mut facts = BTreeMap::new();
            facts.insert("section".to_string(), section.clone());
            nodes.push(KnowledgeNode {
                id: id.clone(),
                kind: "section".to_string(),
                label: name.to_string(),
                vaddr,
                size,
                tags: vec![section
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("section")
                    .to_string()],
                facts,
                provenance: vec!["index-build:/object/sections".to_string()],
            });
            edges.push(KnowledgeEdge {
                from: "binary".to_string(),
                to: id,
                kind: "contains".to_string(),
                provenance: vec!["index-build".to_string()],
            });
        }
    }

    add_function_nodes(&index, &mut nodes, &mut edges, &mut address_to_node);
    if !nodes.iter().any(|n| n.kind == "function") {
        add_entry_node(&index, &mut nodes, &mut edges, &mut address_to_node);
    }
    if let Ok(recovered) = recovery::recover(ws.binary_path(), max_functions) {
        add_recovered_functions(&recovered, &mut nodes, &mut edges, &mut address_to_node);
    }

    overlay_project(ws, &mut nodes, &address_to_node);
    let evidence_links = link_evidence(&records, &address_to_node);
    let triage_queue = triage(&nodes, &evidence_links);
    let stats = KnowledgeStats {
        nodes: nodes.len(),
        edges: edges.len(),
        evidence_links: evidence_links.len(),
        triage_items: triage_queue.len(),
    };

    Ok(KnowledgeGraph {
        kind: "knowledge_graph".to_string(),
        schema_version: 1,
        binary: ws.binary_path_str(),
        nodes,
        edges,
        evidence_links,
        triage_queue,
        stats,
    })
}

pub fn triage_queue(ws: &Workspace, limit: usize) -> Result<Value> {
    let mut graph = build(ws, 300, 200)?;
    graph.triage_queue.truncate(limit.max(1));
    Ok(json!({
        "kind": "triage_queue",
        "binary": graph.binary,
        "items": graph.triage_queue,
        "stats": graph.stats,
    }))
}

fn binary_node(ws: &Workspace, index: &Value) -> KnowledgeNode {
    let mut facts = BTreeMap::new();
    facts.insert("workspace_hash".to_string(), json!(ws.workspace_hash()));
    facts.insert("index".to_string(), index.clone());
    KnowledgeNode {
        id: "binary".to_string(),
        kind: "binary".to_string(),
        label: ws.display_name().to_string(),
        vaddr: index
            .pointer("/elf/entry")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        size: index.get("size").and_then(|v| v.as_u64()),
        tags: vec![
            index
                .pointer("/elf/arch")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            index
                .pointer("/elf/format")
                .and_then(|v| v.as_str())
                .unwrap_or("binary")
                .to_string(),
        ],
        facts,
        provenance: vec![
            "index-build".to_string(),
            "project-db".to_string(),
            "evidence-jsonl".to_string(),
        ],
    }
}

fn add_recovered_functions(
    recovered: &recovery::RecoveryIndex,
    nodes: &mut Vec<KnowledgeNode>,
    edges: &mut Vec<KnowledgeEdge>,
    address_to_node: &mut BTreeMap<String, String>,
) {
    for function in &recovered.functions {
        let id = format!("function:{}", normalize_addr(&function.start));
        if let Some(node) = nodes.iter_mut().find(|node| node.id == id) {
            node.size = Some(function.size);
            node.label = function.name.clone();
            node.tags.push("recovered".to_string());
            node.facts.insert("recovery".to_string(), json!(function));
            node.provenance
                .push("professional-recovery:function".to_string());
        } else {
            let mut facts = BTreeMap::new();
            facts.insert("recovery".to_string(), json!(function));
            nodes.push(KnowledgeNode {
                id: id.clone(),
                kind: "function".to_string(),
                label: function.name.clone(),
                vaddr: Some(function.start.clone()),
                size: Some(function.size),
                tags: vec!["recovered".to_string(), function.confidence.clone()],
                facts,
                provenance: vec!["professional-recovery:function".to_string()],
            });
            edges.push(KnowledgeEdge {
                from: "binary".to_string(),
                to: id.clone(),
                kind: "contains".to_string(),
                provenance: vec!["professional-recovery".to_string()],
            });
        }
        address_to_node.insert(normalize_addr(&function.start), id.clone());
    }

    for xref in &recovered.xrefs {
        let Some(from_fn) = xref
            .function
            .as_ref()
            .map(|addr| format!("function:{}", normalize_addr(addr)))
        else {
            continue;
        };
        let Some(to_fn) = address_to_node.get(&normalize_addr(&xref.to)).cloned() else {
            continue;
        };
        if from_fn == to_fn {
            continue;
        }
        edges.push(KnowledgeEdge {
            from: from_fn,
            to: to_fn,
            kind: xref.kind.clone(),
            provenance: vec![format!("professional-recovery:xref:{}", xref.from)],
        });
    }
    edges.sort_by(|a, b| (&a.from, &a.to, &a.kind).cmp(&(&b.from, &b.to, &b.kind)));
    edges.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
}

fn add_function_nodes(
    index: &Value,
    nodes: &mut Vec<KnowledgeNode>,
    edges: &mut Vec<KnowledgeEdge>,
    address_to_node: &mut BTreeMap<String, String>,
) {
    let Some(functions) = index.get("functions") else {
        return;
    };
    let candidates = if let Some(array) = functions.as_array() {
        array.clone()
    } else if let Some(array) = functions.get("functions").and_then(|v| v.as_array()) {
        array.clone()
    } else {
        Vec::new()
    };
    for (idx, function) in candidates.iter().enumerate() {
        let vaddr = string_field(function, &["vaddr", "address", "entry", "start"]);
        let label = string_field(function, &["name", "symbol"])
            .or_else(|| vaddr.clone())
            .unwrap_or_else(|| format!("function_{idx}"));
        let id = vaddr
            .as_ref()
            .map(|addr| format!("function:{}", addr.to_lowercase()))
            .unwrap_or_else(|| format!("function:index:{idx}"));
        let size = function.get("size").and_then(|v| v.as_u64());
        let mut facts = BTreeMap::new();
        facts.insert("function".to_string(), function.clone());
        nodes.push(KnowledgeNode {
            id: id.clone(),
            kind: "function".to_string(),
            label,
            vaddr: vaddr.clone(),
            size,
            tags: vec!["static".to_string()],
            facts,
            provenance: vec!["index-build:/functions".to_string()],
        });
        if let Some(addr) = vaddr {
            address_to_node.insert(normalize_addr(&addr), id.clone());
        }
        edges.push(KnowledgeEdge {
            from: "binary".to_string(),
            to: id,
            kind: "contains".to_string(),
            provenance: vec!["index-build".to_string()],
        });
    }
}

fn add_entry_node(
    index: &Value,
    nodes: &mut Vec<KnowledgeNode>,
    edges: &mut Vec<KnowledgeEdge>,
    address_to_node: &mut BTreeMap<String, String>,
) {
    let Some(entry) = index.pointer("/elf/entry").and_then(|v| v.as_str()) else {
        return;
    };
    let id = format!("function:{}", entry.to_lowercase());
    let mut facts = BTreeMap::new();
    facts.insert("entry".to_string(), json!(entry));
    facts.insert(
        "confidence".to_string(),
        json!("entry fallback; function prologues unavailable"),
    );
    nodes.push(KnowledgeNode {
        id: id.clone(),
        kind: "function".to_string(),
        label: "_start".to_string(),
        vaddr: Some(entry.to_string()),
        size: None,
        tags: vec!["entry".to_string(), "fallback".to_string()],
        facts,
        provenance: vec!["index-build:/elf/entry".to_string()],
    });
    address_to_node.insert(normalize_addr(entry), id.clone());
    edges.push(KnowledgeEdge {
        from: "binary".to_string(),
        to: id,
        kind: "entry".to_string(),
        provenance: vec!["index-build".to_string()],
    });
}

fn overlay_project(
    ws: &Workspace,
    nodes: &mut [KnowledgeNode],
    address_to_node: &BTreeMap<String, String>,
) {
    let project = ws.with_project(|p| p.clone());
    for node in nodes.iter_mut() {
        if node.kind == "binary" {
            continue;
        }
        let Some(vaddr) = &node.vaddr else {
            continue;
        };
        let Ok(addr) = parse_addr(vaddr) else {
            continue;
        };
        if let Some(name) = project.renames.get(&addr) {
            node.label = name.clone();
            node.tags.push("renamed".to_string());
            node.facts.insert("rename".to_string(), json!(name));
            node.provenance.push("project-db:renames".to_string());
        }
        if let Some(comment) = project.comments.get(&addr) {
            node.tags.push("commented".to_string());
            node.facts.insert("comment".to_string(), json!(comment));
            node.provenance.push("project-db:comments".to_string());
        }
        if let Some(score) = project.vuln_scores.get(&addr) {
            node.tags.push("scored".to_string());
            node.facts.insert("vuln_score".to_string(), json!(score));
            node.provenance.push("project-db:vuln_scores".to_string());
        }
        let notes = project
            .notes
            .iter()
            .filter(|n| n.vaddr == Some(addr))
            .map(|n| json!({ "id": n.id, "text": n.text, "timestamp": n.timestamp }))
            .collect::<Vec<_>>();
        if !notes.is_empty() {
            node.tags.push("noted".to_string());
            node.facts.insert("notes".to_string(), json!(notes));
            node.provenance.push("project-db:notes".to_string());
        }
        let findings = project
            .findings
            .iter()
            .filter(|f| f.vaddr.as_deref().map(normalize_addr) == Some(normalize_addr(vaddr)))
            .map(|f| json!({ "id": f.id, "severity": f.severity, "status": f.status, "rule": f.rule }))
            .collect::<Vec<_>>();
        if !findings.is_empty() {
            node.tags.push("finding".to_string());
            node.facts.insert("findings".to_string(), json!(findings));
            node.provenance.push("project-db:findings".to_string());
        }
    }

    for finding in project.findings.iter().filter(|f| f.vaddr.is_none()) {
        let id = format!("finding:{}", finding.id);
        if address_to_node.values().any(|existing| existing == &id) {
            continue;
        }
    }
}

fn link_evidence(
    records: &[evidence::EvidenceRecord],
    address_to_node: &BTreeMap<String, String>,
) -> Vec<EvidenceLink> {
    records
        .iter()
        .map(|record| {
            let vaddr = first_address_in_value(&record.data);
            let target_node = vaddr
                .as_deref()
                .map(normalize_addr)
                .and_then(|addr| address_to_node.get(&addr).cloned());
            EvidenceLink {
                evidence_id: record.id.clone(),
                kind: record.kind.clone(),
                summary: record.summary.clone(),
                target_node,
                vaddr,
                created_at: record.created_at.clone(),
            }
        })
        .collect()
}

fn triage(nodes: &[KnowledgeNode], evidence_links: &[EvidenceLink]) -> Vec<TriageItem> {
    let evidence_by_node =
        evidence_links
            .iter()
            .fold(BTreeMap::<String, Vec<String>>::new(), |mut acc, link| {
                if let Some(node) = &link.target_node {
                    acc.entry(node.clone())
                        .or_default()
                        .push(link.evidence_id.clone());
                }
                acc
            });
    let mut items = Vec::new();
    for node in nodes.iter().filter(|n| n.kind == "function") {
        let mut score = 0;
        let mut reasons = Vec::new();
        if node.tags.iter().any(|t| t == "entry") {
            score += 20;
            reasons.push("program entry".to_string());
        }
        if let Some(score_value) = node.facts.get("vuln_score").and_then(|v| v.as_u64()) {
            score += (score_value as i64) * 10;
            reasons.push(format!("vuln score {score_value}/10"));
        }
        if let Some(findings) = node.facts.get("findings").and_then(|v| v.as_array()) {
            score += 25 * findings.len() as i64;
            reasons.push(format!("{} linked findings", findings.len()));
        }
        if let Some(ids) = evidence_by_node.get(&node.id) {
            score += 15 * ids.len() as i64;
            reasons.push(format!("{} linked evidence records", ids.len()));
        }
        let label_l = node.label.to_ascii_lowercase();
        for needle in [
            "read", "recv", "gets", "scanf", "strcpy", "memcpy", "system", "exec", "open",
        ] {
            if label_l.contains(needle) {
                score += 12;
                reasons.push(format!("name contains {needle}"));
            }
        }
        if node.tags.iter().any(|t| t == "fallback") {
            score += 8;
            reasons.push("fallback function boundary; inspect manually".to_string());
        }
        if reasons.is_empty() {
            continue;
        }
        items.push(TriageItem {
            rank: 0,
            node_id: node.id.clone(),
            vaddr: node.vaddr.clone(),
            label: node.label.clone(),
            score,
            reasons,
            evidence_ids: evidence_by_node.get(&node.id).cloned().unwrap_or_default(),
        });
    }
    items.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.label.cmp(&b.label)));
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
    }
    items
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(|v| v.as_str()).map(str::to_string))
}

fn normalize_addr(addr: &str) -> String {
    parse_addr(addr)
        .map(|v| format!("0x{v:x}"))
        .unwrap_or_else(|_| addr.to_ascii_lowercase())
}

fn parse_addr(addr: &str) -> Result<u64, std::num::ParseIntError> {
    let trimmed = addr.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(hex, 16)
}

fn first_address_in_value(value: &Value) -> Option<String> {
    let mut seen = BTreeSet::new();
    collect_addresses(value, &mut seen);
    seen.into_iter().next()
}

fn collect_addresses(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let key_l = key.to_ascii_lowercase();
                if matches!(key_l.as_str(), "rip" | "eip" | "pc" | "vaddr" | "address") {
                    if let Some(s) = value.as_str().filter(|s| s.starts_with("0x")) {
                        out.insert(normalize_addr(s));
                    }
                }
                collect_addresses(value, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_addresses(value, out);
            }
        }
        Value::String(s) if s.starts_with("0x") => {
            out.insert(normalize_addr(s));
        }
        _ => {}
    }
}
