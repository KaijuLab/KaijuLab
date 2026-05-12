//! Analyst playbooks — repeatable reverse-engineering workflows built from
//! deterministic tools.  Playbooks are intentionally evidence-first: they
//! summarize tool output and propose findings that the web/MCP surfaces can
//! review or persist.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{
    analysis,
    findings::{Evidence, FindingKind, Severity},
    Workspace,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum PlaybookId {
    MalwareTriage,
    CtfFlagHunt,
    VulnerabilityAudit,
    CapabilitySurvey,
}

impl PlaybookId {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "malware_triage" => Ok(Self::MalwareTriage),
            "ctf_flag_hunt" => Ok(Self::CtfFlagHunt),
            "vulnerability_audit" => Ok(Self::VulnerabilityAudit),
            "capability_survey" => Ok(Self::CapabilitySurvey),
            _ => Err(anyhow!("unknown playbook: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct Playbook {
    pub id: PlaybookId,
    pub title: String,
    pub audience: String,
    pub goal: String,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PlaybookRunRequest {
    pub max_functions: Option<u32>,
    #[serde(default = "default_create_findings")]
    pub create_findings: bool,
}

fn default_create_findings() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PlaybookRun {
    pub id: PlaybookId,
    pub title: String,
    pub summary: String,
    pub steps: Vec<PlaybookStep>,
    pub proposed_findings: Vec<PlaybookFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PlaybookStep {
    pub title: String,
    pub status: String,
    pub evidence: Vec<PlaybookEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PlaybookEvidence {
    pub label: String,
    pub tool: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PlaybookFinding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub vaddr: Option<String>,
    pub rule: String,
    pub rationale: String,
    pub evidence: Vec<Evidence>,
    pub suggested_actions: Vec<String>,
}

pub fn list_playbooks() -> Vec<Playbook> {
    vec![
        Playbook {
            id: PlaybookId::MalwareTriage,
            title: "Malware triage".into(),
            audience: "malware analyst".into(),
            goal: "Identify packing, suspicious imports, network/process IOCs, and initial capability leads.".into(),
            steps: vec![
                "Inspect file metadata and section entropy".into(),
                "Cluster high-interest imports".into(),
                "Extract strings and IOCs".into(),
                "Run vulnerability/capability heuristics".into(),
            ],
        },
        Playbook {
            id: PlaybookId::CtfFlagHunt,
            title: "CTF flag hunt".into(),
            audience: "beginner to advanced CTF player".into(),
            goal: "Find likely flag/checker paths, comparison strings, decoders, and candidate functions.".into(),
            steps: vec![
                "Find flag-like strings and comparison hints".into(),
                "List functions for fast navigation".into(),
                "Search vulnerability/decoder heuristics".into(),
                "Point analyst at next functions to inspect".into(),
            ],
        },
        Playbook {
            id: PlaybookId::VulnerabilityAudit,
            title: "Vulnerability audit".into(),
            audience: "security reviewer".into(),
            goal: "Surface dangerous APIs, risky memory operations, and functions worth dataflow review.".into(),
            steps: vec![
                "Resolve imports".into(),
                "Run vulnerability scan".into(),
                "Collect xref/dataflow follow-up hints".into(),
            ],
        },
        Playbook {
            id: PlaybookId::CapabilitySurvey,
            title: "Capability survey".into(),
            audience: "reverse engineer".into(),
            goal: "Create a quick capability map from imports, strings, crypto constants, and callgraph context.".into(),
            steps: vec![
                "Summarize binary metadata".into(),
                "Collect imports and strings".into(),
                "Build shallow callgraph context".into(),
                "Record capability leads".into(),
            ],
        },
    ]
}

pub fn run_playbook(
    ws: &Workspace,
    id: PlaybookId,
    max_functions: Option<u32>,
) -> Result<PlaybookRun> {
    match id {
        PlaybookId::MalwareTriage => malware_triage(ws, max_functions),
        PlaybookId::CtfFlagHunt => ctf_flag_hunt(ws, max_functions),
        PlaybookId::VulnerabilityAudit => vulnerability_audit(ws, max_functions),
        PlaybookId::CapabilitySurvey => capability_survey(ws, max_functions),
    }
}

fn malware_triage(ws: &Workspace, max_functions: Option<u32>) -> Result<PlaybookRun> {
    let info = safe("file_info", || analysis::file_info(ws));
    let entropy = safe("section_entropy", || analysis::section_entropy(ws));
    let imports = safe("imports", || analysis::imports(ws));
    let strings = safe("strings_extract", || {
        analysis::strings_extract(ws, None, Some(5))
    });
    let vuln = safe("scan_vulnerabilities", || {
        analysis::scan_vulnerabilities(ws, max_functions.or(Some(80)))
    });

    let mut findings = Vec::new();
    push_import_finding(&mut findings, &imports);
    push_ioc_finding(&mut findings, &strings);
    push_entropy_finding(&mut findings, &entropy);
    push_vuln_finding(&mut findings, &vuln);

    Ok(run(
        PlaybookId::MalwareTriage,
        "Malware triage",
        format!(
            "{} evidence groups, {} proposed findings. Review imports, strings, entropy, and vuln leads first.",
            5,
            findings.len()
        ),
        vec![
            step("File and entropy", "complete", vec![ev("file_info", "file_info", &info), ev("section_entropy", "section_entropy", &entropy)]),
            step("Suspicious imports", "complete", vec![ev("imports", "imports", &imports)]),
            step("Strings and IOCs", "complete", vec![ev("strings", "strings_extract", &strings)]),
            step("Risk scan", "complete", vec![ev("scan", "scan_vulnerabilities", &vuln)]),
        ],
        findings,
    ))
}

fn ctf_flag_hunt(ws: &Workspace, max_functions: Option<u32>) -> Result<PlaybookRun> {
    let strings = safe("strings_extract", || {
        analysis::strings_extract(ws, None, Some(4))
    });
    let functions = safe("list_functions", || analysis::list_functions(ws, false));
    let vuln = safe("scan_vulnerabilities", || {
        analysis::scan_vulnerabilities(ws, max_functions.or(Some(120)))
    });

    let flag_hits = find_lines(
        &strings,
        &["flag", "ctf", "correct", "wrong", "password", "key{", "{"],
        12,
    );
    let mut findings = Vec::new();
    if !flag_hits.is_empty() {
        findings.push(PlaybookFinding {
            kind: FindingKind::StringOfInterest,
            severity: Severity::Med,
            vaddr: None,
            rule: "ctf_flag_string_leads".into(),
            rationale: format!("Flag/checker string leads found:\n{}", flag_hits.join("\n")),
            evidence: vec![tool_evidence("strings_extract", &strings)],
            suggested_actions: vec![
                "Open xrefs for each candidate string address or offset.".into(),
                "Inspect nearby comparison/check functions and rename them.".into(),
            ],
        });
    }
    push_vuln_finding(&mut findings, &vuln);

    Ok(run(
        PlaybookId::CtfFlagHunt,
        "CTF flag hunt",
        format!(
            "{} flag/checker string leads, {} proposed findings.",
            flag_hits.len(),
            findings.len()
        ),
        vec![
            step(
                "Flag/checker strings",
                "complete",
                vec![ev(
                    "candidate strings",
                    "strings_extract",
                    &flag_hits.join("\n"),
                )],
            ),
            step(
                "Function navigation",
                "complete",
                vec![ev("functions", "list_functions", &functions)],
            ),
            step(
                "Decoder/risk hints",
                "complete",
                vec![ev("scan", "scan_vulnerabilities", &vuln)],
            ),
        ],
        findings,
    ))
}

fn vulnerability_audit(ws: &Workspace, max_functions: Option<u32>) -> Result<PlaybookRun> {
    let imports = safe("imports", || analysis::imports(ws));
    let vuln = safe("scan_vulnerabilities", || {
        analysis::scan_vulnerabilities(ws, max_functions.or(Some(200)))
    });
    let functions = safe("list_functions", || analysis::list_functions(ws, false));

    let mut findings = Vec::new();
    push_import_finding(&mut findings, &imports);
    push_vuln_finding(&mut findings, &vuln);

    Ok(run(
        PlaybookId::VulnerabilityAudit,
        "Vulnerability audit",
        format!(
            "{} proposed findings. Prioritize dangerous imports and high-risk scan output.",
            findings.len()
        ),
        vec![
            step(
                "Dangerous imports",
                "complete",
                vec![ev("imports", "imports", &imports)],
            ),
            step(
                "Function inventory",
                "complete",
                vec![ev("functions", "list_functions", &functions)],
            ),
            step(
                "Risk scan",
                "complete",
                vec![ev("scan", "scan_vulnerabilities", &vuln)],
            ),
        ],
        findings,
    ))
}

fn capability_survey(ws: &Workspace, max_functions: Option<u32>) -> Result<PlaybookRun> {
    let info = safe("file_info", || analysis::file_info(ws));
    let imports = safe("imports", || analysis::imports(ws));
    let strings = safe("strings_extract", || {
        analysis::strings_extract(ws, None, Some(5))
    });
    let callgraph = safe("callgraph", || analysis::call_graph(ws, Some(2)));
    let vuln = safe("scan_vulnerabilities", || {
        analysis::scan_vulnerabilities(ws, max_functions.or(Some(60)))
    });

    let mut findings = Vec::new();
    push_import_finding(&mut findings, &imports);
    push_ioc_finding(&mut findings, &strings);

    Ok(run(
        PlaybookId::CapabilitySurvey,
        "Capability survey",
        format!(
            "Capability survey complete with {} proposed findings.",
            findings.len()
        ),
        vec![
            step(
                "Binary profile",
                "complete",
                vec![ev("file", "file_info", &info)],
            ),
            step(
                "Capability imports",
                "complete",
                vec![ev("imports", "imports", &imports)],
            ),
            step(
                "String indicators",
                "complete",
                vec![ev("strings", "strings_extract", &strings)],
            ),
            step(
                "Callgraph context",
                "complete",
                vec![ev("callgraph", "callgraph", &callgraph)],
            ),
            step(
                "Risk hints",
                "complete",
                vec![ev("scan", "scan_vulnerabilities", &vuln)],
            ),
        ],
        findings,
    ))
}

fn safe(name: &str, f: impl FnOnce() -> Result<String>) -> String {
    f().unwrap_or_else(|e| format!("{} failed: {}", name, e))
}

fn run(
    id: PlaybookId,
    title: &str,
    summary: String,
    steps: Vec<PlaybookStep>,
    proposed_findings: Vec<PlaybookFinding>,
) -> PlaybookRun {
    PlaybookRun {
        id,
        title: title.into(),
        summary,
        steps,
        proposed_findings,
    }
}

fn step(title: &str, status: &str, evidence: Vec<PlaybookEvidence>) -> PlaybookStep {
    PlaybookStep {
        title: title.into(),
        status: status.into(),
        evidence,
    }
}

fn ev(label: &str, tool: &str, text: &str) -> PlaybookEvidence {
    PlaybookEvidence {
        label: label.into(),
        tool: tool.into(),
        snippet: snippet(text, 1600),
    }
}

fn snippet(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}

fn tool_evidence(tool: &str, output: &str) -> Evidence {
    Evidence::ToolOutput {
        tool: tool.into(),
        args: serde_json::json!({}),
        snippet: snippet(output, 1200),
    }
}

fn push_import_finding(out: &mut Vec<PlaybookFinding>, imports: &str) {
    let hits = find_lines(
        imports,
        &[
            "virtualalloc",
            "writeprocessmemory",
            "createremotethread",
            "loadlibrary",
            "getprocaddress",
            "internetopen",
            "winhttp",
            "socket",
            "connect",
            "strcpy",
            "sprintf",
            "memcpy",
        ],
        16,
    );
    if hits.is_empty() {
        return;
    }
    out.push(PlaybookFinding {
        kind: FindingKind::ImportOfInterest,
        severity: Severity::Med,
        vaddr: None,
        rule: "high_interest_imports".into(),
        rationale: format!(
            "High-interest imports suggest capability or vuln leads:\n{}",
            hits.join("\n")
        ),
        evidence: vec![tool_evidence("imports", imports)],
        suggested_actions: vec![
            "Use xrefs_to on import/IAT addresses to identify caller functions.".into(),
            "Rename caller functions by capability after inspecting decompile output.".into(),
        ],
    });
}

fn push_ioc_finding(out: &mut Vec<PlaybookFinding>, strings: &str) {
    let hits = find_lines(
        strings,
        &[
            "http://",
            "https://",
            ".onion",
            "user-agent",
            "powershell",
            "cmd.exe",
            "/bin/sh",
            "mutex",
            "software\\microsoft",
            "runonce",
        ],
        16,
    );
    if hits.is_empty() {
        return;
    }
    out.push(PlaybookFinding {
        kind: FindingKind::StringOfInterest,
        severity: Severity::Med,
        vaddr: None,
        rule: "ioc_string_leads".into(),
        rationale: format!("IOC/capability-like strings found:\n{}", hits.join("\n")),
        evidence: vec![tool_evidence("strings_extract", strings)],
        suggested_actions: vec![
            "Follow string xrefs to recover config, command, or network routines.".into(),
            "Promote confirmed network/file/process indicators into the case report.".into(),
        ],
    });
}

fn push_entropy_finding(out: &mut Vec<PlaybookFinding>, entropy: &str) {
    let hits = find_lines(entropy, &["packed", "high", "7.", "8."], 8);
    if hits.is_empty() {
        return;
    }
    out.push(PlaybookFinding {
        kind: FindingKind::CfgAnomaly,
        severity: Severity::Low,
        vaddr: None,
        rule: "packed_or_high_entropy_sections".into(),
        rationale: format!(
            "Entropy output suggests packed/encrypted sections:\n{}",
            hits.join("\n")
        ),
        evidence: vec![tool_evidence("section_entropy", entropy)],
        suggested_actions: vec![
            "Inspect entrypoint and early writes into executable memory.".into(),
            "Collect dynamic trace after unpacking if static strings/imports are sparse.".into(),
        ],
    });
}

fn push_vuln_finding(out: &mut Vec<PlaybookFinding>, vuln: &str) {
    let hits = find_lines(
        vuln,
        &[
            "high",
            "critical",
            "strcpy",
            "sprintf",
            "memcpy",
            "overflow",
            "injection",
        ],
        16,
    );
    if hits.is_empty() {
        return;
    }
    out.push(PlaybookFinding {
        kind: FindingKind::Vuln,
        severity: if hits.iter().any(|h| h.to_lowercase().contains("critical")) {
            Severity::Critical
        } else {
            Severity::High
        },
        vaddr: None,
        rule: "heuristic_vulnerability_scan".into(),
        rationale: format!(
            "Vulnerability scan produced high-risk leads:\n{}",
            hits.join("\n")
        ),
        evidence: vec![tool_evidence("scan_vulnerabilities", vuln)],
        suggested_actions: vec![
            "Open each referenced function and run function_context.".into(),
            "Use dataflow/slicing follow-up before confirming exploitability.".into(),
        ],
    });
}

fn find_lines(text: &str, needles: &[&str], max: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_lowercase();
        if needles.iter().any(|n| lower.contains(n)) {
            out.push(line.trim().to_string());
            if out.len() >= max {
                break;
            }
        }
    }
    out
}
