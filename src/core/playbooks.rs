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
    CommandHandlerHunt,
    LicenseCheckHunt,
    CryptoSecretHunt,
    NetworkParserHunt,
    AuthBypassReview,
}

impl PlaybookId {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "malware_triage" => Ok(Self::MalwareTriage),
            "ctf_flag_hunt" => Ok(Self::CtfFlagHunt),
            "vulnerability_audit" => Ok(Self::VulnerabilityAudit),
            "capability_survey" => Ok(Self::CapabilitySurvey),
            "command_handler_hunt" => Ok(Self::CommandHandlerHunt),
            "license_check_hunt" => Ok(Self::LicenseCheckHunt),
            "crypto_secret_hunt" => Ok(Self::CryptoSecretHunt),
            "network_parser_hunt" => Ok(Self::NetworkParserHunt),
            "auth_bypass_review" => Ok(Self::AuthBypassReview),
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
        Playbook {
            id: PlaybookId::CommandHandlerHunt,
            title: "Command handlers".into(),
            audience: "beginner analyst".into(),
            goal: "Rank likely command dispatchers, opcode parsers, verb tables, and switch-heavy control paths.".into(),
            steps: vec![
                "Search strings for command verbs and parser errors".into(),
                "Scan function inventory for dispatch/table names".into(),
                "Collect vulnerability hints that often sit near handlers".into(),
                "Produce next functions to inspect with evidence".into(),
            ],
        },
        Playbook {
            id: PlaybookId::LicenseCheckHunt,
            title: "License checks".into(),
            audience: "beginner analyst".into(),
            goal: "Find serial, trial, activation, comparison, and patchable branch leads.".into(),
            steps: vec![
                "Search user-facing strings for trial/license/auth wording".into(),
                "Find comparison and crypto-adjacent imports".into(),
                "Rank candidate checker functions".into(),
            ],
        },
        Playbook {
            id: PlaybookId::CryptoSecretHunt,
            title: "Crypto and secrets".into(),
            audience: "malware and product analyst".into(),
            goal: "Surface hardcoded keys, crypto constants, hashing APIs, and decoding routines.".into(),
            steps: vec![
                "Search imports for crypto and hashing APIs".into(),
                "Search strings for keys, tokens, certificates, and encodings".into(),
                "Run risk scan for decoder/decryption leads".into(),
            ],
        },
        Playbook {
            id: PlaybookId::NetworkParserHunt,
            title: "Network parsers".into(),
            audience: "protocol reverse engineer".into(),
            goal: "Find socket/HTTP ingress, parser errors, packet format hints, and unsafe parsing leads.".into(),
            steps: vec![
                "Collect network imports and URL/protocol strings".into(),
                "Search for parser grammar, length, and error strings".into(),
                "Run vulnerability scan for parsing sinks".into(),
            ],
        },
        Playbook {
            id: PlaybookId::AuthBypassReview,
            title: "Auth bypass".into(),
            audience: "security reviewer".into(),
            goal: "Find authentication gates, role checks, authorization strings, and branches needing evidence review.".into(),
            steps: vec![
                "Search auth, role, token, and permission strings".into(),
                "Collect imports used by auth and token validation".into(),
                "Create review leads with confirmation steps".into(),
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
        PlaybookId::CommandHandlerHunt => expert_hunt(
            ws,
            PlaybookId::CommandHandlerHunt,
            "Command handlers",
            max_functions,
            &[
                "command", "cmd", "opcode", "dispatch", "handler", "verb", "request",
                "response", "unknown command", "invalid opcode", "switch",
            ],
            &[
                "recv", "read", "fgets", "strtok", "strcmp", "strncmp", "memcmp",
                "getopt", "argparse",
            ],
            "command_handler_leads",
            "Command/dispatch evidence found. Prioritize xrefs from strings/imports into switch or table-driven functions.",
        ),
        PlaybookId::LicenseCheckHunt => expert_hunt(
            ws,
            PlaybookId::LicenseCheckHunt,
            "License checks",
            max_functions,
            &[
                "license", "serial", "activation", "activate", "trial", "expired",
                "registered", "registration", "valid", "invalid", "password",
            ],
            &[
                "strcmp", "strncmp", "memcmp", "crypt", "sha", "md5", "getvolume",
                "regopenkey", "regqueryvalue",
            ],
            "license_check_leads",
            "License/authentication evidence found. Inspect comparison callers and patch-sensitive success/failure branches.",
        ),
        PlaybookId::CryptoSecretHunt => expert_hunt(
            ws,
            PlaybookId::CryptoSecretHunt,
            "Crypto and secrets",
            max_functions,
            &[
                "key", "secret", "token", "password", "private", "public key", "BEGIN ",
                "certificate", "base64", "aes", "rsa", "sha", "md5", "salt",
            ],
            &[
                "crypt", "bcrypt", "openssl", "EVP_", "AES_", "RSA_", "SHA", "MD5",
                "CryptAcquireContext", "BCrypt",
            ],
            "crypto_secret_leads",
            "Crypto or secret material evidence found. Confirm whether constants are test data, public material, or sensitive runtime secrets.",
        ),
        PlaybookId::NetworkParserHunt => expert_hunt(
            ws,
            PlaybookId::NetworkParserHunt,
            "Network parsers",
            max_functions,
            &[
                "http", "https", "socket", "packet", "header", "content-length",
                "user-agent", "parse", "malformed", "protocol", "request",
            ],
            &[
                "socket", "connect", "recv", "send", "accept", "listen", "WinHttp",
                "InternetOpen", "curl", "read",
            ],
            "network_parser_leads",
            "Network/parser evidence found. Trace ingress buffers into length checks, copies, and dispatch routines.",
        ),
        PlaybookId::AuthBypassReview => expert_hunt(
            ws,
            PlaybookId::AuthBypassReview,
            "Auth bypass",
            max_functions,
            &[
                "auth", "authorize", "permission", "role", "admin", "token", "session",
                "denied", "forbidden", "unauthorized", "login", "logout",
            ],
            &[
                "strcmp", "strncmp", "memcmp", "jwt", "crypt", "sha", "getenv",
                "RegQueryValue", "sqlite",
            ],
            "auth_bypass_review_leads",
            "Authentication/authorization evidence found. Confirm callers enforce failure paths before trusting the gate.",
        ),
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

fn expert_hunt(
    ws: &Workspace,
    id: PlaybookId,
    title: &str,
    max_functions: Option<u32>,
    string_needles: &[&str],
    import_needles: &[&str],
    rule: &str,
    rationale: &str,
) -> Result<PlaybookRun> {
    let strings = safe("strings_extract", || {
        analysis::strings_extract(ws, None, Some(4))
    });
    let imports = safe("imports", || analysis::imports(ws));
    let functions = safe("list_functions", || analysis::list_functions(ws, false));
    let vuln = safe("scan_vulnerabilities", || {
        analysis::scan_vulnerabilities(ws, max_functions.or(Some(160)))
    });

    let string_hits = find_lines(&strings, string_needles, 18);
    let import_hits = find_lines(&imports, import_needles, 18);
    let function_hits = find_lines(&functions, string_needles, 18);
    let mut findings = Vec::new();

    if !string_hits.is_empty() || !import_hits.is_empty() || !function_hits.is_empty() {
        findings.push(PlaybookFinding {
            kind: FindingKind::StringOfInterest,
            severity: Severity::Med,
            vaddr: None,
            rule: rule.into(),
            rationale: format!(
                "{rationale}\n\nString leads:\n{}\n\nImport leads:\n{}\n\nFunction-name leads:\n{}",
                empty_dash(&string_hits),
                empty_dash(&import_hits),
                empty_dash(&function_hits)
            ),
            evidence: vec![
                tool_evidence("strings_extract", &strings),
                tool_evidence("imports", &imports),
                tool_evidence("list_functions", &functions),
            ],
            suggested_actions: vec![
                "Follow xrefs from the strongest string/import lead into caller functions.".into(),
                "Rename confirmed handlers/checkers immediately so later evidence reads like source.".into(),
                "Run agent triage on the top candidate and require address-backed evidence before confirming.".into(),
            ],
        });
    }
    push_vuln_finding(&mut findings, &vuln);

    Ok(run(
        id,
        title,
        format!(
            "{} string leads, {} import leads, {} function-name leads, {} proposed findings.",
            string_hits.len(),
            import_hits.len(),
            function_hits.len(),
            findings.len()
        ),
        vec![
            step(
                "String leads",
                "complete",
                vec![ev("strings", "strings_extract", &string_hits.join("\n"))],
            ),
            step(
                "Import leads",
                "complete",
                vec![ev("imports", "imports", &import_hits.join("\n"))],
            ),
            step(
                "Function-name leads",
                "complete",
                vec![ev("functions", "list_functions", &function_hits.join("\n"))],
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

fn empty_dash(lines: &[String]) -> String {
    if lines.is_empty() {
        "-".into()
    } else {
        lines.join("\n")
    }
}
