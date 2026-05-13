//! Production-workstation contracts for agents, CLI automation, and the web UI.
//!
//! This module does not try to replace the existing analyzers. It normalizes
//! their outputs into stable JSON manifests that higher-level workflows can
//! depend on while deeper engines mature.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use goblin::elf::{dynamic, header::*, program_header::*};
use object::{Object, ObjectSection, ObjectSymbol};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::tools;

pub fn workstation_status(path: Option<&Path>) -> Result<Value> {
    let binary = match path {
        Some(path) => Some(binary_index(path, 40, 40)?),
        None => None,
    };
    Ok(json!({
        "kind": "workstation_status",
        "version": 1,
        "areas": [
            area("stateful_dynamic_debug", "foundation", [
                "debug-probe supports one-shot native gdb and foreign-ELF qemu gdbstub probes",
                "runtime-run captures stdin/stdout/stderr/exit/signal with qemu auto-selection",
                "next missing piece: persistent step/read/write/snapshot sessions"
            ]),
            area("structured_binary_database", "foundation", [
                "index-build emits normalized sections/imports/functions/strings/protections",
                "next missing piece: persisted typed xref/CFG/type database"
            ]),
            area("exploit_automation_stack", "foundation", [
                "exploit-kit emits checksec, PLT/GOT text, gadget hints, cyclic helper, recipes",
                "next missing piece: ROP chain builder, libc database, seccomp parser"
            ]),
            area("agent_job_runtime", "foundation", [
                "agent-job-plan emits resumable phases, artifacts, stop criteria, verification commands",
                "next missing piece: durable job executor with per-step artifacts"
            ]),
            area("container_sysroot_manager", "foundation", [
                "sysroot-doctor detects qemu/gdb/gdb-multiarch/container tools and loader blockers",
                "next missing piece: managed sysroot/container profiles"
            ]),
            area("workbench_ui_contract", "foundation", [
                "workbench-manifest defines dense panes, hotkeys, agent evidence targets",
                "next missing piece: wire manifest into React workbench state"
            ]),
            area("benchmark_harness", "foundation", [
                "benchmark-plan inventories corpora and runtime readiness",
                "next missing piece: expected-result grading and regression dashboard"
            ]),
        ],
        "tools": tool_inventory(),
        "binary": binary,
    }))
}

pub fn binary_index(path: &Path, max_functions: usize, max_strings: usize) -> Result<Value> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha256 = hex::encode(hasher.finalize());
    let object_index = object_index(path, &data, max_functions)?;
    let elf_index = elf_index(&data).unwrap_or_else(|| json!({ "format": "unknown" }));
    let strings = tools::dispatch(
        "strings_extract",
        &json!({
            "path": path.to_string_lossy(),
            "min_len": 4,
            "max_results": max_strings,
        }),
    );
    let functions_raw = tools::dispatch(
        "list_functions",
        &json!({
            "path": path.to_string_lossy(),
            "max_results": max_functions,
            "json": true,
        }),
    );
    let functions = serde_json::from_str::<Value>(&functions_raw.output)
        .unwrap_or_else(|_| json!({ "raw": functions_raw.output }));
    Ok(json!({
        "kind": "binary_index",
        "schema_version": 1,
        "path": path,
        "size": data.len(),
        "sha256": sha256,
        "object": object_index,
        "elf": elf_index,
        "functions": functions,
        "strings": {
            "ok": !strings.output.starts_with("Error:"),
            "text": strings.output,
        },
        "contracts": {
            "address_format": "hex strings for UI/agent surfaces; raw integers may appear in legacy tool output",
            "confidence": "index-build is deterministic static inventory, not a proof of function boundaries"
        },
    }))
}

pub fn sysroot_doctor(path: Option<&Path>) -> Result<Value> {
    let binary = if let Some(path) = path {
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Some(json!({
            "path": path,
            "elf": elf_index(&data),
            "runtime_blockers": runtime_blockers(&data),
        }))
    } else {
        None
    };
    Ok(json!({
        "kind": "sysroot_doctor",
        "tools": tool_inventory(),
        "container_tools": {
            "docker": find_in_path("docker"),
            "podman": find_in_path("podman"),
            "bwrap": find_in_path("bwrap"),
            "firejail": find_in_path("firejail"),
        },
        "common_sysroots": common_sysroots(),
        "binary": binary,
        "recommended_profiles": [
            {
                "name": "native-readonly",
                "purpose": "same-arch benign analysis",
                "policy": ["read-only workspace mount", "network disabled by default", "timeout required"]
            },
            {
                "name": "qemu-foreign",
                "purpose": "foreign ELF execution/debugging",
                "policy": ["qemu-user runner", "explicit --sysroot for dynamic targets", "captured stdout/stderr"]
            },
            {
                "name": "hostile-sample",
                "purpose": "malware/unknown binary triage",
                "policy": ["container required", "network denied", "filesystem allowlist", "artifact directory only"]
            }
        ],
    }))
}

pub fn exploit_stack_manifest(path: Option<&Path>) -> Result<Value> {
    let binary = if let Some(path) = path {
        Some(binary_index(path, 20, 20)?)
    } else {
        None
    };
    Ok(json!({
        "kind": "exploit_stack_manifest",
        "helpers": [
            "exploit-context",
            "exploit-kit",
            "runtime-run",
            "debug-probe",
            "analysis-loop",
            "exploit-verify"
        ],
        "implemented": [
            "checksec-style protection summary",
            "qemu/native runtime candidates",
            "byte-pattern gadget hints",
            "PLT/GOT resolver text",
            "cyclic pattern generate/find",
            "PoC verification predicates"
        ],
        "next_engine_gaps": [
            "semantic ROP gadget verifier",
            "automatic chain builder",
            "libc/one_gadget resolver",
            "seccomp parser",
            "heap allocator model helpers",
            "shellcode assembler templates"
        ],
        "binary": binary,
    }))
}

pub fn agent_job_plan(path: Option<&Path>, goal: &str) -> Result<Value> {
    Ok(json!({
        "kind": "agent_job_plan",
        "schema_version": 1,
        "goal": goal,
        "target": path,
        "artifacts": {
            "binary_index": "index-build JSON",
            "runtime_logs": "runtime-run/debug-probe JSON",
            "candidate_poc": "/tmp/kaijulab-poc.py",
            "verification": "exploit-verify JSON",
            "report": "markdown or finding records"
        },
        "phases": [
            phase("index", "Build binary index and sysroot doctor output", ["index-build", "sysroot-doctor"]),
            phase("hypothesize", "Choose input path, target function, and exploit strategy", ["ir-query", "exploit-kit"]),
            phase("observe", "Run target or debugger to collect concrete behavior", ["runtime-run", "debug-probe"]),
            phase("produce", "Create or edit candidate artifact", ["agent console", "filesystem"]),
            phase("verify", "Run explicit success/failure predicate", ["exploit-verify"]),
            phase("review", "Attach evidence, limitations, and reproduction command", ["findings", "report"])
        ],
        "stop_criteria": [
            "success=true from verifier",
            "structured environment blocker with remediation",
            "attempt budget exhausted with last observation preserved"
        ],
        "safety": [
            "no execution without explicit runtime/debug command",
            "timeout required for dynamic commands",
            "prefer qemu/container profiles for foreign or hostile binaries"
        ],
    }))
}

pub fn workbench_manifest() -> Value {
    json!({
        "kind": "workbench_manifest",
        "layout": {
            "left": ["workspace tree", "functions", "imports", "strings"],
            "center": ["disassembly", "decompile", "hex", "CFG"],
            "right": ["inspector", "xrefs", "types", "comments"],
            "bottom": ["agent console", "runtime logs", "debug session", "findings", "benchmarks"]
        },
        "navigation_contracts": [
            "every agent evidence item should carry path/vaddr/tool/artifact id",
            "clicking function/vaddr syncs asm, decompile, xrefs, CFG, and notes",
            "runtime/debug logs link back to binary index and selected function",
            "verification artifacts are immutable unless rerun"
        ],
        "hotkeys": [
            {"key": "g", "action": "go to address"},
            {"key": "n", "action": "rename symbol"},
            {"key": ";", "action": "comment"},
            {"key": "x", "action": "xrefs"},
            {"key": "space", "action": "toggle graph/text"}
        ],
        "ui_gaps": [
            "persisted pane layout",
            "graph/decompile/hex synchronization",
            "agent evidence overlay",
            "debugger session pane"
        ],
    })
}

pub fn benchmark_plan(root: &Path, max_files: usize) -> Result<Value> {
    let mut files = Vec::new();
    collect_files(root, &mut files, max_files)?;
    let cases: Vec<Value> = files
        .iter()
        .map(|path| {
            let data = fs::read(path).unwrap_or_default();
            json!({
                "path": path,
                "size": data.len(),
                "elf": elf_index(&data),
                "runtime_blockers": runtime_blockers(&data),
                "expected_artifacts": [
                    "binary_index",
                    "runtime_smoke",
                    "debug_probe_or_blocker",
                    "agent_job_plan"
                ],
            })
        })
        .collect();
    Ok(json!({
        "kind": "benchmark_plan",
        "root": root,
        "case_count": cases.len(),
        "cases": cases,
        "grading_contract": {
            "smoke": "index-build succeeds and runtime/debug either run or return structured blocker",
            "exploit": "optional expected predicate per challenge, e.g. target exit 42",
            "regression": "case output should be diffable JSON with tool versions and binary hash"
        },
    }))
}

fn area<const N: usize>(id: &str, status: &str, notes: [&str; N]) -> Value {
    json!({ "id": id, "status": status, "notes": notes.as_slice() })
}

fn phase<const N: usize>(id: &str, objective: &str, tools: [&str; N]) -> Value {
    json!({ "id": id, "objective": objective, "tools": tools.as_slice() })
}

fn object_index(path: &Path, data: &[u8], max_functions: usize) -> Result<Value> {
    let obj = object::File::parse(data)?;
    let sections: Vec<Value> = obj
        .sections()
        .map(|section| {
            json!({
                "name": section.name().unwrap_or(""),
                "address": format!("0x{:x}", section.address()),
                "size": section.size(),
                "kind": format!("{:?}", section.kind()),
            })
        })
        .collect();
    let symbols: Vec<Value> = obj
        .symbols()
        .filter(|sym| sym.kind() == object::SymbolKind::Text && sym.address() != 0)
        .take(max_functions)
        .map(|sym| {
            json!({
                "name": sym.name().unwrap_or(""),
                "address": format!("0x{:x}", sym.address()),
                "size": sym.size(),
            })
        })
        .collect();
    Ok(json!({
        "path": path,
        "architecture": format!("{:?}", obj.architecture()),
        "is_64": obj.is_64(),
        "endianness": format!("{:?}", obj.endianness()),
        "entry_hint": symbols.first().and_then(|s| s.get("address")).cloned(),
        "sections": sections,
        "text_symbols_sample": symbols,
    }))
}

fn elf_index(data: &[u8]) -> Option<Value> {
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return None;
    };
    let arch = match (elf.header.e_machine, elf.is_64) {
        (EM_X86_64, _) => "x86_64".to_string(),
        (EM_386, _) => "i386".to_string(),
        (EM_AARCH64, _) => "aarch64".to_string(),
        (EM_ARM, _) => "arm".to_string(),
        (_, true) => format!("machine:{}-64", elf.header.e_machine),
        _ => format!("machine:{}-32", elf.header.e_machine),
    };
    let imports: Vec<&str> = elf
        .dynsyms
        .iter()
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .filter(|s| !s.is_empty())
        .take(80)
        .collect();
    Some(json!({
        "format": "ELF",
        "arch": arch,
        "entry": format!("0x{:x}", elf.entry),
        "interpreter": elf.interpreter,
        "protections": elf_protections(&elf),
        "imports_sample": imports,
    }))
}

fn elf_protections(elf: &goblin::elf::Elf<'_>) -> Value {
    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK);
    let nx = gnu_stack.map(|ph| ph.p_flags & PF_X == 0).unwrap_or(true);
    let relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().map_or(false, |dyns| {
        dyns.dyns.iter().any(|d| {
            d.d_tag == dynamic::DT_BIND_NOW
                || (d.d_tag == dynamic::DT_FLAGS && d.d_val & dynamic::DF_BIND_NOW != 0)
                || (d.d_tag == dynamic::DT_FLAGS_1 && d.d_val & dynamic::DF_1_NOW != 0)
        })
    });
    let canary = elf
        .dynsyms
        .iter()
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .any(|s| s == "__stack_chk_fail" || s == "__stack_chk_guard");
    json!({
        "nx": nx,
        "pie": elf.is_lib,
        "relro": if relro && bind_now { "full" } else if relro { "partial" } else { "none" },
        "canary_import": canary,
        "static": elf.interpreter.is_none(),
    })
}

fn runtime_blockers(data: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return out;
    };
    if let Some(interpreter) = elf.interpreter {
        if !Path::new(interpreter).exists() {
            out.push(json!({
                "kind": "missing_interpreter",
                "path": interpreter,
                "hint": if interpreter.ends_with("ld-linux.so.2") {
                    "install libc6:i386 or pass qemu -L <i386-sysroot>"
                } else {
                    "install matching loader/sysroot or pass qemu -L <sysroot>"
                },
            }));
        }
    }
    out
}

fn tool_inventory() -> Value {
    json!({
        "gdb": find_in_path("gdb"),
        "gdb_multiarch": find_in_path("gdb-multiarch"),
        "qemu_i386": find_in_path("qemu-i386-static").or_else(|| find_in_path("qemu-i386")),
        "qemu_x86_64": find_in_path("qemu-x86_64-static").or_else(|| find_in_path("qemu-x86_64")),
        "qemu_arm": find_in_path("qemu-arm-static").or_else(|| find_in_path("qemu-arm")),
        "qemu_aarch64": find_in_path("qemu-aarch64-static").or_else(|| find_in_path("qemu-aarch64")),
    })
}

fn common_sysroots() -> Vec<Value> {
    [
        "/usr/i386-linux-gnu",
        "/usr/x86_64-linux-gnu",
        "/usr/arm-linux-gnueabihf",
        "/usr/aarch64-linux-gnu",
        "/opt/sysroots/i386",
        "/opt/sysroots/x86_64",
    ]
    .iter()
    .map(|path| json!({ "path": path, "exists": Path::new(path).exists() }))
    .collect()
}

fn find_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>, max_files: usize) -> Result<()> {
    if out.len() >= max_files {
        return Ok(());
    }
    if root.is_file() {
        out.push(root.to_path_buf());
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read dir {}", root.display()))? {
        if out.len() >= max_files {
            break;
        }
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out, max_files)?;
        } else if is_probable_binary(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_probable_binary(path: &Path) -> bool {
    if path.extension().is_some_and(|ext| {
        matches!(
            ext.to_string_lossy().as_ref(),
            "html" | "htm" | "md" | "txt" | "py" | "json" | "db"
        )
    }) {
        return false;
    }
    fs::read(path)
        .map(|data| goblin::Object::parse(&data).is_ok())
        .unwrap_or(false)
}
