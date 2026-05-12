//! Command palette executor.  Parses single-line commands and dispatches them
//! to the same core APIs used by REST/MCP, so the palette is a uniform
//! power-user spine across clients.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ts_rs::TS;

use crate::core::{analysis, events::Source, project_store};

use super::AppState;

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct PaletteRequest {
    pub input: String,
    #[serde(default)]
    pub current_vaddr: Option<String>,
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaletteResult {
    Navigate { vaddr: String },
    Text { text: String },
    Ok { message: String },
    Error { message: String },
}

pub async fn exec(State(s): State<AppState>, Json(req): Json<PaletteRequest>) -> Json<Value> {
    let result = run(&s, &req);
    Json(json!(result))
}

fn run(s: &AppState, req: &PaletteRequest) -> PaletteResult {
    let input = req.input.trim();
    if input.is_empty() {
        return PaletteResult::Error {
            message: "empty command".into(),
        };
    }

    // Bare address jump: "0x401000" or "401000"
    if let Some(v) = try_parse_vaddr(input) {
        return PaletteResult::Navigate {
            vaddr: format!("0x{:x}", v),
        };
    }

    // Slash commands
    if let Some(cmd) = input.strip_prefix('/') {
        return run_slash(s, cmd, req.current_vaddr.as_deref());
    }

    // Bare symbol: try to match a renamed function name; otherwise navigate
    // to a vaddr if the inner list_functions output contains it.
    let needle = input.to_ascii_lowercase();
    let hit = s.workspace.with_project(|p| {
        p.renames
            .iter()
            .find(|(_, name)| name.to_ascii_lowercase().contains(&needle))
            .map(|(v, _)| *v)
    });
    if let Some(v) = hit {
        return PaletteResult::Navigate {
            vaddr: format!("0x{:x}", v),
        };
    }
    PaletteResult::Error {
        message: format!("no match for '{}'", input),
    }
}

fn run_slash(s: &AppState, cmd: &str, current_vaddr: Option<&str>) -> PaletteResult {
    let mut parts = cmd.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();

    match head {
        "rename" => {
            let mut a = rest.splitn(2, char::is_whitespace);
            let v_s = a.next().unwrap_or("");
            let name = a.next().unwrap_or("").trim();
            let Some(v) = try_parse_vaddr(v_s) else {
                return PaletteResult::Error {
                    message: "usage: /rename <vaddr> <name>".into(),
                };
            };
            if name.is_empty() {
                return PaletteResult::Error {
                    message: "usage: /rename <vaddr> <name>".into(),
                };
            }
            match project_store::rename_function(&s.workspace, &s.events, v, name, Source::User) {
                Ok(_) => PaletteResult::Ok {
                    message: format!("renamed 0x{:x} → {}", v, name),
                },
                Err(e) => PaletteResult::Error {
                    message: e.to_string(),
                },
            }
        }
        "comment" => {
            let mut a = rest.splitn(2, char::is_whitespace);
            let v_s = a.next().unwrap_or("");
            let text = a.next().unwrap_or("").trim();
            let Some(v) = try_parse_vaddr(v_s) else {
                return PaletteResult::Error {
                    message: "usage: /comment <vaddr> <text>".into(),
                };
            };
            match project_store::add_comment(&s.workspace, &s.events, v, text, Source::User) {
                Ok(_) => PaletteResult::Ok {
                    message: format!("comment @ 0x{:x}", v),
                },
                Err(e) => PaletteResult::Error {
                    message: e.to_string(),
                },
            }
        }
        "note" => {
            let v = current_vaddr.and_then(try_parse_vaddr);
            match project_store::add_note(&s.workspace, &s.events, rest, v, Source::User) {
                Ok(n) => PaletteResult::Ok {
                    message: format!("note #{}", n.id),
                },
                Err(e) => PaletteResult::Error {
                    message: e.to_string(),
                },
            }
        }
        "scan" => match rest {
            "vuln" => match analysis::scan_vulnerabilities(&s.workspace, None) {
                Ok(text) => PaletteResult::Text { text },
                Err(e) => PaletteResult::Error {
                    message: e.to_string(),
                },
            },
            _ => PaletteResult::Error {
                message: "usage: /scan vuln".into(),
            },
        },
        "goto" => try_parse_vaddr(rest)
            .map(|v| PaletteResult::Navigate {
                vaddr: format!("0x{:x}", v),
            })
            .unwrap_or(PaletteResult::Error {
                message: "usage: /goto <vaddr>".into(),
            }),
        "info" => match analysis::file_info(&s.workspace) {
            Ok(text) => PaletteResult::Text { text },
            Err(e) => PaletteResult::Error {
                message: e.to_string(),
            },
        },
        _ => PaletteResult::Error {
            message: format!("unknown command: /{}", head),
        },
    }
}

fn try_parse_vaddr(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let hex = t.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).ok()
}
