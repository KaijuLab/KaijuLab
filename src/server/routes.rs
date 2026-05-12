//! REST routes for `kaijulab serve`.

use std::path::PathBuf;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ts_rs::TS;

use crate::{
    agent_bridge::{
        claude::ClaudeAdapter,
        codex::CodexAdapter,
        prompts::{report_section_prompt, triage_prompt, yara_prompt, TriageOutput},
        scope::{ContextPack, Target as AgentTarget},
        WritePolicy as AgentWritePolicy,
    },
    core::{
        analysis,
        events::Source,
        findings::{
            self, CreateFinding, CreatedBy, Evidence, Finding, FindingKind, Severity, UpdateFinding,
        },
        playbooks::{self, PlaybookId, PlaybookRunRequest},
        project_store,
        workspace::{read_recent, socket_path_for, Workspace},
    },
};

use super::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        // Workspace management
        .route("/api/workspaces", get(list_workspaces))
        .route("/api/workspaces/open", post(open_workspace))
        .route("/api/workspaces/upload", post(upload_workspace))
        .route("/api/workspaces/recent", get(get_recent))
        .route("/api/workspaces/:hash/activate", post(activate_workspace))
        .route("/api/workspaces/:hash", delete(close_workspace))
        // Active-workspace data
        .route("/api/workspace", get(get_active))
        .route("/api/binary/info", get(binary_info))
        .route("/api/sections", get(sections))
        .route("/api/imports", get(imports))
        .route("/api/strings", get(strings))
        .route("/api/functions", get(list_functions))
        .route("/api/functions/:vaddr/disasm", get(disasm))
        .route("/api/functions/:vaddr/decompile", get(decompile))
        .route("/api/functions/:vaddr/context", get(function_context))
        .route("/api/functions/:vaddr/xrefs", get(xrefs))
        .route("/api/graph/callgraph", get(callgraph))
        .route("/api/graph/cfg/:vaddr", get(cfg))
        .route("/api/project", get(project_snapshot))
        .route("/api/project/renames", post(post_rename))
        .route("/api/project/comments", post(post_comment))
        .route("/api/project/notes", post(post_note))
        .route("/api/project/notes/:id", delete(delete_note))
        .route("/api/project/vuln-scores", post(post_vuln_score))
        .route("/api/findings", get(list_findings).post(create_finding))
        .route("/api/findings/:id", get(get_finding).patch(update_finding))
        .route("/api/scans/vuln", post(start_vuln_scan))
        .route("/api/playbooks", get(list_playbooks))
        .route("/api/playbooks/:id/run", post(run_playbook))
        .route("/api/agents/:agent/run", post(run_agent))
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/:id", get(get_job))
        .route("/api/jobs/:id/cancel", post(cancel_job))
        .route("/api/palette/exec", post(super::palette::exec))
        .with_state(state)
}

fn active(s: &AppState) -> Result<Workspace, ApiError> {
    s.registry
        .active()
        .ok_or_else(|| ApiError::not_found("no active workspace — open a binary first"))
}

/// Open a binary as a workspace and spawn its per-workspace Unix-socket
/// listener so MCP shims attach correctly.  Used by main.rs at startup and by
/// the open / upload REST handlers.
pub fn open_and_spawn(s: &AppState, path: &std::path::Path) -> Result<Workspace, ApiError> {
    let ws = s
        .registry
        .open(path)
        .map_err(|e| ApiError::bad_request(format!("open failed: {}", e)))?;
    let socket = socket_path_for(ws.workspace_hash())
        .map_err(|e| ApiError::internal(format!("socket path: {}", e)))?;
    // Spawn (idempotent on existing sockets — spawn_server removes stale files).
    if let Err(e) = crate::ipc::spawn_server(socket, ws.clone(), s.events.clone()) {
        tracing::warn!("ipc socket for {} disabled: {}", ws.binary_path_str(), e);
    }
    Ok(ws)
}

// ─── Health & workspace ──────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn get_active(State(s): State<AppState>) -> Json<Value> {
    match s.registry.active() {
        Some(ws) => Json(json!(ws.info())),
        None => Json(Value::Null),
    }
}

async fn list_workspaces(State(s): State<AppState>) -> Json<Value> {
    Json(json!(s.registry.snapshot()))
}

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct OpenWorkspaceRequest {
    pub path: String,
}

async fn open_workspace(
    State(s): State<AppState>,
    Json(req): Json<OpenWorkspaceRequest>,
) -> Result<Json<Value>, ApiError> {
    let path = std::path::PathBuf::from(&req.path);
    let ws = open_and_spawn(&s, &path)?;
    Ok(Json(json!(ws.info())))
}

async fn upload_workspace(
    State(s): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, ApiError> {
    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("multipart: {}", e)))?
    {
        if field.name() == Some("file") {
            filename = field.file_name().map(|s| s.to_string());
            let data = field
                .bytes()
                .await
                .map_err(|e| ApiError::bad_request(format!("read: {}", e)))?;
            bytes = Some(data.to_vec());
        }
    }
    let filename = filename.ok_or_else(|| ApiError::bad_request("missing file field"))?;
    let bytes = bytes.ok_or_else(|| ApiError::bad_request("empty upload"))?;

    let upload_dir: PathBuf = {
        let home = std::env::var("HOME").map_err(|_| ApiError::internal("HOME not set"))?;
        let dir = PathBuf::from(home).join(".kaiju").join("uploads");
        std::fs::create_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;
        dir
    };
    // Strip any path component a malicious client might have stuffed into the
    // filename — we only honour the basename.
    let safe = std::path::Path::new(&filename)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| ApiError::bad_request("invalid filename"))?;
    let dest = upload_dir.join(safe);
    std::fs::write(&dest, &bytes).map_err(|e| ApiError::internal(e.to_string()))?;

    let ws = open_and_spawn(&s, &dest)?;
    Ok(Json(json!(ws.info())))
}

async fn get_recent() -> Json<Value> {
    Json(json!(read_recent()))
}

async fn activate_workspace(
    State(s): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if s.registry.activate(&hash) {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(ApiError::not_found("workspace not found"))
    }
}

async fn close_workspace(State(s): State<AppState>, Path(hash): Path<String>) -> Json<Value> {
    let removed = s.registry.close(&hash);
    Json(json!({ "removed": removed }))
}

// ─── Binary info ─────────────────────────────────────────────────────────────

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct TextResponse {
    pub text: String,
}

async fn binary_info(State(s): State<AppState>) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(TextResponse {
        text: analysis::file_info(&ws).map_err(ApiError::from)?,
    }))
}

async fn sections(State(s): State<AppState>) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(TextResponse {
        text: analysis::sections(&ws).map_err(ApiError::from)?,
    }))
}

async fn imports(State(s): State<AppState>) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(TextResponse {
        text: analysis::imports(&ws).map_err(ApiError::from)?,
    }))
}

#[derive(Deserialize)]
struct StringsQuery {
    section: Option<String>,
    min_len: Option<u32>,
}

async fn strings(
    State(s): State<AppState>,
    Query(q): Query<StringsQuery>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(TextResponse {
        text: analysis::strings_extract(&ws, q.section.as_deref(), q.min_len)
            .map_err(ApiError::from)?,
    }))
}

// ─── Functions ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct FunctionsQuery {
    #[serde(default)]
    json: bool,
}

async fn list_functions(
    State(s): State<AppState>,
    Query(q): Query<FunctionsQuery>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let raw = analysis::list_functions(&ws, q.json).map_err(ApiError::from)?;
    if q.json {
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(Json(parsed))
    } else {
        Ok(Json(json!({ "text": raw })))
    }
}

#[derive(Deserialize)]
struct DisasmQuery {
    length: Option<u32>,
}

async fn disasm(
    State(s): State<AppState>,
    Path(vaddr): Path<String>,
    Query(q): Query<DisasmQuery>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&vaddr)?;
    Ok(Json(TextResponse {
        text: analysis::disassemble(&ws, v, q.length).map_err(ApiError::from)?,
    }))
}

async fn decompile(
    State(s): State<AppState>,
    Path(vaddr): Path<String>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&vaddr)?;
    Ok(Json(TextResponse {
        text: analysis::decompile(&ws, v).map_err(ApiError::from)?,
    }))
}

async fn function_context(
    State(s): State<AppState>,
    Path(vaddr): Path<String>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&vaddr)?;
    Ok(Json(TextResponse {
        text: analysis::function_context(&ws, v).map_err(ApiError::from)?,
    }))
}

async fn xrefs(
    State(s): State<AppState>,
    Path(vaddr): Path<String>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&vaddr)?;
    Ok(Json(TextResponse {
        text: analysis::xrefs_to(&ws, v).map_err(ApiError::from)?,
    }))
}

#[derive(Deserialize)]
struct CallgraphQuery {
    max_depth: Option<u32>,
}

async fn callgraph(
    State(s): State<AppState>,
    Query(q): Query<CallgraphQuery>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(TextResponse {
        text: analysis::call_graph(&ws, q.max_depth).map_err(ApiError::from)?,
    }))
}

async fn cfg(
    State(s): State<AppState>,
    Path(vaddr): Path<String>,
) -> Result<Json<TextResponse>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&vaddr)?;
    Ok(Json(TextResponse {
        text: analysis::cfg_view(&ws, v).map_err(ApiError::from)?,
    }))
}

// ─── Project annotations ─────────────────────────────────────────────────────

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct ProjectSnapshot {
    pub renames: Vec<RenameEntry>,
    pub comments: Vec<CommentEntry>,
    pub notes: Vec<NoteEntry>,
    pub vuln_scores: Vec<VulnScoreEntry>,
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct RenameEntry {
    pub vaddr: String,
    pub name: String,
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct CommentEntry {
    pub vaddr: String,
    pub text: String,
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct NoteEntry {
    pub id: i64,
    pub vaddr: Option<String>,
    pub text: String,
    pub timestamp: String,
}

#[derive(Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
struct VulnScoreEntry {
    pub vaddr: String,
    pub score: u8,
}

async fn project_snapshot(State(s): State<AppState>) -> Result<Json<ProjectSnapshot>, ApiError> {
    let ws = active(&s)?;
    let snap = ws.with_project(|p| ProjectSnapshot {
        renames: p
            .renames
            .iter()
            .map(|(k, v)| RenameEntry {
                vaddr: format!("0x{:x}", k),
                name: v.clone(),
            })
            .collect(),
        comments: p
            .comments
            .iter()
            .map(|(k, v)| CommentEntry {
                vaddr: format!("0x{:x}", k),
                text: v.clone(),
            })
            .collect(),
        notes: p
            .notes
            .iter()
            .map(|n| NoteEntry {
                id: n.id,
                vaddr: n.vaddr.map(|v| format!("0x{:x}", v)),
                text: n.text.clone(),
                timestamp: n.timestamp.clone(),
            })
            .collect(),
        vuln_scores: p
            .vuln_scores
            .iter()
            .map(|(k, v)| VulnScoreEntry {
                vaddr: format!("0x{:x}", k),
                score: *v,
            })
            .collect(),
    });
    Ok(Json(snap))
}

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct RenameRequest {
    pub vaddr: String,
    pub name: String,
    #[serde(default)]
    pub source: Option<String>,
}

async fn post_rename(
    State(s): State<AppState>,
    Json(req): Json<RenameRequest>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&req.vaddr)?;
    let src = req
        .source
        .as_deref()
        .map(Source::from_str_or_user)
        .unwrap_or(Source::User);
    project_store::rename_function(&ws, &s.events, v, &req.name, src).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct CommentRequest {
    pub vaddr: String,
    pub text: String,
    #[serde(default)]
    pub source: Option<String>,
}

async fn post_comment(
    State(s): State<AppState>,
    Json(req): Json<CommentRequest>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&req.vaddr)?;
    let src = req
        .source
        .as_deref()
        .map(Source::from_str_or_user)
        .unwrap_or(Source::User);
    project_store::add_comment(&ws, &s.events, v, &req.text, src).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct NoteRequest {
    pub text: String,
    #[serde(default)]
    pub vaddr: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

async fn post_note(
    State(s): State<AppState>,
    Json(req): Json<NoteRequest>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let v = req.vaddr.as_deref().map(parse_vaddr).transpose()?;
    let src = req
        .source
        .as_deref()
        .map(Source::from_str_or_user)
        .unwrap_or(Source::User);
    let note =
        project_store::add_note(&ws, &s.events, &req.text, v, src).map_err(ApiError::from)?;
    Ok(Json(json!({
        "id": note.id,
        "timestamp": note.timestamp,
    })))
}

async fn delete_note(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let removed =
        project_store::delete_note(&ws, &s.events, id, Source::User).map_err(ApiError::from)?;
    Ok(Json(json!({ "removed": removed })))
}

#[derive(Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct VulnScoreRequest {
    pub vaddr: String,
    pub score: u8,
    #[serde(default)]
    pub source: Option<String>,
}

async fn post_vuln_score(
    State(s): State<AppState>,
    Json(req): Json<VulnScoreRequest>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let v = parse_vaddr(&req.vaddr)?;
    let src = req
        .source
        .as_deref()
        .map(Source::from_str_or_user)
        .unwrap_or(Source::User);
    project_store::set_vuln_score(&ws, &s.events, v, req.score, src).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

// ─── Findings ────────────────────────────────────────────────────────────────

async fn list_findings(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    Ok(Json(json!(findings::list_findings(&ws))))
}

async fn get_finding(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    findings::get_finding(&ws, &id)
        .map(|f| Json(json!(f)))
        .ok_or_else(|| ApiError::not_found("finding not found"))
}

async fn create_finding(
    State(s): State<AppState>,
    Json(req): Json<CreateFinding>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let f = findings::create_finding(&ws, req).map_err(ApiError::from)?;
    emit_finding_created(&s, &f, Source::Tool);
    Ok(Json(json!(f)))
}

async fn update_finding(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateFinding>,
) -> Result<Json<Value>, ApiError> {
    use crate::core::events::{now_ts, Event};
    let status_str = req.status.map(|st| {
        serde_json::to_string(&st)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string()
    });
    let owner_clone = req.owner.clone();
    let ws = active(&s)?;
    let f = findings::update_finding(&ws, &id, req)
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("finding not found"))?;
    s.events.emit(Event::FindingUpdated {
        id: f.id.clone(),
        status: status_str,
        owner: owner_clone,
        source: Source::User,
        ts: now_ts(),
    });
    Ok(Json(json!(f)))
}

fn emit_finding_created(s: &AppState, finding: &Finding, source: Source) {
    use crate::core::events::{now_ts, Event};
    let kind_str = serde_json::to_string(&finding.kind).unwrap_or_else(|_| "custom".into());
    let sev_str = serde_json::to_string(&finding.severity).unwrap_or_else(|_| "info".into());
    s.events.emit(Event::FindingCreated {
        id: finding.id.clone(),
        kind: kind_str.trim_matches('"').to_string(),
        severity: sev_str.trim_matches('"').to_string(),
        vaddr: finding.vaddr.clone(),
        rule: finding.rule.clone(),
        source,
        ts: now_ts(),
    });
}

// ─── Jobs ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VulnScanRequest {
    max_fns: Option<u32>,
}

async fn start_vuln_scan(
    State(s): State<AppState>,
    Json(req): Json<VulnScanRequest>,
) -> Result<Json<Value>, ApiError> {
    use crate::core::jobs::JobKind;
    let ws = active(&s)?;
    let (job_id, _token) = s.jobs.register(JobKind::ScanVuln);
    let runner = s.jobs.clone();
    let id_for_task = job_id.0.clone();
    tokio::task::spawn_blocking(
        move || match analysis::scan_vulnerabilities(&ws, req.max_fns) {
            Ok(text) => runner.finish(
                &crate::core::jobs::JobId(id_for_task),
                Some(format!("{} chars", text.len())),
            ),
            Err(e) => runner.fail(&crate::core::jobs::JobId(id_for_task), e.to_string()),
        },
    );
    Ok(Json(json!({ "job_id": job_id.0 })))
}

// ─── Playbooks ───────────────────────────────────────────────────────────────

async fn list_playbooks() -> Json<Value> {
    Json(json!(playbooks::list_playbooks()))
}

async fn run_playbook(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PlaybookRunRequest>,
) -> Result<Json<Value>, ApiError> {
    let ws = active(&s)?;
    let id = PlaybookId::parse(&id).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let run = playbooks::run_playbook(&ws, id, req.max_functions).map_err(ApiError::from)?;
    let created_findings = if req.create_findings {
        persist_playbook_findings(&ws, &s, &run)?
    } else {
        Vec::new()
    };
    Ok(Json(json!({
        "run": run,
        "created_findings": created_findings,
    })))
}

fn persist_playbook_findings(
    ws: &Workspace,
    s: &AppState,
    run: &playbooks::PlaybookRun,
) -> Result<Vec<String>, ApiError> {
    let mut ids = Vec::new();
    for proposed in &run.proposed_findings {
        let kind = proposed.kind.clone();
        let severity = proposed.severity;
        let finding = findings::create_finding(
            ws,
            CreateFinding {
                kind,
                severity,
                vaddr: proposed.vaddr.clone(),
                rule: proposed.rule.clone(),
                rationale: proposed.rationale.clone(),
                evidence: proposed.evidence.clone(),
                suggested_actions: proposed.suggested_actions.clone(),
                created_by: CreatedBy::Tool {
                    name: format!("{:?}", run.id),
                },
            },
        )
        .map_err(ApiError::from)?;
        emit_finding_created(s, &finding, Source::Tool);
        ids.push(finding.id);
    }
    Ok(ids)
}

async fn list_jobs(State(s): State<AppState>) -> Json<Value> {
    Json(json!(s.jobs.list()))
}

async fn get_job(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    s.jobs
        .get(&id)
        .map(|j| Json(json!(j)))
        .ok_or_else(|| ApiError::not_found("job not found"))
}

async fn cancel_job(State(s): State<AppState>, Path(id): Path<String>) -> Json<Value> {
    let cancelled = s.jobs.cancel(&id);
    Json(json!({ "cancelled": cancelled }))
}

// ─── Agent bridge ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../web/src/types/")]
pub enum AgentRunKind {
    Triage,
    ReportSection,
    Yara,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct AgentRunRequest {
    pub kind: AgentRunKind,
    pub vaddr: String,
    #[serde(default)]
    pub write_policy: Option<AgentWritePolicy>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../web/src/types/")]
pub struct AgentRunResponse {
    pub agent: String,
    pub kind: String,
    pub job_id: String,
    pub text: String,
    pub created_finding_id: Option<String>,
    pub applied: bool,
}

async fn run_agent(
    State(s): State<AppState>,
    Path(agent): Path<String>,
    Json(req): Json<AgentRunRequest>,
) -> Result<Json<AgentRunResponse>, ApiError> {
    use crate::core::jobs::{JobId, JobKind};

    let ws = active(&s)?;
    let vaddr = parse_vaddr(&req.vaddr)?;
    let source = match agent.as_str() {
        "claude" => Source::Claude,
        "codex" => Source::Codex,
        _ => return Err(ApiError::bad_request("agent must be claude or codex")),
    };
    let write_policy = req.write_policy.unwrap_or(AgentWritePolicy::Suggest);
    let pack = build_context_pack(&ws, vaddr, write_policy)?;
    let prompt = match req.kind {
        AgentRunKind::Triage => triage_prompt(&pack),
        AgentRunKind::ReportSection => report_section_prompt(&pack),
        AgentRunKind::Yara => yara_prompt(&pack),
    };

    let (job_id, _token) = s.jobs.register(JobKind::AgentBridge);
    let job = JobId(job_id.0.clone());
    let result = match agent.as_str() {
        "claude" => ClaudeAdapter::default().run(&prompt, &pack).await,
        "codex" => CodexAdapter::default().run(&prompt, &pack).await,
        _ => unreachable!(),
    };

    match result {
        Ok(text) => {
            let mut created_finding_id = None;
            let mut applied = false;
            if matches!(req.kind, AgentRunKind::Triage) {
                if let Ok(parsed) = parse_triage_output(&text) {
                    let finding =
                        create_agent_triage_finding(&ws, &s, &parsed, vaddr, &agent, source)?;
                    created_finding_id = Some(finding.id.clone());
                    if write_policy == AgentWritePolicy::Apply {
                        apply_triage_suggestions(&ws, &s, &parsed, vaddr, source)?;
                        applied = true;
                    }
                }
            }
            s.jobs.finish(&job, Some(format!("{} chars", text.len())));
            Ok(Json(AgentRunResponse {
                agent,
                kind: format!("{:?}", req.kind),
                job_id: job_id.0,
                text,
                created_finding_id,
                applied,
            }))
        }
        Err(e) => {
            s.jobs.fail(&job, e.to_string());
            Err(ApiError::internal(e.to_string()))
        }
    }
}

fn build_context_pack(
    ws: &Workspace,
    vaddr: u64,
    write_policy: AgentWritePolicy,
) -> Result<ContextPack, ApiError> {
    let function_context = analysis::function_context(ws, vaddr).unwrap_or_else(|e| e.to_string());
    let project = ws.with_project(|p| {
        json!({
            "renames": p.renames,
            "comments": p.comments,
            "vuln_scores": p.vuln_scores,
            "notes": p.notes,
        })
    });
    Ok(ContextPack {
        workspace_summary: format!("{} ({})", ws.info().display_name, ws.binary_path_str()),
        target: AgentTarget::Function {
            vaddr: format!("0x{:x}", vaddr),
        },
        annotations: json!({
            "function_context": function_context,
            "project": project,
        }),
        prior_findings: Vec::new(),
        allowed_tools: vec![
            "file_info".into(),
            "list_functions".into(),
            "disassemble".into(),
            "decompile".into(),
            "function_context".into(),
            "xrefs_to".into(),
            "create_finding".into(),
        ],
        write_policy,
        output_schema: json!({
            "type": "object",
            "properties": {
                "severity": { "type": "string" },
                "rationale": { "type": "string" },
                "suggested_name": { "type": ["string", "null"] },
                "suggested_comments": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "vaddr": { "type": "string" },
                            "text": { "type": "string" }
                        }
                    }
                }
            }
        }),
    })
}

fn parse_triage_output(text: &str) -> Result<TriageOutput, serde_json::Error> {
    if let Ok(v) = serde_json::from_str::<TriageOutput>(text.trim()) {
        return Ok(v);
    }
    let start = text.find('{').unwrap_or(0);
    let end = text.rfind('}').map(|i| i + 1).unwrap_or(text.len());
    serde_json::from_str(&text[start..end])
}

fn create_agent_triage_finding(
    ws: &Workspace,
    s: &AppState,
    parsed: &TriageOutput,
    vaddr: u64,
    agent: &str,
    source: Source,
) -> Result<crate::core::Finding, ApiError> {
    let severity = severity_from_str(&parsed.severity);
    let f = findings::create_finding(
        ws,
        CreateFinding {
            kind: FindingKind::Vuln,
            severity,
            vaddr: Some(format!("0x{:x}", vaddr)),
            rule: format!("{}_triage", agent),
            rationale: parsed.rationale.clone(),
            evidence: vec![
                Evidence::Decompile {
                    vaddr: format!("0x{:x}", vaddr),
                },
                Evidence::Disasm {
                    vaddr: format!("0x{:x}", vaddr),
                    length: 256,
                },
            ],
            suggested_actions: parsed
                .suggested_comments
                .iter()
                .map(|c| format!("comment {}: {}", c.vaddr, c.text))
                .collect(),
            created_by: CreatedBy::Agent {
                agent: agent.to_string(),
            },
        },
    )
    .map_err(ApiError::from)?;
    emit_finding_created(s, &f, source);
    Ok(f)
}

fn apply_triage_suggestions(
    ws: &Workspace,
    s: &AppState,
    parsed: &TriageOutput,
    target_vaddr: u64,
    source: Source,
) -> Result<(), ApiError> {
    if let Some(name) = parsed
        .suggested_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        project_store::rename_function(ws, &s.events, target_vaddr, name, source)
            .map_err(ApiError::from)?;
    }
    for comment in &parsed.suggested_comments {
        let v = parse_vaddr(&comment.vaddr)?;
        project_store::add_comment(ws, &s.events, v, &comment.text, source)
            .map_err(ApiError::from)?;
    }
    Ok(())
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "med" | "medium" => Severity::Med,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_vaddr(s: &str) -> Result<u64, ApiError> {
    let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).map_err(|_| ApiError::bad_request("invalid vaddr"))
}

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}
