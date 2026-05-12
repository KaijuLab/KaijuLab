# KaijuLab Web + MCP Architecture

KaijuLab becomes a local web reverse-engineering workbench with first-class
Claude Code and Codex integration. The terminal UI is removed once the web
surface covers the same manual workflows.

## Product Shape

KaijuLab owns the binary-analysis state and durable project memory. Claude Code
and Codex act as external reasoning engines that inspect and mutate that state
through stable local interfaces — never through hosted API keys held by
KaijuLab itself.

```text
Browser UI ─────────┐
                    │  HTTP / WebSocket
                    ▼
            KaijuLab `serve` daemon
            (analysis core + project DB + job runner)
                    ▲
                    │  Unix socket  (kaiju://)
                    │
              `kaijulab mcp` shim  (stdio)
                    ▲
                    │  MCP
                    │
          Claude Code  /  Codex CLI
```

The daemon is the single source of truth. Both the browser and the MCP shim
talk to it; both see the same in-memory binary cache, the same LRU tool cache,
the same SQLite project store, and the same event stream.

The user never gives KaijuLab an Anthropic or OpenAI key. Agent work happens
either (a) in the user's own Claude Code / Codex session driving KaijuLab via
MCP, or (b) through a strictly scoped local-CLI bridge (`claude -p`,
`codex exec --json`) launched by the daemon for non-interactive jobs only.

## Backend Module Split

The current `tools::dispatch(name, args)` boundary remains the inner core.
Service wrappers expose typed APIs to the web, MCP, and agent layers without
forcing a tool-by-tool refactor up front.

```text
src/main.rs
  CLI mode selection: serve, mcp, analyze, plugin

src/core/
  analysis.rs        typed wrappers around tools::dispatch
  project_store.rs   load/save project DB, deltas, snapshots
  workspace.rs       active binary, paths, case metadata, multi-workspace
  jobs.rs            async job model, CancellationToken plumbing
  findings.rs        Finding model + findings store
  events.rs          internal event bus (broadcast channel)

src/server/
  mod.rs             axum bootstrap, bind, auth middleware
  routes.rs          REST endpoints
  ws.rs              WebSocket fan-out from events.rs
  palette.rs         command-palette parser + executor
  static_assets.rs   embedded UI (release) / disk (KAIJULAB_DEV=1)

src/mcp/
  mod.rs             stdio shim, daemon-discovery, fallback to in-process
  resources.rs       small set of true browse resources
  tools.rs           MCP tool declarations bound to core/

src/agent_bridge/
  mod.rs             scoped, non-interactive only
  claude.rs          `claude -p --output-format=stream-json` adapter
  codex.rs           `codex exec --json` adapter
  prompts.rs         schema-bound prompt templates
  scope.rs           ContextPack assembly + write-policy enforcement

src/ipc/
  socket.rs          Unix-socket protocol between mcp shim and serve daemon
  protocol.rs        framed JSON-RPC, version negotiation

web/
  Vite + React or Solid; ts-rs generated types from Rust
```

The legacy `src/tui.rs`, `src/ui.rs`, `src/agent.rs`, and `src/llm/*` are
deleted once web parity is reached.

## Process Modes

```bash
kaijulab serve <binary>          # daemon: web UI + job runner + Unix socket
kaijulab mcp                     # stdio MCP shim; attaches to running serve
kaijulab analyze <binary>        # one-shot JSON to stdout (replaces --headless)
kaijulab plugin <name> [binary]  # run a Rhai plugin (unchanged surface)
```

### `serve` and `mcp` share state

`mcp` is a **thin shim**, not a peer daemon. On startup it:

1. Computes a workspace hash from the binary path / project path.
2. Looks for `~/.kaiju/run/<hash>.sock` — a Unix socket owned by a running
   `serve` daemon for the same workspace.
3. If found, proxies every MCP call to the daemon. Both browser and MCP see
   the same in-memory state, same caches, same events.
4. If not found, runs MCP standalone with its own short-lived state. Useful
   for "just give Claude Code access to one binary" workflows without a UI.

The recommended workflow: `kaijulab serve foo.bin` in one terminal, then point
Claude Code's MCP config at `kaijulab mcp`. Live state, live UI, no
double-load.

### Dev mode

```bash
KAIJULAB_DEV=1 kaijulab serve foo.bin   # UI served from web/dist on disk
                                        # with file-watcher hot reload
```

Release builds embed `web/dist` via `include_dir!`.

## Web Server API

REST for snapshots and idempotent mutations. WebSocket for live state.
All endpoints are JSON. All wire types are generated from Rust via `ts-rs` to
guarantee the browser stays in lockstep.

### Bind & auth

- Default bind: `127.0.0.1:7878`. Same-origin only; no CORS.
- `--bind 0.0.0.0 --token <hex>` enables remote access. All API calls and WS
  upgrades require `Authorization: Bearer <token>`. UI prompts for the token
  on first load and stores it in `sessionStorage`.

### REST surface

```text
GET    /api/health
GET    /api/workspace
POST   /api/workspace/open
GET    /api/workspaces                       # multi-workspace listing

GET    /api/binary/info
GET    /api/sections
GET    /api/imports
GET    /api/strings?section=&query=&min_len=&limit=
GET    /api/functions?query=&limit=&offset=
GET    /api/functions/:vaddr
GET    /api/functions/:vaddr/disasm
GET    /api/functions/:vaddr/decompile
GET    /api/functions/:vaddr/context
GET    /api/functions/:vaddr/xrefs
GET    /api/graph/callgraph?max_depth=
GET    /api/graph/cfg/:vaddr

GET    /api/project
POST   /api/project/renames                  # mutations carry `source`
POST   /api/project/comments
POST   /api/project/notes
DELETE /api/project/notes/:id
POST   /api/project/vuln-scores
POST   /api/project/batch-annotate

GET    /api/findings
GET    /api/findings/:id
PATCH  /api/findings/:id                     # status, owner, notes
POST   /api/scans/vuln                       # creates a job

POST   /api/reports/export

GET    /api/jobs
POST   /api/jobs
GET    /api/jobs/:id
POST   /api/jobs/:id/cancel

GET    /api/agents
POST   /api/agents/claude/run                # scoped, non-interactive
POST   /api/agents/codex/run

POST   /api/palette/exec                     # command-palette entry point

GET    /api/plugins
POST   /api/plugins/run
```

Streaming endpoints (`disasm`, `decompile` of large functions, scans) accept
`Accept: application/x-ndjson` and emit one JSON object per line so the UI
can render incrementally.

### WebSocket events

`GET /api/events` upgrades to WS. Events are **granular deltas** with
source attribution — never "something in this category changed."

```json
{ "type": "function.renamed", "vaddr": "0x401000",
  "old": "FUN_401000", "new": "parse_header",
  "source": "claude", "job_id": "j_8a2", "ts": 1731000000 }

{ "type": "comment.added", "vaddr": "0x401040",
  "text": "loop bound = strlen(buf)", "source": "user", "ts": 1731000005 }

{ "type": "note.added", "id": "n_17", "vaddr": "0x4011c0",
  "text": "off-by-one in length check", "source": "user", "ts": 1731000010 }

{ "type": "vuln_score.set", "vaddr": "0x4011c0", "score": 9,
  "source": "claude", "job_id": "j_8a2", "ts": 1731000012 }

{ "type": "finding.created", "id": "f_3", "kind": "vuln",
  "severity": "high", "vaddr": "0x4011c0", "rule": "strcpy-unbounded",
  "source": "tool", "ts": 1731000013 }

{ "type": "finding.updated", "id": "f_3",
  "fields": { "status": "confirmed", "owner": "alice" },
  "source": "user", "ts": 1731000200 }

{ "type": "job.started",  "id": "j_8a2", "kind": "scan_vuln", "ts": ... }
{ "type": "job.progress", "id": "j_8a2", "pct": 0.42 }
{ "type": "job.finished", "id": "j_8a2", "status": "ok" }
{ "type": "job.cancelled","id": "j_8a2" }
{ "type": "job.failed",   "id": "j_8a2", "error": "..." }

{ "type": "tool.call",    "id": "tc_99", "job_id": "j_8a2",
  "name": "decompile", "args": { "vaddr": "0x4011c0" },
  "source": "claude" }
{ "type": "tool.stream",  "id": "tc_99", "name": "decompile",
  "chunk": "int parse_header(...) {\n", "seq": 0 }
{ "type": "tool.result",  "id": "tc_99", "name": "decompile",
  "ok": true, "bytes": 4821 }

{ "type": "agent.delta",  "job_id": "j_8a2", "text": "looking at xrefs..." }
```

The `source` field is non-negotiable. Every mutation has one of:
`user`, `claude`, `codex`, `plugin`, `tool`. The UI uses this to attribute
("Claude renamed this 3s ago") and to filter the timeline.

## MCP Server Surface

KaijuLab is exposed as an analysis database, not a shell. Tools are
deterministic, scoped to the active workspace, and return compact structured
data.

### Resources (small, browseable only)

```text
kaiju://workspace              current state, binary path, recent activity
kaiju://findings               findings board
kaiju://project/notes          all notes — cold-start orientation
```

Everything else — functions, disasm, decompile, cfg, callgraph — is a **tool**.
Listing them as resources just inflates Claude's session-start prompt tax
without changing behaviour (Claude calls tools either way).

### Read tools

```text
open_workspace(path)
file_info()
sections()
imports()
list_functions(query?, limit?, offset?)
function_context(vaddr)
disassemble(vaddr?, offset?, length?)
decompile(vaddr)
xrefs_to(vaddr)
xrefs_data(vaddr)
strings_extract(section?, query?, min_len?, limit?)
callgraph(max_depth?)
cfg(vaddr)
scan_vulnerabilities(max_fns?)
list_findings(status?, kind?, severity?)
get_finding(id)
search_bytes(pattern)
section_entropy()
```

### Write tools

All writes carry an implicit `source: "claude"` (or `"codex"`) in the
resulting event. Daemon-side `write_policy` gates dangerous ops.

```text
rename_function(vaddr, name)
add_comment(vaddr, comment)
add_note(text, vaddr?)
delete_note(id)
set_vuln_score(vaddr, score)
batch_annotate(vaddr, rename?, comment?, signature?, vars?, score?)
create_finding(kind, severity, vaddr, rule, rationale, evidence)
update_finding(id, status?, owner?, notes?)
export_report(format)
patch_bytes(vaddr, bytes_hex)        # blocked unless --allow-patch on serve
run_binary(args?, stdin?)            # blocked unless --allow-exec on serve
```

### Composite tools removed

`auto_analyze` and `explain_function` are deleted from the MCP surface.
Claude *is* the agent now — orchestration is its job. The "run an explanation
workflow" affordance moves to a Claude Code slash command that calls the
primitive tools (`disassemble` + `decompile` + `function_context`) in sequence.

## Findings — first-class schema

Findings are the platform's primary output. Every tool, agent, or user that
produces an actionable observation creates a `Finding`.

```rust
struct Finding {
    id: String,                       // f_<short-id>
    kind: FindingKind,                // Vuln, HashMatch, ImportOfInterest,
                                      // CfgAnomaly, StringOfInterest, Custom
    severity: Severity,               // Info, Low, Med, High, Critical
    vaddr: Option<Vaddr>,             // primary anchor
    rule: String,                     // machine id, e.g. "strcpy-unbounded"
    rationale: String,                // human-readable; REQUIRED
    evidence: Vec<Evidence>,          // vaddr ranges, tool outputs, strings, xrefs
    suggested_actions: Vec<String>,
    status: FindingStatus,            // New, Triaging, Confirmed, Dismissed,
                                      //   FalsePositive
    owner: Option<String>,
    created_by: CreatedBy,            // Tool(name), Agent(claude|codex), User
    notes: Vec<NoteRef>,
    created_at: i64,
    updated_at: i64,
}

enum Evidence {
    Disasm   { vaddr: Vaddr, length: u32 },
    Decompile{ vaddr: Vaddr },
    Xref     { from: Vaddr, to: Vaddr },
    String   { offset: u64, text: String },
    Import   { name: String },
    ToolOutput { tool: String, args: serde_json::Value, snippet: String },
}
```

`scan_vulnerabilities`, `match_all_functions`, and agent jobs all emit
`Finding`s rather than ad-hoc strings. The findings board is the analyst's
work queue.

## Cancellation

Long-running jobs (`scan_vulnerabilities`, `match_all_functions`,
decompilation of large functions) run in `tokio::task::spawn_blocking` and
receive a `CancellationToken`. Tool implementations check
`token.is_cancelled()` at iteration boundaries: per-function loops, per-block
decompiler passes, per-instruction disasm loops over large ranges.

`POST /api/jobs/:id/cancel` flips the token. The job emits
`job.cancelled` over WS. Partial results already streamed are kept.

## Agent Bridge — narrowly scoped

KaijuLab does **not** spawn sub-Claude/Codex sessions for interactive work.
That role belongs to the user's own Claude Code session driving KaijuLab via
MCP.

The bridge is reserved for **schema-bound, non-interactive jobs** that are
awkward to express as a single MCP tool call:

```text
produce_report_section(scope) -> markdown
triage_function(vaddr)        -> { severity, rationale, suggested_name,
                                   suggested_comments[] }
draft_yara_rule(scope)        -> { rule_text, false_positive_risks[] }
```

Output is **always** structured (JSON-schema-validated) and lands in the
findings board / project DB as suggestions, never silent edits. The "review
this with Claude" button in the UI does **not** invoke the bridge — it copies
a prepared prompt + context pack to the clipboard for the user's primary
Claude Code session, or opens a `kaiju://prompt/<id>` URL that Claude Code
registers as a handler.

### Context packs

Every bridge invocation gets a compact, explicit `ContextPack`:

```rust
struct ContextPack {
    workspace_summary: String,
    target: Target,                   // function vaddr, range, or finding id
    annotations: Vec<Annotation>,     // current renames/comments for target
    prior_findings: Vec<FindingRef>,
    allowed_tools: Vec<String>,       // restricted MCP tool subset
    write_policy: WritePolicy,        // Suggest | Apply | None
    output_schema: serde_json::Value, // JSON Schema for expected output
}
```

The agent session is **not** durable truth — the project DB is. Each bridge
invocation starts cold from the context pack; resume IDs are stored only as a
caching optimisation for retry/continue within the same job.

### Adapters

- `claude.rs` — `claude -p --output-format=stream-json --input-format=json`,
  parses streaming JSON, captures session ID per task.
- `codex.rs` — `codex exec --json`, parses JSONL.

Both adapters honour `KAIJULAB_AGENT_TIMEOUT` and emit `agent.delta` events
over WS for the timeline.

## Shared types

Wire types live in Rust with `#[derive(TS)]`; a `cargo test` step writes
`.ts` files into `web/src/types/`. The browser imports them directly. Any
field added to a Rust struct without regenerating fails CI.

## Command palette

The palette (`Ctrl+K` / `Cmd+K`) is the power-user spine.

```text
> 0x401000                       jump to address
> parse_header                   fuzzy-find symbol
> /rename 0x401000 parse_header  run write tool
> /comment 0x401040 loop bound   add comment at address
> /note this looks fishy         note at current address
> /scan vuln                     start a scan job
> /finding 0x4011c0 high strcpy  create a finding
> /goto callers parse_header     navigate to xrefs
> ?claude explain this           copy prompt+context to clipboard
                                 for primary Claude session
```

`POST /api/palette/exec` takes the raw string, parses it server-side,
dispatches, and returns either a result or a navigation hint. The browser
owns no parsing logic — keeps the palette consistent across clients.

## Web UI

Dense and operational. Closer to a trading terminal than a landing page.

### Layout

```text
Top bar
  workspace switcher, binary metadata, agent status, palette trigger

Left rail
  Functions  Imports  Strings  Sections  Findings  Jobs  Notes

Center workspace
  Tabbed panes: Disasm  Decompile  Graph  Hex  Report
  Default: Disasm + Decompile side-by-side, cursor-synced

Right inspector
  Selected entity:
    - identity (name, address, size, kind)
    - annotations (current + history with source/timestamp)
    - xrefs in / out
    - hash-DB matches across other binaries
    - vuln score + rationale
    - linked findings
    - agent suggestions awaiting review

Bottom timeline
  Granular event stream: tool calls, mutations, agent deltas, errors.
  Filterable by source (user / claude / codex / tool / plugin).
```

### Inspector is the killer feature

Every selectable entity (function, string, import, basic block) exposes
*everything known about it* in one panel. This is where KaijuLab beats IDA's
modal-dialog UX and Ghidra's tab-sprawl. Cross-binary hash matches in
particular are unique to KaijuLab and belong here, not buried in a separate
view.

### Interaction model

- Selecting an address updates all panes (disasm, decompile, inspector,
  graph minimap).
- Agent outputs land as **suggested mutations** in the inspector, not silent
  edits — unless `write_policy: Apply` is set on the originating job.
- Every mutation is visible in the timeline with `source` attribution.
- Large outputs (disasm of huge functions, big call graphs) are virtualized
  and streamed.
- The palette can run local tools, agent jobs, and navigation in one place.

## Migration Plan

1. Add `src/core/` with typed wrappers around `tools::dispatch`. Existing
   tools unchanged.
2. Add `src/server/` with `kaijulab serve`. Ship read-only endpoints first:
   binary info, functions, disasm, decompile, strings, imports, project
   annotations.
3. Build the web UI shell: functions table + split disasm/decompile +
   inspector. Ship `ts-rs` type generation.
4. Add WebSocket event bus with granular deltas and `source` attribution.
   Wire annotation writes through it.
5. Add `src/core/jobs.rs` with cancellation; port `scan_vulnerabilities` and
   `match_all_functions` to the job model.
6. Add `src/core/findings.rs` and the findings board view.
7. Add `src/ipc/` Unix-socket protocol and `src/mcp/` stdio shim with
   daemon-discovery. Wire read tools first, then write tools.
8. Add command palette (`POST /api/palette/exec` + UI).
9. Add `src/agent_bridge/` for the three schema-bound jobs only. Defer
   anything interactive.
10. Delete `src/tui.rs`, `src/ui.rs`, `src/agent.rs`, `src/llm/*`. Remove
    `gemini` / `openai` / `anthropic` deps. Update CLAUDE.md.

## First Milestone

`kaijulab serve samples/PwnableTW/Start/start` opens an app where the user
can:

1. See binary info, functions list (virtualized), strings, imports, sections.
2. Click a function → split disasm + decompile pane updates; inspector shows
   xrefs and annotations.
3. Rename / comment / note from the UI; persists to `<binary>.kaiju.db`.
4. Timeline shows every mutation with `source: "user"`.
5. Run `kaijulab mcp` from a Claude Code config and have Claude rename /
   comment / score via MCP. **The browser UI updates live via WebSocket
   with `source: "claude"`, both views editing the same project
   simultaneously.**
6. Command palette (`Ctrl+K`) runs any tool by name and jumps to addresses
   or symbols.

The fifth item is the demo that sells the pivot: Claude and a human editing
the same project, watching each other in real time. Without it, the milestone
is just "a worse Ghidra." With it, KaijuLab ships something nobody else does.
