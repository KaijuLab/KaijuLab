# KaijuLab — Claude Code guide

## Build & run

**Always use `--release`.** `iced-x86` (the disassembler) and the sleigh-based
decompiler are substantially slower in debug mode. Never suggest or run a
plain `cargo build` / `cargo run` without `--release`.

```bash
cargo build --release
cd web && npm install && npm run build && cd ..
cargo build --release       # rebuild so web/dist gets embedded

# Modes
cargo run --release -- serve   /path/to/binary
cargo run --release -- mcp     /path/to/binary
cargo run --release -- analyze /path/to/binary
cargo run --release -- plugin  vuln_triage /path/to/binary
cargo run --release -- --help
```

Tests:

```bash
cargo test --release          # also regenerates web/src/types/*.ts via ts-rs
```

UI dev loop:

```bash
KAIJULAB_DEV=1 cargo run --release -- serve /path/to/binary
# in another terminal:
cd web && npm run dev          # Vite proxies /api to the daemon, full HMR
```

## Project structure

```
src/
├── main.rs              CLI entry (clap subcommand dispatch)
├── core/
│   ├── workspace.rs     Workspace, WritePolicy, socket_path_for
│   ├── events.rs        Event bus (tokio::broadcast) with Source attribution
│   ├── jobs.rs          Job model + CancellationToken
│   ├── findings.rs      Finding schema + in-memory store
│   ├── project_store.rs Write wrappers that emit granular events
│   └── analysis.rs      Typed wrappers around tools::dispatch
├── server/
│   ├── mod.rs           axum bootstrap + AppState
│   ├── routes.rs        REST endpoints
│   ├── ws.rs            WebSocket fan-out from EventBus
│   ├── palette.rs       Command-palette parser/executor
│   └── static_assets.rs include_dir!() embed; KAIJULAB_DEV=1 disk-serve
├── ipc/
│   ├── socket.rs        Per-workspace Unix-socket daemon ↔ mcp shim IPC
│   └── protocol.rs      Framed JSON-RPC for IPC
├── mcp/
│   ├── mod.rs           Stdio entry; daemon discovery via socket
│   ├── server.rs        JSON-RPC over stdio + McpBackend trait
│   ├── tools.rs         MCP tool surface (smaller than internal toolset)
│   └── resources.rs     The three browseable resources
├── agent_bridge/
│   ├── claude.rs        `claude -p` adapter skeleton (NotImplemented)
│   ├── codex.rs         `codex exec --json` adapter skeleton (NotImplemented)
│   ├── prompts.rs       Schema-bound templates
│   └── scope.rs         ContextPack
├── tools.rs             Inner tool dispatcher (catch_unwind + LRU cache)
├── plugin.rs            Rhai scripting engine — same RE tools as MCP
├── project.rs           Per-binary SQLite store (<binary>.kaiju.db)
├── hashdb.rs            Cross-binary function-hash DB (~/.kaiju/fn_hashes.db)
├── arch.rs              Architecture abstraction (Capstone, prologue patterns)
├── decompiler/          P-code decompiler (vendored from Ouroboros, MIT/Apache)
└── dwarf.rs             DWARF debug-info helpers

web/
├── package.json         React + Vite + TS + Tailwind
├── vite.config.ts       Dev-mode proxy to localhost:7878
├── src/
│   ├── App.tsx          Root component
│   ├── api.ts           REST client
│   ├── state.ts         Zustand store + event types
│   ├── hooks/           useEventStream (WS subscription)
│   ├── components/      TopBar / LeftRail / CenterWorkspace / Inspector /
│   │                    Timeline / CommandPalette
│   └── types/           ts-rs generated from Rust wire types
└── dist/                Built bundle, embedded via include_dir!()
```

## Process model

- `kaijulab serve <FILE>` launches the daemon. Binds `127.0.0.1:7878` by
  default; also opens `~/.kaiju/run/<workspace-hash>.sock` for the MCP shim.
- `kaijulab mcp <FILE>` runs an MCP stdio shim. On startup it detects a
  running `serve` daemon for the same workspace (via the socket) and proxies
  all calls there, so both the browser and Claude see the same live state.
  Without a daemon it runs standalone with its own state.
- `kaijulab analyze <FILE>` is one-shot: prints a JSON object with workspace
  info + file_info + functions to stdout and exits.
- `kaijulab plugin <NAME> [FILE]` runs a Rhai script.

## Source attribution — non-negotiable

Every mutation (rename / comment / note / vuln_score / finding) emits a
**granular** event on the EventBus carrying a `source` field:

```
user | claude | codex | plugin | tool | system
```

The web Timeline and Inspector use this to attribute changes. **Never bypass
`core::project_store` for writes** — direct writes to the SQLite project file
would skip the event emission and de-sync the UI.

REST handlers tag writes with `source: user` by default (overridable via
request body). MCP handlers tag with `source: claude` (the LLM client driving
the shim).

## Adding a new RE tool

1. Implement in `src/tools.rs` — return `ToolResult::ok(string)` or
   `ToolResult::err(string)`.
2. Add a branch to `dispatch_inner()`.
3. If the tool is read-heavy and deterministic, add its name to
   `CACHEABLE_TOOLS`. If it mutates project state, add it to `WRITE_TOOLS`.
4. Expose to the web UI via `src/core/analysis.rs` (typed wrapper) +
   `src/server/routes.rs` (REST endpoint).
5. Expose to MCP via `src/mcp/tools.rs` (declare in `tool_definitions()` and
   add a branch in `dispatch_mcp()`).
6. If it touches project state, route writes through `src/core/project_store`
   so events fire with source attribution.

## Adding a new MCP tool

The MCP surface is intentionally **smaller** than `tools::dispatch`. Analyst
composite tools (`auto_analyze`, `explain_function`) are not exposed — Claude
orchestrates the primitives itself. Only add MCP tools that are useful for
Claude to call directly.

## Adding a new event type

1. Add a variant to the `Event` enum in `src/core/events.rs`. Use a dotted
   `#[serde(rename = "category.action")]` discriminator (e.g.
   `"function.renamed"`).
2. Emit the event from the write path that produces it.
3. Add a TS-side discriminant in `web/src/state.ts` (the `BusEvent` union).
4. Run `cargo test --release` to regenerate `web/src/types/Event.ts`.

## Wire types — `ts-rs`

Every type that crosses the Rust↔TS boundary derives `TS` and uses
`#[ts(export, export_to = "../web/src/types/")]`. Test-time generation drops
one `.ts` file per type. After adding or modifying a wire type, run
`cargo test --release` and commit the regenerated files.

## Static-asset embedding

`src/server/static_assets.rs` embeds `web/dist/` at compile time via
`include_dir!`. The repo tracks a placeholder `web/dist/index.html` so fresh
clones can build the Rust binary without first running `npm run build`. For
a real release, build the web first, then rebuild the Rust binary so the
real bundle gets embedded.

## Project state

Per-binary state persists to `<binary>.kaiju.db` (SQLite) next to the binary
file. Cross-binary function hashes live in `~/.kaiju/fn_hashes.db`. Rhai
plugins live in `~/.kaiju/plugins/`.

## Environment variables

KaijuLab itself takes no API keys.  AI runs through the user's own Claude
Code / Codex install via MCP.

| Variable | Purpose | Default |
|---|---|---|
| `RUST_LOG` | Daemon log filter (`info`, `debug`, `trace`) | `info` |
| `KAIJULAB_DEV` | Serve UI from disk instead of embedded bundle | unset |
| `KAIJU_BINARY` | Default binary path inherited by `run_python` | unset |
| `VIRUSTOTAL_API_KEY` | Enable `virustotal_check` tool | unset |

@.claude/h5i.md
