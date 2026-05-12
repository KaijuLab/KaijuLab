# KaijuLab

> **AI-native reverse engineering workbench — local web UI driven by your own Claude Code or Codex.**

<p align="center">
  <a href="https://github.com/Koukyosyumei/" target="_blank">
      <img src="https://github.com/KaijuLab/KaijuLab.github.io/blob/main/static/images/logo.png" alt="KaijuLab Logo" height="126">
  </a>
</p>

KaijuLab is a local reverse-engineering workbench. It runs as a single binary
that opens a dense, trading-terminal-style web UI in your browser, and exposes
the same analysis tools over the Model Context Protocol (MCP) so your Claude
Code or Codex session can drive analysis directly. Both surfaces share live
state — when Claude renames a function via MCP, your browser updates instantly,
attributed to `source: claude` in the event timeline.

**No API keys required for AI use.** KaijuLab does not call hosted LLM APIs;
it uses the user's existing local Claude Code or Codex install through MCP /
local-CLI bridges.

## Quickstart

```bash
# 1. Build
cargo build --release
cd web && npm install && npm run build && cd ..
cargo build --release   # rebuild so web/dist gets embedded into the binary

# 2. Launch the workbench; open or drag-drop a binary in the browser
./target/release/kaijulab serve
#  → open http://127.0.0.1:7878 in your browser

# 3. Configure Claude Code / Codex once to launch the MCP shim
./target/release/kaijulab mcp
#  → the shim attaches to the active workspace last opened by the web UI.
```

## Modes

| Mode | Command | Purpose |
|---|---|---|
| **Workbench daemon** | `kaijulab serve [FILE]` | Run the local web UI + MCP-over-IPC daemon |
| **MCP stdio shim** | `kaijulab mcp [FILE]` | Attach Claude Code / Codex to the active daemon workspace, or a specific binary |
| **Hook setup** | `kaijulab hook setup` | Create or update project-local `.mcp.json` for Claude Code / Codex |
| **One-shot analyze** | `kaijulab analyze <FILE>` | Print a JSON summary to stdout and exit |
| **Run a Rhai plugin** | `kaijulab plugin <NAME> [FILE]` | Execute a `.rhai` script from `~/.kaiju/plugins/` |

### `serve` — the workbench daemon

```bash
kaijulab serve foo.bin                            # bind 127.0.0.1:7878
kaijulab serve foo.bin --bind 0.0.0.0:7878 --token $(openssl rand -hex 32)
kaijulab serve foo.bin --allow-patch              # enable patch_bytes MCP tool
kaijulab serve foo.bin --allow-exec               # enable run_binary MCP tool
```

The daemon:

- Serves the React UI at `http://<bind>/`.
- Exposes REST endpoints under `/api/...` and a WebSocket event stream at `/api/events`.
- Opens a per-workspace Unix socket at `~/.kaiju/run/<hash>.sock` so a co-located `kaijulab mcp` shim attaches automatically.

Defaults to `127.0.0.1` only. For remote access, bind a non-loopback address and pass `--token`; all API calls and WS upgrades will then require `Authorization: Bearer <token>`.

### `mcp` — the stdio shim

```bash
kaijulab mcp          # attach to the active workspace opened by the web UI
kaijulab mcp foo.bin  # attach to that binary's daemon, or run standalone
```

A minimal Model Context Protocol server over stdio. Implements
`initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`.

- With no `FILE`, the shim reads `~/.kaiju/run/active.json` and attaches to the workspace most recently opened or activated in the web UI.
- If a `serve` daemon is running for the selected binary, the shim **proxies all calls to the daemon** — same in-memory caches, same project state, same event bus. Claude's writes fire WebSocket events that the browser sees instantly.
- If no daemon is running, the shim runs standalone with its own state.

Example Claude Code MCP config snippet:

```json
{
  "mcpServers": {
    "kaijulab": {
      "command": "/path/to/kaijulab",
      "args": ["mcp"]
    }
  }
}
```

Or create that file automatically in the current directory:

```bash
kaijulab hook setup
```

This preserves any existing `.mcp.json` servers and updates only the
`mcpServers.kaijulab` entry. Use `--output <PATH>` or `--command <PATH>` to
override the target config file or binary path.

### `analyze` — one-shot

```bash
kaijulab analyze foo.bin > report.json
```

Prints a JSON object with `workspace`, `file_info`, and `functions`. Useful in
CI pipelines or for cold orientation before opening the workbench.

## Web UI

```
┌─ Topbar ─────────────────────────────────────────────────────┐
│  kaijulab  •  foo.bin (x86_64, ELF)  •  ⌘K palette          │
├──────────┬─────────────────────────────┬────────────────────┤
│ Function │  Disassembly  │  Decompile  │  Entity Inspector  │
│ List     │  ──────────── │  ────────── │  ────────────────  │
│ (search) │  cursor sync                │  rename / comment  │
│ vuln     │  inline cmnt  │  renames    │  vuln score / note │
│ badges   │               │             │                    │
├──────────┴───────────────┴─────────────┴────────────────────┤
│  Timeline — granular events, filterable by source           │
│  → claude (3s ago): function.renamed 0x401200 → parse_hdr   │
│  → user   (8s ago): comment.added 0x401204 "stack bof"      │
└──────────────────────────────────────────────────────────────┘
```

- **Command palette** (`Ctrl+K` / `Cmd+K`): `0x401000` jumps · `parse_header` fuzzy-finds · `/rename`, `/comment`, `/note`, `/scan vuln`, `/goto`, `/info`.
- **Playbooks**: guided expert workflows for malware triage, CTF flag hunting, vulnerability audit, and capability survey. Playbooks run deterministic tools, summarize evidence, and can create findings for review.
- **Findings board**: review evidence-backed findings, jump to addresses, and move items through triage, confirmed, dismissed, or false-positive states.
- **Source attribution**: every mutation in the timeline shows whether it came from `user`, `claude`, `codex`, `plugin`, or `tool`. Filter the stream by source.
- **Inspector**: shows the selected function's annotations, vuln score, notes. Edit in place; writes hit the same project DB as MCP writes.

### Dev mode

```bash
KAIJULAB_DEV=1 kaijulab serve foo.bin
# in another shell:
cd web && npm run dev
```

In dev mode, the daemon serves UI assets from `web/dist` on disk; the Vite dev server (`localhost:5173`) proxies `/api` to the daemon, giving you instant React HMR without rebuilding the Rust binary.

## Project state

Per-binary annotations (renames, comments, notes, vuln scores, struct
definitions, function signatures) persist to `<binary>.kaiju.db` (SQLite) next
to the binary file. The daemon, the MCP shim, manual UI edits, and legacy TUI
edits all share this same database.

## Available tools

Tools are available identically through REST (`/api/...`), MCP
(`tools/call`), and the legacy TUI. The full list:

### Binary info & disassembly
`file_info`, `sections`, `imports`, `hexdump`, `read_section`,
`strings_extract`, `section_entropy`, `disassemble`, `list_functions`,
`resolve_plt`, `resolve_pe_imports`, `dwarf_info`, `load_pdb`.

### Control flow & xrefs
`xrefs_to`, `xrefs_data`, `cfg_view`, `callgraph`.

### Decompilation
`decompile`, `decompile_flat`, `function_context` (disasm + decompile + xrefs in one call).

### Search & patch
`search_bytes`, `patch_bytes` (writes `<file>.patched`; original untouched), `generate_yara_rule`.

### Intelligence
`scan_vulnerabilities`, `identify_library_functions`, `diff_binary`,
`virustotal_check` (requires `VIRUSTOTAL_API_KEY`).

### Playbooks
`list_playbooks`, `run_playbook`. Available playbooks:
`malware_triage`, `ctf_flag_hunt`, `vulnerability_audit`,
`capability_survey`.

### Function hash database (cross-binary)
`register_function_hash`, `lookup_function_hash`, `match_all_functions`
(`~/.kaiju/fn_hashes.db`).

### Project annotations (persistent)
`rename_function`, `add_comment`, `add_note`, `delete_note`,
`set_vuln_score`, `rename_variable`, `set_return_type`, `set_param_type`,
`set_param_name`, `define_struct`, `list_types`, `load_project`,
`export_report`.

### ELF / PE internals
`elf_internals`, `pe_internals`, `run_binary` (gated by `--allow-exec`).

For the full API shape (REST routes, WS event types, MCP tool schemas),
see [`docs/web-mcp-architecture.md`](docs/web-mcp-architecture.md).

## Environment variables

KaijuLab itself does not require any API keys.  AI interactions happen
through your own Claude Code / Codex installs, which authenticate
themselves against your existing subscription — KaijuLab never sees a
token.

| Variable | Purpose | Default |
|---|---|---|
| `RUST_LOG` | Daemon log filter (`info`, `debug`, `trace`) | `info` |
| `KAIJULAB_DEV` | Serve UI assets from disk instead of embed | unset |
| `KAIJU_BINARY` | Default binary path picked up by `run_python` tool | unset |
| `VIRUSTOTAL_API_KEY` | Enable `virustotal_check` tool | unset |

## Prerequisites

- Rust toolchain (stable, 1.75+)
- Node.js 18+ and npm (for the web UI build)

## License

Apache 2.0 — see [LICENSE](LICENSE).
