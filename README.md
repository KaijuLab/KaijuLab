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
| **REST CLI client** | `kaijulab api ...` | Script the running web daemon from shells, bots, Claude, or Codex |
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

Defaults to `127.0.0.1` only. For remote access, bind a non-loopback address and pass `--token`; all API calls require `Authorization: Bearer <token>` and the `/api/events` WebSocket accepts the same token as `?token=<token>` for browser clients. The bundled web UI prompts for the token on the first protected API call and stores it in browser local storage.

### `api` — script the web daemon

```bash
kaijulab serve foo.bin --token "$KAIJULAB_API_TOKEN"

kaijulab api get /api/workspace
kaijulab api open ./foo.bin
kaijulab api get '/api/functions?json=true'
kaijulab api get /api/functions/0x401000/context
kaijulab api post /api/project/notes --data '{"text":"review parser", "vaddr":"0x401000", "source":"tool"}'
kaijulab api run-playbook vulnerability_audit --max-functions 200
kaijulab api agent-run codex --kind triage --vaddr 0x401000 --write-policy suggest
kaijulab api console claude
kaijulab api console codex --prompt 'Use kaijulab MCP to summarize the active workspace.' --idle-timeout-secs 30
kaijulab api exploit-context
kaijulab api runtime-run --stdin 'AAAA' --save-evidence --tag smoke
kaijulab api debug-probe --stdin @crash.input --break 0x401000 --save-evidence --tag crash
kaijulab api exploit-kit --cyclic-len 256 --cyclic-find 0x61413161
kaijulab api ir-query --search read
kaijulab api analysis-loop --candidate /tmp/poc.py --observation 'SIGSEGV at EIP'
kaijulab api evidence-list --limit 10
kaijulab api execution-profiles
kaijulab api debug-session-contract
kaijulab api benchmark-smoke
kaijulab api workstation-status --file ./foo.bin
kaijulab api index-build --file ./foo.bin --output .kaiju/index/foo.json
kaijulab api sysroot-doctor --file ./foo.bin
kaijulab api agent-job-plan --file ./foo.bin --goal 'produce verified PoC'
kaijulab api benchmark-plan --root samples/PwnableTW --max-files 16
kaijulab api exploit-verify --expect-target-exit 42 /tmp/poc.py
kaijulab api exploit-loop claude --output /tmp/poc.py
```

`kaijulab api` is a bot-friendly wrapper around the same REST endpoints used by
the browser UI. It prints pretty JSON, sends `Authorization: Bearer ...` from
`--token` or `KAIJULAB_API_TOKEN`, supports raw `get`, `post`, `patch`, and
`delete` calls for the full `/api/...` surface, and can attach to the same
PTY-backed Agent Console terminal used by the Web UI. `post` and `patch` accept
`--data '<json>'` or `--data @payload.json`.

Convenience subcommands cover the common automation loop:

- `open <FILE>` opens a binary in the daemon and makes it active.
- `run-playbook <ID>` returns the full playbook evidence and created finding IDs.
- `agent-run <claude|codex> --kind <triage|report_section|yara> --vaddr <ADDR>` returns the full local-agent result.
- `console <claude|codex>` attaches stdin/stdout to the daemon-owned Agent Console terminal.
- `console <claude|codex> --prompt ... --idle-timeout-secs N` sends one prompt to that terminal and exits after quiet output.
- `wait-job <JOB_ID>` polls `/api/jobs/<JOB_ID>` until `ok`, `failed`, or `cancelled`.
- `exploit-context [--file FILE]` emits an exploit workbench bundle: ELF protections, qemu/native runtime candidates, missing loader/sysroot notes, prompt strings, and common gadget hints.
- `runtime-run [--file FILE] [--arg X] [--stdin TEXT|@FILE] [--runner qemu-i386 --sysroot ROOT] [--save-evidence]` runs the target with captured stdout/stderr, timeout, exit code, signal, and runtime diagnostics.
- `debug-probe [--file FILE] [--stdin TEXT|@FILE] [--break ADDR] [--sysroot ROOT] [--save-evidence]` runs a non-interactive `gdb`/`gdb-multiarch` probe and returns parsed registers, backtrace, PC disassembly, mappings, signal hints, and next action. Foreign-architecture ELF targets are run under qemu's gdbstub automatically; dynamically linked foreign targets need a matching `--sysroot`.
- `exploit-kit [--file FILE] [--cyclic-len N] [--cyclic-find VALUE]` emits checksec/runtime data, PLT/GOT text, gadget hints, exploit recipes, and cyclic pattern helpers.
- `ir-query [--file FILE] [--function 0xADDR] [--search TEXT]` returns structured function lists, strings, and combined decompile/disassembly/xrefs for a selected function.
- `analysis-loop [--file FILE] [--candidate SCRIPT] [--observation TEXT]` builds a state bundle for hypothesize/run/debug/edit/verify loops and recommends the next CLI primitive.
- `evidence-list [--file FILE] [--kind KIND]` lists immutable JSONL evidence records saved by runtime/debug/verification commands.
- `execution-profiles [--file FILE]` emits native/qemu/hostile-sample execution profiles and their safety policies.
- `debug-session-contract [--file FILE]` emits the planned persistent debugger API contract: start, breakpoints, continue, step, registers, memory, snapshot, stop.
- `benchmark-smoke [--file FILE]` emits per-target smoke checks for index/runtime/debug/evidence regression tests.
- `workstation-status [--file FILE]` reports production-readiness across the seven core areas: dynamic/debug, binary database, exploit automation, agent jobs, sysroots/containers, workbench UI, and benchmarks.
- `index-build [--file FILE] [--output OUT]` emits a normalized binary index with hash, sections, functions, strings, ELF protections, imports, and contracts for UI/agent consumers.
- `sysroot-doctor [--file FILE]` inventories qemu/gdb/container tooling and reports loader/sysroot blockers.
- `exploit-stack [--file FILE]` lists implemented exploit helpers and remaining engine gaps such as semantic ROP, libc, seccomp, and heap helpers.
- `agent-job-plan [--file FILE] --goal TEXT` emits a resumable job contract with phases, artifacts, safety rules, and stop criteria.
- `workbench-manifest` emits the dense UI pane/navigation/hotkey/evidence contract for the web workbench.
- `benchmark-plan --root DIR` inventories binary corpus cases and expected grading artifacts for regression work.
- `exploit-verify [--file FILE] [--expect-exit N|--expect-target-exit N|--expect-output TEXT] [--save-evidence] SCRIPT` runs a candidate PoC with `KAIJU_BINARY`/qemu env vars and returns structured success/failure JSON.
- `exploit-loop <claude|codex> --output /tmp/poc.py` sends Agent Console a bounded PoC-development prompt that requires `analysis-loop`, `runtime-run`, `debug-probe`, `exploit-kit`, `ir-query`, and `exploit-verify` as needed.

For CTF exploit work, prefer the loop commands over ad-hoc shell probing:

```bash
kaijulab serve samples/PwnableTW/3x17/3x17 --allow-exec
kaijulab api exploit-context
kaijulab api exploit-kit --cyclic-len 256
kaijulab api runtime-run --stdin 'AAAA'
kaijulab api exploit-loop claude --output /tmp/kaijulab-3x17-poc.py \
  --goal 'Write a stdlib Python PoC that proves code execution with target exit 42.'
kaijulab api exploit-verify --expect-target-exit 42 /tmp/kaijulab-3x17-poc.py
```

`exploit-context` also reports environment blockers such as missing
`/lib/ld-linux.so.2` for dynamically linked i386 binaries and suggests either
installing `libc6:i386` or running qemu with an i386 sysroot.

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
│  Expert Workbench — mission, evidence graph, checklist,     │
│  training prompts, report/YARA drafting                      │
├──────────────────────────────────────────────────────────────┤
│  Agent Console — embedded Claude/Codex PTY with MCP events   │
├──────────────────────────────────────────────────────────────┤
│  Findings — evidence-backed leads with review states         │
├──────────────────────────────────────────────────────────────┤
│  Timeline — granular events, filterable by source           │
│  → claude (3s ago): function.renamed 0x401200 → parse_hdr   │
│  → user   (8s ago): comment.added 0x401204 "stack bof"      │
└──────────────────────────────────────────────────────────────┘
```

- **Command palette** (`Ctrl+K` / `Cmd+K`): `0x401000` jumps · `parse_header` fuzzy-finds · `/rename`, `/comment`, `/note`, `/scan vuln`, `/goto`, `/info`.
- **Playbooks**: guided expert workflows for malware triage, CTF flag hunting, vulnerability audit, capability survey, command-handler hunts, license checks, crypto/secret review, network-parser review, and auth-bypass review. Playbooks run deterministic tools, summarize evidence, and can create findings for review.
- **Expert Workbench**: beginner-facing mission control with professional hunt launchers, an evidence graph, investigation checklist, training prompts, and report/YARA drafting through local Claude/Codex bridge jobs.
- **Agent Console**: embedded Claude/Codex terminal sessions over daemon-managed PTYs. Sessions survive browser reloads, can be reattached, stream transcript tails, log to `~/.kaiju/agent-console/`, support resize / `ctrl-c` / stop controls, and include guided prompts. Use the terminal as the native agent loop; KaijuLab treats MCP tool calls, project writes, findings, and timeline events as the structured source of truth.
- **Findings board**: review evidence-backed findings, jump to addresses, and move items through triage, confirmed, dismissed, or false-positive states.
- **Source attribution**: every mutation in the timeline shows whether it came from `user`, `claude`, `codex`, `plugin`, or `tool`. Filter the stream by source.
- **Inspector**: shows the selected function's annotations, vuln score, notes, and function-level agent workflows for triage, applyable suggestions, report sections, and YARA drafts. Edit in place; writes hit the same project DB as MCP writes.

### Dev mode

```bash
KAIJULAB_DEV=1 kaijulab serve foo.bin
# in another shell:
cd web && npm run dev
```

In dev mode, the daemon serves UI assets from `web/dist` on disk; the Vite dev server (`localhost:5173`) proxies `/api` to the daemon, giving you instant React HMR without rebuilding the Rust binary.

## Project state

Per-binary annotations (renames, comments, notes, vuln scores, findings,
struct definitions, function signatures) persist to `<binary>.kaiju.db`
(SQLite) next to the binary file. The daemon, the MCP shim, manual UI edits,
and legacy TUI edits all share this same database.

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
`capability_survey`, `command_handler_hunt`, `license_check_hunt`,
`crypto_secret_hunt`, `network_parser_hunt`, `auth_bypass_review`.

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

KaijuLab itself does not require any hosted LLM API keys.  AI interactions happen
through your own Claude Code / Codex installs, which authenticate
themselves against your existing subscription — KaijuLab never sees those
tokens. The optional `kaijulab serve --token ...` value is only a local
HTTP access token for the workbench daemon.

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
