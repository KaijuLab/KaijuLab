# KaijuLab

**LLM-native Reverse Engineering Lab**

KaijuLab is a terminal-based reverse-engineering environment where an LLM acts as the analyst, not merely a chatbot sidebar. It exposes a rich set of binary-analysis primitives — disassembly, decompilation, cross-references, call graphs, YARA generation, vulnerability scoring, and more — and lets the model drive the investigation autonomously: forming hypotheses, calling tools, interpreting results, and reporting findings in plain language. A no-LLM manual mode lets you use every tool directly without any API keys.

```
 KaijuLab v0.1.0  ·  gemini-2.5-flash  ·  x86_64 · 0x00401a50 · 1234 tok
 [1] Functions  [2] Disasm  [3] Decompile  [4] Strings  [5] Imports  [6] Chat  [7] Context
┌───────────────────────────────────────────────────────────────────────────────┐
│  0x00401a50  f3 0f 1e fa              endbr64                                 │
│  0x00401a54  31 ed                    xor       ebp, ebp                      │
│  0x00401a56  49 89 d1                 mov       r9, rdx                       │
│  0x00401a59  5e                       pop       rsi                           │
│  …                                                                            │
└───────────────────────────────────────────────────────────────────────────────┘
 ● Ready                                          Tab:next  1-7:tab  ↑↓:scroll
 > _
```

## How it works

```
User prompt
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│  Agent loop (src/agent.rs)                                       │
│                                                                  │
│  1. Append user message to conversation history                  │
│  2. POST history + tool schemas → LLM backend (streaming)       │
│  3. If response contains tool call(s):                          │
│       execute each tool locally (with LRU cache)                │
│       append tool results to history                             │
│       goto 2                                                     │
│  4. Emit final text response; save session to disk              │
└──────────────────────────────────────────────────────────────────┘
         │                         ▲
         │  tool call              │  result string
         ▼                         │
┌──────────────────────────────────────────────────────────────────┐
│  Tool dispatcher (src/tools.rs)                                  │
│  file_info · disassemble · decompile · list_functions           │
│  xrefs_to · callgraph · cfg · strings_extract · hexdump         │
│  generate_yara_rule · patch_bytes · vuln_scan · …               │
└──────────────────────────────────────────────────────────────────┘
```

LLM responses stream to the Chat tab in real time. Tool results auto-populate the matching panel tab (Functions, Disasm, Decompile, Strings, or Imports). Session history is persisted to `~/.kaiju/sessions/` so context survives between runs.

## Prerequisites

- Rust toolchain (stable, 1.75+)
- Credentials for at least one supported LLM backend — **or none** (no-LLM manual mode works without any API key)

## Setup

### 1. Clone

```bash
git clone https://github.com/Koukyosyumei/KaijuLab
cd KaijuLab
```

### 2. Choose a backend and set credentials

**No LLM** (default — full manual tool access, no key needed):
```bash
cargo run --release                       # opens TUI in manual mode
```

**Gemini** — Vertex AI service account:
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json   # never commit this
export GOOGLE_PROJECT_ID=my-gcp-project
# optional: GOOGLE_LOCATION (default: us-central1)
# optional: KAIJULAB_MODEL  (default: gemini-2.5-flash)
cargo run --release -- --backend gemini
```

**OpenAI**:
```bash
export OPENAI_API_KEY=sk-...
# optional: OPENAI_BASE_URL (default: https://api.openai.com/v1)
# optional: KAIJULAB_MODEL  (default: gpt-4o)
cargo run --release -- --backend openai
```

**Anthropic**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# optional: KAIJULAB_MODEL (default: claude-opus-4-5)
cargo run --release -- --backend anthropic
```

**Ollama** (local, no key needed):
```bash
# optional: OLLAMA_BASE_URL (default: http://localhost:11434/v1)
# optional: KAIJULAB_MODEL  (default: llama3.2)
ollama serve   # in another terminal
cargo run --release -- --backend ollama --model llama3.2
```

### 3. Build

```bash
cargo build --release
```

Always use `--release`. `iced-x86` (the disassembler/normaliser) is substantially slower in debug mode.

## Usage

### Interactive TUI (default)

```bash
cargo run --release                                         # no LLM (manual mode)
cargo run --release -- --backend gemini                    # Gemini via Vertex AI
cargo run --release -- --backend openai                    # OpenAI
cargo run --release -- --backend anthropic                 # Anthropic Claude
cargo run --release -- --backend ollama --model llama3.2   # local Ollama
```

KaijuLab opens a full-screen terminal UI with seven tabs:

```
 KaijuLab v0.1.0  ·  gemini-2.5-flash  ·  x86_64 · 0x00401a50 · 1234 tok
 [1] Functions  [2] Disasm  [3] Decompile  [4] Strings  [5] Imports  [6] Chat  [7] Context
┌───────────────────────────────────────────────────────────────────────────────┐
│  (scrollable content of active tab)                                           │
│                                                                               │
│  Disasm:  address=yellow  bytes=gray  mnemonic=cyan                           │
│           registers=green  immediates=magenta  labels=bold-white              │
└───────────────────────────────────────────────────────────────────────────────┘
 ● Ready                                          Tab:next  1-7:tab  ↑↓:scroll
 > _
```

Tool results auto-populate their tab: `list_functions` → **Functions**, `disassemble` → **Disasm**, `decompile` → **Decompile**, `strings_extract` → **Strings**, `resolve_plt`/`resolve_pe_imports` → **Imports**. A `●` dot on the tab label indicates new unseen content.

### Key bindings

| Key | Action |
|---|---|
| `1`–`7` (empty input) | Jump to tab by number |
| `Tab` / `Shift+Tab` | Cycle tabs forward / backward |
| `↑` / `↓` | Scroll active panel one line |
| `PgUp` / `PgDn` | Scroll active panel one page |
| `g` / `G` (empty input) | Jump to top / bottom of panel |
| `Enter` | Send message to agent |
| `Ctrl+C` (empty input) | Quit |
| `Ctrl+C` (non-empty) | Clear input without sending |
| `↑` / `↓` (with text) | Navigate input history |
| `Ctrl+L` | Clear chat history |
| `s` (empty input) | Toggle split-pane view |
| `x` (empty input) | Show cross-reference popup at cursor address |
| `r` (empty input) | Rename function at cursor |
| `y` (empty input) | Copy panel content to clipboard |
| `:cmd` | Command palette — pre-fills input without sending |
| `:file_info <path>` | Pre-fill a manual tool command |
| `f` (Functions tab) | Filter function list |
| `/` | Incremental search within active panel |
| `n` / `N` | Jump to next / previous search match |
| `Enter` (Functions tab) | Jump to Disasm for selected function |

### One-shot analysis

Pass a binary as a positional argument. KaijuLab analyses it and exits:

```bash
cargo run --release -- /path/to/binary
cargo run --release -- --backend openai /path/to/binary
cargo run --release -- --backend gemini /path/to/binary --output-json   # structured JSON to stdout
```

### Script / batch mode

Run a file of tool commands (one per line, `#` comments and blank lines ignored) and exit:

```bash
cargo run --release -- --script analysis.txt
```

```
# analysis.txt
file_info /path/to/binary
functions /path/to/binary 20
disassemble /path/to/binary 0x401a50
entropy /path/to/binary
```

### Headless mode

Implies `--no-tui --output-json`. Useful in CI or automated pipelines:

```bash
cargo run --release -- --headless --backend gemini /path/to/binary
```

### Plain-text REPL (`--no-tui`)

For piping output or minimal environments:

```bash
cargo run --release -- --no-tui
```

### Session persistence

By default, conversation history is saved to `~/.kaiju/sessions/` keyed by binary path. On restart with the same binary, the previous session is restored automatically. Use `--no-session` to opt out:

```bash
cargo run --release -- --no-session /path/to/binary
```

### CLI flags reference

```
--backend     <NAME>    none (default) | gemini | openai | anthropic | ollama
--model       <ID>      Model ID override (backend-specific default)
--credentials <FILE>    [Gemini] Service-account JSON key path
--project     <ID>      [Gemini] GCP project ID
--location    <REGION>  [Gemini] Vertex AI region (default: us-central1)
--api-key     <KEY>     [OpenAI/Anthropic] API key
--base-url    <URL>     [OpenAI/Ollama] API base URL
--no-tui                Use plain-text REPL instead of the TUI
--output-json           [One-shot] Emit structured JSON to stdout
--script      <FILE>    Run commands from a script file, then exit
--headless              Implies --no-tui --output-json
--no-session            Disable session save/load for this run
```

## Available tools

### Binary info

| Tool | Description |
|---|---|
| `file_info` | Parse ELF / PE / Mach-O headers: format, arch, entry point, LOAD segment table (vaddr ↔ file offset), section table, imports |
| `hexdump` | Hex + ASCII dump at an arbitrary file offset |
| `read_section` | Hex dump of a named section (`.text`, `.rodata`, etc.) |
| `strings_extract` | Extract printable ASCII strings; optional `section` filter (e.g. `.rodata`) to avoid code-byte noise |
| `section_entropy` | Per-section Shannon entropy — detect packed / encrypted regions |

### Disassembly & control flow

| Tool | Description |
|---|---|
| `disassemble` | Disassemble x86 / x86-64 in Intel syntax; accepts `vaddr` (auto-translated via LOAD segments) or raw `offset` |
| `list_functions` | List functions: symbol table for non-stripped binaries; prologue scan (`endbr64` / `push rbp; mov rbp,rsp`) for stripped ones |
| `xrefs_to` | All call/jump sites that reference a given virtual address |
| `callgraph` | Full static call graph of the binary (JSON edge list) |
| `cfg` | Control-flow graph (basic-block edges) for a single function |
| `byte_search` | Byte-pattern search with wildcard support (e.g. `E8 ?? ?? ?? ??`) |

### Decompilation & symbols

| Tool | Description |
|---|---|
| `decompile` | Lift a function to pseudo-C using the built-in p-code lifter |
| `decompile_flat` | Decompile raw firmware or shellcode at an arbitrary base address |
| `resolve_plt` | Map PLT stub addresses → imported symbol names (ELF `.rela.plt` + dynamic symbol table) |
| `resolve_pe_imports` | Map PE import thunks → DLL!symbol strings |
| `dwarf_info` | Parse DWARF debug information: source files, line info, variable names |
| `load_pdb` | Load Windows PDB symbols and annotate functions |

### Intelligence & generation

| Tool | Description |
|---|---|
| `vuln_scan` | Heuristic vulnerability scan across the top N functions; emits risk scores |
| `explain_function` | Ask the LLM to explain a specific function in plain language |
| `generate_yara_rule` | Generate a YARA signature for a function, normalised for relocatability |
| `identify_library` | FLIRT-style library recognition using normalised function hashes |
| `auto_analysis` | Full automated analysis pass: functions → decompile → explain → score |
| `virustotal_check` | Hash lookup against VirusTotal (requires `VIRUSTOTAL_API_KEY`) |

### Patching & output

| Tool | Description |
|---|---|
| `patch_bytes` | Patch bytes at a virtual address → writes `<file>.patched`; original untouched |
| `diff_binaries` | Diff two binaries function-by-function by normalised hash |
| `export_report` | Export a full HTML analysis report |

### Project / annotations (persistent)

| Tool | Description |
|---|---|
| `rename_function` | Attach a human-readable name to an address (saved to `~/.kaiju/`) |
| `add_comment` | Attach a comment to an address |
| `list_annotations` | Show all saved names and comments for a binary |
| `list_types` | Show saved struct and function-signature definitions |

## Project layout

```
src/
├── main.rs           CLI entry point (clap), mode dispatch, backend factory,
│                     manual tool dispatcher, script/headless runner
├── config.rs         BackendKind / BackendConfig — env vars → CLI flags → defaults
├── agent.rs          Agentic loop — streaming LLM calls; emits AgentEvent for TUI;
│                     LRU tool-result cache; conversation history trimming;
│                     session save / load (~/.kaiju/sessions/)
├── tools.rs          All RE tool implementations + ToolDefinition list
├── tui.rs            ratatui TUI — 7-tab layout, async event loop,
│                     disasm syntax highlighting, split-pane, xref popup,
│                     clipboard copy, incremental search, command palette
├── ui.rs             Plain-text helpers for one-shot / --no-tui mode
├── hashdb.rs         Cross-binary function hash DB (SQLite at ~/.kaiju/fn_hashes.db);
│                     normalised FNV-1a hash — zeroes CALL/JMP rel32 and RIP-relative
│                     offsets so hashes are relocate-invariant
├── project.rs        Persistent project store — function names, comments, types
├── decompiler/       p-code lifter (ported from icicle-emu / Ouroboros)
├── dwarf.rs          DWARF debug-info parsing (gimli)
└── llm/
    ├── mod.rs        LlmBackend trait + universal types
    │                 (LlmMessage, MessageContent, ToolCall, ToolResult)
    ├── gemini.rs     Gemini / Vertex AI — JWT auth, uppercase schema, streaming
    ├── openai.rs     OpenAI + Ollama — OpenAI-compatible /chat/completions
    └── anthropic.rs  Anthropic Claude — x-api-key, tool_use content blocks
```

## Key dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `reqwest` | Async HTTP (rustls, no OpenSSL dep) |
| `ratatui` + `crossterm` | Full-screen terminal UI |
| `clap` | CLI argument parsing |
| `serde` + `serde_json` | Serialisation |
| `object` | ELF / PE / Mach-O parser |
| `goblin` | ELF dynamic symbol + relocation parsing |
| `iced-x86` | x86 / x86-64 disassembler and instruction decoder |
| `capstone` | Multi-architecture disassembler (ARM64, ARM, MIPS, …) |
| `gimli` | DWARF debug-information parsing |
| `pdb` | Windows PDB symbol loading |
| `petgraph` | Call graph and CFG data structures |
| `rusqlite` | SQLite (bundled) — function hash DB and project store |
| `arboard` | System clipboard (copy panel content with `y`) |
| `jsonwebtoken` | RS256 JWT signing for Gemini service-account auth |
| `indicatif` | Spinner in plain-text mode |
| `colored` | ANSI colour output |
| `anyhow` | Error handling |

## Environment variables

| Variable | Backend | Purpose | Default |
|---|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Gemini | Path to service-account JSON key | — (required) |
| `GOOGLE_PROJECT_ID` | Gemini | GCP project ID | — (required) |
| `GOOGLE_LOCATION` | Gemini | Vertex AI region | `us-central1` |
| `OPENAI_API_KEY` | OpenAI | API key | — (required) |
| `OPENAI_BASE_URL` | OpenAI | API base URL | `https://api.openai.com/v1` |
| `ANTHROPIC_API_KEY` | Anthropic | API key | — (required) |
| `OLLAMA_BASE_URL` | Ollama | Server base URL | `http://localhost:11434/v1` |
| `KAIJULAB_MODEL` | All | Model ID override | backend-specific |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal hash lookup | — (optional) |

All of the above can also be supplied with the corresponding CLI flags (see `--help`).

## Security notes

- No credentials of any kind are stored in source code or tracked config files.
- All secrets are read from environment variables or CLI flags at runtime only.
- Gemini OAuth2 access tokens are cached in-process and never written to disk.
- `CRED/` and `*.json` are in `.gitignore` to prevent accidental commits of key files.
- `patch_bytes` always writes to `<file>.patched`; the original binary is never modified.

## License

Apache 2.0 — see [LICENSE](LICENSE).
