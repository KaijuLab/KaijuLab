# KaijuLab

**LLM-native Reverse Engineering Lab**

KaijuLab is a command-line RE tool where the LLM is the analyst, not the assistant. Instead of bolting an AI chatbot onto an existing disassembler, KaijuLab gives Gemini a set of binary-analysis primitives and lets it drive the investigation autonomously — forming hypotheses, calling tools, interpreting results, and reporting findings in plain language.

```
  ╭──────────────────────────────────────────────────────╮
  │  KaijuLab  v0.1.0                                    │
  │  LLM-native Reverse Engineering Lab                  │
  │                                                      │
  │  Model   : gemini-2.5-flash                          │
  │  Project : my-gcp-project                            │
  ╰──────────────────────────────────────────────────────╯

> Analyse /bin/ls

  ⏺ file_info(path="/bin/ls")
  ┌──────────────────────────────────────────────────────────
  │ File         : /bin/ls
  │ Format       : Elf
  │ Architecture : X86_64 64-bit LE
  │ Entry point  : 0x0000000000004650
  │ Sections (27): .text, .rodata, .data, …
  └──────────────────────────────────────────────────────────

  ⏺ disassemble(path="/bin/ls", offset=18000, length=128)
  ┌──────────────────────────────────────────────────────────
  │   0x0000000000004650  f3 0f 1e fa              endbr64
  │   0x0000000000004654  31 ed                    xor       ebp, ebp
  │   …
  └──────────────────────────────────────────────────────────

  This is the GNU `ls` utility. The entry point follows the standard
  glibc startup sequence: clear the frame pointer, pop argc from the
  stack, then call __libc_start_main …
```

## How it works

```
User prompt
    │
    ▼
┌──────────────────────────────────────────────┐
│  Agent loop (src/agent.rs)                   │
│                                              │
│  1. Append user message to history           │
│  2. POST history + tool schemas → Gemini     │
│  3. If response contains functionCall(s):    │
│       execute each tool locally              │
│       append functionResponse to history     │
│       goto 2                                 │
│  4. Print final text response                │
└──────────────────────────────────────────────┘
         │                    ▲
         │  tool call         │  result JSON
         ▼                    │
┌──────────────────────────────────────────────┐
│  Tool dispatcher (src/tools.rs)              │
│  file_info · hexdump · strings_extract       │
│  disassemble · read_section                  │
└──────────────────────────────────────────────┘
```

The LLM backend is **Gemini via Vertex AI** with native function-calling. The OAuth2 token is obtained by signing a short-lived JWT with the service-account private key — no `gcloud` binary required at runtime.

## Prerequisites

- Rust toolchain (stable, 1.75+)
- Credentials for at least one supported LLM backend (see below)

## Setup

### 1. Clone

```bash
git clone https://github.com/Koukyosyumei/KaijuLab
cd KaijuLab
```

### 2. Choose a backend and set credentials

**Gemini** (default) — Vertex AI service account:
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json   # never commit this
export GOOGLE_PROJECT_ID=my-gcp-project
# optional: GOOGLE_LOCATION (default: us-central1)
# optional: KAIJULAB_MODEL  (default: gemini-2.5-flash)
```

**OpenAI**:
```bash
export OPENAI_API_KEY=sk-...
# optional: OPENAI_BASE_URL (default: https://api.openai.com/v1)
# optional: KAIJULAB_MODEL  (default: gpt-4o)
```

**Anthropic**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# optional: KAIJULAB_MODEL (default: claude-opus-4-5)
```

**Ollama** (local, no key needed):
```bash
# optional: OLLAMA_BASE_URL (default: http://localhost:11434/v1)
# optional: KAIJULAB_MODEL  (default: llama3.2)
ollama serve   # in another terminal
```

### 3. Build

```bash
cargo build --release
```

The compiled binary is `target/release/kaijulab`. Always use `--release`; `iced-x86` in debug mode is noticeably slower.

## Usage

### Interactive TUI (default)

```bash
cargo run --release                                      # Gemini (default)
cargo run --release -- --backend openai                 # OpenAI
cargo run --release -- --backend anthropic              # Anthropic Claude
cargo run --release -- --backend ollama --model llama3.2  # local Ollama
```

KaijuLab opens a full-screen terminal UI with five tabs:

```
 KaijuLab v0.1.0  ·  gemini-2.5-flash  ·  3x17
 [1] Functions  [2] Disasm  [3] Strings  [4] Imports  [5] Chat
┌──────────────────────────────────────────────────────────────┐
│  0x00401a50  31 ed                    xor       ebp, ebp     │
│  0x00401a52  49 89 d1                 mov       r9, rdx      │
│  0x00401a55  5e                       pop       rsi          │
│  …                                                           │
└──────────────────────────────────────────────────────────────┘
 ● Ready                           Tab:next  1-5:tab  ↑↓:scroll
 > Disassemble the main function
```

| Key | Action |
|---|---|
| `1`–`5` (empty input) | Jump to tab |
| `Tab` / `Shift+Tab` | Cycle tabs |
| `↑↓` / `PgUp` / `PgDn` | Scroll panel |
| `Enter` | Send message to agent |
| `Ctrl+C` | Quit (or clear input) |

Tool results auto-populate their tab: `list_functions` → **Functions**, `disassemble` → **Disasm**, `strings_extract` → **Strings**, `resolve_plt` → **Imports**. A `●` dot on the tab label indicates new unseen content.

### One-shot analysis

Pass a binary as a positional argument; KaijuLab analyses it and exits:

```bash
cargo run --release -- /path/to/binary
cargo run --release -- --backend openai /path/to/binary
```

### Plain-text REPL (`--no-tui`)

For scripting, piping output, or minimal environments:

```bash
cargo run --release -- --no-tui
```

### CLI flags

All env vars can be overridden with flags:

```
--backend     <NAME>   gemini (default) | openai | anthropic | ollama
--model       <ID>     Model ID (backend-specific default)
--credentials <FILE>   [Gemini] Service-account JSON key path
--project     <ID>     [Gemini] GCP project ID
--location    <REGION> [Gemini] Vertex AI region
--api-key     <KEY>    [OpenAI/Anthropic] API key
--base-url    <URL>    [OpenAI/Ollama] API base URL
--no-tui               Use plain-text REPL instead of the TUI
```

## Available tools

| Tool | Description |
|---|---|
| `file_info` | Parse ELF / PE / Mach-O headers: format, arch, entry point, LOAD segment table (vaddr ↔ file offset), section table, imports |
| `hexdump` | Hex + ASCII dump at an arbitrary file offset |
| `strings_extract` | Extract printable ASCII strings; optional `section` filter (e.g. `.rodata`) to avoid code-byte noise |
| `disassemble` | Disassemble x86 / x86-64 bytes in Intel syntax; accepts `vaddr` (auto-translated via LOAD segments) or raw `offset` |
| `read_section` | Hex dump of a named section (`.text`, `.rodata`, etc.) |
| `resolve_plt` | Map PLT stub addresses → imported symbol names via `.rela.plt` + dynamic symbol table |
| `list_functions` | List functions: symbol table for non-stripped binaries; prologue scan (`endbr64` / `push rbp; mov rbp,rsp`) for stripped ones |

## Project layout

```
src/
├── main.rs          CLI entry point (clap), mode dispatch, backend factory
├── config.rs        BackendKind / BackendConfig — env vars → CLI flags → defaults
├── agent.rs         Agentic loop — emits AgentEvent for TUI; falls back to ui:: for one-shot
├── tools.rs         RE tool implementations + ToolDefinition list
├── tui.rs           ratatui TUI — 5-tab layout, async event loop, disasm syntax highlighting
├── ui.rs            Plain-text helpers for one-shot / --no-tui mode
└── llm/
    ├── mod.rs       LlmBackend trait + universal types
    ├── gemini.rs    Gemini / Vertex AI backend
    ├── openai.rs    OpenAI + Ollama backend
    └── anthropic.rs Anthropic Claude backend
```

## Key dependencies

| Crate | Purpose |
|---|---|
| `reqwest` | Async HTTP (rustls, no OpenSSL) |
| `jsonwebtoken` | RS256 JWT signing for service-account auth |
| `object` | Pure-Rust ELF / PE / Mach-O parser |
| `iced-x86` | Pure-Rust x86 / x86-64 disassembler |
| `indicatif` | Spinner while waiting for Gemini |
| `rustyline` | Readline-style REPL with history |
| `colored` | ANSI colour output |

## Security notes

- No credentials of any kind are stored in source code or tracked config files.
- All secrets are read from environment variables or CLI flags at runtime only.
- Gemini OAuth2 access tokens are cached in-process and never written to disk.
- `CRED/` and `*.json` are in `.gitignore` to prevent accidental commits of key files.

## License

Apache 2.0 — see [LICENSE](LICENSE).
