# KaijuLab

> **AI-Powered Reverse Engineering Lab**

<p align="center">
  <a href="https://github.com/Koukyosyumei/" target="_blank">
      <img src="https://github.com/KaijuLab/KaijuLab.github.io/blob/main/static/images/logo.png" alt="h5i Logo" height="126">
  </a>
</p>

KaijuLab is a terminal-based reverse-engineering environment where an AI agent acts as the analyst, using tools like disassembly, decompilation, cross-references, call graphs, YARA generation, and vulnerability scoring to autonomously investigate binaries and report findings in natural language.

## Prerequisites

- Rust toolchain (stable, 1.75+)
- Credentials for at least one supported LLM backend　**or none** (no-LLM manual mode works without any API key)

## Setup

### 1. Install

```bash
cargo install --git https://github.com/KaijuLab/KaijuLab kaijulab
```

### 2. Choose a backend and set credentials

**Gemini** — Vertex AI service account:
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json   # never commit this
export GOOGLE_PROJECT_ID=my-gcp-project
# optional: GOOGLE_LOCATION (default: us-central1)
# optional: KAIJULAB_MODEL  (default: gemini-2.5-flash)
kaijulab -- --backend gemini
```

**OpenAI**:
```bash
export OPENAI_API_KEY=sk-...
# optional: OPENAI_BASE_URL (default: https://api.openai.com/v1)
# optional: KAIJULAB_MODEL  (default: gpt-4o)
kaijulab -- --backend openai
```

**Anthropic**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# optional: KAIJULAB_MODEL (default: claude-opus-4-5)
kaijulab -- --backend anthropic
```

**Ollama** (local, no key needed):
```bash
# optional: OLLAMA_BASE_URL (default: http://localhost:11434/v1)
# optional: KAIJULAB_MODEL  (default: llama3.2)
ollama serve   # in another terminal
kaijulab -- --backend ollama --model llama3.2
```

## Usage

### Interactive TUI (default)

```bash
kaijulab                                        # no LLM (manual mode)
kaijulab -- --backend gemini                    # Gemini via Vertex AI
kaijulab -- --backend openai                    # OpenAI
kaijulab -- --backend anthropic                 # Anthropic Claude
kaijulab -- --backend ollama --model llama3.2   # local Ollama
```

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
kaijulab -- /path/to/binary
kaijulab -- --backend openai /path/to/binary
kaijulab -- --backend gemini /path/to/binary --output-json   # structured JSON to stdout
```

### Script / batch mode

Run a file of tool commands (one per line, `#` comments and blank lines ignored) and exit:

```bash
kaijulab -- --script analysis.txt
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
kaijulab -- --headless --backend gemini /path/to/binary
```

### Plain-text REPL (`--no-tui`)

For piping output or minimal environments:

```bash
kaijulab -- --no-tui
```

### Session persistence

By default, conversation history is saved to `~/.kaiju/sessions/` keyed by binary path. On restart with the same binary, the previous session is restored automatically. Use `--no-session` to opt out:

```bash
kaijulab -- --no-session /path/to/binary
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

## License

Apache 2.0 — see [LICENSE](LICENSE).
