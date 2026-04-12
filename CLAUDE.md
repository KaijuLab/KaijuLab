# KaijuLab — Claude Code guide

## Build & run

**Always use `--release`.** `iced-x86` (the disassembler) is substantially
slower in debug mode, and the overall binary analysis loop is noticeably
laggier without optimisation. Never suggest or run a plain `cargo build` /
`cargo run` without `--release`.

```bash
cargo build --release                                     # build
cargo run --release                                       # Gemini REPL (default)
cargo run --release -- --backend openai                  # OpenAI REPL
cargo run --release -- --backend anthropic               # Anthropic REPL
cargo run --release -- --backend ollama --model llama3.2 # local Ollama REPL
cargo run --release -- /path/to/binary                   # one-shot analysis
cargo run --release -- --headless /path/to/binary        # headless JSON output
cargo run --release -- --script cmds.txt                 # batch/script mode
cargo run --release -- --no-session                      # skip session save/load
cargo run --release -- --plugin vuln_triage              # run a plugin by name
cargo run --release -- --plugin /path/to/script.rhai     # run a plugin by path
cargo run --release -- --plugin hello /bin/ls            # run plugin with binary
cargo run --release -- --help                            # flag reference
```

Run tests:

```bash
cargo test --release
```

## Project structure

```
src/
├── main.rs         CLI (clap) + backend factory + mode dispatch
├── config.rs       BackendKind / BackendConfig — load from env vars or CLI flags
├── agent.rs        Agentic loop — drives any LlmBackend; emits AgentEvent for TUI
├── tools.rs        RE tool implementations + ToolDefinition list + LRU cache
├── plugin.rs       Rhai scripting engine — all RE tools callable from .rhai scripts
├── arch.rs         Architecture abstraction (ArchClass, Capstone builder, prologue patterns)
├── tui.rs          Full ratatui TUI — 8-tab layout, disasm syntax highlighting
├── ui.rs           Plain-text fallback helpers (one-shot / --no-tui mode)
├── project.rs      Per-binary annotations (renames, comments, signatures, structs)
│                   Persisted to <binary>.kaiju.db (SQLite); legacy JSON migrated on first load
├── hashdb.rs       Cross-binary function hash DB (~/.kaiju/fn_hashes.db, SQLite)
├── dwarf.rs        DWARF debug-info helpers
└── llm/
    ├── mod.rs      LlmBackend trait + universal types
    │               (LlmMessage, MessageContent, ToolCall, ToolResult, ToolDefinition)
    │               All types derive Serialize/Deserialize for session persistence.
    ├── gemini.rs   Gemini / Vertex AI  — JWT auth, uppercase schema conversion
    ├── openai.rs   OpenAI + Ollama     — OpenAI-compatible /chat/completions
    └── anthropic.rs  Anthropic Claude  — x-api-key, input_schema, tool_use blocks
```

## UI modes

| Mode | When | How |
|---|---|---|
| TUI (default) | Interactive REPL | Full ratatui TUI with 7 tabs |
| Plain-text REPL | `--no-tui` flag | Spinner/print output |
| One-shot | Positional `FILE` argument | Plain-text output, then exit |
| Headless | `--headless FILE` | Runs analysis, emits structured JSON to stdout |
| Script | `--script FILE` | Executes manual commands line-by-line, prints to stdout |

### TUI layout

```
 KaijuLab v0.1.0  ·  gemini-2.5-flash  ·  3x17
 [1] Functions  [2] Disasm  [3] Decompile  [4] Strings  [5] Imports  [6] Chat  [7] Context
┌─────────────────────────────────────────────────────────────┐
│  (scrollable content of active tab)                         │
│                                                             │
│  Disasm: address=yellow, bytes=gray, mnemonic=cyan,         │
│          registers=green, immediates=magenta                │
│          inline comments (;) = dark-gray italic             │
└─────────────────────────────────────────────────────────────┘
 ● Ready  x86_64  ·  @ 0x401000  ·  [████░░░░░░] 42%    Tab  1-7:tab  ?:help
 > _
```

### TUI key bindings

| Key | Condition | Action |
|---|---|---|
| `1`–`7` | input empty | Jump to tab directly |
| `Tab` | input empty, normal mode | Cycle to next tab |
| `Tab` | input empty, split-pane | Toggle focus left ↔ right |
| `Shift+Tab` | — | Cycle to previous tab |
| `↑` / `↓` | — | Browse sent-message history |
| `PgUp` / `PgDn` | — | Scroll active panel |
| `j` / `k` | input empty | Move line cursor in panel |
| `Enter` | input empty, panel with address at cursor | Go-to-definition |
| `Enter` | input non-empty | Send message to agent |
| `g 0xADDR` + Enter | — | Jump to address in current panel |
| `/pattern` + Enter | — | Search panel (highlights matches) |
| `n` / `N` | input empty, search active | Next / previous search match |
| `Esc` | popup open | Close popup |
| `Esc` | search active | Clear search |
| `[` / `]` | input empty | Navigate back / forward (address history) |
| `m` | input empty | Bookmark current address (focused or cursor) |
| `B` | input empty | Toggle bookmarks popup (0-9 to jump, Esc to close) |
| `x` | input empty | Xref popup — callers of address at cursor |
| `y` | input empty | Copy panel content to system clipboard |
| `s` | input empty | Toggle split-pane (Disasm left, Decompile right) |
| `r` | input empty, status starts with "Error" | Retry last message |
| `Ctrl+R` | input empty | Cycle input through sent-message history |
| `:cmd` + Enter | — | Pre-fill input with `cmd` for editing/confirmation |
| `?` | input empty | Toggle keyboard help popup |
| `Ctrl+C` | input empty | Quit |
| `Ctrl+C` | input non-empty | Clear input |

### TUI architecture

- `agent.rs` emits `AgentEvent` via `tokio::sync::mpsc::UnboundedChannel`
- `tui::run_tui()` drives a `tokio::select!` loop over agent events + `crossterm::EventStream`
- Tool results auto-populate the matching tab (`list_functions`→Functions, `disassemble`→Disasm,
  `decompile`→Decompile, `strings_extract`→Strings, `resolve_plt`/`resolve_pe_imports`→Imports)
  and mark it dirty (●)
- Chat tab always shows the full conversation with inline tool-call previews
- Context tab shows a per-entry breakdown of the LLM context window with a token-budget bar
- LLM text is streamed via `LlmTextChunk` events (appended to the last `ChatMsg::Assistant`)
- Split-pane mode (`s` key) renders Disasm and Decompile side-by-side; `Tab` switches focus

### Session persistence

- On TUI startup, if `~/.kaiju/sessions/<slug>.session.json` exists for the loaded binary,
  the conversation history is restored automatically (unless `--no-session` is passed).
- On TUI exit, the history is saved back to the same file.

## Credentials — never hardcode

| Backend   | Required env var                    | Optional env var        |
|-----------|-------------------------------------|-------------------------|
| Gemini    | `GOOGLE_APPLICATION_CREDENTIALS`    | `GOOGLE_PROJECT_ID`, `GOOGLE_LOCATION` |
| OpenAI    | `OPENAI_API_KEY`                    | `OPENAI_BASE_URL`       |
| Anthropic | `ANTHROPIC_API_KEY`                 | —                       |
| Ollama    | —                                   | `OLLAMA_BASE_URL`       |

All of the above can also be set with CLI flags (see `--help`).  Never write
API keys, project IDs, or key file paths into source files.

## Adding a new RE tool

1. Implement the function in `src/tools.rs` — return `ToolResult::ok(string)`
   or `ToolResult::err(string)`.

2. Add a branch to `dispatch_inner()`.

3. Add a `ToolDefinition` to `all_definitions()`.  Use lowercase JSON Schema
   types (`"object"`, `"string"`, `"integer"`, `"boolean"`).  The name in the
   definition must exactly match the branch in `dispatch_inner()`.

4. If the tool populates a dedicated panel, add it to `Tab::from_tool()` in `src/tui.rs`.

5. If the tool result should be cached (expensive read-only), add its name to `CACHEABLE_TOOLS`
   in `src/tools.rs`.  Write tools that modify project state must be added to `WRITE_TOOLS`
   so the cache is invalidated automatically.

6. Add a manual command entry to `dispatch_manual_command()` in `src/main.rs` and update
   the `MANUAL_HELP` string.

No changes to any LLM backend files are required.

## Adding a new LLM backend

1. Create `src/llm/<name>.rs`.

2. Implement `LlmBackend` from `src/llm/mod.rs`:

```rust
#[async_trait]
impl LlmBackend for MyBackend {
    async fn generate(
        &self,
        system: &str,
        history: &[LlmMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmMessage> { … }

    // Optional: override for true streaming support
    async fn generate_streaming(
        &self,
        system: &str,
        history: &[LlmMessage],
        tools: &[ToolDefinition],
        chunk_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Result<LlmMessage> { … }

    fn display_name(&self) -> String { … }
}
```

3. Declare the module in `src/llm/mod.rs`:  `pub mod <name>;`

4. Add a variant to `BackendKind` and `BackendConfig` in `src/config.rs`.

5. Add a match arm in `build_backend()` in `src/main.rs`.

## Available RE tools

### Binary info & disassembly

| Tool | Key behaviour |
|---|---|
| `file_info` | Format, arch, entry point, LOAD segments (vaddr↔offset), sections, imports |
| `hexdump` | Raw hex dump at a file offset |
| `read_section` | Hex dump of a named section |
| `strings_extract` | Optional `section` param (e.g. `.rodata`) narrows scan |
| `disassemble` | Accepts `vaddr` — auto-translates via LOAD segments; or raw `offset`; stops at `ret` |
| `list_functions` | Symbol table if available; prologue scan for stripped binaries; optional `json:true` |
| `resolve_plt` | `.rela.plt` + `.dynsym` → stub address → symbol name (ELF) |
| `resolve_pe_imports` | PE import table → DLL + function name per thunk |
| `dwarf_info` | Function names/addresses/sizes from DWARF debug info |
| `xrefs_to` | All CALL/JMP sites in `.text` that target a given vaddr (x86/x86-64 only) |
| `decompile` | Lifts a function to pseudo-C using the built-in pcode decompiler; applies project renames/types |
| `decompile_flat` | Decompile raw bytes at an arbitrary base address (firmware / shellcode) |
| `cfg_view` | Control-flow graph (basic blocks + edges) for a function |
| `call_graph` | Full static call graph up to `max_depth` levels |

### Search & patch

| Tool | Key behaviour |
|---|---|
| `search_bytes` | Hex byte-pattern search with `??` wildcards throughout the binary |
| `patch_bytes` | Write bytes at a file offset or vaddr; output is `<file>.patched` (original untouched) |
| `section_entropy` | Shannon entropy per section + whole file; flags packed/encrypted regions |
| `generate_yara_rule` | Auto-wildcards position-dependent bytes for a relocatable YARA detection rule |

### Intelligence & vulnerability analysis

| Tool | Key behaviour |
|---|---|
| `scan_vulnerabilities` | Heuristic scan for dangerous patterns (strcpy, gets, format-string, etc.) |
| `set_vuln_score` | Persist an analyst 0-10 score for a function; TUI shows [!] / [!!] badges |
| `explain_function` | Combined disasm + decompile + project context; prompts analyst for interpretation |
| `identify_library_functions` | FLIRT-style hash comparison against standard library prologues |
| `auto_analyze` | Full-pass: file_info → list_functions → strings → vuln scan → summary |
| `diff_binary` | Compare two binaries by function-level content hash |
| `virustotal_check` | SHA-256 lookup against VT v3 API (needs `VIRUSTOTAL_API_KEY`) |

### Function hash database (cross-binary)

| Tool | Key behaviour |
|---|---|
| `register_function_hash` | Normalise-hash a function and store in `~/.kaiju/fn_hashes.db` |
| `lookup_function_hash` | Look up a function's hash against the DB |
| `match_all_functions` | Scan every function in a binary; report any DB matches |

Normalisation zeroes CALL/JMP rel32, RIP-relative disp32, and `MOV r64, imm64` so the hash
is relocate-invariant (survives ASLR and recompilation).

### Project annotations (persistent per binary)

| Tool | Key behaviour |
|---|---|
| `rename_function` | Assign a name to a vaddr; appears in subsequent disasm/decompile |
| `add_comment` | Attach a comment to an address |
| `rename_variable` | Rename a decompiler variable inside a specific function |
| `set_return_type` | Set the return type for a function signature |
| `set_param_type` | Set the type of parameter N (1-indexed) |
| `set_param_name` | Set the name of parameter N (1-indexed) |
| `define_struct` | Define a named struct with typed fields |
| `list_types` | List all struct and signature annotations in the project |
| `load_project` | Show all saved annotations (renames, comments, notes, scores) for a binary |
| `load_pdb` | Load Windows PDB symbols and import names + addresses into the project |
| `export_report` | Generate a self-contained HTML analysis report (`<binary>.kaiju.html`) |
| `add_note` | Save a free-form analyst note (optionally anchored to a vaddr); persists to SQLite; updates TUI Notes tab live |
| `delete_note` | Delete an analyst note by id |
| `list_notes` | List all analyst notes for a binary |
| `get_vuln_scores` | Read all previously set vulnerability scores for a binary |

### vaddr / file-offset distinction

ELF virtual addresses ≠ file offsets.  The `disassemble` tool internally
resolves vaddr → file offset using the LOAD segment table, so passing
`vaddr=entry_point` just works.  Always call `file_info` first so the LLM
knows the segment layout before calling `disassemble`.

## Plugin / Scripting API

KaijuLab embeds [Rhai](https://rhai.rs/) as a Rust-native scripting engine.
Scripts are `.rhai` files stored in `~/.kaiju/plugins/`.

### Invoking plugins

```bash
# CLI: run a plugin by name (looked up in ~/.kaiju/plugins/)
kaijulab --plugin vuln_triage --backend none /path/to/binary

# CLI: run a plugin by file path
kaijulab --plugin /path/to/script.rhai --backend none /bin/ls

# TUI: type in the input box and press Enter
run vuln_triage           # uses current loaded binary automatically
run hello /bin/ls         # explicit binary path
plugins                   # list all installed plugins
```

### Script API

Every Rhai script receives a pre-set `binary` global (the currently loaded
binary path).  All RE tools are callable as top-level functions that return
`String`.

**Analysis (read-only)**
```rhai
file_info(path)               // binary metadata
disassemble(path, vaddr)      // default 128-byte window
disassemble_at(path, vaddr, length)
list_functions(path)
strings_extract(path)
decompile(path, vaddr)
scan_vulnerabilities(path)
xrefs_to(path, vaddr)
cfg_view(path, vaddr)
call_graph(path)
hexdump(path, offset, length)
section_entropy(path)
load_project(path)            // all saved annotations
list_notes(path)
get_vuln_scores(path)
dwarf_info(path)
search_bytes(path, pattern)   // e.g. "E8 ?? ?? ?? ??"
generate_yara(path, vaddr)
identify_library_functions(path)
diff_binary(path_a, path_b)
```

**Annotation (write — persisted to SQLite)**
```rhai
rename_function(path, vaddr, name)
add_comment(path, vaddr, text)
add_note(path, text)
add_note_at(path, text, vaddr)
set_vuln_score(path, vaddr, score)  // 0–10
rename_variable(path, fn_vaddr, old_name, new_name)
set_return_type(path, vaddr, type_str)
set_param_type(path, vaddr, param_index, type_str)
set_param_name(path, vaddr, param_index, name)
delete_note(path, id)
```

**Utility**
```rhai
hex(n)            // 0x401000i64 → "0x401000"
parse_addr(s)     // "0x401000" → 4198400i64
plugins_dir()     // path to ~/.kaiju/plugins/
```

### Writing a plugin

```rhai
// ~/.kaiju/plugins/my_plugin.rhai
// First comment line becomes the description shown in `plugins` listing.

print("Analysing: " + binary);

let info = file_info(binary);
print(info);

let fns = list_functions(binary);
print(fns);

// Rename a function at a known address
rename_function(binary, 0x401000, "entry_point");
add_note_at(binary, "Analysis started by my_plugin", 0x401000);
```

### Key design decisions for plugins (`src/plugin.rs`)

- **`build_engine(print_buf)`** constructs a fresh `rhai::Engine` per run
  with all tool functions registered.  `on_print` / `on_debug` are wired to
  an `Arc<Mutex<String>>` so output is captured rather than written to stdout.
- Plugins run in **`tokio::task::spawn_blocking`** in TUI mode so they never
  stall the async event loop.
- The `binary` variable is injected into the `Scope` before `eval_with_scope`.
  When the user types `run <name>` in the TUI without a path, the current
  `app.binary_path` is appended automatically.
- Write tools inside a plugin invalidate the LRU cache exactly as they do
  when called by the LLM.
- Example plugins live in `examples/plugins/`.

## Key design decisions

### Universal message format (`src/llm/mod.rs`)

All backends translate to/from `Vec<LlmMessage>`.  Tool call IDs are
preserved in `ToolCall.id` and echoed in `ToolResult.call_id`; this is
required by OpenAI and Anthropic.  Gemini doesn't use IDs so it encodes them
as `"<name>-<index>"` and ignores them on the response side.

All `LlmMessage` types derive `Serialize`/`Deserialize` for session persistence.

### LRU tool cache (`src/tools.rs`)

`TOOL_CACHE` (50-entry FIFO) caches results for expensive read-only tools
(`disassemble`, `decompile`, `xrefs_to`, `cfg_view`, `call_graph`).
Write tools (`rename_function`, `add_comment`, `set_vuln_score`, etc.) call
`cache.invalidate_path()` to evict all entries for the affected binary.
All dispatch is wrapped in `catch_unwind` so a malformed binary cannot crash the process.

### `#[serde(untagged)]` on Gemini `GPart`

Gemini returns parts as plain JSON objects distinguished only by field
presence (`text`, `functionCall`, `functionResponse`).  `#[serde(untagged)]`
tries each variant in declaration order; the `Unknown(Value)` catch-all
absorbs future part types (e.g. `thought`, `executableCode`).  Most-specific
variants must come first.

### Anthropic `#[serde(tag = "type")]` on content blocks

Anthropic content blocks carry an explicit `"type"` field.  Using an
internally-tagged enum keeps the deserialisation clean.  The `#[serde(other)]`
`Unknown` variant absorbs any unknown block types.

### Token caching (Gemini only)

`GeminiBackend` caches the OAuth2 access token in `Mutex<Option<CachedToken>>`
and refreshes when fewer than 60 s remain.  The token is never written to disk.

### Tool output is a plain string

`tools::ToolResult.output` is just a `String`.  Each backend wraps it
appropriately:
- Gemini wraps it as `{"output": "..."}` inside a `functionResponse`.
- OpenAI passes it as the `content` of a `role: "tool"` message.
- Anthropic passes it as the `content` of a `tool_result` block.

### Schema normalisation

`tools::all_definitions()` uses standard lowercase JSON Schema types
(`"object"`, `"string"`, `"integer"`).  The Gemini backend uppercases them
via `uppercase_types()` before sending; OpenAI and Anthropic accept lowercase
directly.

### History trimming (`src/agent.rs`)

`trim_history()` compresses tool-result messages to compact summaries once the
estimated character count exceeds `MAX_HISTORY_CHARS` (≈ 80 K chars / 20 K tokens).
Plain user/assistant text is never dropped.  Summaries are injected as user
messages so the LLM retains awareness of previously seen data.

### Streaming (`src/llm/mod.rs`, `src/agent.rs`)

`LlmBackend::generate_streaming()` default falls through to `generate()`.
Backends that support true streaming override it and send `String` chunks via
`chunk_tx`.  In TUI mode the agent spawns a forward task that converts each
chunk to an `AgentEvent::LlmTextChunk`, appended live to the Chat panel.

## Gemini API endpoint

```
POST https://{location}-aiplatform.googleapis.com/v1/projects/{project}/
     locations/{location}/publishers/google/models/{model}:generateContent
Authorization: Bearer <oauth2_access_token>
```

## Environment variables reference

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
| `VIRUSTOTAL_API_KEY` | — | Enable `virustotal_check` tool | — (optional) |
