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
cargo run --release -- --help                            # flag reference
```

Run tests (none yet, but for future work):

```bash
cargo test --release
```

## Project structure

```
src/
├── main.rs         CLI (clap) + REPL (rustyline) + backend factory
├── config.rs       BackendKind / BackendConfig — load from env vars or CLI flags
├── agent.rs        Agentic loop — drives any LlmBackend, no backend knowledge
├── tools.rs        RE tool implementations + ToolDefinition list
├── ui.rs           Terminal rendering (banner, spinner, tool output, response)
└── llm/
    ├── mod.rs      LlmBackend trait + universal types
    │               (LlmMessage, MessageContent, ToolCall, ToolResult, ToolDefinition)
    ├── gemini.rs   Gemini / Vertex AI  — JWT auth, uppercase schema conversion
    ├── openai.rs   OpenAI + Ollama     — OpenAI-compatible /chat/completions
    └── anthropic.rs  Anthropic Claude  — x-api-key, input_schema, tool_use blocks
```

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

2. Add a branch to `dispatch()`.

3. Add a `ToolDefinition` to `all_definitions()`.  Use lowercase JSON Schema
   types (`"object"`, `"string"`, `"integer"`, `"boolean"`).  The name in the
   definition must exactly match the branch in `dispatch()`.

No changes to any other file are required.

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

    fn display_name(&self) -> String { … }
}
```

3. Declare the module in `src/llm/mod.rs`:  `pub mod <name>;`

4. Add a variant to `BackendKind` and `BackendConfig` in `src/config.rs`.

5. Add a match arm in `build_backend()` in `src/main.rs`.

## Key design decisions

### Universal message format (`src/llm/mod.rs`)

All backends translate to/from `Vec<LlmMessage>`.  Tool call IDs are
preserved in `ToolCall.id` and echoed in `ToolResult.call_id`; this is
required by OpenAI and Anthropic.  Gemini doesn't use IDs so it encodes them
as `"<name>-<index>"` and ignores them on the response side.

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
