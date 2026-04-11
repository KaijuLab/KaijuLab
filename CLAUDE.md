# KaijuLab — Claude Code guide

## Build & run

**Always use `--release`.** `iced-x86` (the disassembler) is substantially
slower in debug mode, and the overall binary analysis loop is noticeably
laggier without optimisation. Never suggest or run a plain `cargo build` /
`cargo run` without `--release`.

```bash
cargo build --release                          # build
cargo run --release                            # interactive REPL
cargo run --release -- /path/to/binary        # one-shot analysis
cargo run --release -- --help                  # flag reference
```

Run tests (there are none yet, but for future work):

```bash
cargo test --release
```

## Project structure

```
src/
├── main.rs      CLI (clap) + interactive REPL (rustyline)
├── config.rs    Load credentials / project / location / model
│                Priority: CLI flag > env var > default
├── llm.rs       Gemini / Vertex AI client
│                  - ServiceAccount JSON parsing
│                  - RS256 JWT → OAuth2 token exchange, cached
│                  - generateContent request / response types
│                  - SYSTEM_PROMPT constant
├── agent.rs     Agentic loop
│                  - Maintains conversation history (Vec<Content>)
│                  - Calls llm::GeminiClient::generate()
│                  - Dispatches tool calls, feeds results back
│                  - Loops until no more functionCall parts
├── tools.rs     RE tool implementations + Gemini function declarations
│                  - dispatch(name, args) → ToolResult
│                  - all_declarations() → Vec<FunctionDeclaration>
└── ui.rs        Terminal rendering
                   - print_banner, new_spinner
                   - print_tool_call, print_tool_output
                   - print_agent_response, print_separator
                   - readline (rustyline wrapper)
```

## Credentials — never hardcode

Credentials are loaded strictly from:

1. `--credentials <path>` CLI flag
2. `GOOGLE_APPLICATION_CREDENTIALS` env var

Project ID from:

1. `--project <id>` CLI flag
2. `GOOGLE_PROJECT_ID` env var

Do not write project IDs, key file paths, or any GCP identifiers into source
files. The actual key file lives outside the repo (e.g. `../CRED/`).

## Adding a new RE tool

1. Implement the function in `src/tools.rs` — return `ToolResult::ok(string)`
   or `ToolResult::err(string)`.

2. Add a branch to `dispatch()` mapping the tool name to your function.

3. Add a `FunctionDeclaration` to `all_declarations()` using the Gemini JSON
   Schema format (`"type": "OBJECT"`, `"type": "STRING"`, `"type": "INTEGER"`,
   `"required": [...]`). The `name` field must exactly match the branch in
   `dispatch()`.

No changes to `agent.rs`, `llm.rs`, or `main.rs` are required — the tool list
is passed to the API at runtime.

## Adding a new LLM backend

The only LLM-facing surface is `llm::GeminiClient::generate()`:

```rust
pub async fn generate(
    &self,
    history: &[Content],
    tools: &[FunctionDeclaration],
) -> Result<Candidate>
```

`Content` / `Part` / `FunctionDeclaration` are defined in `llm.rs`.
To add a second backend (e.g. Claude API), introduce a trait:

```rust
pub trait LlmBackend {
    async fn generate(&self, history: &[Content], tools: &[FunctionDeclaration])
        -> Result<Candidate>;
}
```

then make `Agent` generic over it.

## Key design decisions

### `#[serde(untagged)]` on `Part`

Gemini returns parts as plain JSON objects distinguished only by field
presence (`text`, `functionCall`, `functionResponse`). `#[serde(untagged)]`
tries each variant in declaration order; the `Unknown(Value)` catch-all
absorbs future part types (e.g. `thought`, `executableCode`) without
breaking deserialisation.

Variant order matters — put more-specific variants (those with rarer field
names) before less-specific ones.

### Function-response protocol

Gemini expects function results back as `role: "user"` messages containing
`functionResponse` parts (not a dedicated `role: "tool"`). One user message
may contain multiple `functionResponse` parts when the model called several
tools in parallel.

### Token caching

`GeminiClient` caches the OAuth2 access token in a `Mutex<Option<CachedToken>>`
and refreshes it when fewer than 60 seconds remain. This avoids one JWT
signing + HTTP round-trip per LLM call. The token is never written to disk.

### Tool output truncation

`ui::print_tool_output` shows at most 30 lines to keep the terminal readable.
The full string is still sent to the LLM inside the `functionResponse`, so the
model sees everything even when the terminal display is truncated.

## Gemini API endpoint

```
POST https://{location}-aiplatform.googleapis.com/v1/projects/{project}/
     locations/{location}/publishers/google/models/{model}:generateContent
```

Authentication: `Authorization: Bearer <oauth2_access_token>`.

## Environment variables reference

| Variable | Purpose | Default |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service-account JSON key | — (required) |
| `GOOGLE_PROJECT_ID` | GCP project ID | — (required) |
| `GOOGLE_LOCATION` | Vertex AI region | `us-central1` |
| `KAIJULAB_MODEL` | Gemini model ID | `gemini-2.5-flash` |
