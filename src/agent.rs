use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::llm::{LlmBackend, LlmMessage, ToolResult};
use crate::tools;
use crate::ui;

// ─── Events sent to the TUI ──────────────────────────────────────────────────

/// Events the agent emits so the TUI can update its panels in real time.
/// When no channel is attached (one-shot / plain-text mode) these are never
/// created — the agent falls back to the `ui::print_*` functions instead.
/// Lightweight summary of one message in the LLM history, for the Context tab.
#[derive(Debug, Clone)]
pub struct ContextEntry {
    pub role: &'static str,   // "user" | "assistant"
    pub kind: &'static str,   // "text" | "tool_call" | "tool_result"
    pub tool_name: Option<String>,
    pub char_count: usize,
    pub preview: String,      // first ~100 chars of content
}

#[derive(Debug)]
pub enum AgentEvent {
    /// LLM is generating a response.
    Thinking,
    /// LLM issued a tool call.
    ToolCall { name: String, display_args: String },
    /// Tool finished; `output` is the full result string.
    ToolResult { name: String, output: String },
    /// LLM produced a final text response (non-streaming fallback or after streaming).
    LlmText(String),
    /// A single streaming text chunk from the LLM (partial response).
    LlmTextChunk(String),
    /// Agent turn is complete.
    Done,
    /// API or tool error.
    Error(String),
    /// The agent is actively examining a virtual address.
    /// The TUI uses this to highlight and scroll to the address.
    Focus { vaddr: u64, tool: String },
    /// Snapshot of the current LLM context window, for the Context tab.
    ContextUpdate(Vec<ContextEntry>),
    /// Updated vulnerability scores from a scan_vulnerabilities / set_vuln_score run.
    /// Maps fn_vaddr → score (0–10). TUI uses these for [!] badges in Functions tab.
    VulnScores(HashMap<u64, u8>),
    /// Progress update during a multi-tool turn (e.g. auto_analysis).
    /// `step` is 1-based; `total` is the expected total number of tool calls.
    Progress { step: usize, total: usize, label: String },
    /// The current agent turn was cancelled by the user (Ctrl+X).
    Cancelled,
    /// Updated notes list after an add_note / delete_note tool call.
    /// The TUI uses this to refresh the Notes tab immediately.
    NotesUpdate(Vec<crate::project::Note>),
    /// A plugin script finished running.
    /// `name` is the plugin identifier; `output` is its captured print output.
    PluginOutput { name: String, output: String },
}

/// Estimated character budget before we start trimming old tool-result messages.
/// ~80 K chars ≈ 20 K tokens, comfortable headroom under typical 128 K limits.
const MAX_HISTORY_CHARS: usize = 80_000;

/// Replace the oldest tool-result messages with compact summaries until the total
/// estimated character count falls below `MAX_HISTORY_CHARS`.
/// Plain user/assistant text is never dropped so the conversation thread stays coherent.
/// Summaries are injected as user messages so the LLM knows what data was seen,
/// even though the full output is gone.
fn trim_history(history: &mut Vec<crate::llm::LlmMessage>) {
    loop {
        let total: usize = history.iter().map(|m| m.estimated_chars()).sum();
        if total <= MAX_HISTORY_CHARS {
            break;
        }
        if let Some(pos) = history.iter().position(|m| m.is_tool_result_message()) {
            let summary = summarize_tool_result_msg(&history[pos]);
            history[pos] = crate::llm::LlmMessage::user_text(summary);
        } else {
            break; // nothing left to compress
        }
    }
}

/// Build a compact summary of a tool-result message so the LLM retains
/// awareness of what was found without the full output consuming context budget.
fn summarize_tool_result_msg(msg: &crate::llm::LlmMessage) -> String {
    use crate::llm::MessageContent;
    let parts: Vec<String> = msg.content.iter().filter_map(|c| {
        if let MessageContent::ToolResult(tr) = c {
            let lines = tr.content.lines().count();
            // Keep the first 3 non-empty lines as a preview
            let preview: String = tr.content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ");
            let preview = if preview.len() > 300 {
                format!("{}…", &preview[..300])
            } else {
                preview
            };
            Some(format!(
                "[context-compressed] Previously called `{}` ({} lines). Preview: {}",
                tr.name, lines, preview
            ))
        } else {
            None
        }
    }).collect();
    parts.join("\n")
}

const SYSTEM_PROMPT: &str = "\
You are KaijuLab, an expert reverse-engineering assistant embedded in an interactive \
analysis environment. You have persistent tools that write findings directly into the \
analyst's workspace — use them proactively.

## Workflow

1. **Orient first**: call `load_project` to see what renames, comments, notes, and \
vulnerability scores already exist from previous sessions. Call `list_notes` if you \
want to read analyst observations in detail.

2. **Enumerate before diving**: call `file_info` (format/arch/segments), then \
`list_functions` (or `dwarf_info` for debug-info binaries) to understand scope.

3. **Annotate as you go** — every finding should be persisted immediately:
   - **Prefer `batch_annotate`** over individual calls when you have multiple annotations \
     for the same function. One `batch_annotate` call can set the function name, comment, \
     return type, all parameter names/types, and variable renames atomically. \
     Always re-decompile after `batch_annotate` to confirm the output looks right.
   - `rename_function(path, vaddr, name)` for quick single renames.
   - `add_comment(path, vaddr, comment)` for important addresses, suspicious patterns, \
     or non-obvious observations at instruction level.
   - `add_note(path, text, vaddr?)` for high-level findings: algorithm identification, \
     vulnerability hypotheses, analysis conclusions, or anything the analyst should know.
   - `set_vuln_score(path, vaddr, score)` after reviewing any function: 0=clean, \
     4-6=suspicious, 7-9=high-risk, 10=critical. Always score functions you analyse.

4. **Verify with disasm/decompile**: never assume what a call target does — use \
`disassemble` or `decompile` to confirm. Use `xrefs_to` to understand data flow.

5. **Summarise at the end**: after tool calls, give a concise, structured summary of \
what you found. Reference function names and addresses. Highlight the most important findings.

## Tool selection guidance

- Strings → `strings_extract` (pass `section='.rodata'` to avoid .text noise)
- Vulnerability hunting → `scan_vulnerabilities`, then `decompile` suspicious functions, \
  then `set_vuln_score`
- **Crypto identification** → `crypto_identify` before decompiling — instantly maps which \
  algorithms (AES, SHA-256, ChaCha20, MD5, CRC32, ...) are present and at which addresses. \
  Follow up with `decompile` at the returned VA to see how the algorithm is called.
- **Deep single-function analysis** → `function_context` instead of separate decompile + \
  xrefs_to + disassemble calls. Returns decompiled pseudo-C, all callers with call-sites, \
  all direct callees, and existing annotations in one response.
- **Finding crash/bypass inputs** → `angr_find(path, find_addr)` uses angr symbolic execution \
  to find concrete stdin bytes that reach a target address. This is the one capability a \
  pure static LLM cannot replicate. Use it for: CTF win-condition paths, license checks, \
  password validation bypass. Run `python_env` first to confirm angr is installed.
- **PE hardening audit** (Windows .exe/.dll) → **always call `pe_security_audit` first** \
  before `scan_vulnerabilities`. It runs in O(file_size) with no decompilation and detects \
  structural mitigations issues: writable .rodata/.fptable sections (exploitable without \
  VirtualProtect), CFG declared but guard-check stub is a RET no-op, bare BLR ratio, \
  stack canary (SecurityCookie) coverage, and missing Force Integrity. These findings are \
  missed by `scan_vulnerabilities` alone on large stripped PE binaries.
- Unknown stripped binary → `identify_library_functions` first to name libc functions
- Import resolution → `resolve_plt` (ELF) or `resolve_pe_imports` (PE) before disassembling
- Full pass → `auto_analyze` kicks off file_info + list_functions + strings + vuln scan
- **C++ binary** → `recover_vtables` early to map classes and virtual dispatch chains before \
  spending decompile budget; rename discovered methods immediately with `rename_function`
- **No readable strings / high entropy** → `find_string_decoders` to locate XOR/ADD loop stubs, \
  then emulate with `run_python` + unicorn (see template below) to recover plaintext
- **Runtime behaviour** → `frida_trace` with specific import names or addresses to log call \
  arguments and return values without a full debugger; run `python_env` first to confirm frida \
  is installed

## Large binary warning

**Never call `auto_analyze` on a binary with more than ~100 functions.** \
Statically linked binaries (musl, glibc-static) routinely contain 500–2000+ functions; \
running `auto_analyze` on them causes memory exhaustion and is explicitly blocked. \
If `list_functions` or `file_info` reveals a large function count:\
\n1. `file_info` — architecture, segments, sections\
\n2. For PE binaries: `pe_security_audit` — O(file_size) hardening audit (no decompilation)\
\n3. **`run_python` with capstone** — bulk-scan the whole binary in one call to locate \
high-value targets (all callers of a dangerous import, all functions with suspicious byte \
patterns) before spending tool budget on individual functions\
\n4. `list_functions` — browse and pick high-value targets by address\
\n5. `disassemble` / `decompile` on the small set of targets identified above\
\n6. `scan_vulnerabilities` — limited to a small `max_fns` count

## Decompile-failure protocol — MANDATORY

When `decompile` returns an error (too complex, AST panic, irreducible CFG, or any other \
error), follow this **ordered fallback chain** without stopping at step 1:

1. **`disassemble(path, vaddr=<addr>)`** — for PE binaries this auto-sizes to the full \
   function body from .pdata, giving you every instruction even for 20k-IR-block functions. \
   Read the disassembly carefully: identify callers (`bl`/`call`), loops, and memory accesses.
2. **`function_context(path, vaddr=<addr>)`** — get callers, callees, and annotations without \
   running the decompiler.
3. **`run_python` with capstone** (see Trigger 1 below) — scan the function bytes for \
   dangerous call targets, crypto constants, and loop signatures.

**Never say 'decompilation failed, further analysis requires dynamic tools' without first \
completing all three steps above.** The function is often the most important one; skipping it \
is not an option.

## run_python — when and how

`run_python` executes a **complete, self-contained Python 3 script** in a subprocess. \
Each call is independent: no state carries over between calls. \
**Call `python_env` once before writing scripts** to confirm which packages are installed. \
**Always write the full script in one call.** If a script fails, fix the specific line and \
resubmit the entire corrected script — never give up after one failure.

### Trigger 1 — decompile fails (function too complex)

The function is often the most important one in the binary. Do NOT skip it. \
Use capstone to scan it for dangerous call targets, crypto constants, and loop structures. \
**First use the `disassemble` tool** (it auto-sizes from .pdata for PE), then use this script \
for deeper pattern scanning or if you need to filter thousands of instructions.

  import capstone, pefile, os, struct
  pe    = pefile.PE(os.environ['KAIJU_BINARY'])
  base  = pe.OPTIONAL_HEADER.ImageBase
  # detect arch: check PE machine type
  machine = pe.FILE_HEADER.Machine  # 0xAA64=ARM64, 0x8664=x64
  if machine == 0xAA64:
      cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
  else:
      cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
  cs.detail = True
  # locate the function bytes; get size from .pdata if available
  va_start = 0x140001000  # replace with actual vaddr
  rva      = va_start - base
  raw_off  = pe.get_offset_from_rva(rva)
  fn_size  = 4096  # conservative default; override with .pdata size if known
  data     = open(os.environ['KAIJU_BINARY'], 'rb').read()
  code     = data[raw_off : raw_off + fn_size]
  for insn in cs.disasm(code, va_start):
      if insn.mnemonic in ('bl', 'blr', 'call', 'jmp'):
          print('0x%x  %-6s %s' % (insn.address, insn.mnemonic, insn.op_str))
      if insn.mnemonic in ('ret', 'retn'):
          break

### Trigger 2 — large binary, goal is 'find all X'

When `list_functions` returns >100 functions and you need to locate a pattern across the \
whole binary (every caller of VirtualAlloc, every function containing a specific byte \
sequence), one Python script beats calling `disassemble` dozens of times.

  import capstone, pefile, os
  pe   = pefile.PE(os.environ['KAIJU_BINARY'])
  base = pe.OPTIONAL_HEADER.ImageBase
  imp  = {e.name.decode(): e.address for s in pe.sections
          if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
          for entry in pe.DIRECTORY_ENTRY_IMPORT
          for e in entry.imports if e.name}
  target_name = b'VirtualAlloc'  # change as needed
  target_thunk = next((e.address for entry in pe.DIRECTORY_ENTRY_IMPORT
                       for e in entry.imports if e.name == target_name), None)
  cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
  text = next(s for s in pe.sections if b'.text' in s.Name)
  code = text.get_data()
  va   = base + text.VirtualAddress
  for insn in cs.disasm(code, va):
      if insn.mnemonic == 'call' and target_thunk:
          ops = insn.op_str.replace(' ', '')
          try:
              if int(ops, 16) == target_thunk:
                  print('caller at 0x%x' % insn.address)
          except ValueError:
              pass

### Trigger 3 — high entropy section (packed / encrypted data)

`section_entropy` returned > 7.5 on a non-.text section. Attempt decryption immediately \
rather than browsing hex fragments.

  import os, struct, math
  data = open(os.environ['KAIJU_BINARY'], 'rb').read()
  # locate section — replace offset/size from file_info output
  blob = data[0x1000 : 0x1000 + 0x400]
  # try single-byte XOR brute-force; pick key with highest printable ratio
  best_key, best_score, best = 0, 0, b''
  for k in range(256):
      dec = bytes(b ^ k for b in blob)
      score = sum(0x20 <= c < 0x7f for c in dec)
      if score > best_score:
          best_key, best_score, best = k, score, dec
  print('best XOR key: 0x%02x  printable: %d/%d' % (best_key, best_score, len(blob)))
  print(best[:256])

### Trigger 4 — custom data format or embedded config

`pe_internals`/`elf_internals` doesn't parse it. Strings are obfuscated or encoded. \
Use `struct.unpack` or manual parsing directly on the raw bytes.

  import os, struct
  data = open(os.environ['KAIJU_BINARY'], 'rb').read()
  u32 = lambda off: struct.unpack_from('<I', data, off)[0]
  u64 = lambda off: struct.unpack_from('<Q', data, off)[0]
  # example: walk a config table at a known offset
  off = 0x3000
  count = u32(off); off += 4
  for i in range(count):
      key   = u32(off);  off += 4
      value = u64(off);  off += 8
      print('entry %d: key=0x%x val=0x%x' % (i, key, value))

### Trigger 5 — emulate a decoder stub with unicorn

After `find_string_decoders` identifies a candidate and `decompile` shows the loop body, \
use unicorn to run it and extract the plaintext strings without executing the whole binary.

  import unicorn, unicorn.x86_const as x86, os, struct, pefile
  pe   = pefile.PE(os.environ['KAIJU_BINARY'])
  base = pe.OPTIONAL_HEADER.ImageBase
  data = open(os.environ['KAIJU_BINARY'], 'rb').read()

  DECODER_VA = 0x140012345  # replace with address from find_string_decoders
  DECODER_RVA = DECODER_VA - base
  raw_off  = pe.get_offset_from_rva(DECODER_RVA)
  code     = data[raw_off : raw_off + 256]    # enough for a small stub

  STACK_BASE = 0x7ff000000000
  HEAP_BASE  = 0x7fe000000000
  HEAP_SIZE  = 0x10000
  encrypted  = b'\\x41\\x02\\x43'  # replace with actual encrypted bytes
  key        = 0x41                # replace with XOR key from find_string_decoders

  mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
  # map code page
  PAGE = (DECODER_VA & ~0xfff)
  mu.mem_map(PAGE, 0x2000)
  mu.mem_write(DECODER_VA, code)
  # map heap for input/output buffers
  mu.mem_map(HEAP_BASE, HEAP_SIZE)
  mu.mem_write(HEAP_BASE, encrypted)
  # map stack
  mu.mem_map(STACK_BASE - 0x10000, 0x10000)
  mu.reg_write(x86.UC_X86_REG_RSP, STACK_BASE - 0x100)
  # set arguments (rdi=dst, rsi=src, rdx=len, rcx=key)
  mu.reg_write(x86.UC_X86_REG_RDI, HEAP_BASE + 0x1000)
  mu.reg_write(x86.UC_X86_REG_RSI, HEAP_BASE)
  mu.reg_write(x86.UC_X86_REG_RDX, len(encrypted))
  mu.reg_write(x86.UC_X86_REG_RCX, key)

  # hook invalid memory to stop cleanly at CALL imports
  def hook_mem(uc, access, addr, size, val, user):
      uc.emu_stop()
      return True
  mu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, hook_mem)

  try:
      mu.emu_start(DECODER_VA, DECODER_VA + len(code), timeout=2_000_000, count=5000)
  except unicorn.UcError:
      pass

  result = bytes(mu.mem_read(HEAP_BASE + 0x1000, len(encrypted)))
  print('decrypted:', result)
  try: print('as string:', result.decode('utf-8', errors='replace'))
  except: pass

### Other uses

- ELF analysis: `pyelftools` — `ELFFile`, `SymbolTableSection`, DWARF sections
- CTF/pwn: `pwntools` — never call `p.interactive()` (stdin is /dev/null, it blocks). \
  Use `p.recv(timeout=5)` or `p.recvall(timeout=5)` instead.
- Symbolic execution: `angr` — prefer the built-in `angr_find` tool for simple reachability; \
  use `run_python` directly only when you need custom SimulationManager control.
- Any math on binary data: checksums, hash verification, format brute-force

## Decompilation conventions

The built-in pcode decompiler outputs pseudo-C with these naming conventions:

- **`arg_1`, `arg_2`, …** — function parameters in ABI order (rdi, rsi, rdx, rcx, r8, r9 \
  on x86-64). Rename them via `batch_annotate` params[] or `set_param_name`.
- **`local_XX`** — stack-allocated local variables. The suffix is the hex stack offset (e.g. \
  `local_18` = `[rbp-0x18]`). Rename with `batch_annotate` variables[] or `rename_variable`.
- **`DAT_XXXXXXXX`** — a global/static variable or data label at that virtual address. \
  Rename it with `rename_function` (the same rename table covers data labels too).
- **`FUN_XXXXXXXX`** — an unresolved call target. If `load_project` or `list_functions` \
  shows a name for that address, calling `decompile` again after renaming will show it. \
  Run `identify_library_functions` to name common libc functions automatically.
- **`phi(x, y)`** — SSA φ-function: the variable holds either `x` or `y` depending on \
  which predecessor basic block was taken. It does not represent an actual function call.
- **`int32_t`, `int64_t` widths** — inferred from instruction widths; treat them as hints, \
  not ground truth. Signed/unsigned is often ambiguous — use context (comparisons, shifts) \
  to decide.

**Annotation workflow after decompiling a function:**
1. Identify parameters, locals, and called functions from pseudo-C.
2. Call `batch_annotate` with function_name, return_type, params[], variables[] all at once.
3. Call `decompile` again to confirm the renamed output is readable.
4. Call `set_vuln_score` to record your confidence in its safety.

## AArch64 PE deep vulnerability analysis

When `file_info` reports Machine=AArch64 (0xAA64) and the binary is a PE, run this \
**dedicated deep-analysis sequence** after the standard hardening audit:

1. **`stack_bof_candidates(path)`** — ranks functions by frame size, flagging those without \
   pointer-authentication (`pacibsp`/`paciasp`) or an MSVC `__security_cookie` guard. \
   Investigate the top results with `decompile` + `function_context`.
2. **`writable_iat_hijack_surface(path)`** — finds IAT slots in writable sections (.rdata / \
   .fptable with IMAGE_SCN_MEM_WRITE set) and lists every ADRP+LDR+BLR call site that loads \
   through each slot. Writable IAT = overwritable without VirtualProtect; highest-call-count \
   imports are the highest-impact hijack targets.
3. **`find_injection_chains(path)`** — locates functions that call \
   VirtualAllocEx + WriteProcessMemory/NtWriteVirtualMemory + \
   CreateRemoteThread/NtCreateThreadEx/QueueUserAPC in combination. \
   These are process-injection primitives; document each finding with `add_note`.

After running all three, correlate findings: a function in `stack_bof_candidates` that also \
calls through a writable IAT slot is a combined exploit primitive worth scoring 9–10.

## What the analyst sees

Renames appear inline in disassembly and decompile output. Comments appear as `; comment` \
annotations. Vuln scores appear as `[!]`/`[!!]` badges in the Functions panel. Notes appear \
in the dedicated Notes tab. Everything persists across sessions in a per-binary SQLite database.";

static LOADED_SYSTEM_PROMPT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Load the system prompt from `~/.kaiju/system_prompt.md` if it exists,
/// otherwise fall back to the built-in constant.
fn load_system_prompt() -> &'static str {
    LOADED_SYSTEM_PROMPT.get_or_init(|| {
        if let Some(home) = std::env::var_os("HOME") {
            let path = std::path::Path::new(&home).join(".kaiju").join("system_prompt.md");
            if let Ok(content) = std::fs::read_to_string(&path) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
        SYSTEM_PROMPT.to_string()
    })
}

// ─── Agent ───────────────────────────────────────────────────────────────────

pub struct Agent {
    backend: Box<dyn LlmBackend>,
    tools: Vec<crate::llm::ToolDefinition>,
    history: Vec<LlmMessage>,
    event_tx: Option<mpsc::UnboundedSender<AgentEvent>>,
    /// When set, the agent checks this flag between tool calls.
    /// If `true`, the current turn is cancelled and `AgentEvent::Cancelled` is emitted.
    cancel_token: Option<Arc<AtomicBool>>,
    /// Whether the most recent LLM response was delivered via streaming chunks.
    /// Used to avoid double-displaying text when the backend doesn't stream.
    last_response_streamed: bool,
}

impl Agent {
    pub fn new(backend: Box<dyn LlmBackend>) -> Self {
        Agent {
            tools: tools::all_definitions(),
            backend,
            history: Vec::new(),
            event_tx: None,
            cancel_token: None,
            last_response_streamed: false,
        }
    }

    /// Attach a cancellation token.  Set the bool to `true` from the TUI to
    /// interrupt the current agent turn between tool calls.
    pub fn with_cancel_token(mut self, token: Arc<AtomicBool>) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Returns true if the user has requested cancellation.
    fn is_cancelled(&self) -> bool {
        self.cancel_token
            .as_ref()
            .map_or(false, |t| t.load(Ordering::Relaxed))
    }

    /// Reset the cancellation flag so the next turn starts fresh.
    fn clear_cancel(&self) {
        if let Some(t) = &self.cancel_token {
            t.store(false, Ordering::Relaxed);
        }
    }

    /// Collect all tool results and assistant text from history as structured JSON.
    /// Intended for `--output-json` one-shot mode.
    pub fn structured_output(&self, binary_path: &str) -> serde_json::Value {
        use crate::llm::MessageContent;
        use serde_json::{json, Value};

        let mut tool_results: std::collections::HashMap<String, Vec<Value>> =
            std::collections::HashMap::new();
        let mut conversation: Vec<Value> = Vec::new();

        for msg in &self.history {
            let role = match msg.role {
                crate::llm::MessageRole::User      => "user",
                crate::llm::MessageRole::Assistant => "assistant",
            };
            for content in &msg.content {
                match content {
                    MessageContent::Text(t) if !t.trim().is_empty() => {
                        conversation.push(json!({"role": role, "text": t}));
                    }
                    MessageContent::ToolCall(tc) => {
                        conversation.push(json!({
                            "role":    "tool_call",
                            "name":    tc.name,
                            "args":    tc.args,
                        }));
                    }
                    MessageContent::ToolResult(tr) => {
                        conversation.push(json!({
                            "role":   "tool_result",
                            "name":   tr.name,
                            "output": tr.content,
                        }));
                        tool_results
                            .entry(tr.name.clone())
                            .or_default()
                            .push(json!(tr.content));
                    }
                    _ => {}
                }
            }
        }

        // Final assistant text = last non-empty text from an assistant message
        let summary = self.history.iter().rev()
            .flat_map(|m| m.texts())
            .find(|t| !t.trim().is_empty())
            .map(|t| t.to_string());

        json!({
            "binary":       binary_path,
            "backend":      self.backend.display_name(),
            "tool_results": tool_results,
            "summary":      summary,
            "conversation": conversation,
        })
    }

    /// Attach a TUI event channel.  When set the agent emits `AgentEvent`s
    /// instead of calling `ui::print_*` functions.
    pub fn with_events(mut self, tx: mpsc::UnboundedSender<AgentEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    fn emit(&self, event: AgentEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    fn tui_mode(&self) -> bool {
        self.event_tx.is_some()
    }

    /// Run one user turn through the agentic loop.
    pub async fn run(&mut self, user_input: &str) -> Result<()> {
        self.clear_cancel();
        self.history.push(LlmMessage::user_text(user_input));
        let mut tool_step = 0usize;

        loop {
            // ── Trim history to stay within context budget ──────────────────
            trim_history(&mut self.history);

            // ── Snapshot the context window for the Context tab ─────────────
            self.emit(AgentEvent::ContextUpdate(snapshot_context(&self.history)));

            // ── Call the LLM ────────────────────────────────────────────────
            self.emit(AgentEvent::Thinking);
            let spinner = if !self.tui_mode() {
                Some(ui::new_spinner("Thinking…"))
            } else {
                None
            };

            let result = if self.tui_mode() {
                // In TUI mode: use streaming so text chunks appear incrementally.
                // The default generate_streaming just calls generate() with no chunks.
                // Real streaming backends will send chunks through chunk_tx.
                let (chunk_tx, chunk_rx) =
                    tokio::sync::mpsc::unbounded_channel::<String>();
                let backend_ref = self.backend.as_ref();
                let system = load_system_prompt();
                let event_tx_clone = self.event_tx.clone();

                // Track whether the backend actually sent any streaming chunks.
                let had_chunks = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let had_chunks_fwd = had_chunks.clone();

                // Spawn a task to forward chunks to the TUI
                let forward_task = tokio::spawn(async move {
                    let mut rx = chunk_rx;
                    while let Some(chunk) = rx.recv().await {
                        had_chunks_fwd.store(true, Ordering::Relaxed);
                        if let Some(tx) = &event_tx_clone {
                            let _ = tx.send(AgentEvent::LlmTextChunk(chunk));
                        }
                    }
                });

                // Run the streaming call (drops chunk_tx when it returns, closing the channel)
                let stream_result = backend_ref.generate_streaming(
                    system, &self.history, &self.tools, &chunk_tx
                ).await;
                drop(chunk_tx); // ensure receiver loop terminates

                // Wait for forward task to drain any buffered chunks
                let _ = forward_task.await;

                // Store whether streaming actually produced any chunks.
                self.last_response_streamed = had_chunks.load(Ordering::Relaxed);

                stream_result
            } else {
                self.backend
                    .generate(load_system_prompt(), &self.history, &self.tools)
                    .await
            };

            if let Some(s) = spinner {
                s.finish_and_clear();
            }

            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("API error: {}", e);
                    self.emit(AgentEvent::Error(msg.clone()));
                    if !self.tui_mode() {
                        ui::print_error(&msg);
                    }
                    self.history.pop(); // let the user retry
                    return Ok(());
                }
            };

            // ── Emit / print any inline text ────────────────────────────────
            // In TUI mode, prefer streaming chunks (LlmTextChunk).
            // If the backend doesn't implement streaming (no chunks were sent),
            // fall back to emitting a single LlmText event so the response is
            // never silently dropped.
            for text in response.texts() {
                if !text.trim().is_empty() {
                    if self.tui_mode() {
                        if !self.last_response_streamed {
                            self.emit(AgentEvent::LlmText(text.to_string()));
                        }
                        // else: already displayed incrementally via LlmTextChunk
                    } else {
                        ui::print_agent_response(text);
                    }
                }
            }

            let has_text = response.texts().iter().any(|t| !t.trim().is_empty());
            let tool_calls = response.tool_calls().into_iter().cloned().collect::<Vec<_>>();
            self.history.push(response);

            if tool_calls.is_empty() {
                // If the LLM returned neither text nor tool calls the response was
                // silently empty (e.g. content filtered).  Surface it so the user
                // isn't left staring at a "Thinking…" spinner that never clears.
                if !has_text && !self.last_response_streamed {
                    self.emit(AgentEvent::Error(
                        "The model returned an empty response — the request may have been \
                         blocked by a content filter. Try rephrasing."
                            .to_string(),
                    ));
                } else {
                    self.emit(AgentEvent::Done);
                }
                break;
            }

            // ── Execute tool calls ──────────────────────────────────────────
            let total_calls = tool_calls.len();
            let mut results: Vec<ToolResult> = Vec::new();
            for tc in &tool_calls {
                // Check for cancellation before each tool call
                if self.is_cancelled() {
                    self.emit(AgentEvent::Cancelled);
                    self.history.pop(); // remove the assistant message with tool calls
                    return Ok(());
                }

                tool_step += 1;
                let display = args_display(&tc.args);

                // Emit a Focus event so the TUI can highlight the address
                if let Some(vaddr) = extract_focus_vaddr(&tc.name, &tc.args) {
                    self.emit(AgentEvent::Focus { vaddr, tool: tc.name.clone() });
                }

                if self.tui_mode() {
                    self.emit(AgentEvent::Progress {
                        step:  tool_step,
                        total: total_calls,
                        label: format!("{}({})", tc.name, display),
                    });
                    self.emit(AgentEvent::ToolCall {
                        name: tc.name.clone(),
                        display_args: display.clone(),
                    });
                } else {
                    ui::print_tool_call(&tc.name, &display);
                }

                let tool_out = tools::dispatch(&tc.name, &tc.args);

                if self.tui_mode() {
                    self.emit(AgentEvent::ToolResult {
                        name: tc.name.clone(),
                        output: tool_out.output.clone(),
                    });
                } else {
                    ui::print_tool_output(&tool_out.output);
                }

                // After write tools, reload the project and broadcast updated state to TUI
                if tc.name == "set_vuln_score" {
                    if let Some(path) = tc.args["path"].as_str() {
                        let p = crate::project::Project::load_for(path);
                        self.emit(AgentEvent::VulnScores(p.vuln_scores.clone()));
                    }
                }
                if tc.name == "add_note" || tc.name == "delete_note" {
                    if let Some(path) = tc.args["path"].as_str() {
                        let p = crate::project::Project::load_for(path);
                        self.emit(AgentEvent::NotesUpdate(p.notes.clone()));
                    }
                }

                results.push(ToolResult {
                    call_id: tc.id.clone(),
                    name: tc.name.clone(),
                    content: tool_out.output,
                });
            }

            self.history.push(LlmMessage::tool_results(results));
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn pop_last_user_message(&mut self) -> Option<String> {
        if let Some(pos) = self.history.iter().rposition(|m| m.role == crate::llm::MessageRole::User) {
            let msg = self.history.remove(pos);
            msg.texts().first().map(|s| s.to_string())
        } else {
            None
        }
    }

    // ─── Session persistence ─────────────────────────────────────────────────

    /// Persist the current conversation history to `~/.kaiju/sessions/<slug>.json`.
    /// The slug is derived from the binary path so each binary has its own file.
    pub fn save_session(&self, binary_path: &str) -> anyhow::Result<()> {
        let path = session_path(binary_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.history)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Restore a previously saved conversation history from disk.
    /// Returns `true` if a session was loaded, `false` if none existed.
    pub fn load_session(&mut self, binary_path: &str) -> anyhow::Result<bool> {
        let path = session_path(binary_path)?;
        if !path.exists() {
            return Ok(false);
        }
        let raw = std::fs::read_to_string(&path)?;
        let history: Vec<LlmMessage> = serde_json::from_str(&raw)?;
        self.history = history;
        Ok(true)
    }

    /// True if a saved session exists for `binary_path`.
    pub fn has_session(binary_path: &str) -> bool {
        session_path(binary_path).map(|p| p.exists()).unwrap_or(false)
    }
}

fn session_path(binary_path: &str) -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let sessions_dir = std::path::PathBuf::from(home).join(".kaiju").join("sessions");
    // Derive a safe filename from the binary path
    let slug: String = binary_path
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let slug = if slug.len() > 120 { slug[slug.len() - 120..].to_string() } else { slug };
    Ok(sessions_dir.join(format!("{}.session.json", slug)))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmMessage, ToolResult};

    fn big_tool_result(chars: usize) -> LlmMessage {
        LlmMessage::tool_results(vec![ToolResult {
            call_id: "id".to_string(),
            name: "tool".to_string(),
            content: "x".repeat(chars),
        }])
    }

    fn user_msg(s: &str) -> LlmMessage {
        LlmMessage::user_text(s)
    }

    #[test]
    fn trim_does_nothing_when_under_budget() {
        let mut history = vec![
            user_msg("hello"),
            big_tool_result(100),
        ];
        let before = history.len();
        trim_history(&mut history);
        assert_eq!(history.len(), before, "nothing should be trimmed");
    }

    #[test]
    fn trim_drops_oldest_tool_result_first() {
        // Two tool results, combined > MAX_HISTORY_CHARS
        let big = MAX_HISTORY_CHARS / 2 + 1000;
        let mut history = vec![
            user_msg("task"),
            big_tool_result(big),   // oldest tool result
            big_tool_result(big),   // newer tool result
        ];
        trim_history(&mut history);
        // At least one tool result should have been removed
        let remaining_tool_results = history
            .iter()
            .filter(|m| m.is_tool_result_message())
            .count();
        assert!(remaining_tool_results < 2, "should have dropped at least one tool result");
    }

    #[test]
    fn trim_never_drops_user_text() {
        let big = MAX_HISTORY_CHARS / 2 + 1000;
        let mut history = vec![
            user_msg("important context"),
            user_msg("more context"),
            big_tool_result(big),
            big_tool_result(big),
        ];
        trim_history(&mut history);
        // Both user messages must survive
        let user_texts: Vec<_> = history
            .iter()
            .flat_map(|m| m.texts())
            .collect();
        assert!(user_texts.contains(&"important context"));
        assert!(user_texts.contains(&"more context"));
    }

    #[test]
    fn trim_stops_when_under_budget() {
        // The huge result is oldest; once it's dropped the budget is satisfied
        // and the small result (newer) should survive.
        let mut history = vec![
            user_msg("q"),
            big_tool_result(MAX_HISTORY_CHARS + 1000), // huge — oldest, dropped first
            big_tool_result(100),                      // small — newer, survives
        ];
        trim_history(&mut history);
        assert!(
            history.iter().any(|m| m.is_tool_result_message()),
            "the small (newer) tool result should survive after the huge one is dropped"
        );
    }

    #[test]
    fn trim_handles_empty_history() {
        let mut history: Vec<LlmMessage> = vec![];
        trim_history(&mut history); // must not panic
        assert!(history.is_empty());
    }

    // ── extract_focus_vaddr ──────────────────────────────────────────────────

    #[test]
    fn focus_vaddr_from_disassemble() {
        let args = serde_json::json!({"path": "/bin/foo", "vaddr": 0x401000_u64});
        assert_eq!(extract_focus_vaddr("disassemble", &args), Some(0x401000));
    }

    #[test]
    fn focus_vaddr_from_fn_vaddr() {
        let args = serde_json::json!({"path": "/bin/foo", "fn_vaddr": 0x402000_u64});
        assert_eq!(extract_focus_vaddr("rename_function", &args), Some(0x402000));
    }

    #[test]
    fn focus_vaddr_unrelated_tool_returns_none() {
        let args = serde_json::json!({"path": "/bin/foo"});
        assert_eq!(extract_focus_vaddr("file_info", &args), None);
        assert_eq!(extract_focus_vaddr("strings_extract", &args), None);
    }

    #[test]
    fn focus_vaddr_missing_field_returns_none() {
        let args = serde_json::json!({"path": "/bin/foo"});
        assert_eq!(extract_focus_vaddr("disassemble", &args), None);
    }

    // ── truncate_preview ─────────────────────────────────────────────────────

    #[test]
    fn truncate_preview_short_string() {
        assert_eq!(truncate_preview("hello", 100), "hello");
    }

    #[test]
    fn truncate_preview_exact_boundary() {
        let s = "a".repeat(100);
        assert_eq!(truncate_preview(&s, 100), s);
    }

    #[test]
    fn truncate_preview_long_string() {
        let s = "a".repeat(150);
        let result = truncate_preview(&s, 100);
        assert!(result.ends_with('…'));
        // The non-ellipsis part should be 100 chars
        assert!(result.len() > 100);
    }

    #[test]
    fn truncate_preview_trims_whitespace() {
        assert_eq!(truncate_preview("  hello  ", 100), "hello");
    }

    // ── args_display ─────────────────────────────────────────────────────────

    #[test]
    fn args_display_simple_string() {
        let args = serde_json::json!({"path": "/bin/foo"});
        let d = args_display(&args);
        assert!(d.contains("path"), "should contain key");
        assert!(d.contains("/bin/foo"), "should contain value");
    }

    #[test]
    fn args_display_long_string_truncated() {
        let long_val = "x".repeat(100);
        let args = serde_json::json!({"key": long_val});
        let d = args_display(&args);
        assert!(d.contains('…'), "long string should be truncated with ellipsis");
    }

    #[test]
    fn args_display_numeric_value() {
        let args = serde_json::json!({"vaddr": 0x401000_u64});
        let d = args_display(&args);
        assert!(d.contains("vaddr"), "should contain key");
    }

    #[test]
    fn args_display_non_object() {
        let args = serde_json::json!("bare string");
        let d = args_display(&args);
        assert_eq!(d, "\"bare string\"");
    }

    // ── snapshot_context ─────────────────────────────────────────────────────

    #[test]
    fn snapshot_context_empty_history() {
        let entries = snapshot_context(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn snapshot_context_text_entry() {
        let history = vec![LlmMessage::user_text("analyze this")];
        let entries = snapshot_context(&history);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].role, "user");
        assert_eq!(entries[0].kind, "text");
        assert!(entries[0].tool_name.is_none());
        assert_eq!(entries[0].char_count, "analyze this".len());
    }

    #[test]
    fn snapshot_context_tool_call_entry() {
        use crate::llm::{MessageRole, MessageContent, ToolCall};
        let msg = LlmMessage {
            role: MessageRole::Assistant,
            content: vec![MessageContent::ToolCall(ToolCall {
                id: "id1".to_string(),
                name: "file_info".to_string(),
                args: serde_json::json!({"path": "/bin/ls"}),
            })],
        };
        let entries = snapshot_context(&[msg]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "tool_call");
        assert_eq!(entries[0].tool_name.as_deref(), Some("file_info"));
    }

    #[test]
    fn snapshot_context_tool_result_entry() {
        use crate::llm::{ToolResult};
        let msg = LlmMessage::tool_results(vec![ToolResult {
            call_id: "id1".to_string(),
            name: "hexdump".to_string(),
            content: "deadbeef".to_string(),
        }]);
        let entries = snapshot_context(&[msg]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "tool_result");
        assert_eq!(entries[0].tool_name.as_deref(), Some("hexdump"));
        assert_eq!(entries[0].char_count, "deadbeef".len());
    }

    // ── summarize_tool_result_msg ─────────────────────────────────────────────

    #[test]
    fn summarize_contains_tool_name() {
        use crate::llm::ToolResult;
        let msg = LlmMessage::tool_results(vec![ToolResult {
            call_id: "id".to_string(),
            name: "disassemble".to_string(),
            content: "push rbp\nmov rbp, rsp\nret".to_string(),
        }]);
        let s = summarize_tool_result_msg(&msg);
        assert!(s.contains("disassemble"), "should mention tool name");
        assert!(s.contains("context-compressed"), "should be marked compressed");
    }

    #[test]
    fn summarize_includes_line_count() {
        use crate::llm::ToolResult;
        let content = (1..=10).map(|i| format!("line {}", i)).collect::<Vec<_>>().join("\n");
        let msg = LlmMessage::tool_results(vec![ToolResult {
            call_id: "id".to_string(),
            name: "mytool".to_string(),
            content,
        }]);
        let s = summarize_tool_result_msg(&msg);
        assert!(s.contains("10 lines"), "should include line count: {}", s);
    }

    #[test]
    fn summarize_non_tool_result_returns_empty() {
        let msg = LlmMessage::user_text("hello");
        let s = summarize_tool_result_msg(&msg);
        assert!(s.is_empty(), "non-tool-result message should produce empty summary");
    }

    // ── session_path ─────────────────────────────────────────────────────────

    #[test]
    fn session_path_produces_valid_path() {
        let p = session_path("/tmp/my_binary").unwrap();
        let s = p.to_str().unwrap();
        assert!(s.contains(".kaiju"), "should be under .kaiju dir: {}", s);
        assert!(s.ends_with(".session.json"), "should end with .session.json: {}", s);
        assert!(s.contains("_tmp_my_binary"), "slug should encode path: {}", s);
    }

    #[test]
    fn session_path_slug_truncated_for_long_names() {
        let long_path = format!("/tmp/{}", "a".repeat(200));
        let p = session_path(&long_path).unwrap();
        let filename = p.file_name().unwrap().to_str().unwrap();
        // Slug is capped at 120 chars + ".session.json"
        assert!(filename.len() <= 135, "filename too long: {} chars", filename.len());
    }

    // ── pop_last_user_message ─────────────────────────────────────────────────

    struct MockBackend;

    #[async_trait::async_trait]
    impl crate::llm::LlmBackend for MockBackend {
        async fn generate(
            &self,
            _system: &str,
            _history: &[crate::llm::LlmMessage],
            _tools: &[crate::llm::ToolDefinition],
        ) -> anyhow::Result<crate::llm::LlmMessage> {
            Ok(crate::llm::LlmMessage::user_text("mock"))
        }
        fn display_name(&self) -> String { "mock".to_string() }
    }

    fn make_agent() -> Agent {
        Agent::new(Box::new(MockBackend))
    }

    #[test]
    fn pop_last_user_message_returns_text() {
        let mut agent = make_agent();
        agent.history.push(LlmMessage::user_text("first"));
        agent.history.push(LlmMessage::user_text("second"));
        let popped = agent.pop_last_user_message();
        assert_eq!(popped.as_deref(), Some("second"));
        assert_eq!(agent.history.len(), 1, "only one message should remain");
    }

    #[test]
    fn pop_last_user_message_empty_history_returns_none() {
        let mut agent = make_agent();
        assert!(agent.pop_last_user_message().is_none());
    }

    #[test]
    fn pop_last_user_message_skips_non_user_messages() {
        use crate::llm::{MessageRole, MessageContent, ToolCall};
        let mut agent = make_agent();
        agent.history.push(LlmMessage::user_text("my question"));
        // Push an assistant message (tool call)
        agent.history.push(LlmMessage {
            role: MessageRole::Assistant,
            content: vec![MessageContent::ToolCall(ToolCall {
                id: "id".to_string(),
                name: "file_info".to_string(),
                args: serde_json::json!({}),
            })],
        });
        let popped = agent.pop_last_user_message();
        assert_eq!(popped.as_deref(), Some("my question"));
        // The assistant message should remain
        assert_eq!(agent.history.len(), 1);
        assert_eq!(agent.history[0].role, MessageRole::Assistant);
    }

    // ── save/load session ─────────────────────────────────────────────────────

    #[test]
    fn save_load_session_roundtrip() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        let fake_binary = format!("/tmp/kaijulab_test_session_{}.bin", ts);

        let mut agent = make_agent();
        agent.history.push(LlmMessage::user_text("hello session"));
        agent.save_session(&fake_binary).unwrap();

        assert!(Agent::has_session(&fake_binary), "session should exist after save");

        let mut agent2 = make_agent();
        let loaded = agent2.load_session(&fake_binary).unwrap();
        assert!(loaded, "should report session was loaded");
        assert_eq!(agent2.history.len(), 1);
        let texts: Vec<_> = agent2.history[0].texts().to_vec();
        assert_eq!(texts, vec!["hello session"]);

        // Cleanup
        let path = session_path(&fake_binary).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_session_nonexistent_returns_false() {
        let mut agent = make_agent();
        let result = agent.load_session("/no/such/binary/ever.bin").unwrap();
        assert!(!result);
    }

    #[test]
    fn has_session_returns_false_for_missing() {
        assert!(!Agent::has_session("/no/such/binary/ever.bin"));
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a virtual address from tool arguments, if the tool operates on one.
/// Used to drive the Focus event for active highlighting in the TUI.
fn extract_focus_vaddr(tool: &str, args: &serde_json::Value) -> Option<u64> {
    match tool {
        "disassemble" | "decompile" | "xrefs_to" | "cfg_view" | "explain_function"
        | "rename_function" | "rename_variable"
        | "set_return_type" | "set_param_type" | "set_param_name" | "set_vuln_score" => {
            args["vaddr"].as_u64().or_else(|| args["fn_vaddr"].as_u64())
        }
        _ => None,
    }
}

/// Build a lightweight snapshot of the current history for the Context tab.
fn snapshot_context(history: &[crate::llm::LlmMessage]) -> Vec<ContextEntry> {
    use crate::llm::MessageContent;

    let mut entries = Vec::new();
    for msg in history {
        let role = match msg.role {
            crate::llm::MessageRole::User      => "user",
            crate::llm::MessageRole::Assistant => "assistant",
        };
        for content in &msg.content {
            let entry = match content {
                MessageContent::Text(t) => ContextEntry {
                    role,
                    kind: "text",
                    tool_name: None,
                    char_count: t.len(),
                    preview: truncate_preview(t, 100),
                },
                MessageContent::ToolCall(tc) => ContextEntry {
                    role,
                    kind: "tool_call",
                    tool_name: Some(tc.name.clone()),
                    char_count: tc.args.to_string().len(),
                    preview: truncate_preview(&tc.args.to_string(), 100),
                },
                MessageContent::ToolResult(tr) => ContextEntry {
                    role,
                    kind: "tool_result",
                    tool_name: Some(tr.name.clone()),
                    char_count: tr.content.len(),
                    preview: truncate_preview(&tr.content, 100),
                },
            };
            entries.push(entry);
        }
    }
    entries
}

fn truncate_preview(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() <= max {
        s.to_string()
    } else {
        // Floor to the nearest char boundary so we never slice inside a multi-byte char.
        let boundary = s.char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max)
            .last()
            .unwrap_or(0);
        format!("{}…", &s[..boundary])
    }
}

fn args_display(args: &serde_json::Value) -> String {
    match args.as_object() {
        None => args.to_string(),
        Some(map) => map
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => {
                    let s = if s.len() > 50 {
                        let b = s.char_indices()
                            .map(|(i, _)| i)
                            .take_while(|&i| i <= 50)
                            .last()
                            .unwrap_or(0);
                        format!("{}…", &s[..b])
                    } else {
                        s.clone()
                    };
                    format!("{}=\"{}\"", k, s)
                }
                _ => format!("{}={}", k, v),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}
