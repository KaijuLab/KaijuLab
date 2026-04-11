use anyhow::Result;

use crate::llm::{LlmBackend, LlmMessage, ToolResult};
use crate::tools;
use crate::ui;

const SYSTEM_PROMPT: &str = "\
You are KaijuLab, an expert reverse-engineering assistant. \
You analyse binary files using the tools available to you. \
Start with file_info to understand the file format, then use other tools \
to dig deeper as needed. Be precise, technical, and explain your reasoning \
step by step. When you encounter addresses or offsets, prefer the \
disassemble tool to verify what the code actually does.";

// ─── Agent ───────────────────────────────────────────────────────────────────

pub struct Agent {
    backend: Box<dyn LlmBackend>,
    tools: Vec<crate::llm::ToolDefinition>,
    history: Vec<LlmMessage>,
}

impl Agent {
    pub fn new(backend: Box<dyn LlmBackend>) -> Self {
        Agent {
            tools: tools::all_definitions(),
            backend,
            history: Vec::new(),
        }
    }

    /// Run one user turn through the agentic loop.
    pub async fn run(&mut self, user_input: &str) -> Result<()> {
        self.history.push(LlmMessage::user_text(user_input));

        loop {
            let spinner = ui::new_spinner("Thinking…");
            let result = self.backend.generate(SYSTEM_PROMPT, &self.history, &self.tools).await;
            spinner.finish_and_clear();

            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    ui::print_error(&format!("API error: {}", e));
                    self.history.pop(); // let the user retry
                    return Ok(());
                }
            };

            // Print any inline text the model may have emitted alongside tool calls
            for text in response.texts() {
                if !text.trim().is_empty() {
                    ui::print_agent_response(text);
                }
            }

            let tool_calls = response.tool_calls().into_iter().cloned().collect::<Vec<_>>();

            // Append the assistant turn to history before executing tools
            self.history.push(response);

            if tool_calls.is_empty() {
                break; // final text response — we're done
            }

            // Execute each tool call and collect results
            let mut results: Vec<ToolResult> = Vec::new();
            for tc in &tool_calls {
                let display = args_display(&tc.args);
                ui::print_tool_call(&tc.name, &display);

                let tool_out = tools::dispatch(&tc.name, &tc.args);
                ui::print_tool_output(&tool_out.output);

                results.push(ToolResult {
                    call_id: tc.id.clone(),
                    name: tc.name.clone(),
                    content: tool_out.output,
                });
            }

            // Feed results back as the next user message
            self.history.push(LlmMessage::tool_results(results));
        }

        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn args_display(args: &serde_json::Value) -> String {
    match args.as_object() {
        None => args.to_string(),
        Some(map) => map
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => {
                    let s = if s.len() > 50 { format!("{}…", &s[..50]) } else { s.clone() };
                    format!("{}=\"{}\"", k, s)
                }
                _ => format!("{}={}", k, v),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}
