use anyhow::Result;

use crate::llm::{Content, FunctionCallPart, FunctionResponsePart, GeminiClient, Part};
use crate::tools;
use crate::ui;

// ─── Agent ───────────────────────────────────────────────────────────────────

pub struct Agent {
    client: GeminiClient,
    tools: Vec<tools::FunctionDeclaration>,
    /// Conversation history sent to the API on every turn
    history: Vec<Content>,
}

impl Agent {
    pub fn new(client: GeminiClient) -> Self {
        Agent {
            tools: tools::all_declarations(),
            client,
            history: Vec::new(),
        }
    }

    /// Run one user turn through the agentic loop.
    pub async fn run(&mut self, user_input: &str) -> Result<()> {
        // Append the user message
        self.history.push(Content {
            role: "user".to_string(),
            parts: vec![Part::Text {
                text: user_input.to_string(),
            }],
        });

        // Agentic loop: keep calling Gemini until it returns a plain text response
        loop {
            let spinner = ui::new_spinner("Gemini is thinking…");
            let candidate = self
                .client
                .generate(&self.history, &self.tools)
                .await;
            spinner.finish_and_clear();

            let candidate = match candidate {
                Ok(c) => c,
                Err(e) => {
                    ui::print_error(&format!("API error: {}", e));
                    // Remove the user message we just added so the user can retry
                    self.history.pop();
                    return Ok(());
                }
            };

            // Surface any stop-reason warnings (SAFETY, etc.)
            if let Some(reason) = &candidate.finish_reason {
                if reason != "STOP" && reason != "MAX_TOKENS" && reason != "TOOL_CODE_EXECUTION" {
                    ui::print_error(&format!("Gemini finish_reason: {}", reason));
                }
            }

            // Collect function calls and text parts from this response
            let mut function_calls: Vec<FunctionCallPart> = Vec::new();
            let mut text_parts: Vec<String> = Vec::new();

            for part in &candidate.content.parts {
                match part {
                    Part::FunctionCall { function_call } => {
                        function_calls.push(function_call.clone());
                    }
                    Part::Text { text } => {
                        text_parts.push(text.clone());
                    }
                    Part::FunctionResponse { .. } | Part::Unknown(_) => {}
                }
            }

            // Print any inline text (can accompany function calls in some models)
            for text in &text_parts {
                if !text.trim().is_empty() {
                    ui::print_agent_response(text);
                }
            }

            // Add the model turn to history
            self.history.push(candidate.content.clone());

            // If no function calls → final response, we're done
            if function_calls.is_empty() {
                break;
            }

            // Execute each function call, collect results
            let mut result_parts: Vec<Part> = Vec::new();
            for fc in function_calls {
                let display = args_display(&fc.args);
                ui::print_tool_call(&fc.name, &display);

                let result = tools::dispatch(&fc.name, &fc.args);
                ui::print_tool_output(&result.display);

                result_parts.push(Part::FunctionResponse {
                    function_response: FunctionResponsePart {
                        name: fc.name.clone(),
                        response: result.json,
                    },
                });
            }

            // Feed results back as a "user" turn (Gemini's function-response protocol)
            self.history.push(Content {
                role: "user".to_string(),
                parts: result_parts,
            });
        }

        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Format JSON args compactly for display, e.g.: path="/bin/ls", offset=0
fn args_display(args: &serde_json::Value) -> String {
    match args.as_object() {
        None => args.to_string(),
        Some(map) => map
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => {
                    let s = if s.len() > 50 {
                        format!("{}…", &s[..50])
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
