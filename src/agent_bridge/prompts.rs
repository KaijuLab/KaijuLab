//! Schema-bound prompt templates for the three permitted bridge jobs.

use serde::{Deserialize, Serialize};

use super::scope::ContextPack;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageOutput {
    pub severity: String,
    pub rationale: String,
    pub suggested_name: Option<String>,
    pub suggested_comments: Vec<SuggestedComment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedComment {
    pub vaddr: String,
    pub text: String,
}

pub fn triage_prompt(pack: &ContextPack) -> String {
    format!(
        "You are triaging a single function for vulnerability risk.\n\
         Workspace: {}\n\
         Target: {:?}\n\
         Annotations: {}\n\
         Output JSON matching:\n\
         {{\"severity\":\"info|low|med|high|critical\",\
            \"rationale\":\"...\",\
            \"suggested_name\":\"...\"|null,\
            \"suggested_comments\":[{{\"vaddr\":\"0x...\",\"text\":\"...\"}}]}}\n",
        pack.workspace_summary,
        pack.target,
        serde_json::to_string_pretty(&pack.annotations).unwrap_or_default()
    )
}

pub fn report_section_prompt(pack: &ContextPack) -> String {
    format!(
        "Produce a markdown report section for the following target.\n\
         Workspace: {}\n\
         Target: {:?}\n\
         Annotations: {}\n\
         Output: markdown only, no preamble.",
        pack.workspace_summary,
        pack.target,
        serde_json::to_string_pretty(&pack.annotations).unwrap_or_default()
    )
}

pub fn yara_prompt(pack: &ContextPack) -> String {
    format!(
        "Draft a YARA rule for the following target.\n\
         Workspace: {}\n\
         Target: {:?}\n\
         Output JSON: {{\"rule_text\":\"...\",\"false_positive_risks\":[\"...\"]}}",
        pack.workspace_summary, pack.target
    )
}
