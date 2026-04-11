use anyhow::{Context, Result};
use std::path::PathBuf;

// ─── Backend selection ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BackendKind {
    None,
    Gemini,
    OpenAi,
    Anthropic,
    Ollama,
}

impl std::str::FromStr for BackendKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" | "manual" | "" => Ok(BackendKind::None),
            "gemini" => Ok(BackendKind::Gemini),
            "openai" => Ok(BackendKind::OpenAi),
            "anthropic" => Ok(BackendKind::Anthropic),
            "ollama" => Ok(BackendKind::Ollama),
            other => anyhow::bail!(
                "Unknown backend '{}'. Valid options: none, gemini, openai, anthropic, ollama",
                other
            ),
        }
    }
}

// ─── Per-backend configuration ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum BackendConfig {
    None,
    Gemini {
        credentials_path: PathBuf,
        project_id: String,
        location: String,
        model_id: String,
    },
    OpenAi {
        api_key: String,
        base_url: String,
        model_id: String,
    },
    Anthropic {
        api_key: String,
        model_id: String,
    },
    Ollama {
        base_url: String,
        model_id: String,
    },
}

impl BackendConfig {
    /// Build a `BackendConfig` from env vars, with optional CLI overrides.
    pub fn load(
        kind: BackendKind,
        // Shared
        model_override: Option<String>,
        // Gemini
        credentials_override: Option<PathBuf>,
        project_override: Option<String>,
        location_override: Option<String>,
        // OpenAI / Ollama
        api_key_override: Option<String>,
        base_url_override: Option<String>,
    ) -> Result<Self> {
        match kind {
            BackendKind::None => return Ok(BackendConfig::None),
            BackendKind::Gemini => {
                let credentials_path = credentials_override
                    .or_else(|| {
                        std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok().map(PathBuf::from)
                    })
                    .context(
                        "Gemini backend: no credentials found.\n\
                         Set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n\
                         or pass --credentials /path/to/key.json",
                    )?;
                let project_id = project_override
                    .or_else(|| std::env::var("GOOGLE_PROJECT_ID").ok())
                    .context(
                        "Gemini backend: no GCP project ID found.\n\
                         Set GOOGLE_PROJECT_ID=your-project-id\n\
                         or pass --project your-project-id",
                    )?;
                let location = location_override
                    .or_else(|| std::env::var("GOOGLE_LOCATION").ok())
                    .unwrap_or_else(|| "us-central1".to_string());
                let model_id = model_override
                    .or_else(|| std::env::var("KAIJULAB_MODEL").ok())
                    .unwrap_or_else(|| "gemini-2.5-flash".to_string());
                Ok(BackendConfig::Gemini { credentials_path, project_id, location, model_id })
            }

            BackendKind::OpenAi => {
                let api_key = api_key_override
                    .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                    .context(
                        "OpenAI backend: no API key found.\n\
                         Set OPENAI_API_KEY=sk-...\n\
                         or pass --api-key sk-...",
                    )?;
                let base_url = base_url_override
                    .or_else(|| std::env::var("OPENAI_BASE_URL").ok())
                    .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
                let model_id = model_override
                    .or_else(|| std::env::var("KAIJULAB_MODEL").ok())
                    .unwrap_or_else(|| "gpt-4o".to_string());
                Ok(BackendConfig::OpenAi { api_key, base_url, model_id })
            }

            BackendKind::Anthropic => {
                let api_key = api_key_override
                    .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                    .context(
                        "Anthropic backend: no API key found.\n\
                         Set ANTHROPIC_API_KEY=sk-ant-...\n\
                         or pass --api-key sk-ant-...",
                    )?;
                let model_id = model_override
                    .or_else(|| std::env::var("KAIJULAB_MODEL").ok())
                    .unwrap_or_else(|| "claude-opus-4-5".to_string());
                Ok(BackendConfig::Anthropic { api_key, model_id })
            }

            BackendKind::Ollama => {
                let base_url = base_url_override
                    .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
                    .unwrap_or_else(|| "http://localhost:11434/v1".to_string());
                let model_id = model_override
                    .or_else(|| std::env::var("KAIJULAB_MODEL").ok())
                    .unwrap_or_else(|| "llama3.2".to_string());
                Ok(BackendConfig::Ollama { base_url, model_id })
            }
        }
    }

}
