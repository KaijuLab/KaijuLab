use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::tools::FunctionDeclaration;

// ─── Service-account JSON ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
}

// ─── JWT / token exchange ────────────────────────────────────────────────────

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

struct CachedToken {
    access_token: String,
    expires_at: i64,
}

// ─── Gemini API types ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
    pub role: String,
    pub parts: Vec<Part>,
}

/// Individual part inside a `Content`.
///
/// `#[serde(untagged)]` lets serde pick the right variant by field presence.
/// Order matters: most-specific variants first.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Part {
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: FunctionCallPart,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: FunctionResponsePart,
    },
    Text {
        text: String,
    },
    /// Catch-all for unknown part types (e.g. thought, executableCode)
    Unknown(serde_json::Value),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionCallPart {
    pub name: String,
    pub args: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionResponsePart {
    pub name: String,
    pub response: serde_json::Value,
}

// ─── Request types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct GenerateRequest<'a> {
    contents: &'a [Content],
    tools: Vec<ToolSpec<'a>>,
    #[serde(rename = "systemInstruction")]
    system_instruction: SystemInstruction,
    #[serde(rename = "toolConfig")]
    tool_config: ToolConfig,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Serialize)]
struct SystemInstruction {
    parts: Vec<SystemPart>,
}

#[derive(Serialize)]
struct SystemPart {
    text: String,
}

#[derive(Serialize)]
struct ToolSpec<'a> {
    #[serde(rename = "functionDeclarations")]
    function_declarations: &'a [FunctionDeclaration],
}

#[derive(Serialize)]
struct ToolConfig {
    #[serde(rename = "functionCallingConfig")]
    function_calling_config: FunctionCallingConfig,
}

#[derive(Serialize)]
struct FunctionCallingConfig {
    mode: &'static str,
}

#[derive(Serialize)]
struct GenerationConfig {
    temperature: f32,
}

// ─── Response types ──────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct GenerateResponse {
    candidates: Vec<Candidate>,
    #[allow(dead_code)]
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
pub struct Candidate {
    pub content: Content,
    #[serde(rename = "finishReason")]
    pub finish_reason: Option<String>,
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct GeminiClient {
    http: reqwest::Client,
    sa: ServiceAccount,
    pub project_id: String,
    pub location: String,
    pub model_id: String,
    token_cache: Arc<Mutex<Option<CachedToken>>>,
}

const SYSTEM_PROMPT: &str = "\
You are KaijuLab, an expert reverse-engineering assistant. \
You analyse binary files using the tools available to you. \
Start with file_info to understand the file format, then use other tools \
to dig deeper as needed. Be precise, technical, and explain your reasoning \
step by step. When you encounter addresses or offsets, prefer the \
disassemble tool to verify what the code actually does.";

impl GeminiClient {
    pub fn new(
        credentials_path: &Path,
        project_id: String,
        location: String,
        model_id: String,
    ) -> Result<Self> {
        let raw = std::fs::read_to_string(credentials_path)
            .with_context(|| format!("Cannot read '{}'", credentials_path.display()))?;
        let sa: ServiceAccount =
            serde_json::from_str(&raw).context("Cannot parse service-account JSON")?;

        Ok(GeminiClient {
            http: reqwest::Client::new(),
            sa,
            project_id,
            location,
            model_id,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    // ── Token management ──────────────────────────────────────────────────────

    async fn access_token(&self) -> Result<String> {
        let mut cache = self.token_cache.lock().await;
        let now = Utc::now().timestamp();

        // Return cached token if still valid for > 60 s
        if let Some(tok) = cache.as_ref() {
            if tok.expires_at > now + 60 {
                return Ok(tok.access_token.clone());
            }
        }

        // Build JWT
        let claims = JwtClaims {
            iss: self.sa.client_email.clone(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
            aud: self.sa.token_uri.clone(),
            exp: now + 3600,
            iat: now,
        };
        let key = EncodingKey::from_rsa_pem(self.sa.private_key.as_bytes())
            .context("Cannot parse private key from service-account JSON")?;
        let jwt =
            encode(&Header::new(Algorithm::RS256), &claims, &key).context("JWT signing failed")?;

        // Exchange for access token
        let resp: TokenResponse = self
            .http
            .post(&self.sa.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .context("Token exchange request failed")?
            .json()
            .await
            .context("Token exchange: unexpected response format")?;

        let token = resp.access_token.clone();
        *cache = Some(CachedToken {
            access_token: resp.access_token,
            expires_at: now + resp.expires_in,
        });

        Ok(token)
    }

    // ── generateContent ───────────────────────────────────────────────────────

    pub async fn generate(
        &self,
        history: &[Content],
        tools: &[FunctionDeclaration],
    ) -> Result<Candidate> {
        let token = self.access_token().await?;

        let url = format!(
            "https://{loc}-aiplatform.googleapis.com/v1/projects/{proj}/locations/{loc}/publishers/google/models/{model}:generateContent",
            loc   = self.location,
            proj  = self.project_id,
            model = self.model_id,
        );

        let request = GenerateRequest {
            contents: history,
            tools: vec![ToolSpec {
                function_declarations: tools,
            }],
            system_instruction: SystemInstruction {
                parts: vec![SystemPart {
                    text: SYSTEM_PROMPT.to_string(),
                }],
            },
            tool_config: ToolConfig {
                function_calling_config: FunctionCallingConfig { mode: "AUTO" },
            },
            generation_config: GenerationConfig { temperature: 0.1 },
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .context("Gemini API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Gemini API error {}: {}", status, body);
        }

        let gen_resp: GenerateResponse = resp
            .json()
            .await
            .context("Failed to parse Gemini response")?;

        gen_resp
            .candidates
            .into_iter()
            .next()
            .context("Gemini returned no candidates")
    }
}
