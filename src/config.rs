use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// Path to Google service account JSON key file
    pub credentials_path: PathBuf,
    pub project_id: String,
    pub location: String,
    pub model_id: String,
}

impl Config {
    pub fn load(
        credentials_override: Option<PathBuf>,
        project_override: Option<String>,
        location_override: Option<String>,
        model_override: Option<String>,
    ) -> Result<Self> {
        let credentials_path = credentials_override
            .or_else(|| std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok().map(PathBuf::from))
            .context(
                "No credentials found.\n\
                 Set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n\
                 or pass --credentials /path/to/key.json",
            )?;

        let project_id = project_override
            .or_else(|| std::env::var("GOOGLE_PROJECT_ID").ok())
            .context(
                "No GCP project ID found.\n\
                 Set GOOGLE_PROJECT_ID=your-project-id\n\
                 or pass --project your-project-id",
            )?;

        let location = location_override
            .or_else(|| std::env::var("GOOGLE_LOCATION").ok())
            .unwrap_or_else(|| "us-central1".to_string());

        let model_id = model_override
            .or_else(|| std::env::var("KAIJULAB_MODEL").ok())
            .unwrap_or_else(|| "gemini-2.5-flash".to_string());

        Ok(Config {
            credentials_path,
            project_id,
            location,
            model_id,
        })
    }
}
