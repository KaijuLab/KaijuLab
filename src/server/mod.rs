//! HTTP server bootstrap + AppState.  Wires REST routes, WebSocket fan-out,
//! and the embedded UI static assets together behind a single axum router.

pub mod palette;
pub mod routes;
pub mod static_assets;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::core::{EventBus, FindingStore, JobRunner, Workspace};

#[derive(Clone)]
pub struct AppState {
    pub workspace: Workspace,
    pub events: EventBus,
    pub jobs: JobRunner,
    pub findings: FindingStore,
    pub auth_token: Option<Arc<String>>,
}

pub async fn serve(
    workspace: Workspace,
    events: EventBus,
    bind: SocketAddr,
    auth_token: Option<String>,
) -> Result<()> {
    let jobs = JobRunner::new(events.clone());
    let findings = FindingStore::new();

    let state = AppState {
        workspace: workspace.clone(),
        events: events.clone(),
        jobs,
        findings,
        auth_token: auth_token.map(Arc::new),
    };

    let app = Router::new()
        .merge(routes::router(state.clone()))
        .merge(ws::router(state.clone()))
        .merge(static_assets::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    tracing::info!(
        "kaijulab serve listening on http://{} (binary: {})",
        bind,
        workspace.binary_path_str()
    );

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {}", bind))?;
    axum::serve(listener, app).await?;
    Ok(())
}
