//! HTTP server bootstrap + AppState.  Wires REST routes, WebSocket fan-out,
//! and the embedded UI static assets together behind a single axum router.

pub mod agent_console;
pub mod palette;
pub mod routes;
pub mod static_assets;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::core::{EventBus, JobRunner, WorkspaceRegistry};
use agent_console::AgentConsoleManager;

#[derive(Clone)]
pub struct AppState {
    pub registry: WorkspaceRegistry,
    pub events: EventBus,
    pub jobs: JobRunner,
    pub auth_token: Option<Arc<String>>,
    pub agent_console: AgentConsoleManager,
}

pub async fn serve(
    registry: WorkspaceRegistry,
    events: EventBus,
    bind: SocketAddr,
    auth_token: Option<String>,
) -> Result<()> {
    let jobs = JobRunner::new(events.clone());

    let state = AppState {
        registry: registry.clone(),
        events: events.clone(),
        jobs,
        auth_token: auth_token.map(Arc::new),
        agent_console: AgentConsoleManager::new(),
    };

    let auth_layer = middleware::from_fn_with_state(state.clone(), require_auth);
    let api = routes::router(state.clone()).layer(auth_layer.clone());
    let events = ws::router(state.clone()).layer(auth_layer.clone());
    let agent_console = agent_console::router(state.clone()).layer(auth_layer);

    let app = Router::new()
        .merge(api)
        .merge(events)
        .merge(agent_console)
        .merge(static_assets::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    tracing::info!("kaijulab serve listening on http://{}", bind);
    if state.auth_token.is_some() {
        tracing::info!(
            "API authentication enabled; browser UI will prompt for the token on first use"
        );
    }
    if let Some(ws) = registry.active() {
        tracing::info!("active workspace: {}", ws.binary_path_str());
    } else {
        tracing::info!("no active workspace — open one via the UI or POST /api/workspaces/open");
    }

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {}", bind))?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn require_auth(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    if request_is_authorized(&state, &req) {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "unauthorized",
            "message": "missing or invalid KaijuLab API token"
        })),
    )
        .into_response()
}

fn request_is_authorized(state: &AppState, req: &Request<Body>) -> bool {
    let Some(token) = state.auth_token.as_deref() else {
        return true;
    };

    bearer_token_matches(req, token) || websocket_query_token_matches(req, token)
}

fn bearer_token_matches(req: &Request<Body>, token: &str) -> bool {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == token)
}

fn websocket_query_token_matches(req: &Request<Body>, token: &str) -> bool {
    let path = req.uri().path();
    if path != "/api/events" && !path.starts_with("/api/agent-console/") {
        return false;
    }

    req.uri()
        .query()
        .is_some_and(|query| query_param_matches(query, "token", token))
}

fn query_param_matches(query: &str, key: &str, expected: &str) -> bool {
    query.split('&').any(|pair| {
        let mut parts = pair.splitn(2, '=');
        let Some(raw_key) = parts.next() else {
            return false;
        };
        let raw_value = parts.next().unwrap_or_default();
        percent_decode(raw_key).as_deref() == Some(key)
            && percent_decode(raw_value).as_deref() == Some(expected)
    })
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_value(bytes[i + 1])?;
                let lo = hex_value(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'%' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8(out).ok()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn query_token_matching_decodes_websocket_token() {
        assert!(query_param_matches(
            "workspace=main&token=abc%20123%2B",
            "token",
            "abc 123+"
        ));
    }

    #[test]
    fn websocket_query_token_is_limited_to_events_endpoint() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/events?token=secret")
            .body(Body::empty())
            .unwrap();
        assert!(websocket_query_token_matches(&req, "secret"));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/workspaces?token=secret")
            .body(Body::empty())
            .unwrap();
        assert!(!websocket_query_token_matches(&req, "secret"));
    }

    #[test]
    fn websocket_query_token_allows_agent_console_endpoint() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/agent-console/claude?token=secret")
            .body(Body::empty())
            .unwrap();
        assert!(websocket_query_token_matches(&req, "secret"));
    }
}
