//! Static asset serving.
//!
//! In release builds, `web/dist` is embedded via `include_dir!` so the binary
//! is fully self-contained.  When `KAIJULAB_DEV=1` is set, assets are served
//! from disk so the UI can be edited and reloaded without rebuilding the
//! Rust binary.

use axum::{
    body::Body,
    extract::Path,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use include_dir::{include_dir, Dir};

static DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/*path", get(asset))
}

async fn index() -> Response {
    serve_file("index.html").await
}

async fn asset(Path(path): Path<String>) -> Response {
    // Don't shadow /api/* — those routes are merged before this; axum's matcher
    // will prefer the more specific routes.
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve_file(&path).await
}

async fn serve_file(path: &str) -> Response {
    if std::env::var("KAIJULAB_DEV").is_ok() {
        return serve_from_disk(path).await;
    }
    serve_embedded(path)
}

fn serve_embedded(path: &str) -> Response {
    let file = DIST.get_file(path).or_else(|| {
        if should_fallback_to_index(path) {
            DIST.get_file("index.html")
        } else {
            None
        }
    });
    match file {
        Some(f) => {
            let mime = mime_for(path);
            ([(header::CONTENT_TYPE, mime)], f.contents()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "asset not found").into_response(),
    }
}

async fn serve_from_disk(path: &str) -> Response {
    let mut full = std::path::PathBuf::from("web/dist");
    full.push(path);
    let path_str = path.to_string();
    match tokio::fs::read(&full).await {
        Ok(bytes) => {
            let mime = mime_for(&path_str);
            ([(header::CONTENT_TYPE, mime)], Body::from(bytes)).into_response()
        }
        Err(_) => {
            if should_fallback_to_index(&path_str) {
                match tokio::fs::read("web/dist/index.html").await {
                    Ok(bytes) => (
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        Body::from(bytes),
                    )
                        .into_response(),
                    Err(_) => (StatusCode::NOT_FOUND, "asset not found").into_response(),
                }
            } else {
                (StatusCode::NOT_FOUND, "asset not found").into_response()
            }
        }
    }
}

fn should_fallback_to_index(path: &str) -> bool {
    // SPA routes should fall back to index.html, but hashed bundle paths must
    // fail loudly. Serving index.html as JavaScript/CSS produces a blank page
    // with a misleading module parse error when web/dist is stale.
    let last = path.rsplit('/').next().unwrap_or(path);
    !last.contains('.')
}

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[allow(dead_code)]
fn _uri_assert(_: Uri) {}
