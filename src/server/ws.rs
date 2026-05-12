//! WebSocket fan-out from the internal EventBus to browser clients.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;

use super::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/events", get(events_handler))
        .with_state(state)
}

async fn events_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.events.subscribe();

    // Greet the client with a hello frame containing workspace info.
    if let Ok(hello) = serde_json::to_string(&serde_json::json!({
        "type": "hello",
        "workspace": state.workspace.info(),
    })) {
        let _ = sender.send(Message::Text(hello)).await;
    }

    loop {
        tokio::select! {
            ev = event_rx.recv() => match ev {
                Ok(event) => {
                    if let Ok(s) = serde_json::to_string(&event) {
                        if sender.send(Message::Text(s)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    // Subscriber fell behind; notify and continue.
                    let _ = sender
                        .send(Message::Text(
                            r#"{"type":"warning","message":"event stream lagged"}"#.into(),
                        ))
                        .await;
                }
                Err(RecvError::Closed) => break,
            },
            msg = receiver.next() => match msg {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(p))) => {
                    let _ = sender.send(Message::Pong(p)).await;
                }
                Some(Ok(_)) => { /* ignore client text/binary */ }
                Some(Err(_)) => break,
            }
        }
    }
}
