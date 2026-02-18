//! HTTP REST server for remote pilot control.
//!
//! Uses axum to expose control plane endpoints with optional API key
//! authentication. Disabled when `http_listen` is empty.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tracing::info;

use crate::command::{Command, CommandResponse};
use crate::server::handler::handle_command;
use crate::server::CommandTx;

/// Shared state for HTTP handlers.
struct AppState {
    command_tx: CommandTx,
    api_key: String,
}

/// Start the HTTP control server.
///
/// Binds to the given address and serves until the `shutdown` future resolves.
/// Returns `Ok(())` on clean shutdown or an error if binding fails.
pub async fn serve(
    listen_addr: &str,
    command_tx: CommandTx,
    api_key: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("invalid listen address {listen_addr:?}: {e}"))?;

    let state = Arc::new(AppState { command_tx, api_key });

    let app = Router::new()
        .route("/v1/status", get(status_handler))
        .route("/v1/output", get(output_handler))
        .route("/v1/command", post(command_handler))
        .route("/v1/pending", get(pending_handler))
        .route("/v1/pending/{id}/approve", post(approve_handler))
        .route("/v1/pending/{id}/deny", post(deny_handler))
        .route("/v1/input", post(input_handler))
        .with_state(state);

    info!(addr = %addr, "starting HTTP control server");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    let mut shutdown = shutdown;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|&v| v).await;
        })
        .await
        .map_err(|e| format!("HTTP server error: {e}"))
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Check API key if one is configured.
fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<CommandResponse>)> {
    if state.api_key.is_empty() {
        return Ok(());
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {}", state.api_key);
    if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(CommandResponse::error("invalid or missing API key")),
        ));
    }
    Ok(())
}

async fn status_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let resp = handle_command(&state.command_tx, Command::Status).await;
    (StatusCode::OK, Json(resp))
}

async fn output_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<OutputParams>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let resp = handle_command(
        &state.command_tx,
        Command::GetOutput { lines: params.lines },
    )
    .await;
    (StatusCode::OK, Json(resp))
}

#[derive(serde::Deserialize)]
struct OutputParams {
    lines: Option<usize>,
}

async fn command_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(command): Json<Command>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let resp = handle_command(&state.command_tx, command).await;
    (StatusCode::OK, Json(resp))
}

async fn pending_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    // Use Status command -- pending info is included in status
    let resp = handle_command(&state.command_tx, Command::Status).await;
    (StatusCode::OK, Json(resp))
}

async fn approve_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let resp = handle_command(&state.command_tx, Command::Approve { request_id: id }).await;
    (StatusCode::OK, Json(resp))
}

async fn deny_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    body: Option<Json<DenyBody>>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let reason = body.and_then(|b| b.reason.clone());
    let resp = handle_command(
        &state.command_tx,
        Command::Deny { request_id: id, reason },
    )
    .await;
    (StatusCode::OK, Json(resp))
}

#[derive(serde::Deserialize)]
struct DenyBody {
    reason: Option<String>,
}

async fn input_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InputBody>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let resp = handle_command(
        &state.command_tx,
        Command::SendInput { text: body.text },
    )
    .await;
    (StatusCode::OK, Json(resp))
}

#[derive(serde::Deserialize)]
struct InputBody {
    text: String,
}
