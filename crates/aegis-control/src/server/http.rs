//! HTTP REST server for remote pilot control.
//!
//! Uses axum to expose control plane endpoints with optional API key
//! authentication. Disabled when `http_listen` is empty.
//!
//! ## Fleet-level endpoints
//!
//! When a `daemon_tx` is provided (daemon mode), additional fleet-level
//! endpoints are available under `/v1/agents/` and `/v1/config/`. These
//! proxy to `DaemonCommand` variants. In standalone pilot mode (no
//! `daemon_tx`), these endpoints return 501 Not Implemented.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tracing::info;

use aegis_types::AcpServerConfig;

use crate::acp_server::{self, AcpState, IpRateLimiter};
use crate::command::{Command, CommandResponse};
use crate::daemon::{DaemonCommand, DaemonResponse};
use crate::server::handler::handle_command;
use crate::server::CommandTx;

/// Channel type for forwarding fleet-level commands to the daemon.
pub type DaemonCommandTx =
    tokio::sync::mpsc::Sender<(DaemonCommand, tokio::sync::oneshot::Sender<DaemonResponse>)>;

/// Shared state for HTTP handlers.
struct AppState {
    command_tx: CommandTx,
    api_key: String,
    /// Optional daemon command channel. When present, fleet-level endpoints
    /// are active. When `None` (standalone pilot mode), they return 501.
    daemon_tx: Option<DaemonCommandTx>,
}

/// Start the HTTP control server.
///
/// Binds to the given address and serves until the `shutdown` future resolves.
/// Returns `Ok(())` on clean shutdown or an error if binding fails.
///
/// Pass `daemon_tx` as `Some(...)` in daemon mode to enable fleet endpoints,
/// or `None` for standalone pilot mode.
///
/// When `acp_config` is provided and `daemon_tx` is available, ACP protocol
/// endpoints are mounted under `/acp/v1/`. ACP routes have their own
/// authentication (SHA-256 token hash allowlist) independent of the main
/// API key.
pub async fn serve(
    listen_addr: &str,
    command_tx: CommandTx,
    api_key: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
    daemon_tx: Option<DaemonCommandTx>,
    acp_config: Option<AcpServerConfig>,
) -> Result<(), String> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("invalid listen address {listen_addr:?}: {e}"))?;

    let state = Arc::new(AppState {
        command_tx,
        api_key: api_key.clone(),
        daemon_tx: daemon_tx.clone(),
    });

    let mut app = Router::new()
        // Pilot-level endpoints
        .route("/v1/status", get(status_handler))
        .route("/v1/output", get(output_handler))
        .route("/v1/command", post(command_handler))
        .route("/v1/pending", get(pending_handler))
        .route("/v1/pending/{id}/approve", post(approve_handler))
        .route("/v1/pending/{id}/deny", post(deny_handler))
        .route("/v1/input", post(input_handler))
        // Fleet-level endpoints (require daemon_tx)
        .route("/v1/agents", get(fleet_list_agents))
        .route("/v1/agents/{name}/start", post(fleet_start_agent))
        .route("/v1/agents/{name}/stop", post(fleet_stop_agent))
        .route("/v1/agents/{name}/restart", post(fleet_restart_agent))
        .route("/v1/agents/{name}/context", get(fleet_agent_context))
        .route("/v1/config/reload", post(fleet_config_reload))
        .with_state(state.clone());

    // Mount ACP routes if configured and daemon is available
    if let (Some(acp_cfg), Some(dtx)) = (acp_config, daemon_tx) {
        let rate_limiter = Arc::new(IpRateLimiter::new(acp_cfg.rate_limit_per_minute));
        let token_hashes = acp_cfg.token_hashes.clone();

        let acp_state = Arc::new(AcpState {
            token_hashes: token_hashes.clone(),
            rate_limiter: rate_limiter.clone(),
            max_body_size: acp_cfg.max_body_size,
            daemon_tx: dtx.clone(),
        });
        let acp_router = acp_server::acp_routes(acp_state);

        // Mount ACP WebSocket endpoint alongside HTTP routes
        let acp_ws_state = Arc::new(crate::acp_websocket::AcpWsState {
            token_hashes: token_hashes.clone(),
            rate_limiter,
            max_body_size: acp_cfg.max_body_size,
            rate_limit_per_minute: acp_cfg.rate_limit_per_minute,
            daemon_tx: dtx.clone(),
            shutdown: shutdown.clone(),
        });
        let acp_ws_router = crate::acp_websocket::acp_ws_routes(acp_ws_state);

        // Enhanced ACP protocol endpoints (handshake, discovery, sessions)
        let session_store = std::sync::Arc::new(crate::acp_enhanced::SessionStore::new());
        let acp_enhanced_state = std::sync::Arc::new(crate::acp_enhanced::AcpEnhancedState {
            token_hashes: token_hashes.clone(),
            sessions: session_store,
            max_body_size: acp_cfg.max_body_size,
            daemon_tx: dtx.clone(),
        });
        let acp_enhanced_router = crate::acp_enhanced::acp_enhanced_routes(acp_enhanced_state);

        app = app
            .nest("/acp/v1", acp_router)
            .nest("/acp/v1", acp_ws_router)
            .nest("/acp/v1", acp_enhanced_router);
        info!("ACP server routes mounted at /acp/v1 (HTTP + WebSocket + Enhanced)");

        // OpenAI-compatible endpoint
        let openai_state = std::sync::Arc::new(crate::openai_compat::OpenAiState {
            api_key,
            daemon_tx: dtx.clone(),
        });
        let openai_router = crate::openai_compat::openai_routes(openai_state);
        app = app.merge(openai_router);
        info!("OpenAI-compatible routes mounted at /v1/chat/completions, /v1/models");

        // OpenResponses tool API
        let tool_api_state = std::sync::Arc::new(crate::open_responses::ToolApiState {
            api_key: state.api_key.clone(),
            tools: crate::open_responses::default_tool_catalog(),
            invocations: std::sync::Arc::new(crate::open_responses::InvocationStore::new()),
            daemon_tx: dtx,
        });
        let tool_api_router = crate::open_responses::tool_api_routes(tool_api_state);
        app = app.merge(tool_api_router);
        info!("OpenResponses tool API routes mounted at /v1/tools");
    }

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
fn check_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<CommandResponse>)> {
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
        Command::GetOutput {
            lines: params.lines,
        },
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
        Command::Deny {
            request_id: id,
            reason,
        },
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
    let resp = handle_command(&state.command_tx, Command::SendInput { text: body.text }).await;
    (StatusCode::OK, Json(resp))
}

#[derive(serde::Deserialize)]
struct InputBody {
    text: String,
}

// ---------------------------------------------------------------------------
// Fleet-level endpoints (proxy to DaemonCommand via daemon_tx)
// ---------------------------------------------------------------------------

/// Send a `DaemonCommand` through the daemon channel and await the response.
async fn send_daemon_cmd(
    tx: &DaemonCommandTx,
    cmd: DaemonCommand,
) -> Result<DaemonResponse, String> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    tx.send((cmd, resp_tx))
        .await
        .map_err(|_| "daemon command channel closed".to_string())?;
    resp_rx
        .await
        .map_err(|_| "daemon response channel closed".to_string())
}

/// Convert a `DaemonResponse` into an HTTP response pair.
fn daemon_resp_to_http(resp: DaemonResponse) -> (StatusCode, Json<CommandResponse>) {
    let cr = CommandResponse {
        ok: resp.ok,
        message: resp.message,
        data: resp.data,
    };
    if cr.ok {
        (StatusCode::OK, Json(cr))
    } else {
        (StatusCode::BAD_REQUEST, Json(cr))
    }
}

/// Return 501 when fleet endpoints are called without a daemon_tx.
fn not_implemented() -> (StatusCode, Json<CommandResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(CommandResponse::error(
            "fleet endpoints not available in standalone pilot mode",
        )),
    )
}

/// `GET /v1/agents` -- list all agents in the fleet.
async fn fleet_list_agents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::ListAgents).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

/// `POST /v1/agents/{name}/start` -- start a specific agent.
async fn fleet_start_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::StartAgent { name }).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

/// `POST /v1/agents/{name}/stop` -- stop a specific agent.
async fn fleet_stop_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::StopAgent { name }).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

/// `POST /v1/agents/{name}/restart` -- restart a specific agent.
async fn fleet_restart_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::RestartAgent { name }).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

/// `GET /v1/agents/{name}/context` -- get agent context (role, goal, etc.).
async fn fleet_agent_context(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::GetAgentContext { name }).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

/// `POST /v1/config/reload` -- reload daemon configuration from disk.
async fn fleet_config_reload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let daemon_tx = match &state.daemon_tx {
        Some(tx) => tx,
        None => return not_implemented(),
    };
    match send_daemon_cmd(daemon_tx, DaemonCommand::ReloadConfig).await {
        Ok(resp) => daemon_resp_to_http(resp),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(CommandResponse::error(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_same_bytes() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\x00\xff", b"\x00\xff"));
    }

    #[test]
    fn constant_time_eq_different_bytes() {
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"hello", b"HELLO"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"hi", b"hello"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn not_implemented_returns_501() {
        let (status, json) = not_implemented();
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(!json.ok);
        assert!(json.message.contains("standalone pilot mode"));
    }

    #[test]
    fn daemon_resp_to_http_ok() {
        let resp = DaemonResponse::ok_with_data("found", serde_json::json!({"count": 3}));
        let (status, json) = daemon_resp_to_http(resp);
        assert_eq!(status, StatusCode::OK);
        assert!(json.ok);
        assert_eq!(json.message, "found");
        assert!(json.data.is_some());
    }

    #[test]
    fn daemon_resp_to_http_error() {
        let resp = DaemonResponse::error("agent not found");
        let (status, json) = daemon_resp_to_http(resp);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!json.ok);
        assert_eq!(json.message, "agent not found");
    }

    #[test]
    fn check_auth_no_api_key_passes() {
        let state = AppState {
            command_tx: tokio::sync::mpsc::channel(1).0,
            api_key: String::new(),
            daemon_tx: None,
        };
        assert!(check_auth(&state, &HeaderMap::new()).is_ok());
    }

    #[test]
    fn check_auth_valid_bearer() {
        let state = AppState {
            command_tx: tokio::sync::mpsc::channel(1).0,
            api_key: "test-key".into(),
            daemon_tx: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-key".parse().unwrap());
        assert!(check_auth(&state, &headers).is_ok());
    }

    #[test]
    fn check_auth_invalid_bearer() {
        let state = AppState {
            command_tx: tokio::sync::mpsc::channel(1).0,
            api_key: "test-key".into(),
            daemon_tx: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-key".parse().unwrap());
        assert!(check_auth(&state, &headers).is_err());
    }

    #[test]
    fn check_auth_missing_header() {
        let state = AppState {
            command_tx: tokio::sync::mpsc::channel(1).0,
            api_key: "test-key".into(),
            daemon_tx: None,
        };
        assert!(check_auth(&state, &HeaderMap::new()).is_err());
    }
}
