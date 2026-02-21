//! Read-only web dashboard server for the daemon.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, warn};

use aegis_control::daemon::{DaemonCommand, DaemonResponse, DashboardStatus};
use aegis_toolkit::contract::ToolAction;

use crate::control::DaemonCmdTx;

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard/index.html");

/// Token-bucket rate limiter keyed by client IP address.
///
/// Each IP gets `burst` tokens initially. Tokens refill at `per_sec` per
/// second. Each request costs 1 token. When tokens are exhausted the
/// request is rejected with 429 Too Many Requests.
#[derive(Clone)]
struct RateLimiter {
    buckets: Arc<std::sync::Mutex<HashMap<IpAddr, (f64, Instant)>>>,
    burst: f64,
    per_sec: f64,
}

impl RateLimiter {
    fn new(burst: u32, per_sec: f64) -> Self {
        Self {
            buckets: Arc::new(std::sync::Mutex::new(HashMap::new())),
            burst: burst as f64,
            per_sec,
        }
    }

    /// Check whether a request from the given IP should be allowed.
    ///
    /// Returns `true` if the request is permitted, `false` if rate-limited.
    fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let (tokens, last) = buckets
            .entry(ip)
            .or_insert((self.burst, now));
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.per_sec).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct DashboardState {
    cmd_tx: DaemonCmdTx,
    token: String,
    base_url: String,
    listen: String,
    rate_limiter: RateLimiter,
}

pub fn spawn_dashboard_server(
    listen: String,
    token: String,
    cmd_tx: DaemonCmdTx,
    shutdown: Arc<AtomicBool>,
    rate_limit_burst: u32,
    rate_limit_per_sec: f64,
) -> Result<std::thread::JoinHandle<()>, String> {
    let base_url = format!("http://{listen}");
    let rate_limiter = RateLimiter::new(rate_limit_burst, rate_limit_per_sec);
    let state = DashboardState {
        cmd_tx,
        token,
        base_url,
        listen,
        rate_limiter,
    };

    std::thread::Builder::new()
        .name("dashboard-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime creation failed");
            rt.block_on(async move {
                if let Err(e) = serve(state, shutdown).await {
                    warn!(error = %e, "dashboard server stopped");
                }
            });
        })
        .map_err(|e| format!("failed to spawn dashboard server thread: {e}"))
}

async fn serve(state: DashboardState, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/snapshot", get(snapshot))
        .route("/api/frame/{agent}", get(frame))
        .route("/api/logs/{agent}", get(logs))
        .route("/ws", get(ws))
        .route("/gateway/ws", get(gateway_ws))
        .with_state(state.clone());

    let addr: SocketAddr = state
        .listen
        .parse()
        .map_err(|e| format!("invalid dashboard listen addr: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("dashboard bind failed: {e}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
        .map_err(|e| format!("dashboard server failed: {e}"))?;
    Ok(())
}

async fn shutdown_signal(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

/// Extract the remote IP address from request headers for audit logging.
///
/// Checks X-Forwarded-For first (first entry), then X-Real-Ip, then
/// falls back to "unknown".
fn extract_remote_ip(headers: &HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(text) = xff.to_str() {
            if let Some(first) = text.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(text) = real_ip.to_str() {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "unknown".to_string()
}

fn auth_ok(headers: &HeaderMap, token_query: Option<&str>, token: &str) -> bool {
    if let Some(value) = token_query {
        if constant_time_eq(value.as_bytes(), token.as_bytes()) {
            return true;
        }
    }
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(text) = auth.to_str() {
            if let Some(rest) = text.strip_prefix("Bearer ") {
                if constant_time_eq(rest.as_bytes(), token.as_bytes()) {
                    return true;
                }
            }
        }
    }
    if let Some(header) = headers.get("x-aegis-token") {
        if let Ok(text) = header.to_str() {
            if constant_time_eq(text.as_bytes(), token.as_bytes()) {
                return true;
            }
        }
    }
    let remote_ip = extract_remote_ip(headers);
    warn!(
        remote_ip = %remote_ip,
        "dashboard auth failed: no valid token provided"
    );
    false
}

/// Check rate limit for the request. Returns an error response if rate-limited.
fn check_rate_limit(headers: &HeaderMap, limiter: &RateLimiter) -> Option<StatusCode> {
    let ip_str = extract_remote_ip(headers);
    let ip: IpAddr = ip_str
        .parse()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if !limiter.check(ip) {
        warn!(remote_ip = %ip_str, "dashboard rate limit exceeded");
        Some(StatusCode::TOO_MANY_REQUESTS)
    } else {
        None
    }
}

#[derive(serde::Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

async fn index(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Html(DASHBOARD_HTML).into_response()
}

async fn status(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let payload = DashboardStatus {
        enabled: true,
        listen: state.listen.clone(),
        base_url: Some(state.base_url.clone()),
        token: Some(state.token.clone()),
    };
    Json(payload).into_response()
}

async fn snapshot(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match send_cmd(&state.cmd_tx, DaemonCommand::DashboardSnapshot).await {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                Json(data).into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Ok(resp) => (StatusCode::BAD_REQUEST, resp.message).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    lines: Option<usize>,
    token: Option<String>,
}

async fn logs(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(agent): Path<String>,
    Query(q): Query<LogsQuery>,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let lines = q.lines.unwrap_or(50);
    match send_cmd(
        &state.cmd_tx,
        DaemonCommand::AgentOutput {
            name: agent,
            lines: Some(lines),
        },
    )
    .await
    {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                Json(data).into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Ok(resp) => (StatusCode::BAD_REQUEST, resp.message).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

async fn frame(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(agent): Path<String>,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match send_cmd(
        &state.cmd_tx,
        DaemonCommand::LatestCaptureFrame {
            name: agent,
            region: None,
        },
    )
    .await
    {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                Json(data).into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Ok(resp) => (StatusCode::BAD_REQUEST, resp.message).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

async fn ws(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    ws.on_upgrade(move |socket| async move {
        let (mut sender, mut _receiver) = socket.split();
        loop {
            match send_cmd(&state.cmd_tx, DaemonCommand::DashboardSnapshot).await {
                Ok(resp) if resp.ok => {
                    if let Some(data) = resp.data {
                        if let Ok(text) = serde_json::to_string(&data) {
                            if sender
                                .send(axum::extract::ws::Message::Text(text.into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                Ok(resp) => {
                    debug!(message = %resp.message, "dashboard snapshot error");
                }
                Err(e) => {
                    debug!(error = %e, "dashboard snapshot transport error");
                }
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GatewayRequest {
    #[serde(default)]
    id: Option<String>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GatewayResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GatewayEvent {
    event: String,
    data: serde_json::Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SessionParams {
    session_key: String,
    #[serde(default)]
    lines: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SessionSendParams {
    session_key: String,
    text: String,
}

/// Params for gateway methods that take just an agent name.
#[derive(Debug, Clone, serde::Deserialize)]
struct NameParams {
    name: String,
}

/// Params for approve/deny methods that take an agent name and request ID.
#[derive(Debug, Clone, serde::Deserialize)]
struct NameRequestParams {
    name: String,
    request_id: String,
}

/// Params for tool.execute: agent name and action payload.
#[derive(Debug, Clone, serde::Deserialize)]
struct ToolExecuteParams {
    name: String,
    action: serde_json::Value,
}

#[derive(Debug, Clone)]
struct FollowState {
    session_key: String,
    lines: usize,
    last_len: usize,
    last_tail: Option<String>,
}

async fn gateway_ws(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if let Some(status) = check_rate_limit(&headers, &state.rate_limiter) {
        return status.into_response();
    }
    if !auth_ok(&headers, q.token.as_deref(), &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    ws.on_upgrade(move |socket| async move {
        gateway_loop(socket, state).await;
    })
}

async fn gateway_loop(socket: WebSocket, state: DashboardState) {
    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));
    let follow = Arc::new(Mutex::new(None::<FollowState>));

    let follow_sender = Arc::clone(&sender);
    let follow_state = Arc::clone(&follow);
    let cmd_tx = state.cmd_tx.clone();

    let follow_task = tokio::spawn(async move {
        loop {
            let config = { follow_state.lock().await.clone() };
            if let Some(mut cfg) = config {
                let resp = send_cmd(
                    &cmd_tx,
                    DaemonCommand::SessionHistory {
                        session_key: cfg.session_key.clone(),
                        lines: Some(cfg.lines),
                    },
                )
                .await;
                if let Ok(resp) = resp {
                    if resp.ok {
                        if let Some(data) = resp.data {
                            if let Ok(history) = serde_json::from_value::<
                                aegis_control::daemon::SessionHistory,
                            >(data)
                            {
                                let len = history.lines.len();
                                let tail = history.lines.last().cloned();
                                if len != cfg.last_len || tail != cfg.last_tail {
                                    cfg.last_len = len;
                                    cfg.last_tail = tail.clone();
                                    *follow_state.lock().await = Some(cfg.clone());
                                    let payload = serde_json::json!({
                                        "session_key": history.session_key,
                                        "lines": history.lines,
                                    });
                                    let event = GatewayEvent {
                                        event: "session.history".to_string(),
                                        data: payload,
                                    };
                                    if send_gateway(&follow_sender, event).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
    });

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text.to_string(),
            Ok(Message::Binary(bin)) => String::from_utf8_lossy(&bin).to_string(),
            Ok(Message::Close(_)) | Err(_) => break,
            _ => continue,
        };

        let parsed: Result<GatewayRequest, _> = serde_json::from_str(&msg);
        let req = match parsed {
            Ok(req) => req,
            Err(err) => {
                let resp = GatewayResponse {
                    id: None,
                    ok: false,
                    result: None,
                    error: Some(format!("invalid request: {err}")),
                };
                if send_gateway(&sender, resp).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let response = handle_gateway_request(&state, &follow, req).await;
        if send_gateway(&sender, response).await.is_err() {
            break;
        }
    }

    follow_task.abort();
}

async fn handle_gateway_request(
    state: &DashboardState,
    follow: &Arc<Mutex<Option<FollowState>>>,
    req: GatewayRequest,
) -> GatewayResponse {
    let id = req.id.clone();
    match req.method.as_str() {
        "ping" => GatewayResponse {
            id,
            ok: true,
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        },
        "session.list" => match send_cmd(&state.cmd_tx, DaemonCommand::SessionList).await {
            Ok(resp) if resp.ok => GatewayResponse {
                id,
                ok: true,
                result: resp.data,
                error: None,
            },
            Ok(resp) => GatewayResponse {
                id,
                ok: false,
                result: None,
                error: Some(resp.message),
            },
            Err(e) => GatewayResponse {
                id,
                ok: false,
                result: None,
                error: Some(e),
            },
        },
        "session.history" => {
            let params: Result<SessionParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(params) => params,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::SessionHistory {
                    session_key: params.session_key,
                    lines: params.lines,
                },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "session.send" => {
            let params: Result<SessionSendParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(params) => params,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::SessionSend {
                    session_key: params.session_key,
                    text: params.text,
                },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "session.follow" => {
            let params: Result<SessionParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(params) => params,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            let lines = params.lines.unwrap_or(50);
            let mut guard = follow.lock().await;
            *guard = Some(FollowState {
                session_key: params.session_key,
                lines,
                last_len: 0,
                last_tail: None,
            });
            GatewayResponse {
                id,
                ok: true,
                result: Some(serde_json::json!({"following": true})),
                error: None,
            }
        }
        "session.unfollow" => {
            let mut guard = follow.lock().await;
            *guard = None;
            GatewayResponse {
                id,
                ok: true,
                result: Some(serde_json::json!({"following": false})),
                error: None,
            }
        }
        "fleet.status" => {
            match send_cmd(&state.cmd_tx, DaemonCommand::ListAgents).await {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "agent.approve" => {
            let params: Result<NameRequestParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(p) => p,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::ApproveRequest {
                    name: params.name,
                    request_id: params.request_id,
                },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "agent.deny" => {
            let params: Result<NameRequestParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(p) => p,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::DenyRequest {
                    name: params.name,
                    request_id: params.request_id,
                },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "agent.start" => {
            let params: Result<NameParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(p) => p,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::StartAgent { name: params.name },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "agent.stop" => {
            let params: Result<NameParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(p) => p,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::StopAgent { name: params.name },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "config.reload" => {
            match send_cmd(&state.cmd_tx, DaemonCommand::ReloadConfig).await {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        "tool.execute" => {
            let params: Result<ToolExecuteParams, _> = serde_json::from_value(req.params);
            let params = match params {
                Ok(p) => p,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid params: {err}")),
                    };
                }
            };
            let action: ToolAction = match serde_json::from_value(params.action) {
                Ok(a) => a,
                Err(err) => {
                    return GatewayResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid tool action: {err}")),
                    };
                }
            };
            match send_cmd(
                &state.cmd_tx,
                DaemonCommand::ExecuteToolAction {
                    name: params.name,
                    action,
                },
            )
            .await
            {
                Ok(resp) if resp.ok => GatewayResponse {
                    id,
                    ok: true,
                    result: resp.data,
                    error: None,
                },
                Ok(resp) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(resp.message),
                },
                Err(e) => GatewayResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some(e),
                },
            }
        }
        other => GatewayResponse {
            id,
            ok: false,
            result: None,
            error: Some(format!("unknown method '{other}'")),
        },
    }
}

async fn send_gateway<T: serde::Serialize>(
    sender: &Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
    payload: T,
) -> Result<(), ()> {
    let text = serde_json::to_string(&payload).map_err(|_| ())?;
    let mut guard = sender.lock().await;
    guard.send(Message::Text(text.into())).await.map_err(|_| ())
}

async fn send_cmd(cmd_tx: &DaemonCmdTx, cmd: DaemonCommand) -> Result<DaemonResponse, String> {
    let (resp_tx, resp_rx) = oneshot::channel();
    cmd_tx
        .send((cmd, resp_tx))
        .map_err(|_| "daemon command channel closed".to_string())?;
    resp_rx
        .await
        .map_err(|_| "daemon response channel closed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- constant_time_eq tests --

    #[test]
    fn constant_time_eq_identical() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq(b"secret-token", b"secret-tokex"));
        assert!(!constant_time_eq(b"abc", b"ABC"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer-value"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    // -- extract_remote_ip tests --

    #[test]
    fn extract_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());
        assert_eq!(extract_remote_ip(&headers), "10.0.0.1");
    }

    #[test]
    fn extract_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "192.168.1.1".parse().unwrap());
        assert_eq!(extract_remote_ip(&headers), "192.168.1.1");
    }

    #[test]
    fn extract_ip_fallback_to_unknown() {
        let headers = HeaderMap::new();
        assert_eq!(extract_remote_ip(&headers), "unknown");
    }

    #[test]
    fn extract_ip_xff_takes_precedence_over_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        headers.insert("x-real-ip", "192.168.1.1".parse().unwrap());
        assert_eq!(extract_remote_ip(&headers), "10.0.0.1");
    }

    // -- auth_ok tests --

    #[test]
    fn auth_ok_with_query_token() {
        let headers = HeaderMap::new();
        assert!(auth_ok(&headers, Some("my-token"), "my-token"));
    }

    #[test]
    fn auth_ok_with_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer my-token".parse().unwrap(),
        );
        assert!(auth_ok(&headers, None, "my-token"));
    }

    #[test]
    fn auth_ok_with_x_aegis_token_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-aegis-token", "my-token".parse().unwrap());
        assert!(auth_ok(&headers, None, "my-token"));
    }

    #[test]
    fn auth_ok_rejects_wrong_token() {
        let headers = HeaderMap::new();
        assert!(!auth_ok(&headers, Some("wrong"), "my-token"));
    }

    #[test]
    fn auth_ok_rejects_no_credentials() {
        let headers = HeaderMap::new();
        assert!(!auth_ok(&headers, None, "my-token"));
    }

    // -- RateLimiter tests --

    #[test]
    fn rate_limiter_allows_burst() {
        let limiter = RateLimiter::new(3, 1.0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        // Fourth should be blocked (burst exhausted, no time elapsed)
        assert!(!limiter.check(ip));
    }

    #[test]
    fn rate_limiter_different_ips_independent() {
        let limiter = RateLimiter::new(1, 0.0);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip2));
        // Both exhausted independently
        assert!(!limiter.check(ip1));
        assert!(!limiter.check(ip2));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new(1, 1000.0); // Very fast refill
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));
        // Wait a tiny bit -- with 1000 tokens/sec, even 10ms refills ~10 tokens
        std::thread::sleep(Duration::from_millis(10));
        assert!(limiter.check(ip));
    }

    // -- check_rate_limit tests --

    #[test]
    fn check_rate_limit_passes_when_under_limit() {
        let limiter = RateLimiter::new(10, 1.0);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert!(check_rate_limit(&headers, &limiter).is_none());
    }

    #[test]
    fn check_rate_limit_returns_429_when_exceeded() {
        let limiter = RateLimiter::new(1, 0.0);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert!(check_rate_limit(&headers, &limiter).is_none());
        assert_eq!(
            check_rate_limit(&headers, &limiter),
            Some(StatusCode::TOO_MANY_REQUESTS)
        );
    }

    // -- Param struct deserialization tests --

    #[test]
    fn name_params_deserialize() {
        let json = serde_json::json!({"name": "claude-1"});
        let params: NameParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "claude-1");
    }

    #[test]
    fn name_request_params_deserialize() {
        let json = serde_json::json!({"name": "claude-1", "request_id": "abc-123"});
        let params: NameRequestParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "claude-1");
        assert_eq!(params.request_id, "abc-123");
    }

    #[test]
    fn tool_execute_params_deserialize() {
        let json = serde_json::json!({
            "name": "claude-1",
            "action": {"MouseMove": {"x": 100, "y": 200}}
        });
        let params: ToolExecuteParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "claude-1");
        assert!(params.action.is_object());
    }

    // -- GatewayRequest/GatewayResponse serialization tests --

    #[test]
    fn gateway_request_deserialize_minimal() {
        let json = r#"{"method": "ping"}"#;
        let req: GatewayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "ping");
        assert!(req.id.is_none());
    }

    #[test]
    fn gateway_request_deserialize_with_id_and_params() {
        let json = r#"{"id": "1", "method": "agent.start", "params": {"name": "claude-1"}}"#;
        let req: GatewayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id.as_deref(), Some("1"));
        assert_eq!(req.method, "agent.start");
    }

    #[test]
    fn gateway_response_serialization_ok() {
        let resp = GatewayResponse {
            id: Some("1".into()),
            ok: true,
            result: Some(serde_json::json!({"agents": []})),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
        // error field should be skipped
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn gateway_response_serialization_error() {
        let resp = GatewayResponse {
            id: None,
            ok: false,
            result: None,
            error: Some("not found".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("not found"));
        // id and result should be skipped
        assert!(!json.contains("\"id\""));
        assert!(!json.contains("\"result\""));
    }
}
