//! Read-only web dashboard server for the daemon.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

use crate::control::DaemonCmdTx;

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard/index.html");

#[derive(Clone)]
struct DashboardState {
    cmd_tx: DaemonCmdTx,
    token: String,
    base_url: String,
    listen: String,
}

pub fn spawn_dashboard_server(
    listen: String,
    token: String,
    cmd_tx: DaemonCmdTx,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let base_url = format!("http://{listen}");
    let state = DashboardState {
        cmd_tx,
        token,
        base_url,
        listen,
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

fn auth_ok(headers: &HeaderMap, token_query: Option<&str>, token: &str) -> bool {
    if let Some(value) = token_query {
        if value == token {
            return true;
        }
    }
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(text) = auth.to_str() {
            if let Some(rest) = text.strip_prefix("Bearer ") {
                return rest == token;
            }
        }
    }
    if let Some(header) = headers.get("x-aegis-token") {
        if let Ok(text) = header.to_str() {
            return text == token;
        }
    }
    false
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
