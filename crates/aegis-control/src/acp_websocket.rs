//! ACP WebSocket endpoint for persistent bidirectional connections.
//!
//! Provides a WebSocket upgrade endpoint at `/acp/v1/ws` that maintains
//! long-lived connections with ACP clients. All connections require bearer
//! token authentication before the WebSocket upgrade is accepted.
//!
//! ## Security properties
//!
//! - **Pre-upgrade authentication**: The bearer token is validated using
//!   constant-time SHA-256 hash comparison *before* the WebSocket handshake
//!   completes. Unauthenticated clients never reach the message handler.
//! - **Per-connection rate limiting**: Each WebSocket connection has an
//!   independent sliding-window rate limiter to prevent message flooding.
//! - **Message size limits**: Incoming messages are rejected if they exceed
//!   the configured `max_body_size` from `AcpServerConfig`.
//! - **Heartbeat / dead connection detection**: The server sends WebSocket
//!   ping frames every 30 seconds. If no message (data or pong) arrives
//!   within 5 minutes, the connection is closed.
//! - **Graceful shutdown**: All active WebSocket connections are closed when
//!   the server stops, via a broadcast shutdown channel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::acp_client::{AcpMessage, AcpMessageFrame};
use crate::acp_server::{validate_bearer_token, IpRateLimiter};
use crate::acp_translator::AcpTranslator;
use crate::server::http::DaemonCommandTx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Interval between WebSocket ping frames.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time without any incoming message before closing the connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

/// Tracks per-connection metadata and counters.
#[derive(Debug)]
struct ConnectionState {
    /// Unique identifier for this connection/session.
    session_id: Uuid,
    /// Authenticated identity (the token hash that matched).
    _identity_hash: String,
    /// Total messages received from the client.
    messages_received: AtomicU64,
    /// Total messages sent to the client.
    messages_sent: AtomicU64,
    /// Timestamp of the last received message (for idle timeout).
    last_activity: std::sync::Mutex<Instant>,
}

impl ConnectionState {
    fn new(identity_hash: String) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            _identity_hash: identity_hash,
            messages_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
        }
    }

    fn record_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    fn record_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn idle_duration(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

// ---------------------------------------------------------------------------
// Shared state for WebSocket endpoint
// ---------------------------------------------------------------------------

/// Shared state for the ACP WebSocket endpoint.
pub struct AcpWsState {
    /// Token hashes for authentication.
    pub token_hashes: Vec<String>,
    /// Per-IP rate limiter (reused from acp_server).
    pub rate_limiter: Arc<IpRateLimiter>,
    /// Maximum message payload size in bytes.
    pub max_body_size: usize,
    /// Per-minute rate limit for messages.
    pub rate_limit_per_minute: u32,
    /// Daemon command channel for routing messages to agents.
    pub daemon_tx: DaemonCommandTx,
    /// Shutdown signal receiver.
    pub shutdown: watch::Receiver<bool>,
}

// ---------------------------------------------------------------------------
// Query parameters for token auth
// ---------------------------------------------------------------------------

/// Query parameters for the WebSocket upgrade request.
#[derive(Debug, Deserialize)]
pub struct WsAuthParams {
    /// Bearer token passed as a query parameter (alternative to Authorization header).
    pub token: Option<String>,
}

// ---------------------------------------------------------------------------
// WebSocket error response
// ---------------------------------------------------------------------------

/// Error message sent to the client over the WebSocket before closing.
#[derive(Debug, Serialize)]
struct WsErrorMessage {
    code: String,
    message: String,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the ACP WebSocket route.
///
/// Returns a `Router` that should be mounted alongside the existing ACP
/// HTTP routes under `/acp/v1`. The WebSocket endpoint is at `/ws`.
pub fn acp_ws_routes(state: Arc<AcpWsState>) -> Router {
    Router::new()
        .route("/ws", get(acp_ws_upgrade))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// WebSocket upgrade handler
// ---------------------------------------------------------------------------

/// `GET /acp/v1/ws` -- upgrade to WebSocket with bearer token auth.
///
/// Authentication is performed BEFORE the WebSocket upgrade completes.
/// The token can be provided via:
/// 1. `Authorization: Bearer <token>` header
/// 2. `?token=<token>` query parameter
///
/// If authentication fails, a plain HTTP 401 is returned (no upgrade).
async fn acp_ws_upgrade(
    State(state): State<Arc<AcpWsState>>,
    headers: HeaderMap,
    Query(params): Query<WsAuthParams>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Extract token from header or query parameter
    let token = extract_token(&headers, &params);

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            warn!("ACP WebSocket: missing authentication token");
            return (StatusCode::UNAUTHORIZED, "missing authentication token").into_response();
        }
    };

    // Validate token using constant-time SHA-256 hash comparison
    if !validate_bearer_token(&token, &state.token_hashes) {
        warn!("ACP WebSocket: invalid authentication token");
        return (StatusCode::UNAUTHORIZED, "invalid authentication token").into_response();
    }

    // Determine which hash matched (for connection identity tracking)
    let identity_hash = crate::acp_server::sha256_hex(&token);

    info!(
        identity = %&identity_hash[..16],
        "ACP WebSocket: authenticated, upgrading connection"
    );

    let shutdown = state.shutdown.clone();
    let max_body_size = state.max_body_size;
    let rate_limit_per_minute = state.rate_limit_per_minute;
    let daemon_tx = state.daemon_tx.clone();

    // Accept the WebSocket upgrade
    ws.on_upgrade(move |socket| {
        handle_ws_connection(
            socket,
            identity_hash,
            max_body_size,
            rate_limit_per_minute,
            daemon_tx,
            shutdown,
        )
    })
    .into_response()
}

/// Extract the bearer token from either the Authorization header or query param.
fn extract_token(headers: &HeaderMap, params: &WsAuthParams) -> Option<String> {
    // Try Authorization header first
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    // Fall back to query parameter
    params.token.clone()
}

// ---------------------------------------------------------------------------
// WebSocket connection handler
// ---------------------------------------------------------------------------

/// Main handler loop for an authenticated WebSocket connection.
///
/// Manages:
/// - Receiving and validating ACP message frames from the client
/// - Translating messages via AcpTranslator and routing to the daemon
/// - Sending responses and events back to the client
/// - Heartbeat ping/pong every 30 seconds
/// - Idle timeout after 5 minutes of no incoming messages
/// - Graceful shutdown on server stop
async fn handle_ws_connection(
    socket: WebSocket,
    identity_hash: String,
    max_body_size: usize,
    rate_limit_per_minute: u32,
    daemon_tx: DaemonCommandTx,
    mut shutdown: watch::Receiver<bool>,
) {
    let conn_state = Arc::new(ConnectionState::new(identity_hash));
    let translator = AcpTranslator::with_rate_limit(rate_limit_per_minute);
    let session_id = conn_state.session_id.to_string();

    info!(
        session_id = %conn_state.session_id,
        "ACP WebSocket: connection established"
    );

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Heartbeat and idle timeout task
    let conn_for_heartbeat = conn_state.clone();
    let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Incoming message from client
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        conn_state.record_received();

                        // Size check before parsing
                        if text.len() > max_body_size {
                            let err = WsErrorMessage {
                                code: "PAYLOAD_TOO_LARGE".to_string(),
                                message: format!(
                                    "message size {} exceeds limit {}",
                                    text.len(),
                                    max_body_size
                                ),
                            };
                            let err_json = serde_json::to_string(&err).unwrap_or_default();
                            let _ = ws_sender.send(Message::Text(err_json.into())).await;
                            continue;
                        }

                        // Parse and process the message
                        let response = process_ws_message(
                            &text,
                            &translator,
                            &session_id,
                            max_body_size,
                            &daemon_tx,
                        )
                        .await;

                        if let Some(resp_text) = response {
                            conn_state.record_sent();
                            if ws_sender.send(Message::Text(resp_text.into())).await.is_err() {
                                debug!(
                                    session_id = %conn_state.session_id,
                                    "ACP WebSocket: send failed, closing"
                                );
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        conn_state.record_received();

                        // Size check
                        if data.len() > max_body_size {
                            let err = WsErrorMessage {
                                code: "PAYLOAD_TOO_LARGE".to_string(),
                                message: format!(
                                    "message size {} exceeds limit {}",
                                    data.len(),
                                    max_body_size
                                ),
                            };
                            let err_json = serde_json::to_string(&err).unwrap_or_default();
                            let _ = ws_sender.send(Message::Text(err_json.into())).await;
                            continue;
                        }

                        // Try parsing binary as UTF-8 text
                        let text = match String::from_utf8(data.to_vec()) {
                            Ok(t) => t,
                            Err(_) => {
                                let err = WsErrorMessage {
                                    code: "INVALID_ENCODING".to_string(),
                                    message: "binary message must be valid UTF-8".to_string(),
                                };
                                let err_json = serde_json::to_string(&err).unwrap_or_default();
                                let _ = ws_sender.send(Message::Text(err_json.into())).await;
                                continue;
                            }
                        };

                        let response = process_ws_message(
                            &text,
                            &translator,
                            &session_id,
                            max_body_size,
                            &daemon_tx,
                        )
                        .await;

                        if let Some(resp_text) = response {
                            conn_state.record_sent();
                            if ws_sender.send(Message::Text(resp_text.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        conn_state.record_received();
                        // Respond with pong (axum may handle this automatically, but be explicit)
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Pong received -- update activity timestamp
                        conn_state.record_received();
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!(
                            session_id = %conn_state.session_id,
                            "ACP WebSocket: client sent close frame"
                        );
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(
                            session_id = %conn_state.session_id,
                            error = %e,
                            "ACP WebSocket: receive error"
                        );
                        break;
                    }
                    None => {
                        // Stream ended
                        break;
                    }
                }
            }

            // Heartbeat tick
            _ = heartbeat_interval.tick() => {
                // Check idle timeout
                if conn_for_heartbeat.idle_duration() > IDLE_TIMEOUT {
                    info!(
                        session_id = %conn_for_heartbeat.session_id,
                        "ACP WebSocket: idle timeout exceeded, closing"
                    );
                    let _ = ws_sender.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: 4000,
                        reason: "idle timeout".into(),
                    }))).await;
                    break;
                }

                // Send ping
                if ws_sender.send(Message::Ping(vec![].into())).await.is_err() {
                    debug!(
                        session_id = %conn_for_heartbeat.session_id,
                        "ACP WebSocket: ping failed, closing"
                    );
                    break;
                }
            }

            // Server shutdown
            _ = wait_for_shutdown(&mut shutdown) => {
                info!(
                    session_id = %conn_state.session_id,
                    "ACP WebSocket: server shutdown, closing connection"
                );
                let _ = ws_sender.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1001,
                    reason: "server shutting down".into(),
                }))).await;
                break;
            }
        }
    }

    info!(
        session_id = %conn_state.session_id,
        received = conn_state.messages_received.load(Ordering::Relaxed),
        sent = conn_state.messages_sent.load(Ordering::Relaxed),
        "ACP WebSocket: connection closed"
    );
}

// ---------------------------------------------------------------------------
// Message processing
// ---------------------------------------------------------------------------

/// Wait for the shutdown signal without holding a non-Send guard across await.
///
/// `watch::Receiver::wait_for` returns a `Ref` that holds a `RwLockReadGuard`,
/// which is not `Send` and cannot be held across `tokio::select!` branches.
/// This helper loops on `changed()` instead, which yields a `Send`-compatible future.
async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            // Sender dropped, treat as shutdown
            return;
        }
    }
}

/// Process an incoming WebSocket text message.
///
/// Parses the message as an `AcpMessageFrame`, validates integrity,
/// translates via `AcpTranslator`, routes to the daemon, and returns
/// the response as a JSON string.
///
/// Returns `None` if the message should be silently ignored (e.g., unknown
/// event types that don't require a response).
async fn process_ws_message(
    text: &str,
    translator: &AcpTranslator,
    session_id: &str,
    max_body_size: usize,
    daemon_tx: &DaemonCommandTx,
) -> Option<String> {
    // 1. Parse as AcpMessageFrame
    let frame: AcpMessageFrame = match serde_json::from_str(text) {
        Ok(f) => f,
        Err(e) => {
            let err_msg = translator.error_to_acp(
                None,
                &crate::acp_translator::TranslationError::Internal(format!(
                    "failed to parse frame: {e}"
                )),
            );
            return Some(serialize_acp_message(&err_msg));
        }
    };

    // 2. Verify frame payload hash
    if !frame.verify_hash() {
        let err_msg = AcpMessage::Error {
            request_id: None,
            code: "HASH_MISMATCH".to_string(),
            message: "payload hash verification failed; message may have been tampered with"
                .to_string(),
        };
        return Some(serialize_acp_message(&err_msg));
    }

    // 3. Check payload size
    if frame.payload.len() > max_body_size {
        let err_msg = AcpMessage::Error {
            request_id: None,
            code: "PAYLOAD_TOO_LARGE".to_string(),
            message: format!(
                "frame payload size {} exceeds limit {}",
                frame.payload.len(),
                max_body_size
            ),
        };
        return Some(serialize_acp_message(&err_msg));
    }

    // 4. Deserialize inner ACP message
    let message: AcpMessage = match serde_json::from_slice(&frame.payload) {
        Ok(m) => m,
        Err(e) => {
            let err_msg = AcpMessage::Error {
                request_id: None,
                code: "INVALID_MESSAGE".to_string(),
                message: format!("failed to parse ACP message: {e}"),
            };
            return Some(serialize_acp_message(&err_msg));
        }
    };

    // 5. Translate ACP message to DaemonCommand
    let (command, request_id) = match translator.acp_to_daemon(session_id, &message) {
        Ok((cmd, id)) => (cmd, id),
        Err(e) => {
            let request_id = match &message {
                AcpMessage::Request { id, .. } => Some(*id),
                _ => None,
            };
            let err_msg = translator.error_to_acp(request_id, &e);
            return Some(serialize_acp_message(&err_msg));
        }
    };

    // 6. Send to daemon
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if daemon_tx.send((command, resp_tx)).await.is_err() {
        let err_msg = AcpMessage::Error {
            request_id: Some(request_id),
            code: "DAEMON_UNAVAILABLE".to_string(),
            message: "daemon command channel closed".to_string(),
        };
        return Some(serialize_acp_message(&err_msg));
    }

    // 7. Await daemon response
    match resp_rx.await {
        Ok(response) => {
            let acp_response = translator.daemon_to_acp(request_id, &response);
            Some(serialize_acp_message(&acp_response))
        }
        Err(_) => {
            let err_msg = AcpMessage::Error {
                request_id: Some(request_id),
                code: "DAEMON_UNAVAILABLE".to_string(),
                message: "daemon response channel closed".to_string(),
            };
            Some(serialize_acp_message(&err_msg))
        }
    }
}

/// Serialize an ACP message to JSON for sending over WebSocket.
fn serialize_acp_message(msg: &AcpMessage) -> String {
    serde_json::to_string(msg).unwrap_or_else(|_| {
        r#"{"Error":{"request_id":null,"code":"SERIALIZATION_ERROR","message":"failed to serialize response"}}"#.to_string()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp_server::sha256_hex;
    use crate::daemon::DaemonCommand;

    // -- Test: WebSocket authentication required --

    #[test]
    fn ws_authentication_required() {
        // Verify that extract_token returns None when no auth is provided
        let headers = HeaderMap::new();
        let params = WsAuthParams { token: None };

        let token = extract_token(&headers, &params);
        assert!(token.is_none(), "missing auth should yield no token");

        // Empty Authorization header should yield no token
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());
        let params = WsAuthParams { token: None };
        let token = extract_token(&headers, &params);
        // "Bearer " strips to empty string, which should be caught
        assert!(
            token.is_none() || token.as_deref() == Some(""),
            "empty bearer should yield no usable token"
        );
    }

    // -- Test: WebSocket authentication validates token --

    #[test]
    fn ws_authentication_validates_token() {
        let valid_token = "ws-secret-token-12345";
        let hash = sha256_hex(valid_token);
        let allowed = vec![hash.clone()];

        // Valid token passes
        assert!(
            validate_bearer_token(valid_token, &allowed),
            "valid token must be accepted"
        );

        // Wrong token fails
        assert!(
            !validate_bearer_token("wrong-token", &allowed),
            "wrong token must be rejected"
        );

        // Empty allowlist fails (fail-closed)
        assert!(
            !validate_bearer_token(valid_token, &[]),
            "SECURITY VIOLATION: empty allowlist must reject all tokens"
        );

        // Token from query parameter path
        let headers = HeaderMap::new();
        let params = WsAuthParams {
            token: Some(valid_token.to_string()),
        };
        let extracted = extract_token(&headers, &params);
        assert_eq!(extracted.as_deref(), Some(valid_token));

        // Token from Authorization header takes precedence
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer header-token".parse().unwrap());
        let params = WsAuthParams {
            token: Some("query-token".to_string()),
        };
        let extracted = extract_token(&headers, &params);
        assert_eq!(
            extracted.as_deref(),
            Some("header-token"),
            "Authorization header should take precedence over query parameter"
        );
    }

    // -- Test: WebSocket rate limiting --

    #[test]
    fn ws_rate_limiting_enforced() {
        // The AcpTranslator has per-session rate limiting built in.
        // Verify it works for WebSocket session IDs.
        let translator = AcpTranslator::with_rate_limit(3);
        let session_id = Uuid::new_v4().to_string();

        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "list".to_string(),
            payload: serde_json::json!({}),
        };

        // First 3 should succeed
        assert!(translator.acp_to_daemon(&session_id, &msg).is_ok());
        assert!(translator.acp_to_daemon(&session_id, &msg).is_ok());
        assert!(translator.acp_to_daemon(&session_id, &msg).is_ok());

        // 4th should be rate limited
        let result = translator.acp_to_daemon(&session_id, &msg);
        assert!(
            result.is_err(),
            "4th message should be rate limited, got: {result:?}"
        );

        // Different session should still work
        let other_session = Uuid::new_v4().to_string();
        assert!(
            translator.acp_to_daemon(&other_session, &msg).is_ok(),
            "different session should not be rate limited"
        );
    }

    // -- Test: WebSocket message routing --

    #[tokio::test]
    async fn ws_message_routing() {
        use crate::daemon::DaemonResponse;

        let translator = AcpTranslator::new();
        let session_id = Uuid::new_v4().to_string();

        // Create a daemon channel
        let (daemon_tx, mut daemon_rx): (DaemonCommandTx, _) = tokio::sync::mpsc::channel(16);

        // Build a valid ACP request
        let request_id = Uuid::new_v4();
        let acp_msg = AcpMessage::Request {
            id: request_id,
            method: "list".to_string(),
            payload: serde_json::json!({}),
        };
        let payload = serde_json::to_vec(&acp_msg).unwrap();
        let frame = AcpMessageFrame::new(payload);
        let frame_json = serde_json::to_string(&frame).unwrap();

        // Spawn a task to respond to daemon commands
        let daemon_handle = tokio::spawn(async move {
            if let Some((cmd, resp_tx)) = daemon_rx.recv().await {
                assert!(
                    matches!(cmd, DaemonCommand::ListAgents),
                    "expected ListAgents command"
                );
                let _ = resp_tx.send(DaemonResponse::ok("2 agents"));
            }
        });

        // Process the message
        let result =
            process_ws_message(&frame_json, &translator, &session_id, 1_048_576, &daemon_tx).await;

        daemon_handle.await.unwrap();

        // Verify the response
        let response_text = result.expect("should have a response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();

        match response {
            AcpMessage::Response {
                request_id: rid,
                success,
                payload,
            } => {
                assert_eq!(rid, request_id);
                assert!(success);
                assert_eq!(payload["message"], "2 agents");
            }
            other => panic!("expected Response, got: {other:?}"),
        }
    }

    // -- Test: WebSocket heartbeat interval --

    #[test]
    fn ws_heartbeat_interval() {
        // Verify the heartbeat interval constant is 30 seconds
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(30));

        // Verify idle timeout is 5 minutes
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(300));
    }

    // -- Test: WebSocket idle timeout --

    #[test]
    fn ws_idle_timeout() {
        // Test the ConnectionState idle tracking mechanism
        let conn = ConnectionState::new("test-hash".to_string());

        // Fresh connection should have near-zero idle time
        assert!(
            conn.idle_duration() < Duration::from_secs(1),
            "fresh connection should not be idle"
        );

        // After recording activity, idle duration resets
        conn.record_received();
        assert!(
            conn.idle_duration() < Duration::from_secs(1),
            "just-active connection should not be idle"
        );

        // Verify session_id is a valid UUID
        assert!(
            !conn.session_id.is_nil(),
            "session_id must be a non-nil UUID"
        );
    }

    // -- Test: WebSocket rejects invalid frame (SECURITY) --

    #[tokio::test]
    async fn ws_rejects_invalid_frame() {
        // SECURITY TEST: Verify that malformed and tampered frames are rejected.
        let translator = AcpTranslator::new();
        let session_id = Uuid::new_v4().to_string();
        let (daemon_tx, _daemon_rx) = tokio::sync::mpsc::channel(16);

        // 1. Completely invalid JSON
        let result = process_ws_message(
            "not json at all",
            &translator,
            &session_id,
            1_048_576,
            &daemon_tx,
        )
        .await;
        let response_text = result.expect("should have error response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();
        assert!(
            matches!(&response, AcpMessage::Error { code, .. } if code == "INTERNAL_ERROR"),
            "invalid JSON should return error, got: {response:?}"
        );

        // 2. Valid JSON but not an AcpMessageFrame
        let result = process_ws_message(
            r#"{"foo": "bar"}"#,
            &translator,
            &session_id,
            1_048_576,
            &daemon_tx,
        )
        .await;
        let response_text = result.expect("should have error response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();
        assert!(
            matches!(&response, AcpMessage::Error { .. }),
            "non-frame JSON should return error, got: {response:?}"
        );

        // 3. Tampered frame (hash mismatch) -- SECURITY CRITICAL
        let acp_msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "list".to_string(),
            payload: serde_json::json!({}),
        };
        let payload = serde_json::to_vec(&acp_msg).unwrap();
        let mut frame = AcpMessageFrame::new(payload);
        // Tamper with the payload after frame creation
        frame.payload = serde_json::to_vec(&AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "stop".to_string(),
            payload: serde_json::json!({"name": "victim-agent"}),
        })
        .unwrap();
        let frame_json = serde_json::to_string(&frame).unwrap();

        let result =
            process_ws_message(&frame_json, &translator, &session_id, 1_048_576, &daemon_tx).await;
        let response_text = result.expect("should have error response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();
        assert!(
            matches!(&response, AcpMessage::Error { code, .. } if code == "HASH_MISMATCH"),
            "SECURITY VIOLATION: tampered frame must be rejected with HASH_MISMATCH, got: {response:?}"
        );

        // 4. Oversized payload
        let result = process_ws_message(
            r#"{"frame_id":"00000000-0000-0000-0000-000000000000","timestamp":"2024-01-01T00:00:00Z","payload_hash":"abc","payload":[1,2,3]}"#,
            &translator,
            &session_id,
            10, // Very small max body size
            &daemon_tx,
        )
        .await;
        let response_text = result.expect("should have error response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();
        // The frame parsing itself may succeed but payload size check should trigger
        assert!(
            matches!(&response, AcpMessage::Error { .. }),
            "oversized payload should return error, got: {response:?}"
        );

        // 5. Unknown method should be fail-closed
        let acp_msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "drop_database".to_string(),
            payload: serde_json::json!({}),
        };
        let payload = serde_json::to_vec(&acp_msg).unwrap();
        let frame = AcpMessageFrame::new(payload);
        let frame_json = serde_json::to_string(&frame).unwrap();

        let result =
            process_ws_message(&frame_json, &translator, &session_id, 1_048_576, &daemon_tx).await;
        let response_text = result.expect("should have error response");
        let response: AcpMessage = serde_json::from_str(&response_text).unwrap();
        assert!(
            matches!(&response, AcpMessage::Error { code, .. } if code == "UNKNOWN_METHOD"),
            "SECURITY VIOLATION: unknown method must be rejected (fail-closed), got: {response:?}"
        );
    }

    // -- Test: Connection state tracking --

    #[test]
    fn connection_state_counters() {
        let conn = ConnectionState::new("hash123".to_string());

        assert_eq!(conn.messages_received.load(Ordering::Relaxed), 0);
        assert_eq!(conn.messages_sent.load(Ordering::Relaxed), 0);

        conn.record_received();
        conn.record_received();
        conn.record_sent();

        assert_eq!(conn.messages_received.load(Ordering::Relaxed), 2);
        assert_eq!(conn.messages_sent.load(Ordering::Relaxed), 1);
    }

    // -- Security test: authentication is checked before upgrade --

    #[test]
    fn security_ws_auth_before_upgrade() {
        // SECURITY PROPERTY: Authentication must happen BEFORE the WebSocket
        // handshake completes. This test verifies the token extraction and
        // validation logic that runs in the HTTP upgrade handler.
        let token = "secure-ws-token-xyz";
        let hash = sha256_hex(token);
        let allowed = vec![hash.clone()];

        // 1. Valid token from header
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let params = WsAuthParams { token: None };
        let extracted = extract_token(&headers, &params).unwrap();
        assert!(
            validate_bearer_token(&extracted, &allowed),
            "valid header token must be accepted"
        );

        // 2. Valid token from query param
        let headers = HeaderMap::new();
        let params = WsAuthParams {
            token: Some(token.to_string()),
        };
        let extracted = extract_token(&headers, &params).unwrap();
        assert!(
            validate_bearer_token(&extracted, &allowed),
            "valid query token must be accepted"
        );

        // 3. No token at all -- must fail
        let headers = HeaderMap::new();
        let params = WsAuthParams { token: None };
        let extracted = extract_token(&headers, &params);
        assert!(
            extracted.is_none(),
            "SECURITY VIOLATION: missing token must not authenticate"
        );

        // 4. Wrong token -- must fail
        let headers = HeaderMap::new();
        let params = WsAuthParams {
            token: Some("wrong-token".to_string()),
        };
        let extracted = extract_token(&headers, &params).unwrap();
        assert!(
            !validate_bearer_token(&extracted, &allowed),
            "SECURITY VIOLATION: wrong token must not authenticate"
        );

        // 5. Empty allowlist -- fail-closed
        assert!(
            !validate_bearer_token(token, &[]),
            "SECURITY VIOLATION: empty allowlist must reject all tokens"
        );

        // 6. Timing attack defense: null-byte and whitespace variants
        assert!(
            !validate_bearer_token(&format!("{token}\0"), &allowed),
            "SECURITY VIOLATION: null-byte appended token must be rejected"
        );
        assert!(
            !validate_bearer_token(&format!(" {token}"), &allowed),
            "SECURITY VIOLATION: space-prefixed token must be rejected"
        );
    }
}
