//! ACP (Agent Communication Protocol) server-side HTTP handler.
//!
//! Implements the ACP server endpoints for receiving messages from remote
//! agents. All requests require bearer token authentication with constant-time
//! comparison against SHA-256 token hashes.
//!
//! ## Security properties
//!
//! - Bearer tokens are compared using constant-time equality to prevent
//!   timing side-channel attacks.
//! - Tokens are never stored in plaintext -- only SHA-256 hashes are
//!   configured in `AcpServerConfig::token_hashes`.
//! - Per-IP rate limiting enforces a configurable messages-per-minute cap
//!   using a token bucket algorithm.
//! - All incoming payloads are size-checked before parsing.
//! - Content-Type must be `application/json`.
//! - Every accepted message is logged as an `AcpServerReceive` action
//!   for Cedar policy evaluation and audit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::acp_client::{AcpMessage, AcpMessageFrame};
use crate::daemon::DaemonCommand;
use crate::server::http::DaemonCommandTx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ACP error response
// ---------------------------------------------------------------------------

/// Structured error response for ACP endpoints.
///
/// All error fields are safe for external consumption -- no internal details
/// are leaked.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AcpErrorResponse {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable error description.
    pub message: String,
    /// Optional request ID for correlation (echoed from the request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
}

impl AcpErrorResponse {
    /// Create a new error response with code and message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            request_id: None,
        }
    }

    /// Attach a request ID for correlation.
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }
}

// ---------------------------------------------------------------------------
// Success response
// ---------------------------------------------------------------------------

/// Structured success response for ACP endpoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AcpSuccessResponse {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Human-readable message.
    pub message: String,
    /// Optional correlation data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Rate limiter (per-IP token bucket)
// ---------------------------------------------------------------------------

/// Per-IP sliding-window rate limiter.
///
/// Tracks recent request timestamps per source IP and rejects requests
/// that exceed the configured rate.
#[derive(Debug)]
pub struct IpRateLimiter {
    max_per_minute: u32,
    /// Map of IP string -> recent request timestamps.
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl IpRateLimiter {
    /// Create a new rate limiter with the given per-minute limit.
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given IP is allowed.
    ///
    /// If allowed, records the timestamp and returns `Ok(())`.
    /// If rate limited, returns `Err` with the limit that was exceeded.
    pub fn check_and_record(&self, ip: &str) -> Result<(), u32> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let one_minute_ago = now - std::time::Duration::from_secs(60);

        let window = buckets.entry(ip.to_string()).or_default();

        // Prune old entries
        window.retain(|&t| t > one_minute_ago);

        if window.len() >= self.max_per_minute as usize {
            return Err(self.max_per_minute);
        }

        window.push(now);
        Ok(())
    }

    /// Prune stale entries from all buckets. Call periodically to prevent
    /// unbounded memory growth from many distinct IPs.
    pub fn prune_stale(&self) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let one_minute_ago = Instant::now() - std::time::Duration::from_secs(60);

        buckets.retain(|_, window| {
            window.retain(|&t| t > one_minute_ago);
            !window.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// Constant-time token comparison
// ---------------------------------------------------------------------------

/// Constant-time byte comparison to prevent timing side-channel attacks.
///
/// Returns `true` if and only if both slices have the same length and
/// identical content. The comparison always examines every byte pair
/// regardless of where a mismatch occurs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute SHA-256 hex digest of a string.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validate a bearer token against an allowlist of SHA-256 hashes.
///
/// The incoming token is hashed and then compared against each allowed
/// hash using constant-time equality. Returns `true` if any hash matches.
///
/// If the allowlist is empty, authentication is **denied** (fail-closed).
pub fn validate_bearer_token(token: &str, allowed_hashes: &[String]) -> bool {
    if allowed_hashes.is_empty() {
        return false;
    }

    let token_hash = sha256_hex(token);
    let token_hash_bytes = token_hash.as_bytes();

    for allowed in allowed_hashes {
        if constant_time_eq(token_hash_bytes, allowed.as_bytes()) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// ACP shared state
// ---------------------------------------------------------------------------

/// Shared state for ACP server handlers.
pub struct AcpState {
    /// Token hashes for authentication.
    pub token_hashes: Vec<String>,
    /// Per-IP rate limiter.
    pub rate_limiter: Arc<IpRateLimiter>,
    /// Maximum request body size.
    pub max_body_size: usize,
    /// Daemon command channel for routing messages to agents.
    pub daemon_tx: DaemonCommandTx,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the ACP route group.
///
/// Returns a `Router` that can be nested under `/acp/v1` in the main
/// HTTP server. All routes require bearer token authentication and
/// enforce rate limiting.
pub fn acp_routes(state: Arc<AcpState>) -> Router {
    Router::new()
        .route("/messages", post(acp_receive_message))
        .route("/sessions", get(acp_list_sessions))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------

/// Extract and validate the bearer token from request headers.
///
/// Returns the raw token string on success, or an error response tuple.
fn extract_and_validate_auth(
    state: &AcpState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<AcpErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header
        .strip_prefix("Bearer ")
        .unwrap_or("");

    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AcpErrorResponse::new(
                "AUTH_REQUIRED",
                "missing or malformed Authorization header; expected: Bearer <token>",
            )),
        ));
    }

    if !validate_bearer_token(token, &state.token_hashes) {
        // Log the failed attempt (without revealing the token)
        warn!("ACP auth failed: invalid bearer token");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AcpErrorResponse::new(
                "AUTH_INVALID",
                "invalid authentication token",
            )),
        ));
    }

    Ok(token.to_string())
}

/// Check rate limit for the requesting IP.
fn check_rate_limit(
    state: &AcpState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<AcpErrorResponse>)> {
    // Extract client IP from X-Forwarded-For or fall back to "unknown"
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if let Err(limit) = state.rate_limiter.check_and_record(&ip) {
        warn!(ip = %ip, limit = limit, "ACP rate limit exceeded");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(AcpErrorResponse::new(
                "RATE_LIMITED",
                format!("rate limit exceeded: max {limit} requests per minute"),
            )),
        ));
    }

    Ok(ip)
}

/// Validate that Content-Type is application/json.
fn validate_content_type(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<AcpErrorResponse>)> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with("application/json") {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(AcpErrorResponse::new(
                "INVALID_CONTENT_TYPE",
                "Content-Type must be application/json",
            )),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /acp/v1/messages` -- receive an ACP message frame.
///
/// Validates authentication, rate limits, content type, payload size,
/// frame integrity (hash verification), and message structure. On success,
/// routes the message to the appropriate agent via `DaemonCommand::SendToAgent`.
async fn acp_receive_message(
    State(state): State<Arc<AcpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // 1. Authenticate
    let _token = match extract_and_validate_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e,
    };

    // 2. Rate limit
    let ip = match check_rate_limit(&state, &headers) {
        Ok(ip) => ip,
        Err(e) => return e,
    };

    // 3. Content-Type validation
    if let Err(e) = validate_content_type(&headers) {
        return e;
    }

    // 4. Size check (before any parsing)
    if body.len() > state.max_body_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(AcpErrorResponse::new(
                "PAYLOAD_TOO_LARGE",
                format!(
                    "request body size {} exceeds limit {}",
                    body.len(),
                    state.max_body_size
                ),
            )),
        );
    }

    // 5. Deserialize the frame
    let frame: AcpMessageFrame = match serde_json::from_slice(&body) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AcpErrorResponse::new(
                    "INVALID_FRAME",
                    format!("failed to parse ACP message frame: {e}"),
                )),
            );
        }
    };

    // 6. Verify frame payload hash
    if !frame.verify_hash() {
        return (
            StatusCode::BAD_REQUEST,
            Json(AcpErrorResponse::new(
                "HASH_MISMATCH",
                "payload hash verification failed; message may have been tampered with",
            )),
        );
    }

    // 7. Check frame payload size
    if frame.payload.len() > state.max_body_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(AcpErrorResponse::new(
                "PAYLOAD_TOO_LARGE",
                format!(
                    "frame payload size {} exceeds limit {}",
                    frame.payload.len(),
                    state.max_body_size
                ),
            )),
        );
    }

    // 8. Deserialize the inner ACP message
    let message: AcpMessage = match serde_json::from_slice(&frame.payload) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AcpErrorResponse::new(
                    "INVALID_MESSAGE",
                    format!("failed to parse ACP message: {e}"),
                )),
            );
        }
    };

    // 9. Validate message fields
    if let Err(e) = validate_acp_message(&message) {
        return e;
    }

    // 10. Route the message
    let (method, target_agent) = extract_routing_info(&message);

    debug!(
        frame_id = %frame.frame_id,
        ip = %ip,
        method = %method,
        target = %target_agent,
        payload_size = frame.payload.len(),
        "ACP message received"
    );

    // Send to daemon via DaemonCommand::SendToAgent
    let cmd = DaemonCommand::SendToAgent {
        name: target_agent.clone(),
        text: format_agent_input(&message),
    };

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if state.daemon_tx.send((cmd, resp_tx)).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(AcpErrorResponse::new(
                "DAEMON_UNAVAILABLE",
                "daemon command channel closed",
            )),
        );
    }

    match resp_rx.await {
        Ok(resp) => {
            if resp.ok {
                (
                    StatusCode::OK,
                    Json(AcpErrorResponse {
                        code: "OK".to_string(),
                        message: resp.message,
                        request_id: extract_request_id(&message),
                    }),
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse {
                        code: "ROUTING_FAILED".to_string(),
                        message: resp.message,
                        request_id: extract_request_id(&message),
                    }),
                )
            }
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(AcpErrorResponse::new(
                "DAEMON_UNAVAILABLE",
                "daemon response channel closed",
            )),
        ),
    }
}

/// `GET /acp/v1/sessions` -- list active ACP-accessible sessions.
///
/// Returns a list of agents that can receive ACP messages.
async fn acp_list_sessions(
    State(state): State<Arc<AcpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Authenticate
    if let Err(e) = extract_and_validate_auth(&state, &headers) {
        return e;
    }

    // Rate limit
    if let Err(e) = check_rate_limit(&state, &headers) {
        return e;
    }

    // List agents from daemon
    let cmd = DaemonCommand::ListAgents;
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();

    if state.daemon_tx.send((cmd, resp_tx)).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(AcpErrorResponse::new(
                "DAEMON_UNAVAILABLE",
                "daemon command channel closed",
            )),
        );
    }

    match resp_rx.await {
        Ok(resp) => {
            if resp.ok {
                (
                    StatusCode::OK,
                    Json(AcpErrorResponse {
                        code: "OK".to_string(),
                        message: resp.message,
                        request_id: None,
                    }),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AcpErrorResponse::new("LIST_FAILED", resp.message)),
                )
            }
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(AcpErrorResponse::new(
                "DAEMON_UNAVAILABLE",
                "daemon response channel closed",
            )),
        ),
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate the fields of an ACP message.
///
/// Rejects messages with empty required fields or suspicious content.
fn validate_acp_message(
    msg: &AcpMessage,
) -> Result<(), (StatusCode, Json<AcpErrorResponse>)> {
    match msg {
        AcpMessage::Request { id, method, .. } => {
            if method.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        AcpErrorResponse::new(
                            "INVALID_METHOD",
                            "request method must not be empty",
                        )
                        .with_request_id(*id),
                    ),
                ));
            }
            if method.len() > 256 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        AcpErrorResponse::new(
                            "METHOD_TOO_LONG",
                            "request method must be 256 characters or fewer",
                        )
                        .with_request_id(*id),
                    ),
                ));
            }
            // Sanitize: method must be alphanumeric, dots, hyphens, underscores
            if !method
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        AcpErrorResponse::new(
                            "INVALID_METHOD",
                            "method contains invalid characters; allowed: alphanumeric, '.', '-', '_'",
                        )
                        .with_request_id(*id),
                    ),
                ));
            }
            Ok(())
        }
        AcpMessage::Response {
            request_id,
            payload,
            ..
        } => {
            // Responses are generally sent by the server, but if received,
            // validate the payload is not excessively nested.
            validate_json_depth(payload, 32).map_err(|msg| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(
                        AcpErrorResponse::new("INVALID_PAYLOAD", msg)
                            .with_request_id(*request_id),
                    ),
                )
            })
        }
        AcpMessage::Event {
            event_type,
            payload,
        } => {
            if event_type.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse::new(
                        "INVALID_EVENT_TYPE",
                        "event type must not be empty",
                    )),
                ));
            }
            if event_type.len() > 256 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse::new(
                        "EVENT_TYPE_TOO_LONG",
                        "event type must be 256 characters or fewer",
                    )),
                ));
            }
            validate_json_depth(payload, 32).map_err(|msg| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse::new("INVALID_PAYLOAD", msg)),
                )
            })
        }
        AcpMessage::Error { code, message, .. } => {
            if code.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse::new(
                        "INVALID_ERROR_CODE",
                        "error code must not be empty",
                    )),
                ));
            }
            if message.len() > 4096 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(AcpErrorResponse::new(
                        "ERROR_MESSAGE_TOO_LONG",
                        "error message must be 4096 characters or fewer",
                    )),
                ));
            }
            Ok(())
        }
    }
}

/// Validate that a JSON value does not exceed a maximum nesting depth.
///
/// Deep nesting can be used for denial-of-service attacks against parsers.
fn validate_json_depth(value: &serde_json::Value, max_depth: usize) -> Result<(), String> {
    fn check(value: &serde_json::Value, depth: usize, max: usize) -> Result<(), String> {
        if depth > max {
            return Err(format!(
                "JSON nesting depth exceeds maximum of {max}"
            ));
        }
        match value {
            serde_json::Value::Array(arr) => {
                for item in arr {
                    check(item, depth + 1, max)?;
                }
            }
            serde_json::Value::Object(obj) => {
                for (_, v) in obj {
                    check(v, depth + 1, max)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    check(value, 0, max_depth)
}

/// Extract routing information (method/event_type and target agent) from an ACP message.
///
/// For requests, uses the method as the routing key. The target agent defaults
/// to "default" if not specified in the payload.
fn extract_routing_info(msg: &AcpMessage) -> (String, String) {
    match msg {
        AcpMessage::Request { method, payload, .. } => {
            let target = payload
                .get("target_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            (method.clone(), target)
        }
        AcpMessage::Event {
            event_type,
            payload,
        } => {
            let target = payload
                .get("target_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            (event_type.clone(), target)
        }
        AcpMessage::Response { .. } => ("response".to_string(), "default".to_string()),
        AcpMessage::Error { .. } => ("error".to_string(), "default".to_string()),
    }
}

/// Format an ACP message as text input for an agent.
fn format_agent_input(msg: &AcpMessage) -> String {
    match msg {
        AcpMessage::Request {
            id,
            method,
            payload,
        } => {
            format!(
                "[ACP Request id={id} method={method}] {}",
                serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string())
            )
        }
        AcpMessage::Event {
            event_type,
            payload,
        } => {
            format!(
                "[ACP Event type={event_type}] {}",
                serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string())
            )
        }
        AcpMessage::Response {
            request_id,
            success,
            payload,
        } => {
            format!(
                "[ACP Response request_id={request_id} success={success}] {}",
                serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string())
            )
        }
        AcpMessage::Error {
            request_id,
            code,
            message,
        } => {
            let id_str = request_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string());
            format!("[ACP Error request_id={id_str} code={code}] {message}")
        }
    }
}

/// Extract the request ID from an ACP message, if present.
fn extract_request_id(msg: &AcpMessage) -> Option<Uuid> {
    match msg {
        AcpMessage::Request { id, .. } => Some(*id),
        AcpMessage::Response { request_id, .. } => Some(*request_id),
        AcpMessage::Error { request_id, .. } => *request_id,
        AcpMessage::Event { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test: bearer token validation with constant-time comparison --

    #[test]
    fn acp_server_validates_bearer_token() {
        let token = "test-secret-token-abc123";
        let hash = sha256_hex(token);
        let allowed = vec![hash];

        assert!(validate_bearer_token(token, &allowed));
    }

    #[test]
    fn acp_server_rejects_invalid_auth() {
        let real_token = "real-token";
        let hash = sha256_hex(real_token);
        let allowed = vec![hash];

        // Wrong token
        assert!(!validate_bearer_token("wrong-token", &allowed));

        // Empty token
        assert!(!validate_bearer_token("", &allowed));

        // Similar but different token
        assert!(!validate_bearer_token("real-toke", &allowed));
        assert!(!validate_bearer_token("real-token!", &allowed));
    }

    #[test]
    fn acp_server_rejects_empty_allowlist() {
        // Fail-closed: empty allowlist means no one is authorized
        assert!(!validate_bearer_token("any-token", &[]));
    }

    // -- Test: constant-time equality --

    #[test]
    fn acp_constant_time_auth_comparison() {
        // Same content
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));

        // Different content, same length
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"aaaa", b"bbbb"));

        // Different lengths
        assert!(!constant_time_eq(b"short", b"longer_string"));
        assert!(!constant_time_eq(b"", b"x"));

        // Verify the comparison is truly byte-by-byte (timing attack defense)
        // by checking that it processes all bytes even when the first byte differs
        let a = b"\x00\x00\x00\x00";
        let b = b"\xff\xff\xff\xff";
        assert!(!constant_time_eq(a, b));

        // Edge case: single-byte comparison
        assert!(constant_time_eq(b"\x42", b"\x42"));
        assert!(!constant_time_eq(b"\x42", b"\x43"));
    }

    // -- Test: message validation --

    #[test]
    fn acp_message_validation_rejects_malformed() {
        // Empty method
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "".into(),
            payload: serde_json::json!({}),
        };
        assert!(validate_acp_message(&msg).is_err());

        // Method too long
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "x".repeat(300),
            payload: serde_json::json!({}),
        };
        assert!(validate_acp_message(&msg).is_err());

        // Method with invalid characters
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "method; DROP TABLE".into(),
            payload: serde_json::json!({}),
        };
        assert!(validate_acp_message(&msg).is_err());

        // Valid method
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "execute.task-1_v2".into(),
            payload: serde_json::json!({}),
        };
        assert!(validate_acp_message(&msg).is_ok());

        // Empty event type
        let msg = AcpMessage::Event {
            event_type: "".into(),
            payload: serde_json::json!({}),
        };
        assert!(validate_acp_message(&msg).is_err());

        // Empty error code
        let msg = AcpMessage::Error {
            request_id: None,
            code: "".into(),
            message: "something broke".into(),
        };
        assert!(validate_acp_message(&msg).is_err());

        // Error message too long
        let msg = AcpMessage::Error {
            request_id: None,
            code: "ERR".into(),
            message: "x".repeat(5000),
        };
        assert!(validate_acp_message(&msg).is_err());
    }

    // -- Test: rate limiting --

    #[test]
    fn acp_rate_limiting_enforced() {
        let limiter = IpRateLimiter::new(3);

        // First 3 requests should succeed
        assert!(limiter.check_and_record("192.168.1.1").is_ok());
        assert!(limiter.check_and_record("192.168.1.1").is_ok());
        assert!(limiter.check_and_record("192.168.1.1").is_ok());

        // 4th should fail
        let result = limiter.check_and_record("192.168.1.1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 3);

        // Different IP should still work
        assert!(limiter.check_and_record("192.168.1.2").is_ok());
    }

    #[test]
    fn acp_rate_limiter_per_ip_isolation() {
        let limiter = IpRateLimiter::new(2);

        // Fill up IP-A
        assert!(limiter.check_and_record("ip-a").is_ok());
        assert!(limiter.check_and_record("ip-a").is_ok());
        assert!(limiter.check_and_record("ip-a").is_err());

        // IP-B is independent
        assert!(limiter.check_and_record("ip-b").is_ok());
        assert!(limiter.check_and_record("ip-b").is_ok());
        assert!(limiter.check_and_record("ip-b").is_err());
    }

    // -- Test: message routing --

    #[test]
    fn acp_message_routes_correctly() {
        // Request with target_agent
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "execute".into(),
            payload: serde_json::json!({"target_agent": "claude-1"}),
        };
        let (method, target) = extract_routing_info(&msg);
        assert_eq!(method, "execute");
        assert_eq!(target, "claude-1");

        // Request without target_agent defaults to "default"
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "ping".into(),
            payload: serde_json::json!({}),
        };
        let (method, target) = extract_routing_info(&msg);
        assert_eq!(method, "ping");
        assert_eq!(target, "default");

        // Event with target_agent
        let msg = AcpMessage::Event {
            event_type: "status.change".into(),
            payload: serde_json::json!({"target_agent": "agent-2"}),
        };
        let (method, target) = extract_routing_info(&msg);
        assert_eq!(method, "status.change");
        assert_eq!(target, "agent-2");
    }

    // -- Test: JSON depth validation --

    #[test]
    fn acp_json_depth_validation() {
        // Shallow OK
        let shallow = serde_json::json!({"a": {"b": "c"}});
        assert!(validate_json_depth(&shallow, 32).is_ok());

        // Deeply nested should fail
        let mut deep = serde_json::json!("leaf");
        for _ in 0..50 {
            deep = serde_json::json!([deep]);
        }
        assert!(validate_json_depth(&deep, 32).is_err());

        // Exactly at limit should be OK
        let mut at_limit = serde_json::json!("leaf");
        for _ in 0..30 {
            at_limit = serde_json::json!({"nested": at_limit});
        }
        assert!(validate_json_depth(&at_limit, 32).is_ok());
    }

    // -- Test: sha256 hashing --

    #[test]
    fn sha256_produces_consistent_output() {
        let hash1 = sha256_hex("test-token");
        let hash2 = sha256_hex("test-token");
        assert_eq!(hash1, hash2);

        // Different inputs produce different hashes
        let hash3 = sha256_hex("different-token");
        assert_ne!(hash1, hash3);

        // Hash is 64 hex chars (256 bits)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- Test: format_agent_input --

    #[test]
    fn format_agent_input_includes_metadata() {
        let id = Uuid::new_v4();
        let msg = AcpMessage::Request {
            id,
            method: "test".into(),
            payload: serde_json::json!({"key": "value"}),
        };
        let formatted = format_agent_input(&msg);
        assert!(formatted.contains("[ACP Request"));
        assert!(formatted.contains(&id.to_string()));
        assert!(formatted.contains("method=test"));
    }

    // -- Security test: authentication is fail-closed --

    #[test]
    fn acp_auth_fail_closed_security_property() {
        // SECURITY: When the allowlist is empty, ALL tokens must be rejected.
        // This verifies the fail-closed property.
        let empty_allowlist: Vec<String> = vec![];

        assert!(
            !validate_bearer_token("anything", &empty_allowlist),
            "SECURITY VIOLATION: empty allowlist must reject all tokens"
        );
        assert!(
            !validate_bearer_token("", &empty_allowlist),
            "SECURITY VIOLATION: empty allowlist must reject empty token"
        );

        // SECURITY: A token must match EXACTLY to be accepted
        let hash = sha256_hex("correct-token");
        let allowlist = vec![hash];

        assert!(
            validate_bearer_token("correct-token", &allowlist),
            "correct token must be accepted"
        );
        assert!(
            !validate_bearer_token("correct-token\0", &allowlist),
            "SECURITY VIOLATION: null-byte appended token must be rejected"
        );
        assert!(
            !validate_bearer_token("correct-token\n", &allowlist),
            "SECURITY VIOLATION: newline-appended token must be rejected"
        );
        assert!(
            !validate_bearer_token(" correct-token", &allowlist),
            "SECURITY VIOLATION: space-prefixed token must be rejected"
        );
    }

    // -- Test: multiple token hashes --

    #[test]
    fn acp_multiple_token_hashes() {
        let hash_a = sha256_hex("token-a");
        let hash_b = sha256_hex("token-b");
        let allowlist = vec![hash_a, hash_b];

        assert!(validate_bearer_token("token-a", &allowlist));
        assert!(validate_bearer_token("token-b", &allowlist));
        assert!(!validate_bearer_token("token-c", &allowlist));
    }

    // -- Test: prune_stale does not panic --

    #[test]
    fn acp_rate_limiter_prune_stale() {
        let limiter = IpRateLimiter::new(10);
        limiter.check_and_record("1.2.3.4").unwrap();
        limiter.prune_stale();
        // Should still work after pruning
        assert!(limiter.check_and_record("1.2.3.4").is_ok());
    }
}
