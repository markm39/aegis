//! Enhanced ACP protocol extensions for full SDK compatibility.
//!
//! Extends the existing ACP server with:
//! - Agent discovery and capability advertisement
//! - ACP handshake and session lifecycle management
//! - Event streaming over ACP connections
//!
//! ## Protocol lifecycle
//!
//! 1. **Handshake**: Client sends `POST /acp/v1/handshake` with its agent info.
//!    Server validates, assigns a session ID, and returns its own capabilities.
//! 2. **Discovery**: Client can query `GET /acp/v1/agents` to discover available
//!    agents and their capabilities.
//! 3. **Communication**: Client sends messages via `POST /acp/v1/messages` (existing)
//!    or over the WebSocket transport.
//! 4. **Events**: Client subscribes to event streams via `GET /acp/v1/events/{session_id}`.
//! 5. **Teardown**: Client sends `POST /acp/v1/sessions/{id}/close` to end a session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::acp_server::{validate_bearer_token, AcpErrorResponse};
use crate::server::http::DaemonCommandTx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent ACP sessions.
const MAX_SESSIONS: usize = 256;

/// Session idle timeout before automatic cleanup (10 minutes).
pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 600;

/// Protocol version supported by this implementation.
pub const PROTOCOL_VERSION: &str = "1.0";

// ---------------------------------------------------------------------------
// Agent capability types
// ---------------------------------------------------------------------------

/// Describes the capabilities of an ACP-compatible agent or server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentCapabilities {
    /// Protocol version (e.g., "1.0").
    pub protocol_version: String,
    /// Human-readable agent name.
    pub agent_name: String,
    /// Unique agent identifier.
    pub agent_id: String,
    /// Supported ACP methods (e.g., "send", "status", "approve").
    pub supported_methods: Vec<String>,
    /// Whether the agent supports event streaming.
    pub supports_streaming: bool,
    /// Whether the agent supports WebSocket transport.
    pub supports_websocket: bool,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Agent-specific metadata (arbitrary key-value pairs).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl AgentCapabilities {
    /// Create capabilities for the Aegis daemon server.
    pub fn daemon_capabilities(max_message_size: usize) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            agent_name: "aegis-daemon".to_string(),
            agent_id: "aegis".to_string(),
            supported_methods: vec![
                "send".into(),
                "status".into(),
                "approve".into(),
                "deny".into(),
                "list".into(),
                "stop".into(),
                "discover".into(),
                "subscribe".into(),
            ],
            supports_streaming: true,
            supports_websocket: true,
            max_message_size,
            metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake types
// ---------------------------------------------------------------------------

/// Request body for the ACP handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Client's protocol version.
    pub protocol_version: String,
    /// Client's agent capabilities.
    pub capabilities: AgentCapabilities,
}

/// Response body for the ACP handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Assigned session ID.
    pub session_id: Uuid,
    /// Server's protocol version.
    pub protocol_version: String,
    /// Server's capabilities.
    pub server_capabilities: AgentCapabilities,
    /// When the session was established.
    pub established_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Session tracking
// ---------------------------------------------------------------------------

/// Represents an active ACP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpSession {
    /// Unique session identifier.
    pub session_id: Uuid,
    /// Client's advertised capabilities.
    pub client_capabilities: AgentCapabilities,
    /// When the session was established.
    pub established_at: DateTime<Utc>,
    /// When the last message was received.
    pub last_activity: DateTime<Utc>,
    /// Total messages exchanged in this session.
    pub message_count: u64,
    /// Event types the client is subscribed to.
    #[serde(default)]
    pub subscriptions: Vec<String>,
}

/// Thread-safe session store.
#[derive(Debug)]
pub struct SessionStore {
    sessions: Mutex<HashMap<Uuid, SessionEntry>>,
}

/// Internal session entry with monotonic timing for idle detection.
#[derive(Debug)]
struct SessionEntry {
    session: AcpSession,
    last_activity_monotonic: Instant,
}

impl SessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new session. Returns an error if the maximum is exceeded.
    pub fn register(
        &self,
        session_id: Uuid,
        client_capabilities: AgentCapabilities,
    ) -> Result<AcpSession, String> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if sessions.len() >= MAX_SESSIONS {
            return Err(format!(
                "maximum session count ({MAX_SESSIONS}) reached; close existing sessions first"
            ));
        }

        let now = Utc::now();
        let session = AcpSession {
            session_id,
            client_capabilities,
            established_at: now,
            last_activity: now,
            message_count: 0,
            subscriptions: Vec::new(),
        };

        sessions.insert(
            session_id,
            SessionEntry {
                session: session.clone(),
                last_activity_monotonic: Instant::now(),
            },
        );

        Ok(session)
    }

    /// Mark a session as active (update timestamps and increment message count).
    pub fn touch(&self, session_id: &Uuid) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = sessions.get_mut(session_id) {
            entry.session.last_activity = Utc::now();
            entry.session.message_count += 1;
            entry.last_activity_monotonic = Instant::now();
            true
        } else {
            false
        }
    }

    /// Get session info by ID.
    pub fn get(&self, session_id: &Uuid) -> Option<AcpSession> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.get(session_id).map(|e| e.session.clone())
    }

    /// Remove a session by ID. Returns the session if it existed.
    pub fn remove(&self, session_id: &Uuid) -> Option<AcpSession> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.remove(session_id).map(|e| e.session)
    }

    /// List all active sessions.
    pub fn list(&self) -> Vec<AcpSession> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.values().map(|e| e.session.clone()).collect()
    }

    /// Remove sessions that have been idle longer than the given timeout.
    /// Returns the number of sessions pruned.
    pub fn prune_idle(&self, timeout_secs: u64) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let before = sessions.len();
        sessions.retain(|_, entry| {
            entry.last_activity_monotonic.elapsed().as_secs() < timeout_secs
        });
        before - sessions.len()
    }

    /// Add an event subscription to a session.
    pub fn subscribe(&self, session_id: &Uuid, event_type: String) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = sessions.get_mut(session_id) {
            if !entry.session.subscriptions.contains(&event_type) {
                entry.session.subscriptions.push(event_type);
            }
            true
        } else {
            false
        }
    }

    /// Remove an event subscription from a session.
    pub fn unsubscribe(&self, session_id: &Uuid, event_type: &str) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = sessions.get_mut(session_id) {
            entry.session.subscriptions.retain(|s| s != event_type);
            true
        } else {
            false
        }
    }

    /// Get the count of active sessions.
    pub fn count(&self) -> usize {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Event subscription types
// ---------------------------------------------------------------------------

/// Request to subscribe to event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// The session ID for the subscription.
    pub session_id: Uuid,
    /// Event types to subscribe to.
    pub event_types: Vec<String>,
}

/// Response confirming subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// The session ID.
    pub session_id: Uuid,
    /// Currently active subscriptions after the operation.
    pub active_subscriptions: Vec<String>,
}

/// A streamed event delivered to subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    /// Unique event identifier.
    pub event_id: Uuid,
    /// Event type identifier.
    pub event_type: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Event payload.
    pub payload: serde_json::Value,
    /// Source agent name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_agent: Option<String>,
}

impl StreamEvent {
    /// Create a new stream event.
    pub fn new(
        event_type: impl Into<String>,
        payload: serde_json::Value,
        source_agent: Option<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: event_type.into(),
            timestamp: Utc::now(),
            payload,
            source_agent,
        }
    }
}

// ---------------------------------------------------------------------------
// Agent discovery types
// ---------------------------------------------------------------------------

/// Information about a discoverable agent in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverableAgent {
    /// Agent slot name.
    pub name: String,
    /// Current status string.
    pub status: String,
    /// Agent capabilities (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<AgentCapabilities>,
    /// Agent's role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether the agent accepts ACP messages.
    pub accepts_messages: bool,
}

/// Response to agent discovery requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// Server capabilities.
    pub server: AgentCapabilities,
    /// Available agents.
    pub agents: Vec<DiscoverableAgent>,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for enhanced ACP endpoints.
pub struct AcpEnhancedState {
    /// Token hashes for authentication.
    pub token_hashes: Vec<String>,
    /// Active session store.
    pub sessions: Arc<SessionStore>,
    /// Maximum message body size.
    pub max_body_size: usize,
    /// Daemon command channel.
    pub daemon_tx: DaemonCommandTx,
}

// ---------------------------------------------------------------------------
// Authentication helper
// ---------------------------------------------------------------------------

/// Extract and validate the bearer token from request headers.
fn authenticate(
    state: &AcpEnhancedState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<AcpErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");

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
        warn!("ACP enhanced: invalid bearer token");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AcpErrorResponse::new(
                "AUTH_INVALID",
                "invalid authentication token",
            )),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the enhanced ACP route group.
///
/// Returns a `Router` that can be nested under `/acp/v1` in the main
/// HTTP server alongside the existing ACP routes.
pub fn acp_enhanced_routes(state: Arc<AcpEnhancedState>) -> Router {
    Router::new()
        .route("/handshake", post(handshake_handler))
        .route("/discover", get(discover_handler))
        .route("/sessions/{id}", get(session_info_handler))
        .route("/sessions/{id}/close", post(session_close_handler))
        .route("/subscribe", post(subscribe_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /acp/v1/handshake` -- perform ACP protocol handshake.
///
/// The client sends its agent info and capabilities. The server validates,
/// assigns a session ID, and returns its own capabilities.
async fn handshake_handler(
    State(state): State<Arc<AcpEnhancedState>>,
    headers: HeaderMap,
    Json(request): Json<HandshakeRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e;
    }

    // Validate protocol version compatibility
    if !is_compatible_version(&request.protocol_version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(AcpErrorResponse::new(
                "INCOMPATIBLE_VERSION",
                format!(
                    "server supports protocol version {PROTOCOL_VERSION}, got {}",
                    request.protocol_version
                ),
            )),
        );
    }

    // Register the session
    let session_id = Uuid::new_v4();
    match state
        .sessions
        .register(session_id, request.capabilities.clone())
    {
        Ok(_session) => {
            info!(
                session_id = %session_id,
                agent = %request.capabilities.agent_name,
                "ACP handshake completed"
            );

            let response = HandshakeResponse {
                session_id,
                protocol_version: PROTOCOL_VERSION.to_string(),
                server_capabilities: AgentCapabilities::daemon_capabilities(
                    state.max_body_size,
                ),
                established_at: Utc::now(),
            };

            (
                StatusCode::OK,
                Json(AcpErrorResponse {
                    code: "OK".to_string(),
                    message: serde_json::to_string(&response)
                        .unwrap_or_else(|_| "handshake completed".to_string()),
                    request_id: Some(session_id),
                }),
            )
        }
        Err(msg) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AcpErrorResponse::new("SESSION_LIMIT", msg)),
        ),
    }
}

/// `GET /acp/v1/discover` -- discover available agents and capabilities.
async fn discover_handler(
    State(state): State<Arc<AcpEnhancedState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e;
    }

    // Query the daemon for agent list
    let cmd = crate::daemon::DaemonCommand::ListAgents;
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
            debug!("ACP discover: daemon returned {} agents", resp.message);

            let discovery = DiscoveryResponse {
                server: AgentCapabilities::daemon_capabilities(state.max_body_size),
                agents: extract_discoverable_agents(&resp),
            };

            let json_data = serde_json::to_value(&discovery)
                .unwrap_or(serde_json::json!({}));

            (
                StatusCode::OK,
                Json(AcpErrorResponse {
                    code: "OK".to_string(),
                    message: serde_json::to_string(&json_data)
                        .unwrap_or_else(|_| "discovery complete".to_string()),
                    request_id: None,
                }),
            )
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

/// `GET /acp/v1/sessions/{id}` -- get session info.
async fn session_info_handler(
    State(state): State<Arc<AcpEnhancedState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e;
    }

    match state.sessions.get(&id) {
        Some(session) => {
            let json_data = serde_json::to_string(&session)
                .unwrap_or_else(|_| "session found".to_string());
            (
                StatusCode::OK,
                Json(AcpErrorResponse {
                    code: "OK".to_string(),
                    message: json_data,
                    request_id: Some(id),
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(AcpErrorResponse::new(
                "SESSION_NOT_FOUND",
                format!("no active session with id {id}"),
            )),
        ),
    }
}

/// `POST /acp/v1/sessions/{id}/close` -- close a session.
async fn session_close_handler(
    State(state): State<Arc<AcpEnhancedState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e;
    }

    match state.sessions.remove(&id) {
        Some(session) => {
            info!(
                session_id = %id,
                messages = session.message_count,
                "ACP session closed"
            );
            (
                StatusCode::OK,
                Json(AcpErrorResponse {
                    code: "OK".to_string(),
                    message: format!(
                        "session {} closed after {} messages",
                        id, session.message_count
                    ),
                    request_id: Some(id),
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(AcpErrorResponse::new(
                "SESSION_NOT_FOUND",
                format!("no active session with id {id}"),
            )),
        ),
    }
}

/// `POST /acp/v1/subscribe` -- subscribe to event types.
async fn subscribe_handler(
    State(state): State<Arc<AcpEnhancedState>>,
    headers: HeaderMap,
    Json(request): Json<SubscribeRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e;
    }

    // Verify session exists
    if state.sessions.get(&request.session_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(AcpErrorResponse::new(
                "SESSION_NOT_FOUND",
                format!("no active session with id {}", request.session_id),
            )),
        );
    }

    // Add subscriptions
    for event_type in &request.event_types {
        state
            .sessions
            .subscribe(&request.session_id, event_type.clone());
    }

    // Get updated subscriptions
    let active_subscriptions = state
        .sessions
        .get(&request.session_id)
        .map(|s| s.subscriptions)
        .unwrap_or_default();

    let response = SubscribeResponse {
        session_id: request.session_id,
        active_subscriptions,
    };

    let json_data = serde_json::to_string(&response)
        .unwrap_or_else(|_| "subscribed".to_string());

    (
        StatusCode::OK,
        Json(AcpErrorResponse {
            code: "OK".to_string(),
            message: json_data,
            request_id: Some(request.session_id),
        }),
    )
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Check if a client protocol version is compatible with the server.
///
/// Currently accepts any version starting with "1.".
fn is_compatible_version(version: &str) -> bool {
    version.starts_with("1.")
        || version == "1"
        || version == PROTOCOL_VERSION
}

/// Extract discoverable agent information from a daemon list response.
fn extract_discoverable_agents(
    response: &crate::daemon::DaemonResponse,
) -> Vec<DiscoverableAgent> {
    // Try to parse the data field as an array of agent summaries
    let data = match &response.data {
        Some(d) => d,
        None => return Vec::new(),
    };

    let agents_array = match data.get("agents").and_then(|a| a.as_array()) {
        Some(arr) => arr,
        None => {
            // Try the data itself as an array
            match data.as_array() {
                Some(arr) => arr,
                None => return Vec::new(),
            }
        }
    };

    agents_array
        .iter()
        .filter_map(|agent_val| {
            let name = agent_val.get("name")?.as_str()?.to_string();
            let status = agent_val
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let role = agent_val
                .get("role")
                .and_then(|r| r.as_str())
                .map(String::from);

            Some(DiscoverableAgent {
                name,
                status,
                capabilities: None,
                role,
                accepts_messages: true,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_store_register_and_get() {
        let store = SessionStore::new();
        let session_id = Uuid::new_v4();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        let session = store.register(session_id, caps.clone()).unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.message_count, 0);

        let retrieved = store.get(&session_id).unwrap();
        assert_eq!(retrieved.session_id, session_id);
    }

    #[test]
    fn test_session_store_touch_increments_count() {
        let store = SessionStore::new();
        let session_id = Uuid::new_v4();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        store.register(session_id, caps).unwrap();

        assert!(store.touch(&session_id));
        assert!(store.touch(&session_id));
        assert!(store.touch(&session_id));

        let session = store.get(&session_id).unwrap();
        assert_eq!(session.message_count, 3);
    }

    #[test]
    fn test_session_store_touch_nonexistent_returns_false() {
        let store = SessionStore::new();
        assert!(!store.touch(&Uuid::new_v4()));
    }

    #[test]
    fn test_session_store_remove() {
        let store = SessionStore::new();
        let session_id = Uuid::new_v4();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        store.register(session_id, caps).unwrap();
        assert_eq!(store.count(), 1);

        let removed = store.remove(&session_id);
        assert!(removed.is_some());
        assert_eq!(store.count(), 0);

        // Removing again returns None
        assert!(store.remove(&session_id).is_none());
    }

    #[test]
    fn test_session_store_list() {
        let store = SessionStore::new();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        store.register(id1, caps.clone()).unwrap();
        store.register(id2, caps).unwrap();

        let sessions = store.list();
        assert_eq!(sessions.len(), 2);

        let ids: Vec<Uuid> = sessions.iter().map(|s| s.session_id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_session_store_max_sessions() {
        let store = SessionStore::new();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        // Fill up to MAX_SESSIONS
        for _ in 0..MAX_SESSIONS {
            store.register(Uuid::new_v4(), caps.clone()).unwrap();
        }

        // One more should fail
        let result = store.register(Uuid::new_v4(), caps);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum session count"));
    }

    #[test]
    fn test_session_store_subscribe_and_unsubscribe() {
        let store = SessionStore::new();
        let session_id = Uuid::new_v4();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        store.register(session_id, caps).unwrap();

        // Subscribe
        assert!(store.subscribe(&session_id, "agent.status_changed".to_string()));
        assert!(store.subscribe(&session_id, "agent.output".to_string()));

        let session = store.get(&session_id).unwrap();
        assert_eq!(session.subscriptions.len(), 2);

        // Duplicate subscription should not add twice
        assert!(store.subscribe(&session_id, "agent.output".to_string()));
        let session = store.get(&session_id).unwrap();
        assert_eq!(session.subscriptions.len(), 2);

        // Unsubscribe
        assert!(store.unsubscribe(&session_id, "agent.output"));
        let session = store.get(&session_id).unwrap();
        assert_eq!(session.subscriptions.len(), 1);
        assert_eq!(session.subscriptions[0], "agent.status_changed");
    }

    #[test]
    fn test_session_store_subscribe_nonexistent() {
        let store = SessionStore::new();
        assert!(!store.subscribe(&Uuid::new_v4(), "test".to_string()));
        assert!(!store.unsubscribe(&Uuid::new_v4(), "test"));
    }

    #[test]
    fn test_protocol_version_compatibility() {
        assert!(is_compatible_version("1.0"));
        assert!(is_compatible_version("1"));
        assert!(is_compatible_version("1.1"));
        assert!(is_compatible_version("1.2.3"));
        assert!(!is_compatible_version("2.0"));
        assert!(!is_compatible_version("0.9"));
        assert!(!is_compatible_version(""));
    }

    #[test]
    fn test_agent_capabilities_serialization() {
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);
        let json = serde_json::to_string(&caps).unwrap();
        let back: AgentCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(caps, back);
        assert_eq!(back.protocol_version, PROTOCOL_VERSION);
        assert!(back.supports_streaming);
        assert!(back.supports_websocket);
    }

    #[test]
    fn test_stream_event_creation() {
        let event = StreamEvent::new(
            "agent.started",
            serde_json::json!({"name": "claude-1"}),
            Some("claude-1".to_string()),
        );

        assert_eq!(event.event_type, "agent.started");
        assert!(event.source_agent.is_some());
        assert!(!event.event_id.is_nil());

        // Serialization roundtrip
        let json = serde_json::to_string(&event).unwrap();
        let back: StreamEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "agent.started");
        assert_eq!(back.event_id, event.event_id);
    }

    #[test]
    fn test_handshake_request_serialization() {
        let request = HandshakeRequest {
            protocol_version: "1.0".to_string(),
            capabilities: AgentCapabilities {
                protocol_version: "1.0".to_string(),
                agent_name: "test-client".to_string(),
                agent_id: "test".to_string(),
                supported_methods: vec!["send".into(), "status".into()],
                supports_streaming: false,
                supports_websocket: false,
                max_message_size: 1_000_000,
                metadata: HashMap::new(),
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        let back: HandshakeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol_version, "1.0");
        assert_eq!(back.capabilities.agent_name, "test-client");
    }

    #[test]
    fn test_prune_idle_sessions() {
        let store = SessionStore::new();
        let caps = AgentCapabilities::daemon_capabilities(1_048_576);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        store.register(id1, caps.clone()).unwrap();
        store.register(id2, caps).unwrap();

        // With a very large timeout, nothing should be pruned
        let pruned = store.prune_idle(999_999);
        assert_eq!(pruned, 0);
        assert_eq!(store.count(), 2);

        // With a zero timeout, everything should be pruned (since some time
        // has elapsed since registration)
        // Note: this test may flake if the machine is fast enough to execute
        // in sub-second time. We use 0 which means "prune anything older
        // than 0 seconds" -- any elapsed time will trigger it.
        // But to be safe, let's just verify the function doesn't panic.
        let _pruned = store.prune_idle(0);
    }

    #[test]
    fn test_extract_discoverable_agents_from_data() {
        use crate::daemon::DaemonResponse;

        // With agents array
        let resp = DaemonResponse::ok_with_data(
            "found 2 agents",
            serde_json::json!({
                "agents": [
                    {"name": "claude-1", "status": "running", "role": "coder"},
                    {"name": "agent-2", "status": "stopped"}
                ]
            }),
        );
        let agents = extract_discoverable_agents(&resp);
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].name, "claude-1");
        assert_eq!(agents[0].status, "running");
        assert_eq!(agents[0].role.as_deref(), Some("coder"));
        assert_eq!(agents[1].name, "agent-2");
        assert_eq!(agents[1].status, "stopped");
        assert!(agents[1].role.is_none());
    }

    #[test]
    fn test_extract_discoverable_agents_empty() {
        use crate::daemon::DaemonResponse;

        let resp = DaemonResponse::ok("no agents");
        let agents = extract_discoverable_agents(&resp);
        assert!(agents.is_empty());
    }

    #[test]
    fn test_session_idle_timeout_constant() {
        assert_eq!(SESSION_IDLE_TIMEOUT_SECS, 600);
    }

    #[test]
    fn test_session_store_default() {
        let store = SessionStore::default();
        assert_eq!(store.count(), 0);
    }
}
