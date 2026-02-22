//! OpenResponses HTTP API for tool discovery and invocation.
//!
//! Provides a standard RESTful API for discovering and invoking tools:
//! - `GET /v1/tools` -- list available tools with schemas
//! - `GET /v1/tools/{name}` -- get details for a specific tool
//! - `POST /v1/tools/{name}/invoke` -- invoke a tool synchronously
//! - `POST /v1/tools/{name}/invoke_async` -- invoke a tool asynchronously
//! - `GET /v1/tools/invocations/{id}` -- poll async invocation status
//!
//! ## Design
//!
//! Tools are defined with JSON Schema parameters and return standardized
//! result envelopes. Each invocation gets a unique ID for tracking.
//! Asynchronous invocations return immediately with a pending status and
//! can be polled for completion.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::daemon::DaemonCommand;
use crate::server::http::DaemonCommandTx;

// ---------------------------------------------------------------------------
// Tool definition types
// ---------------------------------------------------------------------------

/// A tool available for invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Unique tool name (e.g., "send_message", "list_agents").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub parameters: serde_json::Value,
    /// JSON Schema for the tool's return value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<serde_json::Value>,
    /// Category for grouping (e.g., "fleet", "agent", "system").
    pub category: String,
    /// Whether the tool supports async invocation.
    pub supports_async: bool,
}

/// Response listing available tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolListResponse {
    /// Available tools.
    pub tools: Vec<ToolInfo>,
    /// Total count.
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Invocation types
// ---------------------------------------------------------------------------

/// Request body for tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// Input parameters for the tool (must match the tool's parameter schema).
    pub parameters: serde_json::Value,
    /// Optional context metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Status of a tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    /// Invocation is queued but not started.
    Pending,
    /// Invocation is currently executing.
    Running,
    /// Invocation completed successfully.
    Completed,
    /// Invocation failed.
    Failed,
    /// Invocation was cancelled.
    Cancelled,
}

/// Result of a tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationResult {
    /// Unique invocation identifier.
    pub invocation_id: Uuid,
    /// Name of the tool that was invoked.
    pub tool_name: String,
    /// Current status.
    pub status: InvocationStatus,
    /// When the invocation was created.
    pub created_at: DateTime<Utc>,
    /// When the invocation completed (if finished).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// The output data (when completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Error message (when failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Execution duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl InvocationResult {
    /// Create a new pending invocation result.
    fn pending(invocation_id: Uuid, tool_name: String) -> Self {
        Self {
            invocation_id,
            tool_name,
            status: InvocationStatus::Pending,
            created_at: Utc::now(),
            completed_at: None,
            output: None,
            error: None,
            duration_ms: None,
        }
    }

    /// Mark as completed with output.
    fn complete(mut self, output: serde_json::Value) -> Self {
        let now = Utc::now();
        let duration = (now - self.created_at).num_milliseconds().max(0) as u64;
        self.status = InvocationStatus::Completed;
        self.completed_at = Some(now);
        self.output = Some(output);
        self.duration_ms = Some(duration);
        self
    }

    /// Mark as failed with error.
    fn fail(mut self, error: String) -> Self {
        let now = Utc::now();
        let duration = (now - self.created_at).num_milliseconds().max(0) as u64;
        self.status = InvocationStatus::Failed;
        self.completed_at = Some(now);
        self.error = Some(error);
        self.duration_ms = Some(duration);
        self
    }
}

/// Error response for tool API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolApiError {
    /// Error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ToolApiError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Async invocation store
// ---------------------------------------------------------------------------

/// Tracks async invocation results for polling.
#[derive(Debug)]
pub struct InvocationStore {
    results: Mutex<HashMap<Uuid, InvocationResult>>,
}

impl InvocationStore {
    /// Create a new empty invocation store.
    pub fn new() -> Self {
        Self {
            results: Mutex::new(HashMap::new()),
        }
    }

    /// Store an invocation result.
    pub fn store(&self, result: InvocationResult) {
        let mut results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        results.insert(result.invocation_id, result);
    }

    /// Get an invocation result by ID.
    pub fn get(&self, id: &Uuid) -> Option<InvocationResult> {
        let results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        results.get(id).cloned()
    }

    /// Update an invocation result. Returns false if not found.
    pub fn update(&self, result: InvocationResult) -> bool {
        let mut results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            results.entry(result.invocation_id)
        {
            e.insert(result);
            true
        } else {
            false
        }
    }

    /// Remove completed invocations older than the given age.
    /// Returns the number of entries pruned.
    pub fn prune_completed(&self, max_age_secs: i64) -> usize {
        let mut results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs);
        let before = results.len();

        results.retain(|_, result| {
            match result.status {
                InvocationStatus::Completed | InvocationStatus::Failed | InvocationStatus::Cancelled => {
                    // Keep if completed after cutoff
                    result
                        .completed_at
                        .is_some_and(|t| t > cutoff)
                }
                // Always keep pending/running
                _ => true,
            }
        });

        before - results.len()
    }

    /// Get the number of stored invocations.
    pub fn count(&self) -> usize {
        let results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        results.len()
    }
}

impl Default for InvocationStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Built-in tool catalog
// ---------------------------------------------------------------------------

/// Build the default tool catalog for the Aegis daemon.
///
/// These tools map to DaemonCommand variants and are available for
/// programmatic invocation via the REST API.
pub fn default_tool_catalog() -> Vec<ToolInfo> {
    vec![
        ToolInfo {
            name: "list_agents".to_string(),
            description: "List all agents in the fleet with their current status.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            returns: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "agents": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "status": {"type": "string"},
                                "tool": {"type": "string"}
                            }
                        }
                    }
                }
            })),
            category: "fleet".to_string(),
            supports_async: false,
        },
        ToolInfo {
            name: "agent_status".to_string(),
            description: "Get detailed status for a specific agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name"
                    }
                },
                "required": ["name"]
            }),
            returns: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "status": {"type": "string"},
                    "uptime_secs": {"type": "integer"}
                }
            })),
            category: "agent".to_string(),
            supports_async: false,
        },
        ToolInfo {
            name: "send_message".to_string(),
            description: "Send a text message to an agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Target agent name"
                    },
                    "text": {
                        "type": "string",
                        "description": "Message text to send"
                    }
                },
                "required": ["name", "text"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: true,
        },
        ToolInfo {
            name: "start_agent".to_string(),
            description: "Start a specific agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name to start"
                    }
                },
                "required": ["name"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: true,
        },
        ToolInfo {
            name: "stop_agent".to_string(),
            description: "Stop a running agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name to stop"
                    }
                },
                "required": ["name"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: true,
        },
        ToolInfo {
            name: "restart_agent".to_string(),
            description: "Restart a specific agent (stop + start).".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name to restart"
                    }
                },
                "required": ["name"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: true,
        },
        ToolInfo {
            name: "approve_request".to_string(),
            description: "Approve a pending permission request for an agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name"
                    },
                    "request_id": {
                        "type": "string",
                        "description": "ID of the pending request to approve"
                    }
                },
                "required": ["name", "request_id"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: false,
        },
        ToolInfo {
            name: "deny_request".to_string(),
            description: "Deny a pending permission request for an agent.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name"
                    },
                    "request_id": {
                        "type": "string",
                        "description": "ID of the pending request to deny"
                    }
                },
                "required": ["name", "request_id"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: false,
        },
        ToolInfo {
            name: "fleet_goal".to_string(),
            description: "Get or set the fleet-wide goal.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "goal": {
                        "type": "string",
                        "description": "New fleet goal (omit to get current goal)"
                    }
                }
            }),
            returns: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "goal": {"type": "string"}
                }
            })),
            category: "fleet".to_string(),
            supports_async: false,
        },
        ToolInfo {
            name: "nudge_agent".to_string(),
            description: "Nudge a stalled agent with an optional message.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name to nudge"
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional nudge message"
                    }
                },
                "required": ["name"]
            }),
            returns: None,
            category: "agent".to_string(),
            supports_async: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tool-to-command mapping
// ---------------------------------------------------------------------------

/// Map a tool invocation to a DaemonCommand.
///
/// Returns an error string if the tool name is unknown or required parameters
/// are missing.
fn tool_to_command(
    tool_name: &str,
    params: &serde_json::Value,
) -> Result<DaemonCommand, String> {
    match tool_name {
        "list_agents" => Ok(DaemonCommand::ListAgents),
        "agent_status" => {
            let name = require_param_string(params, "name")?;
            Ok(DaemonCommand::AgentStatus { name })
        }
        "send_message" => {
            let name = require_param_string(params, "name")?;
            let text = require_param_string(params, "text")?;
            Ok(DaemonCommand::SendToAgent { name, text })
        }
        "start_agent" => {
            let name = require_param_string(params, "name")?;
            Ok(DaemonCommand::StartAgent { name })
        }
        "stop_agent" => {
            let name = require_param_string(params, "name")?;
            Ok(DaemonCommand::StopAgent { name })
        }
        "restart_agent" => {
            let name = require_param_string(params, "name")?;
            Ok(DaemonCommand::RestartAgent { name })
        }
        "approve_request" => {
            let name = require_param_string(params, "name")?;
            let request_id = require_param_string(params, "request_id")?;
            Ok(DaemonCommand::ApproveRequest { name, request_id })
        }
        "deny_request" => {
            let name = require_param_string(params, "name")?;
            let request_id = require_param_string(params, "request_id")?;
            Ok(DaemonCommand::DenyRequest { name, request_id })
        }
        "fleet_goal" => {
            let goal = params
                .get("goal")
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(DaemonCommand::FleetGoal { goal })
        }
        "nudge_agent" => {
            let name = require_param_string(params, "name")?;
            let message = params
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from);
            Ok(DaemonCommand::NudgeAgent { name, message })
        }
        _ => Err(format!("unknown tool: {tool_name}")),
    }
}

/// Extract a required string parameter from a JSON value.
fn require_param_string(params: &serde_json::Value, field: &str) -> Result<String, String> {
    params
        .get(field)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("required parameter '{field}' is missing or not a string"))
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the OpenResponses tool API.
pub struct ToolApiState {
    /// API key for authentication.
    pub api_key: String,
    /// Available tool catalog.
    pub tools: Vec<ToolInfo>,
    /// Async invocation result store.
    pub invocations: Arc<InvocationStore>,
    /// Daemon command channel.
    pub daemon_tx: DaemonCommandTx,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Authenticate a request using Bearer token.
#[allow(clippy::result_large_err)]
fn authenticate(
    state: &ToolApiState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ToolApiError>)> {
    if state.api_key.is_empty() {
        return Ok(());
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth.strip_prefix("Bearer ").unwrap_or("");

    if token.is_empty() || !constant_time_eq(token.as_bytes(), state.api_key.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ToolApiError::new(
                "AUTH_REQUIRED",
                "invalid or missing API key",
            )),
        ));
    }

    Ok(())
}

/// Constant-time byte comparison.
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

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the OpenResponses tool API route group.
///
/// Returns a `Router` that provides tool discovery and invocation endpoints.
pub fn tool_api_routes(state: Arc<ToolApiState>) -> Router {
    Router::new()
        .route("/v1/tools", get(list_tools_handler))
        .route("/v1/tools/{name}", get(get_tool_handler))
        .route("/v1/tools/{name}/invoke", post(invoke_tool_handler))
        .route(
            "/v1/tools/{name}/invoke_async",
            post(invoke_tool_async_handler),
        )
        .route(
            "/v1/tools/invocations/{id}",
            get(get_invocation_handler),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/tools` -- list available tools.
async fn list_tools_handler(
    State(state): State<Arc<ToolApiState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ListToolsParams>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    let tools: Vec<&ToolInfo> = if let Some(ref category) = params.category {
        state.tools.iter().filter(|t| &t.category == category).collect()
    } else {
        state.tools.iter().collect()
    };

    let response = ToolListResponse {
        total: tools.len(),
        tools: tools.into_iter().cloned().collect(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Query parameters for tool listing.
#[derive(Debug, Deserialize)]
struct ListToolsParams {
    /// Filter by category.
    #[serde(default)]
    category: Option<String>,
}

/// `GET /v1/tools/{name}` -- get a specific tool's details.
async fn get_tool_handler(
    State(state): State<Arc<ToolApiState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    match state.tools.iter().find(|t| t.name == name) {
        Some(tool) => (StatusCode::OK, Json(tool.clone())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ToolApiError::new(
                "TOOL_NOT_FOUND",
                format!("no tool named '{name}'"),
            )),
        )
            .into_response(),
    }
}

/// `POST /v1/tools/{name}/invoke` -- invoke a tool synchronously.
async fn invoke_tool_handler(
    State(state): State<Arc<ToolApiState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(request): Json<InvokeRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    // Verify tool exists
    if !state.tools.iter().any(|t| t.name == name) {
        return (
            StatusCode::NOT_FOUND,
            Json(ToolApiError::new(
                "TOOL_NOT_FOUND",
                format!("no tool named '{name}'"),
            )),
        )
            .into_response();
    }

    // Map to daemon command
    let command = match tool_to_command(&name, &request.parameters) {
        Ok(cmd) => cmd,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ToolApiError::new("INVALID_PARAMETERS", msg)),
            )
                .into_response();
        }
    };

    // Execute via daemon
    let invocation_id = Uuid::new_v4();
    let result = InvocationResult::pending(invocation_id, name.clone());

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if state.daemon_tx.send((command, resp_tx)).await.is_err() {
        let failed = result.fail("daemon unavailable".to_string());
        return (StatusCode::BAD_GATEWAY, Json(failed)).into_response();
    }

    match resp_rx.await {
        Ok(resp) => {
            let completed = if resp.ok {
                let output = serde_json::json!({
                    "message": resp.message,
                    "data": resp.data,
                });
                result.complete(output)
            } else {
                result.fail(resp.message)
            };

            debug!(
                tool = %name,
                invocation_id = %invocation_id,
                status = ?completed.status,
                "tool invocation completed"
            );

            (StatusCode::OK, Json(completed)).into_response()
        }
        Err(_) => {
            let failed = result.fail("daemon response channel closed".to_string());
            (StatusCode::BAD_GATEWAY, Json(failed)).into_response()
        }
    }
}

/// `POST /v1/tools/{name}/invoke_async` -- invoke a tool asynchronously.
///
/// Returns immediately with a pending invocation ID. The caller can poll
/// `GET /v1/tools/invocations/{id}` for the result.
async fn invoke_tool_async_handler(
    State(state): State<Arc<ToolApiState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(request): Json<InvokeRequest>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    // Verify tool exists and supports async
    match state.tools.iter().find(|t| t.name == name) {
        Some(tool) if !tool.supports_async => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ToolApiError::new(
                    "ASYNC_NOT_SUPPORTED",
                    format!("tool '{name}' does not support async invocation"),
                )),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ToolApiError::new(
                    "TOOL_NOT_FOUND",
                    format!("no tool named '{name}'"),
                )),
            )
                .into_response();
        }
        _ => {}
    }

    // Map to daemon command
    let command = match tool_to_command(&name, &request.parameters) {
        Ok(cmd) => cmd,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ToolApiError::new("INVALID_PARAMETERS", msg)),
            )
                .into_response();
        }
    };

    // Create pending invocation
    let invocation_id = Uuid::new_v4();
    let pending = InvocationResult::pending(invocation_id, name.clone());
    state.invocations.store(pending.clone());

    info!(
        tool = %name,
        invocation_id = %invocation_id,
        "async tool invocation started"
    );

    // Spawn background task to execute and update result
    let invocations = state.invocations.clone();
    let daemon_tx = state.daemon_tx.clone();
    tokio::spawn(async move {
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        if daemon_tx.send((command, resp_tx)).await.is_err() {
            let failed = InvocationResult::pending(invocation_id, name)
                .fail("daemon unavailable".to_string());
            invocations.update(failed);
            return;
        }

        match resp_rx.await {
            Ok(resp) => {
                let result = InvocationResult::pending(invocation_id, name.clone());
                let updated = if resp.ok {
                    let output = serde_json::json!({
                        "message": resp.message,
                        "data": resp.data,
                    });
                    result.complete(output)
                } else {
                    result.fail(resp.message)
                };
                invocations.update(updated);
            }
            Err(_) => {
                let failed = InvocationResult::pending(invocation_id, name)
                    .fail("daemon response channel closed".to_string());
                invocations.update(failed);
            }
        }
    });

    // Return the pending result immediately
    (StatusCode::ACCEPTED, Json(pending)).into_response()
}

/// `GET /v1/tools/invocations/{id}` -- poll async invocation status.
async fn get_invocation_handler(
    State(state): State<Arc<ToolApiState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = authenticate(&state, &headers) {
        return e.into_response();
    }

    match state.invocations.get(&id) {
        Some(result) => (StatusCode::OK, Json(result)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ToolApiError::new(
                "INVOCATION_NOT_FOUND",
                format!("no invocation with id {id}"),
            )),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_catalog_has_expected_tools() {
        let tools = default_tool_catalog();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

        assert!(names.contains(&"list_agents"));
        assert!(names.contains(&"agent_status"));
        assert!(names.contains(&"send_message"));
        assert!(names.contains(&"start_agent"));
        assert!(names.contains(&"stop_agent"));
        assert!(names.contains(&"approve_request"));
        assert!(names.contains(&"deny_request"));
        assert!(names.contains(&"fleet_goal"));
        assert!(names.contains(&"nudge_agent"));
    }

    #[test]
    fn test_tool_info_serialization() {
        let tool = ToolInfo {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }),
            returns: None,
            category: "test".to_string(),
            supports_async: true,
        };

        let json = serde_json::to_string(&tool).unwrap();
        let back: ToolInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test_tool");
        assert!(back.supports_async);
    }

    #[test]
    fn test_tool_to_command_list_agents() {
        let cmd = tool_to_command("list_agents", &serde_json::json!({})).unwrap();
        assert!(matches!(cmd, DaemonCommand::ListAgents));
    }

    #[test]
    fn test_tool_to_command_agent_status() {
        let cmd = tool_to_command(
            "agent_status",
            &serde_json::json!({"name": "claude-1"}),
        )
        .unwrap();
        match cmd {
            DaemonCommand::AgentStatus { name } => assert_eq!(name, "claude-1"),
            other => panic!("expected AgentStatus, got: {other:?}"),
        }
    }

    #[test]
    fn test_tool_to_command_send_message() {
        let cmd = tool_to_command(
            "send_message",
            &serde_json::json!({"name": "agent-1", "text": "hello"}),
        )
        .unwrap();
        match cmd {
            DaemonCommand::SendToAgent { name, text } => {
                assert_eq!(name, "agent-1");
                assert_eq!(text, "hello");
            }
            other => panic!("expected SendToAgent, got: {other:?}"),
        }
    }

    #[test]
    fn test_tool_to_command_missing_required_param() {
        let result = tool_to_command("agent_status", &serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("name"));
    }

    #[test]
    fn test_tool_to_command_unknown_tool() {
        let result = tool_to_command("nonexistent_tool", &serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown tool"));
    }

    #[test]
    fn test_tool_to_command_fleet_goal_get() {
        let cmd = tool_to_command("fleet_goal", &serde_json::json!({})).unwrap();
        match cmd {
            DaemonCommand::FleetGoal { goal } => assert!(goal.is_none()),
            other => panic!("expected FleetGoal, got: {other:?}"),
        }
    }

    #[test]
    fn test_tool_to_command_fleet_goal_set() {
        let cmd = tool_to_command(
            "fleet_goal",
            &serde_json::json!({"goal": "ship v2"}),
        )
        .unwrap();
        match cmd {
            DaemonCommand::FleetGoal { goal } => {
                assert_eq!(goal.as_deref(), Some("ship v2"));
            }
            other => panic!("expected FleetGoal, got: {other:?}"),
        }
    }

    #[test]
    fn test_tool_to_command_nudge_agent() {
        let cmd = tool_to_command(
            "nudge_agent",
            &serde_json::json!({"name": "agent-1", "message": "wake up"}),
        )
        .unwrap();
        match cmd {
            DaemonCommand::NudgeAgent { name, message } => {
                assert_eq!(name, "agent-1");
                assert_eq!(message.as_deref(), Some("wake up"));
            }
            other => panic!("expected NudgeAgent, got: {other:?}"),
        }
    }

    #[test]
    fn test_invocation_result_lifecycle() {
        let id = Uuid::new_v4();
        let result = InvocationResult::pending(id, "test_tool".to_string());
        assert_eq!(result.status, InvocationStatus::Pending);
        assert!(result.output.is_none());
        assert!(result.completed_at.is_none());

        let completed = result.complete(serde_json::json!({"result": "ok"}));
        assert_eq!(completed.status, InvocationStatus::Completed);
        assert!(completed.output.is_some());
        assert!(completed.completed_at.is_some());
        assert!(completed.duration_ms.is_some());
    }

    #[test]
    fn test_invocation_result_failure() {
        let id = Uuid::new_v4();
        let result = InvocationResult::pending(id, "test_tool".to_string());
        let failed = result.fail("something went wrong".to_string());
        assert_eq!(failed.status, InvocationStatus::Failed);
        assert_eq!(failed.error.as_deref(), Some("something went wrong"));
        assert!(failed.completed_at.is_some());
    }

    #[test]
    fn test_invocation_store_crud() {
        let store = InvocationStore::new();
        let id = Uuid::new_v4();
        let result = InvocationResult::pending(id, "test".to_string());

        // Store
        store.store(result.clone());
        assert_eq!(store.count(), 1);

        // Get
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.invocation_id, id);
        assert_eq!(retrieved.status, InvocationStatus::Pending);

        // Update
        let updated = InvocationResult::pending(id, "test".to_string())
            .complete(serde_json::json!({"ok": true}));
        assert!(store.update(updated));

        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.status, InvocationStatus::Completed);

        // Update nonexistent
        let fake_id = Uuid::new_v4();
        let fake = InvocationResult::pending(fake_id, "fake".to_string());
        assert!(!store.update(fake));
    }

    #[test]
    fn test_invocation_store_prune() {
        let store = InvocationStore::new();

        // Add a completed invocation
        let id = Uuid::new_v4();
        let result = InvocationResult::pending(id, "test".to_string())
            .complete(serde_json::json!({}));
        store.store(result);

        // Add a pending invocation
        let id2 = Uuid::new_v4();
        let pending = InvocationResult::pending(id2, "test2".to_string());
        store.store(pending);

        assert_eq!(store.count(), 2);

        // Prune with zero max_age should remove completed but keep pending
        let pruned = store.prune_completed(0);
        assert_eq!(pruned, 1);
        assert_eq!(store.count(), 1);

        // The pending one should remain
        assert!(store.get(&id2).is_some());
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_invoke_request_serialization() {
        let req = InvokeRequest {
            parameters: serde_json::json!({"name": "agent-1"}),
            metadata: HashMap::from([("source".to_string(), "api".to_string())]),
        };

        let json = serde_json::to_string(&req).unwrap();
        let back: InvokeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parameters["name"], "agent-1");
        assert_eq!(back.metadata.get("source").unwrap(), "api");
    }

    #[test]
    fn test_invocation_status_serialization() {
        let statuses = vec![
            InvocationStatus::Pending,
            InvocationStatus::Running,
            InvocationStatus::Completed,
            InvocationStatus::Failed,
            InvocationStatus::Cancelled,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let back: InvocationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn test_tool_list_response_serialization() {
        let response = ToolListResponse {
            tools: vec![ToolInfo {
                name: "test".to_string(),
                description: "a test".to_string(),
                parameters: serde_json::json!({}),
                returns: None,
                category: "test".to_string(),
                supports_async: false,
            }],
            total: 1,
        };

        let json = serde_json::to_string(&response).unwrap();
        let back: ToolListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total, 1);
        assert_eq!(back.tools[0].name, "test");
    }

    #[test]
    fn test_tool_api_error_serialization() {
        let err = ToolApiError::new("TEST_ERROR", "something happened");
        let json = serde_json::to_string(&err).unwrap();
        let back: ToolApiError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "TEST_ERROR");
        assert_eq!(back.message, "something happened");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_require_param_string() {
        let params = serde_json::json!({"name": "agent-1", "count": 5});

        assert_eq!(
            require_param_string(&params, "name").unwrap(),
            "agent-1"
        );
        assert!(require_param_string(&params, "missing").is_err());
        assert!(require_param_string(&params, "count").is_err()); // not a string
    }

    #[test]
    fn test_invocation_store_default() {
        let store = InvocationStore::default();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_tool_categories() {
        let tools = default_tool_catalog();
        let fleet_tools: Vec<&ToolInfo> = tools.iter().filter(|t| t.category == "fleet").collect();
        let agent_tools: Vec<&ToolInfo> = tools.iter().filter(|t| t.category == "agent").collect();

        assert!(!fleet_tools.is_empty(), "should have fleet tools");
        assert!(!agent_tools.is_empty(), "should have agent tools");
    }

    #[test]
    fn test_tool_parameters_are_valid_json_schema() {
        let tools = default_tool_catalog();
        for tool in &tools {
            // All parameter schemas should be objects
            assert_eq!(
                tool.parameters.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "tool '{}' parameters should be an object schema",
                tool.name
            );
        }
    }
}
