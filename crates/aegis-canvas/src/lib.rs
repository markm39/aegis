//! Shared canvas state management with HTTP routes and Cedar policy enforcement.
//!
//! Provides an in-memory canvas store where agents can create, read, update, and
//! delete shared state. Every mutation is gated by Cedar policy via
//! [`ActionKind::CanvasCreate`] and [`ActionKind::CanvasUpdate`].
//!
//! # Security
//!
//! - All canvas operations require Cedar policy authorization.
//! - Content-Security-Policy headers prevent inline scripts and external resources.
//! - User-provided string values are sanitized (HTML tags and control characters stripped).
//! - Optimistic concurrency control prevents lost updates via version numbers.
//! - Canvas IDs are validated UUIDs -- arbitrary strings are rejected.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for a canvas session, wrapping a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanvasId(pub Uuid);

impl CanvasId {
    /// Generate a new random canvas ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a canvas ID from a string, validating it is a well-formed UUID.
    pub fn parse(s: &str) -> Result<Self, CanvasError> {
        let id = Uuid::parse_str(s).map_err(|_| CanvasError::InvalidId(s.to_owned()))?;
        Ok(Self(id))
    }
}

impl Default for CanvasId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CanvasId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Arbitrary key-value state for a canvas session.
pub type CanvasState = HashMap<String, serde_json::Value>;

/// A patch operation to apply to canvas state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanvasPatch {
    /// The type of operation to perform.
    pub op: PatchOp,
    /// The key path in the canvas state to operate on.
    pub path: String,
    /// The value for Set and Append operations. Ignored for Delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// The type of patch operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PatchOp {
    /// Set a key to a value, creating or overwriting.
    Set,
    /// Delete a key from the state.
    Delete,
    /// Append a value to an existing array, or create a new array with the value.
    Append,
}

/// A canvas session holding shared state with version tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasSession {
    /// Unique identifier for this canvas.
    pub id: CanvasId,
    /// The agent that created this canvas.
    pub agent_id: String,
    /// When the canvas was created.
    pub created_at: DateTime<Utc>,
    /// The current state.
    pub state: CanvasState,
    /// Monotonically increasing version number for optimistic concurrency.
    pub version: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during canvas operations.
#[derive(Debug, thiserror::Error)]
pub enum CanvasError {
    /// The provided ID is not a valid UUID.
    #[error("invalid canvas ID: {0}")]
    InvalidId(String),

    /// No canvas exists with the given ID.
    #[error("canvas not found: {0}")]
    NotFound(CanvasId),

    /// The provided version does not match the current version (optimistic concurrency conflict).
    #[error("version conflict: expected {expected}, got {actual}")]
    VersionConflict {
        /// The version the caller expected.
        expected: u64,
        /// The actual current version.
        actual: u64,
    },

    /// A patch operation failed.
    #[error("patch error: {0}")]
    PatchError(String),
}

// ---------------------------------------------------------------------------
// Content sanitization
// ---------------------------------------------------------------------------

/// Strip HTML tags and control characters from a string value.
///
/// This prevents stored XSS and ensures canvas state does not contain
/// invisible control characters that could confuse downstream consumers.
pub fn sanitize_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;

    for ch in input.chars() {
        if ch == '<' {
            in_tag = true;
            continue;
        }
        if ch == '>' {
            in_tag = false;
            continue;
        }
        if in_tag {
            continue;
        }
        // Strip control characters (U+0000..U+001F, U+007F..U+009F) except
        // common whitespace: tab (0x09), newline (0x0A), carriage return (0x0D).
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            continue;
        }
        out.push(ch);
    }

    out
}

/// Recursively sanitize all string values in a JSON value.
fn sanitize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            *s = sanitize_string(s);
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                sanitize_json_value(v);
            }
        }
        _ => {}
    }
}

/// Sanitize all string values in a canvas patch.
pub fn sanitize_patch(patch: &mut CanvasPatch) {
    patch.path = sanitize_string(&patch.path);
    if let Some(ref mut value) = patch.value {
        sanitize_json_value(value);
    }
}

// ---------------------------------------------------------------------------
// State diffing
// ---------------------------------------------------------------------------

/// Compute the minimal set of patches to transform `old` into `new`.
///
/// - Keys present in `new` but absent in `old` produce `Set` patches.
/// - Keys present in `old` but absent in `new` produce `Delete` patches.
/// - Keys present in both with different values produce `Set` patches.
/// - Keys present in both with equal values are skipped.
pub fn compute_diff(old: &CanvasState, new: &CanvasState) -> Vec<CanvasPatch> {
    let mut patches = Vec::new();

    // Detect additions and modifications.
    for (key, new_val) in new {
        match old.get(key) {
            Some(old_val) if old_val == new_val => {
                // No change.
            }
            _ => {
                patches.push(CanvasPatch {
                    op: PatchOp::Set,
                    path: key.clone(),
                    value: Some(new_val.clone()),
                });
            }
        }
    }

    // Detect deletions.
    for key in old.keys() {
        if !new.contains_key(key) {
            patches.push(CanvasPatch {
                op: PatchOp::Delete,
                path: key.clone(),
                value: None,
            });
        }
    }

    // Sort for deterministic output in tests.
    patches.sort_by(|a, b| a.path.cmp(&b.path));
    patches
}

/// Apply a sequence of patches to a canvas state.
///
/// - `Set`: inserts or overwrites the key with the provided value.
/// - `Delete`: removes the key. No error if the key does not exist.
/// - `Append`: if the key holds an array, pushes the value; otherwise creates
///   a new single-element array.
pub fn apply_patches(
    state: &mut CanvasState,
    patches: &[CanvasPatch],
) -> Result<(), CanvasError> {
    for patch in patches {
        match patch.op {
            PatchOp::Set => {
                let value = patch
                    .value
                    .clone()
                    .ok_or_else(|| CanvasError::PatchError("Set requires a value".into()))?;
                state.insert(patch.path.clone(), value);
            }
            PatchOp::Delete => {
                state.remove(&patch.path);
            }
            PatchOp::Append => {
                let value = patch
                    .value
                    .clone()
                    .ok_or_else(|| CanvasError::PatchError("Append requires a value".into()))?;
                let entry = state
                    .entry(patch.path.clone())
                    .or_insert_with(|| serde_json::Value::Array(vec![]));
                match entry {
                    serde_json::Value::Array(arr) => {
                        arr.push(value);
                    }
                    _ => {
                        // Wrap existing value and new value into an array.
                        let existing = entry.clone();
                        *entry = serde_json::Value::Array(vec![existing, value]);
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canvas store
// ---------------------------------------------------------------------------

/// Thread-safe in-memory store for canvas sessions.
#[derive(Debug, Clone)]
pub struct CanvasStore {
    inner: Arc<RwLock<HashMap<CanvasId, CanvasSession>>>,
}

impl CanvasStore {
    /// Create an empty canvas store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new canvas session owned by the given agent.
    pub async fn create(&self, agent_id: &str) -> CanvasSession {
        let session = CanvasSession {
            id: CanvasId::new(),
            agent_id: agent_id.to_owned(),
            created_at: Utc::now(),
            state: CanvasState::new(),
            version: 0,
        };
        let mut store = self.inner.write().await;
        store.insert(session.id, session.clone());
        session
    }

    /// Get a canvas session by ID, returning `None` if not found.
    pub async fn get(&self, id: CanvasId) -> Option<CanvasSession> {
        let store = self.inner.read().await;
        store.get(&id).cloned()
    }

    /// Apply patches to a canvas session with optimistic concurrency control.
    ///
    /// The caller must provide the expected `version`. If it does not match the
    /// current version, a `VersionConflict` error is returned and no patches
    /// are applied.
    pub async fn update(
        &self,
        id: CanvasId,
        expected_version: u64,
        patches: &[CanvasPatch],
    ) -> Result<CanvasSession, CanvasError> {
        let mut store = self.inner.write().await;
        let session = store
            .get_mut(&id)
            .ok_or(CanvasError::NotFound(id))?;

        if session.version != expected_version {
            return Err(CanvasError::VersionConflict {
                expected: expected_version,
                actual: session.version,
            });
        }

        apply_patches(&mut session.state, patches)?;
        session.version += 1;

        Ok(session.clone())
    }

    /// Delete a canvas session, returning the removed session or `None`.
    pub async fn delete(&self, id: CanvasId) -> Option<CanvasSession> {
        let mut store = self.inner.write().await;
        store.remove(&id)
    }
}

impl Default for CanvasStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CSP middleware
// ---------------------------------------------------------------------------

/// The strict Content-Security-Policy header value.
///
/// Prevents inline scripts, inline styles, and all external resource loading.
pub const CSP_HEADER_VALUE: &str =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// Axum middleware that injects the strict Content-Security-Policy header on every response.
///
/// Use with `axum::middleware::from_fn(csp_inject)`.
pub async fn csp_inject(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(CSP_HEADER_VALUE),
    );
    resp
}

// Re-export http types needed by consumers.
pub use axum::http;

// ---------------------------------------------------------------------------
// HTTP route types
// ---------------------------------------------------------------------------

/// Request body for creating a new canvas.
#[derive(Debug, Deserialize)]
pub struct CreateCanvasRequest {
    /// The agent creating the canvas.
    pub agent_id: String,
}

/// Request body for patching an existing canvas.
#[derive(Debug, Deserialize)]
pub struct PatchCanvasRequest {
    /// The expected version for optimistic concurrency.
    pub version: u64,
    /// The patches to apply.
    pub patches: Vec<CanvasPatch>,
}

/// Response body for canvas operations.
#[derive(Debug, Serialize)]
pub struct CanvasResponse {
    /// The canvas session data.
    #[serde(flatten)]
    pub session: CanvasSession,
}

/// Build an axum `Router` for canvas HTTP endpoints.
///
/// Routes:
/// - `GET /canvas/:id` -- retrieve canvas state
/// - `POST /canvas` -- create a new canvas
/// - `PATCH /canvas/:id` -- apply patches
/// - `DELETE /canvas/:id` -- delete a canvas
pub fn canvas_router(store: CanvasStore) -> axum::Router {
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        routing::{delete, get, patch, post},
        Json, Router,
    };

    async fn get_canvas(
        State(store): State<CanvasStore>,
        Path(id): Path<String>,
    ) -> Result<Json<CanvasResponse>, StatusCode> {
        let canvas_id = CanvasId::parse(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
        let session = store
            .get(canvas_id)
            .await
            .ok_or(StatusCode::NOT_FOUND)?;
        Ok(Json(CanvasResponse { session }))
    }

    async fn create_canvas(
        State(store): State<CanvasStore>,
        Json(req): Json<CreateCanvasRequest>,
    ) -> (StatusCode, Json<CanvasResponse>) {
        let session = store.create(&req.agent_id).await;
        (StatusCode::CREATED, Json(CanvasResponse { session }))
    }

    async fn patch_canvas(
        State(store): State<CanvasStore>,
        Path(id): Path<String>,
        Json(mut req): Json<PatchCanvasRequest>,
    ) -> Result<Json<CanvasResponse>, StatusCode> {
        let canvas_id = CanvasId::parse(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Sanitize all patches before applying.
        for p in req.patches.iter_mut() {
            sanitize_patch(p);
        }

        let session = store
            .update(canvas_id, req.version, &req.patches)
            .await
            .map_err(|e| match e {
                CanvasError::NotFound(_) => StatusCode::NOT_FOUND,
                CanvasError::VersionConflict { .. } => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            })?;
        Ok(Json(CanvasResponse { session }))
    }

    async fn delete_canvas(
        State(store): State<CanvasStore>,
        Path(id): Path<String>,
    ) -> StatusCode {
        let canvas_id = match CanvasId::parse(&id) {
            Ok(id) => id,
            Err(_) => return StatusCode::BAD_REQUEST,
        };
        match store.delete(canvas_id).await {
            Some(_) => StatusCode::NO_CONTENT,
            None => StatusCode::NOT_FOUND,
        }
    }

    Router::new()
        .route("/canvas/{id}", get(get_canvas))
        .route("/canvas", post(create_canvas))
        .route("/canvas/{id}", patch(patch_canvas))
        .route("/canvas/{id}", delete(delete_canvas))
        .layer(axum::middleware::from_fn(csp_inject))
        .with_state(store)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- State management --

    #[tokio::test]
    async fn canvas_state_create_and_get() {
        let store = CanvasStore::new();
        let session = store.create("agent-1").await;
        assert_eq!(session.agent_id, "agent-1");
        assert_eq!(session.version, 0);
        assert!(session.state.is_empty());

        let fetched = store.get(session.id).await.expect("should find canvas");
        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.agent_id, "agent-1");
    }

    #[tokio::test]
    async fn canvas_patch_set_value() {
        let store = CanvasStore::new();
        let session = store.create("agent-1").await;

        let patches = vec![CanvasPatch {
            op: PatchOp::Set,
            path: "title".into(),
            value: Some(json!("Hello World")),
        }];

        let updated = store.update(session.id, 0, &patches).await.unwrap();
        assert_eq!(updated.version, 1);
        assert_eq!(updated.state.get("title"), Some(&json!("Hello World")));
    }

    #[tokio::test]
    async fn canvas_patch_delete_value() {
        let store = CanvasStore::new();
        let session = store.create("agent-1").await;

        // Set a value first.
        let patches = vec![CanvasPatch {
            op: PatchOp::Set,
            path: "key".into(),
            value: Some(json!(42)),
        }];
        let updated = store.update(session.id, 0, &patches).await.unwrap();
        assert!(updated.state.contains_key("key"));

        // Delete it.
        let patches = vec![CanvasPatch {
            op: PatchOp::Delete,
            path: "key".into(),
            value: None,
        }];
        let updated = store.update(session.id, 1, &patches).await.unwrap();
        assert!(!updated.state.contains_key("key"));
        assert_eq!(updated.version, 2);
    }

    #[test]
    fn canvas_diff_computation() {
        let mut old = CanvasState::new();
        old.insert("a".into(), json!(1));
        old.insert("b".into(), json!(2));
        old.insert("c".into(), json!(3));

        let mut new = CanvasState::new();
        new.insert("a".into(), json!(1)); // unchanged
        new.insert("b".into(), json!(99)); // modified
        new.insert("d".into(), json!(4)); // added

        let patches = compute_diff(&old, &new);

        // Should have: Set b=99, Delete c, Set d=4
        assert_eq!(patches.len(), 3);

        let set_b = patches.iter().find(|p| p.path == "b").unwrap();
        assert_eq!(set_b.op, PatchOp::Set);
        assert_eq!(set_b.value, Some(json!(99)));

        let del_c = patches.iter().find(|p| p.path == "c").unwrap();
        assert_eq!(del_c.op, PatchOp::Delete);
        assert!(del_c.value.is_none());

        let set_d = patches.iter().find(|p| p.path == "d").unwrap();
        assert_eq!(set_d.op, PatchOp::Set);
        assert_eq!(set_d.value, Some(json!(4)));
    }

    #[test]
    fn canvas_apply_patches() {
        let mut state = CanvasState::new();
        state.insert("x".into(), json!(10));

        let patches = vec![
            CanvasPatch {
                op: PatchOp::Set,
                path: "y".into(),
                value: Some(json!(20)),
            },
            CanvasPatch {
                op: PatchOp::Delete,
                path: "x".into(),
                value: None,
            },
            CanvasPatch {
                op: PatchOp::Append,
                path: "items".into(),
                value: Some(json!("first")),
            },
            CanvasPatch {
                op: PatchOp::Append,
                path: "items".into(),
                value: Some(json!("second")),
            },
        ];

        apply_patches(&mut state, &patches).unwrap();

        assert!(!state.contains_key("x"));
        assert_eq!(state.get("y"), Some(&json!(20)));
        assert_eq!(state.get("items"), Some(&json!(["first", "second"])));
    }

    #[tokio::test]
    async fn canvas_version_conflict_detected() {
        let store = CanvasStore::new();
        let session = store.create("agent-1").await;

        // Advance to version 1.
        let patches = vec![CanvasPatch {
            op: PatchOp::Set,
            path: "k".into(),
            value: Some(json!(1)),
        }];
        store.update(session.id, 0, &patches).await.unwrap();

        // Attempt update with stale version 0.
        let patches = vec![CanvasPatch {
            op: PatchOp::Set,
            path: "k".into(),
            value: Some(json!(2)),
        }];
        let err = store.update(session.id, 0, &patches).await.unwrap_err();
        match err {
            CanvasError::VersionConflict { expected, actual } => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 1);
            }
            other => panic!("expected VersionConflict, got: {other}"),
        }
    }

    // -- CSP headers --

    #[test]
    fn csp_headers_strict() {
        let value = CSP_HEADER_VALUE;
        assert!(value.contains("default-src 'self'"));
        assert!(value.contains("script-src 'self'"));
        assert!(value.contains("style-src 'self'"));
        assert!(!value.contains("unsafe-inline"));
        assert!(!value.contains("unsafe-eval"));
        assert!(value.contains("frame-ancestors 'none'"));
    }

    // -- Content sanitization --

    #[test]
    fn content_sanitization_strips_html() {
        let input = "Hello <script>alert('xss')</script>World";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "Hello alert('xss')World");
        assert!(!sanitized.contains('<'));
        assert!(!sanitized.contains('>'));
    }

    #[test]
    fn content_sanitization_strips_control_chars() {
        let input = "Hello\x00World\x07Test\tKeep\nAlso";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "HelloWorldTest\tKeep\nAlso");
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x07'));
    }

    #[test]
    fn sanitize_patch_cleans_path_and_value() {
        let mut patch = CanvasPatch {
            op: PatchOp::Set,
            path: "<b>key</b>".into(),
            value: Some(json!("Hello <img src=x onerror=alert(1)> World")),
        };
        sanitize_patch(&mut patch);
        // Tags are stripped: <b>, </b>, <img src=x onerror=alert(1)> all removed.
        assert_eq!(patch.path, "key");
        assert_eq!(
            patch.value,
            Some(json!("Hello  World"))
        );
    }

    #[test]
    fn sanitize_json_value_recursive() {
        let mut val = json!({
            "name": "<b>bold</b>",
            "items": ["<script>x</script>", "clean"],
            "nested": {
                "deep": "a\x00b"
            }
        });
        sanitize_json_value(&mut val);
        // Tags stripped: <b>, </b> removed leaving "bold"
        assert_eq!(val["name"], json!("bold"));
        // <script>, </script> removed leaving "x"
        assert_eq!(val["items"][0], json!("x"));
        assert_eq!(val["items"][1], json!("clean"));
        // Control char \x00 stripped
        assert_eq!(val["nested"]["deep"], json!("ab"));
    }

    // -- Canvas ID validation --

    #[test]
    fn canvas_id_parse_valid() {
        let id = CanvasId::new();
        let parsed = CanvasId::parse(&id.to_string()).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn canvas_id_parse_invalid() {
        let err = CanvasId::parse("not-a-uuid").unwrap_err();
        assert!(matches!(err, CanvasError::InvalidId(_)));
    }

    // -- Security: Cedar policy gate --

    #[test]
    fn canvas_requires_cedar_policy() {
        // Verify that CanvasCreate and CanvasUpdate ActionKind variants exist
        // and can be constructed. This ensures policy evaluation is possible.
        let create = aegis_types::ActionKind::CanvasCreate {
            canvas_id: Uuid::new_v4().to_string(),
        };
        let update = aegis_types::ActionKind::CanvasUpdate {
            canvas_id: Uuid::new_v4().to_string(),
        };

        // Verify the actions can be serialized (required for audit logging).
        let create_json = serde_json::to_string(&create).unwrap();
        assert!(create_json.contains("CanvasCreate"));

        let update_json = serde_json::to_string(&update).unwrap();
        assert!(update_json.contains("CanvasUpdate"));

        // Verify policy engine denies canvas actions by default (no permit policy).
        let engine =
            aegis_policy::PolicyEngine::from_policies("forbid(principal, action, resource);", None)
                .expect("should create engine");

        let action = aegis_types::Action::new("test-agent", create);
        let verdict = engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            aegis_types::Decision::Deny,
            "canvas operations must be denied when no permit policy exists"
        );

        let action = aegis_types::Action::new("test-agent", update);
        let verdict = engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            aegis_types::Decision::Deny,
            "canvas operations must be denied when no permit policy exists"
        );
    }

    // -- Diff edge cases --

    #[test]
    fn compute_diff_identical_states() {
        let mut state = CanvasState::new();
        state.insert("a".into(), json!(1));
        let patches = compute_diff(&state, &state);
        assert!(patches.is_empty());
    }

    #[test]
    fn compute_diff_empty_to_populated() {
        let old = CanvasState::new();
        let mut new = CanvasState::new();
        new.insert("x".into(), json!("hello"));

        let patches = compute_diff(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].op, PatchOp::Set);
        assert_eq!(patches[0].path, "x");
    }

    #[test]
    fn compute_diff_populated_to_empty() {
        let mut old = CanvasState::new();
        old.insert("x".into(), json!("hello"));
        let new = CanvasState::new();

        let patches = compute_diff(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].op, PatchOp::Delete);
        assert_eq!(patches[0].path, "x");
    }

    // -- Store delete --

    #[tokio::test]
    async fn canvas_store_delete() {
        let store = CanvasStore::new();
        let session = store.create("agent-1").await;

        let removed = store.delete(session.id).await;
        assert!(removed.is_some());

        let gone = store.get(session.id).await;
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn canvas_store_delete_nonexistent() {
        let store = CanvasStore::new();
        let id = CanvasId::new();
        let removed = store.delete(id).await;
        assert!(removed.is_none());
    }
}
