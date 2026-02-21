//! Tool executor with Cedar policy gate, audit logging, and timeout enforcement.
//!
//! [`ToolExecutor`] wraps every tool call in a security pipeline:
//!
//! 1. **Input validation** -- structural checks against the tool's JSON schema.
//! 2. **Input size check** -- reject payloads exceeding a configurable limit.
//! 3. **Cedar policy evaluation** -- consult a [`PolicyGate`] before execution.
//! 4. **Timeout enforcement** -- abort if the tool exceeds its time budget.
//! 5. **Audit logging** -- record every call (allowed or denied) via [`AuditSink`].
//! 6. **Error normalization** -- all failures surface as [`ExecutionError`].
//!
//! Policy and audit integration use injected traits so this crate stays
//! decoupled from `aegis-policy` and `aegis-ledger`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::definition::ToolOutput;
use crate::registry::ToolRegistry;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the [`ToolExecutor`] security pipeline.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum wall-clock time (in milliseconds) for a single tool call.
    /// Defaults to 30 000 ms (30 seconds).
    pub default_timeout_ms: u64,
    /// Maximum serialized JSON size (in bytes) accepted as tool input.
    /// Defaults to 1 048 576 (1 MiB).
    pub max_input_size_bytes: usize,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30_000,
            max_input_size_bytes: 1_048_576, // 1 MiB
        }
    }
}

// ---------------------------------------------------------------------------
// Policy gate trait
// ---------------------------------------------------------------------------

/// Result of a policy evaluation for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The tool call is permitted.
    Allow,
    /// The tool call is denied with a human-readable reason.
    Deny { reason: String },
}

/// Policy evaluator for tool calls -- injected by the daemon.
///
/// Implementations bridge to the Cedar policy engine (or any other policy
/// backend) without this crate depending on `aegis-policy` directly.
pub trait PolicyGate: Send + Sync {
    /// Evaluate whether `principal` may invoke `tool_name`.
    ///
    /// `input_hash` is the SHA-256 hex digest of the serialized input so
    /// policies can match on it without seeing the raw (potentially secret)
    /// payload.
    fn evaluate_tool_call(
        &self,
        tool_name: &str,
        input_hash: &str,
        principal: &str,
    ) -> PolicyDecision;
}

// ---------------------------------------------------------------------------
// Audit sink trait
// ---------------------------------------------------------------------------

/// A record written to the audit log after every tool call attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolAuditRecord {
    /// Name of the tool that was invoked (or attempted).
    pub tool_name: String,
    /// SHA-256 hex digest of the serialized input.
    pub input_hash: String,
    /// The agent or entity that requested the tool call.
    pub principal: String,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Wall-clock execution time in milliseconds (0 if denied before execution).
    pub latency_ms: u64,
    /// Whether the tool executed successfully.
    pub success: bool,
    /// Error message, if the call failed for any reason.
    pub error: Option<String>,
}

/// Audit logger for tool calls -- injected by the daemon.
///
/// Implementations bridge to `aegis-ledger` (or any other audit backend)
/// without this crate depending on it directly.
pub trait AuditSink: Send + Sync {
    /// Record a tool call attempt.
    fn log_tool_call(&self, record: ToolAuditRecord);
}

// ---------------------------------------------------------------------------
// Execution errors
// ---------------------------------------------------------------------------

/// Structured error returned by [`ToolExecutor::execute`].
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    /// The requested tool is not registered.
    #[error("tool not found: {name}")]
    ToolNotFound { name: String },

    /// The serialized input exceeds [`ExecutorConfig::max_input_size_bytes`].
    #[error("input too large: {size} bytes exceeds limit of {limit} bytes")]
    InputTooLarge { size: usize, limit: usize },

    /// The input failed structural validation against the tool's schema.
    #[error("input validation failed: {reason}")]
    ValidationFailed { reason: String },

    /// The Cedar policy denied the tool call.
    #[error("policy denied tool call {tool_name}: {reason}")]
    PolicyDenied { tool_name: String, reason: String },

    /// The tool execution exceeded the configured timeout.
    #[error("tool {tool_name} timed out after {timeout_ms}ms")]
    Timeout { tool_name: String, timeout_ms: u64 },

    /// The tool returned an error during execution.
    #[error("tool {tool_name} execution failed: {source}")]
    ToolError {
        tool_name: String,
        source: anyhow::Error,
    },
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Wraps tool calls in a security pipeline: validation, policy check,
/// timeout, and audit logging.
pub struct ToolExecutor {
    registry: ToolRegistry,
    config: ExecutorConfig,
    policy_gate: Arc<dyn PolicyGate>,
    audit_sink: Arc<dyn AuditSink>,
}

impl ToolExecutor {
    /// Create a new executor.
    ///
    /// * `registry` -- the tool registry to look up tools in.
    /// * `config` -- executor configuration (timeouts, size limits).
    /// * `policy_gate` -- Cedar policy evaluator.
    /// * `audit_sink` -- audit logger.
    pub fn new(
        registry: ToolRegistry,
        config: ExecutorConfig,
        policy_gate: Arc<dyn PolicyGate>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            registry,
            config,
            policy_gate,
            audit_sink,
        }
    }

    /// Execute a tool through the full security pipeline.
    ///
    /// # Pipeline
    ///
    /// 1. Look up the tool in the registry.
    /// 2. Serialize and size-check the input.
    /// 3. Validate the input against the tool's JSON schema (structural).
    /// 4. Evaluate the Cedar policy.
    /// 5. Execute with timeout enforcement.
    /// 6. Log the result to the audit sink.
    pub async fn execute(
        &self,
        tool_name: &str,
        input: serde_json::Value,
        principal: &str,
    ) -> Result<ToolOutput, ExecutionError> {
        // 1. Look up tool
        let tool = self
            .registry
            .get_tool(tool_name)
            .ok_or_else(|| ExecutionError::ToolNotFound {
                name: tool_name.to_string(),
            })?;

        // 2. Serialize input and check size
        let serialized = serde_json::to_string(&input).map_err(|e| {
            ExecutionError::ValidationFailed {
                reason: format!("failed to serialize input: {e}"),
            }
        })?;

        if serialized.len() > self.config.max_input_size_bytes {
            let err = ExecutionError::InputTooLarge {
                size: serialized.len(),
                limit: self.config.max_input_size_bytes,
            };
            self.audit_sink.log_tool_call(ToolAuditRecord {
                tool_name: tool_name.to_string(),
                input_hash: compute_input_hash(&serialized),
                principal: principal.to_string(),
                decision: "deny".to_string(),
                latency_ms: 0,
                success: false,
                error: Some(err.to_string()),
            });
            return Err(err);
        }

        // Compute deterministic hash of serialized input
        let input_hash = compute_input_hash(&serialized);

        // 3. Validate input against tool schema (basic structural checks)
        if let Err(reason) = validate_input_against_schema(&input, &tool.input_schema()) {
            let err = ExecutionError::ValidationFailed {
                reason: reason.clone(),
            };
            self.audit_sink.log_tool_call(ToolAuditRecord {
                tool_name: tool_name.to_string(),
                input_hash,
                principal: principal.to_string(),
                decision: "deny".to_string(),
                latency_ms: 0,
                success: false,
                error: Some(err.to_string()),
            });
            return Err(err);
        }

        // 4. Policy evaluation
        let decision = self
            .policy_gate
            .evaluate_tool_call(tool_name, &input_hash, principal);

        if let PolicyDecision::Deny { reason } = &decision {
            let err = ExecutionError::PolicyDenied {
                tool_name: tool_name.to_string(),
                reason: reason.clone(),
            };
            self.audit_sink.log_tool_call(ToolAuditRecord {
                tool_name: tool_name.to_string(),
                input_hash,
                principal: principal.to_string(),
                decision: "deny".to_string(),
                latency_ms: 0,
                success: false,
                error: Some(err.to_string()),
            });
            return Err(err);
        }

        // 5. Execute with timeout
        let timeout = Duration::from_millis(self.config.default_timeout_ms);
        let start = Instant::now();

        let result = tokio::time::timeout(timeout, tool.execute(input)).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => {
                // Success
                self.audit_sink.log_tool_call(ToolAuditRecord {
                    tool_name: tool_name.to_string(),
                    input_hash,
                    principal: principal.to_string(),
                    decision: "allow".to_string(),
                    latency_ms,
                    success: true,
                    error: None,
                });
                Ok(output)
            }
            Ok(Err(tool_err)) => {
                // Tool returned an error
                let err_msg = tool_err.to_string();
                self.audit_sink.log_tool_call(ToolAuditRecord {
                    tool_name: tool_name.to_string(),
                    input_hash,
                    principal: principal.to_string(),
                    decision: "allow".to_string(),
                    latency_ms,
                    success: false,
                    error: Some(err_msg.clone()),
                });
                Err(ExecutionError::ToolError {
                    tool_name: tool_name.to_string(),
                    source: tool_err,
                })
            }
            Err(_elapsed) => {
                // Timeout
                let err = ExecutionError::Timeout {
                    tool_name: tool_name.to_string(),
                    timeout_ms: self.config.default_timeout_ms,
                };
                self.audit_sink.log_tool_call(ToolAuditRecord {
                    tool_name: tool_name.to_string(),
                    input_hash,
                    principal: principal.to_string(),
                    decision: "allow".to_string(),
                    latency_ms,
                    success: false,
                    error: Some(err.to_string()),
                });
                Err(err)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of a serialized input string.
///
/// This is deterministic: the same byte sequence always produces the same hash.
fn compute_input_hash(serialized: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Basic structural validation of `input` against a JSON Schema object.
///
/// This is intentionally lightweight (no `jsonschema` crate dependency):
/// - Checks that the input is a JSON object when the schema says `"type": "object"`.
/// - Checks that required fields are present.
/// - Checks that present fields have the correct top-level JSON type.
fn validate_input_against_schema(
    input: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    let schema_obj = match schema.as_object() {
        Some(o) => o,
        None => return Ok(()), // Non-object schemas: skip validation
    };

    // Type check
    if let Some(serde_json::Value::String(expected_type)) = schema_obj.get("type") {
        match expected_type.as_str() {
            "object" => {
                if !input.is_object() {
                    return Err("input must be a JSON object".to_string());
                }
            }
            "array" => {
                if !input.is_array() {
                    return Err("input must be a JSON array".to_string());
                }
            }
            "string" => {
                if !input.is_string() {
                    return Err("input must be a string".to_string());
                }
            }
            "number" | "integer" => {
                if !input.is_number() {
                    return Err("input must be a number".to_string());
                }
            }
            "boolean" => {
                if !input.is_boolean() {
                    return Err("input must be a boolean".to_string());
                }
            }
            _ => {}
        }
    }

    // Required fields check (only for object inputs)
    if let (Some(input_obj), Some(serde_json::Value::Array(required))) =
        (input.as_object(), schema_obj.get("required"))
    {
        for req in required {
            if let Some(field_name) = req.as_str() {
                if !input_obj.contains_key(field_name) {
                    return Err(format!("missing required field: {field_name}"));
                }
            }
        }
    }

    // Property type checks (only for object inputs with a properties schema)
    if let (Some(input_obj), Some(serde_json::Value::Object(properties))) =
        (input.as_object(), schema_obj.get("properties"))
    {
        for (field_name, field_schema) in properties {
            if let Some(field_value) = input_obj.get(field_name) {
                if let Some(serde_json::Value::String(field_type)) =
                    field_schema.get("type")
                {
                    let ok = match field_type.as_str() {
                        "string" => field_value.is_string(),
                        "number" | "integer" => field_value.is_number(),
                        "boolean" => field_value.is_boolean(),
                        "object" => field_value.is_object(),
                        "array" => field_value.is_array(),
                        _ => true, // Unknown type: pass
                    };
                    if !ok {
                        return Err(format!(
                            "field {field_name} must be of type {field_type}"
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::{ToolDefinition, ToolOutput, ToolOutputMetadata};
    use std::sync::Mutex;

    // -- Mock tool ---------------------------------------------------------

    struct MockTool {
        tool_name: String,
        schema: serde_json::Value,
        delay: Option<Duration>,
    }

    impl MockTool {
        fn new(name: &str) -> Self {
            Self {
                tool_name: name.to_string(),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                delay: None,
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }

        fn with_schema(mut self, schema: serde_json::Value) -> Self {
            self.schema = schema;
            self
        }
    }

    #[async_trait::async_trait]
    impl ToolDefinition for MockTool {
        fn name(&self) -> &str {
            &self.tool_name
        }

        fn description(&self) -> &str {
            "mock tool for testing"
        }

        fn input_schema(&self) -> serde_json::Value {
            self.schema.clone()
        }

        async fn execute(&self, _input: serde_json::Value) -> anyhow::Result<ToolOutput> {
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            Ok(ToolOutput {
                result: serde_json::json!({"status": "ok"}),
                content: None,
                metadata: ToolOutputMetadata {
                    latency_ms: 1,
                    bytes_transferred: None,
                },
            })
        }
    }

    // -- Mock policy gate --------------------------------------------------

    struct AllowAllPolicy;

    impl PolicyGate for AllowAllPolicy {
        fn evaluate_tool_call(
            &self,
            _tool_name: &str,
            _input_hash: &str,
            _principal: &str,
        ) -> PolicyDecision {
            PolicyDecision::Allow
        }
    }

    struct DenyAllPolicy {
        reason: String,
    }

    impl DenyAllPolicy {
        fn new(reason: &str) -> Self {
            Self {
                reason: reason.to_string(),
            }
        }
    }

    impl PolicyGate for DenyAllPolicy {
        fn evaluate_tool_call(
            &self,
            _tool_name: &str,
            _input_hash: &str,
            _principal: &str,
        ) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: self.reason.clone(),
            }
        }
    }

    // -- Mock audit sink ---------------------------------------------------

    struct RecordingAuditSink {
        records: Mutex<Vec<ToolAuditRecord>>,
    }

    impl RecordingAuditSink {
        fn new() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
            }
        }

        fn records(&self) -> Vec<ToolAuditRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl AuditSink for RecordingAuditSink {
        fn log_tool_call(&self, record: ToolAuditRecord) {
            self.records.lock().unwrap().push(record);
        }
    }

    // -- Helper to build executor -----------------------------------------

    fn make_executor(
        registry: ToolRegistry,
        config: ExecutorConfig,
        policy: Arc<dyn PolicyGate>,
        sink: Arc<RecordingAuditSink>,
    ) -> ToolExecutor {
        ToolExecutor::new(registry, config, policy, sink)
    }

    fn default_registry_with_tool(tool: MockTool) -> ToolRegistry {
        let registry = ToolRegistry::new();
        registry.register(Box::new(tool)).unwrap();
        registry
    }

    // -- Tests ------------------------------------------------------------

    #[tokio::test]
    async fn test_executor_allows_valid_tool_call() {
        let registry = default_registry_with_tool(MockTool::new("read_file"));
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let result = executor
            .execute("read_file", serde_json::json!({}), "agent_1")
            .await;

        assert!(result.is_ok(), "expected success, got: {result:?}");
        let output = result.unwrap();
        assert_eq!(output.result["status"], "ok");

        // Verify audit record
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tool_name, "read_file");
        assert_eq!(records[0].decision, "allow");
        assert!(records[0].success);
        assert!(records[0].error.is_none());
    }

    #[tokio::test]
    async fn test_executor_denies_when_policy_rejects() {
        let registry = default_registry_with_tool(MockTool::new("write_file"));
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(DenyAllPolicy::new("write access not permitted")),
            Arc::clone(&sink),
        );

        let result = executor
            .execute("write_file", serde_json::json!({}), "agent_1")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::PolicyDenied { tool_name, reason } => {
                assert_eq!(tool_name, "write_file");
                assert_eq!(reason, "write access not permitted");
            }
            other => panic!("expected PolicyDenied, got: {other:?}"),
        }

        // Verify audit record
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "deny");
        assert!(!records[0].success);
    }

    #[tokio::test]
    async fn test_executor_timeout_enforcement() {
        let tool = MockTool::new("slow_tool").with_delay(Duration::from_millis(200));
        let registry = default_registry_with_tool(tool);
        let sink = Arc::new(RecordingAuditSink::new());
        let config = ExecutorConfig {
            default_timeout_ms: 50,
            ..ExecutorConfig::default()
        };
        let executor = make_executor(
            registry,
            config,
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let result = executor
            .execute("slow_tool", serde_json::json!({}), "agent_1")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::Timeout {
                tool_name,
                timeout_ms,
            } => {
                assert_eq!(tool_name, "slow_tool");
                assert_eq!(timeout_ms, 50);
            }
            other => panic!("expected Timeout, got: {other:?}"),
        }

        // Verify audit record
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert!(records[0].error.as_ref().unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn test_executor_rejects_unknown_tool() {
        let registry = ToolRegistry::new(); // Empty registry
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let result = executor
            .execute("nonexistent", serde_json::json!({}), "agent_1")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::ToolNotFound { name } => {
                assert_eq!(name, "nonexistent");
            }
            other => panic!("expected ToolNotFound, got: {other:?}"),
        }

        // No audit record for unknown tools -- we don't even get to that stage
        assert_eq!(sink.records().len(), 0);
    }

    #[tokio::test]
    async fn test_executor_rejects_oversized_input() {
        let registry = default_registry_with_tool(MockTool::new("small_tool"));
        let sink = Arc::new(RecordingAuditSink::new());
        let config = ExecutorConfig {
            max_input_size_bytes: 10,
            ..ExecutorConfig::default()
        };
        let executor = make_executor(
            registry,
            config,
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let large_input = serde_json::json!({"data": "this is way too large for the limit"});
        let result = executor
            .execute("small_tool", large_input, "agent_1")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::InputTooLarge { size, limit } => {
                assert!(size > 10);
                assert_eq!(limit, 10);
            }
            other => panic!("expected InputTooLarge, got: {other:?}"),
        }

        // Audit sink should record the rejection
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(records[0].decision, "deny");
    }

    #[tokio::test]
    async fn test_executor_audit_sink_called_on_success() {
        let tool = MockTool::new("audited_tool").with_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"]
        }));
        let registry = default_registry_with_tool(tool);
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let input = serde_json::json!({"path": "/tmp/test.txt"});
        let result = executor.execute("audited_tool", input, "agent_42").await;
        assert!(result.is_ok());

        let records = sink.records();
        assert_eq!(records.len(), 1);

        let record = &records[0];
        assert_eq!(record.tool_name, "audited_tool");
        assert_eq!(record.principal, "agent_42");
        assert_eq!(record.decision, "allow");
        assert!(record.success);
        assert!(record.error.is_none());
        assert!(!record.input_hash.is_empty());
        // Hash should be a valid 64-char hex string (SHA-256)
        assert_eq!(record.input_hash.len(), 64);
        assert!(record.input_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_executor_audit_sink_called_on_denial() {
        let registry = default_registry_with_tool(MockTool::new("denied_tool"));
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(DenyAllPolicy::new("forbidden by policy")),
            Arc::clone(&sink),
        );

        let result = executor
            .execute("denied_tool", serde_json::json!({}), "untrusted_agent")
            .await;
        assert!(result.is_err());

        let records = sink.records();
        assert_eq!(records.len(), 1);

        let record = &records[0];
        assert_eq!(record.tool_name, "denied_tool");
        assert_eq!(record.principal, "untrusted_agent");
        assert_eq!(record.decision, "deny");
        assert!(!record.success);
        assert!(record.error.is_some());
        assert!(record.error.as_ref().unwrap().contains("policy denied"));
    }

    #[tokio::test]
    async fn test_executor_input_hash_is_deterministic() {
        let registry = default_registry_with_tool(MockTool::new("hash_tool"));
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let input = serde_json::json!({"key": "value", "n": 42});

        // Execute twice with the same input
        let _ = executor.execute("hash_tool", input.clone(), "agent_1").await;
        let _ = executor.execute("hash_tool", input, "agent_1").await;

        let records = sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].input_hash, records[1].input_hash,
            "same input must produce the same hash"
        );
        // Also verify it is a valid SHA-256 hex string
        assert_eq!(records[0].input_hash.len(), 64);
    }

    /// SECURITY TEST: The raw input must NOT appear in the audit record.
    /// Only the SHA-256 hash should be stored, preventing secret leakage.
    #[tokio::test]
    async fn test_executor_input_hash_hides_secrets() {
        let registry = default_registry_with_tool(MockTool::new("secret_tool"));
        let sink = Arc::new(RecordingAuditSink::new());
        let executor = make_executor(
            registry,
            ExecutorConfig::default(),
            Arc::new(AllowAllPolicy),
            Arc::clone(&sink),
        );

        let secret_value = "super_secret_api_key_12345";
        let input = serde_json::json!({"api_key": secret_value});

        let _ = executor
            .execute("secret_tool", input, "agent_1")
            .await;

        let records = sink.records();
        assert_eq!(records.len(), 1);

        let record = &records[0];

        // The raw secret must NOT appear anywhere in the audit record
        let record_json = serde_json::to_string(record).unwrap();
        assert!(
            !record_json.contains(secret_value),
            "audit record must not contain raw input secrets; got: {record_json}"
        );

        // The hash must be a SHA-256 digest, not the raw value
        assert_ne!(record.input_hash, secret_value);
        assert_eq!(record.input_hash.len(), 64);
    }
}
