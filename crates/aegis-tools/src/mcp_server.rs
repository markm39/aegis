//! MCP (Model Context Protocol) stdio server.
//!
//! Exposes registered tools to agents via JSON-RPC 2.0 over stdin/stdout.
//! Each line on stdin is a JSON-RPC request; each response is written as a
//! single line on stdout.
//!
//! The server routes MCP protocol methods:
//! - `initialize` -- returns server capabilities
//! - `notifications/initialized` -- acknowledgement (no response)
//! - `tools/list` -- enumerates all registered tools
//! - `tools/call` -- executes a tool through [`ToolExecutor`]

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::executor::{AuditSink, ExecutorConfig, PolicyGate, ToolExecutor};
use crate::registry::ToolRegistry;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The method name.
    pub method: String,
    /// Optional parameters.
    #[serde(default)]
    pub params: Option<Value>,
    /// Request ID. Absent for notifications.
    #[serde(default)]
    pub id: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The result on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Mirrors the request ID.
    pub id: Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code (standard JSON-RPC or application-specific).
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC error codes.
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;

// Application-specific error codes.
const TOOL_NOT_FOUND: i64 = -32000;
const POLICY_DENIED: i64 = -32001;
const TOOL_EXECUTION_ERROR: i64 = -32002;

// ---------------------------------------------------------------------------
// McpServer
// ---------------------------------------------------------------------------

/// MCP stdio server that exposes registered tools via JSON-RPC 2.0.
///
/// The server reads JSON-RPC requests from stdin and writes responses to
/// stdout, one JSON object per line. Tool calls are routed through
/// [`ToolExecutor`] which enforces policy, timeouts, and audit logging.
pub struct McpServer {
    registry: ToolRegistry,
    executor: ToolExecutor,
}

impl McpServer {
    /// Create a new MCP server.
    ///
    /// * `registry` -- tool registry for listing and lookup.
    /// * `executor_config` -- timeout and size limit configuration.
    /// * `policy_gate` -- Cedar policy evaluator.
    /// * `audit_sink` -- audit logger.
    pub fn new(
        registry: ToolRegistry,
        executor_config: ExecutorConfig,
        policy_gate: Arc<dyn PolicyGate>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        let executor = ToolExecutor::new(
            registry.clone(),
            executor_config,
            policy_gate,
            audit_sink,
        );
        Self { registry, executor }
    }

    /// Run the server loop, reading from `stdin` and writing to `stdout`.
    ///
    /// Exits cleanly when stdin reaches EOF.
    pub async fn run(
        self,
        stdin: impl AsyncBufRead + Unpin,
        mut stdout: impl AsyncWrite + Unpin,
    ) -> Result<()> {
        let mut lines = stdin.lines();

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            // Parse JSON
            let request: JsonRpcRequest = match serde_json::from_str(&line) {
                Ok(req) => req,
                Err(_) => {
                    // JSON parse error -- respond with null id per spec
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: PARSE_ERROR,
                            message: "Parse error".to_string(),
                            data: None,
                        }),
                        id: Value::Null,
                    };
                    write_response(&mut stdout, &response).await?;
                    continue;
                }
            };

            // Notifications have no id -- handle without responding
            if request.id.is_none() {
                // Recognized notifications are silently acknowledged.
                // Unknown notifications are also ignored per JSON-RPC spec.
                continue;
            }

            let id = request.id.clone().unwrap_or(Value::Null);

            let response = match request.method.as_str() {
                "initialize" => self.handle_initialize(id),
                "tools/list" => self.handle_tools_list(id),
                "tools/call" => self.handle_tools_call(id, request.params).await,
                _ => JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: METHOD_NOT_FOUND,
                        message: format!("Method not found: {}", request.method),
                        data: None,
                    }),
                    id,
                },
            };

            write_response(&mut stdout, &response).await?;
        }

        // EOF on stdin -- clean exit
        Ok(())
    }

    /// Handle the `initialize` method.
    fn handle_initialize(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "aegis-tools",
                    "version": "0.1.0"
                }
            })),
            error: None,
            id,
        }
    }

    /// Handle the `tools/list` method.
    fn handle_tools_list(&self, id: Value) -> JsonRpcResponse {
        let tools = self.registry.list_tools();
        let tool_objects: Vec<Value> = tools
            .into_iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })
            })
            .collect();

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({ "tools": tool_objects })),
            error: None,
            id,
        }
    }

    /// Handle the `tools/call` method.
    ///
    /// Params must contain `{ "name": String, "arguments": Value }`.
    /// The call is always routed through [`ToolExecutor`] -- there is no
    /// bypass path.
    async fn handle_tools_call(&self, id: Value, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: INTERNAL_ERROR,
                        message: "Missing params for tools/call".to_string(),
                        data: None,
                    }),
                    id,
                };
            }
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name.to_string(),
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: INTERNAL_ERROR,
                        message: "Missing 'name' in tools/call params".to_string(),
                        data: None,
                    }),
                    id,
                };
            }
        };

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // All tool calls go through the executor -- this is the ONLY execution
        // path. The executor enforces input validation, size limits, Cedar
        // policy evaluation, timeout enforcement, and audit logging.
        let principal = "mcp-agent";
        match self.executor.execute(&tool_name, arguments, principal).await {
            Ok(output) => {
                // Format result as MCP content array
                let text = serde_json::to_string(&output.result)
                    .unwrap_or_else(|_| "{}".to_string());
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": text,
                        }]
                    })),
                    error: None,
                    id,
                }
            }
            Err(exec_err) => {
                let (code, message) = match &exec_err {
                    crate::executor::ExecutionError::ToolNotFound { .. } => {
                        (TOOL_NOT_FOUND, exec_err.to_string())
                    }
                    crate::executor::ExecutionError::PolicyDenied { .. } => {
                        (POLICY_DENIED, exec_err.to_string())
                    }
                    _ => (TOOL_EXECUTION_ERROR, exec_err.to_string()),
                };
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code,
                        message,
                        data: None,
                    }),
                    id,
                }
            }
        }
    }
}

/// Write a JSON-RPC response as a single line to the writer.
async fn write_response(
    writer: &mut (impl AsyncWrite + Unpin),
    response: &JsonRpcResponse,
) -> Result<()> {
    let mut line = serde_json::to_string(response)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Build the `CLAUDE_MCP_SERVERS` JSON for an agent with MCP tools enabled.
///
/// Returns a JSON string suitable for the `CLAUDE_MCP_SERVERS` environment
/// variable. The actual MCP server binary will be wired when the
/// `aegis mcp-serve` CLI command is added.
pub fn mcp_server_env_value() -> String {
    serde_json::json!({
        "aegis-tools": {
            "command": "aegis",
            "args": ["mcp-serve"]
        }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::{ToolDefinition, ToolOutput, ToolOutputMetadata};
    use crate::executor::{AuditSink, PolicyDecision, PolicyGate, ToolAuditRecord};
    use std::sync::Mutex;

    // -- Mock tool ---------------------------------------------------------

    struct MockTool {
        tool_name: String,
        tool_description: String,
        schema: serde_json::Value,
        response: serde_json::Value,
    }

    impl MockTool {
        fn new(name: &str, description: &str, schema: serde_json::Value) -> Self {
            Self {
                tool_name: name.to_string(),
                tool_description: description.to_string(),
                schema,
                response: serde_json::json!({"ok": true}),
            }
        }

        fn with_response(mut self, response: serde_json::Value) -> Self {
            self.response = response;
            self
        }
    }

    #[async_trait::async_trait]
    impl ToolDefinition for MockTool {
        fn name(&self) -> &str {
            &self.tool_name
        }

        fn description(&self) -> &str {
            &self.tool_description
        }

        fn input_schema(&self) -> serde_json::Value {
            self.schema.clone()
        }

        async fn execute(&self, _input: serde_json::Value) -> Result<ToolOutput> {
            Ok(ToolOutput {
                result: self.response.clone(),
                content: None,
                metadata: ToolOutputMetadata {
                    latency_ms: 1,
                    bytes_transferred: None,
                },
            })
        }
    }

    // -- Mock policy gates -------------------------------------------------

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

    // -- Helpers -----------------------------------------------------------

    fn make_registry_with_tools(tools: Vec<MockTool>) -> ToolRegistry {
        let registry = ToolRegistry::new();
        for tool in tools {
            registry.register(Box::new(tool)).unwrap();
        }
        registry
    }

    fn make_server(
        registry: ToolRegistry,
        policy: Arc<dyn PolicyGate>,
        sink: Arc<dyn AuditSink>,
    ) -> McpServer {
        McpServer::new(registry, ExecutorConfig::default(), policy, sink)
    }

    /// Run the server with the given input lines and return the collected
    /// output lines.
    async fn run_server(server: McpServer, input_lines: &[&str]) -> Vec<String> {
        let mut input = String::new();
        for line in input_lines {
            input.push_str(line);
            input.push('\n');
        }

        let stdin = tokio::io::BufReader::new(std::io::Cursor::new(input.into_bytes()));
        let mut stdout_buf: Vec<u8> = Vec::new();

        server.run(stdin, &mut stdout_buf).await.unwrap();

        let output = String::from_utf8(stdout_buf).unwrap();
        output
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect()
    }

    fn parse_response(line: &str) -> JsonRpcResponse {
        serde_json::from_str(line).expect("failed to parse response JSON")
    }

    // -- Tests ------------------------------------------------------------

    #[tokio::test]
    async fn test_initialize_response() {
        let registry = ToolRegistry::new();
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1
        });

        let lines = run_server(server, &[&request.to_string()]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        assert!(result.get("capabilities").is_some());
        assert!(result["capabilities"].get("tools").is_some());

        let server_info = &result["serverInfo"];
        assert_eq!(server_info["name"], "aegis-tools");
        assert_eq!(server_info["version"], "0.1.0");

        assert_eq!(resp.id, serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_tools_list_returns_registered_tools() {
        let tools = vec![
            MockTool::new(
                "read_file",
                "Read a file",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    },
                    "required": ["path"]
                }),
            ),
            MockTool::new(
                "write_file",
                "Write a file",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"]
                }),
            ),
        ];
        let registry = make_registry_with_tools(tools);
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        });

        let lines = run_server(server, &[&request.to_string()]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);

        // Tools are sorted by name in the registry
        assert_eq!(tools[0]["name"], "read_file");
        assert_eq!(tools[0]["description"], "Read a file");
        assert!(tools[0]["inputSchema"].is_object());
        assert_eq!(tools[0]["inputSchema"]["type"], "object");

        assert_eq!(tools[1]["name"], "write_file");
        assert_eq!(tools[1]["description"], "Write a file");
        assert!(tools[1]["inputSchema"]["type"] == "object");
    }

    #[tokio::test]
    async fn test_tools_call_executes_tool() {
        let tool = MockTool::new(
            "greet",
            "Greet someone",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                }
            }),
        )
        .with_response(serde_json::json!({"greeting": "hello"}));

        let registry = make_registry_with_tools(vec![tool]);
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "greet",
                "arguments": {"name": "world"}
            },
            "id": 3
        });

        let lines = run_server(server, &[&request.to_string()]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");

        // The text field contains the serialized tool result
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["greeting"], "hello");
    }

    #[tokio::test]
    async fn test_tools_call_unknown_tool_returns_error() {
        let registry = ToolRegistry::new(); // Empty -- no tools registered
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {}
            },
            "id": 4
        });

        let lines = run_server(server, &[&request.to_string()]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert!(resp.result.is_none());

        let err = resp.error.unwrap();
        assert_eq!(err.code, TOOL_NOT_FOUND);
        assert!(err.message.contains("not found"));
    }

    #[tokio::test]
    async fn test_tools_call_policy_denied() {
        let tool = MockTool::new(
            "dangerous_tool",
            "A dangerous tool",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        let registry = make_registry_with_tools(vec![tool]);
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(
            registry,
            Arc::new(DenyAllPolicy::new("access forbidden")),
            sink,
        );

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "dangerous_tool",
                "arguments": {}
            },
            "id": 5
        });

        let lines = run_server(server, &[&request.to_string()]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert!(resp.result.is_none());

        let err = resp.error.unwrap();
        assert_eq!(err.code, POLICY_DENIED);
        assert!(err.message.contains("policy denied"));
    }

    #[tokio::test]
    async fn test_notification_no_response() {
        let registry = ToolRegistry::new();
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        // Notification: has method but no id
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let lines = run_server(server, &[&notification.to_string()]).await;
        assert!(
            lines.is_empty(),
            "notification should produce no response, got: {lines:?}"
        );
    }

    #[tokio::test]
    async fn test_jsonrpc_parse_error() {
        let registry = ToolRegistry::new();
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        let lines = run_server(server, &["this is not valid json"]).await;
        assert_eq!(lines.len(), 1);

        let resp = parse_response(&lines[0]);
        assert!(resp.result.is_none());

        let err = resp.error.unwrap();
        assert_eq!(err.code, PARSE_ERROR);
        assert_eq!(err.message, "Parse error");
        assert_eq!(resp.id, Value::Null);
    }

    #[tokio::test]
    async fn test_server_exits_on_eof() {
        let registry = ToolRegistry::new();
        let sink: Arc<dyn AuditSink> = Arc::new(RecordingAuditSink::new());
        let server = make_server(registry, Arc::new(AllowAllPolicy), sink);

        // Empty input = immediate EOF
        let stdin = tokio::io::BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let mut stdout_buf: Vec<u8> = Vec::new();

        let result = server.run(stdin, &mut stdout_buf).await;
        assert!(result.is_ok(), "server should exit cleanly on EOF");
        assert!(stdout_buf.is_empty(), "no output expected for empty input");
    }

    /// SECURITY TEST: Verify that tools/call always routes through ToolExecutor.
    ///
    /// We confirm this by checking that:
    /// 1. A tool call with a deny policy returns a policy-denied error (proving
    ///    the policy gate was consulted).
    /// 2. A tool call with an allow policy produces an audit record (proving
    ///    the audit sink was invoked).
    /// 3. Both paths go through the same executor -- there is no alternate
    ///    code path that bypasses policy or audit.
    #[tokio::test]
    async fn test_tools_call_goes_through_executor() {
        // Part 1: Deny policy blocks execution
        {
            let tool = MockTool::new(
                "guarded_tool",
                "A guarded tool",
                serde_json::json!({"type": "object", "properties": {}}),
            );
            let registry = make_registry_with_tools(vec![tool]);
            let sink = Arc::new(RecordingAuditSink::new());
            let server = make_server(
                registry,
                Arc::new(DenyAllPolicy::new("blocked by test policy")),
                sink.clone() as Arc<dyn AuditSink>,
            );

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guarded_tool",
                    "arguments": {}
                },
                "id": 100
            });

            let lines = run_server(server, &[&request.to_string()]).await;
            let resp = parse_response(&lines[0]);

            // Must be denied -- executor consulted the policy gate
            let err = resp.error.as_ref().expect("expected error response");
            assert_eq!(err.code, POLICY_DENIED);
            assert!(err.message.contains("blocked by test policy"));

            // Audit sink should have recorded the denial
            let records = sink.records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].decision, "deny");
            assert_eq!(records[0].tool_name, "guarded_tool");
        }

        // Part 2: Allow policy permits execution and produces audit record
        {
            let tool = MockTool::new(
                "guarded_tool",
                "A guarded tool",
                serde_json::json!({"type": "object", "properties": {}}),
            )
            .with_response(serde_json::json!({"executed": true}));
            let registry = make_registry_with_tools(vec![tool]);
            let sink = Arc::new(RecordingAuditSink::new());
            let server = make_server(
                registry,
                Arc::new(AllowAllPolicy),
                sink.clone() as Arc<dyn AuditSink>,
            );

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guarded_tool",
                    "arguments": {}
                },
                "id": 101
            });

            let lines = run_server(server, &[&request.to_string()]).await;
            let resp = parse_response(&lines[0]);

            // Must succeed
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            let text = result["content"][0]["text"].as_str().unwrap();
            let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
            assert_eq!(parsed["executed"], true);

            // Audit sink should have recorded the successful call
            let records = sink.records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].decision, "allow");
            assert!(records[0].success);
            assert_eq!(records[0].tool_name, "guarded_tool");
            assert_eq!(records[0].principal, "mcp-agent");
        }
    }
}
