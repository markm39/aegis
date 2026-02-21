//! Core tool abstraction: the [`ToolDefinition`] trait, [`ToolOutput`], and [`ToolInfo`].
//!
//! Every tool that can be invoked by an agent implements [`ToolDefinition`].
//! The trait is `Send + Sync` so tools can be stored in a shared registry
//! and called from any async task.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A tool that an agent can invoke.
///
/// Implementations must be `Send + Sync` so the registry can hand out
/// `Arc<dyn ToolDefinition>` across tasks.
#[async_trait::async_trait]
pub trait ToolDefinition: Send + Sync {
    /// Unique, human-readable name (alphanumeric + underscores, max 64 chars).
    fn name(&self) -> &str;

    /// Short description of what the tool does.
    fn description(&self) -> &str;

    /// JSON Schema describing the valid input for [`Self::execute`].
    fn input_schema(&self) -> serde_json::Value;

    /// Run the tool with the given input and return structured output.
    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput>;
}

/// Structured output returned by a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolOutput {
    /// The structured result of the tool invocation.
    pub result: serde_json::Value,
    /// Optional base64-encoded binary content (e.g., screenshot PNG).
    pub content: Option<String>,
    /// Execution metadata for auditing and performance tracking.
    pub metadata: ToolOutputMetadata,
}

/// Execution metadata attached to every [`ToolOutput`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolOutputMetadata {
    /// Wall-clock execution time in milliseconds.
    pub latency_ms: u64,
    /// Bytes transferred during execution, if applicable.
    pub bytes_transferred: Option<u64>,
}

/// Summary information about a registered tool (returned by registry listing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// JSON Schema for valid input.
    pub input_schema: serde_json::Value,
}

/// Maximum allowed length for a tool name.
const MAX_TOOL_NAME_LEN: usize = 64;

/// Validate that a tool name contains only alphanumeric characters and
/// underscores, is non-empty, and does not exceed [`MAX_TOOL_NAME_LEN`].
pub fn validate_tool_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("tool name must not be empty");
    }
    if name.len() > MAX_TOOL_NAME_LEN {
        anyhow::bail!(
            "tool name exceeds maximum length of {MAX_TOOL_NAME_LEN} characters: {name}"
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        anyhow::bail!(
            "tool name must contain only alphanumeric characters and underscores: {name}"
        );
    }
    Ok(())
}

/// Validate that an input schema is a JSON object with a `"type"` field.
pub fn validate_input_schema(schema: &serde_json::Value) -> Result<()> {
    let obj = schema
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("input schema must be a JSON object"))?;
    if !obj.contains_key("type") {
        anyhow::bail!("input schema must contain a \"type\" field");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configurable mock tool for testing.
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

    #[test]
    fn test_tool_output_serialization() {
        let output = ToolOutput {
            result: serde_json::json!({"status": "ok", "count": 42}),
            content: Some("aGVsbG8=".to_string()),
            metadata: ToolOutputMetadata {
                latency_ms: 150,
                bytes_transferred: Some(1024),
            },
        };

        let json = serde_json::to_value(&output).unwrap();

        assert_eq!(json["result"]["status"], "ok");
        assert_eq!(json["result"]["count"], 42);
        assert_eq!(json["content"], "aGVsbG8=");
        assert_eq!(json["metadata"]["latency_ms"], 150);
        assert_eq!(json["metadata"]["bytes_transferred"], 1024);

        // Round-trip
        let back: ToolOutput = serde_json::from_value(json).unwrap();
        assert_eq!(back, output);
    }

    #[test]
    fn test_tool_output_serialization_without_content() {
        let output = ToolOutput {
            result: serde_json::json!(null),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms: 0,
                bytes_transferred: None,
            },
        };

        let json = serde_json::to_value(&output).unwrap();
        assert!(json["content"].is_null());
        assert!(json["metadata"]["bytes_transferred"].is_null());

        let back: ToolOutput = serde_json::from_value(json).unwrap();
        assert_eq!(back, output);
    }

    #[test]
    fn test_tool_name_validation() {
        // Valid names
        assert!(validate_tool_name("read_file").is_ok());
        assert!(validate_tool_name("tool1").is_ok());
        assert!(validate_tool_name("A").is_ok());
        assert!(validate_tool_name("abc_def_123").is_ok());
        assert!(validate_tool_name(&"a".repeat(64)).is_ok());

        // Invalid: empty
        assert!(validate_tool_name("").is_err());

        // Invalid: too long
        assert!(validate_tool_name(&"a".repeat(65)).is_err());

        // Invalid: special characters (injection attempts)
        assert!(validate_tool_name("read-file").is_err());
        assert!(validate_tool_name("read file").is_err());
        assert!(validate_tool_name("tool;rm -rf /").is_err());
        assert!(validate_tool_name("tool\nname").is_err());
        assert!(validate_tool_name("../etc/passwd").is_err());
        assert!(validate_tool_name("tool<script>").is_err());
        assert!(validate_tool_name("tool'OR 1=1").is_err());
        assert!(validate_tool_name("tool\"name").is_err());
        assert!(validate_tool_name("tool\0name").is_err());
    }

    #[test]
    fn test_tool_input_schema_validation() {
        // Valid schema
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        });
        assert!(validate_input_schema(&schema).is_ok());

        // Invalid: not an object
        assert!(validate_input_schema(&serde_json::json!("string")).is_err());
        assert!(validate_input_schema(&serde_json::json!(42)).is_err());
        assert!(validate_input_schema(&serde_json::json!(null)).is_err());
        assert!(validate_input_schema(&serde_json::json!([1, 2])).is_err());

        // Invalid: missing "type" field
        let no_type = serde_json::json!({"properties": {}});
        assert!(validate_input_schema(&no_type).is_err());
    }

    #[tokio::test]
    async fn test_mock_tool_execute() {
        let tool = MockTool::new(
            "test_tool",
            "a test",
            serde_json::json!({"type": "object"}),
        )
        .with_response(serde_json::json!({"answer": 42}));

        assert_eq!(tool.name(), "test_tool");
        assert_eq!(tool.description(), "a test");

        let output = tool.execute(serde_json::json!({})).await.unwrap();
        assert_eq!(output.result["answer"], 42);
    }
}
