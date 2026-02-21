//! Thread-safe tool registry.
//!
//! [`ToolRegistry`] stores tool implementations behind `Arc<RwLock<...>>`
//! so tools can be registered and looked up from any async task.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};

use crate::definition::{validate_input_schema, validate_tool_name, ToolDefinition, ToolInfo};

/// A thread-safe registry of tool definitions.
///
/// Tools are stored as `Arc<dyn ToolDefinition>` so callers can share
/// references without holding the lock during execution.
#[derive(Clone)]
pub struct ToolRegistry {
    tools: Arc<RwLock<HashMap<String, Arc<dyn ToolDefinition>>>>,
}

impl ToolRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a tool. Rejects duplicate names, invalid names, and
    /// invalid input schemas.
    pub fn register(&self, tool: Box<dyn ToolDefinition>) -> Result<()> {
        let name = tool.name().to_string();
        validate_tool_name(&name)?;
        validate_input_schema(&tool.input_schema())?;

        let mut map = self
            .tools
            .write()
            .map_err(|e| anyhow::anyhow!("registry lock poisoned: {e}"))?;

        if map.contains_key(&name) {
            bail!("tool already registered: {name}");
        }

        map.insert(name, Arc::from(tool));
        Ok(())
    }

    /// Look up a tool by name.
    pub fn get_tool(&self, name: &str) -> Option<Arc<dyn ToolDefinition>> {
        let map = self.tools.read().ok()?;
        map.get(name).cloned()
    }

    /// List all registered tools (sorted by name for deterministic output).
    pub fn list_tools(&self) -> Vec<ToolInfo> {
        let map = self.tools.read().expect("registry lock poisoned");
        let mut infos: Vec<ToolInfo> = map
            .values()
            .map(|t| ToolInfo {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        infos
    }

    /// Number of registered tools.
    pub fn tool_count(&self) -> usize {
        self.tools.read().expect("registry lock poisoned").len()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::{ToolDefinition, ToolOutput, ToolOutputMetadata};

    /// A configurable mock tool for testing.
    struct MockTool {
        tool_name: String,
        tool_description: String,
        schema: serde_json::Value,
    }

    impl MockTool {
        fn new(name: &str) -> Self {
            Self {
                tool_name: name.to_string(),
                tool_description: format!("Mock tool: {name}"),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            }
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
            &self.tool_description
        }

        fn input_schema(&self) -> serde_json::Value {
            self.schema.clone()
        }

        async fn execute(&self, _input: serde_json::Value) -> anyhow::Result<ToolOutput> {
            Ok(ToolOutput {
                result: serde_json::json!({"tool": self.tool_name}),
                content: None,
                metadata: ToolOutputMetadata {
                    latency_ms: 0,
                    bytes_transferred: None,
                },
            })
        }
    }

    #[test]
    fn test_tool_registry_register_and_list() {
        let registry = ToolRegistry::new();

        registry.register(Box::new(MockTool::new("alpha"))).unwrap();
        registry.register(Box::new(MockTool::new("beta"))).unwrap();
        registry
            .register(Box::new(MockTool::new("gamma")))
            .unwrap();

        let tools = registry.list_tools();
        assert_eq!(tools.len(), 3);

        // Sorted by name
        assert_eq!(tools[0].name, "alpha");
        assert_eq!(tools[1].name, "beta");
        assert_eq!(tools[2].name, "gamma");

        // Each has a valid schema
        for tool in &tools {
            assert!(tool.input_schema.is_object());
            assert!(tool.input_schema.get("type").is_some());
        }
    }

    #[test]
    fn test_tool_registry_rejects_duplicate() {
        let registry = ToolRegistry::new();

        registry
            .register(Box::new(MockTool::new("duplicate_tool")))
            .unwrap();

        let err = registry
            .register(Box::new(MockTool::new("duplicate_tool")))
            .unwrap_err();

        assert!(
            err.to_string().contains("already registered"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn test_tool_registry_get_tool() {
        let registry = ToolRegistry::new();

        registry
            .register(Box::new(MockTool::new("lookup_test")))
            .unwrap();

        let tool = registry.get_tool("lookup_test");
        assert!(tool.is_some());
        assert_eq!(tool.unwrap().name(), "lookup_test");

        assert!(registry.get_tool("nonexistent").is_none());
    }

    #[test]
    fn test_tool_registry_tool_count() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.tool_count(), 0);

        registry.register(Box::new(MockTool::new("one"))).unwrap();
        assert_eq!(registry.tool_count(), 1);

        registry.register(Box::new(MockTool::new("two"))).unwrap();
        assert_eq!(registry.tool_count(), 2);
    }

    #[test]
    fn test_tool_registry_thread_safety() {
        let registry = ToolRegistry::new();
        let mut handles = vec![];

        for i in 0..10 {
            let reg = registry.clone();
            let handle = std::thread::spawn(move || {
                let name = format!("thread_tool_{i}");
                reg.register(Box::new(MockTool::new(&name)))
            });
            handles.push(handle);
        }

        let mut successes = 0;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                successes += 1;
            }
        }

        assert_eq!(successes, 10);
        assert_eq!(registry.tool_count(), 10);
    }

    #[test]
    fn test_tool_registry_rejects_invalid_names() {
        let registry = ToolRegistry::new();

        // Special characters should be rejected
        let bad_names = [
            "bad-name",
            "bad name",
            "bad;name",
            "../path",
            "bad\nname",
            "",
        ];

        for name in &bad_names {
            // Create a tool with an invalid name by bypassing MockTool::new
            let tool = MockTool {
                tool_name: name.to_string(),
                tool_description: "bad".to_string(),
                schema: serde_json::json!({"type": "object"}),
            };
            let result = registry.register(Box::new(tool));
            assert!(result.is_err(), "expected rejection for name: {name:?}");
        }
    }

    #[test]
    fn test_tool_registry_rejects_invalid_schema() {
        let registry = ToolRegistry::new();

        // Schema that is not an object
        let tool = MockTool::new("bad_schema").with_schema(serde_json::json!("not an object"));
        let result = registry.register(Box::new(tool));
        assert!(result.is_err());

        // Schema missing "type" field
        let tool =
            MockTool::new("missing_type").with_schema(serde_json::json!({"properties": {}}));
        let result = registry.register(Box::new(tool));
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_registry_default() {
        let registry = ToolRegistry::default();
        assert_eq!(registry.tool_count(), 0);
    }
}
