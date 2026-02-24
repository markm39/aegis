//! Agent-callable memory tools: `memory_search` and `memory_get`.
//!
//! These tools implement the [`ToolDefinition`] trait from `aegis-tools`,
//! allowing agents to search and retrieve memories through the standard
//! tool execution pipeline with policy checks and audit logging.
//!
//! ## Tools
//!
//! - **`memory_search`**: Search memories by keyword or semantic query.
//!   Returns matching entries with relevance scores.
//! - **`memory_get`**: Retrieve a specific memory by namespace and key,
//!   or list entries from a date in the daily log.
//!
//! ## Registration
//!
//! Use [`register_memory_tools`] to register both tools with a
//! [`ToolRegistry`].

use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use aegis_tools::definition::{ToolDefinition, ToolOutput, ToolOutputMetadata};
use aegis_tools::registry::ToolRegistry;

use crate::memory::MemoryStore;
use crate::memory_daily_log::{DailyLogConfig, DailyLogManager};

/// Shared memory store reference for tools.
///
/// Wraps a `MemoryStore` in a `Mutex` for thread-safety (required by the
/// `ToolDefinition: Send + Sync` bound). Also holds a daily log manager
/// for date-based retrieval.
pub struct MemoryToolContext {
    store: Mutex<MemoryStore>,
    daily_log: Option<DailyLogManager>,
}

impl MemoryToolContext {
    /// Create a new tool context with just a memory store.
    pub fn new(store: MemoryStore) -> Self {
        Self {
            store: Mutex::new(store),
            daily_log: None,
        }
    }

    /// Create a new tool context with a memory store and daily log manager.
    pub fn with_daily_log(store: MemoryStore, daily_log: DailyLogManager) -> Self {
        Self {
            store: Mutex::new(store),
            daily_log: Some(daily_log),
        }
    }
}

// ---------------------------------------------------------------------------
// memory_search tool
// ---------------------------------------------------------------------------

/// Input schema for the `memory_search` tool.
#[derive(Debug, Deserialize)]
struct MemorySearchInput {
    /// The search query string.
    query: String,
    /// Optional namespace to search in. Defaults to all accessible namespaces.
    #[serde(default)]
    namespace: Option<String>,
    /// Maximum number of results to return. Default: 10.
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    10
}

/// Single search result entry.
#[derive(Debug, Serialize, Deserialize)]
struct SearchResultEntry {
    key: String,
    value: String,
    score: f64,
    namespace: String,
}

/// The `memory_search` tool: search memories by keyword query.
pub struct MemorySearchTool {
    ctx: Arc<MemoryToolContext>,
    default_namespace: String,
}

impl MemorySearchTool {
    /// Create a new memory search tool.
    pub fn new(ctx: Arc<MemoryToolContext>, default_namespace: String) -> Self {
        Self {
            ctx,
            default_namespace,
        }
    }
}

#[async_trait]
impl ToolDefinition for MemorySearchTool {
    fn name(&self) -> &str {
        "memory_search"
    }

    fn description(&self) -> &str {
        "Search agent memories by keyword query. Returns matching entries with relevance scores."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query string"
                },
                "namespace": {
                    "type": "string",
                    "description": "Optional namespace to search in"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 10)"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let start = std::time::Instant::now();

        let params: MemorySearchInput =
            serde_json::from_value(input).context("parse memory_search input")?;

        let namespace = params
            .namespace
            .as_deref()
            .unwrap_or(&self.default_namespace);

        let limit = params.limit.min(100); // Cap at 100 to prevent abuse.

        let store = self.ctx.store.lock();
        let results = store
            .search_safe(namespace, &params.query, limit, None)
            .context("execute memory search")?;

        let entries: Vec<SearchResultEntry> = results
            .into_iter()
            .map(|(key, value, score, _ts)| SearchResultEntry {
                key,
                value,
                score,
                namespace: namespace.to_string(),
            })
            .collect();

        let result_json = serde_json::to_value(&entries).context("serialize search results")?;
        let latency = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: result_json,
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms: latency,
                bytes_transferred: None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// memory_get tool
// ---------------------------------------------------------------------------

/// Input schema for the `memory_get` tool.
#[derive(Debug, Deserialize)]
struct MemoryGetInput {
    /// The key to retrieve. Required unless `date` is specified.
    #[serde(default)]
    key: Option<String>,
    /// Optional namespace. Defaults to the configured namespace.
    #[serde(default)]
    namespace: Option<String>,
    /// Optional date (YYYY-MM-DD) to retrieve daily log entries.
    /// If specified, returns all entries from that date's log.
    #[serde(default)]
    date: Option<String>,
}

/// Response for a single memory entry.
#[derive(Debug, Serialize, Deserialize)]
struct MemoryGetResult {
    /// Whether the key was found.
    found: bool,
    /// The key that was looked up.
    key: Option<String>,
    /// The value, if found.
    value: Option<String>,
    /// Daily log entries, if a date was specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_entries: Option<Vec<DailyLogEntryOutput>>,
}

/// Daily log entry in the tool output.
#[derive(Debug, Serialize, Deserialize)]
struct DailyLogEntryOutput {
    timestamp: String,
    category: String,
    content: String,
}

/// The `memory_get` tool: retrieve a specific memory by key or date.
pub struct MemoryGetTool {
    ctx: Arc<MemoryToolContext>,
    default_namespace: String,
}

impl MemoryGetTool {
    /// Create a new memory get tool.
    pub fn new(ctx: Arc<MemoryToolContext>, default_namespace: String) -> Self {
        Self {
            ctx,
            default_namespace,
        }
    }
}

#[async_trait]
impl ToolDefinition for MemoryGetTool {
    fn name(&self) -> &str {
        "memory_get"
    }

    fn description(&self) -> &str {
        "Retrieve a specific memory by namespace and key, or list entries from a daily log by date."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The memory key to retrieve"
                },
                "namespace": {
                    "type": "string",
                    "description": "Optional namespace (default: agent namespace)"
                },
                "date": {
                    "type": "string",
                    "description": "Optional date (YYYY-MM-DD) to retrieve daily log entries"
                }
            }
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let start = std::time::Instant::now();

        let params: MemoryGetInput =
            serde_json::from_value(input).context("parse memory_get input")?;

        let namespace = params
            .namespace
            .as_deref()
            .unwrap_or(&self.default_namespace);

        // If a date was specified, return daily log entries.
        if let Some(date_str) = &params.date {
            let date = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
                .with_context(|| format!("parse date: {date_str}"))?;

            let entries = match &self.ctx.daily_log {
                Some(dl) => dl.load_date(date).unwrap_or_default(),
                None => Vec::new(),
            };

            let output_entries: Vec<DailyLogEntryOutput> = entries
                .into_iter()
                .map(|e| DailyLogEntryOutput {
                    timestamp: e.timestamp,
                    category: e.category,
                    content: e.content,
                })
                .collect();

            let result = MemoryGetResult {
                found: !output_entries.is_empty(),
                key: None,
                value: None,
                daily_entries: Some(output_entries),
            };

            let latency = start.elapsed().as_millis() as u64;
            return Ok(ToolOutput {
                result: serde_json::to_value(&result)?,
                content: None,
                metadata: ToolOutputMetadata {
                    latency_ms: latency,
                    bytes_transferred: None,
                },
            });
        }

        // Otherwise, look up by key.
        let key = params.key.as_deref().unwrap_or("");

        if key.is_empty() {
            anyhow::bail!("either 'key' or 'date' must be provided");
        }

        let store = self.ctx.store.lock();
        let value = store
            .get_safe(namespace, key)
            .context("get memory by key")?;

        let result = MemoryGetResult {
            found: value.is_some(),
            key: Some(key.to_string()),
            value,
            daily_entries: None,
        };

        let latency = start.elapsed().as_millis() as u64;
        Ok(ToolOutput {
            result: serde_json::to_value(&result)?,
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms: latency,
                bytes_transferred: None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register both memory tools (`memory_search`, `memory_get`) with the
/// given tool registry.
///
/// The `store_path` is the path to the memory SQLite database. The
/// `daily_log_dir` is an optional path to the daily log directory.
/// The `default_namespace` is used when tools are called without an
/// explicit namespace parameter.
pub fn register_memory_tools(
    registry: &ToolRegistry,
    store_path: &std::path::Path,
    daily_log_dir: Option<PathBuf>,
    default_namespace: &str,
) -> Result<()> {
    let store = MemoryStore::new(store_path).context("open memory store for tools")?;

    let daily_log = match daily_log_dir {
        Some(dir) => {
            let config = DailyLogConfig {
                log_dir: dir,
                ..Default::default()
            };
            Some(DailyLogManager::new(config).context("create daily log manager for tools")?)
        }
        None => None,
    };

    let ctx = match daily_log {
        Some(dl) => Arc::new(MemoryToolContext::with_daily_log(store, dl)),
        None => Arc::new(MemoryToolContext::new(store)),
    };

    let search_tool = MemorySearchTool::new(Arc::clone(&ctx), default_namespace.to_string());
    let get_tool = MemoryGetTool::new(ctx, default_namespace.to_string());

    registry
        .register(Box::new(search_tool))
        .context("register memory_search tool")?;
    registry
        .register(Box::new(get_tool))
        .context("register memory_get tool")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_daily_log::{DailyLogConfig, DailyLogEntry};
    use tempfile::TempDir;

    fn test_context() -> (Arc<MemoryToolContext>, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        let daily_config = DailyLogConfig {
            log_dir: dir.path().join("memory"),
            ..Default::default()
        };
        let daily_log = DailyLogManager::new(daily_config).unwrap();
        let ctx = Arc::new(MemoryToolContext::with_daily_log(store, daily_log));
        (ctx, dir)
    }

    fn test_context_no_daily() -> (Arc<MemoryToolContext>, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        let ctx = Arc::new(MemoryToolContext::new(store));
        (ctx, dir)
    }

    // -- memory_search tests --

    #[tokio::test]
    async fn test_memory_search_finds_results() {
        let (ctx, _dir) = test_context();

        ctx.store
            .lock()
            .set(
                "agent1",
                "rust_tips",
                "Rust ownership and borrowing patterns",
            )
            .unwrap();
        ctx.store
            .lock()
            .set("agent1", "go_tips", "Go goroutines and channels")
            .unwrap();

        let tool = MemorySearchTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"query": "Rust ownership"});
        let output = tool.execute(input).await.unwrap();

        let results: Vec<SearchResultEntry> = serde_json::from_value(output.result).unwrap();
        assert!(!results.is_empty(), "should find at least one result");

        let keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"rust_tips"), "should find 'rust_tips' entry");
    }

    #[tokio::test]
    async fn test_memory_search_empty_results() {
        let (ctx, _dir) = test_context();

        let tool = MemorySearchTool::new(ctx, "empty_ns".into());

        let input = serde_json::json!({"query": "nonexistent"});
        let output = tool.execute(input).await.unwrap();

        let results: Vec<SearchResultEntry> = serde_json::from_value(output.result).unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_memory_search_with_namespace() {
        let (ctx, _dir) = test_context();

        ctx.store.lock().set("ns1", "key1", "value in ns1").unwrap();
        ctx.store.lock().set("ns2", "key1", "value in ns2").unwrap();

        let tool = MemorySearchTool::new(ctx, "ns1".into());

        let input = serde_json::json!({"query": "value", "namespace": "ns2"});
        let output = tool.execute(input).await.unwrap();

        let results: Vec<SearchResultEntry> = serde_json::from_value(output.result).unwrap();
        for r in &results {
            assert_eq!(r.namespace, "ns2");
        }
    }

    #[tokio::test]
    async fn test_memory_search_caps_limit() {
        let (ctx, _dir) = test_context();

        let tool = MemorySearchTool::new(ctx, "agent1".into());

        // Request absurdly high limit -- should be capped.
        let input = serde_json::json!({"query": "test", "limit": 99999});
        let output = tool.execute(input).await.unwrap();

        // Should not error even with extreme limit.
        assert!(output.result.is_array());
    }

    #[tokio::test]
    async fn test_memory_search_has_metadata() {
        let (ctx, _dir) = test_context();

        let tool = MemorySearchTool::new(ctx, "agent1".into());
        let input = serde_json::json!({"query": "test"});
        let output = tool.execute(input).await.unwrap();

        assert!(output.content.is_none());
        // latency_ms should be reasonable.
        assert!(output.metadata.latency_ms < 5000);
    }

    // -- memory_get tests --

    #[tokio::test]
    async fn test_memory_get_by_key() {
        let (ctx, _dir) = test_context();

        ctx.store
            .lock()
            .set("agent1", "db_config", "PostgreSQL on port 5432")
            .unwrap();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"key": "db_config"});
        let output = tool.execute(input).await.unwrap();

        let result: MemoryGetResult = serde_json::from_value(output.result).unwrap();
        assert!(result.found);
        assert_eq!(result.value.as_deref(), Some("PostgreSQL on port 5432"));
    }

    #[tokio::test]
    async fn test_memory_get_missing_key() {
        let (ctx, _dir) = test_context();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"key": "nonexistent"});
        let output = tool.execute(input).await.unwrap();

        let result: MemoryGetResult = serde_json::from_value(output.result).unwrap();
        assert!(!result.found);
        assert!(result.value.is_none());
    }

    #[tokio::test]
    async fn test_memory_get_quarantined_not_returned() {
        let (ctx, _dir) = test_context();

        ctx.store
            .lock()
            .set_quarantined(
                "agent1",
                "bad_key",
                "malicious content",
                "injection detected",
            )
            .unwrap();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"key": "bad_key"});
        let output = tool.execute(input).await.unwrap();

        let result: MemoryGetResult = serde_json::from_value(output.result).unwrap();
        assert!(!result.found, "quarantined entries should not be returned");
    }

    #[tokio::test]
    async fn test_memory_get_by_date() {
        let (ctx, _dir) = test_context();

        // Write an entry to today's daily log.
        let today = chrono::Utc::now().date_naive();
        if let Some(dl) = &ctx.daily_log {
            dl.append_entry(&DailyLogEntry {
                timestamp: "14:30:00".into(),
                category: "fact".into(),
                content: "Test fact for date retrieval.".into(),
            })
            .unwrap();
        }

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let date_str = today.format("%Y-%m-%d").to_string();
        let input = serde_json::json!({"date": date_str});
        let output = tool.execute(input).await.unwrap();

        let result: MemoryGetResult = serde_json::from_value(output.result).unwrap();
        assert!(result.found);

        let daily = result.daily_entries.unwrap();
        assert!(!daily.is_empty());
        assert_eq!(daily[0].category, "fact");
        assert_eq!(daily[0].content, "Test fact for date retrieval.");
    }

    #[tokio::test]
    async fn test_memory_get_by_date_no_daily_log() {
        let (ctx, _dir) = test_context_no_daily();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"date": "2026-02-21"});
        let output = tool.execute(input).await.unwrap();

        let result: MemoryGetResult = serde_json::from_value(output.result).unwrap();
        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_memory_get_no_key_no_date_errors() {
        let (ctx, _dir) = test_context();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({});
        let result = tool.execute(input).await;
        assert!(
            result.is_err(),
            "should error when neither key nor date is provided"
        );
    }

    #[tokio::test]
    async fn test_memory_get_invalid_date_errors() {
        let (ctx, _dir) = test_context();

        let tool = MemoryGetTool::new(ctx, "agent1".into());

        let input = serde_json::json!({"date": "not-a-date"});
        let result = tool.execute(input).await;
        assert!(result.is_err(), "should error on invalid date format");
    }

    // -- Tool definition trait tests --

    #[test]
    fn test_memory_search_tool_name() {
        let (ctx, _dir) = test_context();
        let tool = MemorySearchTool::new(ctx, "agent1".into());
        assert_eq!(tool.name(), "memory_search");
    }

    #[test]
    fn test_memory_get_tool_name() {
        let (ctx, _dir) = test_context();
        let tool = MemoryGetTool::new(ctx, "agent1".into());
        assert_eq!(tool.name(), "memory_get");
    }

    #[test]
    fn test_tool_schemas_are_valid() {
        let (ctx, _dir) = test_context();

        let search = MemorySearchTool::new(Arc::clone(&ctx), "agent1".into());
        let get = MemoryGetTool::new(ctx, "agent1".into());

        let search_schema = search.input_schema();
        assert!(search_schema.is_object());
        assert_eq!(search_schema["type"], "object");
        assert!(search_schema["properties"]["query"].is_object());

        let get_schema = get.input_schema();
        assert!(get_schema.is_object());
        assert_eq!(get_schema["type"], "object");
    }

    // -- Registration test --

    #[test]
    fn test_register_memory_tools() {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("memory.db");
        let daily_log_dir = dir.path().join("memory");

        // Create the store so registration succeeds.
        let _store = MemoryStore::new(&store_path).unwrap();

        let registry = ToolRegistry::new();
        register_memory_tools(&registry, &store_path, Some(daily_log_dir), "agent1").unwrap();

        assert_eq!(registry.tool_count(), 2);
        assert!(registry.get_tool("memory_search").is_some());
        assert!(registry.get_tool("memory_get").is_some());
    }

    #[test]
    fn test_register_without_daily_log() {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("memory.db");

        let _store = MemoryStore::new(&store_path).unwrap();

        let registry = ToolRegistry::new();
        register_memory_tools(&registry, &store_path, None, "agent1").unwrap();

        assert_eq!(registry.tool_count(), 2);
    }
}
