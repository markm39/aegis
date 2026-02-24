//! Builtin tool implementations for the daemon's tool registry.
//!
//! These tools are used by the chat TUI's agentic loop to execute actions
//! through the daemon. Each tool implements [`ToolDefinition`] from `aegis-tools`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use aegis_execpolicy::{Decision, Policy};
use aegis_tools::definition::{ToolDefinition, ToolOutput, ToolOutputMetadata};
use aegis_tools::ToolRegistry;
use anyhow::{bail, Context, Result};

// BashTool is now PolicyAwareBashTool (see below, after ExecPolicy section).

// ---------------------------------------------------------------------------
// ReadFileTool
// ---------------------------------------------------------------------------

/// Read file contents from disk.
struct ReadFileTool;

/// Maximum file size we will read (500 KB).
const MAX_READ_SIZE: u64 = 500 * 1024;

#[async_trait::async_trait]
impl ToolDefinition for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Read file contents from disk (max 500KB)"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to read"
                }
            },
            "required": ["file_path"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let file_path = input
            .get("file_path")
            .and_then(|v| v.as_str())
            .context("missing required field: file_path")?;

        let start = Instant::now();

        let metadata = std::fs::metadata(file_path)
            .with_context(|| format!("cannot stat file: {file_path}"))?;

        if metadata.len() > MAX_READ_SIZE {
            bail!(
                "file too large: {} bytes (max {})",
                metadata.len(),
                MAX_READ_SIZE
            );
        }

        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("cannot read file: {file_path}"))?;

        let bytes = content.len() as u64;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "content": content,
                "size_bytes": bytes,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: Some(bytes),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// WriteFileTool
// ---------------------------------------------------------------------------

/// Write or create a file on disk, creating parent directories if needed.
struct WriteFileTool;

#[async_trait::async_trait]
impl ToolDefinition for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Write content to a file, creating parent directories if needed"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to write"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["file_path", "content"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let file_path = input
            .get("file_path")
            .and_then(|v| v.as_str())
            .context("missing required field: file_path")?;

        let content = input
            .get("content")
            .and_then(|v| v.as_str())
            .context("missing required field: content")?;

        let start = Instant::now();

        // Create parent directories if they don't exist.
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create parent directories for: {file_path}"))?;
        }

        let bytes = content.len() as u64;
        std::fs::write(file_path, content)
            .with_context(|| format!("cannot write file: {file_path}"))?;

        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "message": format!("wrote {bytes} bytes to {file_path}"),
                "bytes_written": bytes,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: Some(bytes),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// EditFileTool
// ---------------------------------------------------------------------------

/// Search and replace in a file.
struct EditFileTool;

#[async_trait::async_trait]
impl ToolDefinition for EditFileTool {
    fn name(&self) -> &str {
        "edit_file"
    }

    fn description(&self) -> &str {
        "Replace the first occurrence of old_string with new_string in a file"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to edit"
                },
                "old_string": {
                    "type": "string",
                    "description": "The exact string to find and replace"
                },
                "new_string": {
                    "type": "string",
                    "description": "The replacement string"
                }
            },
            "required": ["file_path", "old_string", "new_string"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let file_path = input
            .get("file_path")
            .and_then(|v| v.as_str())
            .context("missing required field: file_path")?;

        let old_string = input
            .get("old_string")
            .and_then(|v| v.as_str())
            .context("missing required field: old_string")?;

        let new_string = input
            .get("new_string")
            .and_then(|v| v.as_str())
            .context("missing required field: new_string")?;

        let start = Instant::now();

        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("cannot read file: {file_path}"))?;

        // Count occurrences to validate uniqueness.
        let count = content.matches(old_string).count();
        if count == 0 {
            bail!("old_string not found in {file_path}");
        }
        if count > 1 {
            bail!(
                "old_string found {count} times in {file_path}; must be unique (found {count} occurrences)"
            );
        }

        let new_content = content.replacen(old_string, new_string, 1);
        std::fs::write(file_path, &new_content)
            .with_context(|| format!("cannot write file: {file_path}"))?;

        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "message": format!("edited {file_path}: replaced 1 occurrence"),
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: Some(new_content.len() as u64),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// GlobTool
// ---------------------------------------------------------------------------

/// Find files by glob pattern.
struct GlobTool;

/// Maximum number of glob results returned.
const MAX_GLOB_RESULTS: usize = 1000;

#[async_trait::async_trait]
impl ToolDefinition for GlobTool {
    fn name(&self) -> &str {
        "glob_search"
    }

    fn description(&self) -> &str {
        "Find files matching a glob pattern (e.g., \"**/*.rs\")"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match files (e.g., \"**/*.rs\", \"src/**/*.ts\")"
                },
                "path": {
                    "type": "string",
                    "description": "Base directory to search in (defaults to current directory)"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let pattern = input
            .get("pattern")
            .and_then(|v| v.as_str())
            .context("missing required field: pattern")?;

        let base_path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");

        let start = Instant::now();

        // Construct the full glob pattern with base path.
        let full_pattern = if pattern.starts_with('/') {
            pattern.to_string()
        } else {
            format!("{base_path}/{pattern}")
        };

        let entries = glob::glob(&full_pattern)
            .with_context(|| format!("invalid glob pattern: {full_pattern}"))?;

        let mut matches: Vec<String> = Vec::new();
        for entry in entries {
            if matches.len() >= MAX_GLOB_RESULTS {
                break;
            }
            match entry {
                Ok(path) => matches.push(path.display().to_string()),
                Err(e) => {
                    tracing::debug!(error = %e, "glob entry error, skipping");
                }
            }
        }

        let count = matches.len();
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "matches": matches,
                "count": count,
                "truncated": count >= MAX_GLOB_RESULTS,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// GrepTool
// ---------------------------------------------------------------------------

/// Search file contents by regex pattern.
struct GrepTool;

/// Maximum number of grep matches returned.
const MAX_GREP_MATCHES: usize = 100;

#[async_trait::async_trait]
impl ToolDefinition for GrepTool {
    fn name(&self) -> &str {
        "grep_search"
    }

    fn description(&self) -> &str {
        "Search file contents for a regex pattern, returning matching lines with context"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (defaults to current directory)"
                },
                "include": {
                    "type": "string",
                    "description": "Glob pattern to filter files (e.g., \"*.rs\", \"*.py\")"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let pattern = input
            .get("pattern")
            .and_then(|v| v.as_str())
            .context("missing required field: pattern")?;

        let search_path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");

        let include_glob = input.get("include").and_then(|v| v.as_str());

        let start = Instant::now();

        let re = regex::Regex::new(pattern)
            .with_context(|| format!("invalid regex pattern: {pattern}"))?;

        let include_pattern = include_glob
            .map(|g| {
                let full = if g.contains('/') {
                    g.to_string()
                } else {
                    format!("**/{g}")
                };
                glob::Pattern::new(&full)
            })
            .transpose()
            .context("invalid include glob pattern")?;

        let mut matches: Vec<serde_json::Value> = Vec::new();
        search_dir(
            std::path::Path::new(search_path),
            &re,
            include_pattern.as_ref(),
            &mut matches,
        );

        let count = matches.len();
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "matches": matches,
                "count": count,
                "truncated": count >= MAX_GREP_MATCHES,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: None,
            },
        })
    }
}

/// Recursively search a directory for regex matches.
fn search_dir(
    dir: &std::path::Path,
    re: &regex::Regex,
    include: Option<&glob::Pattern>,
    matches: &mut Vec<serde_json::Value>,
) {
    if matches.len() >= MAX_GREP_MATCHES {
        return;
    }

    // If the path is a file, search it directly.
    if dir.is_file() {
        search_file(dir, re, include, matches);
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        if matches.len() >= MAX_GREP_MATCHES {
            return;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        // Skip hidden directories and common non-source directories.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') || name == "node_modules" || name == "target" {
                continue;
            }
        }

        if path.is_dir() {
            search_dir(&path, re, include, matches);
        } else if path.is_file() {
            search_file(&path, re, include, matches);
        }
    }
}

/// Search a single file for regex matches.
fn search_file(
    path: &std::path::Path,
    re: &regex::Regex,
    include: Option<&glob::Pattern>,
    matches: &mut Vec<serde_json::Value>,
) {
    // Apply include filter if specified.
    if let Some(pattern) = include {
        let path_str = path.to_string_lossy();
        if !pattern.matches(&path_str) {
            // Also try just the filename.
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !pattern.matches(name) {
                    return;
                }
            } else {
                return;
            }
        }
    }

    // Skip binary files and large files.
    if let Ok(metadata) = path.metadata() {
        if metadata.len() > MAX_READ_SIZE {
            return;
        }
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return, // Skip files that can't be read as UTF-8.
    };

    let path_str = path.display().to_string();
    for (line_num, line) in content.lines().enumerate() {
        if matches.len() >= MAX_GREP_MATCHES {
            return;
        }
        if re.is_match(line) {
            matches.push(serde_json::json!({
                "file": path_str,
                "line": line_num + 1,
                "content": line,
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// ApplyPatchTool
// ---------------------------------------------------------------------------

/// Apply a V4A structured patch to create, update, or delete files.
struct ApplyPatchTool;

#[async_trait::async_trait]
impl ToolDefinition for ApplyPatchTool {
    fn name(&self) -> &str {
        "apply_patch"
    }

    fn description(&self) -> &str {
        "Apply a V4A structured patch to create, update, or delete files"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "patch": {
                    "type": "string",
                    "description": "V4A patch content (*** Begin Patch ... *** End Patch)"
                }
            },
            "required": ["patch"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let patch = input
            .get("patch")
            .and_then(|v| v.as_str())
            .context("missing required field: patch")?;

        let start = Instant::now();

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let success = match aegis_apply_patch::apply_patch(patch, &mut stdout_buf, &mut stderr_buf)
        {
            Ok(()) => true,
            Err(e) => {
                // Write the error to stderr_buf if not already captured.
                let err_msg = e.to_string();
                if !stderr_buf.iter().any(|_| true) {
                    let _ = std::io::Write::write_all(&mut stderr_buf, err_msg.as_bytes());
                }
                false
            }
        };

        let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
        let stderr = String::from_utf8_lossy(&stderr_buf).to_string();
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "success": success,
                "stdout": stdout,
                "stderr": stderr,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: Some((stdout_buf.len() + stderr_buf.len()) as u64),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// FileSearchTool
// ---------------------------------------------------------------------------

/// Fuzzy file search with gitignore support.
struct FileSearchTool;

#[async_trait::async_trait]
impl ToolDefinition for FileSearchTool {
    fn name(&self) -> &str {
        "file_search"
    }

    fn description(&self) -> &str {
        "Fuzzy search for files by name across the project (respects .gitignore)"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Fuzzy search query for file names"
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (defaults to current directory)"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .context("missing required field: query")?;

        let search_path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");

        let start = Instant::now();

        // Run the blocking file search on a thread pool to avoid blocking
        // the async executor.
        let query_owned = query.to_string();
        let path_owned = search_path.to_string();
        let results = tokio::task::spawn_blocking(move || {
            aegis_file_search::run(
                &query_owned,
                vec![PathBuf::from(path_owned)],
                aegis_file_search::FileSearchOptions::default(),
                None,
            )
        })
        .await
        .context("file search task panicked")?
        .context("file search failed")?;

        let matches: Vec<serde_json::Value> = results
            .matches
            .iter()
            .map(|m| {
                serde_json::json!({
                    "path": m.full_path().display().to_string(),
                    "score": m.score,
                })
            })
            .collect();

        let count = matches.len();
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(ToolOutput {
            result: serde_json::json!({
                "matches": matches,
                "count": count,
                "total_match_count": results.total_match_count,
            }),
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// ExecPolicy support
// ---------------------------------------------------------------------------

/// Load an execution policy from a file, or return an empty policy.
///
/// Used by `register_builtins` to optionally gate bash commands.
fn load_exec_policy() -> Policy {
    // Look for policy files in $AEGIS_EXEC_POLICY or fall back to empty.
    if let Ok(path) = std::env::var("AEGIS_EXEC_POLICY") {
        let policy_path = std::path::Path::new(&path);
        if policy_path.exists() {
            match std::fs::read_to_string(policy_path) {
                Ok(contents) => {
                    let mut parser = aegis_execpolicy::PolicyParser::new();
                    match parser.parse(path.as_str(), &contents) {
                        Ok(()) => return parser.build(),
                        Err(e) => {
                            tracing::warn!(error = %e, path = %path, "failed to parse exec policy, using empty policy");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %path, "failed to read exec policy file, using empty policy");
                }
            }
        }
    }
    Policy::empty()
}

/// Evaluate a shell command against the execution policy.
///
/// Returns the policy decision. If no policy rules match, defaults to
/// `Decision::Prompt` (the caller's existing approval flow handles this).
fn check_command_policy(policy: &Policy, command: &str) -> Decision {
    let tokens = match shlex::split(command) {
        Some(t) => t,
        None => return Decision::Prompt, // Unparseable command -- require approval.
    };
    if tokens.is_empty() {
        return Decision::Prompt;
    }
    let evaluation = policy.check(&tokens, &|_| Decision::Prompt);
    evaluation.decision
}

// ---------------------------------------------------------------------------
// PolicyAwareBashTool
// ---------------------------------------------------------------------------

/// Bash execution gated by an optional Starlark execution policy.
///
/// Commands matching `Decision::Allow` prefix rules execute immediately.
/// Commands matching `Decision::Forbidden` rules are rejected.
/// Everything else falls through to the existing approval flow (`Decision::Prompt`).
struct PolicyAwareBashTool {
    policy: Arc<Policy>,
}

#[async_trait::async_trait]
impl ToolDefinition for PolicyAwareBashTool {
    fn name(&self) -> &str {
        "bash"
    }

    fn description(&self) -> &str {
        "Execute a shell command and return stdout/stderr"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                }
            },
            "required": ["command"]
        })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolOutput> {
        let command = input
            .get("command")
            .and_then(|v| v.as_str())
            .context("missing required field: command")?;

        // Check against execution policy.
        let decision = check_command_policy(&self.policy, command);
        if decision == Decision::Forbidden {
            bail!("command blocked by execution policy: {command}");
        }
        // Decision::Allow and Decision::Prompt both proceed to execution.
        // The chat TUI's approval flow already handles the Prompt case before
        // calling ExecuteTool, so by the time we get here the user has approved.

        let start = Instant::now();

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .output(),
        )
        .await
        .context("command timed out after 30 seconds")?
        .context("failed to execute command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        let latency_ms = start.elapsed().as_millis() as u64;

        let result = serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        });

        Ok(ToolOutput {
            result,
            content: None,
            metadata: ToolOutputMetadata {
                latency_ms,
                bytes_transferred: Some((output.stdout.len() + output.stderr.len()) as u64),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register all builtin tools with the given registry.
pub fn register_builtins(registry: &ToolRegistry) -> Result<()> {
    let policy = Arc::new(load_exec_policy());
    registry.register(Box::new(PolicyAwareBashTool { policy }))?;
    registry.register(Box::new(ReadFileTool))?;
    registry.register(Box::new(WriteFileTool))?;
    registry.register(Box::new(EditFileTool))?;
    registry.register(Box::new(GlobTool))?;
    registry.register(Box::new(GrepTool))?;
    registry.register(Box::new(ApplyPatchTool))?;
    registry.register(Box::new(FileSearchTool))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_builtins() {
        let registry = ToolRegistry::new();
        register_builtins(&registry).unwrap();
        assert_eq!(registry.tool_count(), 8);

        // Verify all tools are registered.
        assert!(registry.get_tool("bash").is_some());
        assert!(registry.get_tool("read_file").is_some());
        assert!(registry.get_tool("write_file").is_some());
        assert!(registry.get_tool("edit_file").is_some());
        assert!(registry.get_tool("glob_search").is_some());
        assert!(registry.get_tool("grep_search").is_some());
        assert!(registry.get_tool("apply_patch").is_some());
        assert!(registry.get_tool("file_search").is_some());
    }

    #[test]
    fn test_tool_schemas_valid() {
        let registry = ToolRegistry::new();
        register_builtins(&registry).unwrap();

        for info in registry.list_tools() {
            assert!(
                info.input_schema.is_object(),
                "schema for {} is not object",
                info.name
            );
            assert!(
                info.input_schema.get("type").is_some(),
                "schema for {} missing type",
                info.name
            );
            assert!(
                info.input_schema.get("properties").is_some(),
                "schema for {} missing properties",
                info.name
            );
        }
    }

    #[test]
    fn test_llm_definitions() {
        let registry = ToolRegistry::new();
        register_builtins(&registry).unwrap();

        let defs = registry.to_llm_definitions();
        assert_eq!(defs.len(), 8);

        // Verify sorted order.
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            &[
                "apply_patch",
                "bash",
                "edit_file",
                "file_search",
                "glob_search",
                "grep_search",
                "read_file",
                "write_file",
            ]
        );
    }

    #[tokio::test]
    async fn test_bash_tool_execute() {
        let tool = PolicyAwareBashTool {
            policy: Arc::new(Policy::empty()),
        };
        let input = serde_json::json!({ "command": "echo hello" });
        let output = tool.execute(input).await.unwrap();
        let stdout = output.result["stdout"].as_str().unwrap();
        assert_eq!(stdout.trim(), "hello");
        assert_eq!(output.result["exit_code"], 0);
    }

    #[tokio::test]
    async fn test_bash_tool_missing_command() {
        let tool = PolicyAwareBashTool {
            policy: Arc::new(Policy::empty()),
        };
        let input = serde_json::json!({});
        let result = tool.execute(input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_file_tool() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let tool = ReadFileTool;
        let input = serde_json::json!({ "file_path": file_path.to_str().unwrap() });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["content"], "hello world");
        assert_eq!(output.result["size_bytes"], 11);
    }

    #[tokio::test]
    async fn test_read_file_not_found() {
        let tool = ReadFileTool;
        let input = serde_json::json!({ "file_path": "/nonexistent/path/file.txt" });
        let result = tool.execute(input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_write_file_tool() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("subdir").join("output.txt");

        let tool = WriteFileTool;
        let input = serde_json::json!({
            "file_path": file_path.to_str().unwrap(),
            "content": "test content"
        });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["bytes_written"], 12);

        // Verify file was written.
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[tokio::test]
    async fn test_edit_file_tool() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("edit_test.txt");
        std::fs::write(&file_path, "hello world, hello universe").unwrap();

        let tool = EditFileTool;

        // Fails when old_string is not unique.
        let input = serde_json::json!({
            "file_path": file_path.to_str().unwrap(),
            "old_string": "hello",
            "new_string": "goodbye"
        });
        let result = tool.execute(input).await;
        assert!(result.is_err());

        // Succeeds with unique old_string.
        let input = serde_json::json!({
            "file_path": file_path.to_str().unwrap(),
            "old_string": "hello world",
            "new_string": "goodbye world"
        });
        let output = tool.execute(input).await.unwrap();
        assert!(output.result["message"]
            .as_str()
            .unwrap()
            .contains("replaced 1 occurrence"));

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "goodbye world, hello universe");
    }

    #[tokio::test]
    async fn test_edit_file_not_found() {
        let tool = EditFileTool;
        let input = serde_json::json!({
            "file_path": "/tmp/aegis_nonexistent_edit_test.txt",
            "old_string": "foo",
            "new_string": "bar"
        });
        let result = tool.execute(input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_glob_tool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "").unwrap();
        std::fs::write(dir.path().join("b.rs"), "").unwrap();
        std::fs::write(dir.path().join("c.txt"), "").unwrap();

        let tool = GlobTool;
        let input = serde_json::json!({
            "pattern": "*.rs",
            "path": dir.path().to_str().unwrap()
        });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["count"], 2);

        let matches = output.result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[tokio::test]
    async fn test_grep_tool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.rs"),
            "fn main() {\n    println!(\"hello\");\n}\n",
        )
        .unwrap();

        let tool = GrepTool;
        let input = serde_json::json!({
            "pattern": "println",
            "path": dir.path().to_str().unwrap()
        });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["count"], 1);

        let matches = output.result["matches"].as_array().unwrap();
        assert_eq!(matches[0]["line"], 2);
        assert!(matches[0]["content"].as_str().unwrap().contains("println"));
    }

    #[tokio::test]
    async fn test_apply_patch_tool_add_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("new_file.txt");

        let patch = format!(
            "*** Begin Patch\n*** Add File: {}\n+hello from patch\n+second line\n*** End Patch\n",
            file_path.display()
        );

        let tool = ApplyPatchTool;
        let input = serde_json::json!({ "patch": patch });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["success"], true);

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello from patch\nsecond line\n");
    }

    #[tokio::test]
    async fn test_apply_patch_tool_invalid_patch() {
        let tool = ApplyPatchTool;
        let input = serde_json::json!({ "patch": "not a valid patch" });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["success"], false);
        let stderr = output.result["stderr"].as_str().unwrap();
        assert!(!stderr.is_empty());
    }

    #[tokio::test]
    async fn test_file_search_tool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("lib.rs"), "pub fn lib() {}").unwrap();
        std::fs::write(dir.path().join("readme.md"), "# readme").unwrap();

        let tool = FileSearchTool;
        let input = serde_json::json!({
            "query": "main",
            "path": dir.path().to_str().unwrap()
        });
        let output = tool.execute(input).await.unwrap();
        let count = output.result["count"].as_u64().unwrap();
        assert!(count >= 1, "expected at least 1 match for 'main'");

        let matches = output.result["matches"].as_array().unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_check_command_policy_empty() {
        let policy = Policy::empty();
        // Empty policy -- everything falls through to Prompt.
        assert_eq!(check_command_policy(&policy, "ls -la"), Decision::Prompt);
        assert_eq!(check_command_policy(&policy, "rm -rf /"), Decision::Prompt);
    }

    #[test]
    fn test_check_command_policy_with_rules() {
        let policy_src = r#"
prefix_rule(pattern = ["git", "status"], decision = "allow")
prefix_rule(pattern = ["rm"], decision = "forbidden")
        "#;
        let mut parser = aegis_execpolicy::PolicyParser::new();
        parser.parse("test.rules", policy_src).unwrap();
        let policy = parser.build();

        assert_eq!(check_command_policy(&policy, "git status"), Decision::Allow);
        assert_eq!(
            check_command_policy(&policy, "rm -rf /tmp/foo"),
            Decision::Forbidden
        );
        assert_eq!(
            check_command_policy(&policy, "python script.py"),
            Decision::Prompt
        );
    }

    #[tokio::test]
    async fn test_policy_aware_bash_blocks_forbidden() {
        let policy_src = r#"
prefix_rule(pattern = ["rm"], decision = "forbidden")
        "#;
        let mut parser = aegis_execpolicy::PolicyParser::new();
        parser.parse("test.rules", policy_src).unwrap();
        let policy = Arc::new(parser.build());

        let tool = PolicyAwareBashTool { policy };
        let input = serde_json::json!({ "command": "rm -rf /tmp/test" });
        let result = tool.execute(input).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("blocked by execution policy"));
    }

    #[tokio::test]
    async fn test_grep_tool_with_include() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn hello()").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hello there").unwrap();

        let tool = GrepTool;
        let input = serde_json::json!({
            "pattern": "hello",
            "path": dir.path().to_str().unwrap(),
            "include": "*.rs"
        });
        let output = tool.execute(input).await.unwrap();
        assert_eq!(output.result["count"], 1);

        let matches = output.result["matches"].as_array().unwrap();
        assert!(matches[0]["file"].as_str().unwrap().ends_with("main.rs"));
    }
}
