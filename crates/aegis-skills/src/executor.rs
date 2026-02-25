//! Skill executor -- runs skills as subprocesses.
//!
//! The executor handles launching skill entry points, passing structured
//! JSON input on stdin, and reading JSON output from stdout. It enforces
//! timeouts and captures stderr for diagnostics.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;

use crate::manifest::SkillManifest;
use crate::sdk::{SkillContext, SkillInput, SkillOutput};

/// Default execution timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum stdout size we will read from a skill process (10 MB).
const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Execution mode for running a skill.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// Run the skill as an external subprocess.
    #[default]
    Subprocess,
    // Future: Native dynamic library loading.
}

/// Configuration for the skill executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum time a skill process may run before being killed.
    pub timeout: Duration,
    /// Maximum stdout output size in bytes.
    pub max_output_bytes: usize,
    /// Working directory for skill processes (defaults to skill directory).
    pub working_dir: Option<PathBuf>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: MAX_OUTPUT_BYTES,
            working_dir: None,
        }
    }
}

/// Executor for running skill entry points.
///
/// Manages subprocess lifecycle, I/O, and timeout enforcement.
pub struct SkillExecutor {
    config: ExecutorConfig,
}

impl SkillExecutor {
    /// Create a new executor with default configuration.
    pub fn new() -> Self {
        Self {
            config: ExecutorConfig::default(),
        }
    }

    /// Create an executor with a custom configuration.
    pub fn with_config(config: ExecutorConfig) -> Self {
        Self { config }
    }

    /// Execute a skill's entry point with the given input.
    ///
    /// The entry point is resolved relative to `skill_dir`. The executor
    /// determines the interpreter from the file extension and passes the
    /// input as JSON on stdin. Output is expected as JSON on stdout.
    pub async fn execute(
        &self,
        manifest: &SkillManifest,
        skill_dir: &Path,
        action: &str,
        parameters: serde_json::Value,
        context: SkillContext,
    ) -> Result<SkillOutput> {
        let entry_point = skill_dir.join(&manifest.entry_point);
        if !entry_point.exists() {
            bail!(
                "skill entry point does not exist: {}",
                entry_point.display()
            );
        }

        // Validate the entry point stays inside the skill directory
        let canonical_dir = skill_dir.canonicalize().with_context(|| {
            format!("failed to canonicalize skill dir: {}", skill_dir.display())
        })?;
        let canonical_entry = entry_point.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize entry point: {}",
                entry_point.display()
            )
        })?;
        if !canonical_entry.starts_with(&canonical_dir) {
            bail!(
                "skill entry point escapes skill directory: {}",
                entry_point.display()
            );
        }

        let input = SkillInput {
            action: action.to_string(),
            parameters,
            context,
        };

        let input_json =
            serde_json::to_string(&input).context("failed to serialize skill input")?;

        let (program, args) = resolve_interpreter(&entry_point)?;
        let work_dir = self.config.working_dir.as_deref().unwrap_or(skill_dir);

        debug!(
            skill = manifest.name,
            entry_point = %entry_point.display(),
            program = %program,
            "executing skill subprocess"
        );

        let mut child = Command::new(&program)
            .args(&args)
            .current_dir(work_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn skill process: {program}"))?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input_json.as_bytes())
                .await
                .context("failed to write to skill stdin")?;
            // Drop stdin to signal EOF
        }

        // Wait with timeout (manifest can override default)
        let effective_timeout = manifest
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.config.timeout);
        let output = tokio::time::timeout(effective_timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "skill '{}' timed out after {:.0}s",
                    manifest.name,
                    effective_timeout.as_secs_f64()
                )
            })?
            .with_context(|| format!("skill '{}' process failed", manifest.name))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into());
            bail!(
                "skill '{}' exited with code {}: {}",
                manifest.name,
                code,
                stderr.trim()
            );
        }

        // Parse stdout as JSON
        let stdout = &output.stdout;
        if stdout.len() > self.config.max_output_bytes {
            bail!(
                "skill '{}' output exceeds maximum size ({} bytes > {} bytes)",
                manifest.name,
                stdout.len(),
                self.config.max_output_bytes
            );
        }

        let stdout_str = std::str::from_utf8(stdout)
            .with_context(|| format!("skill '{}' produced non-UTF-8 output", manifest.name))?;

        // Try to parse as SkillOutput first, then fall back to wrapping raw JSON
        if let Ok(skill_output) = serde_json::from_str::<SkillOutput>(stdout_str) {
            Ok(skill_output)
        } else if let Ok(raw_value) = serde_json::from_str::<serde_json::Value>(stdout_str) {
            // Wrap raw JSON as the result field
            Ok(SkillOutput::simple(raw_value))
        } else {
            // Return raw text as a string value
            Ok(SkillOutput::simple(serde_json::Value::String(
                stdout_str.trim().to_string(),
            )))
        }
    }
}

impl Default for SkillExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine the interpreter and arguments for a skill entry point based on
/// its file extension.
///
/// Returns `(program, args)` where `args` includes the entry point path.
fn resolve_interpreter(entry_point: &Path) -> Result<(String, Vec<String>)> {
    let ext = entry_point
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let path_str = entry_point
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("entry point path is not valid UTF-8"))?
        .to_string();

    match ext {
        "sh" | "bash" => Ok(("bash".into(), vec![path_str])),
        "zsh" => Ok(("zsh".into(), vec![path_str])),
        "py" | "pyw" => Ok(("python3".into(), vec![path_str])),
        "js" | "mjs" | "cjs" => Ok(("node".into(), vec![path_str])),
        "ts" | "mts" => Ok(("npx".into(), vec!["ts-node".into(), path_str])),
        "rb" => Ok(("ruby".into(), vec![path_str])),
        "pl" => Ok(("perl".into(), vec![path_str])),
        "" => {
            // No extension -- check if file is executable, try running directly
            Ok((path_str, vec![]))
        }
        _ => {
            // Unknown extension -- try running directly
            Ok((path_str, vec![]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_interpreter_shell() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/run.sh")).unwrap();
        assert_eq!(prog, "bash");
        assert_eq!(args, vec!["/tmp/skill/run.sh"]);
    }

    #[test]
    fn test_resolve_interpreter_python() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/main.py")).unwrap();
        assert_eq!(prog, "python3");
        assert_eq!(args, vec!["/tmp/skill/main.py"]);
    }

    #[test]
    fn test_resolve_interpreter_node() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/index.js")).unwrap();
        assert_eq!(prog, "node");
        assert_eq!(args, vec!["/tmp/skill/index.js"]);
    }

    #[test]
    fn test_resolve_interpreter_typescript() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/main.ts")).unwrap();
        assert_eq!(prog, "npx");
        assert_eq!(args, vec!["ts-node", "/tmp/skill/main.ts"]);
    }

    #[test]
    fn test_resolve_interpreter_ruby() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/run.rb")).unwrap();
        assert_eq!(prog, "ruby");
        assert_eq!(args, vec!["/tmp/skill/run.rb"]);
    }

    #[test]
    fn test_resolve_interpreter_no_extension() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/run")).unwrap();
        assert_eq!(prog, "/tmp/skill/run");
        assert!(args.is_empty());
    }

    #[test]
    fn test_resolve_interpreter_unknown_extension() {
        let (prog, args) = resolve_interpreter(Path::new("/tmp/skill/run.exe")).unwrap();
        assert_eq!(prog, "/tmp/skill/run.exe");
        assert!(args.is_empty());
    }

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_output_bytes, 10 * 1024 * 1024);
        assert!(config.working_dir.is_none());
    }

    #[test]
    fn test_executor_default_creates_instance() {
        let executor = SkillExecutor::default();
        assert_eq!(executor.config.timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_execute_missing_entry_point() {
        let executor = SkillExecutor::new();
        let manifest = crate::manifest::parse_manifest(
            r#"
name = "test-skill"
version = "1.0.0"
description = "Test"
entry_point = "nonexistent.sh"
"#,
        )
        .unwrap();

        let result = executor
            .execute(
                &manifest,
                Path::new("/tmp/nonexistent-skill-dir"),
                "run",
                serde_json::json!({}),
                SkillContext::default(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not exist") || err.contains("entry point"),
            "expected entry point error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_execute_simple_skill() {
        // Create a simple shell skill that echoes JSON
        let tmp = tempfile::TempDir::new().unwrap();
        let skill_dir = tmp.path().join("echo-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();

        let script_content = r#"#!/bin/bash
# Read stdin and produce output
read input
echo '{"result": "hello", "artifacts": [], "messages": ["ok"]}'
"#;
        let script_path = skill_dir.join("run.sh");
        std::fs::write(&script_path, script_content).unwrap();

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let manifest = crate::manifest::parse_manifest(
            r#"
name = "echo-skill"
version = "1.0.0"
description = "Test"
entry_point = "run.sh"
"#,
        )
        .unwrap();

        let executor = SkillExecutor::new();
        let output = executor
            .execute(
                &manifest,
                &skill_dir,
                "echo",
                serde_json::json!({"text": "hello"}),
                SkillContext::default(),
            )
            .await
            .unwrap();

        assert_eq!(output.result, serde_json::json!("hello"));
        assert_eq!(output.messages, vec!["ok"]);
    }

    #[tokio::test]
    async fn test_execute_timeout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let skill_dir = tmp.path().join("slow-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();

        let script_content = "#!/bin/bash\nsleep 60\n";
        let script_path = skill_dir.join("slow.sh");
        std::fs::write(&script_path, script_content).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let manifest = crate::manifest::parse_manifest(
            r#"
name = "slow-skill"
version = "1.0.0"
description = "Test"
entry_point = "slow.sh"
"#,
        )
        .unwrap();

        let config = ExecutorConfig {
            timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let executor = SkillExecutor::with_config(config);

        let result = executor
            .execute(
                &manifest,
                &skill_dir,
                "run",
                serde_json::json!({}),
                SkillContext::default(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("timed out"),
            "expected timeout error, got: {err}"
        );
    }
}
