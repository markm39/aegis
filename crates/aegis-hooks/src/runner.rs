//! Hook script execution engine.
//!
//! Runs discovered hook scripts as subprocesses with event data on stdin,
//! captures their stdout as a hook response, and enforces timeout limits.
//!
//! Script execution is dispatched by language:
//! - Shell (`.sh`): `sh -c <script>` with event data in `AEGIS_HOOK_EVENT` env var
//! - JavaScript (`.js`): `node <script>` with event data on stdin
//! - TypeScript (`.ts`): `npx tsx <script>` (fallback: `deno run`, `bun run`) with stdin
//! - Python (`.py`): `python3 <script>` with event data on stdin

use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::discovery::{DiscoveredHook, ScriptLanguage};
use crate::events::{HookEvent, HookResponse, HookResponseAction};

/// Maximum bytes to read from hook stdout/stderr to prevent memory exhaustion.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Policy for how hook execution errors (timeout, crash, parse failure) are treated.
///
/// `FailClosed` (the default) blocks the triggering action when a hook fails.
/// `FailOpen` permits the action, matching pre-hardening behavior. Can be set
/// via the `AEGIS_HOOK_FAIL_OPEN=1` environment variable for development.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFailurePolicy {
    /// Block the action when a hook fails to produce a valid response.
    FailClosed,
    /// Permit the action when a hook fails (use only in development).
    FailOpen,
}

impl Default for HookFailurePolicy {
    fn default() -> Self {
        if std::env::var("AEGIS_HOOK_FAIL_OPEN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            HookFailurePolicy::FailOpen
        } else {
            HookFailurePolicy::FailClosed
        }
    }
}

impl HookFailurePolicy {
    /// Return the appropriate response for an error condition.
    fn error_response(&self, reason: &str, message: String) -> HookResponse {
        match self {
            HookFailurePolicy::FailClosed => HookResponse::block(reason, message),
            HookFailurePolicy::FailOpen => HookResponse {
                action: HookResponseAction::Allow,
                message: format!("[fail-open] {message}"),
                payload: None,
                reason: Some(reason.to_string()),
            },
        }
    }
}

/// Result of executing a single hook script.
#[derive(Debug, Clone)]
pub struct HookExecution {
    /// The event name that triggered this hook.
    pub event_name: String,

    /// Path to the script that was executed.
    pub script_path: std::path::PathBuf,

    /// The parsed response from the hook, or a default allow on parse failure.
    pub response: HookResponse,

    /// Execution duration.
    pub duration: Duration,

    /// Whether the hook executed successfully (exited 0 and produced valid output).
    pub success: bool,

    /// Error message if the hook failed.
    pub error: Option<String>,
}

/// Execute a single hook script with the given event data.
///
/// The script receives the event as JSON on stdin (or in an environment
/// variable for shell scripts). Its stdout is parsed as a JSON
/// [`HookResponse`]. Exit codes are interpreted as:
/// - 0: success, stdout is parsed as the response
/// - 1: hook wants to block/modify (stdout is parsed for details)
/// - 2+: hook error (blocked by default under fail-closed policy)
///
/// Execution is bounded by `timeout_ms`. If the script exceeds the timeout,
/// the process is killed and the action is blocked (under fail-closed policy).
///
/// The `failure_policy` controls whether errors result in Block or Allow.
/// Default is `FailClosed`; set `AEGIS_HOOK_FAIL_OPEN=1` for development.
pub async fn execute_hook(hook: &DiscoveredHook, event: &HookEvent) -> HookExecution {
    execute_hook_with_policy(hook, event, HookFailurePolicy::default()).await
}

/// Execute a hook with an explicit failure policy.
pub async fn execute_hook_with_policy(
    hook: &DiscoveredHook,
    event: &HookEvent,
    failure_policy: HookFailurePolicy,
) -> HookExecution {
    let start = std::time::Instant::now();
    let event_json = match serde_json::to_string(event) {
        Ok(json) => json,
        Err(e) => {
            let msg = format!("failed to serialize event: {e}");
            return HookExecution {
                event_name: event.event_name().to_string(),
                script_path: hook.script_path.clone(),
                response: failure_policy.error_response("serialize_failure", msg.clone()),
                duration: start.elapsed(),
                success: false,
                error: Some(msg),
            };
        }
    };

    let timeout = Duration::from_millis(hook.timeout_ms);

    let result = tokio::time::timeout(
        timeout,
        run_script(&hook.script_path, hook.language, &event_json),
    )
    .await;

    let duration = start.elapsed();

    match result {
        Ok(Ok((exit_code, stdout, stderr))) => interpret_result(
            event,
            hook,
            exit_code,
            &stdout,
            &stderr,
            duration,
            failure_policy,
        ),
        Ok(Err(e)) => HookExecution {
            event_name: event.event_name().to_string(),
            script_path: hook.script_path.clone(),
            response: failure_policy.error_response("execution_failure", e.clone()),
            duration,
            success: false,
            error: Some(e),
        },
        Err(_elapsed) => {
            let msg = format!("hook timed out after {}ms", hook.timeout_ms);
            tracing::warn!(
                script = %hook.script_path.display(),
                timeout_ms = hook.timeout_ms,
                "hook script timed out"
            );
            HookExecution {
                event_name: event.event_name().to_string(),
                script_path: hook.script_path.clone(),
                response: failure_policy.error_response("hook_timeout", msg.clone()),
                duration,
                success: false,
                error: Some(msg),
            }
        }
    }
}

/// Interpret the exit code and output of a hook script.
fn interpret_result(
    event: &HookEvent,
    hook: &DiscoveredHook,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
    duration: Duration,
    failure_policy: HookFailurePolicy,
) -> HookExecution {
    let event_name = event.event_name().to_string();
    let script_path = hook.script_path.clone();

    // Log stderr if present (always informational).
    if !stderr.is_empty() {
        tracing::debug!(
            script = %hook.script_path.display(),
            stderr = %truncate(stderr, 500),
            "hook stderr output"
        );
    }

    match exit_code {
        0 | 1 => {
            // Exit 0: success. Exit 1: hook wants to block/modify.
            // In both cases, try to parse stdout as HookResponse.
            let response = parse_hook_stdout(stdout, failure_policy);
            HookExecution {
                event_name,
                script_path,
                response,
                duration,
                success: true,
                error: None,
            }
        }
        code => {
            // Exit 2+: hook error. Apply failure policy (default: block).
            let err_msg = if stderr.is_empty() {
                format!("hook exited with code {code}")
            } else {
                format!("hook exited with code {code}: {}", truncate(stderr, 500))
            };
            tracing::warn!(
                script = %hook.script_path.display(),
                exit_code = code,
                "hook script error"
            );
            HookExecution {
                event_name,
                script_path,
                response: failure_policy
                    .error_response(&format!("exit_code_{code}"), err_msg.clone()),
                duration,
                success: false,
                error: Some(err_msg),
            }
        }
    }
}

/// Parse hook stdout as a JSON [`HookResponse`].
///
/// If stdout is empty, the hook is treated as a successful no-op (allow).
/// A hook that exits 0 with no output is intentionally permitting the action.
/// If stdout is present but not valid JSON, the failure policy applies.
fn parse_hook_stdout(stdout: &str, failure_policy: HookFailurePolicy) -> HookResponse {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        // Empty stdout from a successfully-exited hook (exit 0/1) means
        // the hook chose not to interfere. This is an explicit allow.
        return HookResponse::allow();
    }

    match serde_json::from_str::<HookResponse>(trimmed) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!(
                error = %e,
                stdout = %truncate(trimmed, 200),
                "hook stdout is not valid HookResponse JSON"
            );
            failure_policy
                .error_response("parse_failure", format!("hook produced invalid JSON: {e}"))
        }
    }
}

/// Execute a script file using the appropriate interpreter.
async fn run_script(
    script_path: &Path,
    language: ScriptLanguage,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    match language {
        ScriptLanguage::Shell => run_shell_script(script_path, event_json).await,
        ScriptLanguage::JavaScript => run_node_script(script_path, event_json).await,
        ScriptLanguage::TypeScript => run_typescript_script(script_path, event_json).await,
        ScriptLanguage::Python => run_python_script(script_path, event_json).await,
    }
}

/// Set the safe environment variables on a hook subprocess command.
///
/// Clears inherited env and provides only:
/// - PATH, HOME, TMPDIR -- required for basic operation
/// - AEGIS_HOOK_EVENT -- the serialized event data
/// - LANG, LC_ALL -- locale for consistent text processing
///
/// This prevents hook scripts from accessing secrets like API keys,
/// bot tokens, or database credentials from the parent process.
fn apply_safe_env(cmd: &mut Command, event_json: &str) {
    cmd.env_clear();

    // System essentials.
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        cmd.env("TMPDIR", tmpdir);
    }

    // Locale.
    cmd.env("LANG", "en_US.UTF-8");
    cmd.env("LC_ALL", "en_US.UTF-8");

    // Hook-specific data.
    cmd.env("AEGIS_HOOK_EVENT", event_json);
}

/// Run a shell script via `sh`.
///
/// Shell scripts receive the event JSON in the `AEGIS_HOOK_EVENT` environment
/// variable (since piping stdin to `sh -c` is less ergonomic).
async fn run_shell_script(
    script_path: &Path,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new("sh");
    cmd.arg(script_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_safe_env(&mut cmd, event_json);

    if let Some(parent) = script_path.parent() {
        cmd.current_dir(parent);
    }

    spawn_and_collect(&mut cmd).await
}

/// Run a JavaScript file via `node`.
async fn run_node_script(
    script_path: &Path,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new("node");
    cmd.arg(script_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_safe_env(&mut cmd, event_json);

    if let Some(parent) = script_path.parent() {
        cmd.current_dir(parent);
    }

    spawn_write_stdin_and_collect(&mut cmd, event_json).await
}

/// Run a TypeScript file, trying `npx tsx`, then `deno run`, then `bun run`.
async fn run_typescript_script(
    script_path: &Path,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    // Try npx tsx first (most common in Node.js projects).
    let npx_result = try_typescript_runner(
        "npx",
        &["tsx", &script_path.to_string_lossy()],
        script_path,
        event_json,
    )
    .await;
    if npx_result.is_ok() {
        return npx_result;
    }

    // Try deno.
    let deno_result = try_typescript_runner(
        "deno",
        &[
            "run",
            "--allow-read",
            "--allow-env",
            &script_path.to_string_lossy(),
        ],
        script_path,
        event_json,
    )
    .await;
    if deno_result.is_ok() {
        return deno_result;
    }

    // Try bun.
    let bun_result = try_typescript_runner(
        "bun",
        &["run", &script_path.to_string_lossy()],
        script_path,
        event_json,
    )
    .await;
    if bun_result.is_ok() {
        return bun_result;
    }

    Err("no TypeScript runtime found (tried npx tsx, deno, bun). \
         Install one of: tsx (npm i -g tsx), deno, or bun"
        .to_string())
}

/// Try a single TypeScript runner command.
async fn try_typescript_runner(
    program: &str,
    args: &[&str],
    script_path: &Path,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_safe_env(&mut cmd, event_json);

    if let Some(parent) = script_path.parent() {
        cmd.current_dir(parent);
    }

    spawn_write_stdin_and_collect(&mut cmd, event_json).await
}

/// Run a Python file via `python3`.
async fn run_python_script(
    script_path: &Path,
    event_json: &str,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new("python3");
    cmd.arg(script_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_safe_env(&mut cmd, event_json);

    if let Some(parent) = script_path.parent() {
        cmd.current_dir(parent);
    }

    spawn_write_stdin_and_collect(&mut cmd, event_json).await
}

/// Spawn a command and collect its stdout/stderr (no stdin writing).
async fn spawn_and_collect(cmd: &mut Command) -> Result<(i32, String, String), String> {
    let child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn hook process: {e}"))?;

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for hook process: {e}"))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = truncate_bytes_to_string(&output.stdout, MAX_OUTPUT_BYTES);
    let stderr = truncate_bytes_to_string(&output.stderr, MAX_OUTPUT_BYTES);

    Ok((exit_code, stdout, stderr))
}

/// Spawn a command, write event JSON to stdin, and collect output.
async fn spawn_write_stdin_and_collect(
    cmd: &mut Command,
    input: &str,
) -> Result<(i32, String, String), String> {
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn hook process: {e}"))?;

    // Write event data to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
        // Drop stdin to signal EOF.
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for hook process: {e}"))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = truncate_bytes_to_string(&output.stdout, MAX_OUTPUT_BYTES);
    let stderr = truncate_bytes_to_string(&output.stderr, MAX_OUTPUT_BYTES);

    Ok((exit_code, stdout, stderr))
}

/// Convert bytes to a string, truncating to max_bytes at a valid UTF-8 boundary.
fn truncate_bytes_to_string(bytes: &[u8], max_bytes: usize) -> String {
    let slice = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).to_string()
}

/// Truncate a string for log output.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Execute multiple hooks for a single event, collecting all results.
///
/// Hooks are executed sequentially. If any hook returns `Block`, subsequent
/// hooks are still executed (for audit purposes) but the final aggregate
/// response will be `Block`. If any hook returns `Modify`, the modified
/// payload is passed to subsequent hooks.
pub async fn execute_hooks_for_event(
    hooks: &[&DiscoveredHook],
    event: &HookEvent,
) -> Vec<HookExecution> {
    let mut results = Vec::with_capacity(hooks.len());

    for hook in hooks {
        let execution = execute_hook(hook, event).await;
        results.push(execution);
    }

    results
}

/// Aggregate multiple hook execution results into a single response.
///
/// Aggregation rules:
/// - If any hook returned `Block`, the aggregate is `Block`.
/// - If any hook returned `Modify` (and none blocked), the aggregate is
///   `Modify` with the last modifier's payload.
/// - Otherwise, the aggregate is `Allow`.
pub fn aggregate_responses(executions: &[HookExecution]) -> HookResponse {
    // Start from Allow: aggregation combines explicit hook responses.
    // Individual hooks already applied the failure policy on errors.
    let mut aggregate = HookResponse::allow();

    for exec in executions {
        match exec.response.action {
            HookResponseAction::Block => {
                aggregate.action = HookResponseAction::Block;
                if !exec.response.message.is_empty() {
                    aggregate.message = exec.response.message.clone();
                }
            }
            HookResponseAction::Modify => {
                // Only apply modification if not already blocked.
                if aggregate.action != HookResponseAction::Block {
                    aggregate.action = HookResponseAction::Modify;
                    aggregate.payload = exec.response.payload.clone();
                    if !exec.response.message.is_empty() {
                        aggregate.message = exec.response.message.clone();
                    }
                }
            }
            HookResponseAction::Allow => {
                // Preserve the message from allow responses if no
                // higher-priority action has set one.
                if aggregate.action == HookResponseAction::Allow
                    && aggregate.message.is_empty()
                    && !exec.response.message.is_empty()
                {
                    aggregate.message = exec.response.message.clone();
                }
            }
        }
    }

    aggregate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_stdout_returns_allow() {
        // Empty stdout from a successfully-exited hook is an explicit allow.
        let resp = parse_hook_stdout("", HookFailurePolicy::FailClosed);
        assert_eq!(resp.action, HookResponseAction::Allow);
    }

    #[test]
    fn parse_valid_block_response() {
        let stdout = r#"{"action": "block", "message": "denied by policy"}"#;
        let resp = parse_hook_stdout(stdout, HookFailurePolicy::FailClosed);
        assert_eq!(resp.action, HookResponseAction::Block);
        assert_eq!(resp.message, "denied by policy");
    }

    #[test]
    fn parse_modify_with_payload() {
        let stdout =
            r#"{"action": "modify", "message": "redacted", "payload": {"content": "***"}}"#;
        let resp = parse_hook_stdout(stdout, HookFailurePolicy::FailClosed);
        assert_eq!(resp.action, HookResponseAction::Modify);
        assert_eq!(resp.payload.unwrap()["content"], "***");
    }

    #[test]
    fn parse_invalid_json_blocks_under_fail_closed() {
        let resp = parse_hook_stdout("not json at all", HookFailurePolicy::FailClosed);
        assert_eq!(resp.action, HookResponseAction::Block);
        assert_eq!(resp.reason.as_deref(), Some("parse_failure"));
    }

    #[test]
    fn parse_invalid_json_allows_under_fail_open() {
        let resp = parse_hook_stdout("not json at all", HookFailurePolicy::FailOpen);
        assert_eq!(resp.action, HookResponseAction::Allow);
        assert_eq!(resp.reason.as_deref(), Some("parse_failure"));
    }

    #[test]
    fn aggregate_all_allow() {
        let executions = vec![
            make_execution(HookResponseAction::Allow, None),
            make_execution(HookResponseAction::Allow, None),
        ];
        let agg = aggregate_responses(&executions);
        assert_eq!(agg.action, HookResponseAction::Allow);
    }

    #[test]
    fn aggregate_one_block() {
        let executions = vec![
            make_execution(HookResponseAction::Allow, None),
            make_execution(HookResponseAction::Block, None),
            make_execution(HookResponseAction::Allow, None),
        ];
        let agg = aggregate_responses(&executions);
        assert_eq!(agg.action, HookResponseAction::Block);
    }

    #[test]
    fn aggregate_modify_then_block() {
        let executions = vec![
            make_execution(
                HookResponseAction::Modify,
                Some(serde_json::json!({"x": 1})),
            ),
            make_execution(HookResponseAction::Block, None),
        ];
        let agg = aggregate_responses(&executions);
        assert_eq!(agg.action, HookResponseAction::Block);
    }

    #[test]
    fn aggregate_modify_without_block() {
        let payload = serde_json::json!({"filtered": true});
        let executions = vec![
            make_execution(HookResponseAction::Allow, None),
            make_execution(HookResponseAction::Modify, Some(payload.clone())),
        ];
        let agg = aggregate_responses(&executions);
        assert_eq!(agg.action, HookResponseAction::Modify);
        assert_eq!(agg.payload, Some(payload));
    }

    #[test]
    fn truncate_within_limit() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_at_limit() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    fn make_execution(
        action: HookResponseAction,
        payload: Option<serde_json::Value>,
    ) -> HookExecution {
        HookExecution {
            event_name: "test".to_string(),
            script_path: std::path::PathBuf::from("/test.sh"),
            response: HookResponse {
                action,
                message: String::new(),
                payload,
                reason: None,
            },
            duration: Duration::from_millis(10),
            success: true,
            error: None,
        }
    }

    #[tokio::test]
    async fn execute_shell_hook_integration() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test_hook.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"action\": \"allow\", \"message\": \"ok\"}'",
        )
        .unwrap();

        // Make executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let hook = DiscoveredHook {
            event: "pre_tool_use".to_string(),
            script_path: script,
            language: ScriptLanguage::Shell,
            timeout_ms: 5000,
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::PreToolUse {
            tool_name: "Bash".to_string(),
            arguments: serde_json::json!({"command": "ls"}),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(result.success);
        assert_eq!(result.response.action, HookResponseAction::Allow);
        assert_eq!(result.response.message, "ok");
    }

    #[tokio::test]
    async fn execute_shell_hook_block() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("blocker.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"action\": \"block\", \"message\": \"nope\"}'\nexit 1",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let hook = DiscoveredHook {
            event: "pre_tool_use".to_string(),
            script_path: script,
            language: ScriptLanguage::Shell,
            timeout_ms: 5000,
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::PreToolUse {
            tool_name: "Bash".to_string(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(result.success);
        assert_eq!(result.response.action, HookResponseAction::Block);
    }

    #[tokio::test]
    async fn execute_hook_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("slow.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 60").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let hook = DiscoveredHook {
            event: "on_message".to_string(),
            script_path: script,
            language: ScriptLanguage::Shell,
            timeout_ms: 200, // 200ms timeout.
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::OnMessage {
            sender: "user".to_string(),
            content: "hello".to_string(),
            channel: "test".to_string(),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn execute_hook_error_exit() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 2").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let hook = DiscoveredHook {
            event: "on_error".to_string(),
            script_path: script,
            language: ScriptLanguage::Shell,
            timeout_ms: 5000,
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::OnError {
            error: "something broke".to_string(),
            context: "test".to_string(),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("exited with code 2"));
        // Fail-closed: error exit blocks the action.
        assert_eq!(result.response.action, HookResponseAction::Block);
        assert_eq!(result.response.reason.as_deref(), Some("exit_code_2"));
    }

    #[tokio::test]
    async fn execute_python_hook() {
        // Only run if python3 is available.
        if which_sync("python3").is_none() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("check.py");
        std::fs::write(
            &script,
            r#"
import sys, json
event = json.load(sys.stdin)
print(json.dumps({"action": "allow", "message": f"processed {event['event']}"}))
"#,
        )
        .unwrap();

        let hook = DiscoveredHook {
            event: "on_agent_start".to_string(),
            script_path: script,
            language: ScriptLanguage::Python,
            timeout_ms: 10_000,
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::OnAgentStart {
            agent_name: "claude-1".to_string(),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(result.success, "error: {:?}", result.error);
        assert_eq!(result.response.action, HookResponseAction::Allow);
        assert!(result.response.message.contains("on_agent_start"));
    }

    #[tokio::test]
    async fn hook_env_isolation_blocks_secrets() {
        // Set a fake secret in the parent environment.
        std::env::set_var("AEGIS_TEST_SECRET_TOKEN", "super-secret-value");

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("env_check.sh");
        // Hook that tries to read the secret and reports it.
        std::fs::write(
            &script,
            r#"#!/bin/sh
if [ -n "$AEGIS_TEST_SECRET_TOKEN" ]; then
    echo '{"action": "block", "message": "LEAKED"}'
    exit 1
else
    echo '{"action": "allow", "message": "isolated"}'
fi
"#,
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let hook = DiscoveredHook {
            event: "pre_tool_use".to_string(),
            script_path: script,
            language: ScriptLanguage::Shell,
            timeout_ms: 5000,
            enabled: true,
            source: crate::discovery::DiscoverySource::Convention,
        };

        let event = HookEvent::PreToolUse {
            tool_name: "Bash".to_string(),
            arguments: serde_json::json!({"command": "test"}),
        };

        let result = execute_hook(&hook, &event).await;
        assert!(result.success);
        assert_eq!(result.response.action, HookResponseAction::Allow);
        assert_eq!(result.response.message, "isolated");

        // Clean up.
        std::env::remove_var("AEGIS_TEST_SECRET_TOKEN");
    }

    /// Check if a command is available in PATH.
    fn which_sync(cmd: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let full = dir.join(cmd);
                if full.is_file() {
                    Some(full)
                } else {
                    None
                }
            })
        })
    }
}
