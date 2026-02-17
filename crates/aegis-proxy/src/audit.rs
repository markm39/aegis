//! Process-level audit logging and Seatbelt violation harvesting.
//!
//! Provides functions to log process lifecycle events (spawn/exit) to the
//! audit ledger, and to harvest Seatbelt sandbox violation logs from macOS
//! system logs for a given process.

use std::sync::{Arc, Mutex};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, AegisError};

/// Log a process spawn event to the audit ledger.
///
/// Creates a `ProcessSpawn` action, evaluates it against the policy engine,
/// and appends both the action and verdict to the audit store.
///
/// If `session_id` is `Some`, the entry is linked to that session and its
/// action counters are incremented.
pub fn log_process_spawn(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    args: &[String],
    session_id: Option<&uuid::Uuid>,
) -> Result<(), AegisError> {
    let kind = ActionKind::ProcessSpawn {
        command: command.to_string(),
        args: args.to_vec(),
    };
    evaluate_and_log(store, engine, principal, kind, session_id)
}

/// Log a process exit event to the audit ledger.
///
/// Creates a `ProcessExit` action, evaluates it against the policy engine,
/// and appends both the action and verdict to the audit store.
///
/// If `session_id` is `Some`, the entry is linked to that session and its
/// action counters are incremented.
pub fn log_process_exit(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    exit_code: i32,
    session_id: Option<&uuid::Uuid>,
) -> Result<(), AegisError> {
    let kind = ActionKind::ProcessExit {
        command: command.to_string(),
        exit_code,
    };
    evaluate_and_log(store, engine, principal, kind, session_id)
}

/// Evaluate an action against the policy engine and log the result to the audit store.
///
/// This is the shared implementation for `log_process_spawn` and `log_process_exit`.
/// Acquires the policy lock, evaluates, acquires the store lock, and appends.
fn evaluate_and_log(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    kind: ActionKind,
    session_id: Option<&uuid::Uuid>,
) -> Result<(), AegisError> {
    let action = Action::new(principal, kind);

    let verdict = engine
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(&action);

    let mut guard = store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?;

    if let Some(sid) = session_id {
        guard.append_with_session(&action, &verdict, sid)?;
    } else {
        guard.append(&action, &verdict)?;
    }

    tracing::info!(
        action_kind = %action.kind,
        session_id = session_id.map(|s| s.to_string()),
        decision = %verdict.decision,
        "logged action"
    );

    Ok(())
}

/// Harvest Seatbelt sandbox violation logs from macOS system logs.
///
/// Runs `log show` with a predicate filtering for sandbox violations by the
/// given process ID within the specified time range. Each violation is logged
/// as a Deny audit entry.
///
/// Returns the number of violations found.
#[cfg(target_os = "macos")]
pub fn harvest_seatbelt_violations(
    store: &Arc<Mutex<AuditStore>>,
    principal: &str,
    pid: u32,
    start_time: &chrono::DateTime<chrono::Utc>,
    end_time: &chrono::DateTime<chrono::Utc>,
) -> Result<usize, AegisError> {
    let start_str = start_time.format("%Y-%m-%d %H:%M:%S%z").to_string();
    let end_str = end_time.format("%Y-%m-%d %H:%M:%S%z").to_string();

    let predicate = format!(
        "subsystem == \"com.apple.sandbox\" AND processID == {}",
        pid
    );

    tracing::debug!(
        pid,
        start = %start_str,
        end = %end_str,
        "harvesting seatbelt violations"
    );

    let output = std::process::Command::new("log")
        .arg("show")
        .arg("--predicate")
        .arg(&predicate)
        .arg("--start")
        .arg(&start_str)
        .arg("--end")
        .arg(&end_str)
        .arg("--style")
        .arg("json")
        .output()
        .map_err(|e| AegisError::SandboxError(format!("failed to run `log show`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(stderr = %stderr, "log show returned non-zero exit");
        return Ok(0);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the JSON output. macOS `log show --style json` returns an array
    // of log entries. Each entry represents a sandbox violation.
    let entries: Vec<serde_json::Value> = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            // If parsing fails (empty output, malformed JSON), treat as no violations
            tracing::debug!("no valid JSON from log show, assuming 0 violations");
            return Ok(0);
        }
    };

    let mut violation_count = 0;

    let mut store_guard = store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?;

    for entry in &entries {
        let message = entry
            .get("eventMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("seatbelt violation");

        // Create a Deny verdict for each violation. We use ToolCall as the
        // action kind since Seatbelt violations are generic OS-level denials
        // that don't map cleanly to a single ActionKind.
        let action = Action::new(
            principal,
            ActionKind::ToolCall {
                tool: "seatbelt".to_string(),
                args: serde_json::json!({
                    "violation": message,
                    "pid": pid,
                }),
            },
        );

        let verdict = aegis_types::Verdict::deny(
            action.id,
            format!("seatbelt violation: {message}"),
            None,
        );

        if let Err(e) = store_guard.append(&action, &verdict) {
            tracing::warn!(error = %e, "failed to log seatbelt violation");
        } else {
            violation_count += 1;
        }
    }

    tracing::info!(
        pid,
        violations = violation_count,
        "harvested seatbelt violations"
    );

    Ok(violation_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ledger::AuditStore;
    use aegis_policy::PolicyEngine;
    use tempfile::NamedTempFile;

    /// Returns the test deps along with the temp file handle to keep it alive
    /// for the duration of the test. SQLite holds the file descriptor, but
    /// dropping `NamedTempFile` removes the path from the filesystem.
    fn make_test_deps(
        policy_str: &str,
    ) -> (Arc<Mutex<AuditStore>>, Arc<Mutex<PolicyEngine>>, NamedTempFile) {
        let engine =
            PolicyEngine::from_policies(policy_str, None).expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");

        (Arc::new(Mutex::new(store)), Arc::new(Mutex::new(engine)), db_file)
    }

    #[test]
    fn log_process_spawn_creates_audit_entry() {
        let (store, engine, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "echo", &["hello".into()], None)
            .expect("should log spawn");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should have 1 audit entry");
    }

    #[test]
    fn log_process_exit_creates_audit_entry() {
        let (store, engine, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_exit(&store, &engine, "test-agent", "echo", 0, None)
            .expect("should log exit");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should have 1 audit entry");
    }

    #[test]
    fn spawn_and_exit_creates_two_entries() {
        let (store, engine, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "cat", &["/tmp/f".into()], None)
            .expect("should log spawn");
        log_process_exit(&store, &engine, "test-agent", "cat", 1, None)
            .expect("should log exit");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 2, "should have 2 audit entries");
    }

    #[test]
    fn denied_spawn_still_logs() {
        let (store, engine, _db) =
            make_test_deps(r#"forbid(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "rm", &["-rf".into(), "/".into()], None)
            .expect("should log even when denied");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should still have 1 audit entry for denied action");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_violations_returns_zero_for_nonexistent_pid() {
        let (store, _engine, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        let now = chrono::Utc::now();
        let start = now - chrono::Duration::seconds(1);

        let count = harvest_seatbelt_violations(&store, "test-agent", 999999999, &start, &now)
            .expect("should not error");

        assert_eq!(count, 0, "should find no violations for fake PID");
    }
}
