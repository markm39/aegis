/// Process-level audit logging and Seatbelt violation harvesting.
///
/// Provides functions to log process lifecycle events (spawn/exit) to the
/// audit ledger, and to harvest Seatbelt sandbox violation logs from macOS
/// system logs for a given process.
use std::sync::{Arc, Mutex};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, AegisError};

/// Log a process spawn event to the audit ledger.
///
/// Creates a `ProcessSpawn` action, evaluates it against the policy engine,
/// and appends both the action and verdict to the audit store.
pub fn log_process_spawn(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    args: &[String],
) -> Result<(), AegisError> {
    let action = Action::new(
        principal,
        ActionKind::ProcessSpawn {
            command: command.to_string(),
            args: args.to_vec(),
        },
    );

    let verdict = engine
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(&action);

    store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?
        .append(&action, &verdict)?;

    tracing::info!(
        command,
        decision = %verdict.decision,
        "logged ProcessSpawn"
    );

    Ok(())
}

/// Log a process spawn event to the audit ledger, associated with a session.
///
/// Like `log_process_spawn`, but uses `append_with_session` to link the
/// entry to the given session and increment its counters.
pub fn log_process_spawn_with_session(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    args: &[String],
    session_id: &uuid::Uuid,
) -> Result<(), AegisError> {
    let action = Action::new(
        principal,
        ActionKind::ProcessSpawn {
            command: command.to_string(),
            args: args.to_vec(),
        },
    );

    let verdict = engine
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(&action);

    store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?
        .append_with_session(&action, &verdict, session_id)?;

    tracing::info!(
        command,
        %session_id,
        decision = %verdict.decision,
        "logged ProcessSpawn (session)"
    );

    Ok(())
}

/// Log a process exit event to the audit ledger.
///
/// Creates a `ProcessExit` action, evaluates it against the policy engine,
/// and appends both the action and verdict to the audit store.
pub fn log_process_exit(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    exit_code: i32,
) -> Result<(), AegisError> {
    let action = Action::new(
        principal,
        ActionKind::ProcessExit {
            command: command.to_string(),
            exit_code,
        },
    );

    let verdict = engine
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(&action);

    store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?
        .append(&action, &verdict)?;

    tracing::info!(
        command,
        exit_code,
        decision = %verdict.decision,
        "logged ProcessExit"
    );

    Ok(())
}

/// Log a process exit event to the audit ledger, associated with a session.
///
/// Like `log_process_exit`, but uses `append_with_session` to link the
/// entry to the given session and increment its counters.
pub fn log_process_exit_with_session(
    store: &Arc<Mutex<AuditStore>>,
    engine: &Arc<Mutex<PolicyEngine>>,
    principal: &str,
    command: &str,
    exit_code: i32,
    session_id: &uuid::Uuid,
) -> Result<(), AegisError> {
    let action = Action::new(
        principal,
        ActionKind::ProcessExit {
            command: command.to_string(),
            exit_code,
        },
    );

    let verdict = engine
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(&action);

    store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?
        .append_with_session(&action, &verdict, session_id)?;

    tracing::info!(
        command,
        exit_code,
        %session_id,
        decision = %verdict.decision,
        "logged ProcessExit (session)"
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
        .map_err(|e| AegisError::LedgerError(format!("failed to run `log show`: {e}")))?;

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

    fn make_test_deps(
        policy_str: &str,
    ) -> (Arc<Mutex<AuditStore>>, Arc<Mutex<PolicyEngine>>) {
        let engine =
            PolicyEngine::from_policies(policy_str, None).expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");

        (Arc::new(Mutex::new(store)), Arc::new(Mutex::new(engine)))
    }

    #[test]
    fn log_process_spawn_creates_audit_entry() {
        let (store, engine) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "echo", &["hello".into()])
            .expect("should log spawn");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should have 1 audit entry");
    }

    #[test]
    fn log_process_exit_creates_audit_entry() {
        let (store, engine) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_exit(&store, &engine, "test-agent", "echo", 0)
            .expect("should log exit");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should have 1 audit entry");
    }

    #[test]
    fn spawn_and_exit_creates_two_entries() {
        let (store, engine) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "cat", &["/tmp/f".into()])
            .expect("should log spawn");
        log_process_exit(&store, &engine, "test-agent", "cat", 1)
            .expect("should log exit");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 2, "should have 2 audit entries");
    }

    #[test]
    fn denied_spawn_still_logs() {
        let (store, engine) =
            make_test_deps(r#"forbid(principal, action, resource);"#);

        log_process_spawn(&store, &engine, "test-agent", "rm", &["-rf".into(), "/".into()])
            .expect("should log even when denied");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should still have 1 audit entry for denied action");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_violations_returns_zero_for_nonexistent_pid() {
        let (store, _engine) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        let now = chrono::Utc::now();
        let start = now - chrono::Duration::seconds(1);

        let count = harvest_seatbelt_violations(&store, "test-agent", 999999999, &start, &now)
            .expect("should not error");

        assert_eq!(count, 0, "should find no violations for fake PID");
    }
}
