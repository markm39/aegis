//! E2E test harness for daemon integration testing.
//!
//! [`DaemonTestHarness`] manages the full lifecycle of a daemon test:
//! temporary directory creation with restrictive permissions, config file
//! writing, daemon process startup, readiness polling via Unix socket,
//! command sending/receiving, and cleanup on drop.
//!
//! # Security
//!
//! - Temporary directories are created with mode 0700 (owner-only access)
//! - Test configs never contain real API keys or tokens
//! - Daemon processes are killed on drop, even if the test panics
//! - All fixture files are validated before use
//!
//! # Example
//!
//! ```no_run
//! use aegis_harness::daemon_harness::DaemonTestHarness;
//! use aegis_harness::fixtures::FixtureBuilder;
//! use std::path::PathBuf;
//!
//! let fixture = FixtureBuilder::new("my-test")
//!     .echo_agent("agent-1", PathBuf::from("/tmp"))
//!     .build();
//! let harness = DaemonTestHarness::from_fixture(fixture).unwrap();
//! // harness.temp_dir() contains daemon.toml, policy files, etc.
//! // On drop, temp dir is cleaned up.
//! ```

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_control::daemon::{DaemonCommand, DaemonResponse};
use aegis_types::daemon::DaemonConfig;

use crate::error::HarnessError;
use crate::fixtures::{self, TestFixture};

/// E2E test harness that manages a daemon lifecycle.
///
/// Creates a temporary directory with test configuration, optionally starts
/// a daemon process, and provides methods to interact with it. The temp
/// directory and any spawned processes are cleaned up on drop.
pub struct DaemonTestHarness {
    /// Path to the temporary test directory (mode 0700).
    temp_dir: PathBuf,
    /// The fixture this harness was built from.
    fixture: TestFixture,
    /// Handle to the daemon process, if started.
    daemon_process: Option<std::process::Child>,
    /// Whether we own the temp dir and should remove it on drop.
    owns_temp_dir: bool,
}

impl DaemonTestHarness {
    /// Create a harness from a test fixture.
    ///
    /// This creates the temp directory, writes config files, and validates
    /// security constraints. It does NOT start the daemon -- call
    /// [`start_daemon`](Self::start_daemon) for that.
    pub fn from_fixture(fixture: TestFixture) -> Result<Self, HarnessError> {
        // Validate fixture security before proceeding
        fixtures::validate_fixture_security(&fixture)
            .map_err(|e| HarnessError::Other(format!("fixture security validation failed: {e}")))?;

        // Create temp directory with restrictive permissions (0700)
        let temp_dir = create_secure_temp_dir()?;

        let mut harness = Self {
            temp_dir,
            fixture,
            daemon_process: None,
            owns_temp_dir: true,
        };

        // Write config files
        harness.write_config_files()?;

        Ok(harness)
    }

    /// Create a harness with a custom temp directory path.
    ///
    /// The directory must already exist and have appropriate permissions.
    /// The harness will NOT delete this directory on drop.
    pub fn with_temp_dir(fixture: TestFixture, temp_dir: PathBuf) -> Result<Self, HarnessError> {
        fixtures::validate_fixture_security(&fixture)
            .map_err(|e| HarnessError::Other(format!("fixture security validation failed: {e}")))?;

        // Verify the directory exists
        if !temp_dir.is_dir() {
            return Err(HarnessError::Other(format!(
                "temp directory does not exist: {}",
                temp_dir.display()
            )));
        }

        let mut harness = Self {
            temp_dir,
            fixture,
            daemon_process: None,
            owns_temp_dir: false,
        };

        harness.write_config_files()?;

        Ok(harness)
    }

    /// Get the path to the temporary test directory.
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Get the daemon config file path.
    pub fn config_path(&self) -> PathBuf {
        self.temp_dir.join("daemon.toml")
    }

    /// Get the Unix socket path for this harness.
    pub fn socket_path(&self) -> PathBuf {
        self.temp_dir.join("daemon.sock")
    }

    /// Get the policy directory path.
    pub fn policy_dir(&self) -> PathBuf {
        self.temp_dir.join("policies")
    }

    /// Get a reference to the underlying fixture.
    pub fn fixture(&self) -> &TestFixture {
        &self.fixture
    }

    /// Get the daemon config, with the socket path adjusted for our temp dir.
    pub fn effective_config(&self) -> DaemonConfig {
        let mut config = self.fixture.daemon_config.clone();
        config.control.socket_path = self.socket_path();
        config
    }

    /// Send a daemon command and receive the response.
    ///
    /// Connects to the Unix socket, sends the command as newline-delimited
    /// JSON, and reads back the response. Uses a 5-second timeout.
    pub fn send_command(&self, command: &DaemonCommand) -> Result<DaemonResponse, HarnessError> {
        let socket_path = self.socket_path();

        let stream = UnixStream::connect(&socket_path).map_err(|e| {
            HarnessError::Other(format!(
                "failed to connect to daemon at {}: {e}",
                socket_path.display()
            ))
        })?;

        let timeout = Some(Duration::from_secs(5));
        stream
            .set_read_timeout(timeout)
            .map_err(|e| HarnessError::Other(format!("failed to set read timeout: {e}")))?;
        stream
            .set_write_timeout(timeout)
            .map_err(|e| HarnessError::Other(format!("failed to set write timeout: {e}")))?;

        let mut writer = stream
            .try_clone()
            .map_err(|e| HarnessError::Other(format!("failed to clone stream: {e}")))?;

        let mut json = serde_json::to_string(command)
            .map_err(|e| HarnessError::Other(format!("failed to serialize command: {e}")))?;
        json.push('\n');
        writer
            .write_all(json.as_bytes())
            .map_err(|e| HarnessError::Other(format!("failed to send command: {e}")))?;
        writer
            .flush()
            .map_err(|e| HarnessError::Other(format!("failed to flush: {e}")))?;

        // Cap read at 10 MB
        let reader = BufReader::new(std::io::Read::take(&stream, 10 * 1024 * 1024));
        let mut line = String::new();
        let mut buf_reader = BufReader::new(reader);
        buf_reader
            .read_line(&mut line)
            .map_err(|e| HarnessError::Other(format!("failed to read response: {e}")))?;

        serde_json::from_str(&line)
            .map_err(|e| HarnessError::Other(format!("failed to parse response: {e}")))
    }

    /// Poll the Unix socket until the daemon is ready or timeout.
    ///
    /// Attempts to connect to the socket and send a Ping command every
    /// 100ms. Returns Ok(()) when the daemon responds, or an error
    /// if the timeout expires.
    pub fn wait_for_ready(&self, timeout: Duration) -> Result<(), HarnessError> {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            if std::time::Instant::now() >= deadline {
                return Err(HarnessError::Other(
                    "daemon did not become ready within timeout".into(),
                ));
            }

            match self.send_command(&DaemonCommand::Ping) {
                Ok(resp) if resp.ok => return Ok(()),
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    /// Check if the daemon socket is accepting connections.
    pub fn is_daemon_running(&self) -> bool {
        UnixStream::connect(self.socket_path()).is_ok()
    }

    /// Kill the daemon process if it is running.
    pub fn kill_daemon(&mut self) {
        if let Some(ref mut child) = self.daemon_process {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.daemon_process = None;
    }

    /// Write daemon config and policy files to the temp directory.
    fn write_config_files(&mut self) -> Result<(), HarnessError> {
        // Write daemon.toml with adjusted socket path
        let config = self.effective_config();
        let toml_str = config
            .to_toml()
            .map_err(|e| HarnessError::Other(format!("failed to serialize config: {e}")))?;
        fs::write(self.config_path(), &toml_str)
            .map_err(|e| HarnessError::Other(format!("failed to write daemon.toml: {e}")))?;

        // Create policy directory and write policy file
        let policy_dir = self.policy_dir();
        fs::create_dir_all(&policy_dir)
            .map_err(|e| HarnessError::Other(format!("failed to create policy dir: {e}")))?;

        // Set restrictive permissions on policy directory
        fs::set_permissions(&policy_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            HarnessError::Other(format!("failed to set policy dir permissions: {e}"))
        })?;

        let policy_path = policy_dir.join("test.cedar");
        fs::write(&policy_path, &self.fixture.policy_content)
            .map_err(|e| HarnessError::Other(format!("failed to write policy file: {e}")))?;

        Ok(())
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        // Kill daemon process first
        self.kill_daemon();

        // Remove temp directory if we own it
        if self.owns_temp_dir && self.temp_dir.exists() {
            if let Err(e) = fs::remove_dir_all(&self.temp_dir) {
                eprintln!(
                    "warning: failed to remove test temp dir {}: {e}",
                    self.temp_dir.display()
                );
            }
        }
    }
}

/// Create a temporary directory with mode 0700 (owner-only access).
///
/// Returns the path to the created directory. The caller is responsible
/// for cleanup (the `DaemonTestHarness` handles this in its Drop impl).
fn create_secure_temp_dir() -> Result<PathBuf, HarnessError> {
    let base = std::env::temp_dir();
    let name = format!(
        "aegis-test-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("0")
    );
    let dir = base.join(name);

    fs::create_dir_all(&dir)
        .map_err(|e| HarnessError::Other(format!("failed to create temp dir: {e}")))?;

    // Set restrictive permissions (0700 = rwx------)
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| HarnessError::Other(format!("failed to set temp dir permissions: {e}")))?;

    Ok(dir)
}

// -- Subsystem test helpers --

/// Helper for testing Cedar policies in isolation.
///
/// Creates a temporary policy directory, writes Cedar files, and provides
/// a pre-configured `PolicyEngine` for evaluation.
pub struct PolicyTestHelper {
    /// Temp directory containing the Cedar policy files.
    temp_dir: PathBuf,
    /// Whether we own the temp dir.
    owns_temp_dir: bool,
}

impl PolicyTestHelper {
    /// Create a policy test helper with the given Cedar policy content.
    ///
    /// Writes the policy to a temporary `.cedar` file and creates a
    /// `PolicyEngine` from the directory.
    pub fn new(policy_content: &str) -> Result<Self, HarnessError> {
        let dir = create_secure_temp_dir()?;
        let policy_path = dir.join("test.cedar");
        fs::write(&policy_path, policy_content)
            .map_err(|e| HarnessError::Other(format!("failed to write policy file: {e}")))?;

        Ok(Self {
            temp_dir: dir,
            owns_temp_dir: true,
        })
    }

    /// Get the policy directory path.
    pub fn policy_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Create a `PolicyEngine` from the test policies.
    pub fn engine(&self) -> Result<aegis_policy::engine::PolicyEngine, HarnessError> {
        aegis_policy::engine::PolicyEngine::new(self.policy_dir(), None)
            .map_err(|e| HarnessError::Other(format!("failed to create policy engine: {e}")))
    }

    /// Evaluate an action against the test policies.
    ///
    /// Convenience method that creates a fresh engine and evaluates.
    pub fn evaluate(
        &self,
        action: &aegis_types::Action,
    ) -> Result<aegis_types::Verdict, HarnessError> {
        let engine = self.engine()?;
        Ok(engine.evaluate(action))
    }
}

impl Drop for PolicyTestHelper {
    fn drop(&mut self) {
        if self.owns_temp_dir && self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Helper for testing the audit ledger in isolation.
///
/// Creates a temporary SQLite database and provides methods to insert
/// test entries and query results.
pub struct AuditTestHelper {
    /// Temporary file keeping the database alive.
    _temp_file: tempfile::NamedTempFile,
    /// The audit store.
    store: aegis_ledger::AuditStore,
}

impl AuditTestHelper {
    /// Create a new audit test helper with a fresh database.
    pub fn new() -> Result<Self, HarnessError> {
        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| HarnessError::Other(format!("failed to create temp file: {e}")))?;
        let store = aegis_ledger::AuditStore::open(temp_file.path())
            .map_err(|e| HarnessError::Other(format!("failed to open audit store: {e}")))?;

        Ok(Self {
            _temp_file: temp_file,
            store,
        })
    }

    /// Get a mutable reference to the audit store.
    pub fn store_mut(&mut self) -> &mut aegis_ledger::AuditStore {
        &mut self.store
    }

    /// Get a reference to the audit store.
    pub fn store(&self) -> &aegis_ledger::AuditStore {
        &self.store
    }

    /// Insert a test entry with the given action and verdict.
    pub fn insert(
        &mut self,
        action: &aegis_types::Action,
        verdict: &aegis_types::Verdict,
    ) -> Result<aegis_ledger::AuditEntry, HarnessError> {
        self.store
            .append(action, verdict)
            .map_err(|e| HarnessError::Other(format!("failed to append audit entry: {e}")))
    }

    /// Query the last N entries.
    pub fn query_last(&self, n: usize) -> Result<Vec<aegis_ledger::AuditEntry>, HarnessError> {
        self.store
            .query_last(n)
            .map_err(|e| HarnessError::Other(format!("failed to query audit entries: {e}")))
    }

    /// Count total entries in the ledger.
    pub fn count(&self) -> Result<usize, HarnessError> {
        self.store
            .count()
            .map_err(|e| HarnessError::Other(format!("failed to count audit entries: {e}")))
    }

    /// Check if an entry with the given action kind substring exists.
    ///
    /// Searches through all entries (up to 1000) for one whose
    /// `action_kind` field contains the given substring.
    pub fn has_entry_with_action_kind(&self, kind_substr: &str) -> Result<bool, HarnessError> {
        let entries = self.query_last(1000)?;
        Ok(entries.iter().any(|e| e.action_kind.contains(kind_substr)))
    }
}

// -- Assertion helpers --

/// Assert that a daemon command succeeds (response.ok == true).
///
/// Returns the response for further inspection.
pub fn assert_daemon_command_ok(
    harness: &DaemonTestHarness,
    command: &DaemonCommand,
) -> Result<DaemonResponse, HarnessError> {
    let resp = harness.send_command(command)?;
    if !resp.ok {
        return Err(HarnessError::AssertionFailed {
            message: format!("expected command to succeed, got error: {}", resp.message),
            screen: String::new(),
        });
    }
    Ok(resp)
}

/// Assert that a daemon command fails (response.ok == false).
///
/// Returns the response for further inspection.
pub fn assert_daemon_command_err(
    harness: &DaemonTestHarness,
    command: &DaemonCommand,
) -> Result<DaemonResponse, HarnessError> {
    let resp = harness.send_command(command)?;
    if resp.ok {
        return Err(HarnessError::AssertionFailed {
            message: format!(
                "expected command to fail, but got success: {}",
                resp.message
            ),
            screen: String::new(),
        });
    }
    Ok(resp)
}

/// Assert that the audit store contains an entry whose action_kind
/// field contains the given substring.
pub fn assert_audit_entry_exists(
    helper: &AuditTestHelper,
    action_kind_substr: &str,
) -> Result<(), HarnessError> {
    if !helper.has_entry_with_action_kind(action_kind_substr)? {
        return Err(HarnessError::AssertionFailed {
            message: format!(
                "expected audit entry with action kind containing {:?}, but none found",
                action_kind_substr
            ),
            screen: String::new(),
        });
    }
    Ok(())
}

/// Assert that the audit store does NOT contain an entry whose action_kind
/// field contains the given substring.
pub fn assert_audit_entry_absent(
    helper: &AuditTestHelper,
    action_kind_substr: &str,
) -> Result<(), HarnessError> {
    if helper.has_entry_with_action_kind(action_kind_substr)? {
        return Err(HarnessError::AssertionFailed {
            message: format!(
                "expected NO audit entry with action kind containing {:?}, but found one",
                action_kind_substr
            ),
            screen: String::new(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{self, FixtureBuilder};
    use aegis_types::{Action, ActionKind, Decision, Verdict};
    use std::path::PathBuf;

    #[test]
    fn daemon_harness_creates_temp_config() {
        let fixture = FixtureBuilder::new("harness-test")
            .echo_agent("test-agent", PathBuf::from("/tmp"))
            .build();

        let harness = DaemonTestHarness::from_fixture(fixture).expect("should create harness");

        // Config file should exist
        assert!(
            harness.config_path().exists(),
            "daemon.toml should be written"
        );

        // Policy directory should exist
        assert!(
            harness.policy_dir().exists(),
            "policy directory should be created"
        );

        // Policy file should exist
        assert!(
            harness.policy_dir().join("test.cedar").exists(),
            "policy file should be written"
        );

        // Config should be valid TOML
        let content = fs::read_to_string(harness.config_path()).unwrap();
        let parsed = DaemonConfig::from_toml(&content);
        assert!(parsed.is_ok(), "written config should be valid TOML");
    }

    #[test]
    fn daemon_harness_cleanup_on_drop() {
        let temp_path;
        {
            let fixture = FixtureBuilder::new("cleanup-test").build();
            let harness = DaemonTestHarness::from_fixture(fixture).expect("should create harness");
            temp_path = harness.temp_dir().to_path_buf();
            assert!(temp_path.exists(), "temp dir should exist during test");
        }
        // After drop, temp dir should be gone
        assert!(!temp_path.exists(), "temp dir should be removed after drop");
    }

    #[test]
    fn daemon_harness_temp_dir_has_restricted_permissions() {
        let fixture = FixtureBuilder::new("permissions-test").build();
        let harness = DaemonTestHarness::from_fixture(fixture).expect("should create harness");

        let metadata = fs::metadata(harness.temp_dir()).expect("should read metadata");
        let mode = metadata.permissions().mode() & 0o777;

        // Verify permissions are 0700 (owner-only rwx)
        assert_eq!(
            mode, 0o700,
            "temp dir should have mode 0700, got {:o}",
            mode
        );
    }

    #[test]
    fn daemon_harness_policy_dir_has_restricted_permissions() {
        let fixture = FixtureBuilder::new("policy-permissions-test").build();
        let harness = DaemonTestHarness::from_fixture(fixture).expect("should create harness");

        let metadata = fs::metadata(harness.policy_dir()).expect("should read metadata");
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, 0o700,
            "policy dir should have mode 0700, got {:o}",
            mode
        );
    }

    #[test]
    fn policy_test_helper_evaluates_action() {
        let helper =
            PolicyTestHelper::new(fixtures::allow_reads_policy()).expect("should create helper");

        // Create a FileRead action
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );

        let verdict = helper.evaluate(&action).expect("should evaluate");
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "FileRead should be allowed by allow_reads_policy"
        );
    }

    #[test]
    fn policy_test_helper_deny_all_denies() {
        let helper =
            PolicyTestHelper::new(fixtures::default_test_policy()).expect("should create helper");

        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );

        let verdict = helper.evaluate(&action).expect("should evaluate");
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "FileRead should be denied by default_test_policy"
        );
    }

    #[test]
    fn audit_test_helper_inserts_and_queries() {
        let mut helper = AuditTestHelper::new().expect("should create helper");

        // Initially empty
        assert_eq!(helper.count().unwrap(), 0);

        // Insert an entry
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "test allow", None);
        helper.insert(&action, &verdict).expect("should insert");

        // Should now have 1 entry
        assert_eq!(helper.count().unwrap(), 1);

        // Query it back
        let entries = helper.query_last(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal, "test-agent");
        assert_eq!(entries[0].decision, "Allow");
    }

    #[test]
    fn audit_test_helper_has_entry_with_action_kind() {
        let mut helper = AuditTestHelper::new().expect("should create helper");

        let action = Action::new(
            "agent",
            ActionKind::FileWrite {
                path: PathBuf::from("/tmp/file.txt"),
            },
        );
        let verdict = Verdict::deny(action.id, "blocked", None);
        helper.insert(&action, &verdict).unwrap();

        assert!(helper.has_entry_with_action_kind("FileWrite").unwrap());
        assert!(!helper.has_entry_with_action_kind("FileRead").unwrap());
    }

    #[test]
    fn assert_audit_entry_exists_passes() {
        let mut helper = AuditTestHelper::new().expect("should create helper");

        let action = Action::new(
            "agent",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
        );
        let verdict = Verdict::deny(action.id, "blocked", None);
        helper.insert(&action, &verdict).unwrap();

        assert_audit_entry_exists(&helper, "NetConnect").expect("should find NetConnect entry");
    }

    #[test]
    fn assert_audit_entry_absent_passes() {
        let helper = AuditTestHelper::new().expect("should create helper");

        assert_audit_entry_absent(&helper, "FileRead").expect("should confirm no FileRead entries");
    }

    #[test]
    fn assert_audit_entry_exists_fails_when_missing() {
        let helper = AuditTestHelper::new().expect("should create helper");

        let result = assert_audit_entry_exists(&helper, "ProcessSpawn");
        assert!(result.is_err(), "should fail when entry is missing");
    }

    #[test]
    fn assert_audit_entry_absent_fails_when_present() {
        let mut helper = AuditTestHelper::new().expect("should create helper");

        let action = Action::new(
            "agent",
            ActionKind::FileRead {
                path: PathBuf::from("/etc/passwd"),
            },
        );
        let verdict = Verdict::deny(action.id, "blocked", None);
        helper.insert(&action, &verdict).unwrap();

        let result = assert_audit_entry_absent(&helper, "FileRead");
        assert!(result.is_err(), "should fail when entry is present");
    }

    #[test]
    fn policy_test_helper_temp_dir_has_restricted_permissions() {
        let helper =
            PolicyTestHelper::new(fixtures::default_test_policy()).expect("should create helper");

        let metadata = fs::metadata(helper.policy_dir()).expect("should read metadata");
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, 0o700,
            "policy helper temp dir should have mode 0700, got {:o}",
            mode
        );
    }

    #[test]
    fn effective_config_uses_temp_dir_socket() {
        let fixture = FixtureBuilder::new("socket-test")
            .socket_path(PathBuf::from("/should/be/overridden"))
            .build();

        let harness = DaemonTestHarness::from_fixture(fixture).expect("should create harness");

        let config = harness.effective_config();
        assert_eq!(
            config.control.socket_path,
            harness.socket_path(),
            "effective config should use the harness temp dir socket path"
        );
    }

    #[test]
    fn harness_rejects_fixture_with_real_api_key() {
        let mut fixture = FixtureBuilder::new("bad-fixture").build();
        fixture.daemon_config.control.api_key = "real-api-key-123".into();

        let result = DaemonTestHarness::from_fixture(fixture);
        assert!(result.is_err(), "should reject fixture with real API key");
    }
}
