/// Zero-friction agent wrapping with full observability.
///
/// `aegis wrap [--dir PATH] [--policy POLICY] [--name NAME] -- command [args...]`
///
/// Wraps any command with Aegis filesystem observation and audit logging.
/// Uses Process isolation (no Seatbelt) to avoid conflicting with the
/// agent's own sandboxing. Config is stored at `~/.aegis/wraps/<name>/`
/// and reused on subsequent invocations (same ledger, accumulating sessions).
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use tracing::info;

use aegis_ledger::AuditStore;
use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::{AegisConfig, IsolationConfig, ObserverConfig};

/// Run the `aegis wrap` command.
pub fn run(
    dir: Option<&Path>,
    policy: &str,
    name: Option<&str>,
    command: &str,
    args: &[String],
    tag: Option<&str>,
) -> Result<()> {
    let project_dir = match dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("--dir path does not exist: {}", d.display()))?,
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    if !project_dir.is_dir() {
        bail!("--dir is not a directory: {}", project_dir.display());
    }

    let derived_name = match name {
        Some(n) => n.to_string(),
        None => derive_name(command),
    };

    let wrap_dir = wraps_base_dir()?.join(&derived_name);

    let config = ensure_wrap_config(&wrap_dir, &derived_name, policy, &project_dir)?;

    run_pipeline(&config, command, args, tag)
}

/// Derive a config name from a command path.
///
/// Strips path components: `/usr/local/bin/claude` -> `claude`
pub fn derive_name(command: &str) -> String {
    Path::new(command)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string())
}

/// Base directory for wrap configs: `$HOME/.aegis/wraps/`
pub fn wraps_base_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable is not set")?;
    Ok(home.join(".aegis").join("wraps"))
}

/// Ensure a wrap config exists at `wrap_dir`, creating it if needed.
///
/// If the directory already exists, loads the existing config and updates
/// `sandbox_dir` to the current project directory. If it doesn't exist,
/// creates a new config with the specified policy template.
pub fn ensure_wrap_config(
    wrap_dir: &Path,
    name: &str,
    policy_template: &str,
    project_dir: &Path,
) -> Result<AegisConfig> {
    if wrap_dir.exists() {
        // Reuse existing config, update sandbox_dir
        let config_path = wrap_dir.join("aegis.toml");
        let content = fs::read_to_string(&config_path).with_context(|| {
            format!("failed to read wrap config: {}", config_path.display())
        })?;
        let mut config = AegisConfig::from_toml(&content).context("failed to parse wrap config")?;
        config.sandbox_dir = project_dir.to_path_buf();
        config.isolation = IsolationConfig::Process;

        // Write updated config back
        let toml_content = config
            .to_toml()
            .context("failed to serialize wrap config")?;
        fs::write(&config_path, &toml_content)
            .with_context(|| format!("failed to write wrap config: {}", config_path.display()))?;

        info!(name, wrap_dir = %wrap_dir.display(), "reusing existing wrap config");
        Ok(config)
    } else {
        // Create new wrap config
        let policy_text = get_builtin_policy(policy_template).with_context(|| {
            format!(
                "unknown policy template '{policy_template}'; valid options: {}", aegis_policy::builtin::list_builtin_policies().join(", ")
            )
        })?;

        let policies_dir = wrap_dir.join("policies");
        fs::create_dir_all(&policies_dir).with_context(|| {
            format!("failed to create wrap policies dir: {}", policies_dir.display())
        })?;

        let policy_file = policies_dir.join("default.cedar");
        fs::write(&policy_file, policy_text).with_context(|| {
            format!("failed to write policy file: {}", policy_file.display())
        })?;

        let config = AegisConfig {
            name: name.to_string(),
            sandbox_dir: project_dir.to_path_buf(),
            policy_paths: vec![policies_dir],
            schema_path: None,
            ledger_path: wrap_dir.join("audit.db"),
            allowed_network: Vec::new(),
            isolation: IsolationConfig::Process,
            observer: ObserverConfig::default(),
        };

        let toml_content = config
            .to_toml()
            .context("failed to serialize wrap config")?;
        let config_path = wrap_dir.join("aegis.toml");
        fs::write(&config_path, &toml_content)
            .with_context(|| format!("failed to write wrap config: {}", config_path.display()))?;

        info!(name, wrap_dir = %wrap_dir.display(), "created new wrap config");
        Ok(config)
    }
}

/// Execute the wrap pipeline: observe + audit without Seatbelt enforcement.
///
/// Mirrors the pipeline in `run.rs` but:
/// - Always uses ProcessBackend (no Seatbelt)
/// - Skips Seatbelt violation harvesting
fn run_pipeline(config: &AegisConfig, command: &str, args: &[String], tag: Option<&str>) -> Result<()> {
    // Initialize the policy engine
    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;
    let policy_engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;
    info!(policy_dir = %policy_dir.display(), "policy engine loaded");

    // Initialize the audit store
    let mut store =
        AuditStore::open(&config.ledger_path).context("failed to open audit store")?;
    info!(ledger_path = %config.ledger_path.display(), "audit store opened");

    // Begin session
    let session_id = store
        .begin_session(&config.name, command, args, tag)
        .context("failed to begin audit session")?;
    info!(%session_id, "audit session started");

    // Record policy snapshot
    if let Some(policy_dir) = config.policy_paths.first() {
        match aegis_ledger::policy_snapshot::read_policy_files(policy_dir) {
            Ok(policy_files) => {
                match store.record_policy_snapshot(&config.name, &policy_files, Some(&session_id)) {
                    Ok(Some(snap)) => {
                        info!(hash = %snap.policy_hash, "new policy snapshot recorded");
                    }
                    Ok(None) => {
                        info!("policy unchanged since last snapshot");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to record policy snapshot");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to read policy files for snapshot");
            }
        }
    }

    // Always use ProcessBackend for wrap (no Seatbelt)
    let backend = aegis_sandbox::ProcessBackend;
    backend
        .prepare(config)
        .context("failed to prepare sandbox")?;
    info!("process backend prepared");

    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));

    // Start filesystem observer
    let observer_session = match &config.observer {
        ObserverConfig::FsEvents { .. } => {
            match aegis_observer::start_observer(
                &config.sandbox_dir,
                Arc::clone(&store_arc),
                Arc::clone(&policy_arc),
                &config.name,
                Some(session_id),
            ) {
                Ok(session) => {
                    info!("filesystem observer started");
                    Some(session)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to start observer, continuing without it");
                    None
                }
            }
        }
        ObserverConfig::EndpointSecurity => {
            tracing::warn!("EndpointSecurity observer not yet implemented");
            None
        }
        ObserverConfig::None => None,
    };

    // Log process spawn
    aegis_proxy::log_process_spawn_with_session(
        &store_arc,
        &policy_arc,
        &config.name,
        command,
        args,
        &session_id,
    )
    .context("failed to log process spawn")?;

    // Execute the command
    info!(command, ?args, "executing wrapped command");

    let (_pid, status) = backend
        .spawn_and_wait(command, args, config, &[])
        .context("failed to execute command")?;

    let exit_code = status.code().unwrap_or(-1);

    // Log process exit
    aegis_proxy::log_process_exit_with_session(
        &store_arc,
        &policy_arc,
        &config.name,
        command,
        exit_code,
        &session_id,
    )
    .context("failed to log process exit")?;

    // Stop observer
    let observer_summary = if let Some(obs) = observer_session {
        std::thread::sleep(std::time::Duration::from_millis(500));

        match aegis_observer::stop_observer(obs) {
            Ok(summary) => {
                info!(
                    fsevents = summary.fsevents_count,
                    snapshot_reads = summary.snapshot_read_count,
                    total = summary.total_logged,
                    "observer stopped"
                );
                Some(summary)
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to stop observer cleanly");
                None
            }
        }
    } else {
        None
    };

    // End session
    store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
        .end_session(&session_id, exit_code)
        .context("failed to end audit session")?;
    info!(%session_id, exit_code, "audit session ended");

    // Print summary (no Seatbelt violation harvesting)
    let store_lock = store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
    let session = store_lock.get_session(&session_id).ok().flatten();
    let entry_count = store_lock.count().unwrap_or(0);

    println!("Session:  {session_id}");
    if let Some(s) = &session {
        if let Some(t) = &s.tag {
            println!("Tag:      {t}");
        }
    }
    println!("Command exited with code: {exit_code}");
    println!("Audit entries logged: {entry_count}");
    if let Some(s) = &session {
        println!(
            "Session actions: {} total, {} denied",
            s.total_actions, s.denied_actions
        );
    }
    if let Some(obs) = &observer_summary {
        if obs.total_logged > 0 {
            println!(
                "Observer: {} file events ({} realtime, {} snapshot reads)",
                obs.total_logged, obs.fsevents_count, obs.snapshot_read_count
            );
        }
    }

    if !status.success() {
        std::process::exit(exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_name_strips_path() {
        assert_eq!(derive_name("/usr/local/bin/claude"), "claude");
        assert_eq!(derive_name("/usr/bin/python3"), "python3");
        assert_eq!(derive_name("node"), "node");
    }

    #[test]
    fn derive_name_handles_edge_cases() {
        assert_eq!(derive_name("./script.sh"), "script.sh");
        assert_eq!(derive_name(""), "");
    }

    #[test]
    fn wraps_base_dir_under_aegis() {
        let base = wraps_base_dir().expect("should resolve wraps base dir");
        assert!(
            base.to_string_lossy().contains(".aegis/wraps"),
            "wraps dir should be under .aegis: {base:?}"
        );
    }

    #[test]
    fn ensure_wrap_config_creates_new() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("test-wrap");
        let project_dir = tmpdir.path().join("project");
        fs::create_dir_all(&project_dir).expect("create project dir");

        let config = ensure_wrap_config(&wrap_dir, "test-wrap", "permit-all", &project_dir)
            .expect("should create new wrap config");

        assert_eq!(config.name, "test-wrap");
        assert_eq!(config.sandbox_dir, project_dir);
        assert_eq!(config.isolation, IsolationConfig::Process);
        assert!(wrap_dir.join("aegis.toml").exists());
        assert!(wrap_dir.join("policies").join("default.cedar").exists());
    }

    #[test]
    fn ensure_wrap_config_reuses_existing() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("reuse-wrap");
        let project_dir1 = tmpdir.path().join("project1");
        let project_dir2 = tmpdir.path().join("project2");
        fs::create_dir_all(&project_dir1).expect("create project dir1");
        fs::create_dir_all(&project_dir2).expect("create project dir2");

        // First call creates
        let config1 = ensure_wrap_config(&wrap_dir, "reuse-wrap", "permit-all", &project_dir1)
            .expect("first call");
        assert_eq!(config1.sandbox_dir, project_dir1);

        // Second call reuses and updates sandbox_dir
        let config2 = ensure_wrap_config(&wrap_dir, "reuse-wrap", "permit-all", &project_dir2)
            .expect("second call");
        assert_eq!(config2.sandbox_dir, project_dir2);
        assert_eq!(config2.name, "reuse-wrap");
    }

    #[test]
    fn ensure_wrap_config_unknown_policy_fails() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("bad-policy");
        let project_dir = tmpdir.path().join("project");
        fs::create_dir_all(&project_dir).expect("create project dir");

        let result = ensure_wrap_config(&wrap_dir, "bad", "nonexistent-policy", &project_dir);
        assert!(result.is_err(), "unknown policy should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown policy template"),
        );
    }
}
