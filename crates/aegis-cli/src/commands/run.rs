use std::fs;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::info;

use aegis_ledger::AuditStore;
use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::{AegisConfig, IsolationConfig, ObserverConfig};

use crate::commands::init::{ensure_aegis_dir, load_config, resolve_config_dir};

/// Run the `aegis run` command.
///
/// If no config exists for `config_name`, auto-creates one with Process
/// isolation and the specified policy template. Seatbelt enforcement
/// requires explicit opt-in via `aegis init` or the wizard.
pub fn run(config_name: &str, policy: &str, command: &str, args: &[String], tag: Option<&str>) -> Result<()> {
    let config = ensure_run_config(config_name, policy)?;

    // Log auto-init if applicable
    info!(config_name, "loaded config for run");

    // Initialize the policy engine from the first policy path
    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;
    let policy_engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;
    info!(policy_dir = %policy_dir.display(), "policy engine loaded");

    // Initialize the audit store
    let mut store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;
    info!(ledger_path = %config.ledger_path.display(), "audit store opened");

    // Begin a session for this run invocation
    let session_id = store
        .begin_session(&config.name, command, args, tag)
        .context("failed to begin audit session")?;
    info!(%session_id, "audit session started");

    // Record a policy snapshot (no-op if hash unchanged)
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

    // Create sandbox backend with compiled Cedar-to-SBPL profile
    let backend: Box<dyn SandboxBackend> = create_backend(&config.isolation, &config, &policy_engine);

    // Prepare the sandbox
    backend
        .prepare(&config)
        .context("failed to prepare sandbox")?;
    info!("sandbox prepared");

    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));

    // Start the filesystem observer (if configured)
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

    // Log process spawn (linked to session)
    aegis_proxy::log_process_spawn_with_session(
        &store_arc, &policy_arc, &config.name, command, args, &session_id,
    )
    .context("failed to log process spawn")?;

    // Record start time and execute the command
    let start_time = chrono::Utc::now();
    info!(command, ?args, "executing command in sandbox");

    let (pid, status) = backend
        .spawn_and_wait(command, args, &config, &[])
        .context("failed to execute command in sandbox")?;

    let end_time = chrono::Utc::now();
    let exit_code = status.code().unwrap_or(-1);

    // Log process exit (linked to session)
    aegis_proxy::log_process_exit_with_session(
        &store_arc, &policy_arc, &config.name, command, exit_code, &session_id,
    )
    .context("failed to log process exit")?;

    // Stop the observer: wait for FSEvents delivery, capture post-snapshot, diff
    let observer_summary = if let Some(obs) = observer_session {
        // Brief delay for FSEvents delivery latency
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

    // End the session
    store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
        .end_session(&session_id, exit_code)
        .context("failed to end audit session")?;
    info!(%session_id, exit_code, "audit session ended");

    // Harvest Seatbelt violations from macOS system logs
    #[cfg(target_os = "macos")]
    let violation_count = if pid > 0 {
        aegis_proxy::harvest_seatbelt_violations(
            &store_arc,
            &config.name,
            pid,
            &start_time,
            &end_time,
        )
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to harvest seatbelt violations");
            0
        })
    } else {
        0
    };

    #[cfg(not(target_os = "macos"))]
    let violation_count = 0usize;

    // Print summary
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
        println!("Session actions: {} total, {} denied", s.total_actions, s.denied_actions);
    }
    if let Some(obs) = &observer_summary {
        if obs.total_logged > 0 {
            println!(
                "Observer: {} file events ({} realtime, {} snapshot reads)",
                obs.total_logged, obs.fsevents_count, obs.snapshot_read_count
            );
        }
    }
    if violation_count > 0 {
        println!("Seatbelt violations detected: {violation_count}");
    }

    if !status.success() {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Ensure a run config exists, auto-creating one if needed.
///
/// If the config already exists (in either init or wrap namespace), loads it.
/// Otherwise, creates a new config with Process isolation (no Seatbelt) and
/// the specified policy template, using the current directory as the sandbox root.
fn ensure_run_config(name: &str, policy: &str) -> Result<AegisConfig> {
    // Try loading existing config first
    let config_dir = resolve_config_dir(name)?;
    if config_dir.join("aegis.toml").exists() {
        return load_config(name);
    }

    // Auto-create a new config
    ensure_aegis_dir()?;

    let cwd = std::env::current_dir().context("failed to get current directory")?;

    let policy_text = get_builtin_policy(policy).with_context(|| {
        format!(
            "unknown policy template '{policy}'; valid options: default-deny, allow-read-only, permit-all"
        )
    })?;

    // Create directory structure
    let policies_dir = config_dir.join("policies");
    fs::create_dir_all(&policies_dir)
        .with_context(|| format!("failed to create policies dir: {}", policies_dir.display()))?;

    let policy_file = policies_dir.join("default.cedar");
    fs::write(&policy_file, policy_text)
        .with_context(|| format!("failed to write policy file: {}", policy_file.display()))?;

    let config = AegisConfig {
        name: name.to_string(),
        sandbox_dir: cwd.clone(),
        policy_paths: vec![policies_dir],
        schema_path: None,
        ledger_path: config_dir.join("audit.db"),
        allowed_network: Vec::new(),
        isolation: IsolationConfig::Process,
        observer: ObserverConfig::default(),
    };

    let toml_content = config
        .to_toml()
        .context("failed to serialize config to TOML")?;
    let config_path = config_dir.join("aegis.toml");
    fs::write(&config_path, &toml_content)
        .with_context(|| format!("failed to write config: {}", config_path.display()))?;

    println!(
        "Auto-initialized '{}' (policy: {}, dir: {})",
        name,
        policy,
        cwd.display()
    );

    Ok(config)
}

/// Create the sandbox backend, compiling Cedar policies to SBPL on macOS.
fn create_backend(
    isolation: &IsolationConfig,
    config: &aegis_types::AegisConfig,
    engine: &PolicyEngine,
) -> Box<dyn SandboxBackend> {
    match isolation {
        #[cfg(target_os = "macos")]
        IsolationConfig::Seatbelt { .. } => {
            let sbpl = aegis_sandbox::compile_cedar_to_sbpl(config, engine);
            info!("compiled Cedar policies to SBPL profile");
            Box::new(aegis_sandbox::SeatbeltBackend::with_profile(sbpl))
        }
        #[cfg(not(target_os = "macos"))]
        IsolationConfig::Seatbelt { .. } => {
            tracing::warn!("Seatbelt is only available on macOS; falling back to ProcessBackend");
            Box::new(aegis_sandbox::ProcessBackend)
        }
        IsolationConfig::Process | IsolationConfig::None => {
            info!("using Process sandbox backend (no OS-level isolation)");
            Box::new(aegis_sandbox::ProcessBackend)
        }
    }
}
