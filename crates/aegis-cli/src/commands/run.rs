use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::info;

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::{IsolationConfig, ObserverConfig};

use crate::commands::init::load_config;

/// Run the `aegis run` command.
///
/// Pipeline:
/// 1. Load config, init policy engine and audit store
/// 2. Begin a session in the audit ledger
/// 3. Compile Cedar policies into a Seatbelt SBPL profile
/// 4. Prepare the sandbox
/// 5. Start the filesystem observer (FSEvents watcher + pre-snapshot)
/// 6. Log ProcessSpawn to the audit ledger (linked to session)
/// 7. Spawn the command in the sandbox, capturing PID and timestamps
/// 8. Log ProcessExit to the audit ledger (linked to session)
/// 9. Wait for FSEvents delivery, then stop the observer (post-snapshot diff)
/// 10. End the session with the exit code
/// 11. Harvest Seatbelt violation logs from macOS system logs
/// 12. Print summary including session and observer stats
pub fn run(config_name: &str, command: &str, args: &[String]) -> Result<()> {
    let config = load_config(config_name)?;

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
        .begin_session(&config.name, command, args)
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
