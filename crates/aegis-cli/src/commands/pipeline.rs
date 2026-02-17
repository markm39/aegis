/// Shared execution pipeline for `aegis run` and `aegis wrap`.
///
/// Both commands follow the same lifecycle:
///   1. Initialize policy engine and audit store
///   2. Begin a session, record a policy snapshot
///   3. Start the filesystem observer
///   4. Log process spawn, execute the command, log process exit
///   5. Stop the observer, end the session
///   6. Print a summary
///
/// This module extracts that shared pipeline to avoid duplication.
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::info;
use uuid::Uuid;

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::{AegisConfig, ObserverConfig};

/// Options that control pipeline behavior.
pub struct PipelineOptions<'a> {
    /// The sandbox backend to use for execution.
    pub backend: Box<dyn SandboxBackend>,
    /// Whether to harvest macOS Seatbelt violations from system logs.
    pub harvest_violations: bool,
    /// Optional human-readable session tag.
    pub tag: Option<&'a str>,
}

/// Summary returned after pipeline execution.
#[allow(dead_code)]
pub struct PipelineSummary {
    pub session_id: Uuid,
    pub exit_code: i32,
}

/// Execute the full aegis pipeline: observe, audit, sandbox.
pub fn execute(
    config: &AegisConfig,
    command: &str,
    args: &[String],
    opts: PipelineOptions<'_>,
) -> Result<PipelineSummary> {
    // Initialize the policy engine from the first policy path
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

    // Begin a session for this invocation
    let session_id = store
        .begin_session(&config.name, command, args, opts.tag)
        .context("failed to begin audit session")?;
    info!(%session_id, "audit session started");

    // Record a policy snapshot (no-op if hash unchanged)
    record_policy_snapshot(&mut store, config, &session_id);

    // Prepare the sandbox backend
    opts.backend
        .prepare(config)
        .context("failed to prepare sandbox")?;
    info!("sandbox prepared");

    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));

    // Start the filesystem observer (if configured)
    let observer_session = start_observer(config, &store_arc, &policy_arc, session_id);

    // Log process spawn (linked to session)
    aegis_proxy::log_process_spawn(
        &store_arc,
        &policy_arc,
        &config.name,
        command,
        args,
        Some(&session_id),
    )
    .context("failed to log process spawn")?;

    // Execute the command
    let start_time = chrono::Utc::now();
    info!(command, ?args, "executing command in sandbox");

    let (pid, status) = opts
        .backend
        .spawn_and_wait(command, args, config, &[])
        .context("failed to execute command in sandbox")?;

    let end_time = chrono::Utc::now();
    let exit_code = status.code().unwrap_or(-1);

    // Log process exit (linked to session)
    aegis_proxy::log_process_exit(
        &store_arc,
        &policy_arc,
        &config.name,
        command,
        exit_code,
        Some(&session_id),
    )
    .context("failed to log process exit")?;

    // Stop the observer
    let observer_summary = stop_observer(observer_session);

    // End the session
    store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
        .end_session(&session_id, exit_code)
        .context("failed to end audit session")?;
    info!(%session_id, exit_code, "audit session ended");

    // Harvest Seatbelt violations from macOS system logs (if applicable)
    let violation_count = if opts.harvest_violations {
        harvest_violations(&store_arc, &config.name, pid, &start_time, &end_time)
    } else {
        0
    };

    // Print summary
    print_summary(&store_arc, &session_id, exit_code, &observer_summary, violation_count);

    if !status.success() {
        std::process::exit(exit_code);
    }

    Ok(PipelineSummary {
        session_id,
        exit_code,
    })
}

/// Record a policy snapshot (no-op if hash unchanged since last snapshot).
fn record_policy_snapshot(store: &mut AuditStore, config: &AegisConfig, session_id: &Uuid) {
    if let Some(policy_dir) = config.policy_paths.first() {
        match aegis_ledger::policy_snapshot::read_policy_files(policy_dir) {
            Ok(policy_files) => {
                match store.record_policy_snapshot(&config.name, &policy_files, Some(session_id)) {
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
}

/// Start the filesystem observer if configured.
fn start_observer(
    config: &AegisConfig,
    store_arc: &Arc<Mutex<AuditStore>>,
    policy_arc: &Arc<Mutex<PolicyEngine>>,
    session_id: Uuid,
) -> Option<aegis_observer::ObserverSession> {
    match &config.observer {
        ObserverConfig::FsEvents { .. } => {
            match aegis_observer::start_observer(
                &config.sandbox_dir,
                Arc::clone(store_arc),
                Arc::clone(policy_arc),
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
    }
}

/// Stop the observer and return an optional summary.
fn stop_observer(
    observer_session: Option<aegis_observer::ObserverSession>,
) -> Option<aegis_observer::ObserverSummary> {
    let obs = observer_session?;
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
}

/// Harvest Seatbelt violations on macOS.
#[allow(unused_variables)]
fn harvest_violations(
    store_arc: &Arc<Mutex<AuditStore>>,
    config_name: &str,
    pid: u32,
    start_time: &chrono::DateTime<chrono::Utc>,
    end_time: &chrono::DateTime<chrono::Utc>,
) -> usize {
    #[cfg(target_os = "macos")]
    {
        if pid > 0 {
            aegis_proxy::harvest_seatbelt_violations(store_arc, config_name, pid, start_time, end_time)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to harvest seatbelt violations");
                    0
                })
        } else {
            0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// Print the post-execution summary to stdout.
fn print_summary(
    store_arc: &Arc<Mutex<AuditStore>>,
    session_id: &Uuid,
    exit_code: i32,
    observer_summary: &Option<aegis_observer::ObserverSummary>,
    violation_count: usize,
) {
    let store_lock = match store_arc.lock() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to lock store for summary");
            return;
        }
    };
    let session = store_lock.get_session(session_id).ok().flatten();
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
    if let Some(obs) = observer_summary {
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
}
