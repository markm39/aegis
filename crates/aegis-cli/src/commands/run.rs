use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::{info, warn};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_sidecar::Sidecar;
use aegis_types::IsolationConfig;

use crate::commands::init::load_config;

/// Run the `aegis run` command.
///
/// Loads config, initializes the policy engine, audit store, and sandbox backend,
/// optionally starts the FUSE sidecar, then executes the given command inside
/// the sandbox.
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
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;
    info!(ledger_path = %config.ledger_path.display(), "audit store opened");

    // Select sandbox backend based on isolation config
    let backend: Box<dyn SandboxBackend> = select_backend(&config.isolation);

    // Prepare the sandbox
    backend
        .prepare(&config)
        .context("failed to prepare sandbox")?;
    info!("sandbox prepared");

    // Try to start the FUSE sidecar
    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));
    let mut sidecar = try_start_sidecar(&config, Arc::clone(&policy_arc), Arc::clone(&store_arc));

    // Execute the command in the sandbox
    info!(command, ?args, "executing command in sandbox");
    let status = backend
        .exec(command, args, &config)
        .context("failed to execute command in sandbox")?;

    // Stop sidecar if started
    if let Some(ref mut sc) = sidecar {
        if sc.is_mounted() {
            if let Err(e) = sc.stop() {
                warn!("failed to stop sidecar: {e}");
            }
        }
    }

    // Retrieve the audit store back from the Arc for the summary
    let store_lock = store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
    let entry_count = store_lock.count().unwrap_or(0);

    let exit_code = status.code().unwrap_or(-1);
    println!("Command exited with code: {exit_code}");
    println!("Audit entries logged: {entry_count}");

    if !status.success() {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Select the appropriate sandbox backend based on the isolation config.
fn select_backend(isolation: &IsolationConfig) -> Box<dyn SandboxBackend> {
    match isolation {
        #[cfg(target_os = "macos")]
        IsolationConfig::Seatbelt { .. } => {
            info!("using Seatbelt sandbox backend");
            Box::new(aegis_sandbox::SeatbeltBackend)
        }
        #[cfg(not(target_os = "macos"))]
        IsolationConfig::Seatbelt { .. } => {
            warn!("Seatbelt is only available on macOS; falling back to ProcessBackend");
            Box::new(aegis_sandbox::ProcessBackend)
        }
        IsolationConfig::Process | IsolationConfig::None => {
            info!("using Process sandbox backend (no OS-level isolation)");
            Box::new(aegis_sandbox::ProcessBackend)
        }
    }
}

/// Attempt to start the FUSE sidecar. Returns None if it fails (logs a warning).
fn try_start_sidecar(
    config: &aegis_types::AegisConfig,
    policy: Arc<Mutex<PolicyEngine>>,
    store: Arc<Mutex<AuditStore>>,
) -> Option<Sidecar> {
    let mount_point = config.sandbox_dir.join("mnt");
    let passthrough_dir = config.sandbox_dir.clone();

    if let Err(e) = std::fs::create_dir_all(&mount_point) {
        warn!("failed to create FUSE mount point: {e}");
        return None;
    }

    let mut sidecar = Sidecar::new(
        policy,
        store,
        config.name.clone(),
        mount_point,
        passthrough_dir,
    );

    match sidecar.start() {
        Ok(()) => {
            info!(
                mount_point = %sidecar.mount_point().display(),
                "FUSE sidecar started"
            );
            Some(sidecar)
        }
        Err(e) => {
            warn!("FUSE sidecar not available (continuing without it): {e}");
            None
        }
    }
}
