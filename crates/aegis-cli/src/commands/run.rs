use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::info;

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::IsolationConfig;

use crate::commands::init::load_config;

/// Run the `aegis run` command.
///
/// Loads config, initializes the policy engine, audit store, and sandbox backend,
/// then executes the given command inside the sandbox.
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

    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));

    // Log process spawn
    aegis_proxy::log_process_spawn(&store_arc, &policy_arc, &config.name, command, args)
        .context("failed to log process spawn")?;

    // Execute the command in the sandbox
    info!(command, ?args, "executing command in sandbox");
    let status = backend
        .exec(command, args, &config)
        .context("failed to execute command in sandbox")?;

    let exit_code = status.code().unwrap_or(-1);

    // Log process exit
    aegis_proxy::log_process_exit(&store_arc, &policy_arc, &config.name, command, exit_code)
        .context("failed to log process exit")?;

    // Print summary
    let store_lock = store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
    let entry_count = store_lock.count().unwrap_or(0);

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
            Box::new(aegis_sandbox::SeatbeltBackend::new())
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
