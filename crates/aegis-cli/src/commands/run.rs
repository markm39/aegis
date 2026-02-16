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
/// Pipeline:
/// 1. Load config, init policy engine and audit store
/// 2. Compile Cedar policies into a Seatbelt SBPL profile
/// 3. Create SeatbeltBackend with the compiled profile
/// 4. Log ProcessSpawn to the audit ledger
/// 5. Spawn the command in the sandbox, capturing PID and timestamps
/// 6. Log ProcessExit to the audit ledger
/// 7. Harvest Seatbelt violation logs from macOS system logs
/// 8. Print summary
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

    // Create sandbox backend with compiled Cedar-to-SBPL profile
    let backend: Box<dyn SandboxBackend> = create_backend(&config.isolation, &config, &policy_engine);

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

    // Record start time and execute the command
    let start_time = chrono::Utc::now();
    info!(command, ?args, "executing command in sandbox");

    let (pid, status) = backend
        .spawn_and_wait(command, args, &config, &[])
        .context("failed to execute command in sandbox")?;

    let end_time = chrono::Utc::now();
    let exit_code = status.code().unwrap_or(-1);

    // Log process exit
    aegis_proxy::log_process_exit(&store_arc, &policy_arc, &config.name, command, exit_code)
        .context("failed to log process exit")?;

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
    let entry_count = store_lock.count().unwrap_or(0);

    println!("Command exited with code: {exit_code}");
    println!("Audit entries logged: {entry_count}");
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
