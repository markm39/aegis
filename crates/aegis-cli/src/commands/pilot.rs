//! PTY-based autonomous agent supervision with interactive TUI.
//!
//! `aegis pilot [--dir PATH] [--policy POLICY] -- command [args...]`
//!
//! Spawns an AI agent in a pseudo-terminal, monitors its output for
//! permission prompts, and auto-approves or denies them based on Cedar
//! policy. Detects stalls and nudges the agent to keep working.
//!
//! The pilot runs an interactive TUI dashboard showing live agent output,
//! stats, and pending permission requests. Users can approve, deny, send
//! input, or nudge the agent directly from the TUI.

use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use tracing::info;

use aegis_pilot::adapters;
use aegis_pilot::pty::PtySession;
use aegis_pilot::supervisor::{self, PilotEvent, PilotUpdate, SupervisorCommand, SupervisorConfig};
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, AdapterConfig, AegisConfig, PilotConfig, Verdict};

use crate::commands::pipeline;
use crate::commands::wrap;

/// Run the `aegis pilot` command.
#[allow(clippy::too_many_arguments)]
pub fn run(
    dir: Option<&Path>,
    policy: &str,
    name: Option<&str>,
    tag: Option<&str>,
    stall_timeout: Option<u64>,
    adapter_name: Option<&str>,
    listen: Option<&str>,
    api_key: Option<&str>,
    command: &str,
    args: &[String],
) -> Result<()> {
    // Resolve project directory
    let project_dir = match dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("--dir path does not exist: {}", d.display()))?,
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    if !project_dir.is_dir() {
        bail!("--dir is not a directory: {}", project_dir.display());
    }

    // Derive config name from command if not specified
    let derived_name = match name {
        Some(n) => n.to_string(),
        None => wrap::derive_name(command),
    };

    aegis_types::validate_config_name(&derived_name)
        .with_context(|| format!("invalid config name: {derived_name:?}"))?;

    // Reuse wrap's config storage pattern
    let wrap_dir = wrap::wraps_base_dir()?.join(&derived_name);
    let config = wrap::ensure_wrap_config(&wrap_dir, &derived_name, policy, &project_dir)?;

    // Build PilotConfig from CLI flags, merging with any existing config
    let pilot_config = build_pilot_config(&config, stall_timeout, adapter_name, listen, api_key);

    // Auto-set as current config
    crate::commands::use_config::set_current(&derived_name)?;

    // Initialize policy engine
    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;
    let policy_engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;
    info!(policy_dir = %policy_dir.display(), "policy engine loaded");

    // Initialize audit store
    let mut store =
        aegis_ledger::AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

    // Set up alert dispatcher
    let _alert_thread = if !config.alerts.is_empty() {
        let (tx, rx) = std::sync::mpsc::sync_channel(256);
        store.set_alert_sender(tx);
        let dispatcher_config = aegis_alert::dispatcher::DispatcherConfig {
            rules: config.alerts.clone(),
            config_name: config.name.clone(),
            db_path: config.ledger_path.to_string_lossy().into_owned(),
        };
        let handle = std::thread::Builder::new()
            .name("aegis-alert-dispatcher".into())
            .spawn(move || {
                aegis_alert::dispatcher::run(dispatcher_config, rx);
            })
            .context("failed to spawn alert dispatcher thread")?;
        Some(handle)
    } else {
        None
    };

    // Begin audit session
    let session_id = store
        .begin_session(&config.name, command, args, tag)
        .context("failed to begin audit session")?;
    info!(%session_id, "audit session started");

    // Record policy snapshot
    pipeline::record_policy_snapshot(&mut store, &config, &session_id);

    let store_arc = Arc::new(Mutex::new(store));
    let policy_arc = Arc::new(Mutex::new(policy_engine));

    // Start filesystem observer
    let observer_session =
        pipeline::start_observer(&config, &store_arc, &policy_arc, session_id);

    // Collect environment for the child process
    let env: Vec<(String, String)> = std::env::vars().collect();

    // Spawn the agent in a PTY
    let pty = PtySession::spawn(command, args, &project_dir, &env)
        .context("failed to spawn agent in PTY")?;
    info!(pid = pty.pid(), command, "agent spawned in PTY");

    // Create the adapter
    let mut adapter = adapters::create_adapter(&pilot_config.adapter, command);
    let adapter_name_str = adapter.name().to_string();

    // Create channels for supervisor <-> TUI communication
    let (event_tx, event_rx) = mpsc::channel::<PilotEvent>();
    let (update_tx, update_rx) = mpsc::channel::<PilotUpdate>();
    let (command_tx, command_rx) = mpsc::channel::<SupervisorCommand>();

    // Spawn a thread to log pilot events to the audit store
    let event_logger = {
        let store = Arc::clone(&store_arc);
        let config_name = config.name.clone();
        let sid = session_id;
        std::thread::Builder::new()
            .name("pilot-event-logger".into())
            .spawn(move || {
                while let Ok(event) = event_rx.recv() {
                    log_pilot_event(&event, &store, &config_name, &sid);
                }
            })
            .ok()
    };

    // Build supervisor config -- interactive is false because the TUI handles display
    let sup_config = SupervisorConfig {
        pilot_config: pilot_config.clone(),
        principal: config.name.clone(),
        interactive: false,
    };

    // Create a separate policy engine for the supervisor thread
    let policy_dir_for_eval = config.policy_paths.first().cloned().unwrap();
    let eval_engine = PolicyEngine::new(&policy_dir_for_eval, None)
        .context("failed to create evaluation policy engine")?;

    // Spawn the supervisor in a background thread
    let supervisor_handle = std::thread::Builder::new()
        .name("pilot-supervisor".into())
        .spawn(move || {
            supervisor::run(
                &pty,
                adapter.as_mut(),
                &eval_engine,
                &sup_config,
                Some(&event_tx),
                None,
                Some(&update_tx),
                Some(&command_rx),
            )
        })
        .context("failed to spawn supervisor thread")?;

    // Run the TUI on the main thread
    let tui_result = crate::pilot_tui::run_pilot_tui(
        update_rx,
        command_tx,
        session_id.to_string(),
        derived_name.clone(),
        command.to_string(),
    );

    // Wait for the supervisor thread to finish
    let supervisor_result = supervisor_handle
        .join()
        .map_err(|_| anyhow::anyhow!("supervisor thread panicked"))?;

    let (exit_code, stats) = match supervisor_result {
        Ok(result) => result,
        Err(e) => {
            // If TUI also had an error, report both
            if let Err(tui_err) = tui_result {
                tracing::error!("TUI error: {tui_err:#}");
            }
            return Err(e).context("supervisor error");
        }
    };

    // Report any TUI error (non-fatal since supervisor already completed)
    if let Err(tui_err) = tui_result {
        tracing::warn!("TUI exited with error: {tui_err:#}");
    }

    // Drop the event sender to signal the logger thread to exit
    // (event_tx was moved into the supervisor thread, which has exited)
    if let Some(handle) = event_logger {
        let _ = handle.join();
    }

    // Stop observer
    let observer_summary = pipeline::stop_observer(observer_session);

    // End session
    store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
        .end_session(&session_id, exit_code)
        .context("failed to end audit session")?;

    // Print summary (after TUI has restored terminal)
    println!();
    println!("--- Pilot Session Summary ---");
    println!("  Command:      {command}");
    println!("  Adapter:      {adapter_name_str}");
    println!("  Exit code:    {exit_code}");
    println!("  Approved:     {}", stats.approved);
    println!("  Denied:       {}", stats.denied);
    println!("  Uncertain:    {}", stats.uncertain);
    println!("  Nudges sent:  {}", stats.nudges);
    println!("  Lines read:   {}", stats.lines_processed);
    if let Some(ref obs) = observer_summary {
        println!("  FS events:    {}", obs.total_logged);
    }
    println!("  Session:      {session_id}");
    println!("  Config:       {derived_name}");

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Build a PilotConfig from CLI flags merged with any existing config.
fn build_pilot_config(
    config: &AegisConfig,
    stall_timeout: Option<u64>,
    adapter_name: Option<&str>,
    listen: Option<&str>,
    api_key: Option<&str>,
) -> PilotConfig {
    let mut pilot = config.pilot.clone().unwrap_or_default();

    if let Some(timeout) = stall_timeout {
        pilot.stall.timeout_secs = timeout;
    }

    if let Some(name) = adapter_name {
        pilot.adapter = match name.to_lowercase().as_str() {
            "claudecode" | "claude" => AdapterConfig::ClaudeCode,
            "codex" => AdapterConfig::Codex,
            "passthrough" | "none" => AdapterConfig::Passthrough,
            "auto" => AdapterConfig::Auto,
            _ => {
                tracing::warn!("unknown adapter {name:?}, using Auto");
                AdapterConfig::Auto
            }
        };
    }

    if let Some(addr) = listen {
        pilot.control.http_listen = addr.to_string();
    }

    if let Some(key) = api_key {
        pilot.control.api_key = key.to_string();
    }

    pilot
}

/// Log a pilot event to the audit store.
///
/// Writes policy decisions (approved/denied prompts) as audit log entries so they
/// appear alongside filesystem events in `aegis log` and `aegis monitor`.
fn log_pilot_event(
    event: &PilotEvent,
    store: &Arc<Mutex<aegis_ledger::AuditStore>>,
    config_name: &str,
    session_id: &uuid::Uuid,
) {
    match event {
        PilotEvent::PromptDecided { action, decision, reason } => {
            info!(action, ?decision, reason, "pilot: prompt decided");

            // Write to audit store
            let action_obj = Action::new(
                config_name,
                ActionKind::ToolCall {
                    tool: format!("pilot:{action}"),
                    args: serde_json::Value::Null,
                },
            );
            let verdict = match decision {
                aegis_types::Decision::Allow => Verdict::allow(action_obj.id, reason, None),
                aegis_types::Decision::Deny => Verdict::deny(action_obj.id, reason, None),
            };
            if let Ok(mut store) = store.lock() {
                if let Err(e) = store.append_with_session(&action_obj, &verdict, session_id) {
                    tracing::warn!(error = %e, "failed to write pilot decision to audit store");
                }
            }
        }
        PilotEvent::StallNudge { nudge_count, idle_secs } => {
            info!(nudge_count, idle_secs, "pilot: stall nudge sent");
        }
        PilotEvent::AttentionNeeded { nudge_count } => {
            tracing::warn!(nudge_count, "pilot: agent needs attention (max nudges exceeded)");
        }
        PilotEvent::UncertainPrompt { text, action_taken } => {
            tracing::warn!(text, action_taken, "pilot: uncertain prompt");
        }
        PilotEvent::ChildExited { exit_code } => {
            info!(exit_code, "pilot: child process exited");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pilot_config_defaults() {
        let config = AegisConfig::default_for("test", &std::path::PathBuf::from("/tmp/test"));
        let pilot = build_pilot_config(&config, None, None, None, None);
        assert_eq!(pilot.stall.timeout_secs, 120);
        assert!(matches!(pilot.adapter, AdapterConfig::Auto));
    }

    #[test]
    fn build_pilot_config_overrides() {
        let config = AegisConfig::default_for("test", &std::path::PathBuf::from("/tmp/test"));
        let pilot = build_pilot_config(
            &config,
            Some(60),
            Some("ClaudeCode"),
            Some("0.0.0.0:8443"),
            Some("secret"),
        );
        assert_eq!(pilot.stall.timeout_secs, 60);
        assert!(matches!(pilot.adapter, AdapterConfig::ClaudeCode));
        assert_eq!(pilot.control.http_listen, "0.0.0.0:8443");
        assert_eq!(pilot.control.api_key, "secret");
    }
}
