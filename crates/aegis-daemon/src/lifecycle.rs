//! Per-agent lifecycle thread body.
//!
//! Each agent slot spawns a thread that runs `run_agent_slot()`. This function
//! composes the full Aegis pipeline for one agent:
//!
//! 1. Load/create the Cedar policy engine from the agent's config
//! 2. Open (or share) the audit store and begin a session
//! 3. Start the filesystem observer on the agent's working directory
//! 4. Create the agent driver and spawn the process (PTY or external)
//! 5. Run the supervisor loop (blocks until the agent exits)
//! 6. Stop the observer, end the audit session
//! 7. Return the result to the fleet manager

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tracing::{error, info, warn};

use aegis_ledger::AuditStore;
use aegis_pilot::driver::{SpawnStrategy, TaskInjection};
use aegis_pilot::drivers::create_driver;
use aegis_pilot::pty::PtySession;
use aegis_pilot::supervisor::{self, PilotStats, PilotUpdate, SupervisorCommand, SupervisorConfig};
use aegis_policy::PolicyEngine;
use aegis_control::hooks;
use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig};
use aegis_types::AegisConfig;

/// Result returned by a completed agent lifecycle thread.
pub struct SlotResult {
    /// Agent name.
    pub name: String,
    /// Exit code of the agent process (None if never spawned).
    pub exit_code: Option<i32>,
    /// Supervisor statistics.
    pub stats: PilotStats,
    /// The audit session ID for this run.
    pub session_id: Option<uuid::Uuid>,
}

/// Run the full lifecycle for one agent slot. Intended to be called from a
/// spawned thread.
///
/// # Arguments
/// - `slot_config`: configuration for this agent slot
/// - `aegis_config`: base Aegis configuration (for policy paths, ledger, etc.)
/// - `fleet_goal`: optional fleet-wide goal to compose into the agent's prompt
/// - `output_tx`: channel for sending output lines to the fleet manager
/// - `update_tx`: optional channel for sending rich updates (pending prompts, stats)
/// - `command_rx`: optional channel for receiving commands (approve, deny, input)
///
/// Returns a `SlotResult` when the agent exits.
pub fn run_agent_slot(
    slot_config: &AgentSlotConfig,
    aegis_config: &AegisConfig,
    fleet_goal: Option<&str>,
    output_tx: mpsc::Sender<String>,
    update_tx: Option<mpsc::Sender<PilotUpdate>>,
    command_rx: Option<mpsc::Receiver<SupervisorCommand>>,
    child_pid: Arc<AtomicU32>,
) -> SlotResult {
    let name = slot_config.name.clone();

    match run_agent_slot_inner(slot_config, aegis_config, fleet_goal, &output_tx, update_tx.as_ref(), command_rx.as_ref(), &child_pid) {
        Ok(result) => result,
        Err(e) => {
            error!(agent = name, error = %e, "agent lifecycle failed");
            SlotResult {
                name,
                exit_code: None,
                stats: PilotStats::default(),
                session_id: None,
            }
        }
    }
}

/// Inner implementation that returns Result for cleaner error handling.
fn run_agent_slot_inner(
    slot_config: &AgentSlotConfig,
    aegis_config: &AegisConfig,
    fleet_goal: Option<&str>,
    output_tx: &mpsc::Sender<String>,
    update_tx: Option<&mpsc::Sender<PilotUpdate>>,
    command_rx: Option<&mpsc::Receiver<SupervisorCommand>>,
    child_pid: &AtomicU32,
) -> Result<SlotResult, String> {
    let name = &slot_config.name;
    info!(agent = name, "agent lifecycle starting");

    // 1. Create policy engine from config's policy paths
    let policy_dir = aegis_config
        .policy_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));

    let engine = PolicyEngine::new(&policy_dir, None)
        .map_err(|e| format!("failed to create policy engine for {name}: {e}"))?;

    // 2. Open audit store and begin session
    let store = AuditStore::open(&aegis_config.ledger_path)
        .map_err(|e| format!("failed to open audit store for {name}: {e}"))?;

    let store = Arc::new(Mutex::new(store));
    let engine_arc = Arc::new(Mutex::new(engine));

    // Begin audit session
    let session_id = {
        let mut store_guard = store
            .lock()
            .map_err(|e| format!("store lock poisoned: {e}"))?;
        store_guard
            .begin_session(
                &aegis_config.name,
                &format!("daemon:{name}"),
                &[],
                Some(&format!("daemon-agent-{name}")),
            )
            .map_err(|e| format!("failed to begin session for {name}: {e}"))?
    };

    info!(agent = name, session_id = %session_id, "audit session started");

    // 3. Start filesystem observer
    let observer_session = aegis_observer::start_observer(
        &slot_config.working_dir,
        Arc::clone(&store),
        Arc::clone(&engine_arc),
        name,
        Some(session_id),
        matches!(
            aegis_config.observer,
            aegis_types::ObserverConfig::FsEvents { enable_snapshots: true }
        ),
    )
    .map_err(|e| format!("failed to start observer for {name}: {e}"))?;

    // 3b. Start usage proxy if configured
    let usage_proxy_handle = if let Some(proxy_config) = aegis_config
        .usage_proxy
        .as_ref()
        .filter(|p| p.enabled)
    {
        let proxy = aegis_proxy::UsageProxy::new(
            Arc::clone(&store),
            name.clone(),
            Some(session_id),
            proxy_config.port,
        );

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("failed to create tokio runtime for usage proxy: {e}"))?;

        let handle = rt
            .block_on(proxy.start())
            .map_err(|e| format!("failed to start usage proxy for {name}: {e}"))?;

        let port = handle.port;
        info!(agent = name, port, "usage proxy started");

        // Keep the runtime alive in a background thread
        std::thread::Builder::new()
            .name(format!("usage-proxy-rt-{name}"))
            .spawn(move || {
                rt.block_on(async {
                    tokio::signal::ctrl_c().await.ok();
                });
            })
            .map_err(|e| format!("failed to spawn usage proxy runtime thread: {e}"))?;

        Some(handle)
    } else {
        None
    };

    // 3c. Install hook settings so pre-tool-use hooks route every tool call
    // through the daemon for Cedar policy evaluation.
    match &slot_config.tool {
        AgentToolConfig::ClaudeCode { .. } => {
            if let Err(e) = hooks::install_daemon_hooks(&slot_config.working_dir) {
                warn!(agent = name, error = %e, "failed to install Claude Code hook settings, policy enforcement may not work");
            } else {
                info!(agent = name, dir = %slot_config.working_dir.display(), "installed Claude Code PreToolUse hook");
            }
        }
        AgentToolConfig::Cursor { .. } => {
            if let Err(e) = hooks::install_cursor_hooks(&slot_config.working_dir) {
                warn!(agent = name, error = %e, "failed to install Cursor hook settings, policy enforcement may not work");
            } else {
                info!(agent = name, dir = %slot_config.working_dir.display(), "installed Cursor hooks");
            }
        }
        AgentToolConfig::Codex { .. } => {
            // Codex CLI does not have a hooks system yet (PR #11067 in review).
            // AEGIS_AGENT_NAME and AEGIS_SOCKET_PATH env vars are set by the
            // driver for forward-compatibility when hooks ship.
            info!(agent = name, "Codex hooks not yet available, env vars set for future use");
        }
        AgentToolConfig::OpenClaw { .. } => {
            // OpenClaw's before_tool_call plugin hook is not fully wired (Issue #6535).
            // AEGIS_AGENT_NAME and AEGIS_SOCKET_PATH env vars are set by the driver.
            info!(agent = name, "OpenClaw hook bridge not yet implemented, env vars set");
        }
        AgentToolConfig::Custom { .. } => {
            // Custom agents may or may not support hooks -- skip.
        }
    }

    // 4. Create driver and determine spawn strategy
    let driver = create_driver(&slot_config.tool, Some(name));
    let strategy = driver.spawn_strategy(&slot_config.working_dir);

    let pty = match strategy {
        SpawnStrategy::Pty { command, args, mut env } => {
            // Inject usage proxy URLs if active
            if let Some(ref handle) = usage_proxy_handle {
                let port = handle.port;
                env.push(("ANTHROPIC_BASE_URL".into(), format!("http://127.0.0.1:{port}/anthropic/v1")));
                env.push(("OPENAI_BASE_URL".into(), format!("http://127.0.0.1:{port}/openai/v1")));
            }
            info!(
                agent = name,
                command = command,
                "spawning agent in PTY"
            );
            PtySession::spawn(&command, &args, &slot_config.working_dir, &env)
                .map_err(|e| format!("failed to spawn PTY for {name}: {e}"))?
        }
        SpawnStrategy::Process { command, args, mut env } => {
            // Inject usage proxy URLs if active
            if let Some(ref handle) = usage_proxy_handle {
                let port = handle.port;
                env.push(("ANTHROPIC_BASE_URL".into(), format!("http://127.0.0.1:{port}/anthropic/v1")));
                env.push(("OPENAI_BASE_URL".into(), format!("http://127.0.0.1:{port}/openai/v1")));
            }
            // For non-PTY processes, still use PTY for uniformity
            info!(
                agent = name,
                command = command,
                "spawning agent process (via PTY)"
            );
            PtySession::spawn(&command, &args, &slot_config.working_dir, &env)
                .map_err(|e| format!("failed to spawn process for {name}: {e}"))?
        }
        SpawnStrategy::External => {
            // External process (e.g. Cursor already running) -- nothing to spawn
            info!(agent = name, "external agent, skipping spawn");

            // Stop usage proxy, observer, end session
            if let Some(handle) = usage_proxy_handle {
                let _ = handle.shutdown_tx.send(true);
            }
            if let Err(e) = aegis_observer::stop_observer(observer_session) {
                warn!(agent = name, error = %e, "failed to stop observer");
            }
            end_session(&store, &session_id, 0);

            return Ok(SlotResult {
                name: name.clone(),
                exit_code: Some(0),
                stats: PilotStats::default(),
                session_id: Some(session_id),
            });
        }
    };

    // 5. Inject composed prompt (fleet goal + agent context + task)
    let composed = compose_prompt(
        fleet_goal,
        slot_config.role.as_deref(),
        slot_config.agent_goal.as_deref(),
        slot_config.context.as_deref(),
        slot_config.task.as_deref(),
    );
    if let Some(ref prompt) = composed {
        let injection = driver.task_injection(prompt);
        match injection {
            TaskInjection::Stdin { text } => {
                // Wait a moment for the agent to be ready
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Err(e) = pty.send_line(&text) {
                    warn!(agent = name, error = %e, "failed to inject prompt via stdin");
                } else {
                    info!(agent = name, "composed prompt injected via stdin");
                }
            }
            TaskInjection::CliArg { .. } => {
                // CLI args are already included in the spawn strategy
                info!(agent = name, "composed prompt provided via CLI arg");
            }
            TaskInjection::None => {}
        }
    }

    // 6. Create adapter and run supervisor
    let mut adapter: Box<dyn aegis_pilot::adapter::AgentAdapter> =
        match driver.create_adapter() {
            Some(a) => a,
            None => Box::new(aegis_pilot::adapters::passthrough::PassthroughAdapter),
        };

    let pilot_config = slot_config
        .pilot
        .clone()
        .unwrap_or_else(|| {
            aegis_config.pilot.clone().unwrap_or_default()
        });

    let engine_for_supervisor = PolicyEngine::new(&policy_dir, None)
        .map_err(|e| format!("failed to create supervisor policy engine: {e}"))?;

    let sup_config = SupervisorConfig {
        pilot_config,
        principal: name.clone(),
        interactive: false, // daemon agents are non-interactive
    };

    // Publish the child PID so stop_agent() can send SIGTERM.
    child_pid.store(pty.pid(), Ordering::Release);

    info!(agent = name, pid = pty.pid(), "running supervisor loop");

    let result = supervisor::run(
        &pty,
        adapter.as_mut(),
        &engine_for_supervisor,
        &sup_config,
        None,       // no event_tx (could be added for alerting)
        Some(output_tx),
        update_tx,
        command_rx,
    );

    let (exit_code, stats) = match result {
        Ok((code, stats)) => (code, stats),
        Err(e) => {
            error!(agent = name, error = %e, "supervisor failed");
            (-1, PilotStats::default())
        }
    };

    info!(
        agent = name,
        exit_code,
        approved = stats.approved,
        denied = stats.denied,
        lines = stats.lines_processed,
        "agent exited"
    );

    // 7. Stop usage proxy
    if let Some(handle) = usage_proxy_handle {
        let _ = handle.shutdown_tx.send(true);
    }

    // 8. Stop observer and end session
    if let Err(e) = aegis_observer::stop_observer(observer_session) {
        warn!(agent = name, error = %e, "failed to stop observer");
    }

    end_session(&store, &session_id, exit_code);

    Ok(SlotResult {
        name: name.clone(),
        exit_code: Some(exit_code),
        stats,
        session_id: Some(session_id),
    })
}

/// Compose a structured prompt from fleet goal, agent identity, and task.
///
/// Builds markdown sections for each non-empty input. Returns `None` if all
/// inputs are empty/absent, which means no prompt injection is needed.
fn compose_prompt(
    fleet_goal: Option<&str>,
    role: Option<&str>,
    agent_goal: Option<&str>,
    context: Option<&str>,
    task: Option<&str>,
) -> Option<String> {
    let mut sections = Vec::new();

    if let Some(g) = fleet_goal.filter(|s| !s.is_empty()) {
        sections.push(format!("## Fleet Mission\n{g}"));
    }
    if let Some(r) = role.filter(|s| !s.is_empty()) {
        sections.push(format!("## Your Role\n{r}"));
    }
    if let Some(ag) = agent_goal.filter(|s| !s.is_empty()) {
        sections.push(format!("## Your Goal\n{ag}"));
    }
    if let Some(c) = context.filter(|s| !s.is_empty()) {
        sections.push(format!("## Context\n{c}"));
    }
    if let Some(t) = task.filter(|s| !s.is_empty()) {
        sections.push(format!("## Task\n{t}"));
    }

    if sections.is_empty() {
        None
    } else {
        Some(sections.join("\n\n"))
    }
}

/// End an audit session in the store.
fn end_session(store: &Arc<Mutex<AuditStore>>, session_id: &uuid::Uuid, exit_code: i32) {
    match store.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.end_session(session_id, exit_code) {
                warn!(session_id = %session_id, error = %e, "failed to end audit session");
            }
        }
        Err(e) => {
            warn!(error = %e, "store lock poisoned, cannot end session");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_prompt_all_sections() {
        let result = compose_prompt(
            Some("Build a chess app"),
            Some("UX specialist"),
            Some("Build the UI"),
            Some("Use React and TypeScript"),
            Some("Start with the homepage"),
        );
        let text = result.unwrap();
        assert!(text.contains("## Fleet Mission\nBuild a chess app"));
        assert!(text.contains("## Your Role\nUX specialist"));
        assert!(text.contains("## Your Goal\nBuild the UI"));
        assert!(text.contains("## Context\nUse React and TypeScript"));
        assert!(text.contains("## Task\nStart with the homepage"));
    }

    #[test]
    fn compose_prompt_task_only() {
        let result = compose_prompt(None, None, None, None, Some("Do the thing"));
        let text = result.unwrap();
        assert_eq!(text, "## Task\nDo the thing");
    }

    #[test]
    fn compose_prompt_all_empty_returns_none() {
        assert!(compose_prompt(None, None, None, None, None).is_none());
        assert!(compose_prompt(Some(""), Some(""), None, None, None).is_none());
    }

    #[test]
    fn compose_prompt_skips_empty_strings() {
        let result = compose_prompt(Some("Mission"), None, Some(""), None, Some("Task"));
        let text = result.unwrap();
        assert!(text.contains("## Fleet Mission\nMission"));
        assert!(!text.contains("Goal"));
        assert!(text.contains("## Task\nTask"));
    }

    #[test]
    fn slot_result_default_on_error() {
        let result = SlotResult {
            name: "test".into(),
            exit_code: None,
            stats: PilotStats::default(),
            session_id: None,
        };

        assert_eq!(result.name, "test");
        assert!(result.exit_code.is_none());
        assert_eq!(result.stats.approved, 0);
    }
}
