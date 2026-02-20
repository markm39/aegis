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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tracing::{error, info, warn};

use aegis_control::hooks;
use aegis_ledger::AuditStore;
use aegis_pilot::driver::ProcessKind;
use aegis_pilot::driver::{SpawnStrategy, TaskInjection};
use aegis_pilot::drivers::create_driver;
use aegis_pilot::json_stream::JsonStreamSession;
use aegis_pilot::jsonl::{CodexJsonProtocol, JsonlSession};
use aegis_pilot::pty::PtySession;
use aegis_pilot::session::AgentSession;
use aegis_pilot::session::ToolKind;
use aegis_pilot::supervisor::{self, PilotStats, PilotUpdate, SupervisorCommand, SupervisorConfig};
use aegis_pilot::tmux::TmuxSession;
use aegis_policy::PolicyEngine;
use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig, OrchestratorConfig, ToolkitConfig};
use aegis_types::AegisConfig;

use crate::tool_contract::render_orchestrator_tool_contract;

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
#[allow(clippy::too_many_arguments)]
pub fn run_agent_slot(
    slot_config: &AgentSlotConfig,
    aegis_config: &AegisConfig,
    toolkit_config: &ToolkitConfig,
    fleet_goal: Option<&str>,
    orchestrator_name: Option<&str>,
    output_tx: mpsc::Sender<String>,
    update_tx: Option<mpsc::Sender<PilotUpdate>>,
    command_rx: Option<mpsc::Receiver<SupervisorCommand>>,
    child_pid: Arc<AtomicU32>,
    shared_session_id: Arc<std::sync::Mutex<Option<uuid::Uuid>>>,
) -> SlotResult {
    let name = slot_config.name.clone();

    match run_agent_slot_inner(
        slot_config,
        aegis_config,
        toolkit_config,
        fleet_goal,
        orchestrator_name,
        &output_tx,
        update_tx.as_ref(),
        command_rx.as_ref(),
        &child_pid,
        &shared_session_id,
    ) {
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
#[allow(clippy::too_many_arguments)]
fn run_agent_slot_inner(
    slot_config: &AgentSlotConfig,
    aegis_config: &AegisConfig,
    toolkit_config: &ToolkitConfig,
    fleet_goal: Option<&str>,
    orchestrator_name: Option<&str>,
    output_tx: &mpsc::Sender<String>,
    update_tx: Option<&mpsc::Sender<PilotUpdate>>,
    command_rx: Option<&mpsc::Receiver<SupervisorCommand>>,
    child_pid: &AtomicU32,
    shared_session_id: &std::sync::Mutex<Option<uuid::Uuid>>,
) -> Result<SlotResult, String> {
    let name = &slot_config.name;
    info!(agent = name, "agent lifecycle starting");

    // 0. Validate and canonicalize working directory
    let working_dir = slot_config.working_dir.canonicalize().map_err(|e| {
        format!(
            "working directory '{}' for agent {name}: {e}",
            slot_config.working_dir.display()
        )
    })?;
    if !working_dir.is_dir() {
        return Err(format!(
            "working directory '{}' for agent {name} is not a directory",
            working_dir.display()
        ));
    }

    // 1. Create policy engine from config's policy paths
    let policy_dir = aegis_config
        .policy_paths
        .first()
        .cloned()
        .ok_or_else(|| format!("no policy paths configured for agent {name}"))?;

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

    // Share session_id back to the main thread for state persistence
    if let Ok(mut guard) = shared_session_id.lock() {
        *guard = Some(session_id);
    }

    // 3. Start filesystem observer
    let observer_session = aegis_observer::start_observer(
        &working_dir,
        Arc::clone(&store),
        Arc::clone(&engine_arc),
        name,
        Some(session_id),
        matches!(
            aegis_config.observer,
            aegis_types::ObserverConfig::FsEvents {
                enable_snapshots: true
            }
        ),
    )
    .map_err(|e| format!("failed to start observer for {name}: {e}"))?;

    // 3b. Start usage proxy if configured
    let usage_proxy_handle =
        if let Some(proxy_config) = aegis_config.usage_proxy.as_ref().filter(|p| p.enabled) {
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

            // Subscribe to the proxy's shutdown signal so the runtime thread
            // exits cleanly when the agent stops (instead of blocking on ctrl_c
            // which never arrives in a background thread).
            let mut shutdown_sub = handle.shutdown_tx.subscribe();

            std::thread::Builder::new()
                .name(format!("usage-proxy-rt-{name}"))
                .spawn(move || {
                    rt.block_on(async move {
                        let _ = shutdown_sub.wait_for(|&v| v).await;
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
            if let Err(e) = hooks::install_daemon_hooks(&working_dir) {
                warn!(agent = name, error = %e, "failed to install Claude Code hook settings, policy enforcement may not work");
            } else {
                info!(agent = name, dir = %working_dir.display(), "installed Claude Code PreToolUse hook");
            }
        }
        AgentToolConfig::Codex { .. } => {
            // Codex CLI does not have a hooks system yet (PR #11067 in review).
            // AEGIS_AGENT_NAME and AEGIS_SOCKET_PATH env vars are set by the
            // driver for forward-compatibility when hooks ship.
            info!(
                agent = name,
                "Codex hooks not yet available, env vars set for future use"
            );
        }
        AgentToolConfig::OpenClaw { .. } => {
            // OpenClaw's before_tool_call plugin hook is not fully wired (Issue #6535).
            // AEGIS_AGENT_NAME and AEGIS_SOCKET_PATH env vars are set by the driver.
            info!(
                agent = name,
                "OpenClaw hook bridge not yet implemented, env vars set"
            );
        }
        AgentToolConfig::Custom { .. } => {
            // Custom agents may or may not support hooks -- skip.
        }
    }

    // Runtime mediation hardening:
    // If the runtime doesn't have enforced hook mediation, mark it as needing
    // attention so operators/orchestrators keep a human in the loop.
    let mediation_enforced = matches!(&slot_config.tool, AgentToolConfig::ClaudeCode { .. });
    if !mediation_enforced {
        let note = match &slot_config.tool {
            AgentToolConfig::Codex { .. } => {
                "policy mediation is partial (Codex hook bridge unavailable)"
            }
            AgentToolConfig::OpenClaw { .. } => {
                "policy mediation is partial (OpenClaw hook bridge unavailable)"
            }
            AgentToolConfig::Custom { .. } => "policy mediation is custom and may be incomplete",
            _ => "policy mediation is not fully enforced",
        };
        warn!(agent = name, "{note}");
        let _ = output_tx.send(format!("[Aegis] Warning: {note}"));
        if let Some(tx) = update_tx {
            let _ = tx.send(PilotUpdate::AttentionNeeded { nudge_count: 0 });
        }
    }

    // 4. Create driver and determine spawn strategy
    let driver = create_driver(&slot_config.tool, Some(name));
    let strategy = driver.spawn_strategy(&working_dir);

    // 5. Compute task injection BEFORE spawn so CliArg can be folded into args.
    //    Orchestrator slots get a specialized prompt with review-cycle instructions.
    //    Worker slots learn about the orchestrator so they follow its direction.
    let composed = if let Some(ref orch_config) = slot_config.orchestrator {
        Some(compose_orchestrator_prompt(
            name,
            fleet_goal,
            slot_config.role.as_deref(),
            slot_config.agent_goal.as_deref(),
            slot_config.context.as_deref(),
            orch_config,
            toolkit_config,
        ))
    } else {
        compose_prompt(
            fleet_goal,
            slot_config.role.as_deref(),
            slot_config.agent_goal.as_deref(),
            slot_config.context.as_deref(),
            slot_config.task.as_deref(),
            orchestrator_name,
        )
    };
    let injection = composed.as_ref().map(|p| driver.task_injection(p));

    // Extract the prompt text for JsonStreamSession (which handles -p internally)
    let prompt_text: Option<String> = match &injection {
        Some(TaskInjection::CliArg { value, .. }) => Some(value.clone()),
        Some(TaskInjection::Stdin { text }) => Some(text.clone()),
        _ => None,
    };

    let session: Box<dyn AgentSession> = match strategy {
        SpawnStrategy::Process {
            command,
            args,
            mut env,
            kind,
        } => {
            // Process strategy: JSONL sessions with structured output (Claude/Codex),
            // or detached GUI tools.
            if let Some(ref handle) = usage_proxy_handle {
                let port = handle.port;
                env.push((
                    "ANTHROPIC_BASE_URL".into(),
                    format!("http://127.0.0.1:{port}/anthropic/v1"),
                ));
                env.push((
                    "OPENAI_BASE_URL".into(),
                    format!("http://127.0.0.1:{port}/openai/v1"),
                ));
            }

            let prompt = prompt_text.as_deref().unwrap_or("");
            match kind {
                ProcessKind::Json {
                    tool: ToolKind::ClaudeCode,
                    ..
                } => {
                    info!(
                        agent = name,
                        command = command,
                        "spawning agent via JsonStreamSession"
                    );
                    Box::new(
                        JsonStreamSession::spawn(name, &command, &args, &working_dir, &env, prompt)
                            .map_err(|e| {
                                format!("failed to spawn json-stream session for {name}: {e}")
                            })?,
                    )
                }
                ProcessKind::Json {
                    tool: ToolKind::Codex,
                    global_args,
                } => {
                    info!(
                        agent = name,
                        command = command,
                        "spawning agent via Codex JSON session"
                    );
                    let protocol = CodexJsonProtocol::new(global_args);
                    Box::new(
                        JsonlSession::spawn(
                            name,
                            protocol,
                            &command,
                            &args,
                            &working_dir,
                            &env,
                            prompt,
                        )
                        .map_err(|e| {
                            format!("failed to spawn codex json session for {name}: {e}")
                        })?,
                    )
                }
                ProcessKind::Detached => {
                    info!(agent = name, command = command, "spawning detached process");
                    let mut cmd = std::process::Command::new(&command);
                    cmd.args(&args).current_dir(&working_dir).envs(env);
                    cmd.stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null());
                    let _child = cmd
                        .spawn()
                        .map_err(|e| format!("failed to spawn detached process for {name}: {e}"))?;

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
            }
        }
        SpawnStrategy::Pty {
            command,
            mut args,
            mut env,
        } => {
            // PTY strategy: legacy path for non-Claude-Code agents.
            // Append CLI-arg task injection if needed.
            if let Some(TaskInjection::CliArg {
                ref flag,
                ref value,
            }) = injection
            {
                args.extend([flag.clone(), value.clone()]);
            }
            if let Some(ref handle) = usage_proxy_handle {
                let port = handle.port;
                env.push((
                    "ANTHROPIC_BASE_URL".into(),
                    format!("http://127.0.0.1:{port}/anthropic/v1"),
                ));
                env.push((
                    "OPENAI_BASE_URL".into(),
                    format!("http://127.0.0.1:{port}/openai/v1"),
                ));
            }

            if aegis_pilot::tmux::tmux_available() {
                info!(
                    agent = name,
                    command = command,
                    "spawning agent in tmux session"
                );
                Box::new(
                    TmuxSession::spawn(name, &command, &args, &working_dir, &env)
                        .map_err(|e| format!("failed to spawn tmux session for {name}: {e}"))?,
                )
            } else {
                info!(agent = name, command = command, "spawning agent in PTY");
                Box::new(
                    PtySession::spawn(&command, &args, &working_dir, &env)
                        .map_err(|e| format!("failed to spawn PTY for {name}: {e}"))?,
                )
            }
        }
        SpawnStrategy::External => {
            // External process already running -- nothing to spawn
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

    // For PTY-based agents with Stdin injection, inject after spawn.
    // (Claude Code uses Process/JsonStreamSession with CliArg, so this
    // only fires for other agent types that use PTY + Stdin injection.)
    if let Some(TaskInjection::Stdin { ref text }) = injection {
        let timeout = std::time::Duration::from_secs(15);
        match session.wait_for_output(timeout) {
            Ok(true) => {
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Ok(false) => {
                warn!(
                    agent = name,
                    "agent produced no output after 15s, injecting prompt anyway"
                );
            }
            Err(e) => {
                warn!(agent = name, error = %e, "error waiting for agent output");
            }
        }
        if let Err(e) = session.send_paste(text) {
            warn!(agent = name, error = %e, "failed to inject prompt via stdin");
        } else {
            info!(agent = name, "composed prompt injected via bracketed paste");
        }
    }

    // 6. Create adapter and run supervisor
    let mut adapter: Box<dyn aegis_pilot::adapter::AgentAdapter> = match driver.create_adapter() {
        Some(a) => a,
        None => Box::new(aegis_pilot::adapters::passthrough::PassthroughAdapter),
    };

    let pilot_config = slot_config
        .pilot
        .clone()
        .unwrap_or_else(|| aegis_config.pilot.clone().unwrap_or_default());

    let engine_for_supervisor = PolicyEngine::new(&policy_dir, None)
        .map_err(|e| format!("failed to create supervisor policy engine: {e}"))?;

    let sup_config = SupervisorConfig {
        pilot_config,
        principal: name.clone(),
        interactive: false, // daemon agents are non-interactive
    };

    // Publish the child PID so stop_agent() can send SIGTERM.
    child_pid.store(session.pid(), Ordering::Release);

    // Attach/session info is published by the supervisor as it becomes available.

    info!(agent = name, pid = session.pid(), "running supervisor loop");

    let result = supervisor::run(
        session.as_ref(),
        adapter.as_mut(),
        &engine_for_supervisor,
        &sup_config,
        None, // no event_tx (could be added for alerting)
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
    orchestrator_name: Option<&str>,
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
    if let Some(orch) = orchestrator_name.filter(|s| !s.is_empty()) {
        sections.push(format!(
            "## Orchestrator\n\
             You are being coordinated by an orchestrator agent named \"{orch}\". \
             It periodically reviews your work, evaluates whether you are focused on \
             high-value tasks, and may redirect you via messages. When the orchestrator \
             sends you instructions, follow them -- it has visibility across the entire \
             fleet and knows what work matters most."
        ));
    }

    if sections.is_empty() {
        None
    } else {
        Some(sections.join("\n\n"))
    }
}

/// Compose the orchestrator agent's system prompt.
///
/// This is the "intelligence" of the orchestrator: a structured prompt that
/// instructs the agent to run review cycles, evaluate worker output against
/// the backlog, redirect low-value work, and verify what was built.
///
/// The orchestrator never writes code itself -- it only reviews, directs, and
/// verifies. Its behavior emerges from this prompt combined with access to
/// the `aegis` CLI tools.
fn compose_orchestrator_prompt(
    orchestrator_name: &str,
    fleet_goal: Option<&str>,
    role: Option<&str>,
    agent_goal: Option<&str>,
    context: Option<&str>,
    orch_config: &OrchestratorConfig,
    toolkit_config: &ToolkitConfig,
) -> String {
    let mut sections = Vec::new();

    // Identity and mission
    sections.push(
        "# Orchestrator Agent\n\
        You are the orchestrator for an Aegis-managed fleet of coding agents. \
        Your job is strategic oversight: review what agents are doing, evaluate \
        whether their work is high-value, redirect them when they drift, and \
        verify that what they build actually works.\n\n\
        CRITICAL RULES:\n\
        - You NEVER write code, create files, or make commits yourself.\n\
        - You ONLY review, direct, and verify.\n\
        - You use `aegis` CLI commands to interact with the fleet.\n\
        - You use `git log`, `git diff`, and `git show` to review work.\n\
        - You evaluate every piece of work against the backlog priorities."
            .to_string(),
    );

    // Fleet goal
    if let Some(g) = fleet_goal.filter(|s| !s.is_empty()) {
        sections.push(format!("## Fleet Mission\n{g}"));
    }

    // Role and goal
    if let Some(r) = role.filter(|s| !s.is_empty()) {
        sections.push(format!("## Your Role\n{r}"));
    }
    if let Some(ag) = agent_goal.filter(|s| !s.is_empty()) {
        sections.push(format!("## Your Goal\n{ag}"));
    }
    if let Some(c) = context.filter(|s| !s.is_empty()) {
        sections.push(format!("## Context\n{c}"));
    }

    // Backlog
    if let Some(ref backlog_path) = orch_config.backlog_path {
        sections.push(format!(
            "## Backlog\n\
             The project backlog is at `{}`. Read it at the start of each \
             review cycle and use it to prioritize agent work. Items near the \
             top are highest priority.",
            backlog_path.display()
        ));
    }

    // Managed agents
    if !orch_config.managed_agents.is_empty() {
        let names = orch_config.managed_agents.join(", ");
        sections.push(format!(
            "## Managed Agents\nYou are responsible for these agents: {names}"
        ));
    }

    // Review cycle instructions
    let interval = orch_config.review_interval_secs;
    sections.push(format!(
        "## Review Cycle\n\
         Run a review cycle every {interval} seconds. Each cycle:\n\n\
         1. **Check fleet status:** Run `aegis orchestrator status` to get all agent statuses and recent output.\n\
         2. **Check git history:** Run `git log --oneline -30` and `git diff --stat HEAD~5..HEAD` to see recent work.\n\
         3. **Read the backlog** (if configured) to know current priorities.\n\
         4. **Evaluate each agent's work:**\n\
            - Is the agent working on something from the backlog?\n\
            - Is the work high-value (moves the product forward) or low-value (polish nobody asked for, over-engineering)?\n\
            - Is the agent stuck, looping, or producing errors?\n\
         5. **Redirect agents** doing low-value work:\n\
            - `aegis send <agent> \"STOP current work. Switch to: <specific task from backlog>\"`\n\
            - If they ignore the redirect: `aegis context <agent> task \"<new task>\"` then `aegis restart <agent>`\n\
         6. **Verify output** for agents that completed work (see Verification section).\n\
         7. **Sleep** for {interval} seconds before the next cycle.\n\n\
         Between cycles, use `sleep {interval}` to wait."
    ));

    sections.push(
        "## Fast Sense-Act Executor\n\
         When interacting with UIs, use a planner/executor loop:\n\
         1. Planner: produce a short micro-plan (3-10 actions).\n\
         2. Executor: run those actions as a batch.\n\
         3. Observe outcome and only then plan the next batch.\n\n\
         Runtime bootstrap for browser sessions:\n\
         - `aegis daemon capture-start <agent> --fps 30`\n\
         - `aegis daemon browser-profile <agent> <session_id> --headless --url <url>`\n\
         - `aegis daemon tool-batch <agent> '[{{\"action\":\"browser_navigate\",...}},{{\"action\":\"mouse_click\",...}},{{\"action\":\"type_text\",...}},{{\"action\":\"input_batch\",\"actions\":[{{\"kind\":\"wait\",\"duration_ms\":150}}]}}]' --max-actions 6`\n\
         - `aegis daemon latest-frame <agent>` after each batch to validate state transitions.\n\
         - `aegis daemon browser-profile-stop <agent> <session_id>` when done.\n\n\
         Use `aegis daemon tool-batch <agent> '<json-array>' --max-actions <n>` \
         for low-latency execution. Stop a batch when any of these happen:\n\
         - You hit a policy boundary (especially high-risk actions).\n\
         - You are uncertain about UI state.\n\
         - The configured time budget is exhausted.\n\
         - An action is denied or fails."
            .to_string(),
    );

    sections.push(render_orchestrator_tool_contract(
        orchestrator_name,
        toolkit_config,
    ));

    // Verification instructions
    sections.push(
        "## Verification\n\
         After an agent completes a task, verify the result actually works:\n\n\
         ### For TUI applications:\n\
         - Build the project: `cargo build -p <package>`\n\
         - If `aegis-harness` is available, run TUI verification:\n\
           `cargo run -p aegis-harness --example verify_tui -- <binary_path>`\n\
         - Otherwise, run the binary briefly and check stderr/stdout for panics.\n\
         - Run the test suite: `cargo test -p <package>`\n\n\
         ### For web applications:\n\
         - Start the dev server and check that it responds: `curl -s http://localhost:<port>`\n\
         - Run `npx playwright test` if playwright tests exist.\n\
         - Check the browser console for errors.\n\n\
         ### For libraries/backends:\n\
         - Run `cargo test -p <package>` or the equivalent test command.\n\
         - Run `cargo clippy -p <package> -- -D warnings` for code quality.\n\
         - Check that public API signatures match what was requested.\n\n\
         If verification fails, send specific feedback to the worker:\n\
         `aegis send <agent> \"VERIFICATION FAILED: <what broke and how to fix it>\"`"
            .to_string(),
    );

    // Available aegis commands reference
    sections.push(
        "## Aegis CLI Reference\n\
         Commands you can use:\n\
         - `aegis orchestrator status` -- bulk fleet status with recent output\n\
         - `aegis daemon status` -- list all agents with status\n\
         - `aegis daemon output <agent> [--lines N]` -- get agent output\n\
         - `aegis daemon capabilities <agent>` -- show config-backed computer-use contract\n\
         - `aegis daemon tool <agent> '<json>'` -- run one computer-use action\n\
         - `aegis daemon tool-batch <agent> '<json-array>' --max-actions N` -- run micro-action batch\n\
         - `aegis daemon capture-start <agent> --fps <n>` -- start frame stream cache\n\
         - `aegis daemon latest-frame <agent>` -- fetch most recent cached frame\n\
         - `aegis daemon tool <agent> '{\"action\":\"tui_snapshot\",\"session_id\":\"<id>\"}'` -- read terminal state via runtime fast path\n\
         - `aegis daemon tool <agent> '{\"action\":\"tui_input\",\"session_id\":\"<id>\",\"text\":\"...\"}'` -- send terminal input via runtime fast path\n\
         - `aegis daemon browser-profile <agent> <session_id> [--headless] [--url <u>]` -- start managed browser profile\n\
         - `aegis daemon browser-profile-stop <agent> <session_id>` -- stop managed browser profile\n\
         - Parse subagent completion messages starting with `AEGIS_SUBAGENT_RESULT ` as structured JSON results from child sessions\n\
         - `aegis send <agent> \"message\"` -- send text to agent stdin\n\
         - `aegis context <agent> task \"new task\"` -- update agent's task\n\
         - `aegis context <agent> role \"new role\"` -- update agent's role\n\
         - `aegis restart <agent>` -- restart an agent\n\
         - `aegis stop <agent>` -- stop an agent\n\
         - `aegis start <agent>` -- start an agent\n\
         - `aegis goal \"new goal\"` -- set fleet-wide goal"
            .to_string(),
    );

    // Value assessment framework
    sections.push(
        "## Value Assessment Framework\n\
         When evaluating agent work, classify it:\n\n\
         **High value (keep going):**\n\
         - Implements a backlog item\n\
         - Fixes a real bug that affects users\n\
         - Adds a feature the user explicitly requested\n\
         - Makes something that was broken actually work\n\n\
         **Medium value (acceptable but deprioritize):**\n\
         - Test coverage for new code\n\
         - Documentation for public APIs\n\
         - Reasonable refactoring that simplifies code\n\n\
         **Low value (redirect immediately):**\n\
         - Security hardening of local-only interfaces\n\
         - Lint fixes and style changes nobody asked for\n\
         - Over-engineering (adding abstractions for one-time code)\n\
         - \"Improvements\" to working code that add complexity\n\
         - Adding error handling for impossible scenarios\n\n\
         When you see low-value work, redirect the agent to the highest-priority \
         unstarted backlog item."
            .to_string(),
    );

    sections.join("\n\n")
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
            None,
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
        let result = compose_prompt(None, None, None, None, Some("Do the thing"), None);
        let text = result.unwrap();
        assert_eq!(text, "## Task\nDo the thing");
    }

    #[test]
    fn compose_prompt_all_empty_returns_none() {
        assert!(compose_prompt(None, None, None, None, None, None).is_none());
        assert!(compose_prompt(Some(""), Some(""), None, None, None, None).is_none());
    }

    #[test]
    fn compose_prompt_skips_empty_strings() {
        let result = compose_prompt(Some("Mission"), None, Some(""), None, Some("Task"), None);
        let text = result.unwrap();
        assert!(text.contains("## Fleet Mission\nMission"));
        assert!(!text.contains("Goal"));
        assert!(text.contains("## Task\nTask"));
    }

    #[test]
    fn compose_prompt_with_orchestrator_name() {
        let result = compose_prompt(
            None,
            Some("Frontend engineer"),
            None,
            None,
            Some("Build the UI"),
            Some("director"),
        );
        let text = result.unwrap();
        assert!(text.contains("## Orchestrator"));
        assert!(text.contains("\"director\""));
        assert!(text.contains("follow them"));
    }

    #[test]
    fn compose_prompt_no_orchestrator_section_when_none() {
        let result = compose_prompt(None, None, None, None, Some("Task"), None);
        let text = result.unwrap();
        assert!(!text.contains("Orchestrator"));
    }

    #[test]
    fn compose_orchestrator_prompt_includes_core_sections() {
        let config = OrchestratorConfig {
            review_interval_secs: 300,
            backlog_path: Some(std::path::PathBuf::from("./BACKLOG.md")),
            managed_agents: vec!["frontend".into(), "backend".into()],
        };
        let prompt = compose_orchestrator_prompt(
            "orch-1",
            Some("Build a chess app"),
            Some("Technical Director"),
            Some("Keep agents focused"),
            None,
            &config,
            &ToolkitConfig::default(),
        );

        assert!(prompt.contains("# Orchestrator Agent"));
        assert!(prompt.contains("NEVER write code"));
        assert!(prompt.contains("Fleet Mission\nBuild a chess app"));
        assert!(prompt.contains("Your Role\nTechnical Director"));
        assert!(prompt.contains("Your Goal\nKeep agents focused"));
        assert!(prompt.contains("BACKLOG.md"));
        assert!(prompt.contains("frontend, backend"));
        assert!(prompt.contains("300 seconds"));
        assert!(prompt.contains("aegis orchestrator status"));
        assert!(prompt.contains("aegis daemon capabilities orch-1"));
        assert!(prompt.contains("aegis daemon capture-start <agent> --fps 30"));
        assert!(prompt.contains("AEGIS_SUBAGENT_RESULT"));
        assert!(prompt.contains("Tool Capability Contract"));
        assert!(prompt.contains("Value Assessment Framework"));
        assert!(prompt.contains("Low value"));
    }

    #[test]
    fn compose_orchestrator_prompt_minimal() {
        let config = OrchestratorConfig::default();
        let prompt = compose_orchestrator_prompt(
            "orch-1",
            None,
            None,
            None,
            None,
            &config,
            &ToolkitConfig::default(),
        );

        assert!(prompt.contains("# Orchestrator Agent"));
        assert!(prompt.contains("NEVER write code"));
        // Should not contain empty sections
        assert!(!prompt.contains("Fleet Mission"));
        assert!(!prompt.contains("Your Role"));
        assert!(!prompt.contains("Backlog"));
        assert!(!prompt.contains("Managed Agents"));
        // Should still have review cycle and verification
        assert!(prompt.contains("Review Cycle"));
        assert!(prompt.contains("Verification"));
    }

    #[test]
    fn compose_orchestrator_prompt_custom_interval() {
        let config = OrchestratorConfig {
            review_interval_secs: 60,
            backlog_path: None,
            managed_agents: vec![],
        };
        let prompt = compose_orchestrator_prompt(
            "orch-1",
            None,
            None,
            None,
            None,
            &config,
            &ToolkitConfig::default(),
        );
        assert!(prompt.contains("60 seconds"));
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
