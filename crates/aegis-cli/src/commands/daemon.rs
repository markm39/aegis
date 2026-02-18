//! CLI commands for the Aegis daemon.
//!
//! Implements the `aegis daemon` subcommand tree:
//! - `init`: create default daemon.toml
//! - `run`: run the daemon in foreground
//! - `start`/`stop`: manage the daemon process
//! - `status`: query daemon and agent health
//! - `agents`: list all agent slots
//! - `output`: show recent agent output
//! - `send`: inject text into an agent's stdin
//! - `start-agent`/`stop-agent`/`restart-agent`: per-agent lifecycle
//! - `install`/`uninstall`: launchd plist management

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use tracing::info;

use aegis_control::daemon::{DaemonClient, DaemonCommand};
use aegis_daemon::persistence;
use aegis_types::daemon::{
    daemon_config_path, daemon_dir, AgentSlotConfig, AgentToolConfig, DaemonConfig,
    DaemonControlConfig, PersistenceConfig, RestartPolicy,
};
use aegis_types::AegisConfig;

/// Initialize a daemon configuration file at `~/.aegis/daemon/daemon.toml`.
pub fn init() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if config_path.exists() {
        anyhow::bail!(
            "daemon config already exists at {}\nEdit it directly or remove to reinitialize.",
            config_path.display()
        );
    }

    let dir = daemon_dir();
    std::fs::create_dir_all(&dir)?;

    // Create an example config with one commented-out agent slot
    let example = DaemonConfig {
        goal: None,
        persistence: PersistenceConfig::default(),
        control: DaemonControlConfig::default(),
        alerts: vec![],
        agents: vec![AgentSlotConfig {
            name: "claude-1".into(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/path/to/your/project"),
            role: None,
            agent_goal: None,
            context: None,
            task: Some("Implement the feature described in TODO.md".into()),
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: false, // Disabled by default so user must configure
        }],
        channel: None,
    };

    let toml_str = example.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;

    println!("Daemon config created at: {}", config_path.display());
    println!();
    println!("Edit the config to add your agents, then start with:");
    println!("  aegis daemon run");
    println!();
    println!("Or install as a launchd service:");
    println!("  aegis daemon install --start");

    Ok(())
}

/// Run the daemon in the foreground. Blocks until shutdown.
pub fn run(launchd: bool) -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\nRun `aegis daemon init` first.",
            config_path.display()
        );
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config = DaemonConfig::from_toml(&content)?;

    // Check for an existing daemon
    if let Some(pid) = persistence::read_pid() {
        if persistence::is_process_alive(pid) {
            anyhow::bail!(
                "Daemon already running (PID {pid}).\nUse `aegis daemon stop` to stop it first."
            );
        }
        // Stale PID file, clean up
        persistence::remove_pid_file();
    }

    if launchd {
        info!("running in launchd mode");
    }

    // Create base AegisConfig for the fleet
    let aegis_dir = daemon_dir();
    let aegis_config = AegisConfig::default_for("daemon", &aegis_dir);

    let mut runtime = aegis_daemon::DaemonRuntime::new(config, aegis_config);
    let shutdown = runtime.shutdown_flag();

    // Install SIGTERM handler
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nShutdown signal received...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    println!(
        "Daemon starting with {} agent(s)...",
        runtime.fleet.agent_count()
    );

    runtime.run().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Start the daemon in the background.
pub fn start() -> anyhow::Result<()> {
    // Verify daemon.toml exists before spawning background process
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\n\
             Create one with `aegis daemon init` or run the onboard wizard.",
            config_path.display()
        );
    }

    // Check for an existing daemon
    if let Some(pid) = persistence::read_pid() {
        if persistence::is_process_alive(pid) {
            println!("Daemon already running (PID {pid}).");
            return Ok(());
        }
    }

    // Try to find our own binary path
    let binary = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("aegis"));

    let child = std::process::Command::new(&binary)
        .args(["daemon", "run"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()?;

    println!("Daemon started (PID {}).", child.id());
    Ok(())
}

/// Stop a running daemon via the control socket.
pub fn stop() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        println!("Daemon is not running.");
        return Ok(());
    }

    let response = client
        .send(&DaemonCommand::Shutdown)
        .map_err(|e| anyhow::anyhow!("failed to send shutdown: {e}"))?;

    if response.ok {
        println!("Daemon shutdown requested.");
    } else {
        println!("Shutdown failed: {}", response.message);
    }

    Ok(())
}

/// Reload daemon configuration from daemon.toml without restarting.
pub fn reload() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it first with `aegis daemon start`.");
    }

    let response = client
        .send(&DaemonCommand::ReloadConfig)
        .map_err(|e| anyhow::anyhow!("failed to send reload: {e}"))?;

    if response.ok {
        println!("{}", response.message);
    } else {
        println!("Reload failed: {}", response.message);
    }

    Ok(())
}

/// Query daemon status.
pub fn status() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        println!("Daemon is not running.");
        return Ok(());
    }

    let response = client
        .send(&DaemonCommand::Ping)
        .map_err(|e| anyhow::anyhow!("failed to ping daemon: {e}"))?;

    if !response.ok {
        println!("Daemon error: {}", response.message);
        return Ok(());
    }

    if let Some(data) = response.data {
        if let Ok(ping) = serde_json::from_value::<aegis_control::daemon::DaemonPing>(data) {
            println!("Daemon status: running");
            println!("  PID:     {}", ping.daemon_pid);
            println!("  Uptime:  {}s", ping.uptime_secs);
            println!("  Agents:  {} total, {} running", ping.agent_count, ping.running_count);
        }
    }

    Ok(())
}

/// List all agent slots and their status.
pub fn agents() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        println!("Daemon is not running.");
        return Ok(());
    }

    let response = client
        .send(&DaemonCommand::ListAgents)
        .map_err(|e| anyhow::anyhow!("failed to list agents: {e}"))?;

    if !response.ok {
        println!("Error: {}", response.message);
        return Ok(());
    }

    if let Some(data) = response.data {
        if let Ok(agents) =
            serde_json::from_value::<Vec<aegis_control::daemon::AgentSummary>>(data)
        {
            if agents.is_empty() {
                println!("No agents configured.");
                return Ok(());
            }

            // Table header
            println!(
                "{:<20} {:<12} {:<15} {:<8}",
                "NAME", "STATUS", "TOOL", "RESTARTS"
            );
            println!("{}", "-".repeat(60));

            for agent in &agents {
                println!(
                    "{:<20} {:<12} {:<15} {:<8}",
                    agent.name, agent.status, agent.tool, agent.restart_count
                );
            }
        }
    }

    Ok(())
}

/// Show recent output from an agent.
pub fn output(name: &str, lines: usize) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::AgentOutput {
            name: name.to_string(),
            lines: Some(lines),
        })
        .map_err(|e| anyhow::anyhow!("failed to get output: {e}"))?;

    if !response.ok {
        anyhow::bail!("{}", response.message);
    }

    if let Some(data) = response.data {
        if let Ok(output_lines) = serde_json::from_value::<Vec<String>>(data) {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for line in &output_lines {
                writeln!(out, "{line}")?;
            }
        }
    }

    Ok(())
}

/// Send text to an agent's stdin.
pub fn send(name: &str, text: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::SendToAgent {
            name: name.to_string(),
            text: text.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to send to agent: {e}"))?;

    if response.ok {
        println!("Sent to {name}.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Start a specific agent.
pub fn start_agent(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::StartAgent {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to start agent: {e}"))?;

    if response.ok {
        println!("Agent '{name}' started.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Stop a specific agent.
pub fn stop_agent(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::StopAgent {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to stop agent: {e}"))?;

    if response.ok {
        println!("Agent '{name}' stopped.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Restart a specific agent.
pub fn restart_agent(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::RestartAgent {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to restart agent: {e}"))?;

    if response.ok {
        println!("Agent '{name}' restarted.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Approve a pending permission prompt for an agent.
pub fn approve(name: &str, request_id: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::ApproveRequest {
            name: name.to_string(),
            request_id: request_id.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to approve: {e}"))?;

    if response.ok {
        println!("Approved request {request_id} for '{name}'.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Deny a pending permission prompt for an agent.
pub fn deny(name: &str, request_id: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::DenyRequest {
            name: name.to_string(),
            request_id: request_id.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to deny: {e}"))?;

    if response.ok {
        println!("Denied request {request_id} for '{name}'.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Nudge a stalled agent.
pub fn nudge(name: &str, message: Option<&str>) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::NudgeAgent {
            name: name.to_string(),
            message: message.map(|s| s.to_string()),
        })
        .map_err(|e| anyhow::anyhow!("failed to nudge: {e}"))?;

    if response.ok {
        println!("Nudged '{name}'.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// List pending permission prompts for an agent.
pub fn pending(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running.");
    }

    let response = client
        .send(&DaemonCommand::ListPending {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to list pending: {e}"))?;

    if !response.ok {
        anyhow::bail!("{}", response.message);
    }

    if let Some(data) = response.data {
        if let Ok(prompts) =
            serde_json::from_value::<Vec<aegis_control::daemon::PendingPromptSummary>>(data)
        {
            if prompts.is_empty() {
                println!("No pending prompts for '{name}'.");
                return Ok(());
            }

            println!("{:<38} {:<8} PROMPT", "REQUEST ID", "AGE");
            println!("{}", "-".repeat(80));

            for p in &prompts {
                println!(
                    "{:<38} {:<8} {}",
                    p.request_id,
                    format!("{}s", p.age_secs),
                    if p.raw_prompt.len() > 40 {
                        format!("{}...", &p.raw_prompt[..37])
                    } else {
                        p.raw_prompt.clone()
                    }
                );
            }
        }
    }

    Ok(())
}

/// Install the launchd plist.
pub fn install(start_after: bool) -> anyhow::Result<()> {
    let binary = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("aegis"));

    persistence::install_launchd(&binary.to_string_lossy())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let plist = persistence::plist_path();
    println!("Launchd plist installed at: {}", plist.display());

    if start_after {
        // Load the plist
        let output = std::process::Command::new("launchctl")
            .args(["load", &plist.to_string_lossy()])
            .output()?;

        if output.status.success() {
            println!("Daemon started via launchctl.");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("launchctl load failed: {stderr}");
        }
    } else {
        println!("Start with: launchctl load {}", plist.display());
    }

    Ok(())
}

/// Uninstall the launchd plist.
pub fn uninstall() -> anyhow::Result<()> {
    let plist = persistence::plist_path();

    if plist.exists() {
        // Unload first
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist.to_string_lossy()])
            .output();

        persistence::uninstall_launchd()
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        println!("Launchd plist removed.");
    } else {
        println!("No launchd plist found.");
    }

    Ok(())
}

/// Show the daemon configuration (daemon.toml).
pub fn config_show() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\nRun `aegis` to set up, or `aegis daemon init` for a skeleton config.",
            config_path.display()
        );
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config = DaemonConfig::from_toml(&content)?;

    println!("Daemon configuration: {}", config_path.display());
    println!();

    // Agents
    if config.agents.is_empty() {
        println!("Agents: (none)");
    } else {
        println!("Agents:");
        for agent in &config.agents {
            let tool = tool_display_name(&agent.tool);
            let status = if agent.enabled { "enabled" } else { "disabled" };
            println!("  {} ({}, {}):", agent.name, tool, status);
            println!("    Dir:      {}", agent.working_dir.display());
            if let Some(task) = &agent.task {
                println!("    Task:     {task}");
            }
            println!("    Restart:  {:?} (max {})", agent.restart, agent.max_restarts);
        }
    }
    println!();

    // Channel
    match &config.channel {
        Some(aegis_types::config::ChannelConfig::Telegram(tg)) => {
            println!("Telegram:");
            println!("  Chat ID:     {}", tg.chat_id);
            println!("  Poll timeout: {}s", tg.poll_timeout_secs);
            // Don't print the full token for security
            let token_preview = if tg.bot_token.len() > 10 {
                format!("{}...", &tg.bot_token[..10])
            } else {
                "(set)".to_string()
            };
            println!("  Bot token:   {token_preview}");
        }
        None => {
            println!("Telegram: not configured");
        }
    }
    println!();

    // Control
    println!("Control socket: {}", config.control.socket_path.display());

    Ok(())
}

/// Open the daemon configuration in $EDITOR.
pub fn config_edit() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\nRun `aegis` to set up, or `aegis daemon init` for a skeleton config.",
            config_path.display()
        );
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        anyhow::bail!("editor exited with code {}", status.code().unwrap_or(-1));
    }

    // Validate the edited config
    let content = std::fs::read_to_string(&config_path)?;
    match DaemonConfig::from_toml(&content) {
        Ok(cfg) => {
            println!("Configuration saved and validated ({} agent(s)).", cfg.agents.len());
            println!("Restart the daemon for changes to take effect: aegis daemon stop && aegis daemon start");
        }
        Err(e) => {
            println!("WARNING: config may be invalid after editing: {e}");
            println!("Run 'aegis daemon config show' to inspect.");
        }
    }

    Ok(())
}

/// Print the path to daemon.toml (for scripting).
pub fn config_path() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    println!("{}", config_path.display());
    Ok(())
}

/// Add a new agent interactively and persist to daemon.toml.
///
/// Prompts for tool, name, working dir, and task (same flow as the onboard
/// wizard), then appends the agent to daemon.toml and optionally notifies the
/// running daemon.
pub fn add_agent() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\nRun `aegis` to set up first.",
            config_path.display()
        );
    }

    println!("Add a new agent");
    println!("===============");
    println!();

    let tool = crate::commands::onboard::prompt_tool()?;
    let name = crate::commands::onboard::prompt_agent_name()?;
    let working_dir = crate::commands::onboard::prompt_working_dir()?;
    let task = crate::commands::onboard::prompt_task()?;

    let slot = super::build_agent_slot(
        name.clone(),
        tool.clone(),
        working_dir.clone(),
        task.clone(),
        RestartPolicy::OnFailure,
        5,
    );

    // Load existing config, append agent, save
    let content = std::fs::read_to_string(&config_path)?;
    let mut config = DaemonConfig::from_toml(&content)?;

    // Check for name collision
    if config.agents.iter().any(|a| a.name == name) {
        anyhow::bail!("agent '{name}' already exists in daemon.toml");
    }

    config.agents.push(slot.clone());
    let toml_str = config.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;

    let tool_name = tool_display_name(&slot.tool);
    println!();
    println!("Added agent '{name}' ({tool_name}) to {}", config_path.display());

    // If daemon is running, notify it
    let client = DaemonClient::default_path();
    if client.is_running() {
        let resp = client.send(&DaemonCommand::AddAgent {
            config: Box::new(slot),
            start: true,
        });
        match resp {
            Ok(r) if r.ok => println!("Agent '{name}' started in running daemon."),
            Ok(r) => println!("Daemon responded: {}", r.message),
            Err(e) => println!("Could not notify running daemon: {e}\nRestart the daemon to pick up the new agent."),
        }
    } else {
        println!("Daemon is not running. Start it with: aegis daemon start");
    }

    Ok(())
}

/// Remove an agent from daemon.toml (does not affect the running daemon).
pub fn remove_agent(name: &str) -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!("No daemon config found at {}.", config_path.display());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let mut config = DaemonConfig::from_toml(&content)?;

    let before = config.agents.len();
    config.agents.retain(|a| a.name != name);

    if config.agents.len() == before {
        anyhow::bail!("agent '{name}' not found in daemon.toml");
    }

    let toml_str = config.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;

    println!("Removed agent '{name}' from {}", config_path.display());

    // If daemon is running, stop the agent
    let client = DaemonClient::default_path();
    if client.is_running() {
        let resp = client.send(&DaemonCommand::StopAgent { name: name.into() });
        match resp {
            Ok(r) if r.ok => println!("Agent '{name}' stopped in running daemon."),
            Ok(r) => println!("Daemon responded: {}", r.message),
            Err(e) => println!("Could not notify running daemon: {e}"),
        }
    }

    println!("Restart the daemon to fully apply: aegis daemon stop && aegis daemon start");

    Ok(())
}

/// Human-readable display name for a tool config.
pub(crate) fn tool_display_name(tool: &AgentToolConfig) -> &str {
    match tool {
        AgentToolConfig::ClaudeCode { .. } => "Claude Code",
        AgentToolConfig::Codex { .. } => "Codex",
        AgentToolConfig::OpenClaw { .. } => "OpenClaw",
        AgentToolConfig::Cursor { .. } => "Cursor",
        AgentToolConfig::Custom { .. } => "Custom",
    }
}

/// Tail daemon logs.
pub fn logs(follow: bool) -> anyhow::Result<()> {
    let log_dir = daemon_dir();
    let stdout_log = log_dir.join("stdout.log");
    let stderr_log = log_dir.join("stderr.log");

    if !stdout_log.exists() && !stderr_log.exists() {
        println!("No daemon logs found in {}", log_dir.display());
        println!("Logs are created when running via launchd.");
        return Ok(());
    }

    // Use the system tail command for --follow support
    let mut args = vec!["-n", "50"];
    if follow {
        args.push("-f");
    }

    if stdout_log.exists() {
        args.push(stdout_log.to_str().unwrap_or_default());
    }
    if stderr_log.exists() {
        args.push(stderr_log.to_str().unwrap_or_default());
    }

    let status = std::process::Command::new("tail")
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("tail exited with {status}");
    }

    Ok(())
}

/// Follow (tail) an agent's output in real time.
///
/// Polls the daemon every 200ms for new output lines and prints them.
/// Exits when the agent stops or Ctrl+C is pressed.
pub fn follow(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();
    if !client.is_running() {
        anyhow::bail!("daemon is not running. Start it with `aegis daemon start`.");
    }

    // Verify agent exists
    let resp = client.send(&DaemonCommand::AgentStatus { name: name.into() })
        .map_err(|e| anyhow::anyhow!(e))?;
    if !resp.ok {
        anyhow::bail!("{}", resp.message);
    }

    eprintln!("Following output from '{name}' (Ctrl+C to stop)...");

    let mut last_line_count = 0;
    let poll_ms = std::time::Duration::from_millis(200);

    // Install Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .ok();

    while running.load(Ordering::Relaxed) {
        let resp = client.send(&DaemonCommand::AgentOutput {
            name: name.into(),
            lines: Some(500),
        });

        match resp {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    if let Ok(lines) = serde_json::from_value::<Vec<String>>(data) {
                        let total = lines.len();
                        if total > last_line_count {
                            // Print new lines only
                            for line in &lines[last_line_count..] {
                                println!("{line}");
                            }
                            last_line_count = total;
                        }
                    }
                }
            }
            Ok(resp) => {
                eprintln!("Error: {}", resp.message);
                break;
            }
            Err(e) => {
                eprintln!("Connection lost: {e}");
                break;
            }
        }

        // Check if agent is still running
        let status_resp = client.send(&DaemonCommand::AgentStatus { name: name.into() });
        if let Ok(resp) = status_resp {
            if resp.ok {
                if let Some(data) = resp.data {
                    let status_str = data["status"].as_str().unwrap_or("");
                    if status_str == "stopped" || status_str == "failed" {
                        eprintln!("Agent '{name}' has exited.");
                        break;
                    }
                }
            }
        }

        std::thread::sleep(poll_ms);
    }

    Ok(())
}
