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

use anyhow::Context;
use tracing::info;

use aegis_control::daemon::{DaemonClient, DaemonCommand};
use aegis_daemon::persistence;
use aegis_types::daemon::{
    daemon_config_path, daemon_dir, AgentSlotConfig, AgentToolConfig, DaemonConfig,
    DaemonControlConfig, PersistenceConfig, RestartPolicy,
};
use aegis_types::AegisConfig;

use crate::tui_utils::truncate_str;

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
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
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

/// Create default daemon.toml without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI to avoid
/// corrupting the alternate screen with println! output.
pub(crate) fn init_quiet() -> anyhow::Result<String> {
    let dir = daemon_dir();
    std::fs::create_dir_all(&dir)?;

    let config_path = daemon_config_path();
    if config_path.exists() {
        return Ok(format!("daemon.toml already exists at {}", config_path.display()));
    }

    let example = DaemonConfig {
        goal: None,
        persistence: PersistenceConfig::default(),
        control: DaemonControlConfig::default(),
        alerts: vec![],
        agents: vec![AgentSlotConfig {
            name: "claude-1".to_string(),
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
            enabled: false,
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
        }],
        channel: None,
    };

    let toml_str = example.to_toml()?;
    std::fs::write(&config_path, &toml_str)?;

    Ok(format!("Created daemon.toml at {}", config_path.display()))
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
    // Verify daemon.toml exists and is valid before spawning background process.
    // Parsing here catches malformed configs immediately instead of letting the
    // background daemon crash silently after fork.
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found at {}.\n\
             Create one with `aegis daemon init` or run the onboard wizard.",
            config_path.display()
        );
    }
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let _config = DaemonConfig::from_toml(&content)
        .map_err(|e| anyhow::anyhow!("invalid daemon config: {e}"))?;

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

    // Redirect stdout/stderr to log files so daemon output is not lost.
    // Uses append mode to preserve logs across restarts.
    let log_dir = daemon_dir();
    std::fs::create_dir_all(&log_dir)?;
    let stdout_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("stdout.log"))?;
    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("stderr.log"))?;

    let child = std::process::Command::new(&binary)
        .args(["daemon", "run"])
        .stdout(stdout_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null())
        .spawn()?;

    let pid = child.id();

    // Brief poll to verify the daemon didn't crash immediately after fork.
    // The daemon creates its socket within ~100ms. If the process dies before
    // that, we catch it here instead of leaving the user with a false success.
    std::thread::sleep(std::time::Duration::from_millis(300));
    if !persistence::is_process_alive(pid) {
        anyhow::bail!(
            "Daemon exited immediately after starting.\n\
             Check {}/stderr.log for details.",
            log_dir.display()
        );
    }

    println!("Daemon started (PID {pid}).");
    println!("Logs: {}/stdout.log", log_dir.display());
    Ok(())
}

/// Start the daemon in the background without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI.
pub(crate) fn start_quiet() -> anyhow::Result<String> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!(
            "No daemon config found. Create one with :daemon init."
        );
    }
    // Validate config before spawning so errors surface in the TUI command bar,
    // not silently in the background daemon's stderr log.
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let _config = DaemonConfig::from_toml(&content)
        .map_err(|e| anyhow::anyhow!("invalid daemon config: {e}"))?;

    if let Some(pid) = persistence::read_pid() {
        if persistence::is_process_alive(pid) {
            return Ok(format!("Daemon already running (PID {pid})."));
        }
    }

    let binary = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("aegis"));

    let log_dir = daemon_dir();
    std::fs::create_dir_all(&log_dir)?;
    let stdout_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("stdout.log"))?;
    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("stderr.log"))?;

    let child = std::process::Command::new(&binary)
        .args(["daemon", "run"])
        .stdout(stdout_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null())
        .spawn()?;

    let pid = child.id();

    // Poll to verify the daemon started and is accepting connections.
    // The daemon needs time to parse config, bind socket, and start the
    // control server. We try for up to 3 seconds with 200ms intervals.
    let client = DaemonClient::default_path();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if !persistence::is_process_alive(pid) {
            anyhow::bail!(
                "Daemon exited immediately. Check {}/stderr.log",
                log_dir.display()
            );
        }
        if client.is_running() {
            return Ok(format!("Daemon started (PID {pid})."));
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }

    // Process alive but socket not responding -- could still be initializing
    Ok(format!("Daemon started (PID {pid}), socket not yet ready."))
}

/// Stop a running daemon via the control socket.
pub fn stop() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        println!("Daemon is not running. Start it with `aegis daemon start`.");
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

/// Stop a running daemon without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI.
pub(crate) fn stop_quiet() -> anyhow::Result<String> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        return Ok("Daemon is not running. Start it with `aegis daemon start`.".to_string());
    }

    let response = client
        .send(&DaemonCommand::Shutdown)
        .map_err(|e| anyhow::anyhow!("failed to send shutdown: {e}"))?;

    if response.ok {
        Ok("Daemon shutdown requested.".to_string())
    } else {
        Ok(format!("Shutdown failed: {}", response.message))
    }
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

/// Stop and restart the daemon.
pub fn restart() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Use `aegis daemon start` instead.");
    }

    // Stop
    client
        .send(&DaemonCommand::Shutdown)
        .map_err(|e| anyhow::anyhow!("failed to send shutdown: {e}"))?;

    println!("Shutdown requested. Waiting for daemon to exit...");

    wait_for_daemon_exit(&client)?;

    println!("Daemon stopped. Restarting...");

    // Start
    start()?;

    Ok(())
}

/// Stop and restart the daemon without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI.
pub(crate) fn restart_quiet() -> anyhow::Result<String> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Use :daemon start instead.");
    }

    client
        .send(&DaemonCommand::Shutdown)
        .map_err(|e| anyhow::anyhow!("failed to send shutdown: {e}"))?;

    wait_for_daemon_exit(&client)?;

    let msg = start_quiet()?;
    Ok(format!("Daemon restarted. {msg}"))
}

/// Poll until the daemon exits, with a 10-second timeout.
fn wait_for_daemon_exit(client: &DaemonClient) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if !client.is_running() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "daemon did not exit within 10 seconds.\n\
                 Check `aegis daemon status` or stop it manually."
            );
        }
    }
}

/// Query daemon status.
pub fn status() -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        println!("Daemon is not running. Start it with `aegis daemon start`.");
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
        println!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
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
                    truncate_str(&p.raw_prompt, 40)
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
            anyhow::bail!("launchctl load failed: {stderr}");
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
            let token_preview = truncate_str(&tg.bot_token, 13);
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

    // Save original content so we can restore on validation failure
    let original = std::fs::read_to_string(&config_path)?;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        anyhow::bail!("editor exited unsuccessfully ({status})");
    }

    // Validate the edited config
    let content = std::fs::read_to_string(&config_path)?;
    match DaemonConfig::from_toml(&content) {
        Ok(cfg) => {
            println!("Configuration saved and validated ({} agent(s)).", cfg.agents.len());
            println!("Run 'aegis daemon reload' to apply changes without restarting.");
        }
        Err(e) => {
            // Restore the original valid config to prevent breaking daemon operations.
            // Save the user's invalid edit to a .bak file so their work isn't lost.
            let bak_path = config_path.with_extension("toml.bak");
            let _ = std::fs::write(&bak_path, &content);
            std::fs::write(&config_path, &original)?;
            anyhow::bail!(
                "Invalid config: {e}\n\
                 Original config restored. Your edit saved to {}.",
                bak_path.display()
            );
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
            Err(e) => println!("Could not notify running daemon: {e}\nRun 'aegis daemon reload' to pick up the new agent."),
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

    // If daemon is running, reload config so the agent is fully removed
    let client = DaemonClient::default_path();
    if client.is_running() {
        let resp = client.send(&DaemonCommand::ReloadConfig);
        match resp {
            Ok(r) if r.ok => println!("Agent '{name}' removed from running daemon."),
            Ok(r) => println!("Daemon responded: {}", r.message),
            Err(e) => println!("Could not notify running daemon: {e}"),
        }
    }

    Ok(())
}

/// Remove an agent from daemon.toml without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI.
pub(crate) fn remove_agent_quiet(name: &str) -> anyhow::Result<String> {
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

    Ok(format!("Removed '{name}'."))
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

/// Show orchestrator overview: bulk fleet status with recent output.
pub fn orchestrator_status(agents: &[String], lines: usize) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
    }

    let response = client
        .send(&DaemonCommand::OrchestratorContext {
            agents: agents.to_vec(),
            output_lines: Some(lines),
        })
        .map_err(|e| anyhow::anyhow!("failed to get orchestrator context: {e}"))?;

    if !response.ok {
        anyhow::bail!("{}", response.message);
    }

    if let Some(data) = response.data {
        if let Ok(snapshot) =
            serde_json::from_value::<aegis_control::daemon::OrchestratorSnapshot>(data)
        {
            // Fleet goal
            if let Some(goal) = &snapshot.fleet_goal {
                println!("Fleet goal: {goal}");
                println!();
            }

            if snapshot.agents.is_empty() {
                println!("No managed agents.");
                return Ok(());
            }

            for agent in &snapshot.agents {
                // Header line
                let uptime = agent.uptime_secs
                    .map(|s| format!("{}m", s / 60))
                    .unwrap_or_else(|| "-".to_string());
                let attention = if agent.attention_needed { " [ATTENTION]" } else { "" };
                let pending = if agent.pending_count > 0 {
                    format!(" ({} pending)", agent.pending_count)
                } else {
                    String::new()
                };

                println!(
                    "--- {} [{}, up {}{}{}] ---",
                    agent.name, agent.status, uptime, pending, attention,
                );

                // Context
                if let Some(role) = &agent.role {
                    println!("  Role: {role}");
                }
                if let Some(goal) = &agent.agent_goal {
                    println!("  Goal: {goal}");
                }
                if let Some(task) = &agent.task {
                    println!("  Task: {task}");
                }

                // Recent output (last N lines)
                if !agent.recent_output.is_empty() {
                    println!("  Recent output:");
                    for line in &agent.recent_output {
                        println!("    {}", truncate_str(line, 120));
                    }
                }

                println!();
            }
        }
    }

    Ok(())
}

/// Tail daemon logs.
pub fn logs(follow: bool) -> anyhow::Result<()> {
    let log_dir = daemon_dir();
    let stdout_log = log_dir.join("stdout.log");
    let stderr_log = log_dir.join("stderr.log");

    if !stdout_log.exists() && !stderr_log.exists() {
        println!("No daemon logs found in {}", log_dir.display());
        println!("Logs are created when the daemon runs (via `start` or `launchd`).");
        return Ok(());
    }

    // Use the system tail command for --follow support
    let mut args = vec!["-n", "50"];
    if follow {
        args.push("-f");
    }

    let stdout_str = stdout_log
        .to_str()
        .map(|s| s.to_string());
    let stderr_str = stderr_log
        .to_str()
        .map(|s| s.to_string());

    if stdout_log.exists() {
        if let Some(ref s) = stdout_str {
            args.push(s);
        } else {
            anyhow::bail!("daemon stdout log path is not valid UTF-8");
        }
    }
    if stderr_log.exists() {
        if let Some(ref s) = stderr_str {
            args.push(s);
        } else {
            anyhow::bail!("daemon stderr log path is not valid UTF-8");
        }
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

    // Verify agent exists and check for tmux attach support
    let resp = client.send(&DaemonCommand::ListAgents)
        .map_err(|e| anyhow::anyhow!(e))?;
    if let Some(data) = &resp.data {
        if let Ok(agents) = serde_json::from_value::<Vec<aegis_control::daemon::AgentSummary>>(data.clone()) {
            if let Some(agent) = agents.iter().find(|a| a.name == name) {
                if let Some(ref attach_cmd) = agent.attach_command {
                    if attach_cmd.len() >= 2 {
                        // Attach directly to the tmux session for the real TUI
                        eprintln!("Attaching to '{name}' tmux session (Ctrl+B D to detach)...");
                        let status = std::process::Command::new(&attach_cmd[0])
                            .args(&attach_cmd[1..])
                            .status()?;
                        if !status.success() {
                            anyhow::bail!("tmux attach failed with {status}");
                        }
                        return Ok(());
                    }
                }
            } else {
                anyhow::bail!("unknown agent: {name}");
            }
        }
    }

    // Fallback: stream captured output lines (no tmux)
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
        match status_resp {
            Ok(resp) if resp.ok => {
                if let Some(data) = resp.data {
                    let status_str = data["status"].as_str().unwrap_or("unknown");
                    match status_str {
                        "running" | "starting" | "unknown" => {}
                        terminal => {
                            eprintln!("Agent '{name}' has exited (status: {terminal}).");
                            break;
                        }
                    }
                }
            }
            Ok(resp) => {
                // Agent doesn't exist or daemon rejected the query
                eprintln!("Agent '{name}': {}", resp.message);
                break;
            }
            Err(_) => {
                // Connection lost -- already handled in output fetch above,
                // but break here too for safety
                eprintln!("Connection to daemon lost.");
                break;
            }
        }

        std::thread::sleep(poll_ms);
    }

    Ok(())
}

/// Enable an agent slot (allows it to be started).
pub fn enable_agent(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
    }

    let response = client
        .send(&DaemonCommand::EnableAgent {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to enable agent: {e}"))?;

    if response.ok {
        println!("Agent '{name}' enabled.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Disable an agent slot (stops it if running, prevents restart).
pub fn disable_agent(name: &str) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
    }

    let response = client
        .send(&DaemonCommand::DisableAgent {
            name: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to disable agent: {e}"))?;

    if response.ok {
        println!("Agent '{name}' disabled.");
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Get or set the fleet-wide goal.
pub fn goal(text: Option<&str>) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
    }

    let response = client
        .send(&DaemonCommand::FleetGoal {
            goal: text.map(|s| s.to_string()),
        })
        .map_err(|e| anyhow::anyhow!("failed to manage fleet goal: {e}"))?;

    if response.ok {
        println!("{}", response.message);
    } else {
        anyhow::bail!("{}", response.message);
    }

    Ok(())
}

/// Get or set agent context fields (role, goal, context, task).
pub fn context(
    name: &str,
    field: Option<&str>,
    value: Option<&str>,
) -> anyhow::Result<()> {
    let client = DaemonClient::default_path();

    if !client.is_running() {
        anyhow::bail!("Daemon is not running. Start it with `aegis daemon start`.");
    }

    match (field, value) {
        (Some(f), Some(v)) => {
            let (role, agent_goal, ctx, task) = match f {
                "role" => (Some(v.to_string()), None, None, None),
                "goal" => (None, Some(v.to_string()), None, None),
                "context" => (None, None, Some(v.to_string()), None),
                "task" => (None, None, None, Some(v.to_string())),
                _ => anyhow::bail!(
                    "Unknown field '{f}'. Valid fields: role, goal, context, task"
                ),
            };
            let response = client
                .send(&DaemonCommand::UpdateAgentContext {
                    name: name.to_string(),
                    role,
                    agent_goal,
                    context: ctx,
                    task,
                })
                .map_err(|e| anyhow::anyhow!("failed to update context: {e}"))?;

            if response.ok {
                println!("{}", response.message);
            } else {
                anyhow::bail!("{}", response.message);
            }
        }
        _ => {
            let response = client
                .send(&DaemonCommand::GetAgentContext {
                    name: name.to_string(),
                })
                .map_err(|e| anyhow::anyhow!("failed to get context: {e}"))?;

            if response.ok {
                if let Some(data) = &response.data {
                    if let Some(obj) = data.as_object() {
                        for (k, v) in obj {
                            let val = v.as_str().unwrap_or("(none)");
                            let display = if val.is_empty() { "(none)" } else { val };
                            println!("  {k}: {display}");
                        }
                    }
                } else {
                    println!("{}", response.message);
                }
            } else {
                anyhow::bail!("{}", response.message);
            }
        }
    }

    Ok(())
}

