//! Unified first-run onboarding wizard.
//!
//! When `aegis` is invoked with nothing configured, this module runs a single
//! plain stdin/stdout wizard that configures an agent, optionally sets up
//! Telegram notifications, writes `daemon.toml`, starts the daemon, and opens
//! the fleet dashboard.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{bail, Context};

use aegis_channel::telegram::api::TelegramApi;
use aegis_types::config::{ChannelConfig, TelegramConfig};
use aegis_types::daemon::{
    daemon_config_path, daemon_dir, AgentSlotConfig, AgentToolConfig, DaemonConfig,
    DaemonControlConfig, PersistenceConfig, RestartPolicy,
};

/// Run the unified onboarding wizard.
pub fn run() -> anyhow::Result<()> {
    println!("Welcome to Aegis -- zero-trust runtime for AI agents.");
    println!();

    // Step 1: system check
    println!("Step 1: System check");
    let aegis_dir = crate::commands::init::ensure_aegis_dir()?;
    println!("  {} ... ok", aegis_dir.display());
    println!();

    // Step 2: agent configuration
    println!("Step 2: Add your first agent");
    let tool = prompt_tool()?;
    let name = prompt_agent_name()?;
    let working_dir = prompt_working_dir()?;
    let task = prompt_task()?;

    let slot = AgentSlotConfig {
        name: name.clone(),
        tool: tool.clone(),
        working_dir: working_dir.clone(),
        task: task.clone(),
        pilot: None,
        restart: RestartPolicy::OnFailure,
        max_restarts: 5,
        enabled: true,
    };
    println!();

    // Step 3: Telegram (optional)
    let channel = if confirm("Step 3: Set up Telegram notifications?", true)? {
        println!();
        Some(run_telegram_setup()?)
    } else {
        println!();
        None
    };

    // Write config
    let config = DaemonConfig {
        persistence: PersistenceConfig::default(),
        control: DaemonControlConfig::default(),
        alerts: vec![],
        agents: vec![slot],
        channel,
    };

    let dir = daemon_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;

    let config_path = daemon_config_path();
    let toml_str = config.to_toml().context("failed to serialize config")?;
    std::fs::write(&config_path, &toml_str)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    println!("Wrote config to {}", config_path.display());
    println!();

    // Step 4: Start daemon
    let started = if confirm("Start the daemon now?", true)? {
        crate::commands::daemon::start()?;
        true
    } else {
        println!("Run `aegis daemon start` when ready.");
        false
    };
    println!();

    // Summary
    println!("Setup complete!");
    println!("  Agent: {} ({})", name, tool_display_name(&tool));
    println!("  Dir:   {}", working_dir.display());
    if let Some(t) = &task {
        println!("  Task:  {t}");
    }
    println!("  Config: {}", config_path.display());
    println!();
    println!("Next: use the fleet dashboard to manage your agents.");
    println!("  aegis              # open dashboard");
    println!("  aegis daemon stop  # stop the daemon");

    // Open fleet dashboard if daemon started
    if started {
        println!();
        crate::fleet_tui::run_fleet_tui()?;
    }

    Ok(())
}

/// Prompt for agent tool type from a numbered menu.
fn prompt_tool() -> anyhow::Result<AgentToolConfig> {
    println!("  What tool?");
    println!("    [1] Claude Code");
    println!("    [2] Codex");
    println!("    [3] OpenClaw");
    println!("    [4] Custom");

    let choice = prompt("  Choice", "1")?;
    let tool = match choice.as_str() {
        "1" | "" => AgentToolConfig::ClaudeCode {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        },
        "2" => AgentToolConfig::Codex {
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        },
        "3" => AgentToolConfig::OpenClaw {
            agent_name: None,
            extra_args: vec![],
        },
        "4" => {
            let command = prompt("  Command (e.g., /usr/local/bin/my-agent)", "")?;
            if command.is_empty() {
                bail!("command cannot be empty for custom tool");
            }
            AgentToolConfig::Custom {
                command,
                args: vec![],
                adapter: Default::default(),
                env: vec![],
            }
        }
        other => bail!("invalid choice: {other}"),
    };
    Ok(tool)
}

/// Prompt for agent name, defaulting to CWD basename.
fn prompt_agent_name() -> anyhow::Result<String> {
    let default = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "my-agent".into());

    loop {
        let name = prompt(&format!("  Agent name [{default}]"), &default)?;
        match aegis_types::validate_config_name(&name) {
            Ok(()) => return Ok(name),
            Err(e) => println!("  Invalid name: {e}. Try again."),
        }
    }
}

/// Prompt for working directory, defaulting to CWD.
fn prompt_working_dir() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    let default = cwd.display().to_string();

    loop {
        let input = prompt(&format!("  Working directory [{default}]"), &default)?;
        let path = PathBuf::from(&input);
        if path.is_dir() {
            return Ok(path);
        }
        println!("  Directory does not exist: {input}. Try again.");
    }
}

/// Prompt for an optional task string.
fn prompt_task() -> anyhow::Result<Option<String>> {
    let task = prompt("  Task (optional, press Enter to skip)", "")?;
    if task.is_empty() {
        Ok(None)
    } else {
        Ok(Some(task))
    }
}

/// Run the Telegram setup flow, returning a `ChannelConfig`.
///
/// Creates a tokio runtime to call the async Telegram API functions
/// that are shared with the standalone `aegis telegram setup` command.
fn run_telegram_setup() -> anyhow::Result<ChannelConfig> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    rt.block_on(async {
        println!("  1. Open Telegram and search for @BotFather");
        println!("  2. Send /newbot and follow the prompts");
        println!("  3. Copy the bot token (looks like 123456:ABC-DEF...)");
        println!();

        let token = super::telegram::prompt_token()?;
        let user = super::telegram::validate_token(&token).await?;

        let bot_username = user.username.as_deref().unwrap_or("your_bot");
        println!("  Connected to bot @{bot_username} ({})", user.first_name);
        println!();

        let api = TelegramApi::new(&token);
        let chat_id = super::telegram::discover_chat_id(&api, bot_username).await?;

        // Send confirmation
        let confirm_text = format!(
            "Aegis connected! This chat will receive agent notifications.\n\
             Chat ID: {chat_id}"
        );
        api.send_message(chat_id, &confirm_text, None, None, false)
            .await
            .context("failed to send confirmation message")?;
        println!("  Sent confirmation message to Telegram");
        println!();

        Ok(ChannelConfig::Telegram(TelegramConfig {
            bot_token: token,
            chat_id,
            poll_timeout_secs: 30,
            allow_group_commands: false,
        }))
    })
}

/// Read a line from stdin, returning `default` if the user presses Enter.
fn prompt(label: &str, default: &str) -> anyhow::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim().to_string();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

/// Y/n confirmation prompt.
fn confirm(label: &str, default: bool) -> anyhow::Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    print!("{label} {hint} ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input == "y" || input == "yes")
    }
}

/// Human-readable display name for a tool config.
fn tool_display_name(tool: &AgentToolConfig) -> &str {
    match tool {
        AgentToolConfig::ClaudeCode { .. } => "Claude Code",
        AgentToolConfig::Codex { .. } => "Codex",
        AgentToolConfig::OpenClaw { .. } => "OpenClaw",
        AgentToolConfig::Cursor { .. } => "Cursor",
        AgentToolConfig::Custom { .. } => "Custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_display_names() {
        let cc = AgentToolConfig::ClaudeCode {
            skip_permissions: false,
            one_shot: false,
            extra_args: vec![],
        };
        assert_eq!(tool_display_name(&cc), "Claude Code");

        let codex = AgentToolConfig::Codex {
            approval_mode: "suggest".into(),
            one_shot: false,
            extra_args: vec![],
        };
        assert_eq!(tool_display_name(&codex), "Codex");

        let oc = AgentToolConfig::OpenClaw {
            agent_name: None,
            extra_args: vec![],
        };
        assert_eq!(tool_display_name(&oc), "OpenClaw");

        let custom = AgentToolConfig::Custom {
            command: "test".into(),
            args: vec![],
            adapter: Default::default(),
            env: vec![],
        };
        assert_eq!(tool_display_name(&custom), "Custom");
    }

    #[test]
    fn daemon_config_roundtrip_with_agent() {
        let config = DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents: vec![AgentSlotConfig {
                name: "test-agent".into(),
                tool: AgentToolConfig::ClaudeCode {
                    skip_permissions: false,
                    one_shot: false,
                    extra_args: vec![],
                },
                working_dir: PathBuf::from("/tmp/test"),
                task: Some("do stuff".into()),
                pilot: None,
                restart: RestartPolicy::OnFailure,
                max_restarts: 5,
                enabled: true,
            }],
            channel: None,
        };

        let toml_str = config.to_toml().unwrap();
        let back = DaemonConfig::from_toml(&toml_str).unwrap();
        assert_eq!(back.agents.len(), 1);
        assert_eq!(back.agents[0].name, "test-agent");
        assert!(back.channel.is_none());
    }

    #[test]
    fn daemon_config_roundtrip_with_telegram() {
        let config = DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents: vec![AgentSlotConfig {
                name: "my-agent".into(),
                tool: AgentToolConfig::ClaudeCode {
                    skip_permissions: false,
                    one_shot: false,
                    extra_args: vec![],
                },
                working_dir: PathBuf::from("/tmp/project"),
                task: None,
                pilot: None,
                restart: RestartPolicy::OnFailure,
                max_restarts: 5,
                enabled: true,
            }],
            channel: Some(ChannelConfig::Telegram(TelegramConfig {
                bot_token: "123:ABC".into(),
                chat_id: 99999,
                poll_timeout_secs: 30,
                allow_group_commands: false,
            })),
        };

        let toml_str = config.to_toml().unwrap();
        let back = DaemonConfig::from_toml(&toml_str).unwrap();
        assert_eq!(back.agents.len(), 1);
        assert!(back.channel.is_some());
    }
}
