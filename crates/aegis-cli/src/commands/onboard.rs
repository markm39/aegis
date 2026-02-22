//! Unified first-run onboarding wizard.
//!
//! When `aegis` is invoked with nothing configured, this module launches a
//! ratatui TUI wizard that configures an agent, optionally sets up Telegram
//! notifications, writes `daemon.toml`, starts the daemon, and opens the
//! fleet dashboard.
//!
//! The `prompt_*` helpers below are still used by `daemon.rs::add_agent()`
//! for the CLI `aegis daemon add` command.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::bail;

use aegis_types::daemon::AgentToolConfig;

/// Run the unified onboarding wizard.
///
/// Launches a full ratatui TUI wizard that writes `daemon.toml`, starts the
/// daemon (via the health check step), then opens the fleet dashboard.
pub fn run() -> anyhow::Result<()> {
    let result = crate::onboard_tui::run_onboard_wizard()?;

    if result.cancelled {
        println!("Onboarding cancelled.");
        return Ok(());
    }

    // Config was written and daemon started by the wizard's health check step.
    // Open the chat TUI.
    crate::chat_tui::run_chat_tui()
}

/// Prompt for agent tool type from a numbered menu.
pub(crate) fn prompt_tool() -> anyhow::Result<AgentToolConfig> {
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
            let input = prompt("  Command (e.g., /usr/local/bin/my-agent --flag)", "")?;
            if input.is_empty() {
                bail!("command cannot be empty for custom tool");
            }
            // Split "command --flag1 --flag2" into command + args
            let parts: Vec<&str> = input.split_whitespace().collect();
            let command = parts[0].to_string();
            let args: Vec<String> = parts.iter().skip(1).map(|s| s.to_string()).collect();
            AgentToolConfig::Custom {
                command,
                args,
                adapter: Default::default(),
                env: vec![],
            }
        }
        other => bail!("invalid choice: {other}"),
    };
    Ok(tool)
}

/// Prompt for agent name, defaulting to CWD basename.
pub(crate) fn prompt_agent_name() -> anyhow::Result<String> {
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
pub(crate) fn prompt_working_dir() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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
pub(crate) fn prompt_task() -> anyhow::Result<Option<String>> {
    let task = prompt("  Task (optional, press Enter to skip)", "")?;
    if task.is_empty() {
        Ok(None)
    } else {
        Ok(Some(task))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::daemon::tool_display_name;
    use aegis_types::config::{ChannelConfig, TelegramConfig};
    use aegis_types::daemon::{
        AgentSlotConfig, DaemonConfig, DaemonControlConfig, DashboardConfig, PersistenceConfig,
        RestartPolicy,
    };

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
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: DashboardConfig::default(),
            alerts: vec![],
            agents: vec![AgentSlotConfig {
                name: "test-agent".into(),
                tool: AgentToolConfig::ClaudeCode {
                    skip_permissions: false,
                    one_shot: false,
                    extra_args: vec![],
                },
                working_dir: PathBuf::from("/tmp/test"),
                role: None,
                agent_goal: None,
                context: None,
                task: Some("do stuff".into()),
                pilot: None,
                restart: RestartPolicy::OnFailure,
                max_restarts: 5,
                enabled: true,
                orchestrator: None,
                security_preset: None,
                policy_dir: None,
                isolation: None,
                lane: None,
            }],
            channel: None,
            channel_routing: None,
            toolkit: Default::default(),
            memory: Default::default(),
            session_files: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: Default::default(),
            acp_server: None,
            default_model: None,
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
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: DashboardConfig::default(),
            alerts: vec![],
            agents: vec![AgentSlotConfig {
                name: "my-agent".into(),
                tool: AgentToolConfig::ClaudeCode {
                    skip_permissions: false,
                    one_shot: false,
                    extra_args: vec![],
                },
                working_dir: PathBuf::from("/tmp/project"),
                role: None,
                agent_goal: None,
                context: None,
                task: None,
                pilot: None,
                restart: RestartPolicy::OnFailure,
                max_restarts: 5,
                enabled: true,
                orchestrator: None,
                security_preset: None,
                policy_dir: None,
                isolation: None,
                lane: None,
            }],
            channel: Some(ChannelConfig::Telegram(TelegramConfig {
                bot_token: "123:ABC".into(),
                chat_id: 99999,
                poll_timeout_secs: 30,
                allow_group_commands: false,
                active_hours: None,
                webhook_mode: false,
                webhook_port: None,
                webhook_url: None,
                webhook_secret: None,
                inline_queries_enabled: false,
            })),
            channel_routing: None,
            toolkit: Default::default(),
            memory: Default::default(),
            session_files: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: Default::default(),
            acp_server: None,
            default_model: None,
        };

        let toml_str = config.to_toml().unwrap();
        let back = DaemonConfig::from_toml(&toml_str).unwrap();
        assert_eq!(back.agents.len(), 1);
        assert!(back.channel.is_some());
    }
}
