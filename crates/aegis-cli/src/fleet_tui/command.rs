//! Command bar: vim-style `:` mode for fleet control.
//!
//! Parses command strings into `FleetCommand` variants and provides
//! tab completion for command names and agent names.

/// A parsed fleet command from the `:` command bar.
#[derive(Debug, Clone, PartialEq)]
pub enum FleetCommand {
    /// Open the add-agent wizard.
    Add,
    /// Start an agent.
    Start { agent: String },
    /// Stop an agent.
    Stop { agent: String },
    /// Restart an agent.
    Restart { agent: String },
    /// Send text to an agent's stdin.
    Send { agent: String, text: String },
    /// Approve the first pending prompt for an agent.
    Approve { agent: String },
    /// Deny the first pending prompt for an agent.
    Deny { agent: String },
    /// Nudge a stalled agent with optional message.
    Nudge { agent: String, message: Option<String> },
    /// Drill into an agent's output (switch to detail view).
    Follow { agent: String },
    /// Pop an agent's output into a new terminal window.
    Pop { agent: String },
    /// Open the monitor TUI in a new terminal window.
    Monitor,
    /// Show daemon status summary.
    Status,
    /// Show help for all commands.
    Help,
    /// Quit the TUI.
    Quit,
}

/// All known command names for completion.
const COMMAND_NAMES: &[&str] = &[
    "add", "approve", "deny", "follow", "help", "monitor", "nudge",
    "pop", "quit", "restart", "send", "start", "status", "stop",
];

/// Commands that take an agent name as the second token.
const AGENT_COMMANDS: &[&str] = &[
    "approve", "deny", "follow", "nudge", "pop", "restart", "send", "start", "stop",
];

/// Parse a command string into a `FleetCommand`.
///
/// Returns `None` if the string is empty or doesn't match any command.
/// Returns `Err(message)` if the command is recognized but has invalid arguments.
pub fn parse(input: &str) -> Result<Option<FleetCommand>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }

    let mut parts = input.splitn(3, ' ');
    let cmd = parts.next().unwrap_or("");
    let arg1 = parts.next().unwrap_or("").trim();
    let arg2 = parts.next().unwrap_or("").trim();

    match cmd {
        "add" => Ok(Some(FleetCommand::Add)),
        "start" => {
            if arg1.is_empty() {
                Err("usage: start <agent>".into())
            } else {
                Ok(Some(FleetCommand::Start { agent: arg1.into() }))
            }
        }
        "stop" => {
            if arg1.is_empty() {
                Err("usage: stop <agent>".into())
            } else {
                Ok(Some(FleetCommand::Stop { agent: arg1.into() }))
            }
        }
        "restart" => {
            if arg1.is_empty() {
                Err("usage: restart <agent>".into())
            } else {
                Ok(Some(FleetCommand::Restart { agent: arg1.into() }))
            }
        }
        "send" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: send <agent> <text>".into())
            } else {
                Ok(Some(FleetCommand::Send {
                    agent: arg1.into(),
                    text: arg2.into(),
                }))
            }
        }
        "approve" => {
            if arg1.is_empty() {
                Err("usage: approve <agent>".into())
            } else {
                Ok(Some(FleetCommand::Approve { agent: arg1.into() }))
            }
        }
        "deny" => {
            if arg1.is_empty() {
                Err("usage: deny <agent>".into())
            } else {
                Ok(Some(FleetCommand::Deny { agent: arg1.into() }))
            }
        }
        "nudge" => {
            if arg1.is_empty() {
                Err("usage: nudge <agent> [message]".into())
            } else {
                let msg = if arg2.is_empty() { None } else { Some(arg2.into()) };
                Ok(Some(FleetCommand::Nudge {
                    agent: arg1.into(),
                    message: msg,
                }))
            }
        }
        "follow" => {
            if arg1.is_empty() {
                Err("usage: follow <agent>".into())
            } else {
                Ok(Some(FleetCommand::Follow { agent: arg1.into() }))
            }
        }
        "pop" => {
            if arg1.is_empty() {
                Err("usage: pop <agent>".into())
            } else {
                Ok(Some(FleetCommand::Pop { agent: arg1.into() }))
            }
        }
        "monitor" => Ok(Some(FleetCommand::Monitor)),
        "status" => Ok(Some(FleetCommand::Status)),
        "help" => Ok(Some(FleetCommand::Help)),
        "quit" | "q" => Ok(Some(FleetCommand::Quit)),
        _ => Err(format!("unknown command: {cmd}. Type :help for available commands.")),
    }
}

/// Complete the current command buffer, returning possible completions.
///
/// - If the buffer has no space, complete command names.
/// - If the buffer has one space and the command takes an agent, complete agent names.
pub fn completions(buffer: &str, agent_names: &[String]) -> Vec<String> {
    let trimmed = buffer.trim_start();

    if !trimmed.contains(' ') {
        // Complete command name
        let prefix = trimmed;
        COMMAND_NAMES
            .iter()
            .filter(|name| name.starts_with(prefix))
            .map(|name| name.to_string())
            .collect()
    } else {
        // Complete agent name for commands that take one
        let mut parts = trimmed.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let agent_prefix = parts.next().unwrap_or("").trim();

        if !AGENT_COMMANDS.contains(&cmd) {
            return Vec::new();
        }

        agent_names
            .iter()
            .filter(|name| name.starts_with(agent_prefix))
            .cloned()
            .collect()
    }
}

/// Build the full buffer string from a completion selection.
///
/// For command completions: just the command name.
/// For agent completions: "command agent".
pub fn apply_completion(buffer: &str, completion: &str) -> String {
    let trimmed = buffer.trim_start();
    if !trimmed.contains(' ') {
        // Completing command name
        format!("{completion} ")
    } else {
        // Completing agent name
        let cmd = trimmed.split(' ').next().unwrap_or("");
        format!("{cmd} {completion} ")
    }
}

/// Help text listing all available commands.
pub fn help_text() -> &'static str {
    ":add                     Open add-agent wizard\n\
     :start <agent>           Start agent\n\
     :stop <agent>            Stop agent\n\
     :restart <agent>         Restart agent\n\
     :send <agent> <text>     Send text to agent stdin\n\
     :approve <agent>         Approve first pending prompt\n\
     :deny <agent>            Deny first pending prompt\n\
     :nudge <agent> [msg]     Nudge stalled agent\n\
     :follow <agent>          Drill into agent output\n\
     :pop <agent>             Open agent in new terminal\n\
     :monitor                 Open monitor in new terminal\n\
     :status                  Daemon status summary\n\
     :help                    Show this help\n\
     :quit                    Quit TUI"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(parse("  ").unwrap(), None);
    }

    #[test]
    fn parse_add() {
        assert_eq!(parse("add").unwrap(), Some(FleetCommand::Add));
    }

    #[test]
    fn parse_start() {
        assert_eq!(
            parse("start claude-1").unwrap(),
            Some(FleetCommand::Start { agent: "claude-1".into() })
        );
    }

    #[test]
    fn parse_start_missing_agent() {
        assert!(parse("start").is_err());
    }

    #[test]
    fn parse_stop() {
        assert_eq!(
            parse("stop agent-2").unwrap(),
            Some(FleetCommand::Stop { agent: "agent-2".into() })
        );
    }

    #[test]
    fn parse_restart() {
        assert_eq!(
            parse("restart a1").unwrap(),
            Some(FleetCommand::Restart { agent: "a1".into() })
        );
    }

    #[test]
    fn parse_send() {
        assert_eq!(
            parse("send claude-1 fix the bug").unwrap(),
            Some(FleetCommand::Send {
                agent: "claude-1".into(),
                text: "fix the bug".into(),
            })
        );
    }

    #[test]
    fn parse_send_missing_text() {
        assert!(parse("send claude-1").is_err());
    }

    #[test]
    fn parse_send_missing_all() {
        assert!(parse("send").is_err());
    }

    #[test]
    fn parse_approve() {
        assert_eq!(
            parse("approve agent-1").unwrap(),
            Some(FleetCommand::Approve { agent: "agent-1".into() })
        );
    }

    #[test]
    fn parse_deny() {
        assert_eq!(
            parse("deny agent-1").unwrap(),
            Some(FleetCommand::Deny { agent: "agent-1".into() })
        );
    }

    #[test]
    fn parse_nudge_with_message() {
        assert_eq!(
            parse("nudge a1 wake up please").unwrap(),
            Some(FleetCommand::Nudge {
                agent: "a1".into(),
                message: Some("wake up please".into()),
            })
        );
    }

    #[test]
    fn parse_nudge_without_message() {
        assert_eq!(
            parse("nudge a1").unwrap(),
            Some(FleetCommand::Nudge {
                agent: "a1".into(),
                message: None,
            })
        );
    }

    #[test]
    fn parse_follow() {
        assert_eq!(
            parse("follow claude-1").unwrap(),
            Some(FleetCommand::Follow { agent: "claude-1".into() })
        );
    }

    #[test]
    fn parse_status() {
        assert_eq!(parse("status").unwrap(), Some(FleetCommand::Status));
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse("help").unwrap(), Some(FleetCommand::Help));
    }

    #[test]
    fn parse_quit() {
        assert_eq!(parse("quit").unwrap(), Some(FleetCommand::Quit));
        assert_eq!(parse("q").unwrap(), Some(FleetCommand::Quit));
    }

    #[test]
    fn parse_unknown() {
        assert!(parse("bogus").is_err());
    }

    #[test]
    fn parse_pop() {
        assert_eq!(
            parse("pop claude-1").unwrap(),
            Some(FleetCommand::Pop { agent: "claude-1".into() })
        );
    }

    #[test]
    fn parse_pop_missing_agent() {
        assert!(parse("pop").is_err());
    }

    #[test]
    fn parse_monitor() {
        assert_eq!(parse("monitor").unwrap(), Some(FleetCommand::Monitor));
    }

    #[test]
    fn completions_command_names() {
        let agents = vec![];
        let c = completions("st", &agents);
        assert!(c.contains(&"start".to_string()));
        assert!(c.contains(&"status".to_string()));
        assert!(c.contains(&"stop".to_string()));
        assert!(!c.contains(&"add".to_string()));
    }

    #[test]
    fn completions_command_names_empty() {
        let agents = vec![];
        let c = completions("", &agents);
        assert_eq!(c.len(), COMMAND_NAMES.len());
    }

    #[test]
    fn completions_agent_names() {
        let agents = vec![
            "claude-1".to_string(),
            "claude-2".to_string(),
            "codex-1".to_string(),
        ];
        let c = completions("stop cl", &agents);
        assert_eq!(c, vec!["claude-1", "claude-2"]);
    }

    #[test]
    fn completions_no_agent_for_status() {
        let agents = vec!["claude-1".to_string()];
        let c = completions("status ", &agents);
        assert!(c.is_empty());
    }

    #[test]
    fn apply_completion_command() {
        assert_eq!(apply_completion("sta", "start"), "start ");
    }

    #[test]
    fn apply_completion_agent() {
        assert_eq!(apply_completion("stop cl", "claude-1"), "stop claude-1 ");
    }

    #[test]
    fn help_text_not_empty() {
        assert!(help_text().contains(":add"));
        assert!(help_text().contains(":quit"));
    }
}
