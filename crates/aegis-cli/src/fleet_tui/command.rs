//! Command bar: vim-style `:` mode for fleet control.
//!
//! Parses command strings into `FleetCommand` variants and provides
//! tab completion for command names and agent names.

/// A parsed fleet command from the `:` command bar.
#[derive(Debug, Clone, PartialEq)]
pub enum FleetCommand {
    /// Open the add-agent wizard.
    Add,
    /// Remove an agent from the config.
    Remove { agent: String },
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
    /// Open daemon config in $EDITOR (suspends TUI).
    Config,
    /// Show/manage Telegram settings.
    Telegram,
    /// Show help for all commands.
    Help,
    /// Quit the TUI.
    Quit,
    /// Show daemon logs in a new terminal.
    Logs,
    /// List pending prompts for an agent.
    Pending { agent: String },
    /// Wrap a command with Aegis observability in a new terminal.
    Wrap { cmd: String },
    /// Run a sandboxed command in a new terminal.
    Run { cmd: String },
    /// Launch a supervised agent (pilot) in a new terminal.
    Pilot { cmd: String },
    /// Show recent audit log entries in a new terminal.
    Log,
    /// Show policy info in a new terminal.
    Policy,
    /// Generate a compliance report in a new terminal.
    Report,
    /// List all aegis configurations.
    List,
    /// Install aegis hooks for the current project.
    Hook,
    /// Switch active aegis configuration.
    Use { name: Option<String> },
    /// Watch a directory for filesystem changes.
    Watch,
    /// Compare two audit sessions.
    Diff { session1: String, session2: String },
    /// Show alert rules.
    Alerts,
    /// View or set the fleet-wide goal.
    Goal { text: Option<String> },
    /// View or set agent context fields (role, goal, context).
    Context { agent: String, field: Option<String>, value: Option<String> },
    /// Start the daemon in the background.
    DaemonStart,
    /// Stop the running daemon.
    DaemonStop,
    /// Create daemon.toml if it doesn't exist.
    DaemonInit,
    /// Run system checks (verify sandbox, tools, etc.).
    Setup,
    /// Create an aegis project config (init wizard).
    Init,
}

/// All known command names for completion.
const COMMAND_NAMES: &[&str] = &[
    "add", "alerts", "approve", "config", "context", "daemon", "deny", "diff", "follow",
    "goal", "help", "hook", "init", "list", "log", "logs", "monitor", "nudge", "pending",
    "pilot", "policy", "pop", "quit", "remove", "report", "restart", "run", "send", "setup",
    "start", "status", "stop", "telegram", "use", "watch", "wrap",
];

/// Commands that take an agent name as the second token.
const AGENT_COMMANDS: &[&str] = &[
    "approve", "context", "deny", "follow", "nudge", "pending", "pop", "remove", "restart",
    "send", "start", "stop",
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
        "remove" => {
            if arg1.is_empty() {
                Err("usage: remove <agent>".into())
            } else {
                Ok(Some(FleetCommand::Remove { agent: arg1.into() }))
            }
        }
        "config" => Ok(Some(FleetCommand::Config)),
        "telegram" => Ok(Some(FleetCommand::Telegram)),
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
        "daemon" => {
            match arg1 {
                "start" => Ok(Some(FleetCommand::DaemonStart)),
                "stop" => Ok(Some(FleetCommand::DaemonStop)),
                "init" => Ok(Some(FleetCommand::DaemonInit)),
                "" => Err("usage: daemon start|stop|init".into()),
                other => Err(format!("unknown daemon subcommand: {other}. Use: start, stop, init")),
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
        "logs" => Ok(Some(FleetCommand::Logs)),
        "log" => Ok(Some(FleetCommand::Log)),
        "pending" => {
            if arg1.is_empty() {
                Err("usage: pending <agent>".into())
            } else {
                Ok(Some(FleetCommand::Pending { agent: arg1.into() }))
            }
        }
        "wrap" => {
            if arg1.is_empty() {
                Err("usage: wrap <command> [args...]".into())
            } else {
                let full_cmd = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Ok(Some(FleetCommand::Wrap { cmd: full_cmd }))
            }
        }
        "run" => {
            if arg1.is_empty() {
                Err("usage: run <command> [args...]".into())
            } else {
                let full_cmd = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Ok(Some(FleetCommand::Run { cmd: full_cmd }))
            }
        }
        "pilot" => {
            if arg1.is_empty() {
                Err("usage: pilot <command> [args...]".into())
            } else {
                let full_cmd = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Ok(Some(FleetCommand::Pilot { cmd: full_cmd }))
            }
        }
        "policy" => Ok(Some(FleetCommand::Policy)),
        "report" => Ok(Some(FleetCommand::Report)),
        "list" => Ok(Some(FleetCommand::List)),
        "hook" => Ok(Some(FleetCommand::Hook)),
        "use" => {
            let name = if arg1.is_empty() { None } else { Some(arg1.into()) };
            Ok(Some(FleetCommand::Use { name }))
        }
        "watch" => Ok(Some(FleetCommand::Watch)),
        "diff" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: diff <session1> <session2>".into())
            } else {
                Ok(Some(FleetCommand::Diff {
                    session1: arg1.into(),
                    session2: arg2.into(),
                }))
            }
        }
        "alerts" => Ok(Some(FleetCommand::Alerts)),
        "setup" => Ok(Some(FleetCommand::Setup)),
        "init" => Ok(Some(FleetCommand::Init)),
        "goal" => {
            let text = if arg1.is_empty() { None } else {
                let full = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Some(full)
            };
            Ok(Some(FleetCommand::Goal { text }))
        }
        "context" => {
            if arg1.is_empty() {
                Err("usage: context <agent> [role|goal|context <value>]".into())
            } else if arg2.is_empty() {
                // View mode: :context <agent>
                Ok(Some(FleetCommand::Context { agent: arg1.into(), field: None, value: None }))
            } else {
                // Set mode: :context <agent> <field> <value>
                // arg2 contains "field value..." since we did splitn(3, ' ')
                let (field, value) = match arg2.split_once(' ') {
                    Some((f, v)) => (Some(f.to_string()), Some(v.to_string())),
                    None => {
                        return Err("usage: context <agent> <field> <value>".into());
                    }
                };
                Ok(Some(FleetCommand::Context { agent: arg1.into(), field, value }))
            }
        }
        _ => Err(format!("unknown command: {cmd}. Type :help for available commands.")),
    }
}

/// Subcommands for `:daemon`.
const DAEMON_SUBCOMMANDS: &[&str] = &["init", "start", "stop"];

/// Complete the current command buffer, returning possible completions.
///
/// - If the buffer has no space, complete command names.
/// - If the command is `daemon`, complete with daemon subcommands.
/// - If the command takes an agent name, complete agent names.
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
        let mut parts = trimmed.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let sub_prefix = parts.next().unwrap_or("").trim();

        // Complete daemon subcommands
        if cmd == "daemon" {
            return DAEMON_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub_prefix))
                .map(|s| s.to_string())
                .collect();
        }

        // Complete agent name for commands that take one
        if !AGENT_COMMANDS.contains(&cmd) {
            return Vec::new();
        }

        agent_names
            .iter()
            .filter(|name| name.starts_with(sub_prefix))
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
    ":add                     Add a new agent\n\
     :alerts                  Show alert rules\n\
     :approve <agent>         Approve first pending prompt\n\
     :config                  Edit daemon.toml in $EDITOR\n\
     :context <agent>         View agent context\n\
     :context <a> <f> <val>   Set context field (role/goal/context)\n\
     :daemon init             Create daemon.toml\n\
     :daemon start            Start daemon in background\n\
     :daemon stop             Stop running daemon\n\
     :deny <agent>            Deny first pending prompt\n\
     :diff <s1> <s2>          Compare two audit sessions\n\
     :follow <agent>          Drill into agent output\n\
     :goal                    View fleet goal\n\
     :goal <text>             Set fleet goal\n\
     :help                    Show this help\n\
     :hook                    Install aegis hooks (CWD)\n\
     :init                    Create project aegis config\n\
     :list                    List all aegis configs\n\
     :log                     Recent audit entries\n\
     :logs                    Daemon log output\n\
     :monitor                 Open monitor in new terminal\n\
     :nudge <agent> [msg]     Nudge stalled agent\n\
     :pending <agent>         Show pending prompts\n\
     :pilot <cmd...>          Supervised agent in terminal\n\
     :policy                  Show policy info\n\
     :pop <agent>             Open agent in new terminal\n\
     :quit                    Quit TUI\n\
     :remove <agent>          Remove agent from config\n\
     :report                  Compliance report\n\
     :restart <agent>         Restart agent\n\
     :run <cmd...>            Run sandboxed in terminal\n\
     :send <agent> <text>     Send text to agent stdin\n\
     :setup                   Verify system requirements\n\
     :start <agent>           Start agent\n\
     :status                  Daemon status summary\n\
     :stop <agent>            Stop agent\n\
     :telegram                Show Telegram config status\n\
     :use [name]              Switch active config\n\
     :watch                   Watch directory for changes\n\
     :wrap <cmd...>           Wrap command in terminal"
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
    fn parse_remove() {
        assert_eq!(
            parse("remove claude-1").unwrap(),
            Some(FleetCommand::Remove { agent: "claude-1".into() })
        );
    }

    #[test]
    fn parse_remove_missing_agent() {
        assert!(parse("remove").is_err());
    }

    #[test]
    fn parse_config() {
        assert_eq!(parse("config").unwrap(), Some(FleetCommand::Config));
    }

    #[test]
    fn parse_telegram() {
        assert_eq!(parse("telegram").unwrap(), Some(FleetCommand::Telegram));
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
        assert!(help_text().contains(":wrap"));
        assert!(help_text().contains(":pilot"));
    }

    #[test]
    fn parse_logs() {
        assert_eq!(parse("logs").unwrap(), Some(FleetCommand::Logs));
    }

    #[test]
    fn parse_log() {
        assert_eq!(parse("log").unwrap(), Some(FleetCommand::Log));
    }

    #[test]
    fn parse_pending() {
        assert_eq!(
            parse("pending claude-1").unwrap(),
            Some(FleetCommand::Pending { agent: "claude-1".into() })
        );
    }

    #[test]
    fn parse_pending_missing_agent() {
        assert!(parse("pending").is_err());
    }

    #[test]
    fn parse_wrap() {
        assert_eq!(
            parse("wrap claude --help").unwrap(),
            Some(FleetCommand::Wrap { cmd: "claude --help".into() })
        );
    }

    #[test]
    fn parse_wrap_single_arg() {
        assert_eq!(
            parse("wrap claude").unwrap(),
            Some(FleetCommand::Wrap { cmd: "claude".into() })
        );
    }

    #[test]
    fn parse_wrap_missing() {
        assert!(parse("wrap").is_err());
    }

    #[test]
    fn parse_run_cmd() {
        assert_eq!(
            parse("run echo hello world").unwrap(),
            Some(FleetCommand::Run { cmd: "echo hello world".into() })
        );
    }

    #[test]
    fn parse_run_missing() {
        assert!(parse("run").is_err());
    }

    #[test]
    fn parse_pilot_cmd() {
        assert_eq!(
            parse("pilot claude").unwrap(),
            Some(FleetCommand::Pilot { cmd: "claude".into() })
        );
    }

    #[test]
    fn parse_pilot_missing() {
        assert!(parse("pilot").is_err());
    }

    #[test]
    fn parse_policy() {
        assert_eq!(parse("policy").unwrap(), Some(FleetCommand::Policy));
    }

    #[test]
    fn parse_report() {
        assert_eq!(parse("report").unwrap(), Some(FleetCommand::Report));
    }

    #[test]
    fn parse_list_configs() {
        assert_eq!(parse("list").unwrap(), Some(FleetCommand::List));
    }

    #[test]
    fn parse_hook() {
        assert_eq!(parse("hook").unwrap(), Some(FleetCommand::Hook));
    }

    #[test]
    fn parse_use_with_name() {
        assert_eq!(
            parse("use myconfig").unwrap(),
            Some(FleetCommand::Use { name: Some("myconfig".into()) })
        );
    }

    #[test]
    fn parse_use_no_name() {
        assert_eq!(
            parse("use").unwrap(),
            Some(FleetCommand::Use { name: None })
        );
    }

    #[test]
    fn parse_watch_cmd() {
        assert_eq!(parse("watch").unwrap(), Some(FleetCommand::Watch));
    }

    #[test]
    fn parse_diff_sessions() {
        assert_eq!(
            parse("diff abc123 def456").unwrap(),
            Some(FleetCommand::Diff {
                session1: "abc123".into(),
                session2: "def456".into(),
            })
        );
    }

    #[test]
    fn parse_diff_missing_second() {
        assert!(parse("diff abc123").is_err());
    }

    #[test]
    fn parse_diff_missing_both() {
        assert!(parse("diff").is_err());
    }

    #[test]
    fn parse_alerts_cmd() {
        assert_eq!(parse("alerts").unwrap(), Some(FleetCommand::Alerts));
    }

    #[test]
    fn completions_new_commands() {
        let agents = vec![];
        let c = completions("lo", &agents);
        assert!(c.contains(&"log".to_string()));
        assert!(c.contains(&"logs".to_string()));
    }

    #[test]
    fn completions_pending_agent() {
        let agents = vec!["claude-1".to_string(), "codex-1".to_string()];
        let c = completions("pending cl", &agents);
        assert_eq!(c, vec!["claude-1"]);
    }

    #[test]
    fn parse_daemon_start() {
        assert_eq!(
            parse("daemon start").unwrap(),
            Some(FleetCommand::DaemonStart)
        );
    }

    #[test]
    fn parse_daemon_stop() {
        assert_eq!(
            parse("daemon stop").unwrap(),
            Some(FleetCommand::DaemonStop)
        );
    }

    #[test]
    fn parse_daemon_init() {
        assert_eq!(
            parse("daemon init").unwrap(),
            Some(FleetCommand::DaemonInit)
        );
    }

    #[test]
    fn parse_daemon_missing_sub() {
        assert!(parse("daemon").is_err());
    }

    #[test]
    fn parse_daemon_unknown_sub() {
        assert!(parse("daemon bogus").is_err());
    }

    #[test]
    fn completions_daemon_subcommands() {
        let agents = vec![];
        let c = completions("daemon ", &agents);
        assert!(c.contains(&"init".to_string()));
        assert!(c.contains(&"start".to_string()));
        assert!(c.contains(&"stop".to_string()));
    }

    #[test]
    fn completions_daemon_prefix() {
        let agents = vec![];
        let c = completions("daemon st", &agents);
        assert_eq!(c, vec!["start", "stop"]);
    }

    #[test]
    fn completions_daemon_in_command_list() {
        let agents = vec![];
        let c = completions("da", &agents);
        assert!(c.contains(&"daemon".to_string()));
    }
}
