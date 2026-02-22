//! Command bar: vim-style `:` mode for fleet control.
//!
//! Parses command strings into `FleetCommand` variants and provides
//! tab completion for command names and agent names.

/// A parsed fleet command from the `:` command bar.
#[derive(Debug, Clone, PartialEq)]
pub enum FleetCommand {
    /// Open the add-agent wizard.
    Add,
    /// Spawn a constrained subagent from an orchestrator/subagent parent.
    Subagent {
        parent: String,
        name: Option<String>,
    },
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
    /// List active session keys.
    SessionList,
    /// Fetch recent output for a session key.
    SessionHistory {
        session_key: String,
        lines: Option<usize>,
    },
    /// Send text to a session key.
    SessionSend { session_key: String, text: String },
    /// Approve the first pending prompt for an agent.
    Approve { agent: String },
    /// Deny the first pending prompt for an agent.
    Deny { agent: String },
    /// Nudge a stalled agent with optional message.
    Nudge {
        agent: String,
        message: Option<String>,
    },
    /// Drill into an agent's output (switch to detail view).
    Follow { agent: String },
    /// Open orchestrator chat view, or a specific agent detail view.
    Chat { agent: Option<String> },
    /// Pop an agent's output into a new terminal window.
    Pop { agent: String },
    /// Open the monitor TUI in a new terminal window.
    Monitor,
    /// Open the web dashboard in a browser.
    Dashboard,
    /// Show daemon status summary.
    Status,
    /// Open daemon config in $EDITOR in a new terminal window.
    Config,
    /// Read a config value using dot-notation.
    ConfigGet { key: String },
    /// Write a config value using dot-notation to workspace config.
    ConfigSet { key: String, value: String },
    /// Show all effective config key-value pairs.
    ConfigList,
    /// Show which config files are active and their priority.
    ConfigLayers,
    /// Show Telegram configuration status.
    Telegram,
    /// Run Telegram setup wizard in new terminal.
    TelegramSetup,
    /// Disable Telegram notifications.
    TelegramDisable,
    /// Show help for all commands.
    Help,
    /// Quit the TUI.
    Quit,
    /// Show daemon logs in a new terminal.
    Logs,
    /// List pending prompts for an agent.
    Pending { agent: String },
    /// Show runtime capability/mediation profile for an agent.
    Capabilities { agent: String },
    /// Show secure-runtime status from internal matrix.
    ParityStatus,
    /// Show latest secure-runtime delta impact.
    ParityDiff,
    /// Verify secure-runtime controls and fail-closed gates.
    ParityVerify,
    /// Execute a computer-use tool action from JSON payload.
    Tool { agent: String, action_json: String },
    /// Execute a short computer-use tool batch from JSON payload.
    ToolBatch {
        agent: String,
        actions_json: String,
        max_actions: Option<u8>,
    },
    /// Start a capture session for an agent.
    CaptureStart {
        agent: String,
        target_fps: Option<u16>,
    },
    /// Stop the active capture session for an agent.
    CaptureStop { agent: String, session_id: String },
    /// Stop a managed browser profile for an agent.
    BrowserProfileStop { agent: String, session_id: String },
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
    Watch { dir: Option<String> },
    /// Compare two audit sessions.
    Diff { session1: String, session2: String },
    /// Show alert rules.
    Alerts,
    /// View or set the fleet-wide goal.
    Goal { text: Option<String> },
    /// View or set agent context fields (role, goal, context).
    Context {
        agent: String,
        field: Option<String>,
        value: Option<String>,
    },
    /// Open the context editor for an agent field.
    ContextEdit { agent: String, field: String },
    /// Start the daemon in the background.
    DaemonStart,
    /// Stop the running daemon.
    DaemonStop,
    /// Create daemon.toml if it doesn't exist.
    DaemonInit,
    /// Reload daemon configuration from daemon.toml.
    DaemonReload,
    /// Show daemon status in the command result bar.
    DaemonStatus,
    /// Restart the daemon (stop + start).
    DaemonRestart,
    /// Run system checks (verify sandbox, tools, etc.).
    Setup,
    /// Diagnose configuration issues and suggest fixes.
    Doctor { fix: bool },
    /// Create an aegis project config (init wizard).
    Init,
    /// Enable an agent slot (allow starting/restarting).
    Enable { agent: String },
    /// Disable an agent slot (stop and prevent restart).
    Disable { agent: String },
    /// Install launchd plist for daemon auto-start.
    DaemonInstall,
    /// Uninstall launchd plist.
    DaemonUninstall,
    /// List recent audit sessions.
    Sessions,
    /// List sessions with filters (sender, channel, resumable).
    SessionsFiltered {
        sender: Option<String>,
        channel: Option<String>,
        resumable: bool,
    },
    /// Show a conversation chain for a session group.
    SessionChain { group_id: String },
    /// Resume a previous audit session for an agent.
    SessionResumeAudit { agent: String, session_id: String },
    /// Inspect a session with full details, entry counts, and child links.
    SessionInspect { session_id: String },
    /// Reset a session: clear context snapshot and mark non-resumable.
    SessionReset { session_id: String },
    /// Delete a session and all its audit entries (destructive).
    SessionDelete { session_id: String, confirm: bool },
    /// Fork a session, creating a new conversation branch.
    SessionFork { session_id: String },
    /// Display the session tree from a root session.
    SessionTree { session_id: String },
    /// Verify audit hash chain integrity.
    Verify,
    /// Export audit entries in structured format.
    Export { format: Option<String> },
    /// Show orchestrator overview (bulk fleet status for review).
    OrchestratorStatus,
    /// Show parity matrix status from features.yaml (standalone, no daemon).
    MatrixStatus,
    /// Show parity matrix diff from features.yaml (standalone, no daemon).
    MatrixDiff,
    /// Verify parity matrix from features.yaml (standalone, no daemon).
    MatrixVerify,
    /// Suspend a running agent session (SIGSTOP).
    Suspend { agent: String },
    /// Resume a suspended agent session (SIGCONT).
    Resume { agent: String },
    /// Terminate an agent session permanently.
    Terminate { agent: String },
    /// List configured model/provider auth profiles.
    AuthList,
    /// Add a provider auth profile.
    AuthAdd {
        provider: String,
        method: Option<String>,
    },
    /// Login a provider auth profile (OAuth/setup-token/API key flow).
    AuthLogin {
        provider: String,
        method: Option<String>,
    },
    /// Test provider auth profile readiness.
    AuthTest { target: Option<String> },
    /// Log out a provider: remove profile and stored OAuth tokens.
    AuthLogout { provider: String },
    /// Show status of all auth profiles and stored OAuth tokens.
    AuthStatus,
    /// Manually refresh an OAuth token for a provider.
    AuthRefresh { provider: String },
    /// Add a command alias.
    AliasAdd {
        alias: String,
        command: String,
        args: Vec<String>,
    },
    /// Remove a command alias.
    AliasRemove { alias: String },
    /// List all command aliases.
    AliasList,
    /// Add a scheduled auto-reply.
    ScheduleAdd {
        name: String,
        schedule: String,
        template: String,
    },
    /// Remove a scheduled auto-reply.
    ScheduleRemove { name: String },
    /// List all scheduled auto-replies.
    ScheduleList,
    /// Manually trigger a scheduled auto-reply.
    ScheduleTrigger { name: String },
    /// List jobs, optionally filtered by agent.
    Jobs { agent: Option<String> },
    /// Create a job for an agent.
    JobCreate { agent: String, description: String },
    /// Cancel a job by ID.
    JobCancel { id: String },
    /// Get the status of a job by ID.
    JobStatusCmd { id: String },
    /// List all registered push subscriptions.
    PushList,
    /// Remove a push subscription by ID.
    PushRemove { id: String },
    /// Send a test push notification to a subscription.
    PushTest { id: String },
    /// Create a new poll.
    PollCreate {
        question: String,
        options: Vec<String>,
    },
    /// Close a poll by ID.
    PollClose { id: String },
    /// Get results for a poll by ID.
    PollResultsCmd { id: String },
    /// List all active polls.
    PollList,
    /// Show command queue metrics (depth, active, completed, failed, DLQ).
    QueueStatusCmd,
    /// Flush all pending commands from the command queue.
    QueueFlush,
    /// Inspect dead letter queue contents.
    QueueInspect,
    /// Fetch a URL and display its content (title, text, word count).
    Fetch { url: String },
    /// List all execution lanes with utilization.
    Lanes,
    /// List installed skills.
    SkillsList,
    /// Search the skill registry.
    SkillsSearch { query: String },
    /// Install a skill from the registry.
    SkillsInstall { name: String },
    /// Update a skill (or all skills).
    SkillsUpdate { name: Option<String> },
    /// Uninstall a skill.
    SkillsUninstall { name: String },
    /// Show detailed info about a skill.
    SkillsInfo { name: String },
    /// Reload a specific skill or all skills.
    SkillsReload { name: Option<String> },
    /// List all slash commands registered by skills.
    SkillsCommands,
}

/// All known command names for completion.
const COMMAND_NAMES: &[&str] = &[
    "agent",
    "add",
    "alerts",
    "alias",
    "auth",
    "approve",
    "capture-start",
    "capture-stop",
    "browser-profile-stop",
    "capabilities",
    "chat",
    "config",
    "context",
    "daemon",
    "deny",
    "diff",
    "disable",
    "doctor",
    "enable",
    "export",
    "fetch",
    "follow",
    "goal",
    "help",
    "hook",
    "init",
    "job",
    "jobs",
    "lanes",
    "list",
    "log",
    "logs",
    "matrix",
    "monitor",
    "dashboard",
    "nudge",
    "orch",
    "compat",
    "pending",
    "pilot",
    "policy",
    "poll",
    "polls",
    "pop",
    "push",
    "q",
    "queue",
    "quit",
    "remove",
    "report",
    "restart",
    "resume",
    "run",
    "schedule",
    "send",
    "session",
    "session-chain",
    "session-delete",
    "session-fork",
    "session-inspect",
    "session-reset",
    "session-resume",
    "session-tree",
    "sessions",
    "setup",
    "skills",
    "start",
    "status",
    "stop",
    "subagent",
    "suspend",
    "terminate",
    "tool",
    "tool-batch",
    "telegram",
    "use",
    "verify",
    "watch",
    "wrap",
];

/// Commands that take an agent name as the second token.
const AGENT_COMMANDS: &[&str] = &[
    "agent",
    "approve",
    "capture-start",
    "capture-stop",
    "browser-profile-stop",
    "capabilities",
    "chat",
    "context",
    "deny",
    "disable",
    "enable",
    "follow",
    "nudge",
    "pending",
    "pop",
    "remove",
    "restart",
    "resume",
    "send",
    "session-resume",
    "start",
    "stop",
    "subagent",
    "suspend",
    "terminate",
    "tool-batch",
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
        "agent" => {
            let rest = input.strip_prefix("agent").unwrap_or("").trim();
            if rest.is_empty() {
                return Err("usage: agent <agent> [role|goal|context|task [value]]".into());
            }
            let mut agent_parts = rest.splitn(3, ' ');
            let first = agent_parts.next().unwrap_or("").trim();
            let second = agent_parts.next().unwrap_or("").trim();
            let third = agent_parts.next().unwrap_or("").trim();

            if first == "set" {
                if second.is_empty() {
                    return Err("usage: agent set <agent> <field> <value>".into());
                }
                if third.is_empty() {
                    return Err("usage: agent set <agent> <field> <value>".into());
                }
                match third.split_once(' ') {
                    Some((f, v)) => Ok(Some(FleetCommand::Context {
                        agent: second.into(),
                        field: Some(f.to_string()),
                        value: Some(v.to_string()),
                    })),
                    None => Ok(Some(FleetCommand::Context {
                        agent: second.into(),
                        field: Some(third.to_string()),
                        value: Some(String::new()),
                    })),
                }
            } else if first == "edit" {
                if second.is_empty() {
                    return Err("usage: agent edit <agent> <field>".into());
                }
                if third.is_empty() {
                    return Err("usage: agent edit <agent> <field>".into());
                }
                let field = third.split_whitespace().next().unwrap_or("").to_string();
                Ok(Some(FleetCommand::ContextEdit {
                    agent: second.into(),
                    field,
                }))
            } else if second.is_empty() {
                Ok(Some(FleetCommand::Context {
                    agent: first.into(),
                    field: None,
                    value: None,
                }))
            } else {
                let combined = if third.is_empty() {
                    second.to_string()
                } else {
                    format!("{second} {third}")
                };
                match combined.trim().split_once(' ') {
                    Some((f, v)) => Ok(Some(FleetCommand::Context {
                        agent: first.into(),
                        field: Some(f.to_string()),
                        value: Some(v.to_string()),
                    })),
                    None => Ok(Some(FleetCommand::Context {
                        agent: first.into(),
                        field: Some(second.to_string()),
                        value: Some(String::new()),
                    })),
                }
            }
        }
        "alias" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::AliasList)),
            "add" => {
                if arg2.is_empty() {
                    return Err("usage: alias add <alias> <command> [args...]".into());
                }
                // arg2 = "<alias> <command> [args...]"
                let mut parts = arg2.splitn(2, ' ');
                let alias_name = parts.next().unwrap_or("").trim().to_string();
                let rest = parts.next().unwrap_or("").trim();
                if alias_name.is_empty() || rest.is_empty() {
                    return Err("usage: alias add <alias> <command> [args...]".into());
                }
                // rest = "<command> [args...]"
                let mut cmd_parts = rest.splitn(2, ' ');
                let command = cmd_parts.next().unwrap_or("").trim().to_string();
                let args_str = cmd_parts.next().unwrap_or("").trim();
                let args: Vec<String> = if args_str.is_empty() {
                    vec![]
                } else {
                    args_str.split_whitespace().map(String::from).collect()
                };
                Ok(Some(FleetCommand::AliasAdd {
                    alias: alias_name,
                    command,
                    args,
                }))
            }
            "remove" => {
                if arg2.is_empty() {
                    return Err("usage: alias remove <alias>".into());
                }
                let alias_name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if alias_name.is_empty() {
                    return Err("usage: alias remove <alias>".into());
                }
                Ok(Some(FleetCommand::AliasRemove {
                    alias: alias_name,
                }))
            }
            other => Err(format!(
                "unknown alias subcommand: {other}. Use: add, remove, list"
            )),
        },
        "add" => Ok(Some(FleetCommand::Add)),
        "subagent" => {
            if arg1.is_empty() {
                Err("usage: subagent <parent-agent> [child-name]".into())
            } else if arg2.is_empty() {
                Ok(Some(FleetCommand::Subagent {
                    parent: arg1.into(),
                    name: None,
                }))
            } else {
                let child = arg2.split_whitespace().next().unwrap_or("").trim();
                if child.is_empty() {
                    return Err("usage: subagent <parent-agent> [child-name]".into());
                }
                Ok(Some(FleetCommand::Subagent {
                    parent: arg1.into(),
                    name: Some(child.to_string()),
                }))
            }
        }
        "remove" => {
            if arg1.is_empty() {
                Err("usage: remove <agent>".into())
            } else {
                Ok(Some(FleetCommand::Remove { agent: arg1.into() }))
            }
        }
        "config" => match arg1 {
            "" => Ok(Some(FleetCommand::Config)),
            "get" => {
                if arg2.is_empty() {
                    return Err("usage: config get <key>  (e.g., config get pilot.stall.timeout_secs)".into());
                }
                let key = arg2.split_whitespace().next().unwrap_or("").to_string();
                Ok(Some(FleetCommand::ConfigGet { key }))
            }
            "set" => {
                if arg2.is_empty() {
                    return Err("usage: config set <key> <value>  (e.g., config set name myagent)".into());
                }
                match arg2.split_once(' ') {
                    Some((key, value)) => Ok(Some(FleetCommand::ConfigSet {
                        key: key.to_string(),
                        value: value.to_string(),
                    })),
                    None => Err("usage: config set <key> <value>".into()),
                }
            }
            "list" => Ok(Some(FleetCommand::ConfigList)),
            "layers" => Ok(Some(FleetCommand::ConfigLayers)),
            other => Err(format!(
                "unknown config subcommand: {other}. Try: get, set, list, layers"
            )),
        },
        "telegram" => match arg1 {
            "" => Ok(Some(FleetCommand::Telegram)),
            "setup" => Ok(Some(FleetCommand::TelegramSetup)),
            "disable" => Ok(Some(FleetCommand::TelegramDisable)),
            other => Err(format!("unknown telegram subcommand: {other}. Try: setup, disable")),
        },
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
        "suspend" => {
            if arg1.is_empty() {
                Err("usage: suspend <agent>".into())
            } else {
                Ok(Some(FleetCommand::Suspend { agent: arg1.into() }))
            }
        }
        "resume" => {
            if arg1.is_empty() {
                Err("usage: resume <agent>".into())
            } else {
                Ok(Some(FleetCommand::Resume { agent: arg1.into() }))
            }
        }
        "terminate" => {
            if arg1.is_empty() {
                Err("usage: terminate <agent>".into())
            } else {
                Ok(Some(FleetCommand::Terminate { agent: arg1.into() }))
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
        "session" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::SessionList)),
            "history" => {
                if arg2.is_empty() {
                    return Err("usage: session history <session_key> [lines]".into());
                }
                let mut parts = arg2.splitn(2, ' ');
                let session_key = parts.next().unwrap_or("").trim();
                let lines = parts
                    .next()
                    .and_then(|v| v.trim().parse::<usize>().ok());
                if session_key.is_empty() {
                    Err("usage: session history <session_key> [lines]".into())
                } else {
                    Ok(Some(FleetCommand::SessionHistory {
                        session_key: session_key.to_string(),
                        lines,
                    }))
                }
            }
            "send" => {
                if arg2.is_empty() {
                    return Err("usage: session send <session_key> <text>".into());
                }
                let mut parts = arg2.splitn(2, ' ');
                let session_key = parts.next().unwrap_or("").trim();
                let text = parts.next().unwrap_or("").trim();
                if session_key.is_empty() || text.is_empty() {
                    Err("usage: session send <session_key> <text>".into())
                } else {
                    Ok(Some(FleetCommand::SessionSend {
                        session_key: session_key.to_string(),
                        text: text.to_string(),
                    }))
                }
            }
            other => Err(format!(
                "unknown session subcommand: {other}. Use: list, history, send"
            )),
        },
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
                "reload" => Ok(Some(FleetCommand::DaemonReload)),
                "restart" => Ok(Some(FleetCommand::DaemonRestart)),
                "status" => Ok(Some(FleetCommand::DaemonStatus)),
                "install" => Ok(Some(FleetCommand::DaemonInstall)),
                "uninstall" => Ok(Some(FleetCommand::DaemonUninstall)),
                "" => Err("usage: daemon start|stop|init|reload|restart|status|install|uninstall".into()),
                other => Err(format!("unknown daemon subcommand: {other}. Use: start, stop, init, reload, restart, status, install, uninstall")),
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
        "chat" => {
            if arg1.is_empty() {
                Ok(Some(FleetCommand::Chat { agent: None }))
            } else {
                Ok(Some(FleetCommand::Chat {
                    agent: Some(arg1.into()),
                }))
            }
        }
        "auth" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::AuthList)),
            "add" => {
                if arg2.is_empty() {
                    return Err("usage: auth add <provider> [oauth|api-key|setup-token]".into());
                }
                let mut parts = arg2.splitn(2, ' ');
                let provider = parts.next().unwrap_or("").trim().to_string();
                if provider.is_empty() {
                    return Err("usage: auth add <provider> [oauth|api-key|setup-token]".into());
                }
                let method = parts.next().map(|s| s.trim().to_string());
                Ok(Some(FleetCommand::AuthAdd { provider, method }))
            }
            "login" => {
                if arg2.is_empty() {
                    return Err(
                        "usage: auth login <provider> [oauth|api-key|setup-token]".into(),
                    );
                }
                let mut parts = arg2.splitn(2, ' ');
                let provider = parts.next().unwrap_or("").trim().to_string();
                if provider.is_empty() {
                    return Err(
                        "usage: auth login <provider> [oauth|api-key|setup-token]".into(),
                    );
                }
                let method = parts.next().map(|s| s.trim().to_string());
                Ok(Some(FleetCommand::AuthLogin { provider, method }))
            }
            "test" => {
                let target = if arg2.is_empty() {
                    None
                } else {
                    Some(arg2.to_string())
                };
                Ok(Some(FleetCommand::AuthTest { target }))
            }
            "logout" => {
                if arg2.is_empty() {
                    return Err("usage: auth logout <provider>".into());
                }
                Ok(Some(FleetCommand::AuthLogout {
                    provider: arg2.trim().to_string(),
                }))
            }
            "status" => Ok(Some(FleetCommand::AuthStatus)),
            "refresh" => {
                if arg2.is_empty() {
                    return Err("usage: auth refresh <provider>".into());
                }
                Ok(Some(FleetCommand::AuthRefresh {
                    provider: arg2.trim().to_string(),
                }))
            }
            other => Err(format!(
                "unknown auth subcommand: {other}. Use: list, add, login, logout, test, status, refresh"
            )),
        },
        "compat" => match arg1 {
            "" | "status" => Ok(Some(FleetCommand::ParityStatus)),
            "diff" => Ok(Some(FleetCommand::ParityDiff)),
            "verify" => Ok(Some(FleetCommand::ParityVerify)),
            other => Err(format!(
                "unknown compat subcommand: {other}. Use: status, diff, verify"
            )),
        },
        "parity" => match arg1 {
            "" | "status" => Ok(Some(FleetCommand::ParityStatus)),
            "diff" => Ok(Some(FleetCommand::ParityDiff)),
            "verify" => Ok(Some(FleetCommand::ParityVerify)),
            other => Err(format!(
                "unknown compat subcommand: {other}. Use: status, diff, verify"
            )),
        },
        "compat-status" => Ok(Some(FleetCommand::ParityStatus)),
        "compat-diff" => Ok(Some(FleetCommand::ParityDiff)),
        "compat-verify" => Ok(Some(FleetCommand::ParityVerify)),
        "parity-status" => Ok(Some(FleetCommand::ParityStatus)),
        "parity-diff" => Ok(Some(FleetCommand::ParityDiff)),
        "parity-verify" => Ok(Some(FleetCommand::ParityVerify)),
        "matrix" => match arg1 {
            "" | "status" => Ok(Some(FleetCommand::MatrixStatus)),
            "diff" => Ok(Some(FleetCommand::MatrixDiff)),
            "verify" => Ok(Some(FleetCommand::MatrixVerify)),
            other => Err(format!(
                "unknown matrix subcommand: {other}. Use: status, diff, verify"
            )),
        },
        "matrix-status" => Ok(Some(FleetCommand::MatrixStatus)),
        "matrix-diff" => Ok(Some(FleetCommand::MatrixDiff)),
        "matrix-verify" => Ok(Some(FleetCommand::MatrixVerify)),
        "pop" => {
            if arg1.is_empty() {
                Err("usage: pop <agent>".into())
            } else {
                Ok(Some(FleetCommand::Pop { agent: arg1.into() }))
            }
        }
        "monitor" => Ok(Some(FleetCommand::Monitor)),
        "dashboard" => Ok(Some(FleetCommand::Dashboard)),
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
        "capabilities" => {
            if arg1.is_empty() {
                Err("usage: capabilities <agent>".into())
            } else {
                Ok(Some(FleetCommand::Capabilities { agent: arg1.into() }))
            }
        }
        "tool" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: tool <agent> <action-json>".into())
            } else {
                Ok(Some(FleetCommand::Tool {
                    agent: arg1.into(),
                    action_json: arg2.into(),
                }))
            }
        }
        "tool-batch" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: tool-batch <agent> <actions-json> [max-actions]".into())
            } else {
                let mut split = arg2.splitn(2, ' ');
                let actions_json = split.next().unwrap_or("").to_string();
                let max_actions = split
                    .next()
                    .and_then(|s| s.trim().parse::<u8>().ok())
                    .filter(|n| *n > 0);
                Ok(Some(FleetCommand::ToolBatch {
                    agent: arg1.into(),
                    actions_json,
                    max_actions,
                }))
            }
        }
        "capture-start" => {
            if arg1.is_empty() {
                Err("usage: capture-start <agent> [target-fps]".into())
            } else if arg2.is_empty() {
                Ok(Some(FleetCommand::CaptureStart {
                    agent: arg1.into(),
                    target_fps: None,
                }))
            } else {
                let fps = arg2
                    .parse::<u16>()
                    .map_err(|_| "capture-start target-fps must be a number".to_string())?;
                Ok(Some(FleetCommand::CaptureStart {
                    agent: arg1.into(),
                    target_fps: Some(fps),
                }))
            }
        }
        "capture-stop" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: capture-stop <agent> <session-id>".into())
            } else {
                Ok(Some(FleetCommand::CaptureStop {
                    agent: arg1.into(),
                    session_id: arg2.into(),
                }))
            }
        }
        "browser-profile-stop" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: browser-profile-stop <agent> <session-id>".into())
            } else {
                Ok(Some(FleetCommand::BrowserProfileStop {
                    agent: arg1.into(),
                    session_id: arg2.into(),
                }))
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
        "watch" => {
            let dir = if arg1.is_empty() { None } else { Some(arg1.to_string()) };
            Ok(Some(FleetCommand::Watch { dir }))
        }
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
        "fetch" => {
            if arg1.is_empty() {
                Err("usage: fetch <url>".into())
            } else {
                let full_url = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Ok(Some(FleetCommand::Fetch { url: full_url }))
            }
        }
        "alerts" => Ok(Some(FleetCommand::Alerts)),
        "sessions" => {
            if arg1.is_empty() {
                Ok(Some(FleetCommand::Sessions))
            } else if arg1 == "--resumable" {
                Ok(Some(FleetCommand::SessionsFiltered {
                    sender: None,
                    channel: None,
                    resumable: true,
                }))
            } else if arg1 == "--sender" && !arg2.is_empty() {
                let mut parts = arg2.splitn(2, ' ');
                let sender = parts.next().unwrap_or("").to_string();
                Ok(Some(FleetCommand::SessionsFiltered {
                    sender: Some(sender),
                    channel: None,
                    resumable: false,
                }))
            } else if arg1 == "--channel" && !arg2.is_empty() {
                let mut parts = arg2.splitn(2, ' ');
                let channel = parts.next().unwrap_or("").to_string();
                Ok(Some(FleetCommand::SessionsFiltered {
                    sender: None,
                    channel: Some(channel),
                    resumable: false,
                }))
            } else {
                Ok(Some(FleetCommand::Sessions))
            }
        }
        "session-chain" => {
            if arg1.is_empty() {
                Err("usage: session-chain <group-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionChain {
                    group_id: arg1.into(),
                }))
            }
        }
        "session-resume" => {
            if arg1.is_empty() || arg2.is_empty() {
                Err("usage: session-resume <agent> <session-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionResumeAudit {
                    agent: arg1.into(),
                    session_id: arg2.into(),
                }))
            }
        }
        "session-inspect" => {
            if arg1.is_empty() {
                Err("usage: session-inspect <session-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionInspect {
                    session_id: arg1.into(),
                }))
            }
        }
        "session-reset" => {
            if arg1.is_empty() {
                Err("usage: session-reset <session-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionReset {
                    session_id: arg1.into(),
                }))
            }
        }
        "session-delete" => {
            if arg1.is_empty() {
                Err("usage: session-delete <session-uuid> [--confirm]".into())
            } else {
                let confirm = arg2 == "--confirm";
                Ok(Some(FleetCommand::SessionDelete {
                    session_id: arg1.into(),
                    confirm,
                }))
            }
        }
        "session-fork" => {
            if arg1.is_empty() {
                Err("usage: session-fork <session-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionFork {
                    session_id: arg1.into(),
                }))
            }
        }
        "session-tree" => {
            if arg1.is_empty() {
                Err("usage: session-tree <root-session-uuid>".into())
            } else {
                Ok(Some(FleetCommand::SessionTree {
                    session_id: arg1.into(),
                }))
            }
        }
        "verify" => Ok(Some(FleetCommand::Verify)),
        "export" => {
            let format = if arg1.is_empty() { None } else { Some(arg1.to_string()) };
            Ok(Some(FleetCommand::Export { format }))
        }
        "orch" | "orchestrator" => Ok(Some(FleetCommand::OrchestratorStatus)),
        "setup" => Ok(Some(FleetCommand::Setup)),
        "doctor" => {
            let fix = arg1 == "--fix";
            Ok(Some(FleetCommand::Doctor { fix }))
        }
        "init" => Ok(Some(FleetCommand::Init)),
        "enable" => {
            if arg1.is_empty() {
                Err("usage: enable <agent>".into())
            } else {
                Ok(Some(FleetCommand::Enable { agent: arg1.into() }))
            }
        }
        "disable" => {
            if arg1.is_empty() {
                Err("usage: disable <agent>".into())
            } else {
                Ok(Some(FleetCommand::Disable { agent: arg1.into() }))
            }
        }
        "goal" => {
            let text = if arg1.is_empty() { None } else {
                let full = if arg2.is_empty() { arg1.into() } else { format!("{arg1} {arg2}") };
                Some(full)
            };
            Ok(Some(FleetCommand::Goal { text }))
        }
        "context" => {
            if arg1.is_empty() {
                Err("usage: context <agent> [role|goal|context|task [value]]".into())
            } else if arg2.is_empty() {
                // View mode: :context <agent>
                Ok(Some(FleetCommand::Context { agent: arg1.into(), field: None, value: None }))
            } else {
                // arg2 contains "field [value...]" since we did splitn(3, ' ')
                match arg2.split_once(' ') {
                    Some((f, v)) => {
                        // Set mode: :context <agent> <field> <value>
                        Ok(Some(FleetCommand::Context {
                            agent: arg1.into(),
                            field: Some(f.to_string()),
                            value: Some(v.to_string()),
                        }))
                    }
                    None => {
                        // Clear mode: :context <agent> <field> (no value = clear)
                        Ok(Some(FleetCommand::Context {
                            agent: arg1.into(),
                            field: Some(arg2.to_string()),
                            value: Some(String::new()),
                        }))
                    }
                }
            }
        }
        "jobs" => {
            let agent = if arg1.is_empty() { None } else { Some(arg1.to_string()) };
            Ok(Some(FleetCommand::Jobs { agent }))
        }
        "lanes" => Ok(Some(FleetCommand::Lanes)),
        "job" => match arg1 {
            "create" => {
                if arg2.is_empty() {
                    return Err("usage: job create <agent> <description>".into());
                }
                match arg2.split_once(' ') {
                    Some((agent, desc)) if !agent.is_empty() && !desc.is_empty() => {
                        Ok(Some(FleetCommand::JobCreate {
                            agent: agent.to_string(),
                            description: desc.to_string(),
                        }))
                    }
                    _ => Err("usage: job create <agent> <description>".into()),
                }
            }
            "cancel" => {
                if arg2.is_empty() {
                    return Err("usage: job cancel <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: job cancel <id>".into());
                }
                Ok(Some(FleetCommand::JobCancel { id }))
            }
            "status" => {
                if arg2.is_empty() {
                    return Err("usage: job status <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: job status <id>".into());
                }
                Ok(Some(FleetCommand::JobStatusCmd { id }))
            }
            "" => Err("usage: job create|cancel|status".into()),
            other => Err(format!(
                "unknown job subcommand: {other}. Use: create, cancel, status"
            )),
        },
        "push" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::PushList)),
            "remove" => {
                if arg2.is_empty() {
                    return Err("usage: push remove <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: push remove <id>".into());
                }
                Ok(Some(FleetCommand::PushRemove { id }))
            }
            "test" => {
                if arg2.is_empty() {
                    return Err("usage: push test <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: push test <id>".into());
                }
                Ok(Some(FleetCommand::PushTest { id }))
            }
            other => Err(format!(
                "unknown push subcommand: {other}. Use: list, remove, test"
            )),
        },
        "queue" => match arg1 {
            "" | "status" => Ok(Some(FleetCommand::QueueStatusCmd)),
            "flush" => Ok(Some(FleetCommand::QueueFlush)),
            "inspect" => Ok(Some(FleetCommand::QueueInspect)),
            other => Err(format!(
                "unknown queue subcommand: {other}. Use: status, flush, inspect"
            )),
        },
        "polls" => Ok(Some(FleetCommand::PollList)),
        "poll" => match arg1 {
            "" => Err("usage: poll create|close|results".into()),
            "create" => {
                if arg2.is_empty() {
                    return Err(
                        "usage: poll create \"Question?\" opt1,opt2,opt3".into(),
                    );
                }
                // arg2 = "\"Question?\" opt1,opt2,opt3" or "Question? opt1,opt2,opt3"
                // Try to extract a quoted question first, then fall back to splitting on last space-before-comma-list
                let (question, opts_str) = if let Some(stripped) = arg2.strip_prefix('"') {
                    // Find closing quote
                    match stripped.find('"') {
                        Some(end) => {
                            let q = stripped[..end].to_string();
                            let rest = stripped[end + 1..].trim();
                            (q, rest.to_string())
                        }
                        None => {
                            return Err(
                                "usage: poll create \"Question?\" opt1,opt2,opt3".into(),
                            );
                        }
                    }
                } else {
                    // No quotes: split on last space before a comma-separated list
                    // Heuristic: everything before last whitespace-delimited token containing a comma
                    match arg2.rsplit_once(' ') {
                        Some((q, opts)) if opts.contains(',') => {
                            (q.to_string(), opts.to_string())
                        }
                        _ => {
                            return Err(
                                "usage: poll create \"Question?\" opt1,opt2,opt3".into(),
                            );
                        }
                    }
                };
                if question.is_empty() || opts_str.is_empty() {
                    return Err(
                        "usage: poll create \"Question?\" opt1,opt2,opt3".into(),
                    );
                }
                let options: Vec<String> = opts_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if options.len() < 2 {
                    return Err("poll must have at least 2 comma-separated options".into());
                }
                Ok(Some(FleetCommand::PollCreate { question, options }))
            }
            "close" => {
                if arg2.is_empty() {
                    return Err("usage: poll close <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: poll close <id>".into());
                }
                Ok(Some(FleetCommand::PollClose { id }))
            }
            "results" => {
                if arg2.is_empty() {
                    return Err("usage: poll results <id>".into());
                }
                let id = arg2.split_whitespace().next().unwrap_or("").to_string();
                if id.is_empty() {
                    return Err("usage: poll results <id>".into());
                }
                Ok(Some(FleetCommand::PollResultsCmd { id }))
            }
            "list" => Ok(Some(FleetCommand::PollList)),
            other => Err(format!(
                "unknown poll subcommand: {other}. Use: create, close, results"
            )),
        },
        "schedule" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::ScheduleList)),
            "add" => {
                if arg2.is_empty() {
                    return Err("usage: schedule add <name> <schedule> <template>".into());
                }
                // arg2 = "<name> <schedule> <template>"
                let mut parts = arg2.splitn(3, ' ');
                let name = parts.next().unwrap_or("").trim().to_string();
                let rest = parts.next().unwrap_or("").trim();
                let template_rest = parts.next().unwrap_or("").trim();
                if name.is_empty() || rest.is_empty() {
                    return Err("usage: schedule add <name> <schedule> <template>".into());
                }
                // rest could be a schedule like "daily 09:00" or "every 5m"
                // template_rest is the template (may be empty if schedule consumed it)
                let (schedule, template) = if template_rest.is_empty() {
                    // Only two tokens after name -- schedule is rest, template is default
                    (rest.to_string(), String::new())
                } else {
                    (rest.to_string(), template_rest.to_string())
                };
                if schedule.is_empty() {
                    return Err("usage: schedule add <name> <schedule> <template>".into());
                }
                Ok(Some(FleetCommand::ScheduleAdd {
                    name,
                    schedule,
                    template,
                }))
            }
            "remove" => {
                if arg2.is_empty() {
                    return Err("usage: schedule remove <name>".into());
                }
                let name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if name.is_empty() {
                    return Err("usage: schedule remove <name>".into());
                }
                Ok(Some(FleetCommand::ScheduleRemove { name }))
            }
            "trigger" => {
                if arg2.is_empty() {
                    return Err("usage: schedule trigger <name>".into());
                }
                let name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if name.is_empty() {
                    return Err("usage: schedule trigger <name>".into());
                }
                Ok(Some(FleetCommand::ScheduleTrigger { name }))
            }
            other => Err(format!(
                "unknown schedule subcommand: {other}. Use: add, remove, list, trigger"
            )),
        },
        "skills" => match arg1 {
            "" | "list" => Ok(Some(FleetCommand::SkillsList)),
            "search" => {
                if arg2.is_empty() {
                    return Err("usage: skills search <query>".into());
                }
                Ok(Some(FleetCommand::SkillsSearch {
                    query: arg2.to_string(),
                }))
            }
            "install" => {
                if arg2.is_empty() {
                    return Err("usage: skills install <name>".into());
                }
                let name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if name.is_empty() {
                    return Err("usage: skills install <name>".into());
                }
                Ok(Some(FleetCommand::SkillsInstall { name }))
            }
            "update" => {
                let name = if arg2.is_empty() {
                    None
                } else {
                    Some(arg2.split_whitespace().next().unwrap_or("").to_string())
                };
                Ok(Some(FleetCommand::SkillsUpdate { name }))
            }
            "uninstall" => {
                if arg2.is_empty() {
                    return Err("usage: skills uninstall <name>".into());
                }
                let name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if name.is_empty() {
                    return Err("usage: skills uninstall <name>".into());
                }
                Ok(Some(FleetCommand::SkillsUninstall { name }))
            }
            "info" => {
                if arg2.is_empty() {
                    return Err("usage: skills info <name>".into());
                }
                let name = arg2.split_whitespace().next().unwrap_or("").to_string();
                if name.is_empty() {
                    return Err("usage: skills info <name>".into());
                }
                Ok(Some(FleetCommand::SkillsInfo { name }))
            }
            "reload" => {
                let name = if arg2.is_empty() {
                    None
                } else {
                    Some(arg2.split_whitespace().next().unwrap_or("").to_string())
                };
                Ok(Some(FleetCommand::SkillsReload { name }))
            }
            "commands" => Ok(Some(FleetCommand::SkillsCommands)),
            other => Err(format!(
                "unknown skills subcommand: {other}. Use: list, search, install, update, uninstall, info, reload, commands"
            )),
        },
        _ => Err(format!("unknown command: {cmd}. Type :help for available commands.")),
    }
}

/// Subcommands for `:daemon`.
const DAEMON_SUBCOMMANDS: &[&str] = &[
    "init",
    "install",
    "reload",
    "restart",
    "start",
    "status",
    "stop",
    "uninstall",
];

/// Subcommands for `:telegram`.
const TELEGRAM_SUBCOMMANDS: &[&str] = &["disable", "setup"];
/// Subcommands for `:auth`.
const AUTH_SUBCOMMANDS: &[&str] = &["add", "list", "login", "logout", "refresh", "status", "test"];
const SESSION_SUBCOMMANDS: &[&str] = &["list", "history", "send"];
const COMPAT_SUBCOMMANDS: &[&str] = &["diff", "status", "verify"];
const MATRIX_SUBCOMMANDS: &[&str] = &["diff", "status", "verify"];
/// Subcommands for `:alias`.
const ALIAS_SUBCOMMANDS: &[&str] = &["add", "list", "remove"];
/// Subcommands for `:job`.
const JOB_SUBCOMMANDS: &[&str] = &["cancel", "create", "status"];
/// Subcommands for `:push`.
const PUSH_SUBCOMMANDS: &[&str] = &["list", "remove", "test"];
/// Subcommands for `:queue`.
const QUEUE_SUBCOMMANDS: &[&str] = &["flush", "inspect", "status"];
/// Subcommands for `:poll`.
const POLL_SUBCOMMANDS: &[&str] = &["close", "create", "results"];
/// Subcommands for `:schedule`.
const SCHEDULE_SUBCOMMANDS: &[&str] = &["add", "list", "remove", "trigger"];
/// Subcommands for `:skills`.
const SKILLS_SUBCOMMANDS: &[&str] = &["commands", "info", "install", "list", "reload", "search", "uninstall", "update"];

/// Field names for `:context <agent> <field>`.
const CONTEXT_FIELDS: &[&str] = &["context", "goal", "role", "task"];

/// Complete the current command buffer, returning possible completions.
///
/// - If the buffer has no space, complete command names.
/// - If the command is `daemon`, complete with daemon subcommands.
/// - If the command takes an agent name, complete agent names.
/// - If the command is `context` with an agent already typed, complete field names.
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
        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        let cmd = parts[0];
        let sub = parts.get(1).copied().unwrap_or("");

        if cmd == "agent" {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            let ends_with_space = trimmed.ends_with(' ');
            if tokens.len() == 1 && ends_with_space {
                let mut items = vec!["edit".to_string(), "set".to_string()];
                items.extend(agent_names.iter().cloned());
                return items;
            }
            if tokens.len() == 2 {
                if tokens[1] == "set" {
                    return agent_names.to_vec();
                }
                if tokens[1] == "edit" {
                    if ends_with_space {
                        return agent_names.to_vec();
                    }
                    return Vec::new();
                }
                if ends_with_space {
                    return CONTEXT_FIELDS.iter().map(|f| f.to_string()).collect();
                }
                let mut items = Vec::new();
                if "edit".starts_with(tokens[1]) {
                    items.push("edit".to_string());
                }
                if "set".starts_with(tokens[1]) {
                    items.push("set".to_string());
                }
                items.extend(
                    agent_names
                        .iter()
                        .filter(|name| name.starts_with(tokens[1]))
                        .cloned(),
                );
                return items;
            }
            if tokens.len() == 3 {
                if tokens[1] == "set" {
                    if ends_with_space {
                        return CONTEXT_FIELDS.iter().map(|f| f.to_string()).collect();
                    }
                    return agent_names
                        .iter()
                        .filter(|name| name.starts_with(tokens[2]))
                        .cloned()
                        .collect();
                }
                if tokens[1] == "edit" {
                    if ends_with_space {
                        return CONTEXT_FIELDS.iter().map(|f| f.to_string()).collect();
                    }
                    return agent_names
                        .iter()
                        .filter(|name| name.starts_with(tokens[2]))
                        .cloned()
                        .collect();
                }
                let field_prefix = tokens[2];
                return CONTEXT_FIELDS
                    .iter()
                    .filter(|f| f.starts_with(field_prefix))
                    .map(|f| f.to_string())
                    .collect();
            }
            if tokens.len() == 4 && tokens[1] == "set" {
                let field_prefix = tokens[3];
                return CONTEXT_FIELDS
                    .iter()
                    .filter(|f| f.starts_with(field_prefix))
                    .map(|f| f.to_string())
                    .collect();
            }
            if tokens.len() == 4 && tokens[1] == "edit" {
                let field_prefix = tokens[3];
                return CONTEXT_FIELDS
                    .iter()
                    .filter(|f| f.starts_with(field_prefix))
                    .map(|f| f.to_string())
                    .collect();
            }
        }

        // Complete daemon subcommands
        if cmd == "daemon" {
            return DAEMON_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }

        // Complete telegram subcommands
        if cmd == "telegram" {
            return TELEGRAM_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }

        // Complete auth subcommands
        if cmd == "auth" {
            return AUTH_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "compat" {
            return COMPAT_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "matrix" {
            return MATRIX_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "session" {
            return SESSION_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "alias" {
            return ALIAS_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "job" {
            return JOB_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "jobs" {
            // :jobs [agent] -- complete agent names
            return agent_names
                .iter()
                .filter(|name| name.starts_with(sub))
                .cloned()
                .collect();
        }
        if cmd == "queue" {
            return QUEUE_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "poll" {
            return POLL_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "push" {
            return PUSH_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "schedule" {
            return SCHEDULE_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }
        if cmd == "skills" {
            return SKILLS_SUBCOMMANDS
                .iter()
                .filter(|s| s.starts_with(sub))
                .map(|s| s.to_string())
                .collect();
        }

        // Third token: context field completion
        if cmd == "context" && parts.len() == 3 {
            let field_prefix = parts[2].trim();
            return CONTEXT_FIELDS
                .iter()
                .filter(|f| f.starts_with(field_prefix))
                .map(|f| f.to_string())
                .collect();
        }

        // Complete agent name for commands that take one
        if !AGENT_COMMANDS.contains(&cmd) {
            return Vec::new();
        }

        agent_names
            .iter()
            .filter(|name| name.starts_with(sub))
            .cloned()
            .collect()
    }
}

/// Build the full buffer string from a completion selection.
///
/// For command completions: just the command name.
/// For agent/field completions: "command [agent] [field]".
pub fn apply_completion(buffer: &str, completion: &str) -> String {
    let trimmed = buffer.trim_start();
    if !trimmed.contains(' ') {
        // Completing command name
        format!("{completion} ")
    } else {
        let mut parts: Vec<&str> = trimmed.split_whitespace().collect();
        if trimmed.ends_with(' ') {
            parts.push("");
        }
        if let Some(last) = parts.last_mut() {
            *last = completion;
        }
        format!("{} ", parts.join(" "))
    }
}

/// Help text listing all available commands.
pub fn help_text() -> &'static str {
    ":add                     Add a new agent\n\
     :alias list              List command aliases\n\
     :alias add <a> <cmd>     Add alias (a expands to cmd)\n\
     :alias remove <a>        Remove alias\n\
     :agent <a>               View agent context\n\
     :agent <a> <f> <val>     Set field (role/goal/context/task)\n\
     :agent set <a> <f> <val> Set field (explicit)\n\
     :agent edit <a> <f>      Edit field in multiline editor\n\
     :alerts                  Show alert rules\n\
     :auth list               List auth profiles\n\
     :auth add <p> [m]        Add auth profile (m: oauth/api-key/setup-token)\n\
     :auth login <p> [m]      Run provider auth flow\n\
     :auth logout <provider>  Remove auth profile and stored tokens\n\
     :auth test [target]      Test auth readiness\n\
     :auth status             Show all auth profiles and token status\n\
     :auth refresh <provider> Manually refresh an OAuth token\n\
     :approve <agent>         Approve first pending prompt\n\
     :chat [agent]            Open orchestrator chat (or agent detail)\n\
     :config                  Edit daemon.toml in $EDITOR\n\
     :config get <key>        Read config value (dot-notation)\n\
     :config set <key> <val>  Write config value (workspace)\n\
     :config list             Show all effective config values\n\
     :config layers           Show active config file layers\n\
     :context <agent>         View agent context\n\
     :context <a> <field>     Clear field\n\
     :context <a> <f> <val>   Set field (role/goal/context/task)\n\
     :daemon init             Create daemon.toml\n\
     :daemon install          Install launchd plist\n\
     :daemon reload           Reload config from daemon.toml\n\
     :daemon restart          Stop and restart daemon\n\
     :daemon start            Start daemon in background\n\
     :daemon status           Show daemon status\n\
     :daemon stop             Stop running daemon\n\
     :daemon uninstall        Uninstall launchd plist\n\
     :deny <agent>            Deny first pending prompt\n\
     :diff <s1> <s2>          Compare two audit sessions\n\
     :disable <agent>         Disable agent (stop + prevent restart)\n\
     :doctor [--fix]          Diagnose config issues (fix with --fix)\n\
     :enable <agent>          Enable agent (allow starting)\n\
     :export [format]         Export audit data (json/csv/cef)\n\
     :fetch <url>             Fetch URL content (SSRF-safe)\n\
     :follow <agent>          Drill into agent output\n\
     :goal                    View fleet goal\n\
     :goal <text>             Set fleet goal\n\
     :help                    Show this help\n\
     :hook                    Install aegis hooks (CWD)\n\
     :init                    Create project aegis config\n\
     :job create <a> <desc>   Create a job for agent\n\
     :job cancel <id>         Cancel a job by ID\n\
     :job status <id>         Get job status by ID\n\
     :jobs [agent]            List jobs (optionally by agent)\n\
     :lanes                   List execution lanes with utilization\n\
     :list                    List all aegis configs\n\
     :log                     Recent audit entries\n\
     :matrix status           Feature parity matrix summary\n\
     :matrix diff             Incomplete features by wave\n\
     :matrix verify           Verify completed features\n\
     :logs                    Daemon log output\n\
     :monitor                 Open monitor in new terminal\n\
     :dashboard               Open web dashboard\n\
     :nudge <agent> [msg]     Nudge stalled agent\n\
     :orch                    Orchestrator fleet overview\n\
     :pending <agent>         Show pending prompts\n\
     :compat status           Secure-runtime status summary\n\
     :compat diff             Latest secure-runtime delta impact\n\
     :compat verify           Verify secure-runtime controls\n\
     :capabilities <agent>    Runtime capability/mediation profile\n\
     :tool <agent> <json>     Execute computer-use ToolAction JSON\n\
     :tool-batch <a> <json> [n] Execute computer-use ToolAction batch\n\
     :capture-start <a> [fps] Start capture session for agent\n\
     :capture-stop <a> <sid>  Stop capture session by id\n\
     :browser-profile-stop <a> <sid> Stop managed browser profile\n\
     :pilot <cmd...>          Supervised agent in terminal\n\
     :policy                  Show policy info\n\
     :poll create \"Q\" a,b,c  Create a poll with options\n\
     :poll close <id>         Close a poll by ID\n\
     :poll results <id>       Get poll results by ID\n\
     :polls                   List active polls\n\
     :pop <agent>             Open agent in new terminal\n\
     :queue status             Show command queue metrics\n\
     :queue flush              Flush pending queue commands\n\
     :queue inspect            Inspect dead letter queue\n\
     :push list               List push subscriptions\n\
     :push remove <id>        Remove push subscription\n\
     :push test <id>          Test push notification delivery\n\
     :quit / :q               Quit TUI\n\
     :remove <agent>          Remove agent from config\n\
     :report                  Compliance report\n\
     :restart <agent>         Restart agent\n\
     :resume <agent>          Resume suspended session (SIGCONT)\n\
     :run <cmd...>            Run sandboxed in terminal\n\
     :send <agent> <text>     Send text to agent stdin\n\
     :schedule list            List scheduled auto-replies\n\
     :schedule add <n> <s> <t> Add scheduled reply (name, schedule, template)\n\
     :schedule remove <name>   Remove scheduled reply\n\
     :schedule trigger <name>  Manually trigger scheduled reply\n\
     :session list            List active session keys\n\
     :session history <k> [n] Show recent session output\n\
     :session send <k> <txt>  Send text to a session key\n\
     :session-inspect <uuid>  Inspect session (full detail + links)\n\
     :session-reset <uuid>    Clear context, mark non-resumable\n\
     :session-delete <uuid> [--confirm]  Delete session + entries\n\
     :session-fork <uuid>     Fork session (new conversation tree)\n\
     :session-tree <uuid>     Display session tree from root\n\
     :sessions                List recent audit sessions\n\
     :setup                   Verify system requirements\n\
     :skills list             List installed skills\n\
     :skills search <q>       Search skill registry\n\
     :skills install <name>   Install a skill\n\
     :skills update [name]    Update skill(s)\n\
     :skills uninstall <name> Uninstall a skill\n\
     :skills info <name>      Show skill details\n\
     :skills reload [name]    Reload skill(s) from disk\n\
     :skills commands         List all slash commands\n\
     :start <agent>           Start agent\n\
     :status                  Daemon status summary\n\
     :stop <agent>            Stop agent\n\
     :suspend <agent>         Suspend session (SIGSTOP)\n\
     :terminate <agent>       Terminate session permanently\n\
     :subagent <p> [name]     Spawn constrained subagent session\n\
     :telegram                Show Telegram config status\n\
     :telegram setup           Run Telegram setup wizard\n\
     :telegram disable         Disable Telegram notifications\n\
     :use [name]              Switch active config\n\
     :verify                  Verify audit hash chain integrity\n\
     :watch [dir]             Watch directory for changes\n\
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
    fn parse_subagent() {
        assert_eq!(
            parse("subagent orchestrator").unwrap(),
            Some(FleetCommand::Subagent {
                parent: "orchestrator".into(),
                name: None,
            })
        );
        assert_eq!(
            parse("subagent orchestrator worker-sub-1").unwrap(),
            Some(FleetCommand::Subagent {
                parent: "orchestrator".into(),
                name: Some("worker-sub-1".into()),
            })
        );
    }

    #[test]
    fn parse_start() {
        assert_eq!(
            parse("start claude-1").unwrap(),
            Some(FleetCommand::Start {
                agent: "claude-1".into()
            })
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
            Some(FleetCommand::Stop {
                agent: "agent-2".into()
            })
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
            Some(FleetCommand::Approve {
                agent: "agent-1".into()
            })
        );
    }

    #[test]
    fn parse_deny() {
        assert_eq!(
            parse("deny agent-1").unwrap(),
            Some(FleetCommand::Deny {
                agent: "agent-1".into()
            })
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
            Some(FleetCommand::Follow {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_chat() {
        assert_eq!(
            parse("chat").unwrap(),
            Some(FleetCommand::Chat { agent: None })
        );
        assert_eq!(
            parse("chat claude-1").unwrap(),
            Some(FleetCommand::Chat {
                agent: Some("claude-1".into())
            })
        );
    }

    #[test]
    fn parse_status() {
        assert_eq!(parse("status").unwrap(), Some(FleetCommand::Status));
    }

    #[test]
    fn parse_compat_commands() {
        assert_eq!(parse("compat").unwrap(), Some(FleetCommand::ParityStatus));
        assert_eq!(
            parse("compat status").unwrap(),
            Some(FleetCommand::ParityStatus)
        );
        assert_eq!(
            parse("compat diff").unwrap(),
            Some(FleetCommand::ParityDiff)
        );
        assert_eq!(
            parse("compat verify").unwrap(),
            Some(FleetCommand::ParityVerify)
        );
        assert!(parse("compat nope").is_err());
    }

    #[test]
    fn parse_parity_alias_commands() {
        assert_eq!(parse("parity").unwrap(), Some(FleetCommand::ParityStatus));
        assert_eq!(
            parse("parity status").unwrap(),
            Some(FleetCommand::ParityStatus)
        );
        assert_eq!(
            parse("parity diff").unwrap(),
            Some(FleetCommand::ParityDiff)
        );
        assert_eq!(
            parse("parity verify").unwrap(),
            Some(FleetCommand::ParityVerify)
        );
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
            Some(FleetCommand::Remove {
                agent: "claude-1".into()
            })
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
    fn parse_config_get() {
        assert_eq!(
            parse("config get pilot.stall.timeout_secs").unwrap(),
            Some(FleetCommand::ConfigGet {
                key: "pilot.stall.timeout_secs".into(),
            })
        );
        assert!(parse("config get").is_err());
    }

    #[test]
    fn parse_config_set() {
        assert_eq!(
            parse("config set name myagent").unwrap(),
            Some(FleetCommand::ConfigSet {
                key: "name".into(),
                value: "myagent".into(),
            })
        );
        assert!(parse("config set").is_err());
        assert!(parse("config set name").is_err());
    }

    #[test]
    fn parse_config_list() {
        assert_eq!(
            parse("config list").unwrap(),
            Some(FleetCommand::ConfigList)
        );
    }

    #[test]
    fn parse_config_layers() {
        assert_eq!(
            parse("config layers").unwrap(),
            Some(FleetCommand::ConfigLayers)
        );
    }

    #[test]
    fn parse_config_unknown_subcommand() {
        assert!(parse("config foo").is_err());
    }

    #[test]
    fn parse_telegram() {
        assert_eq!(parse("telegram").unwrap(), Some(FleetCommand::Telegram));
        assert_eq!(
            parse("telegram setup").unwrap(),
            Some(FleetCommand::TelegramSetup)
        );
        assert_eq!(
            parse("telegram disable").unwrap(),
            Some(FleetCommand::TelegramDisable)
        );
        assert!(parse("telegram bogus").is_err());
    }

    #[test]
    fn parse_unknown() {
        assert!(parse("bogus").is_err());
    }

    #[test]
    fn parse_pop() {
        assert_eq!(
            parse("pop claude-1").unwrap(),
            Some(FleetCommand::Pop {
                agent: "claude-1".into()
            })
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
    fn parse_dashboard() {
        assert_eq!(parse("dashboard").unwrap(), Some(FleetCommand::Dashboard));
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
        assert!(c.contains(&"compat".to_string()));
        assert!(!c.contains(&"parity".to_string()));
    }

    #[test]
    fn completions_compat_subcommands() {
        let agents = vec![];
        let c = completions("compat st", &agents);
        assert!(c.contains(&"status".to_string()));
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
            Some(FleetCommand::Pending {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_pending_missing_agent() {
        assert!(parse("pending").is_err());
    }

    #[test]
    fn parse_capabilities() {
        assert_eq!(
            parse("capabilities claude-1").unwrap(),
            Some(FleetCommand::Capabilities {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_capabilities_missing_agent() {
        assert!(parse("capabilities").is_err());
    }

    #[test]
    fn parse_tool() {
        assert_eq!(
            parse("tool claude-1 {\"action\":\"mouse_click\",\"x\":1,\"y\":2,\"button\":\"left\"}")
                .unwrap(),
            Some(FleetCommand::Tool {
                agent: "claude-1".into(),
                action_json: "{\"action\":\"mouse_click\",\"x\":1,\"y\":2,\"button\":\"left\"}"
                    .into(),
            })
        );
    }

    #[test]
    fn parse_tool_batch() {
        assert_eq!(
            parse("tool-batch claude-1 [{\"action\":\"mouse_move\",\"x\":1,\"y\":2}] 3").unwrap(),
            Some(FleetCommand::ToolBatch {
                agent: "claude-1".into(),
                actions_json: "[{\"action\":\"mouse_move\",\"x\":1,\"y\":2}]".into(),
                max_actions: Some(3),
            })
        );
    }

    #[test]
    fn parse_capture_start() {
        assert_eq!(
            parse("capture-start claude-1 45").unwrap(),
            Some(FleetCommand::CaptureStart {
                agent: "claude-1".into(),
                target_fps: Some(45),
            })
        );
    }

    #[test]
    fn parse_capture_stop() {
        assert_eq!(
            parse("capture-stop claude-1 cap-123").unwrap(),
            Some(FleetCommand::CaptureStop {
                agent: "claude-1".into(),
                session_id: "cap-123".into(),
            })
        );
    }

    #[test]
    fn parse_browser_profile_stop() {
        assert_eq!(
            parse("browser-profile-stop claude-1 browser-1").unwrap(),
            Some(FleetCommand::BrowserProfileStop {
                agent: "claude-1".into(),
                session_id: "browser-1".into(),
            })
        );
    }

    #[test]
    fn parse_wrap() {
        assert_eq!(
            parse("wrap claude --help").unwrap(),
            Some(FleetCommand::Wrap {
                cmd: "claude --help".into()
            })
        );
    }

    #[test]
    fn parse_wrap_single_arg() {
        assert_eq!(
            parse("wrap claude").unwrap(),
            Some(FleetCommand::Wrap {
                cmd: "claude".into()
            })
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
            Some(FleetCommand::Run {
                cmd: "echo hello world".into()
            })
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
            Some(FleetCommand::Pilot {
                cmd: "claude".into()
            })
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
            Some(FleetCommand::Use {
                name: Some("myconfig".into())
            })
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
        assert_eq!(
            parse("watch").unwrap(),
            Some(FleetCommand::Watch { dir: None })
        );
        assert_eq!(
            parse("watch /tmp/project").unwrap(),
            Some(FleetCommand::Watch {
                dir: Some("/tmp/project".into())
            })
        );
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
    fn parse_auth_commands() {
        assert_eq!(parse("auth").unwrap(), Some(FleetCommand::AuthList));
        assert_eq!(parse("auth list").unwrap(), Some(FleetCommand::AuthList));
        assert_eq!(
            parse("auth add openai oauth").unwrap(),
            Some(FleetCommand::AuthAdd {
                provider: "openai".into(),
                method: Some("oauth".into())
            })
        );
        assert_eq!(
            parse("auth login anthropic setup-token").unwrap(),
            Some(FleetCommand::AuthLogin {
                provider: "anthropic".into(),
                method: Some("setup-token".into())
            })
        );
        assert_eq!(
            parse("auth test").unwrap(),
            Some(FleetCommand::AuthTest { target: None })
        );
        assert_eq!(
            parse("auth test openai").unwrap(),
            Some(FleetCommand::AuthTest {
                target: Some("openai".into())
            })
        );
        assert!(parse("auth nope").is_err());
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
    fn parse_daemon_reload() {
        assert_eq!(
            parse("daemon reload").unwrap(),
            Some(FleetCommand::DaemonReload)
        );
    }

    #[test]
    fn parse_daemon_status() {
        assert_eq!(
            parse("daemon status").unwrap(),
            Some(FleetCommand::DaemonStatus)
        );
    }

    #[test]
    fn parse_daemon_restart() {
        assert_eq!(
            parse("daemon restart").unwrap(),
            Some(FleetCommand::DaemonRestart)
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
        assert!(c.contains(&"reload".to_string()));
        assert!(c.contains(&"restart".to_string()));
        assert!(c.contains(&"start".to_string()));
        assert!(c.contains(&"status".to_string()));
        assert!(c.contains(&"stop".to_string()));
    }

    #[test]
    fn completions_daemon_prefix() {
        let agents = vec![];
        let c = completions("daemon st", &agents);
        assert_eq!(c, vec!["start", "status", "stop"]);
    }

    #[test]
    fn completions_daemon_in_command_list() {
        let agents = vec![];
        let c = completions("da", &agents);
        assert!(c.contains(&"daemon".to_string()));
    }

    #[test]
    fn completions_telegram_subcommands() {
        let agents = vec![];
        let c = completions("telegram ", &agents);
        assert!(c.contains(&"setup".to_string()));
        assert!(c.contains(&"disable".to_string()));

        let c = completions("telegram d", &agents);
        assert_eq!(c, vec!["disable"]);
    }

    #[test]
    fn completions_auth_subcommands() {
        let agents = vec![];
        let c = completions("auth ", &agents);
        assert!(c.contains(&"add".to_string()));
        assert!(c.contains(&"list".to_string()));
        assert!(c.contains(&"login".to_string()));
        assert!(c.contains(&"test".to_string()));
    }

    #[test]
    fn completions_session_subcommands() {
        let agents = vec![];
        let c = completions("session ", &agents);
        assert!(c.contains(&"list".to_string()));
        assert!(c.contains(&"history".to_string()));
        assert!(c.contains(&"send".to_string()));
    }

    #[test]
    fn parse_enable() {
        assert_eq!(
            parse("enable claude-1").unwrap(),
            Some(FleetCommand::Enable {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_enable_missing_agent() {
        assert!(parse("enable").is_err());
    }

    #[test]
    fn parse_disable() {
        assert_eq!(
            parse("disable claude-1").unwrap(),
            Some(FleetCommand::Disable {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_disable_missing_agent() {
        assert!(parse("disable").is_err());
    }

    #[test]
    fn completions_enable_disable_agent() {
        let agents = vec!["claude-1".to_string(), "codex-1".to_string()];
        let c = completions("enable cl", &agents);
        assert_eq!(c, vec!["claude-1"]);
        let c = completions("disable co", &agents);
        assert_eq!(c, vec!["codex-1"]);
    }

    #[test]
    fn parse_context_with_task_field() {
        let result = parse("context claude-1 task Build the feature").unwrap();
        assert_eq!(
            result,
            Some(FleetCommand::Context {
                agent: "claude-1".into(),
                field: Some("task".into()),
                value: Some("Build the feature".into()),
            })
        );
    }

    #[test]
    fn parse_context_clear_field() {
        let result = parse("context claude-1 role").unwrap();
        assert_eq!(
            result,
            Some(FleetCommand::Context {
                agent: "claude-1".into(),
                field: Some("role".into()),
                value: Some(String::new()),
            })
        );
    }

    #[test]
    fn parse_agent_alias_set_field() {
        let result = parse("agent claude-1 goal Ship it").unwrap();
        assert_eq!(
            result,
            Some(FleetCommand::Context {
                agent: "claude-1".into(),
                field: Some("goal".into()),
                value: Some("Ship it".into()),
            })
        );
    }

    #[test]
    fn parse_agent_set_explicit() {
        let result = parse("agent set claude-1 role Lead dev").unwrap();
        assert_eq!(
            result,
            Some(FleetCommand::Context {
                agent: "claude-1".into(),
                field: Some("role".into()),
                value: Some("Lead dev".into()),
            })
        );
    }

    #[test]
    fn parse_agent_edit() {
        let result = parse("agent edit claude-1 context").unwrap();
        assert_eq!(
            result,
            Some(FleetCommand::ContextEdit {
                agent: "claude-1".into(),
                field: "context".into(),
            })
        );
    }

    #[test]
    fn completions_context_field_names() {
        let agents = vec!["claude-1".to_string()];
        // After agent name, should complete field names
        let c = completions("context claude-1 ", &agents);
        assert_eq!(c, vec!["context", "goal", "role", "task"]);
    }

    #[test]
    fn completions_context_field_prefix() {
        let agents = vec!["claude-1".to_string()];
        let c = completions("context claude-1 ro", &agents);
        assert_eq!(c, vec!["role"]);
        let c = completions("context claude-1 t", &agents);
        assert_eq!(c, vec!["task"]);
    }

    #[test]
    fn apply_completion_context_field() {
        assert_eq!(
            apply_completion("context claude-1 ro", "role"),
            "context claude-1 role "
        );
    }

    #[test]
    fn completions_agent_after_name() {
        let agents = vec!["claude-1".to_string()];
        let c = completions("agent claude-1 ", &agents);
        assert_eq!(c, vec!["context", "goal", "role", "task"]);
    }

    #[test]
    fn completions_agent_set_name() {
        let agents = vec!["claude-1".to_string(), "codex-1".to_string()];
        let c = completions("agent set c", &agents);
        assert_eq!(c, vec!["claude-1", "codex-1"]);
    }

    #[test]
    fn completions_agent_edit_field() {
        let agents = vec!["claude-1".to_string()];
        let c = completions("agent edit claude-1 ", &agents);
        assert_eq!(c, vec!["context", "goal", "role", "task"]);
    }

    #[test]
    fn parse_sessions() {
        assert_eq!(parse("sessions").unwrap(), Some(FleetCommand::Sessions));
    }

    #[test]
    fn parse_session_commands() {
        assert_eq!(parse("session").unwrap(), Some(FleetCommand::SessionList));
        assert_eq!(
            parse("session history agent:orchestrator:main 25").unwrap(),
            Some(FleetCommand::SessionHistory {
                session_key: "agent:orchestrator:main".into(),
                lines: Some(25),
            })
        );
        assert_eq!(
            parse("session send agent:orchestrator:main hello world").unwrap(),
            Some(FleetCommand::SessionSend {
                session_key: "agent:orchestrator:main".into(),
                text: "hello world".into(),
            })
        );
    }

    #[test]
    fn parse_verify() {
        assert_eq!(parse("verify").unwrap(), Some(FleetCommand::Verify));
    }

    #[test]
    fn parse_export_no_format() {
        assert_eq!(
            parse("export").unwrap(),
            Some(FleetCommand::Export { format: None })
        );
    }

    #[test]
    fn parse_export_with_format() {
        assert_eq!(
            parse("export csv").unwrap(),
            Some(FleetCommand::Export {
                format: Some("csv".into())
            })
        );
    }

    #[test]
    fn parse_orch() {
        assert_eq!(
            parse("orch").unwrap(),
            Some(FleetCommand::OrchestratorStatus)
        );
        assert_eq!(
            parse("orchestrator").unwrap(),
            Some(FleetCommand::OrchestratorStatus)
        );
    }

    #[test]
    fn completions_orch() {
        let agents = vec![];
        let c = completions("or", &agents);
        assert!(c.contains(&"orch".to_string()));
    }

    #[test]
    fn completions_new_audit_commands() {
        let agents = vec![];
        let c = completions("se", &agents);
        assert!(c.contains(&"send".to_string()));
        assert!(c.contains(&"sessions".to_string()));
        assert!(c.contains(&"setup".to_string()));

        let c = completions("ver", &agents);
        assert_eq!(c, vec!["verify"]);

        let c = completions("exp", &agents);
        assert_eq!(c, vec!["export"]);
    }

    #[test]
    fn parse_alias_list() {
        assert_eq!(parse("alias").unwrap(), Some(FleetCommand::AliasList));
        assert_eq!(parse("alias list").unwrap(), Some(FleetCommand::AliasList));
    }

    #[test]
    fn parse_alias_add() {
        assert_eq!(
            parse("alias add s status").unwrap(),
            Some(FleetCommand::AliasAdd {
                alias: "s".into(),
                command: "status".into(),
                args: vec![],
            })
        );
    }

    #[test]
    fn parse_alias_add_with_args() {
        assert_eq!(
            parse("alias add ap approve --all").unwrap(),
            Some(FleetCommand::AliasAdd {
                alias: "ap".into(),
                command: "approve".into(),
                args: vec!["--all".into()],
            })
        );
    }

    #[test]
    fn parse_alias_add_missing_command() {
        assert!(parse("alias add s").is_err());
    }

    #[test]
    fn parse_alias_add_missing_all() {
        assert!(parse("alias add").is_err());
    }

    #[test]
    fn parse_alias_remove() {
        assert_eq!(
            parse("alias remove s").unwrap(),
            Some(FleetCommand::AliasRemove { alias: "s".into() })
        );
    }

    #[test]
    fn parse_alias_remove_missing() {
        assert!(parse("alias remove").is_err());
    }

    #[test]
    fn parse_alias_unknown_sub() {
        assert!(parse("alias bogus").is_err());
    }

    #[test]
    fn completions_alias_subcommands() {
        let agents = vec![];
        let c = completions("alias ", &agents);
        assert!(c.contains(&"add".to_string()));
        assert!(c.contains(&"list".to_string()));
        assert!(c.contains(&"remove".to_string()));
    }

    #[test]
    fn completions_alias_prefix() {
        let agents = vec![];
        let c = completions("alias a", &agents);
        assert_eq!(c, vec!["add"]);
    }

    #[test]
    fn completions_alias_in_command_list() {
        let agents = vec![];
        let c = completions("al", &agents);
        assert!(c.contains(&"alias".to_string()));
        assert!(c.contains(&"alerts".to_string()));
    }

    #[test]
    fn parse_suspend() {
        assert_eq!(
            parse("suspend claude-1").unwrap(),
            Some(FleetCommand::Suspend {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_suspend_missing_agent() {
        assert!(parse("suspend").is_err());
    }

    #[test]
    fn parse_resume() {
        assert_eq!(
            parse("resume claude-1").unwrap(),
            Some(FleetCommand::Resume {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_resume_missing_agent() {
        assert!(parse("resume").is_err());
    }

    #[test]
    fn parse_terminate() {
        assert_eq!(
            parse("terminate claude-1").unwrap(),
            Some(FleetCommand::Terminate {
                agent: "claude-1".into()
            })
        );
    }

    #[test]
    fn parse_terminate_missing_agent() {
        assert!(parse("terminate").is_err());
    }

    #[test]
    fn completions_session_lifecycle_commands() {
        let agents = vec!["claude-1".to_string()];
        let c = completions("su", &agents);
        assert!(c.contains(&"suspend".to_string()));
        assert!(c.contains(&"subagent".to_string()));

        let c = completions("res", &agents);
        assert!(c.contains(&"resume".to_string()));
        assert!(c.contains(&"restart".to_string()));

        let c = completions("ter", &agents);
        assert_eq!(c, vec!["terminate"]);
    }

    #[test]
    fn completions_session_lifecycle_agent_names() {
        let agents = vec!["claude-1".to_string(), "codex-1".to_string()];
        let c = completions("suspend cl", &agents);
        assert_eq!(c, vec!["claude-1"]);
        let c = completions("resume co", &agents);
        assert_eq!(c, vec!["codex-1"]);
        let c = completions("terminate cl", &agents);
        assert_eq!(c, vec!["claude-1"]);
    }

    #[test]
    fn help_text_includes_session_lifecycle() {
        let help = help_text();
        assert!(help.contains(":suspend"));
        assert!(help.contains(":resume"));
        assert!(help.contains(":terminate"));
    }

    #[test]
    fn help_text_includes_alias() {
        let help = help_text();
        assert!(help.contains(":alias list"));
        assert!(help.contains(":alias add"));
        assert!(help.contains(":alias remove"));
    }

    // -- Schedule command tests --

    #[test]
    fn parse_schedule_list() {
        assert_eq!(parse("schedule").unwrap(), Some(FleetCommand::ScheduleList));
        assert_eq!(
            parse("schedule list").unwrap(),
            Some(FleetCommand::ScheduleList)
        );
    }

    #[test]
    fn parse_schedule_add() {
        assert_eq!(
            parse("schedule add daily-digest daily {{agent_count}} agents").unwrap(),
            Some(FleetCommand::ScheduleAdd {
                name: "daily-digest".into(),
                schedule: "daily".into(),
                template: "{{agent_count}} agents".into(),
            })
        );
    }

    #[test]
    fn parse_schedule_add_missing_args() {
        assert!(parse("schedule add").is_err());
        assert!(parse("schedule add myname").is_err());
    }

    #[test]
    fn parse_schedule_remove() {
        assert_eq!(
            parse("schedule remove daily-digest").unwrap(),
            Some(FleetCommand::ScheduleRemove {
                name: "daily-digest".into(),
            })
        );
    }

    #[test]
    fn parse_schedule_remove_missing() {
        assert!(parse("schedule remove").is_err());
    }

    #[test]
    fn parse_schedule_trigger() {
        assert_eq!(
            parse("schedule trigger health-check").unwrap(),
            Some(FleetCommand::ScheduleTrigger {
                name: "health-check".into(),
            })
        );
    }

    #[test]
    fn parse_schedule_trigger_missing() {
        assert!(parse("schedule trigger").is_err());
    }

    #[test]
    fn parse_schedule_unknown_sub() {
        assert!(parse("schedule bogus").is_err());
    }

    #[test]
    fn completions_schedule_subcommands() {
        let agents = vec![];
        let c = completions("schedule ", &agents);
        assert!(c.contains(&"add".to_string()));
        assert!(c.contains(&"list".to_string()));
        assert!(c.contains(&"remove".to_string()));
        assert!(c.contains(&"trigger".to_string()));
    }

    #[test]
    fn completions_schedule_prefix() {
        let agents = vec![];
        let c = completions("schedule t", &agents);
        assert_eq!(c, vec!["trigger"]);
    }

    #[test]
    fn completions_schedule_in_command_list() {
        let agents = vec![];
        let c = completions("sch", &agents);
        assert!(c.contains(&"schedule".to_string()));
    }

    #[test]
    fn help_text_includes_schedule() {
        let help = help_text();
        assert!(help.contains(":schedule list"));
        assert!(help.contains(":schedule add"));
        assert!(help.contains(":schedule remove"));
        assert!(help.contains(":schedule trigger"));
    }

    #[test]
    fn parse_fetch() {
        assert_eq!(
            parse("fetch https://example.com").unwrap(),
            Some(FleetCommand::Fetch {
                url: "https://example.com".into()
            })
        );
    }

    #[test]
    fn parse_fetch_missing_url() {
        assert!(parse("fetch").is_err());
    }

    #[test]
    fn help_text_includes_fetch() {
        let help = help_text();
        assert!(help.contains(":fetch"));
    }

    #[test]
    fn completions_fetch_in_command_list() {
        let agents = vec![];
        let c = completions("fe", &agents);
        assert!(c.contains(&"fetch".to_string()));
    }

    #[test]
    fn parse_doctor() {
        assert_eq!(
            parse("doctor").unwrap(),
            Some(FleetCommand::Doctor { fix: false })
        );
    }

    #[test]
    fn parse_doctor_fix() {
        assert_eq!(
            parse("doctor --fix").unwrap(),
            Some(FleetCommand::Doctor { fix: true })
        );
    }

    #[test]
    fn completions_doctor_in_command_list() {
        let agents = vec![];
        let c = completions("do", &agents);
        assert!(c.contains(&"doctor".to_string()));
    }

    #[test]
    fn parse_skills_list() {
        assert_eq!(
            parse("skills").unwrap(),
            Some(FleetCommand::SkillsList)
        );
        assert_eq!(
            parse("skills list").unwrap(),
            Some(FleetCommand::SkillsList)
        );
    }

    #[test]
    fn parse_skills_search() {
        assert_eq!(
            parse("skills search git").unwrap(),
            Some(FleetCommand::SkillsSearch {
                query: "git".into()
            })
        );
    }

    #[test]
    fn parse_skills_search_missing_query() {
        assert!(parse("skills search").is_err());
    }

    #[test]
    fn parse_skills_install() {
        assert_eq!(
            parse("skills install code-review").unwrap(),
            Some(FleetCommand::SkillsInstall {
                name: "code-review".into()
            })
        );
    }

    #[test]
    fn parse_skills_install_missing_name() {
        assert!(parse("skills install").is_err());
    }

    #[test]
    fn parse_skills_update() {
        assert_eq!(
            parse("skills update").unwrap(),
            Some(FleetCommand::SkillsUpdate { name: None })
        );
        assert_eq!(
            parse("skills update calculator").unwrap(),
            Some(FleetCommand::SkillsUpdate {
                name: Some("calculator".into())
            })
        );
    }

    #[test]
    fn parse_skills_uninstall() {
        assert_eq!(
            parse("skills uninstall old-skill").unwrap(),
            Some(FleetCommand::SkillsUninstall {
                name: "old-skill".into()
            })
        );
    }

    #[test]
    fn parse_skills_uninstall_missing_name() {
        assert!(parse("skills uninstall").is_err());
    }

    #[test]
    fn parse_skills_info() {
        assert_eq!(
            parse("skills info calculator").unwrap(),
            Some(FleetCommand::SkillsInfo {
                name: "calculator".into()
            })
        );
    }

    #[test]
    fn parse_skills_info_missing_name() {
        assert!(parse("skills info").is_err());
    }

    #[test]
    fn parse_skills_unknown_subcommand() {
        assert!(parse("skills bogus").is_err());
    }

    #[test]
    fn help_text_includes_skills() {
        let help = help_text();
        assert!(help.contains(":skills"));
        assert!(help.contains(":skills list"));
        assert!(help.contains(":skills install"));
        assert!(help.contains(":skills search"));
    }

    #[test]
    fn completions_skills_in_command_list() {
        let agents = vec![];
        let c = completions("sk", &agents);
        assert!(c.contains(&"skills".to_string()));
    }

    #[test]
    fn completions_skills_subcommands() {
        let agents = vec![];
        let c = completions("skills ", &agents);
        assert!(c.contains(&"list".to_string()));
        assert!(c.contains(&"search".to_string()));
        assert!(c.contains(&"install".to_string()));
        assert!(c.contains(&"update".to_string()));
        assert!(c.contains(&"uninstall".to_string()));
        assert!(c.contains(&"info".to_string()));
    }
}
