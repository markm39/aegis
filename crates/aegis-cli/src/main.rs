mod commands;
mod fleet_tui;
mod onboard_tui;
mod pilot_tui;
mod terminal;
mod tui_utils;
mod wizard;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Aegis -- zero-trust runtime for AI agents.
#[derive(Parser, Debug)]
#[command(name = "aegis", version, about)]
struct Cli {
    /// Increase logging verbosity (RUST_LOG=debug)
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Suppress all output except errors
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check system requirements and prepare the environment
    Setup,

    /// Initialize a new aegis configuration (omit name for interactive wizard)
    Init {
        /// Configuration name (omit for interactive wizard)
        name: Option<String>,

        /// Policy template to use
        #[arg(long, default_value = "default-deny")]
        policy: String,

        /// Use an existing project directory as the sandbox root instead of
        /// creating a dedicated sandbox/ subdirectory
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Run a command inside the aegis sandbox
    Run {
        /// Config name (defaults to command basename)
        #[arg(long)]
        config: Option<String>,

        /// Policy template for auto-initialization
        #[arg(long, default_value = "allow-read-only")]
        policy: String,

        /// Human-readable session tag (e.g., "deploy-v2.1")
        #[arg(long)]
        tag: Option<String>,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Launch the real-time audit monitor TUI
    Monitor {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// Set or show the active configuration
    Use {
        /// Config name to activate (omit to show current or pick interactively)
        name: Option<String>,
    },

    /// Policy management subcommands
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Audit ledger subcommands
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Generate a compliance report
    Report {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Output format (json or text)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show the health status of an aegis configuration
    Status {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// List all Aegis configurations
    List,

    /// Show recent audit log entries (shortcut for `audit query`)
    Log {
        /// Config name (omit to use most recently active config)
        config: Option<String>,

        /// Number of entries to show
        #[arg(long, default_value = "20")]
        last: usize,
    },

    /// Compare two sessions for forensic analysis
    Diff {
        /// First session UUID
        session1: String,

        /// Second session UUID
        session2: String,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,
    },

    /// Configuration management subcommands
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Generate shell completions for bash, zsh, fish, elvish, or powershell
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Generate a man page and print to stdout
    Manpage,

    /// Manage webhook alert rules
    Alerts {
        #[command(subcommand)]
        action: AlertCommands,
    },

    /// Wrap a command with Aegis observability (observe-only by default)
    Wrap {
        /// Project directory to observe (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Policy template to use (default: permit-all for observe-only)
        #[arg(long, default_value = "permit-all")]
        policy: String,

        /// Config name (defaults to basename of command)
        #[arg(long)]
        name: Option<String>,

        /// Human-readable session tag (e.g., "deploy-v2.1")
        #[arg(long)]
        tag: Option<String>,

        /// Enable Seatbelt kernel sandbox enforcement (macOS only)
        #[arg(long)]
        seatbelt: bool,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Supervise an AI agent with auto-approval via Cedar policy
    Pilot {
        /// Project directory to observe (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Policy template to use (default: permit-all)
        #[arg(long, default_value = "permit-all")]
        policy: String,

        /// Config name (defaults to basename of command)
        #[arg(long)]
        name: Option<String>,

        /// Human-readable session tag
        #[arg(long)]
        tag: Option<String>,

        /// Stall detection timeout in seconds (overrides config)
        #[arg(long)]
        stall_timeout: Option<u64>,

        /// Agent adapter (ClaudeCode, Auto, or Generic)
        #[arg(long)]
        adapter: Option<String>,

        /// HTTP listen address for remote control (e.g., 0.0.0.0:8443)
        #[arg(long)]
        listen: Option<String>,

        /// API key for HTTP control authentication
        #[arg(long)]
        api_key: Option<String>,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Set up notification channels (Telegram)
    Telegram {
        #[command(subcommand)]
        action: TelegramCommands,
    },

    /// Open the fleet dashboard (live agent management TUI)
    Fleet,

    /// Manage the multi-agent daemon (fleet orchestration)
    Daemon {
        #[command(subcommand)]
        action: DaemonCommands,
    },

    /// Claude Code hook integration (policy enforcement via PreToolUse hooks)
    Hook {
        #[command(subcommand)]
        action: HookCommands,
    },

    /// Watch a directory for filesystem changes (background daemon mode)
    Watch {
        /// Directory to watch (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Policy template to use (default: permit-all for observe-only)
        #[arg(long, default_value = "permit-all")]
        policy: String,

        /// Config name (defaults to directory basename)
        #[arg(long)]
        name: Option<String>,

        /// Human-readable session tag
        #[arg(long)]
        tag: Option<String>,

        /// Seconds of inactivity before session rotation (default: 300)
        #[arg(long, default_value = "300")]
        idle_timeout: u64,

        /// Stop a running watch for this directory/name
        #[arg(long)]
        stop: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Show the full configuration for a named config
    Show {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// Print the path to the config file (for scripting)
    Path {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// Open the config file in $EDITOR
    Edit {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Validate a .cedar policy file against the Aegis schema
    Validate {
        /// Path to the .cedar policy file
        path: PathBuf,
    },

    /// List all policies in a configuration
    List {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// Generate a builtin policy template and print to stdout
    Generate {
        /// Template name (default-deny, allow-read-only)
        template: String,
    },

    /// Import a Cedar policy file into a configuration
    Import {
        /// Path to the .cedar policy file to import
        path: PathBuf,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,
    },

    /// Test a policy against a hypothetical action (dry run)
    Test {
        /// Action to test (FileRead, FileWrite, FileDelete, DirCreate, DirList, NetConnect, NetRequest, ToolCall, ProcessSpawn, ProcessExit)
        action: String,

        /// Resource path or identifier to test against
        resource: String,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Query audit entries with optional filters
    Query {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Number of most recent entries to display (shortcut, ignores other filters)
        #[arg(long)]
        last: Option<usize>,

        /// Only entries at or after this time (RFC 3339, e.g. 2026-02-16T00:00:00Z)
        #[arg(long)]
        from: Option<String>,

        /// Only entries at or before this time (RFC 3339)
        #[arg(long)]
        to: Option<String>,

        /// Filter by action kind (e.g. FileRead, FileWrite, NetConnect)
        #[arg(long)]
        action: Option<String>,

        /// Filter by decision (Allow or Deny)
        #[arg(long)]
        decision: Option<String>,

        /// Filter by principal name
        #[arg(long)]
        principal: Option<String>,

        /// Full-text search in the reason field
        #[arg(long)]
        search: Option<String>,

        /// Page number (1-based, default 1)
        #[arg(long, default_value = "1")]
        page: usize,

        /// Page size (default 20)
        #[arg(long, default_value = "20")]
        page_size: usize,
    },

    /// Verify the integrity of the audit hash chain
    Verify {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// List recent sessions
    Sessions {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Number of sessions to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Show details for a specific session
    Session {
        /// Session UUID
        id: String,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,
    },

    /// Show policy change history
    PolicyHistory {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Number of snapshots to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Tag a session with a human-readable label
    Tag {
        /// Session UUID
        id: String,

        /// Tag to apply
        tag: String,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,
    },

    /// Purge old audit entries (destructive, requires --confirm)
    Purge {
        /// Delete entries older than this duration (e.g. 30d, 7d, 24h)
        older_than: String,

        /// Name of the aegis configuration (uses current if omitted)
        #[arg(long)]
        config: Option<String>,

        /// Confirm the destructive operation
        #[arg(long)]
        confirm: bool,
    },

    /// Watch audit events in real-time (like tail -f)
    Watch {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Filter by decision (Allow or Deny)
        #[arg(long)]
        decision: Option<String>,
    },

    /// Export audit entries in a structured format
    Export {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Output format (json, jsonl, csv, cef)
        #[arg(long, default_value = "json")]
        format: String,

        /// Maximum number of entries to export (default 10000)
        #[arg(long, default_value = "10000")]
        limit: usize,

        /// Continuously follow new entries (like tail -f)
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AlertCommands {
    /// List all configured alert rules
    List {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,
    },

    /// Send a test webhook to verify connectivity
    Test {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Only test the named rule (tests all if omitted)
        #[arg(long)]
        rule: Option<String>,
    },

    /// Show alert dispatch history
    History {
        /// Name of the aegis configuration (uses current if omitted)
        config: Option<String>,

        /// Number of recent dispatches to show (default 20)
        #[arg(long, default_value = "20")]
        last: u32,
    },
}

#[derive(Subcommand, Debug)]
enum TelegramCommands {
    /// Interactive setup wizard for the Telegram bot
    Setup,
    /// Show current Telegram configuration status
    Status,
    /// Remove Telegram notifications from the config
    Disable,
}

#[derive(Subcommand, Debug)]
enum HookCommands {
    /// Handle a PreToolUse hook from Claude Code (reads stdin, outputs verdict)
    PreToolUse,

    /// Show the settings JSON needed to register the aegis hook
    ShowSettings,

    /// Install the aegis hook into a project's .claude/settings.json
    Install {
        /// Project directory (defaults to current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonCommands {
    /// Create a default daemon configuration file
    Init,

    /// Run the daemon in the foreground (blocks until shutdown)
    Run {
        /// Signal that we were started by launchd
        #[arg(long)]
        launchd: bool,
    },

    /// Start the daemon in the background
    Start,

    /// Stop a running daemon
    Stop,

    /// Reload daemon configuration from daemon.toml (no restart)
    Reload,

    /// Stop and restart the daemon
    Restart,

    /// Show daemon status (uptime, agent count)
    Status,

    /// List all agent slots and their status
    Agents,

    /// Daemon configuration management
    Config {
        #[command(subcommand)]
        action: DaemonConfigCommands,
    },

    /// Add a new agent interactively
    Add,

    /// Remove an agent from the configuration
    Remove {
        /// Agent name to remove
        name: String,
    },

    /// Show recent output from an agent
    Output {
        /// Agent name
        name: String,

        /// Number of lines to show
        #[arg(long, default_value = "50")]
        lines: usize,
    },

    /// Send text to an agent's stdin
    Send {
        /// Agent name
        name: String,

        /// Text to send
        text: String,
    },

    /// Start a specific agent
    StartAgent {
        /// Agent name
        name: String,
    },

    /// Stop a specific agent
    StopAgent {
        /// Agent name
        name: String,
    },

    /// Restart a specific agent
    RestartAgent {
        /// Agent name
        name: String,
    },

    /// Approve a pending permission prompt for an agent
    Approve {
        /// Agent name
        name: String,

        /// Request ID (UUID from pending list)
        request_id: String,
    },

    /// Deny a pending permission prompt for an agent
    Deny {
        /// Agent name
        name: String,

        /// Request ID (UUID from pending list)
        request_id: String,
    },

    /// Nudge a stalled agent
    Nudge {
        /// Agent name
        name: String,

        /// Optional message to include with the nudge
        message: Option<String>,
    },

    /// List pending permission prompts for an agent
    Pending {
        /// Agent name
        name: String,
    },

    /// Show runtime capability and policy-mediation coverage for an agent
    Capabilities {
        /// Agent name
        name: String,
    },

    /// Execute a computer-use ToolAction JSON payload for an agent
    Tool {
        /// Agent name
        name: String,

        /// ToolAction JSON payload (e.g. '{"action":"mouse_click","x":10,"y":20,"button":"left"}')
        action_json: String,
    },

    /// Execute a computer-use ToolAction batch JSON payload for an agent
    #[command(name = "tool-batch")]
    ToolBatch {
        /// Agent name
        name: String,

        /// ToolAction array JSON payload
        actions_json: String,

        /// Optional hard cap for actions executed from the payload
        #[arg(long)]
        max_actions: Option<u8>,
    },

    /// Start a capture session for an agent
    #[command(name = "capture-start")]
    CaptureStart {
        /// Agent name
        name: String,

        /// Target frames per second
        #[arg(long, default_value = "30")]
        fps: u16,
    },

    /// Stop a capture session for an agent
    #[command(name = "capture-stop")]
    CaptureStop {
        /// Agent name
        name: String,

        /// Capture session id
        session_id: String,
    },

    /// Fetch the latest cached capture frame for an agent
    #[command(name = "latest-frame")]
    LatestFrame {
        /// Agent name
        name: String,

        /// Optional capture region x
        #[arg(long)]
        x: Option<i32>,

        /// Optional capture region y
        #[arg(long)]
        y: Option<i32>,

        /// Optional capture region width
        #[arg(long)]
        width: Option<u32>,

        /// Optional capture region height
        #[arg(long)]
        height: Option<u32>,
    },

    /// Start a managed browser profile for an agent
    #[command(name = "browser-profile")]
    BrowserProfile {
        /// Agent name
        name: String,

        /// Browser session id
        session_id: String,

        /// Launch in headless mode
        #[arg(long)]
        headless: bool,

        /// Optional URL to open
        #[arg(long)]
        url: Option<String>,
    },

    /// Follow (tail) agent output in real time
    Follow {
        /// Agent name
        name: String,
    },

    /// Enable an agent slot (allows it to be started)
    Enable {
        /// Agent name
        name: String,
    },

    /// Disable an agent slot (stops it, prevents restart)
    Disable {
        /// Agent name
        name: String,
    },

    /// Get or set the fleet-wide goal
    Goal {
        /// Goal text (omit to show current goal)
        text: Option<String>,
    },

    /// Get or set an agent's context fields
    Context {
        /// Agent name
        name: String,

        /// Field to set (role, goal, context, or task)
        field: Option<String>,

        /// Value to set for the field
        value: Option<String>,
    },

    /// Install launchd plist for auto-start
    Install {
        /// Start the daemon after installing
        #[arg(long)]
        start: bool,
    },

    /// Uninstall launchd plist
    Uninstall,

    /// Show daemon log output
    Logs {
        /// Follow log output (like tail -f)
        #[arg(long)]
        follow: bool,
    },

    /// Show orchestrator overview (bulk fleet status for review)
    #[command(name = "orchestrator-status")]
    OrchestratorStatus {
        /// Only include these agents (default: all non-orchestrator agents)
        agents: Vec<String>,

        /// Number of recent output lines per agent
        #[arg(long, default_value = "30")]
        lines: usize,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonConfigCommands {
    /// Show the daemon configuration (daemon.toml)
    Show,
    /// Open daemon.toml in $EDITOR
    Edit,
    /// Print the path to daemon.toml
    Path,
}

/// Resolve config name: use provided value or fall back to current config.
fn resolve_config(config: Option<String>) -> anyhow::Result<String> {
    match config {
        Some(name) => Ok(name),
        None => commands::use_config::get_current(),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on flags: --verbose sets debug, --quiet sets error,
    // otherwise respect RUST_LOG or default to warn.
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else if cli.quiet {
        EnvFilter::new("error")
    } else {
        EnvFilter::from_default_env()
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let command = match cli.command {
        Some(cmd) => cmd,
        None => return commands::default_action::run(),
    };

    match command {
        Commands::Setup => commands::setup::run(),
        Commands::Init { name, policy, dir } => {
            commands::init::run(name.as_deref(), &policy, dir.as_deref())
        }
        Commands::Run {
            config,
            policy,
            tag,
            command,
        } => {
            eprintln!("Note: `aegis run` is deprecated. Use `aegis wrap` instead (add --seatbelt for sandbox enforcement).");
            let (cmd, args) = command.split_first().ok_or_else(|| {
                anyhow::anyhow!("no command specified; usage: aegis run -- <command> [args...]")
            })?;
            commands::wrap::run(
                None,
                &policy,
                config.as_deref(),
                cmd,
                args,
                tag.as_deref(),
                false,
            )
        }
        Commands::Monitor { config } => {
            let config = resolve_config(config)?;
            commands::monitor::run(&config)
        }
        Commands::Use { name } => commands::use_config::run(name.as_deref()),
        Commands::Policy { action } => match action {
            PolicyCommands::Validate { path } => commands::policy::validate(&path),
            PolicyCommands::Import { config, path } => {
                let config = resolve_config(config)?;
                commands::policy::import_policy(&config, &path)
            }
            PolicyCommands::List { config } => {
                let config = resolve_config(config)?;
                commands::policy::list(&config)
            }
            PolicyCommands::Generate { template } => commands::policy::generate(&template),
            PolicyCommands::Test {
                config,
                action,
                resource,
            } => {
                let config = resolve_config(config)?;
                commands::policy::test_policy(&config, &action, &resource)
            }
        },
        Commands::Audit { action } => match action {
            AuditCommands::Query {
                config,
                last,
                from,
                to,
                action,
                decision,
                principal,
                search,
                page,
                page_size,
            } => {
                let config = resolve_config(config)?;
                commands::audit::query(
                    &config,
                    commands::audit::QueryOptions {
                        last,
                        from,
                        to,
                        action,
                        decision,
                        principal,
                        search,
                        page,
                        page_size,
                    },
                )
            }
            AuditCommands::Verify { config } => {
                let config = resolve_config(config)?;
                commands::audit::verify(&config)
            }
            AuditCommands::Sessions { config, last } => {
                let config = resolve_config(config)?;
                commands::audit::list_sessions(&config, last)
            }
            AuditCommands::Session { config, id } => {
                let config = resolve_config(config)?;
                commands::audit::show_session(&config, &id)
            }
            AuditCommands::PolicyHistory { config, last } => {
                let config = resolve_config(config)?;
                commands::audit::policy_history(&config, last)
            }
            AuditCommands::Tag { config, id, tag } => {
                let config = resolve_config(config)?;
                commands::audit::tag_session(&config, &id, &tag)
            }
            AuditCommands::Purge {
                config,
                older_than,
                confirm,
            } => {
                let config = resolve_config(config)?;
                commands::audit::purge(&config, &older_than, confirm)
            }
            AuditCommands::Watch { config, decision } => {
                let config = resolve_config(config)?;
                commands::audit::watch(&config, decision.as_deref())
            }
            AuditCommands::Export {
                config,
                format,
                limit,
                follow,
            } => {
                let config = resolve_config(config)?;
                commands::audit::export(&config, &format, limit, follow)
            }
        },
        Commands::Report { config, format } => {
            let config = resolve_config(config)?;
            commands::report::run(&config, &format)
        }
        Commands::Status { config } => {
            let config = resolve_config(config)?;
            commands::status::run(&config)
        }
        Commands::List => commands::list::run(),
        Commands::Log { config, last } => {
            let config = resolve_config(config)?;
            commands::audit::query(
                &config,
                commands::audit::QueryOptions {
                    last: Some(last),
                    from: None,
                    to: None,
                    action: None,
                    decision: None,
                    principal: None,
                    search: None,
                    page: 1,
                    page_size: last,
                },
            )
        }
        Commands::Diff {
            config,
            session1,
            session2,
        } => {
            let config = resolve_config(config)?;
            commands::diff::run(&config, &session1, &session2)
        }
        Commands::Config { action } => match action {
            ConfigCommands::Show { config } => {
                let config = resolve_config(config)?;
                commands::config::show(&config)
            }
            ConfigCommands::Path { config } => {
                let config = resolve_config(config)?;
                commands::config::path(&config)
            }
            ConfigCommands::Edit { config } => {
                let config = resolve_config(config)?;
                commands::config::edit(&config)
            }
        },
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "aegis", &mut std::io::stdout());
            Ok(())
        }
        Commands::Manpage => {
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())
                .map_err(|e| anyhow::anyhow!("failed to render man page: {e}"))
        }
        Commands::Alerts { action } => match action {
            AlertCommands::List { config } => {
                let config = resolve_config(config)?;
                commands::alerts::list(&config)
            }
            AlertCommands::Test { config, rule } => {
                let config = resolve_config(config)?;
                commands::alerts::test(&config, rule.as_deref())
            }
            AlertCommands::History { config, last } => {
                let config = resolve_config(config)?;
                commands::alerts::history(&config, last)
            }
        },
        Commands::Wrap {
            dir,
            policy,
            name,
            tag,
            seatbelt,
            command,
        } => {
            let (cmd, args) = command.split_first().ok_or_else(|| {
                anyhow::anyhow!("no command specified; usage: aegis wrap -- <command> [args...]")
            })?;
            commands::wrap::run(
                dir.as_deref(),
                &policy,
                name.as_deref(),
                cmd,
                args,
                tag.as_deref(),
                seatbelt,
            )
        }
        Commands::Pilot {
            dir,
            policy,
            name,
            tag,
            stall_timeout,
            adapter,
            listen,
            api_key,
            command,
        } => {
            let (cmd, args) = command.split_first().ok_or_else(|| {
                anyhow::anyhow!("no command specified; usage: aegis pilot -- <command> [args...]")
            })?;
            commands::pilot::run(
                dir.as_deref(),
                &policy,
                name.as_deref(),
                tag.as_deref(),
                stall_timeout,
                adapter.as_deref(),
                listen.as_deref(),
                api_key.as_deref(),
                cmd,
                args,
            )
        }
        Commands::Telegram { action } => match action {
            TelegramCommands::Setup => commands::telegram::run(),
            TelegramCommands::Status => commands::telegram::status(),
            TelegramCommands::Disable => commands::telegram::disable(),
        },
        Commands::Fleet => fleet_tui::run_fleet_tui(),
        Commands::Daemon { action } => match action {
            DaemonCommands::Init => commands::daemon::init(),
            DaemonCommands::Run { launchd } => commands::daemon::run(launchd),
            DaemonCommands::Start => commands::daemon::start(),
            DaemonCommands::Stop => commands::daemon::stop(),
            DaemonCommands::Reload => commands::daemon::reload(),
            DaemonCommands::Restart => commands::daemon::restart(),
            DaemonCommands::Status => commands::daemon::status(),
            DaemonCommands::Agents => commands::daemon::agents(),
            DaemonCommands::Config { action } => match action {
                DaemonConfigCommands::Show => commands::daemon::config_show(),
                DaemonConfigCommands::Edit => commands::daemon::config_edit(),
                DaemonConfigCommands::Path => commands::daemon::config_path(),
            },
            DaemonCommands::Add => commands::daemon::add_agent(),
            DaemonCommands::Remove { name } => commands::daemon::remove_agent(&name),
            DaemonCommands::Output { name, lines } => commands::daemon::output(&name, lines),
            DaemonCommands::Send { name, text } => commands::daemon::send(&name, &text),
            DaemonCommands::StartAgent { name } => commands::daemon::start_agent(&name),
            DaemonCommands::StopAgent { name } => commands::daemon::stop_agent(&name),
            DaemonCommands::RestartAgent { name } => commands::daemon::restart_agent(&name),
            DaemonCommands::Approve { name, request_id } => {
                commands::daemon::approve(&name, &request_id)
            }
            DaemonCommands::Deny { name, request_id } => commands::daemon::deny(&name, &request_id),
            DaemonCommands::Nudge { name, message } => {
                commands::daemon::nudge(&name, message.as_deref())
            }
            DaemonCommands::Pending { name } => commands::daemon::pending(&name),
            DaemonCommands::Capabilities { name } => commands::daemon::capabilities(&name),
            DaemonCommands::Tool { name, action_json } => {
                commands::daemon::tool_action(&name, &action_json)
            }
            DaemonCommands::ToolBatch {
                name,
                actions_json,
                max_actions,
            } => commands::daemon::tool_batch(&name, &actions_json, max_actions),
            DaemonCommands::CaptureStart { name, fps } => {
                commands::daemon::capture_start(&name, fps)
            }
            DaemonCommands::CaptureStop { name, session_id } => {
                commands::daemon::capture_stop(&name, &session_id)
            }
            DaemonCommands::LatestFrame {
                name,
                x,
                y,
                width,
                height,
            } => {
                let region = match (x, y, width, height) {
                    (None, None, None, None) => None,
                    (Some(x), Some(y), Some(width), Some(height)) => {
                        Some(aegis_control::daemon::CaptureRegion {
                            x,
                            y,
                            width,
                            height,
                        })
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "latest-frame requires all of --x, --y, --width, --height"
                        ))
                    }
                };
                commands::daemon::latest_frame(&name, region)
            }
            DaemonCommands::BrowserProfile {
                name,
                session_id,
                headless,
                url,
            } => commands::daemon::browser_profile(&name, &session_id, headless, url.as_deref()),
            DaemonCommands::Follow { name } => commands::daemon::follow(&name),
            DaemonCommands::Enable { name } => commands::daemon::enable_agent(&name),
            DaemonCommands::Disable { name } => commands::daemon::disable_agent(&name),
            DaemonCommands::Goal { text } => commands::daemon::goal(text.as_deref()),
            DaemonCommands::Context { name, field, value } => {
                commands::daemon::context(&name, field.as_deref(), value.as_deref())
            }
            DaemonCommands::Install { start } => commands::daemon::install(start),
            DaemonCommands::Uninstall => commands::daemon::uninstall(),
            DaemonCommands::Logs { follow } => commands::daemon::logs(follow),
            DaemonCommands::OrchestratorStatus { agents, lines } => {
                commands::daemon::orchestrator_status(&agents, lines)
            }
        },
        Commands::Hook { action } => match action {
            HookCommands::PreToolUse => commands::hook::pre_tool_use(),
            HookCommands::ShowSettings => commands::hook::show_settings(),
            HookCommands::Install { dir } => commands::hook::install_settings(dir.as_deref()),
        },
        Commands::Watch {
            dir,
            policy,
            name,
            tag,
            idle_timeout,
            stop,
        } => commands::watch::run(
            dir.as_deref(),
            &policy,
            name.as_deref(),
            tag.as_deref(),
            idle_timeout,
            stop,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parse_init_positional() {
        let cli = Cli::try_parse_from(["aegis", "init", "myagent"]);
        assert!(
            cli.is_ok(),
            "should parse init with positional name: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Init { name, policy, dir } => {
                assert_eq!(name, Some("myagent".to_string()));
                assert_eq!(policy, "default-deny");
                assert!(dir.is_none());
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_no_name_for_wizard() {
        let cli = Cli::try_parse_from(["aegis", "init"]);
        assert!(cli.is_ok(), "should parse init with no name: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Init { name, .. } => {
                assert!(name.is_none(), "name should be None for wizard mode");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_with_policy() {
        let cli = Cli::try_parse_from(["aegis", "init", "agent2", "--policy", "allow-read-only"]);
        assert!(cli.is_ok(), "should parse init with policy: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Init { name, policy, dir } => {
                assert_eq!(name, Some("agent2".to_string()));
                assert_eq!(policy, "allow-read-only");
                assert!(dir.is_none());
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_with_dir() {
        let cli = Cli::try_parse_from(["aegis", "init", "agent3", "--dir", "/tmp/my-project"]);
        assert!(cli.is_ok(), "should parse init with dir: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Init { name, dir, .. } => {
                assert_eq!(name, Some("agent3".to_string()));
                assert_eq!(dir, Some(PathBuf::from("/tmp/my-project")));
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_run_with_config() {
        let cli =
            Cli::try_parse_from(["aegis", "run", "--config", "myagent", "--", "echo", "hello"]);
        assert!(cli.is_ok(), "should parse run with --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Run {
                config,
                policy,
                tag,
                command,
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(policy, "allow-read-only");
                assert!(tag.is_none());
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_run_with_tag() {
        let cli = Cli::try_parse_from([
            "aegis",
            "run",
            "--tag",
            "deploy-v2.1",
            "--",
            "echo",
            "hello",
        ]);
        assert!(cli.is_ok(), "should parse run with --tag: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Run { tag, .. } => {
                assert_eq!(tag, Some("deploy-v2.1".to_string()));
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_run_without_config() {
        let cli = Cli::try_parse_from(["aegis", "run", "--", "echo", "hello"]);
        assert!(cli.is_ok(), "should parse run without --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Run {
                config, command, ..
            } => {
                assert!(config.is_none(), "config should be None when not specified");
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_run_with_policy() {
        let cli = Cli::try_parse_from([
            "aegis",
            "run",
            "--policy",
            "permit-all",
            "--",
            "python3",
            "agent.py",
        ]);
        assert!(cli.is_ok(), "should parse run with --policy: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Run {
                config,
                policy,
                command,
                ..
            } => {
                assert!(config.is_none());
                assert_eq!(policy, "permit-all");
                assert_eq!(command, vec!["python3", "agent.py"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_policy_validate() {
        let cli = Cli::try_parse_from(["aegis", "policy", "validate", "/tmp/test.cedar"]);
        assert!(cli.is_ok(), "should parse policy validate: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Policy {
                action: PolicyCommands::Validate { path },
            } => {
                assert_eq!(path, PathBuf::from("/tmp/test.cedar"));
            }
            _ => panic!("expected Policy Validate command"),
        }
    }

    #[test]
    fn cli_parse_audit_query() {
        let cli = Cli::try_parse_from(["aegis", "audit", "query", "myagent", "--last", "50"]);
        assert!(cli.is_ok(), "should parse audit query: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Query { config, last, .. },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(last, Some(50));
            }
            _ => panic!("expected Audit Query command"),
        }
    }

    #[test]
    fn cli_parse_audit_query_with_filters() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "query",
            "myagent",
            "--decision",
            "Deny",
            "--action",
            "FileWrite",
            "--principal",
            "agent-1",
            "--page",
            "2",
        ]);
        assert!(cli.is_ok(), "should parse filtered query: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Query {
                        config,
                        decision,
                        action,
                        principal,
                        page,
                        ..
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(decision, Some("Deny".into()));
                assert_eq!(action, Some("FileWrite".into()));
                assert_eq!(principal, Some("agent-1".into()));
                assert_eq!(page, 2);
            }
            _ => panic!("expected Audit Query command"),
        }
    }

    #[test]
    fn cli_parse_audit_sessions() {
        let cli = Cli::try_parse_from(["aegis", "audit", "sessions", "myagent", "--last", "5"]);
        assert!(cli.is_ok(), "should parse audit sessions: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Sessions { config, last },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(last, 5);
            }
            _ => panic!("expected Audit Sessions command"),
        }
    }

    #[test]
    fn cli_parse_audit_session_detail() {
        // Positional session ID, no config (uses current)
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "session",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(cli.is_ok(), "should parse audit session: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Session { config, id },
            } => {
                assert!(config.is_none());
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Audit Session command"),
        }
    }

    #[test]
    fn cli_parse_audit_session_with_config() {
        // Positional session ID with --config flag
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "session",
            "--config",
            "myagent",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(
            cli.is_ok(),
            "should parse audit session with --config: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Session { config, id },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Audit Session command"),
        }
    }

    #[test]
    fn cli_parse_audit_tag() {
        // Positional id and tag, no config
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "tag",
            "550e8400-e29b-41d4-a716-446655440000",
            "deploy-v2",
        ]);
        assert!(cli.is_ok(), "should parse audit tag: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Tag { config, id, tag },
            } => {
                assert!(config.is_none());
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(tag, "deploy-v2");
            }
            _ => panic!("expected Audit Tag command"),
        }
    }

    #[test]
    fn cli_parse_audit_tag_with_config() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "tag",
            "--config",
            "myagent",
            "550e8400-e29b-41d4-a716-446655440000",
            "deploy-v2",
        ]);
        assert!(cli.is_ok(), "should parse audit tag with --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Tag { config, id, tag },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(tag, "deploy-v2");
            }
            _ => panic!("expected Audit Tag command"),
        }
    }

    #[test]
    fn cli_parse_audit_purge() {
        // Positional older_than, no config
        let cli = Cli::try_parse_from(["aegis", "audit", "purge", "30d", "--confirm"]);
        assert!(cli.is_ok(), "should parse audit purge: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Purge {
                        config,
                        older_than,
                        confirm,
                    },
            } => {
                assert!(config.is_none());
                assert_eq!(older_than, "30d");
                assert!(confirm);
            }
            _ => panic!("expected Audit Purge command"),
        }
    }

    #[test]
    fn cli_parse_audit_purge_with_config() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "purge",
            "--config",
            "myagent",
            "30d",
            "--confirm",
        ]);
        assert!(
            cli.is_ok(),
            "should parse audit purge with --config: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Purge {
                        config,
                        older_than,
                        confirm,
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(older_than, "30d");
                assert!(confirm);
            }
            _ => panic!("expected Audit Purge command"),
        }
    }

    #[test]
    fn cli_parse_audit_watch() {
        let cli = Cli::try_parse_from(["aegis", "audit", "watch", "myagent"]);
        assert!(cli.is_ok(), "should parse audit watch: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Watch { config, decision },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert!(decision.is_none());
            }
            _ => panic!("expected Audit Watch command"),
        }
    }

    #[test]
    fn cli_parse_audit_watch_with_filter() {
        let cli = Cli::try_parse_from(["aegis", "audit", "watch", "myagent", "--decision", "Deny"]);
        assert!(cli.is_ok(), "should parse audit watch with filter: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Watch { config, decision },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(decision, Some("Deny".to_string()));
            }
            _ => panic!("expected Audit Watch command"),
        }
    }

    #[test]
    fn cli_parse_audit_export() {
        let cli = Cli::try_parse_from(["aegis", "audit", "export", "myagent", "--format", "csv"]);
        assert!(cli.is_ok(), "should parse audit export: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Export {
                        config,
                        format,
                        follow,
                        ..
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(format, "csv");
                assert!(!follow);
            }
            _ => panic!("expected Audit Export command"),
        }
    }

    #[test]
    fn cli_parse_audit_export_follow() {
        let cli = Cli::try_parse_from([
            "aegis", "audit", "export", "myagent", "--format", "jsonl", "--follow",
        ]);
        assert!(
            cli.is_ok(),
            "should parse audit export with follow: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Export {
                        config,
                        format,
                        follow,
                        ..
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(format, "jsonl");
                assert!(follow);
            }
            _ => panic!("expected Audit Export command"),
        }
    }

    #[test]
    fn cli_parse_status() {
        let cli = Cli::try_parse_from(["aegis", "status", "myagent"]);
        assert!(cli.is_ok(), "should parse status: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Status { config } => {
                assert_eq!(config, Some("myagent".to_string()));
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn cli_parse_monitor() {
        let cli = Cli::try_parse_from(["aegis", "monitor", "myagent"]);
        assert!(cli.is_ok(), "should parse monitor: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Monitor { config } => {
                assert_eq!(config, Some("myagent".to_string()));
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn cli_parse_policy_list() {
        let cli = Cli::try_parse_from(["aegis", "policy", "list", "myagent"]);
        assert!(cli.is_ok(), "should parse policy list: {cli:?}");
    }

    #[test]
    fn cli_parse_policy_import() {
        // Positional path, no config
        let cli = Cli::try_parse_from(["aegis", "policy", "import", "/tmp/custom.cedar"]);
        assert!(cli.is_ok(), "should parse policy import: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Policy {
                action: PolicyCommands::Import { config, path },
            } => {
                assert!(config.is_none());
                assert_eq!(path, PathBuf::from("/tmp/custom.cedar"));
            }
            _ => panic!("expected Policy Import command"),
        }
    }

    #[test]
    fn cli_parse_policy_import_with_config() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "import",
            "--config",
            "myagent",
            "/tmp/custom.cedar",
        ]);
        assert!(
            cli.is_ok(),
            "should parse policy import with --config: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Policy {
                action: PolicyCommands::Import { config, path },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(path, PathBuf::from("/tmp/custom.cedar"));
            }
            _ => panic!("expected Policy Import command"),
        }
    }

    #[test]
    fn cli_parse_policy_test() {
        // Positional action and resource, no config
        let cli = Cli::try_parse_from(["aegis", "policy", "test", "FileRead", "/tmp/test.txt"]);
        assert!(cli.is_ok(), "should parse policy test: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Policy {
                action:
                    PolicyCommands::Test {
                        config,
                        action,
                        resource,
                    },
            } => {
                assert!(config.is_none());
                assert_eq!(action, "FileRead");
                assert_eq!(resource, "/tmp/test.txt");
            }
            _ => panic!("expected Policy Test command"),
        }
    }

    #[test]
    fn cli_parse_policy_test_with_config() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "test",
            "--config",
            "myagent",
            "FileRead",
            "/tmp/test.txt",
        ]);
        assert!(
            cli.is_ok(),
            "should parse policy test with --config: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Policy {
                action:
                    PolicyCommands::Test {
                        config,
                        action,
                        resource,
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(action, "FileRead");
                assert_eq!(resource, "/tmp/test.txt");
            }
            _ => panic!("expected Policy Test command"),
        }
    }

    #[test]
    fn cli_parse_policy_generate() {
        // Positional template
        let cli = Cli::try_parse_from(["aegis", "policy", "generate", "default-deny"]);
        assert!(cli.is_ok(), "should parse policy generate: {cli:?}");
    }

    #[test]
    fn cli_parse_diff() {
        // Positional session1 and session2, no config
        let cli = Cli::try_parse_from([
            "aegis",
            "diff",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440001",
        ]);
        assert!(cli.is_ok(), "should parse diff: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Diff {
                config,
                session1,
                session2,
            } => {
                assert!(config.is_none());
                assert_eq!(session1, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(session2, "550e8400-e29b-41d4-a716-446655440001");
            }
            _ => panic!("expected Diff command"),
        }
    }

    #[test]
    fn cli_parse_diff_with_config() {
        let cli = Cli::try_parse_from([
            "aegis",
            "diff",
            "--config",
            "myagent",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440001",
        ]);
        assert!(cli.is_ok(), "should parse diff with --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Diff {
                config,
                session1,
                session2,
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(session1, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(session2, "550e8400-e29b-41d4-a716-446655440001");
            }
            _ => panic!("expected Diff command"),
        }
    }

    #[test]
    fn cli_parse_config_show() {
        let cli = Cli::try_parse_from(["aegis", "config", "show", "myagent"]);
        assert!(cli.is_ok(), "should parse config show: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Config {
                action: ConfigCommands::Show { config },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
            }
            _ => panic!("expected Config Show command"),
        }
    }

    #[test]
    fn cli_parse_config_path() {
        let cli = Cli::try_parse_from(["aegis", "config", "path", "myagent"]);
        assert!(cli.is_ok(), "should parse config path: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Config {
                action: ConfigCommands::Path { config },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
            }
            _ => panic!("expected Config Path command"),
        }
    }

    #[test]
    fn cli_parse_config_edit() {
        let cli = Cli::try_parse_from(["aegis", "config", "edit", "myagent"]);
        assert!(cli.is_ok(), "should parse config edit: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Config {
                action: ConfigCommands::Edit { config },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
            }
            _ => panic!("expected Config Edit command"),
        }
    }

    #[test]
    fn cli_parse_audit_export_with_limit() {
        let cli = Cli::try_parse_from([
            "aegis", "audit", "export", "myagent", "--format", "csv", "--limit", "500",
        ]);
        assert!(cli.is_ok(), "should parse audit export with limit: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action:
                    AuditCommands::Export {
                        config,
                        format,
                        limit,
                        follow,
                    },
            } => {
                assert_eq!(config, Some("myagent".to_string()));
                assert_eq!(format, "csv");
                assert_eq!(limit, 500);
                assert!(!follow);
            }
            _ => panic!("expected Audit Export command"),
        }
    }

    #[test]
    fn cli_parse_list() {
        let cli = Cli::try_parse_from(["aegis", "list"]);
        assert!(cli.is_ok(), "should parse list: {cli:?}");
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Some(Commands::List)));
    }

    #[test]
    fn cli_parse_verbose_flag() {
        let cli = Cli::try_parse_from(["aegis", "--verbose", "list"]);
        assert!(cli.is_ok(), "should parse --verbose: {cli:?}");
        let cli = cli.unwrap();
        assert!(cli.verbose);
        assert!(!cli.quiet);
    }

    #[test]
    fn cli_parse_quiet_flag() {
        let cli = Cli::try_parse_from(["aegis", "--quiet", "list"]);
        assert!(cli.is_ok(), "should parse --quiet: {cli:?}");
        let cli = cli.unwrap();
        assert!(!cli.verbose);
        assert!(cli.quiet);
    }

    #[test]
    fn cli_parse_setup() {
        let cli = Cli::try_parse_from(["aegis", "setup"]);
        assert!(cli.is_ok(), "should parse setup: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Setup => {}
            _ => panic!("expected Setup command"),
        }
    }

    #[test]
    fn cli_parse_wrap_defaults() {
        let cli = Cli::try_parse_from(["aegis", "wrap", "--", "claude", "--help"]);
        assert!(cli.is_ok(), "should parse wrap with defaults: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Wrap {
                dir,
                policy,
                name,
                tag,
                seatbelt,
                command,
            } => {
                assert!(dir.is_none());
                assert_eq!(policy, "permit-all");
                assert!(name.is_none());
                assert!(tag.is_none());
                assert!(!seatbelt);
                assert_eq!(command, vec!["claude", "--help"]);
            }
            _ => panic!("expected Wrap command"),
        }
    }

    #[test]
    fn cli_parse_wrap_with_options() {
        let cli = Cli::try_parse_from([
            "aegis",
            "wrap",
            "--dir",
            "/tmp/project",
            "--policy",
            "allow-read-only",
            "--name",
            "my-agent",
            "--",
            "python3",
            "script.py",
        ]);
        assert!(cli.is_ok(), "should parse wrap with options: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Wrap {
                dir,
                policy,
                name,
                command,
                ..
            } => {
                assert_eq!(dir, Some(PathBuf::from("/tmp/project")));
                assert_eq!(policy, "allow-read-only");
                assert_eq!(name, Some("my-agent".to_string()));
                assert_eq!(command, vec!["python3", "script.py"]);
            }
            _ => panic!("expected Wrap command"),
        }
    }

    #[test]
    fn cli_parse_wrap_without_double_dash() {
        // The key UX improvement: `aegis wrap claude` should work without `--`
        let cli = Cli::try_parse_from(["aegis", "wrap", "claude"]);
        assert!(cli.is_ok(), "should parse wrap without --: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Wrap { command, .. } => {
                assert_eq!(command, vec!["claude"]);
            }
            _ => panic!("expected Wrap command"),
        }
    }

    #[test]
    fn cli_parse_run_without_double_dash() {
        let cli = Cli::try_parse_from(["aegis", "run", "echo", "hello"]);
        assert!(cli.is_ok(), "should parse run without --: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Run { command, .. } => {
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_completions() {
        let cli = Cli::try_parse_from(["aegis", "completions", "zsh"]);
        assert!(cli.is_ok(), "should parse completions: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Zsh);
            }
            _ => panic!("expected Completions command"),
        }
    }

    #[test]
    fn cli_parse_completions_bash() {
        let cli = Cli::try_parse_from(["aegis", "completions", "bash"]);
        assert!(cli.is_ok(), "should parse completions bash: {cli:?}");
    }

    #[test]
    fn cli_parse_manpage() {
        let cli = Cli::try_parse_from(["aegis", "manpage"]);
        assert!(cli.is_ok(), "should parse manpage: {cli:?}");
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Some(Commands::Manpage)));
    }

    #[test]
    fn cli_parse_completions_invalid_shell() {
        let result = Cli::try_parse_from(["aegis", "completions", "invalid"]);
        assert!(result.is_err(), "invalid shell should fail");
    }

    #[test]
    fn cli_missing_required_args_fails() {
        // run without any command should fail
        let result = Cli::try_parse_from(["aegis", "run"]);
        assert!(result.is_err(), "run without command should fail");
    }

    #[test]
    fn cli_parse_status_no_config() {
        let cli = Cli::try_parse_from(["aegis", "status"]);
        assert!(cli.is_ok(), "status without config should parse: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Status { config } => {
                assert!(config.is_none(), "config should be None when omitted");
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn cli_parse_use_set() {
        let cli = Cli::try_parse_from(["aegis", "use", "myconfig"]);
        assert!(cli.is_ok(), "use with name should parse: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Use { name } => {
                assert_eq!(name, Some("myconfig".to_string()));
            }
            _ => panic!("expected Use command"),
        }
    }

    #[test]
    fn cli_parse_use_show() {
        let cli = Cli::try_parse_from(["aegis", "use"]);
        assert!(cli.is_ok(), "use without name should parse: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Use { name } => {
                assert!(name.is_none(), "name should be None for bare use");
            }
            _ => panic!("expected Use command"),
        }
    }

    #[test]
    fn cli_parse_monitor_no_config() {
        let cli = Cli::try_parse_from(["aegis", "monitor"]);
        assert!(cli.is_ok(), "monitor without config should parse: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Monitor { config } => {
                assert!(config.is_none(), "config should be None when omitted");
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn cli_parse_audit_query_no_config() {
        let cli = Cli::try_parse_from(["aegis", "audit", "query", "--last", "50"]);
        assert!(
            cli.is_ok(),
            "audit query without config should parse: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Audit {
                action: AuditCommands::Query { config, last, .. },
            } => {
                assert!(config.is_none(), "config should be None when omitted");
                assert_eq!(last, Some(50));
            }
            _ => panic!("expected Audit Query command"),
        }
    }

    #[test]
    fn cli_bare_aegis_no_subcommand() {
        let cli = Cli::try_parse_from(["aegis"]);
        assert!(cli.is_ok(), "bare aegis should parse: {cli:?}");
        let cli = cli.unwrap();
        assert!(
            cli.command.is_none(),
            "command should be None for bare aegis"
        );
    }

    #[test]
    fn init_creates_config_and_dirs() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("test-agent");

        let result = commands::init::run_in_dir("test-agent", "default-deny", &base, None);
        assert!(result.is_ok(), "init should succeed: {result:?}");

        assert!(base.exists(), "base dir should exist");
        assert!(
            base.join(aegis_types::CONFIG_FILENAME).exists(),
            "config should exist"
        );
        assert!(
            base.join("policies")
                .join(aegis_types::DEFAULT_POLICY_FILENAME)
                .exists(),
            "policy file should exist"
        );
        assert!(base.join("sandbox").exists(), "sandbox dir should exist");

        // Verify the config can be loaded back
        let config = commands::init::load_config_from_dir(&base);
        assert!(config.is_ok(), "config should load: {config:?}");
        let config = config.unwrap();
        assert_eq!(config.name, "test-agent");
    }

    #[test]
    fn init_rejects_duplicate_name() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("duplicate-agent");

        let result = commands::init::run_in_dir("duplicate-agent", "default-deny", &base, None);
        assert!(result.is_ok(), "first init should succeed");

        let result = commands::init::run_in_dir("duplicate-agent", "default-deny", &base, None);
        assert!(result.is_err(), "second init with same name should fail");
    }

    #[test]
    fn init_with_dir_sets_sandbox_dir() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("dir-agent");
        let project_dir = tmpdir.path().join("my-project");
        std::fs::create_dir_all(&project_dir).expect("failed to create project dir");

        let result =
            commands::init::run_in_dir("dir-agent", "default-deny", &base, Some(&project_dir));
        assert!(result.is_ok(), "init with --dir should succeed: {result:?}");

        let config = commands::init::load_config_from_dir(&base).expect("config should load");
        // sandbox_dir should point to the project dir, not base/sandbox
        assert_eq!(config.sandbox_dir, project_dir.canonicalize().unwrap(),);
        // The dedicated sandbox/ subdir should NOT have been created
        assert!(!base.join("sandbox").exists());
    }

    #[test]
    fn cli_parse_watch_defaults() {
        let cli = Cli::try_parse_from(["aegis", "watch"]);
        assert!(cli.is_ok(), "should parse watch with defaults: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Watch {
                dir,
                policy,
                name,
                tag,
                idle_timeout,
                stop,
            } => {
                assert!(dir.is_none());
                assert_eq!(policy, "permit-all");
                assert!(name.is_none());
                assert!(tag.is_none());
                assert_eq!(idle_timeout, 300);
                assert!(!stop);
            }
            _ => panic!("expected Watch command"),
        }
    }

    #[test]
    fn cli_parse_watch_with_options() {
        let cli = Cli::try_parse_from([
            "aegis",
            "watch",
            "--dir",
            "/tmp/project",
            "--name",
            "myproject",
            "--policy",
            "default-deny",
            "--tag",
            "sprint-42",
            "--idle-timeout",
            "600",
        ]);
        assert!(cli.is_ok(), "should parse watch with options: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Watch {
                dir,
                policy,
                name,
                tag,
                idle_timeout,
                stop,
            } => {
                assert_eq!(dir, Some(PathBuf::from("/tmp/project")));
                assert_eq!(policy, "default-deny");
                assert_eq!(name, Some("myproject".to_string()));
                assert_eq!(tag, Some("sprint-42".to_string()));
                assert_eq!(idle_timeout, 600);
                assert!(!stop);
            }
            _ => panic!("expected Watch command"),
        }
    }

    #[test]
    fn cli_parse_watch_stop() {
        let cli = Cli::try_parse_from(["aegis", "watch", "--name", "myproject", "--stop"]);
        assert!(cli.is_ok(), "should parse watch --stop: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Watch { name, stop, .. } => {
                assert_eq!(name, Some("myproject".to_string()));
                assert!(stop);
            }
            _ => panic!("expected Watch command"),
        }
    }

    #[test]
    fn cli_parse_fleet() {
        let cli = Cli::try_parse_from(["aegis", "fleet"]);
        assert!(cli.is_ok(), "should parse fleet: {cli:?}");
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Some(Commands::Fleet)));
    }

    #[test]
    fn cli_parse_daemon_approve() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "approve",
            "claude-1",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(cli.is_ok(), "should parse daemon approve: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Approve { name, request_id },
            } => {
                assert_eq!(name, "claude-1");
                assert_eq!(request_id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Daemon Approve command"),
        }
    }

    #[test]
    fn cli_parse_daemon_deny() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "deny",
            "claude-1",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(cli.is_ok(), "should parse daemon deny: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Deny { name, request_id },
            } => {
                assert_eq!(name, "claude-1");
                assert_eq!(request_id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Daemon Deny command"),
        }
    }

    #[test]
    fn cli_parse_daemon_nudge() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "nudge", "claude-1", "wake up"]);
        assert!(cli.is_ok(), "should parse daemon nudge: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Nudge { name, message },
            } => {
                assert_eq!(name, "claude-1");
                assert_eq!(message, Some("wake up".to_string()));
            }
            _ => panic!("expected Daemon Nudge command"),
        }
    }

    #[test]
    fn cli_parse_daemon_nudge_no_message() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "nudge", "claude-1"]);
        assert!(
            cli.is_ok(),
            "should parse daemon nudge without message: {cli:?}"
        );
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Nudge { name, message },
            } => {
                assert_eq!(name, "claude-1");
                assert!(message.is_none());
            }
            _ => panic!("expected Daemon Nudge command"),
        }
    }

    #[test]
    fn cli_parse_daemon_pending() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "pending", "claude-1"]);
        assert!(cli.is_ok(), "should parse daemon pending: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Pending { name },
            } => {
                assert_eq!(name, "claude-1");
            }
            _ => panic!("expected Daemon Pending command"),
        }
    }

    #[test]
    fn cli_parse_daemon_capabilities() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "capabilities", "claude-1"]);
        assert!(cli.is_ok(), "should parse daemon capabilities: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Capabilities { name },
            } => {
                assert_eq!(name, "claude-1");
            }
            _ => panic!("expected Daemon Capabilities command"),
        }
    }

    #[test]
    fn cli_parse_daemon_tool() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "tool",
            "claude-1",
            "{\"action\":\"mouse_click\",\"x\":1,\"y\":2,\"button\":\"left\"}",
        ]);
        assert!(cli.is_ok(), "should parse daemon tool: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Tool { name, action_json },
            } => {
                assert_eq!(name, "claude-1");
                assert!(action_json.contains("mouse_click"));
            }
            _ => panic!("expected Daemon Tool command"),
        }
    }

    #[test]
    fn cli_parse_daemon_tool_batch() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "tool-batch",
            "claude-1",
            "[{\"action\":\"mouse_move\",\"x\":1,\"y\":2}]",
            "--max-actions",
            "3",
        ]);
        assert!(cli.is_ok(), "should parse daemon tool-batch: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action:
                    DaemonCommands::ToolBatch {
                        name,
                        actions_json,
                        max_actions,
                    },
            } => {
                assert_eq!(name, "claude-1");
                assert!(actions_json.contains("mouse_move"));
                assert_eq!(max_actions, Some(3));
            }
            _ => panic!("expected Daemon ToolBatch command"),
        }
    }

    #[test]
    fn cli_parse_daemon_capture_start() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "capture-start",
            "claude-1",
            "--fps",
            "45",
        ]);
        assert!(cli.is_ok(), "should parse daemon capture-start: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::CaptureStart { name, fps },
            } => {
                assert_eq!(name, "claude-1");
                assert_eq!(fps, 45);
            }
            _ => panic!("expected Daemon CaptureStart command"),
        }
    }

    #[test]
    fn cli_parse_daemon_capture_stop() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "capture-stop", "claude-1", "cap-123"]);
        assert!(cli.is_ok(), "should parse daemon capture-stop: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::CaptureStop { name, session_id },
            } => {
                assert_eq!(name, "claude-1");
                assert_eq!(session_id, "cap-123");
            }
            _ => panic!("expected Daemon CaptureStop command"),
        }
    }

    #[test]
    fn cli_parse_daemon_latest_frame() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "latest-frame",
            "claude-1",
            "--x",
            "1",
            "--y",
            "2",
            "--width",
            "3",
            "--height",
            "4",
        ]);
        assert!(cli.is_ok(), "should parse daemon latest-frame: {cli:?}");
    }

    #[test]
    fn cli_parse_daemon_browser_profile() {
        let cli = Cli::try_parse_from([
            "aegis",
            "daemon",
            "browser-profile",
            "claude-1",
            "browser-1",
            "--headless",
            "--url",
            "https://example.com",
        ]);
        assert!(cli.is_ok(), "should parse daemon browser-profile: {cli:?}");
    }

    #[test]
    fn cli_parse_telegram_setup() {
        let cli = Cli::try_parse_from(["aegis", "telegram", "setup"]);
        assert!(cli.is_ok(), "should parse telegram setup: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Telegram {
                action: TelegramCommands::Setup,
            } => {}
            _ => panic!("expected Telegram Setup command"),
        }
    }

    #[test]
    fn cli_parse_telegram_status() {
        let cli = Cli::try_parse_from(["aegis", "telegram", "status"]);
        assert!(cli.is_ok(), "should parse telegram status: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Telegram {
                action: TelegramCommands::Status,
            } => {}
            _ => panic!("expected Telegram Status command"),
        }
    }

    #[test]
    fn cli_parse_telegram_disable() {
        let cli = Cli::try_parse_from(["aegis", "telegram", "disable"]);
        assert!(cli.is_ok(), "should parse telegram disable: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Telegram {
                action: TelegramCommands::Disable,
            } => {}
            _ => panic!("expected Telegram Disable command"),
        }
    }

    #[test]
    fn cli_parse_daemon_config_show() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "config", "show"]);
        assert!(cli.is_ok(), "should parse daemon config show: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action:
                    DaemonCommands::Config {
                        action: DaemonConfigCommands::Show,
                    },
            } => {}
            _ => panic!("expected Daemon Config Show command"),
        }
    }

    #[test]
    fn cli_parse_daemon_config_edit() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "config", "edit"]);
        assert!(cli.is_ok(), "should parse daemon config edit: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action:
                    DaemonCommands::Config {
                        action: DaemonConfigCommands::Edit,
                    },
            } => {}
            _ => panic!("expected Daemon Config Edit command"),
        }
    }

    #[test]
    fn cli_parse_daemon_config_path() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "config", "path"]);
        assert!(cli.is_ok(), "should parse daemon config path: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action:
                    DaemonCommands::Config {
                        action: DaemonConfigCommands::Path,
                    },
            } => {}
            _ => panic!("expected Daemon Config Path command"),
        }
    }

    #[test]
    fn cli_parse_daemon_reload() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "reload"]);
        assert!(cli.is_ok(), "should parse daemon reload: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Reload,
            } => {}
            _ => panic!("expected Daemon Reload command"),
        }
    }

    #[test]
    fn cli_parse_daemon_add() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "add"]);
        assert!(cli.is_ok(), "should parse daemon add: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Add,
            } => {}
            _ => panic!("expected Daemon Add command"),
        }
    }

    #[test]
    fn cli_parse_daemon_remove() {
        let cli = Cli::try_parse_from(["aegis", "daemon", "remove", "claude-1"]);
        assert!(cli.is_ok(), "should parse daemon remove: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Daemon {
                action: DaemonCommands::Remove { name },
            } => {
                assert_eq!(name, "claude-1");
            }
            _ => panic!("expected Daemon Remove command"),
        }
    }

    #[test]
    fn cli_parse_hook_pre_tool_use() {
        let cli = Cli::try_parse_from(["aegis", "hook", "pre-tool-use"]);
        assert!(cli.is_ok(), "should parse hook pre-tool-use: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Hook {
                action: HookCommands::PreToolUse,
            } => {}
            _ => panic!("expected Hook PreToolUse command"),
        }
    }

    #[test]
    fn cli_parse_hook_show_settings() {
        let cli = Cli::try_parse_from(["aegis", "hook", "show-settings"]);
        assert!(cli.is_ok(), "should parse hook show-settings: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Hook {
                action: HookCommands::ShowSettings,
            } => {}
            _ => panic!("expected Hook ShowSettings command"),
        }
    }

    #[test]
    fn cli_parse_hook_install() {
        let cli = Cli::try_parse_from(["aegis", "hook", "install"]);
        assert!(cli.is_ok(), "should parse hook install: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Hook {
                action: HookCommands::Install { dir },
            } => {
                assert!(dir.is_none());
            }
            _ => panic!("expected Hook Install command"),
        }
    }

    #[test]
    fn cli_parse_hook_install_with_dir() {
        let cli = Cli::try_parse_from(["aegis", "hook", "install", "--dir", "/tmp/project"]);
        assert!(cli.is_ok(), "should parse hook install with dir: {cli:?}");
        let cli = cli.unwrap();
        match cli.command.unwrap() {
            Commands::Hook {
                action: HookCommands::Install { dir },
            } => {
                assert_eq!(dir, Some(PathBuf::from("/tmp/project")));
            }
            _ => panic!("expected Hook Install command"),
        }
    }
}
