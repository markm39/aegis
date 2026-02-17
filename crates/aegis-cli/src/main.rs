mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
    command: Commands,
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
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Launch the real-time audit monitor TUI
    Monitor {
        /// Name of the aegis configuration to use
        config: String,
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
        /// Name of the aegis configuration
        config: String,

        /// Output format (json or text)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show the health status of an aegis configuration
    Status {
        /// Name of the aegis configuration to check
        config: String,
    },

    /// List all Aegis configurations
    List,

    /// Compare two sessions for forensic analysis
    Diff {
        /// Name of the aegis configuration
        config: String,

        /// First session UUID
        #[arg(long)]
        session1: String,

        /// Second session UUID
        #[arg(long)]
        session2: String,
    },

    /// Configuration management subcommands
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
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

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Show the full configuration for a named config
    Show {
        /// Name of the aegis configuration
        config: String,
    },

    /// Print the path to the config file (for scripting)
    Path {
        /// Name of the aegis configuration
        config: String,
    },

    /// Open the config file in $EDITOR
    Edit {
        /// Name of the aegis configuration
        config: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Validate a .cedar policy file against the Aegis schema
    Validate {
        /// Path to the .cedar policy file
        #[arg(long)]
        path: PathBuf,
    },

    /// List all policies in a configuration
    List {
        /// Name of the aegis configuration
        config: String,
    },

    /// Generate a builtin policy template and print to stdout
    Generate {
        /// Template name (default-deny, allow-read-only)
        #[arg(long)]
        template: String,
    },

    /// Import a Cedar policy file into a configuration
    Import {
        /// Name of the aegis configuration
        config: String,

        /// Path to the .cedar policy file to import
        #[arg(long)]
        path: PathBuf,
    },

    /// Test a policy against a hypothetical action (dry run)
    Test {
        /// Name of the aegis configuration
        config: String,

        /// Action to test (FileRead, FileWrite, FileDelete, DirCreate, DirList, NetConnect, ToolCall, ProcessSpawn, ProcessExit)
        #[arg(long)]
        action: String,

        /// Resource path or identifier to test against
        #[arg(long)]
        resource: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Query audit entries with optional filters
    Query {
        /// Name of the aegis configuration
        config: String,

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
        /// Name of the aegis configuration
        config: String,
    },

    /// List recent sessions
    Sessions {
        /// Name of the aegis configuration
        config: String,

        /// Number of sessions to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Show details for a specific session
    Session {
        /// Name of the aegis configuration
        config: String,

        /// Session UUID
        #[arg(long)]
        id: String,
    },

    /// Show policy change history
    PolicyHistory {
        /// Name of the aegis configuration
        config: String,

        /// Number of snapshots to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Tag a session with a human-readable label
    Tag {
        /// Name of the aegis configuration
        config: String,

        /// Session UUID
        #[arg(long)]
        id: String,

        /// Tag to apply
        #[arg(long)]
        tag: String,
    },

    /// Purge old audit entries (destructive, requires --confirm)
    Purge {
        /// Name of the aegis configuration
        config: String,

        /// Delete entries older than this duration (e.g. 30d, 7d, 24h)
        #[arg(long)]
        older_than: String,

        /// Confirm the destructive operation
        #[arg(long)]
        confirm: bool,
    },

    /// Watch audit events in real-time (like tail -f)
    Watch {
        /// Name of the aegis configuration
        config: String,

        /// Filter by decision (Allow or Deny)
        #[arg(long)]
        decision: Option<String>,
    },

    /// Export audit entries in a structured format
    Export {
        /// Name of the aegis configuration
        config: String,

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

    match cli.command {
        Commands::Setup => {
            commands::setup::run()
        }
        Commands::Init { name, policy, dir } => {
            commands::init::run(name.as_deref(), &policy, dir.as_deref())
        }
        Commands::Run { config, policy, tag, command } => {
            let (cmd, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no command specified; usage: aegis run -- <command> [args...]"))?;
            let config_name = config
                .unwrap_or_else(|| commands::wrap::derive_name(cmd));
            commands::run::run(&config_name, &policy, cmd, args, tag.as_deref())
        }
        Commands::Monitor { config } => {
            commands::monitor::run(&config)
        }
        Commands::Policy { action } => match action {
            PolicyCommands::Validate { path } => commands::policy::validate(&path),
            PolicyCommands::Import { config, path } => {
                commands::policy::import_policy(&config, &path)
            }
            PolicyCommands::List { config } => commands::policy::list(&config),
            PolicyCommands::Generate { template } => commands::policy::generate(&template),
            PolicyCommands::Test {
                config,
                action,
                resource,
            } => commands::policy::test_policy(&config, &action, &resource),
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
            } => commands::audit::query(
                &config, last, from, to, action, decision, principal, search, page, page_size,
            ),
            AuditCommands::Verify { config } => commands::audit::verify(&config),
            AuditCommands::Sessions { config, last } => {
                commands::audit::list_sessions(&config, last)
            }
            AuditCommands::Session { config, id } => commands::audit::show_session(&config, &id),
            AuditCommands::PolicyHistory { config, last } => {
                commands::audit::policy_history(&config, last)
            }
            AuditCommands::Tag { config, id, tag } => {
                commands::audit::tag_session(&config, &id, &tag)
            }
            AuditCommands::Purge {
                config,
                older_than,
                confirm,
            } => commands::audit::purge(&config, &older_than, confirm),
            AuditCommands::Watch { config, decision } => {
                commands::audit::watch(&config, decision.as_deref())
            }
            AuditCommands::Export {
                config,
                format,
                limit,
                follow,
            } => commands::audit::export(&config, &format, limit, follow),
        },
        Commands::Report { config, format } => {
            commands::report::run(&config, &format)
        }
        Commands::Status { config } => {
            commands::status::run(&config)
        }
        Commands::List => {
            commands::list::run()
        }
        Commands::Diff {
            config,
            session1,
            session2,
        } => {
            commands::diff::run(&config, &session1, &session2)
        }
        Commands::Config { action } => match action {
            ConfigCommands::Show { config } => commands::config::show(&config),
            ConfigCommands::Path { config } => commands::config::path(&config),
            ConfigCommands::Edit { config } => commands::config::edit(&config),
        }
        Commands::Wrap {
            dir,
            policy,
            name,
            tag,
            command,
        } => {
            let (cmd, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no command specified; usage: aegis wrap -- <command> [args...]"))?;
            commands::wrap::run(dir.as_deref(), &policy, name.as_deref(), cmd, args, tag.as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parse_init_positional() {
        let cli = Cli::try_parse_from(["aegis", "init", "myagent"]);
        assert!(cli.is_ok(), "should parse init with positional name: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
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
        match cli.command {
            Commands::Init { name, .. } => {
                assert!(name.is_none(), "name should be None for wizard mode");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_with_policy() {
        let cli =
            Cli::try_parse_from(["aegis", "init", "agent2", "--policy", "allow-read-only"]);
        assert!(cli.is_ok(), "should parse init with policy: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
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
        let cli = Cli::try_parse_from([
            "aegis", "init", "agent3", "--dir", "/tmp/my-project",
        ]);
        assert!(cli.is_ok(), "should parse init with dir: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Init { name, dir, .. } => {
                assert_eq!(name, Some("agent3".to_string()));
                assert_eq!(dir, Some(PathBuf::from("/tmp/my-project")));
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_run_with_config() {
        let cli = Cli::try_parse_from([
            "aegis", "run", "--config", "myagent", "--", "echo", "hello",
        ]);
        assert!(cli.is_ok(), "should parse run with --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Run { config, policy, tag, command } => {
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
            "aegis", "run", "--tag", "deploy-v2.1", "--", "echo", "hello",
        ]);
        assert!(cli.is_ok(), "should parse run with --tag: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Run { tag, .. } => {
                assert_eq!(tag, Some("deploy-v2.1".to_string()));
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_run_without_config() {
        let cli = Cli::try_parse_from([
            "aegis", "run", "--", "echo", "hello",
        ]);
        assert!(cli.is_ok(), "should parse run without --config: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Run { config, command, .. } => {
                assert!(config.is_none(), "config should be None when not specified");
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_run_with_policy() {
        let cli = Cli::try_parse_from([
            "aegis", "run", "--policy", "permit-all", "--", "python3", "agent.py",
        ]);
        assert!(cli.is_ok(), "should parse run with --policy: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Run { config, policy, command, .. } => {
                assert!(config.is_none());
                assert_eq!(policy, "permit-all");
                assert_eq!(command, vec!["python3", "agent.py"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn cli_parse_policy_validate() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "validate",
            "--path",
            "/tmp/test.cedar",
        ]);
        assert!(cli.is_ok(), "should parse policy validate: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
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
        let cli = Cli::try_parse_from([
            "aegis", "audit", "query", "myagent", "--last", "50",
        ]);
        assert!(cli.is_ok(), "should parse audit query: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Query { config, last, .. },
            } => {
                assert_eq!(config, "myagent");
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
        match cli.command {
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
                assert_eq!(config, "myagent");
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
        let cli = Cli::try_parse_from([
            "aegis", "audit", "sessions", "myagent", "--last", "5",
        ]);
        assert!(cli.is_ok(), "should parse audit sessions: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Sessions { config, last },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(last, 5);
            }
            _ => panic!("expected Audit Sessions command"),
        }
    }

    #[test]
    fn cli_parse_audit_session_detail() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "session",
            "myagent",
            "--id",
            "550e8400-e29b-41d4-a716-446655440000",
        ]);
        assert!(cli.is_ok(), "should parse audit session: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Session { config, id },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Audit Session command"),
        }
    }

    #[test]
    fn cli_parse_audit_tag() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "tag",
            "myagent",
            "--id",
            "550e8400-e29b-41d4-a716-446655440000",
            "--tag",
            "deploy-v2",
        ]);
        assert!(cli.is_ok(), "should parse audit tag: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Tag { config, id, tag },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(tag, "deploy-v2");
            }
            _ => panic!("expected Audit Tag command"),
        }
    }

    #[test]
    fn cli_parse_audit_purge() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "purge",
            "myagent",
            "--older-than",
            "30d",
            "--confirm",
        ]);
        assert!(cli.is_ok(), "should parse audit purge: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action:
                    AuditCommands::Purge {
                        config,
                        older_than,
                        confirm,
                    },
            } => {
                assert_eq!(config, "myagent");
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
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Watch { config, decision },
            } => {
                assert_eq!(config, "myagent");
                assert!(decision.is_none());
            }
            _ => panic!("expected Audit Watch command"),
        }
    }

    #[test]
    fn cli_parse_audit_watch_with_filter() {
        let cli = Cli::try_parse_from([
            "aegis", "audit", "watch", "myagent", "--decision", "Deny",
        ]);
        assert!(cli.is_ok(), "should parse audit watch with filter: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Watch { config, decision },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(decision, Some("Deny".to_string()));
            }
            _ => panic!("expected Audit Watch command"),
        }
    }

    #[test]
    fn cli_parse_audit_export() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "export",
            "myagent",
            "--format",
            "csv",
        ]);
        assert!(cli.is_ok(), "should parse audit export: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Export { config, format, follow, .. },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(format, "csv");
                assert!(!follow);
            }
            _ => panic!("expected Audit Export command"),
        }
    }

    #[test]
    fn cli_parse_audit_export_follow() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "export",
            "myagent",
            "--format",
            "jsonl",
            "--follow",
        ]);
        assert!(cli.is_ok(), "should parse audit export with follow: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Export { config, format, follow, .. },
            } => {
                assert_eq!(config, "myagent");
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
        match cli.command {
            Commands::Status { config } => {
                assert_eq!(config, "myagent");
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn cli_parse_monitor() {
        let cli = Cli::try_parse_from(["aegis", "monitor", "myagent"]);
        assert!(cli.is_ok(), "should parse monitor: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Monitor { config } => {
                assert_eq!(config, "myagent");
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn cli_parse_policy_list() {
        let cli =
            Cli::try_parse_from(["aegis", "policy", "list", "myagent"]);
        assert!(cli.is_ok(), "should parse policy list: {cli:?}");
    }

    #[test]
    fn cli_parse_policy_import() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "import",
            "myagent",
            "--path",
            "/tmp/custom.cedar",
        ]);
        assert!(cli.is_ok(), "should parse policy import: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Policy {
                action: PolicyCommands::Import { config, path },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(path, PathBuf::from("/tmp/custom.cedar"));
            }
            _ => panic!("expected Policy Import command"),
        }
    }

    #[test]
    fn cli_parse_policy_test() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "test",
            "myagent",
            "--action",
            "FileRead",
            "--resource",
            "/tmp/test.txt",
        ]);
        assert!(cli.is_ok(), "should parse policy test: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Policy {
                action:
                    PolicyCommands::Test {
                        config,
                        action,
                        resource,
                    },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(action, "FileRead");
                assert_eq!(resource, "/tmp/test.txt");
            }
            _ => panic!("expected Policy Test command"),
        }
    }

    #[test]
    fn cli_parse_policy_generate() {
        let cli = Cli::try_parse_from([
            "aegis",
            "policy",
            "generate",
            "--template",
            "default-deny",
        ]);
        assert!(cli.is_ok(), "should parse policy generate: {cli:?}");
    }

    #[test]
    fn cli_parse_diff() {
        let cli = Cli::try_parse_from([
            "aegis",
            "diff",
            "myagent",
            "--session1",
            "550e8400-e29b-41d4-a716-446655440000",
            "--session2",
            "550e8400-e29b-41d4-a716-446655440001",
        ]);
        assert!(cli.is_ok(), "should parse diff: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Diff {
                config,
                session1,
                session2,
            } => {
                assert_eq!(config, "myagent");
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
        match cli.command {
            Commands::Config {
                action: ConfigCommands::Show { config },
            } => {
                assert_eq!(config, "myagent");
            }
            _ => panic!("expected Config Show command"),
        }
    }

    #[test]
    fn cli_parse_config_path() {
        let cli = Cli::try_parse_from(["aegis", "config", "path", "myagent"]);
        assert!(cli.is_ok(), "should parse config path: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Config {
                action: ConfigCommands::Path { config },
            } => {
                assert_eq!(config, "myagent");
            }
            _ => panic!("expected Config Path command"),
        }
    }

    #[test]
    fn cli_parse_config_edit() {
        let cli = Cli::try_parse_from(["aegis", "config", "edit", "myagent"]);
        assert!(cli.is_ok(), "should parse config edit: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Config {
                action: ConfigCommands::Edit { config },
            } => {
                assert_eq!(config, "myagent");
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
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Export { config, format, limit, follow },
            } => {
                assert_eq!(config, "myagent");
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
        assert!(matches!(cli.command, Commands::List));
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
        match cli.command {
            Commands::Setup => {}
            _ => panic!("expected Setup command"),
        }
    }

    #[test]
    fn cli_parse_wrap_defaults() {
        let cli = Cli::try_parse_from(["aegis", "wrap", "--", "claude", "--help"]);
        assert!(cli.is_ok(), "should parse wrap with defaults: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Wrap {
                dir,
                policy,
                name,
                tag,
                command,
            } => {
                assert!(dir.is_none());
                assert_eq!(policy, "permit-all");
                assert!(name.is_none());
                assert!(tag.is_none());
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
        match cli.command {
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
    fn cli_missing_required_args_fails() {
        // run without any command should fail
        let result = Cli::try_parse_from(["aegis", "run"]);
        assert!(result.is_err(), "run without command should fail");

        // status without config should fail
        let result = Cli::try_parse_from(["aegis", "status"]);
        assert!(result.is_err(), "status without config should fail");
    }

    #[test]
    fn init_creates_config_and_dirs() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("test-agent");

        let result = commands::init::run_in_dir("test-agent", "default-deny", &base, None);
        assert!(result.is_ok(), "init should succeed: {result:?}");

        assert!(base.exists(), "base dir should exist");
        assert!(base.join("aegis.toml").exists(), "config should exist");
        assert!(
            base.join("policies").join("default.cedar").exists(),
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
    fn wizard_mode_mapping() {
        use commands::init::SecurityMode;

        let (policy, isolation) = SecurityMode::ObserveOnly.to_config();
        assert_eq!(policy, "permit-all");
        assert!(matches!(isolation, aegis_types::IsolationConfig::Process));

        let (policy, isolation) = SecurityMode::ReadOnlySandbox.to_config();
        assert_eq!(policy, "allow-read-only");
        assert!(matches!(isolation, aegis_types::IsolationConfig::Seatbelt { .. }));

        let (policy, isolation) = SecurityMode::FullLockdown.to_config();
        assert_eq!(policy, "default-deny");
        assert!(matches!(isolation, aegis_types::IsolationConfig::Seatbelt { .. }));
    }

    #[test]
    fn init_with_dir_sets_sandbox_dir() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("dir-agent");
        let project_dir = tmpdir.path().join("my-project");
        std::fs::create_dir_all(&project_dir).expect("failed to create project dir");

        let result = commands::init::run_in_dir(
            "dir-agent",
            "default-deny",
            &base,
            Some(&project_dir),
        );
        assert!(result.is_ok(), "init with --dir should succeed: {result:?}");

        let config = commands::init::load_config_from_dir(&base).expect("config should load");
        // sandbox_dir should point to the project dir, not base/sandbox
        assert_eq!(
            config.sandbox_dir,
            project_dir.canonicalize().unwrap(),
        );
        // The dedicated sandbox/ subdir should NOT have been created
        assert!(!base.join("sandbox").exists());
    }
}
