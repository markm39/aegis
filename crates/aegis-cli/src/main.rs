mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Aegis -- zero-trust runtime for AI agents.
#[derive(Parser, Debug)]
#[command(name = "aegis", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check system requirements and prepare the environment
    Setup,

    /// Initialize a new aegis configuration
    Init {
        /// Name for this agent configuration
        #[arg(long)]
        name: String,

        /// Policy template to use
        #[arg(long, default_value = "default-deny")]
        policy: String,
    },

    /// Run a command inside the aegis sandbox
    Run {
        /// Name of the aegis configuration to use
        #[arg(long)]
        config: String,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Launch the real-time audit monitor TUI
    Monitor {
        /// Name of the aegis configuration to use
        #[arg(long)]
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
        #[arg(long)]
        config: String,

        /// Output format (json or text)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show the health status of an aegis configuration
    Status {
        /// Name of the aegis configuration to check
        #[arg(long)]
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
        #[arg(long)]
        config: String,
    },

    /// Generate a builtin policy template and print to stdout
    Generate {
        /// Template name (default-deny, allow-read-only)
        #[arg(long)]
        template: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Query audit entries with optional filters
    Query {
        /// Name of the aegis configuration
        #[arg(long)]
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
        #[arg(long)]
        config: String,
    },

    /// List recent sessions
    Sessions {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Number of sessions to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Show details for a specific session
    Session {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Session UUID
        #[arg(long)]
        id: String,
    },

    /// Show policy change history
    PolicyHistory {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Number of snapshots to show (default 10)
        #[arg(long, default_value = "10")]
        last: usize,
    },

    /// Export audit entries in a structured format
    Export {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Output format (json, jsonl, csv, cef)
        #[arg(long, default_value = "json")]
        format: String,

        /// Continuously follow new entries (like tail -f)
        #[arg(long)]
        follow: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing with env filter (e.g., RUST_LOG=debug)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => {
            commands::setup::run()
        }
        Commands::Init { name, policy } => {
            commands::init::run(&name, &policy)
        }
        Commands::Run { config, command } => {
            let (cmd, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no command provided after --"))?;
            commands::run::run(&config, cmd, args)
        }
        Commands::Monitor { config } => {
            commands::monitor::run(&config)
        }
        Commands::Policy { action } => match action {
            PolicyCommands::Validate { path } => commands::policy::validate(&path),
            PolicyCommands::List { config } => commands::policy::list(&config),
            PolicyCommands::Generate { template } => commands::policy::generate(&template),
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
            AuditCommands::Export {
                config,
                format,
                follow,
            } => commands::audit::export(&config, &format, follow),
        },
        Commands::Report { config, format } => {
            commands::report::run(&config, &format)
        }
        Commands::Status { config } => {
            commands::status::run(&config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parse_init_defaults() {
        let cli = Cli::try_parse_from(["aegis", "init", "--name", "myagent"]);
        assert!(cli.is_ok(), "should parse init with defaults: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Init { name, policy } => {
                assert_eq!(name, "myagent");
                assert_eq!(policy, "default-deny");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_with_policy() {
        let cli =
            Cli::try_parse_from(["aegis", "init", "--name", "agent2", "--policy", "allow-read-only"]);
        assert!(cli.is_ok(), "should parse init with policy: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Init { name, policy } => {
                assert_eq!(name, "agent2");
                assert_eq!(policy, "allow-read-only");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_run() {
        let cli = Cli::try_parse_from([
            "aegis", "run", "--config", "myagent", "--", "echo", "hello",
        ]);
        assert!(cli.is_ok(), "should parse run: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Run { config, command } => {
                assert_eq!(config, "myagent");
                assert_eq!(command, vec!["echo", "hello"]);
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
            "aegis", "audit", "query", "--config", "myagent", "--last", "50",
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
            "--config",
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
            "aegis", "audit", "sessions", "--config", "myagent", "--last", "5",
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
            "--config",
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
    fn cli_parse_audit_export() {
        let cli = Cli::try_parse_from([
            "aegis",
            "audit",
            "export",
            "--config",
            "myagent",
            "--format",
            "csv",
        ]);
        assert!(cli.is_ok(), "should parse audit export: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Export { config, format, follow },
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
            "--config",
            "myagent",
            "--format",
            "jsonl",
            "--follow",
        ]);
        assert!(cli.is_ok(), "should parse audit export with follow: {cli:?}");
        let cli = cli.unwrap();
        match cli.command {
            Commands::Audit {
                action: AuditCommands::Export { config, format, follow },
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
        let cli = Cli::try_parse_from(["aegis", "status", "--config", "myagent"]);
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
        let cli = Cli::try_parse_from(["aegis", "monitor", "--config", "myagent"]);
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
            Cli::try_parse_from(["aegis", "policy", "list", "--config", "myagent"]);
        assert!(cli.is_ok(), "should parse policy list: {cli:?}");
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
    fn cli_missing_required_args_fails() {
        // init without --name should fail
        let result = Cli::try_parse_from(["aegis", "init"]);
        assert!(result.is_err(), "init without --name should fail");

        // run without --config should fail
        let result = Cli::try_parse_from(["aegis", "run"]);
        assert!(result.is_err(), "run without --config should fail");
    }

    #[test]
    fn init_creates_config_and_dirs() {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
        let base = tmpdir.path().join("test-agent");

        let result = commands::init::run_in_dir("test-agent", "default-deny", &base);
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

        let result = commands::init::run_in_dir("duplicate-agent", "default-deny", &base);
        assert!(result.is_ok(), "first init should succeed");

        let result = commands::init::run_in_dir("duplicate-agent", "default-deny", &base);
        assert!(result.is_err(), "second init with same name should fail");
    }
}
