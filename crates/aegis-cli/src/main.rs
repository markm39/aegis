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
    /// Query recent audit entries
    Query {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Number of most recent entries to display
        #[arg(long, default_value = "20")]
        last: usize,
    },

    /// Verify the integrity of the audit hash chain
    Verify {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,
    },

    /// Export audit entries in a structured format
    Export {
        /// Name of the aegis configuration
        #[arg(long)]
        config: String,

        /// Output format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
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
            AuditCommands::Query { config, last } => commands::audit::query(&config, last),
            AuditCommands::Verify { config } => commands::audit::verify(&config),
            AuditCommands::Export { config, format } => commands::audit::export(&config, &format),
        },
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
                action: AuditCommands::Query { config, last },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(last, 50);
            }
            _ => panic!("expected Audit Query command"),
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
                action: AuditCommands::Export { config, format },
            } => {
                assert_eq!(config, "myagent");
                assert_eq!(format, "csv");
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
