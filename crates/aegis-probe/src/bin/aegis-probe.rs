//! Aegis Probe CLI: AI agent security testing.
//!
//! Usage:
//!   aegis-probe run [--agent claude-code|codex|openclaw] [--probes-dir path] [--timeout secs]
//!   aegis-probe list [--probes-dir path]
//!   aegis-probe validate [--probes-dir path]

use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use clap::{Parser, Subcommand};

use aegis_probe::report;
use aegis_probe::runner::{self, RunnerConfig};
use aegis_probe::scoring;
use aegis_probe::testcase::{self, AgentTarget, AttackCategory};

#[derive(Parser)]
#[command(
    name = "aegis-probe",
    about = "AI agent security testing -- adversarial probes for coding agents",
    version,
    after_help = "Examples:\n  \
        aegis-probe run                              # Test Claude Code with all probes\n  \
        aegis-probe run --agent codex                # Test Codex\n  \
        aegis-probe run --category prompt_injection  # Only prompt injection probes\n  \
        aegis-probe run -o report.json               # Save JSON report to file\n  \
        aegis-probe list                             # Show available probes\n  \
        aegis-probe validate                         # Check probe files are valid\n  \
        aegis-probe summary report.json              # Print one-line summary from report"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run security probes against an AI agent.
    Run {
        /// Agent to test.
        #[arg(long, default_value = "claude-code")]
        agent: String,

        /// Path to agent binary (auto-detected if not specified).
        #[arg(long)]
        agent_binary: Option<PathBuf>,

        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,

        /// Only run probes in this category.
        #[arg(long)]
        category: Option<String>,

        /// Only run a specific probe by name.
        #[arg(long)]
        probe: Option<String>,

        /// Timeout per probe in seconds.
        #[arg(long, default_value = "120")]
        timeout: u64,

        /// Disable sandbox isolation (not recommended).
        #[arg(long)]
        no_sandbox: bool,

        /// Output format: terminal, json, or html.
        #[arg(long, default_value = "terminal")]
        format: String,

        /// Show verbose output during execution.
        #[arg(short, long)]
        verbose: bool,

        /// Write report to this file (in addition to stdout/stderr).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List available probes.
    List {
        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,

        /// Filter by category.
        #[arg(long)]
        category: Option<String>,
    },

    /// Validate probe files without running them.
    Validate {
        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,
    },

    /// Print a one-line summary from a JSON report file.
    Summary {
        /// Path to JSON report file.
        report: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    match cli.command {
        Command::Run {
            agent,
            agent_binary,
            probes_dir,
            category,
            probe: probe_name,
            timeout,
            no_sandbox,
            format,
            verbose,
            output,
        } => {
            cmd_run(&RunOptions {
                agent: &agent,
                agent_binary,
                probes_dir: &probes_dir,
                category: category.as_deref(),
                probe_name: probe_name.as_deref(),
                timeout,
                no_sandbox,
                format: &format,
                verbose,
                output: output.as_deref(),
            });
        }
        Command::List {
            probes_dir,
            category,
        } => {
            cmd_list(&probes_dir, category.as_deref());
        }
        Command::Validate { probes_dir } => {
            cmd_validate(&probes_dir);
        }
        Command::Summary { report } => {
            cmd_summary(&report);
        }
    }
}

struct RunOptions<'a> {
    agent: &'a str,
    agent_binary: Option<PathBuf>,
    probes_dir: &'a Path,
    category: Option<&'a str>,
    probe_name: Option<&'a str>,
    timeout: u64,
    no_sandbox: bool,
    format: &'a str,
    verbose: bool,
    output: Option<&'a Path>,
}

fn cmd_run(opts: &RunOptions<'_>) {
    // Parse agent target
    let target = parse_agent_target(opts.agent);

    // Resolve agent binary
    let binary = opts
        .agent_binary
        .clone()
        .unwrap_or_else(|| resolve_agent_binary(&target));

    // Load probes
    let probes = match testcase::load_probes(opts.probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading probes from {}: {e}", opts.probes_dir.display());
            process::exit(1);
        }
    };

    if probes.is_empty() {
        eprintln!("No probes found in {}", opts.probes_dir.display());
        process::exit(1);
    }

    // Filter by category if specified
    let category_filter = opts.category.and_then(parse_category);

    // Filter probes
    let filtered: Vec<(PathBuf, testcase::Probe)> = probes
        .into_iter()
        .filter(|(_, p)| {
            // Target filter
            if !p.probe.targets.contains(&target) {
                return false;
            }
            // Category filter
            if let Some(ref cat) = category_filter {
                if p.probe.category != *cat {
                    return false;
                }
            }
            // Name filter
            if let Some(name) = opts.probe_name {
                if p.probe.name != name {
                    return false;
                }
            }
            true
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No matching probes found.");
        process::exit(1);
    }

    // Build runner config
    let config = RunnerConfig {
        target: target.clone(),
        agent_binary: binary,
        agent_args: default_agent_args(&target),
        sandboxed: !opts.no_sandbox,
        timeout_override: Some(Duration::from_secs(opts.timeout)),
        verbose: opts.verbose,
    };

    eprintln!(
        "\nRunning {} probes against {:?}...\n",
        filtered.len(),
        target
    );

    // Run probes with streaming output
    let mut results = Vec::new();
    for (i, (path, probe)) in filtered.iter().enumerate() {
        if opts.verbose {
            eprintln!(
                "[{}/{}] {} ({})",
                i + 1,
                filtered.len(),
                probe.probe.name,
                path.display()
            );
        }

        match runner::run_probe(probe, &config) {
            Ok(result) => {
                // Stream individual result
                eprint!("{}", report::render_probe_result(&result));
                results.push(result);
            }
            Err(e) => {
                eprintln!("  Error running {}: {e}", probe.probe.name);
                results.push(scoring::ProbeResult {
                    probe_name: probe.probe.name.clone(),
                    category: probe.probe.category,
                    severity: probe.probe.severity,
                    verdict: scoring::Verdict::Error,
                    findings: vec![scoring::Finding {
                        description: format!("Execution error: {e}"),
                        kind: scoring::FindingKind::Suspicious,
                        severity: testcase::Severity::Info,
                        evidence: None,
                    }],
                    agent: format!("{target:?}"),
                    duration_ms: 0,
                    timestamp: chrono::Utc::now(),
                });
            }
        }
    }

    // Generate final report
    let agent_name = format!("{target:?}");
    let final_report = scoring::compute_report(&agent_name, results);

    match opts.format {
        "json" => {
            match report::render_json(&final_report) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("Error serializing report: {e}");
                    process::exit(1);
                }
            }
        }
        "html" => {
            print!("{}", report::render_html(&final_report));
        }
        _ => {
            print!("{}", report::render_report(&final_report));
        }
    }

    // Write report to file if --output specified
    if let Some(output_path) = opts.output {
        match report::render_json(&final_report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(output_path, &json) {
                    eprintln!("Error writing report to {}: {e}", output_path.display());
                    process::exit(1);
                }
                eprintln!("\nReport written to {}", output_path.display());
            }
            Err(e) => {
                eprintln!("Error serializing report: {e}");
                process::exit(1);
            }
        }
    }

    // Exit with non-zero code if there are failures
    if final_report.summary.failed > 0 {
        process::exit(1);
    }
}

fn cmd_list(probes_dir: &Path, category: Option<&str>) {
    let probes = match testcase::load_probes(probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading probes: {e}");
            process::exit(1);
        }
    };

    let category_filter = category.and_then(parse_category);

    let filtered: Vec<_> = probes
        .iter()
        .filter(|(_, p)| {
            category_filter
                .as_ref()
                .is_none_or(|cat| p.probe.category == *cat)
        })
        .collect();

    println!("\n{:<35} {:<22} {:<10} Targets", "NAME", "CATEGORY", "SEVERITY");
    println!("{}", "-".repeat(90));

    for (_path, probe) in &filtered {
        let targets: Vec<String> = probe
            .probe
            .targets
            .iter()
            .map(|t| format!("{t:?}"))
            .collect();

        println!(
            "{:<35} {:<22} {:<10} {}",
            probe.probe.name,
            format!("{:?}", probe.probe.category),
            format!("{:?}", probe.probe.severity),
            targets.join(", "),
        );
    }

    println!("\n{} probes total\n", filtered.len());
}

fn cmd_validate(probes_dir: &Path) {
    let mut valid = 0;
    let mut invalid = 0;

    let pattern = probes_dir.join("**/*.toml");
    let pattern_str = pattern.to_string_lossy();

    let entries: Vec<_> = glob::glob(&pattern_str)
        .unwrap_or_else(|e| {
            eprintln!("Invalid glob pattern: {e}");
            process::exit(1);
        })
        .collect();

    if entries.is_empty() {
        eprintln!("No .toml files found in {}", probes_dir.display());
        process::exit(1);
    }

    for entry in entries {
        match entry {
            Ok(path) => match testcase::Probe::from_file(&path) {
                Ok(probe) => {
                    println!("  OK  {} ({})", probe.probe.name, path.display());
                    valid += 1;
                }
                Err(e) => {
                    println!("  ERR {} -- {e}", path.display());
                    invalid += 1;
                }
            },
            Err(e) => {
                println!("  ERR glob error: {e}");
                invalid += 1;
            }
        }
    }

    println!("\n{valid} valid, {invalid} invalid\n");
    if invalid > 0 {
        process::exit(1);
    }
}

fn cmd_summary(report_path: &Path) {
    let data = match std::fs::read_to_string(report_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {e}", report_path.display());
            process::exit(1);
        }
    };

    let report: scoring::SecurityReport = match serde_json::from_str(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing report: {e}");
            process::exit(1);
        }
    };

    println!(
        "Score: {}/100 | {} passed, {} failed, {} partial, {} errors | Agent: {}",
        report.score,
        report.summary.passed,
        report.summary.failed,
        report.summary.partial,
        report.summary.errors,
        report.agent,
    );

    if report.summary.failed > 0 {
        process::exit(1);
    }
}

fn parse_agent_target(s: &str) -> AgentTarget {
    match s.to_lowercase().as_str() {
        "claude-code" | "claude" => AgentTarget::ClaudeCode,
        "codex" => AgentTarget::Codex,
        "openclaw" => AgentTarget::OpenClaw,
        "cursor" => AgentTarget::Cursor,
        "aider" => AgentTarget::Aider,
        other => AgentTarget::Custom(other.to_string()),
    }
}

fn resolve_agent_binary(target: &AgentTarget) -> PathBuf {
    match target {
        AgentTarget::ClaudeCode => PathBuf::from("claude"),
        AgentTarget::Codex => PathBuf::from("codex"),
        AgentTarget::OpenClaw => PathBuf::from("openclaw"),
        AgentTarget::Cursor => PathBuf::from("cursor"),
        AgentTarget::Aider => PathBuf::from("aider"),
        AgentTarget::Custom(name) => PathBuf::from(name),
    }
}

fn default_agent_args(target: &AgentTarget) -> Vec<String> {
    match target {
        AgentTarget::ClaudeCode => {
            vec!["--dangerously-skip-permissions".into()]
        }
        AgentTarget::Codex => {
            vec!["--approval-mode".into(), "full-auto".into()]
        }
        _ => vec![],
    }
}

fn parse_category(s: &str) -> Option<AttackCategory> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "prompt_injection" => Some(AttackCategory::PromptInjection),
        "data_exfiltration" => Some(AttackCategory::DataExfiltration),
        "privilege_escalation" => Some(AttackCategory::PrivilegeEscalation),
        "malicious_execution" => Some(AttackCategory::MaliciousExecution),
        "supply_chain" => Some(AttackCategory::SupplyChain),
        "social_engineering" => Some(AttackCategory::SocialEngineering),
        "credential_harvesting" => Some(AttackCategory::CredentialHarvesting),
        _ => {
            eprintln!("Unknown category: {s}");
            eprintln!("Valid: prompt_injection, data_exfiltration, privilege_escalation,");
            eprintln!("       malicious_execution, supply_chain, social_engineering,");
            eprintln!("       credential_harvesting");
            None
        }
    }
}
