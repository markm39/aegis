//! Aegis Probe CLI: AI agent security testing.
//!
//! Usage:
//!   aegis-probe run [--agent claude-code|codex|openclaw] [--probes-dir path] [--timeout secs]
//!   aegis-probe list [--probes-dir path]
//!   aegis-probe validate [--probes-dir path]

use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

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

        /// Dry run: validate and list matching probes without executing them.
        #[arg(long)]
        dry_run: bool,

        /// Number of probes to run in parallel (default: 1, sequential).
        #[arg(short, long, default_value = "1")]
        jobs: usize,

        /// Enable anonymous telemetry collection (or set AEGIS_TELEMETRY=1).
        #[arg(long)]
        telemetry: bool,
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

    /// Compare two JSON reports to show security changes.
    Compare {
        /// Path to the baseline (older) report.
        baseline: PathBuf,
        /// Path to the current (newer) report.
        current: PathBuf,
    },

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },

    /// View or manage local telemetry data.
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Show telemetry status and event count.
    Status,
    /// Export telemetry events as JSON.
    Export,
    /// Delete all local telemetry data.
    Clear,
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
            dry_run,
            jobs,
            telemetry,
        } => {
            // Enable telemetry via flag
            if telemetry {
                std::env::set_var("AEGIS_TELEMETRY", "1");
            }

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
                dry_run,
                jobs: jobs.max(1),
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
        Command::Compare { baseline, current } => {
            cmd_compare(&baseline, &current);
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "aegis-probe",
                &mut std::io::stdout(),
            );
        }
        Command::Telemetry { action } => {
            cmd_telemetry(action);
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
    dry_run: bool,
    jobs: usize,
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

    // Dry run: just list what would run
    if opts.dry_run {
        eprintln!(
            "\nDry run: {} probes would run against {:?}\n",
            filtered.len(),
            target
        );
        for (path, probe) in &filtered {
            eprintln!(
                "  {} ({:?}, {:?}) -- {}",
                probe.probe.name,
                probe.probe.category,
                probe.probe.severity,
                path.display()
            );
        }
        eprintln!();
        return;
    }

    let jobs = opts.jobs;
    eprintln!(
        "\nRunning {} probes against {:?}{}...\n",
        filtered.len(),
        target,
        if jobs > 1 {
            format!(" ({jobs} parallel)")
        } else {
            String::new()
        }
    );

    // Run probes -- sequential (jobs=1) or parallel (jobs>1)
    let results = if jobs <= 1 {
        run_probes_sequential(&filtered, &config, &target, opts.verbose)
    } else {
        run_probes_parallel(&filtered, &config, &target, jobs)
    };

    // Generate final report
    let agent_name = format!("{target:?}");
    let final_report = scoring::compute_report(&agent_name, results);

    // Record telemetry if enabled
    aegis_probe::telemetry::record_report(&final_report);

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

fn cmd_compare(baseline_path: &Path, current_path: &Path) {
    let load_report = |path: &Path| -> scoring::SecurityReport {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading {}: {e}", path.display());
                process::exit(1);
            }
        };
        match serde_json::from_str(&data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error parsing {}: {e}", path.display());
                process::exit(1);
            }
        }
    };

    let baseline = load_report(baseline_path);
    let current = load_report(current_path);

    // Score delta
    let score_delta = current.score as i32 - baseline.score as i32;
    let delta_str = if score_delta > 0 {
        format!("+{score_delta}")
    } else {
        format!("{score_delta}")
    };
    println!(
        "\nScore: {} -> {} ({})",
        baseline.score, current.score, delta_str,
    );
    println!(
        "Agent: {} -> {}",
        baseline.agent, current.agent
    );

    // Build probe result maps
    let baseline_map: std::collections::HashMap<&str, &scoring::ProbeResult> = baseline
        .results
        .iter()
        .map(|r| (r.probe_name.as_str(), r))
        .collect();
    let current_map: std::collections::HashMap<&str, &scoring::ProbeResult> = current
        .results
        .iter()
        .map(|r| (r.probe_name.as_str(), r))
        .collect();

    // Find regressions (was pass/partial, now fail)
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut new_probes = Vec::new();
    let mut removed_probes = Vec::new();

    for result in &current.results {
        match baseline_map.get(result.probe_name.as_str()) {
            Some(baseline_result) => {
                let old_v = &baseline_result.verdict;
                let new_v = &result.verdict;
                if verdict_rank(new_v) > verdict_rank(old_v) {
                    regressions.push((&result.probe_name, old_v, new_v));
                } else if verdict_rank(new_v) < verdict_rank(old_v) {
                    improvements.push((&result.probe_name, old_v, new_v));
                }
            }
            None => {
                new_probes.push(&result.probe_name);
            }
        }
    }

    for result in &baseline.results {
        if !current_map.contains_key(result.probe_name.as_str()) {
            removed_probes.push(&result.probe_name);
        }
    }

    if !regressions.is_empty() {
        println!("\nRegressions ({}):", regressions.len());
        for (name, old, new) in &regressions {
            println!("  {name}: {old:?} -> {new:?}");
        }
    }

    if !improvements.is_empty() {
        println!("\nImprovements ({}):", improvements.len());
        for (name, old, new) in &improvements {
            println!("  {name}: {old:?} -> {new:?}");
        }
    }

    if !new_probes.is_empty() {
        println!("\nNew probes ({}):", new_probes.len());
        for name in &new_probes {
            let v = &current_map[name.as_str()].verdict;
            println!("  {name}: {v:?}");
        }
    }

    if !removed_probes.is_empty() {
        println!("\nRemoved probes ({}):", removed_probes.len());
        for name in &removed_probes {
            println!("  {name}");
        }
    }

    if regressions.is_empty() && improvements.is_empty() && new_probes.is_empty() && removed_probes.is_empty() {
        println!("\nNo changes between reports.");
    }

    println!();

    if !regressions.is_empty() {
        process::exit(1);
    }
}

/// Rank verdicts for comparison (lower = better).
fn verdict_rank(v: &scoring::Verdict) -> u8 {
    match v {
        scoring::Verdict::Pass => 0,
        scoring::Verdict::Partial => 1,
        scoring::Verdict::Error => 2,
        scoring::Verdict::Fail => 3,
    }
}

fn cmd_telemetry(action: TelemetryAction) {
    let path = aegis_probe::telemetry::default_telemetry_path();

    match action {
        TelemetryAction::Status => {
            let enabled = aegis_probe::telemetry::is_enabled();
            println!("Telemetry: {}", if enabled { "enabled" } else { "disabled" });
            println!("Data file: {}", path.display());

            if path.exists() {
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                let count = content.lines().filter(|l| !l.is_empty()).count();
                let size = std::fs::metadata(&path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                println!("Events: {count}");
                println!("Size: {:.1} KB", size as f64 / 1024.0);
            } else {
                println!("Events: 0 (no data file)");
            }

            println!("\nTo enable: aegis-probe run --telemetry");
            println!("Or set:    AEGIS_TELEMETRY=1");
        }
        TelemetryAction::Export => {
            if !path.exists() {
                eprintln!("No telemetry data found at {}", path.display());
                process::exit(1);
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error reading {}: {e}", path.display());
                    process::exit(1);
                }
            };

            // Parse JSONL into JSON array
            let events: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();

            match serde_json::to_string_pretty(&events) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("Error serializing: {e}");
                    process::exit(1);
                }
            }
        }
        TelemetryAction::Clear => {
            if path.exists() {
                match std::fs::remove_file(&path) {
                    Ok(()) => println!("Telemetry data cleared: {}", path.display()),
                    Err(e) => {
                        eprintln!("Error deleting {}: {e}", path.display());
                        process::exit(1);
                    }
                }
            } else {
                println!("No telemetry data to clear.");
            }
        }
    }
}

fn run_probes_sequential(
    probes: &[(PathBuf, testcase::Probe)],
    config: &RunnerConfig,
    target: &AgentTarget,
    verbose: bool,
) -> Vec<scoring::ProbeResult> {
    let mut results = Vec::with_capacity(probes.len());

    for (i, (_path, probe)) in probes.iter().enumerate() {
        eprintln!(
            "[{}/{}] {} ({:?}, {:?})",
            i + 1,
            probes.len(),
            probe.probe.name,
            probe.probe.category,
            probe.probe.severity,
        );

        match runner::run_probe(probe, config) {
            Ok(result) => {
                let icon = match result.verdict {
                    scoring::Verdict::Pass => "PASS",
                    scoring::Verdict::Partial => "PARTIAL",
                    scoring::Verdict::Error => "ERROR",
                    scoring::Verdict::Fail => "FAIL",
                };
                eprintln!("        -> {icon}");
                if verbose {
                    for finding in &result.findings {
                        eprintln!("           {:?}: {}", finding.severity, finding.description);
                    }
                }
                results.push(result);
            }
            Err(e) => {
                eprintln!("        -> ERROR: {e}");
                results.push(scoring::ProbeResult {
                    probe_name: probe.probe.name.clone(),
                    category: probe.probe.category,
                    severity: probe.probe.severity,
                    verdict: scoring::Verdict::Error,
                    findings: vec![scoring::Finding {
                        description: format!("Runner error: {e}"),
                        kind: scoring::FindingKind::ForbiddenAction,
                        severity: testcase::Severity::Critical,
                        evidence: None,
                    }],
                    agent: format!("{target:?}"),
                    duration_ms: 0,
                    timestamp: chrono::Utc::now(),
                });
            }
        }
    }

    results
}

fn run_probes_parallel(
    probes: &[(PathBuf, testcase::Probe)],
    config: &RunnerConfig,
    target: &AgentTarget,
    jobs: usize,
) -> Vec<scoring::ProbeResult> {
    let total = probes.len();
    let counter = Arc::new(Mutex::new(0usize));
    let results: Arc<Mutex<Vec<(usize, scoring::ProbeResult)>>> =
        Arc::new(Mutex::new(Vec::with_capacity(total)));

    std::thread::scope(|scope| {
        let work_index = Arc::new(Mutex::new(0usize));

        for _ in 0..jobs {
            let work_index = Arc::clone(&work_index);
            let counter = Arc::clone(&counter);
            let results = Arc::clone(&results);

            scope.spawn(move || {
                loop {
                    let idx = {
                        let mut wi = work_index.lock().unwrap();
                        let i = *wi;
                        if i >= total {
                            return;
                        }
                        *wi += 1;
                        i
                    };

                    let (_path, probe) = &probes[idx];

                    let seq = {
                        let mut c = counter.lock().unwrap();
                        *c += 1;
                        *c
                    };

                    eprintln!(
                        "[{}/{}] {} ({:?}, {:?})",
                        seq,
                        total,
                        probe.probe.name,
                        probe.probe.category,
                        probe.probe.severity,
                    );

                    let result = match runner::run_probe(probe, config) {
                        Ok(r) => {
                            let icon = match r.verdict {
                                scoring::Verdict::Pass => "PASS",
                                scoring::Verdict::Partial => "PARTIAL",
                                scoring::Verdict::Error => "ERROR",
                                scoring::Verdict::Fail => "FAIL",
                            };
                            eprintln!("        -> {icon} ({})", probe.probe.name);
                            r
                        }
                        Err(e) => {
                            eprintln!("        -> ERROR ({}): {e}", probe.probe.name);
                            scoring::ProbeResult {
                                probe_name: probe.probe.name.clone(),
                                category: probe.probe.category,
                                severity: probe.probe.severity,
                                verdict: scoring::Verdict::Error,
                                findings: vec![scoring::Finding {
                                    description: format!("Runner error: {e}"),
                                    kind: scoring::FindingKind::ForbiddenAction,
                                    severity: testcase::Severity::Critical,
                                    evidence: None,
                                }],
                                agent: format!("{target:?}"),
                                duration_ms: 0,
                                timestamp: chrono::Utc::now(),
                            }
                        }
                    };

                    results.lock().unwrap().push((idx, result));
                }
            });
        }
    });

    // Sort by original probe order
    let mut indexed = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    indexed.sort_by_key(|(idx, _)| *idx);
    indexed.into_iter().map(|(_, r)| r).collect()
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
