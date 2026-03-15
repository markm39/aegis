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

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use aegis_probe::report;
use aegis_probe::runner::{self, MockMode, RunnerConfig};
use aegis_probe::scoring::{self, ReportContext};
use aegis_probe::testcase::{self, AgentTarget, AttackCategory};

#[derive(Parser)]
#[command(
    name = "aegis-probe",
    about = "Security testing for AI agents and models",
    version,
    after_help = "Examples:\n  \
        aegis-probe run                              # Test Claude Code with all probes\n  \
        aegis-probe run --agent codex                # Test Codex\n  \
        aegis-probe run --agent mock-vulnerable      # Simulate a vulnerable agent (no API needed)\n  \
        aegis-probe run --agent mock-safe            # Simulate a safe agent (no API needed)\n  \
        aegis-probe run --category prompt_injection  # Only prompt injection probes\n  \
        aegis-probe run --tag ci-artifact            # Only probes with a matching tag\n  \
        aegis-probe run --format sarif > report.sarif # Emit SARIF\n  \
        aegis-probe run -o report.json               # Save JSON report to file\n  \
        aegis-probe list                             # Show available probes\n  \
        aegis-probe validate                         # Check probe files are valid\n  \
        aegis-probe registry export report.json      # Export derived-only bundle\n  \
        aegis-probe summary report.json              # Print one-line summary from report\n  \
        aegis-probe render report.json --format sarif # Re-render a saved report"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run security probes against an AI agent.
    Run {
        /// Agent to test: claude-code, codex, openclaw, mock-safe, or mock-vulnerable.
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

        /// Only run probes with one of these tags (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Only run a specific probe by name.
        #[arg(long)]
        probe: Option<String>,

        /// Timeout per probe in seconds.
        #[arg(long, default_value = "120")]
        timeout: u64,

        /// Disable sandbox isolation (not recommended).
        #[arg(long)]
        no_sandbox: bool,

        /// Output format: terminal, json, html, markdown, junit, or sarif.
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

        /// Preserve raw agent output text in results (for fingerprinting/analysis).
        #[arg(long)]
        capture_output: bool,

        /// Exit non-zero when this severity gate is violated.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,

        /// Exit non-zero when the final score is below this threshold.
        #[arg(long)]
        min_score: Option<u32>,
    },

    /// List available probes.
    List {
        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,

        /// Filter by category.
        #[arg(long)]
        category: Option<String>,

        /// Filter by tag (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        tag: Vec<String>,
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

    /// Re-render a saved JSON report in another output format.
    Render {
        /// Path to JSON report file.
        report: PathBuf,

        /// Output format: terminal, json, html, markdown, junit, or sarif.
        #[arg(long, default_value = "terminal")]
        format: String,

        /// Write rendered output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
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

    /// Export or upload derived-only registry bundles.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },

    /// Run the full benchmark suite and output a standardized scorecard.
    Benchmark {
        /// Agents to benchmark (comma-separated, e.g. "claude-code,codex,openclaw").
        #[arg(long, default_value = "claude-code")]
        agents: String,

        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,

        /// Only benchmark probes with one of these tags (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Timeout per probe in seconds.
        #[arg(long, default_value = "120")]
        timeout: u64,

        /// Number of probes to run in parallel per agent.
        #[arg(short, long, default_value = "1")]
        jobs: usize,

        /// Output directory for benchmark reports.
        #[arg(short, long, default_value = "benchmark-results")]
        output_dir: PathBuf,
    },

    /// Extract a behavioral fingerprint from a JSON report.
    Fingerprint {
        /// Path to a JSON report file.
        report: PathBuf,

        /// Generate extended model fingerprint (requires --capture-output in the run).
        #[arg(long)]
        model: bool,
    },

    /// Compare behavioral fingerprints from two JSON reports.
    Similarity {
        /// Path to first report.
        report_a: PathBuf,
        /// Path to second report.
        report_b: PathBuf,
    },

    /// Run probes multiple times and compute statistical aggregates.
    MultiRun {
        /// Agent to test: claude-code, codex, openclaw, mock-safe, or mock-vulnerable.
        #[arg(long, default_value = "claude-code")]
        agent: String,

        /// Number of runs.
        #[arg(long, default_value = "5")]
        runs: usize,

        /// Directory containing probe TOML files.
        #[arg(long, default_value = "probes")]
        probes_dir: PathBuf,

        /// Only run probes in this category.
        #[arg(long)]
        category: Option<String>,

        /// Only run probes with one of these tags (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Only run a specific probe by name.
        #[arg(long)]
        probe: Option<String>,

        /// Timeout per probe in seconds.
        #[arg(long, default_value = "120")]
        timeout: u64,

        /// Disable sandbox isolation (not recommended).
        #[arg(long)]
        no_sandbox: bool,

        /// Output format: terminal, json.
        #[arg(long, default_value = "terminal")]
        format: String,

        /// Write multi-run report to file.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Analyze whether one agent is a distillation of another.
    Distillation {
        /// Path to first agent's JSON report.
        report_a: PathBuf,
        /// Path to second agent's JSON report.
        report_b: PathBuf,
    },
}

#[derive(Subcommand)]
enum RegistryAction {
    /// Show registry configuration and compatibility state.
    Status,
    /// Export a derived-only bundle from a local report.
    Export {
        /// Path to a local JSON report.
        report: PathBuf,
        /// Write the bundle to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Upload a derived-only bundle from a local report.
    Upload {
        /// Path to a local JSON report.
        report: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FailOn {
    Fail,
    Partial,
    Critical,
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
            tag,
            probe: probe_name,
            timeout,
            no_sandbox,
            format,
            verbose,
            output,
            dry_run,
            jobs,
            capture_output,
            fail_on,
            min_score,
        } => {
            cmd_run(&RunOptions {
                agent: &agent,
                agent_binary,
                probes_dir: &probes_dir,
                category: category.as_deref(),
                tags: &tag,
                probe_name: probe_name.as_deref(),
                timeout,
                no_sandbox,
                format: &format,
                verbose,
                output: output.as_deref(),
                dry_run,
                jobs: jobs.max(1),
                capture_output,
                fail_on,
                min_score,
            });
        }
        Command::List {
            probes_dir,
            category,
            tag,
        } => {
            cmd_list(&probes_dir, category.as_deref(), &tag);
        }
        Command::Validate { probes_dir } => {
            cmd_validate(&probes_dir);
        }
        Command::Summary { report } => {
            cmd_summary(&report);
        }
        Command::Render {
            report,
            format,
            output,
        } => {
            cmd_render(&report, &format, output.as_deref());
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
        Command::Registry { action } => {
            cmd_registry(action);
        }
        Command::Benchmark {
            agents,
            probes_dir,
            tag,
            timeout,
            jobs,
            output_dir,
        } => {
            cmd_benchmark(&agents, &probes_dir, &tag, timeout, jobs, &output_dir);
        }
        Command::Fingerprint { report, model } => {
            if model {
                cmd_model_fingerprint(&report);
            } else {
                cmd_fingerprint(&report);
            }
        }
        Command::Similarity { report_a, report_b } => {
            cmd_similarity(&report_a, &report_b);
        }
        Command::MultiRun {
            agent,
            runs,
            probes_dir,
            category,
            tag,
            probe: probe_name,
            timeout,
            no_sandbox,
            format,
            output,
        } => {
            cmd_multi_run(&MultiRunOptions {
                agent: &agent,
                runs,
                probes_dir: &probes_dir,
                category: category.as_deref(),
                tags: &tag,
                probe_name: probe_name.as_deref(),
                timeout,
                no_sandbox,
                format: &format,
                output: output.as_deref(),
            });
        }
        Command::Distillation { report_a, report_b } => {
            cmd_distillation(&report_a, &report_b);
        }
    }
}

struct RunOptions<'a> {
    agent: &'a str,
    agent_binary: Option<PathBuf>,
    probes_dir: &'a Path,
    category: Option<&'a str>,
    tags: &'a [String],
    probe_name: Option<&'a str>,
    timeout: u64,
    no_sandbox: bool,
    format: &'a str,
    verbose: bool,
    output: Option<&'a Path>,
    dry_run: bool,
    jobs: usize,
    capture_output: bool,
    fail_on: Option<FailOn>,
    min_score: Option<u32>,
}

fn cmd_run(opts: &RunOptions<'_>) {
    if opts.min_score.is_some_and(|score| score > 100) {
        eprintln!("--min-score must be between 0 and 100.");
        process::exit(1);
    }

    // Parse agent target
    let target = parse_agent_target_or_exit(opts.agent);

    // Resolve agent binary
    let binary = opts
        .agent_binary
        .clone()
        .unwrap_or_else(|| resolve_agent_binary(&target));

    // Load probes
    let probes = match testcase::load_probes(opts.probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Error loading probes from {}: {e}",
                opts.probes_dir.display()
            );
            process::exit(1);
        }
    };

    if probes.is_empty() {
        eprintln!("No probes found in {}", opts.probes_dir.display());
        process::exit(1);
    }

    // Filter by category and tags if specified
    let category_filter = opts.category.and_then(parse_category);
    let tag_filter = normalized_tag_filter(opts.tags);

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
            if !probe_matches_tag_filter(p, &tag_filter) {
                return false;
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

    let report_context = ReportContext {
        probe_pack_hash: testcase::probe_pack_hash(&filtered),
    };

    // Build runner config
    let config = RunnerConfig {
        target: target.clone(),
        agent_binary: binary,
        agent_args: default_agent_args(&target),
        sandboxed: !opts.no_sandbox,
        timeout_override: Some(Duration::from_secs(opts.timeout)),
        verbose: opts.verbose,
        capture_output: opts.capture_output,
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
    let mock_mode = parse_mock_mode(opts.agent);

    eprintln!(
        "\nRunning {} probes against {}{}...\n",
        filtered.len(),
        if mock_mode.is_some() {
            opts.agent
        } else {
            &format!("{target:?}")
        },
        if jobs > 1 {
            format!(" ({jobs} parallel)")
        } else {
            String::new()
        }
    );

    // Run probes -- mock mode or real agent
    let results = if let Some(mode) = mock_mode {
        run_probes_mock(&filtered, mode)
    } else if jobs <= 1 {
        run_probes_sequential(&filtered, &config, &target, opts.verbose)
    } else {
        run_probes_parallel(&filtered, &config, &target, jobs)
    };

    // Generate final report
    let agent_name = format!("{target:?}");
    let final_report = scoring::compute_report_with_context(&agent_name, results, &report_context);

    match opts.format {
        "json" => match report::render_json(&final_report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing report: {e}");
                process::exit(1);
            }
        },
        "html" => {
            print!("{}", report::render_html(&final_report));
        }
        "markdown" | "md" => {
            print!("{}", report::render_markdown(&final_report));
        }
        "junit" | "xml" => {
            print!("{}", report::render_junit(&final_report));
        }
        "sarif" => match report::render_sarif(&final_report) {
            Ok(sarif) => println!("{sarif}"),
            Err(e) => {
                eprintln!("Error serializing SARIF report: {e}");
                process::exit(1);
            }
        },
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

    if let Some(min_score) = opts.min_score {
        if final_report.score < min_score {
            eprintln!(
                "Score gate failed: report score {} is below required minimum {}.",
                final_report.score, min_score
            );
            process::exit(1);
        }
    }

    if should_fail_run(&final_report, opts.fail_on) {
        process::exit(1);
    }
}

fn cmd_list(probes_dir: &Path, category: Option<&str>, tags: &[String]) {
    let probes = match testcase::load_probes(probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading probes: {e}");
            process::exit(1);
        }
    };

    let category_filter = category.and_then(parse_category);
    let tag_filter = normalized_tag_filter(tags);

    let filtered: Vec<_> = probes
        .iter()
        .filter(|(_, p)| {
            category_filter
                .as_ref()
                .is_none_or(|cat| p.probe.category == *cat)
                && probe_matches_tag_filter(p, &tag_filter)
        })
        .collect();

    println!(
        "\n{:<35} {:<22} {:<10} {:<24} Targets",
        "NAME", "CATEGORY", "SEVERITY", "TAGS"
    );
    println!("{}", "-".repeat(118));

    for (_path, probe) in &filtered {
        let targets: Vec<String> = probe
            .probe
            .targets
            .iter()
            .map(|t| format!("{t:?}"))
            .collect();
        let tags = if probe.probe.tags.is_empty() {
            "-".to_string()
        } else {
            probe.probe.tags.join(", ")
        };

        println!(
            "{:<35} {:<22} {:<10} {:<24} {}",
            probe.probe.name,
            format!("{:?}", probe.probe.category),
            format!("{:?}", probe.probe.severity),
            tags,
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
    let report = load_report(report_path);

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

fn cmd_render(report_path: &Path, format: &str, output_path: Option<&Path>) {
    let report = load_report(report_path);
    let rendered = match render_report_format(&report, format) {
        Ok(rendered) => rendered,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };

    if let Some(path) = output_path {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Error creating {}: {e}", parent.display());
                process::exit(1);
            }
        }
        if let Err(e) = std::fs::write(path, rendered.as_bytes()) {
            eprintln!("Error writing {}: {e}", path.display());
            process::exit(1);
        }
    } else {
        print!("{rendered}");
    }
}

fn cmd_compare(baseline_path: &Path, current_path: &Path) {
    let baseline = load_report(baseline_path);
    let current = load_report(current_path);
    ensure_compatible_reports(&baseline, &current);

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
    println!("Agent: {} -> {}", baseline.agent, current.agent);
    if !current.metadata.probe_pack_hash.is_empty() {
        println!(
            "Probe pack: {}",
            &current.metadata.probe_pack_hash[..current.metadata.probe_pack_hash.len().min(16)]
        );
    }

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

    if regressions.is_empty()
        && improvements.is_empty()
        && new_probes.is_empty()
        && removed_probes.is_empty()
    {
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

fn load_report(path: &Path) -> scoring::SecurityReport {
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
}

fn render_report_format(report: &scoring::SecurityReport, format: &str) -> Result<String, String> {
    match format {
        "json" => report::render_json(report).map_err(|e| format!("Error serializing report: {e}")),
        "html" => Ok(report::render_html(report)),
        "markdown" | "md" => Ok(report::render_markdown(report)),
        "junit" | "xml" => Ok(report::render_junit(report)),
        "sarif" => {
            report::render_sarif(report).map_err(|e| format!("Error serializing SARIF report: {e}"))
        }
        _ => Ok(report::render_report(report)),
    }
}

fn ensure_compatible_reports(a: &scoring::SecurityReport, b: &scoring::SecurityReport) {
    let hash_a = a.metadata.probe_pack_hash.trim();
    let hash_b = b.metadata.probe_pack_hash.trim();
    if !hash_a.is_empty() && !hash_b.is_empty() && hash_a != hash_b {
        eprintln!("Reports were generated from different probe packs.");
        eprintln!("A: {hash_a}");
        eprintln!("B: {hash_b}");
        process::exit(1);
    }
}

fn should_fail_run(report: &scoring::SecurityReport, fail_on: Option<FailOn>) -> bool {
    match fail_on.unwrap_or(FailOn::Fail) {
        FailOn::Fail => report.summary.failed > 0 || report.summary.errors > 0,
        FailOn::Partial => {
            report.summary.partial > 0 || report.summary.failed > 0 || report.summary.errors > 0
        }
        FailOn::Critical => report.summary.critical_findings > 0 || report.summary.errors > 0,
    }
}

fn cmd_fingerprint(report_path: &Path) {
    let report = load_report(report_path);
    let fp = aegis_probe::fingerprint::extract_fingerprint(&report);

    match serde_json::to_string_pretty(&fp) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Error serializing fingerprint: {e}");
            process::exit(1);
        }
    }
}

fn cmd_similarity(path_a: &Path, path_b: &Path) {
    let report_a = load_report(path_a);
    let report_b = load_report(path_b);
    ensure_compatible_reports(&report_a, &report_b);

    let fp_a = aegis_probe::fingerprint::extract_fingerprint(&report_a);
    let fp_b = aegis_probe::fingerprint::extract_fingerprint(&report_b);
    let result = aegis_probe::fingerprint::compare_fingerprints(&fp_a, &fp_b);

    println!(
        "\nBehavioral Similarity: {} vs {}",
        result.agent_a, result.agent_b
    );
    println!("{}", "=".repeat(55));
    println!("Overall similarity: {:.1}%", result.similarity * 100.0);
    println!("Exact behavioral match: {}", result.exact_match);

    println!(
        "\n{:<25} {:>10} {:>10} {:>10}",
        "CATEGORY", &result.agent_a, &result.agent_b, "DELTA"
    );
    println!("{}", "-".repeat(55));

    for cs in &result.category_similarity {
        println!(
            "{:<25} {:>9.0}% {:>9.0}% {:>+9.0}%",
            cs.category,
            cs.rate_a * 100.0,
            cs.rate_b * 100.0,
            (cs.rate_b - cs.rate_a) * 100.0,
        );
    }

    println!("\nFingerprint hashes:");
    println!("  {}: {}", fp_a.agent, &fp_a.behavioral_hash[..16]);
    println!("  {}: {}", fp_b.agent, &fp_b.behavioral_hash[..16]);
    println!();
}

fn cmd_benchmark(
    agents_str: &str,
    probes_dir: &Path,
    tags: &[String],
    timeout: u64,
    jobs: usize,
    output_dir: &Path,
) {
    let agent_names: Vec<&str> = agents_str.split(',').map(|s| s.trim()).collect();

    if agent_names.is_empty() {
        eprintln!("No agents specified.");
        process::exit(1);
    }

    // Load probes
    let probes = match testcase::load_probes(probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading probes: {e}");
            process::exit(1);
        }
    };

    if probes.is_empty() {
        eprintln!("No probes found in {}", probes_dir.display());
        process::exit(1);
    }

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        eprintln!("Error creating output directory: {e}");
        process::exit(1);
    }

    let mut all_reports = Vec::new();
    let tag_filter = normalized_tag_filter(tags);

    for agent_name in &agent_names {
        let target = parse_agent_target_or_exit(agent_name);
        let binary = resolve_agent_binary(&target);

        // Filter probes that target this agent
        let filtered: Vec<(PathBuf, testcase::Probe)> = probes
            .iter()
            .filter(|(_, p)| {
                p.probe.targets.contains(&target) && probe_matches_tag_filter(p, &tag_filter)
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            eprintln!("No probes target {agent_name}, skipping.");
            continue;
        }

        let report_context = ReportContext {
            probe_pack_hash: testcase::probe_pack_hash(&filtered),
        };

        let config = RunnerConfig {
            target: target.clone(),
            agent_binary: binary,
            agent_args: default_agent_args(&target),
            sandboxed: true,
            timeout_override: Some(Duration::from_secs(timeout)),
            verbose: false,
            capture_output: false,
        };

        eprintln!(
            "\n=== Benchmarking {agent_name} ({} probes) ===\n",
            filtered.len()
        );

        let results = if jobs <= 1 {
            run_probes_sequential(&filtered, &config, &target, false)
        } else {
            run_probes_parallel(&filtered, &config, &target, jobs)
        };

        let agent_label = format!("{target:?}");
        let report = scoring::compute_report_with_context(&agent_label, results, &report_context);

        // Write individual report
        let report_path = output_dir.join(format!("{agent_name}.json"));
        match report::render_json(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&report_path, &json) {
                    eprintln!("Error writing report: {e}");
                } else {
                    eprintln!("Report: {}", report_path.display());
                }
            }
            Err(e) => eprintln!("Error serializing report: {e}"),
        }

        // Write HTML report
        let html_path = output_dir.join(format!("{agent_name}.html"));
        let html = report::render_html(&report);
        if let Err(e) = std::fs::write(&html_path, &html) {
            eprintln!("Error writing HTML report: {e}");
        }

        all_reports.push((agent_name.to_string(), report));
    }

    // Print benchmark summary
    eprintln!("\n{}", "=".repeat(60));
    eprintln!("BENCHMARK RESULTS");
    eprintln!("{}", "=".repeat(60));

    println!(
        "\n{:<20} {:>6} {:>8} {:>8} {:>8} {:>8}",
        "AGENT", "SCORE", "PASSED", "FAILED", "PARTIAL", "ERRORS"
    );
    println!("{}", "-".repeat(60));

    for (name, report) in &all_reports {
        println!(
            "{:<20} {:>5}/100 {:>8} {:>8} {:>8} {:>8}",
            name,
            report.score,
            report.summary.passed,
            report.summary.failed,
            report.summary.partial,
            report.summary.errors,
        );
    }
    println!();

    // Per-category breakdown
    println!(
        "{:<20} {:>15} {:>15} {:>15}",
        "CATEGORY",
        all_reports.first().map(|(n, _)| n.as_str()).unwrap_or(""),
        all_reports.get(1).map(|(n, _)| n.as_str()).unwrap_or(""),
        all_reports.get(2).map(|(n, _)| n.as_str()).unwrap_or(""),
    );
    println!("{}", "-".repeat(65));

    let categories = [
        "PromptInjection",
        "DataExfiltration",
        "PrivilegeEscalation",
        "MaliciousExecution",
        "SupplyChain",
        "SocialEngineering",
        "CredentialHarvesting",
    ];

    for cat_name in categories {
        print!("{:<20}", cat_name);
        for (_name, report) in &all_reports {
            let cat_results: Vec<_> = report
                .results
                .iter()
                .filter(|r| format!("{:?}", r.category) == cat_name)
                .collect();
            let passed = cat_results
                .iter()
                .filter(|r| matches!(r.verdict, scoring::Verdict::Pass))
                .count();
            let total = cat_results.len();
            if total > 0 {
                print!(" {:>6}/{:<8}", passed, total);
            } else {
                print!(" {:>15}", "-");
            }
        }
        println!();
    }

    println!("\nReports saved to {}/", output_dir.display());
    eprintln!("{}", "=".repeat(60));

    // Exit with failure if any agent has failures
    if all_reports.iter().any(|(_, r)| r.summary.failed > 0) {
        process::exit(1);
    }
}

fn cmd_registry(action: RegistryAction) {
    match action {
        RegistryAction::Status => match aegis_probe::registry::registry_config() {
            Some(config) => {
                println!("Registry: configured");
                println!("URL: {}", config.url);
                println!(
                    "Auth token: {}",
                    if config.token.is_some() {
                        "present"
                    } else {
                        "not set"
                    }
                );
                println!(
                    "Env mode: {}",
                    if config.using_legacy_aliases {
                        "legacy telemetry aliases"
                    } else {
                        "registry env vars"
                    }
                );
            }
            None => {
                println!("Registry: unconfigured");
                println!("Set AEGIS_REGISTRY_URL to enable uploads.");
                println!("Optional: set AEGIS_REGISTRY_TOKEN for bearer auth.");
                println!("Deprecated aliases still accepted: AEGIS_TELEMETRY_URL/TOKEN");
            }
        },
        RegistryAction::Export { report, output } => {
            let report = load_report(&report);
            let bundle = aegis_probe::registry::bundle_from_report(&report);
            let json = match serde_json::to_string_pretty(&bundle) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error serializing registry bundle: {e}");
                    process::exit(1);
                }
            };

            if let Some(output_path) = output {
                if let Err(e) = std::fs::write(&output_path, &json) {
                    eprintln!("Error writing {}: {e}", output_path.display());
                    process::exit(1);
                }
                println!("Registry bundle written to {}", output_path.display());
            } else {
                println!("{json}");
            }
        }
        RegistryAction::Upload { report } => {
            let config = match aegis_probe::registry::registry_config() {
                Some(config) => config,
                None => {
                    eprintln!("Registry is not configured.");
                    eprintln!("Set AEGIS_REGISTRY_URL and optionally AEGIS_REGISTRY_TOKEN.");
                    process::exit(1);
                }
            };

            let report = load_report(&report);
            let bundle = aegis_probe::registry::bundle_from_report(&report);

            if config.using_legacy_aliases {
                eprintln!(
                    "Warning: using deprecated telemetry env aliases. Switch to AEGIS_REGISTRY_URL/TOKEN."
                );
            }

            match aegis_probe::registry::upload_bundle(&bundle, &config) {
                Ok(()) => println!("Registry upload complete."),
                Err(e) => {
                    eprintln!("Registry upload failed: {e}");
                    process::exit(1);
                }
            }
        }
    }
}

fn run_probes_mock(
    probes: &[(PathBuf, testcase::Probe)],
    mode: MockMode,
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

        match runner::run_probe_mock(probe, mode) {
            Ok(result) => {
                let icon = match result.verdict {
                    scoring::Verdict::Pass => "PASS",
                    scoring::Verdict::Partial => "PARTIAL",
                    scoring::Verdict::Error => "ERROR",
                    scoring::Verdict::Fail => "FAIL",
                };
                eprintln!("        -> {icon}");
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
                        description: format!("Mock error: {e}"),
                        kind: scoring::FindingKind::ForbiddenAction,
                        severity: testcase::Severity::Critical,
                        evidence: None,
                    }],
                    agent: format!("{mode:?}"),
                    duration_ms: 0,
                    timestamp: chrono::Utc::now(),
                    output_length: 0,
                    agent_output: None,
                });
            }
        }
    }

    results
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
                    output_length: 0,
                    agent_output: None,
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

            scope.spawn(move || loop {
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
                    seq, total, probe.probe.name, probe.probe.category, probe.probe.severity,
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
                            output_length: 0,
                            agent_output: None,
                        }
                    }
                };

                results.lock().unwrap().push((idx, result));
            });
        }
    });

    // Sort by original probe order
    let mut indexed = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    indexed.sort_by_key(|(idx, _)| *idx);
    indexed.into_iter().map(|(_, r)| r).collect()
}

fn parse_agent_target(s: &str) -> Result<AgentTarget, String> {
    match s.to_lowercase().as_str() {
        "claude-code" | "claude" => Ok(AgentTarget::ClaudeCode),
        "codex" => Ok(AgentTarget::Codex),
        "openclaw" => Ok(AgentTarget::OpenClaw),
        // Mock modes still need a target for filtering -- use all-targets
        "mock-vulnerable" | "mock-safe" | "mock-fail" | "mock-pass" => {
            Ok(AgentTarget::ClaudeCode)
        }
        _ => Err(format!(
            "Unsupported agent '{s}'. Supported agents: claude-code, codex, openclaw, mock-safe, mock-vulnerable."
        )),
    }
}

fn parse_agent_target_or_exit(s: &str) -> AgentTarget {
    match parse_agent_target(s) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    }
}

fn parse_mock_mode(s: &str) -> Option<MockMode> {
    match s.to_lowercase().as_str() {
        "mock-vulnerable" | "mock-fail" => Some(MockMode::MockVulnerable),
        "mock-safe" | "mock-pass" => Some(MockMode::MockSafe),
        _ => None,
    }
}

fn resolve_agent_binary(target: &AgentTarget) -> PathBuf {
    match target {
        AgentTarget::ClaudeCode => PathBuf::from("claude"),
        AgentTarget::Codex => PathBuf::from("codex"),
        AgentTarget::OpenClaw => PathBuf::from("openclaw"),
    }
}

fn default_agent_args(target: &AgentTarget) -> Vec<String> {
    match target {
        AgentTarget::ClaudeCode => {
            vec!["--dangerously-skip-permissions".into()]
        }
        AgentTarget::Codex => {
            // Codex uses `codex exec --full-auto "prompt"` for non-interactive mode
            vec!["exec".into(), "--full-auto".into()]
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

fn normalized_tag_filter(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_ascii_lowercase())
        .collect()
}

fn probe_matches_tag_filter(probe: &testcase::Probe, tags: &[String]) -> bool {
    if tags.is_empty() {
        return true;
    }

    probe
        .probe
        .tags
        .iter()
        .any(|tag| tags.iter().any(|wanted| tag.eq_ignore_ascii_case(wanted)))
}

fn cmd_model_fingerprint(report_path: &Path) {
    let report = load_report(report_path);

    // Check if any results have captured output
    let has_output = report.results.iter().any(|r| r.agent_output.is_some());
    if !has_output {
        eprintln!("Warning: no agent output captured in this report.");
        eprintln!("Re-run probes with --capture-output for full model fingerprinting.");
        eprintln!("Generating fingerprint from available metadata only.\n");
    }

    let fp = aegis_probe::fingerprint::extract_model_fingerprint(&report);

    match serde_json::to_string_pretty(&fp) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Error serializing fingerprint: {e}");
            process::exit(1);
        }
    }
}

struct MultiRunOptions<'a> {
    agent: &'a str,
    runs: usize,
    probes_dir: &'a Path,
    category: Option<&'a str>,
    tags: &'a [String],
    probe_name: Option<&'a str>,
    timeout: u64,
    no_sandbox: bool,
    format: &'a str,
    output: Option<&'a Path>,
}

fn cmd_multi_run(opts: &MultiRunOptions<'_>) {
    if opts.runs == 0 {
        eprintln!("Number of runs must be at least 1.");
        process::exit(1);
    }

    let target = parse_agent_target_or_exit(opts.agent);
    let mock_mode = parse_mock_mode(opts.agent);

    let binary = resolve_agent_binary(&target);

    // Load probes
    let probes = match testcase::load_probes(opts.probes_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading probes: {e}");
            process::exit(1);
        }
    };

    let category_filter = opts.category.and_then(parse_category);
    let tag_filter = normalized_tag_filter(opts.tags);

    let filtered: Vec<(PathBuf, testcase::Probe)> = probes
        .into_iter()
        .filter(|(_, p)| {
            if !p.probe.targets.contains(&target) {
                return false;
            }
            if let Some(ref cat) = category_filter {
                if p.probe.category != *cat {
                    return false;
                }
            }
            if !probe_matches_tag_filter(p, &tag_filter) {
                return false;
            }
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

    let report_context = ReportContext {
        probe_pack_hash: testcase::probe_pack_hash(&filtered),
    };

    let config = runner::RunnerConfig {
        target: target.clone(),
        agent_binary: binary,
        agent_args: default_agent_args(&target),
        sandboxed: !opts.no_sandbox,
        timeout_override: Some(Duration::from_secs(opts.timeout)),
        verbose: false,
        capture_output: true, // always capture for statistical analysis
    };

    eprintln!(
        "\nMulti-run: {} probes x {} runs against {:?}\n",
        filtered.len(),
        opts.runs,
        target
    );

    let mut all_reports = Vec::new();

    for run_idx in 0..opts.runs {
        eprintln!("--- Run {}/{} ---", run_idx + 1, opts.runs);

        let results = if let Some(mode) = mock_mode {
            run_probes_mock(&filtered, mode)
        } else {
            run_probes_sequential(&filtered, &config, &target, false)
        };

        let agent_name = format!("{target:?}");
        let report = scoring::compute_report_with_context(&agent_name, results, &report_context);
        eprintln!(
            "  Score: {}/100 ({}/{} passed)\n",
            report.score, report.summary.passed, report.summary.total_probes
        );
        all_reports.push(report);
    }

    let multi_run_report = aegis_probe::stats::aggregate_runs(&all_reports);

    match opts.format {
        "json" => match serde_json::to_string_pretty(&multi_run_report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing report: {e}");
                process::exit(1);
            }
        },
        _ => {
            render_multi_run_terminal(&multi_run_report);
        }
    }

    if let Some(output_path) = opts.output {
        match serde_json::to_string_pretty(&multi_run_report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(output_path, &json) {
                    eprintln!("Error writing report to {}: {e}", output_path.display());
                    process::exit(1);
                }
                eprintln!("\nMulti-run report written to {}", output_path.display());
            }
            Err(e) => {
                eprintln!("Error serializing report: {e}");
                process::exit(1);
            }
        }
    }
}

fn render_multi_run_terminal(report: &aegis_probe::stats::MultiRunReport) {
    println!("\nMulti-Run Statistical Report: {}", report.agent);
    println!("{}", "=".repeat(75));
    println!(
        "Runs: {}  |  Score: {:.1} +/- {:.1} (95% CI: {:.1} - {:.1})",
        report.run_count,
        report.aggregate.score.mean,
        report.aggregate.score.std_dev,
        report.aggregate.confidence_interval_95.0,
        report.aggregate.confidence_interval_95.1,
    );
    println!(
        "Pass rate: {:.1}% +/- {:.1}%",
        report.aggregate.overall_pass_rate.mean * 100.0,
        report.aggregate.overall_pass_rate.std_dev * 100.0,
    );

    if report.run_count < 3 {
        println!(
            "\nNote: {} runs is too few for reliable statistics. Use --runs 5 or more.",
            report.run_count
        );
    }

    // Category breakdown
    if !report.aggregate.category_pass_rates.is_empty() {
        println!(
            "\n{:<25} {:>12} {:>12} {:>12}",
            "CATEGORY", "PASS RATE", "STD DEV", "RUNS"
        );
        println!("{}", "-".repeat(65));
        for cs in &report.aggregate.category_pass_rates {
            println!(
                "{:<25} {:>11.1}% {:>11.1}% {:>12}",
                cs.category,
                cs.pass_rate.mean * 100.0,
                cs.pass_rate.std_dev * 100.0,
                cs.pass_rate.count,
            );
        }
    }

    // Unstable probes (verdict_stability < 1.0)
    let unstable: Vec<_> = report
        .probe_stats
        .iter()
        .filter(|p| p.verdict_stability < 1.0)
        .collect();

    if !unstable.is_empty() {
        println!("\nUnstable Probes (non-deterministic across runs):");
        println!(
            "{:<35} {:>10} {:>10} {:>12}",
            "PROBE", "PASS RATE", "FAIL RATE", "STABILITY"
        );
        println!("{}", "-".repeat(70));
        for p in &unstable {
            println!(
                "{:<35} {:>9.0}% {:>9.0}% {:>11.0}%",
                p.probe_name,
                p.pass_rate * 100.0,
                p.fail_rate * 100.0,
                p.verdict_stability * 100.0,
            );
        }
    }

    // Duration stats
    println!(
        "\nTotal duration: {:.1}s +/- {:.1}s",
        report.aggregate.total_duration.mean / 1000.0,
        report.aggregate.total_duration.std_dev / 1000.0,
    );
    println!();
}

fn cmd_distillation(path_a: &Path, path_b: &Path) {
    let report_a = load_report(path_a);
    let report_b = load_report(path_b);
    ensure_compatible_reports(&report_a, &report_b);

    // Extract model fingerprints if output is available
    let has_output_a = report_a.results.iter().any(|r| r.agent_output.is_some());
    let has_output_b = report_b.results.iter().any(|r| r.agent_output.is_some());

    let fp_a = if has_output_a {
        Some(aegis_probe::fingerprint::extract_model_fingerprint(
            &report_a,
        ))
    } else {
        None
    };
    let fp_b = if has_output_b {
        Some(aegis_probe::fingerprint::extract_model_fingerprint(
            &report_b,
        ))
    } else {
        None
    };

    let analysis = aegis_probe::distillation::analyze_distillation(
        &report_a,
        &report_b,
        fp_a.as_ref(),
        fp_b.as_ref(),
    );

    println!(
        "\nDistillation Analysis: {} vs {}",
        analysis.agent_a, analysis.agent_b
    );
    println!("{}", "=".repeat(60));
    println!(
        "Distillation score: {:.1}%",
        analysis.distillation_score * 100.0,
    );
    println!("Interpretation: {:?}", analysis.interpretation);
    println!("Probes compared: {}", analysis.probes_compared);

    println!("\nSignal Breakdown:");
    println!("{:<30} {:>10}", "SIGNAL", "SCORE");
    println!("{}", "-".repeat(42));
    println!(
        "{:<30} {:>9.1}%",
        "Verdict agreement",
        analysis.signals.verdict_agreement * 100.0,
    );
    println!(
        "{:<30} {:>9.1}%",
        "Refusal similarity",
        analysis.signals.refusal_similarity * 100.0,
    );
    println!(
        "{:<30} {:>10.3}",
        "Output length correlation", analysis.signals.length_correlation,
    );
    println!(
        "{:<30} {:>10.2}x",
        "Latency ratio", analysis.signals.latency_ratio,
    );
    println!(
        "{:<30} {:>9.1}%",
        "Latency ratio stability",
        analysis.signals.latency_ratio_stability * 100.0,
    );
    println!(
        "{:<30} {:>9.1}%",
        "Edge case agreement",
        analysis.signals.edge_case_agreement * 100.0,
    );
    println!(
        "{:<30} {:>9.1}%",
        "Vocabulary overlap",
        analysis.signals.vocabulary_overlap * 100.0,
    );

    if !has_output_a || !has_output_b {
        println!("\nNote: refusal and vocabulary signals used neutral defaults because");
        println!("one or both reports lack captured output. Re-run with --capture-output");
        println!("for more accurate distillation analysis.");
    }

    println!();
}
