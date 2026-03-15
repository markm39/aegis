//! Aegis Probe: AI agent security testing framework.
//!
//! This crate provides adversarial security probes for testing AI coding
//! agents (Claude Code, Codex, OpenClaw, etc.). Each probe defines an
//! attack scenario, spawns the agent in a sandboxed environment, feeds
//! it adversarial inputs, and monitors whether the agent resists or
//! succumbs to the attack.
//!
//! # Architecture
//!
//! - [`testcase`]: Probe definitions loaded from TOML files
//! - [`runner`]: Execution engine that spawns agents and collects observations
//! - [`scoring`]: Pass/fail classification with severity ratings
//!
//! # Example
//!
//! ```no_run
//! use aegis_probe::{testcase, runner, scoring};
//! use std::path::Path;
//!
//! // Load all probes from a directory
//! let probes = testcase::load_probes(Path::new("probes/")).unwrap();
//!
//! // Configure the runner
//! let config = runner::RunnerConfig::default();
//!
//! // Run all probes and collect results
//! let results = runner::run_all_probes(&probes, &config);
//!
//! // Generate a security report
//! let report = scoring::compute_report("claude-code", results);
//! println!("Security Score: {}/100", report.score);
//! ```

pub mod baseline;
pub mod compare;
pub mod distillation;
pub mod fingerprint;
pub mod history;
pub mod profiles;
pub mod registry;
pub mod report;
pub mod runner;
pub mod scoring;
pub mod stats;
pub mod testcase;
