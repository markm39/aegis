//! Parity matrix commands: status, diff, verify.
//!
//! Read the upstream feature catalog from `features.yaml` and display
//! parity status, missing features, and verification results.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// Default parity directory; overridden by `AEGIS_PARITY_DIR`.
fn parity_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AEGIS_PARITY_DIR") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("aegis-parity")
    }
}

fn features_path() -> PathBuf {
    parity_dir().join("matrix").join("features.yaml")
}

// ── YAML schema ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FeaturesFile {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    updated_at_utc: String,
    features: Vec<Feature>,
}

#[derive(Debug, Deserialize)]
struct Feature {
    feature_id: String,
    description: String,
    #[serde(default)]
    risk_level: String,
    parity_status: String,
    #[serde(default)]
    security_controls: Vec<String>,
    #[serde(default)]
    required_tests: Vec<String>,
    #[serde(default)]
    evidence_paths: Vec<String>,
    #[serde(default)]
    aegis_components: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    security_delta: String,
    #[serde(default)]
    #[allow(dead_code)]
    owner: String,
    #[serde(default)]
    #[allow(dead_code)]
    upstream_refs: Vec<String>,
}

// ── helpers ──────────────────────────────────────────────────

/// Extract the domain prefix from a feature_id (e.g. "runtime" from "runtime.hooks.before_tool_call").
fn domain(feature_id: &str) -> &str {
    feature_id.split('.').next().unwrap_or(feature_id)
}

/// Assign features to waves based on domain.
fn wave(feature_id: &str) -> u8 {
    let d = domain(feature_id);
    match d {
        "runtime" | "orchestrator" | "browser" => 1,
        "gateway" | "auto_reply" | "channel" => 2,
        _ => 3,
    }
}

fn load_features(path: &Path) -> anyhow::Result<Vec<Feature>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let file: FeaturesFile =
        serde_yaml::from_str(&content).with_context(|| "failed to parse features.yaml")?;
    Ok(file.features)
}

// ── commands ──────────────────────────────────────────────────

/// `aegis parity status` -- Summary table of features by domain.
pub fn status(format: &str) -> anyhow::Result<()> {
    let path = features_path();
    let features = load_features(&path)?;

    // Group by domain, count statuses.
    let mut domains: BTreeMap<String, [u32; 4]> = BTreeMap::new();
    for f in &features {
        let d = domain(&f.feature_id).to_string();
        let counts = domains.entry(d).or_insert([0; 4]);
        match f.parity_status.as_str() {
            "complete" => counts[0] += 1,
            "partial" => counts[1] += 1,
            "missing" => counts[2] += 1,
            _ => counts[3] += 1,
        }
    }

    if format == "json" {
        let data: Vec<serde_json::Value> = domains
            .iter()
            .map(|(d, c)| {
                serde_json::json!({
                    "domain": d,
                    "complete": c[0],
                    "partial": c[1],
                    "missing": c[2],
                    "other": c[3],
                    "total": c[0] + c[1] + c[2] + c[3],
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    // Text table.
    let total_complete: u32 = domains.values().map(|c| c[0]).sum();
    let total_partial: u32 = domains.values().map(|c| c[1]).sum();
    let total_missing: u32 = domains.values().map(|c| c[2]).sum();
    let total_all: u32 = features.len() as u32;

    println!(
        "Parity Status  ({} features from {})",
        total_all,
        path.display()
    );
    println!();
    println!(
        "{:<16} {:>8} {:>8} {:>8} {:>8}",
        "Domain", "Complete", "Partial", "Missing", "Total"
    );
    println!("{}", "-".repeat(56));
    for (d, c) in &domains {
        let total = c[0] + c[1] + c[2] + c[3];
        println!("{:<16} {:>8} {:>8} {:>8} {:>8}", d, c[0], c[1], c[2], total);
    }
    println!("{}", "-".repeat(56));
    println!(
        "{:<16} {:>8} {:>8} {:>8} {:>8}",
        "TOTAL", total_complete, total_partial, total_missing, total_all,
    );

    let pct = if total_all > 0 {
        (total_complete as f64 / total_all as f64) * 100.0
    } else {
        0.0
    };
    println!();
    println!(
        "Parity: {:.0}% complete ({}/{})",
        pct, total_complete, total_all
    );

    Ok(())
}

/// `aegis parity diff` -- Features not yet complete, grouped by wave.
pub fn diff(format: &str) -> anyhow::Result<()> {
    let path = features_path();
    let features = load_features(&path)?;

    let incomplete: Vec<&Feature> = features
        .iter()
        .filter(|f| f.parity_status != "complete")
        .collect();

    if format == "json" {
        let data: Vec<serde_json::Value> = incomplete
            .iter()
            .map(|f| {
                serde_json::json!({
                    "feature_id": f.feature_id,
                    "parity_status": f.parity_status,
                    "risk_level": f.risk_level,
                    "wave": wave(&f.feature_id),
                    "description": f.description,
                    "aegis_components": f.aegis_components,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("Parity Diff  ({} features not complete)", incomplete.len());
    println!();

    for w in 1..=3 {
        let wave_features: Vec<&&Feature> = incomplete
            .iter()
            .filter(|f| wave(&f.feature_id) == w)
            .collect();
        if wave_features.is_empty() {
            continue;
        }
        let label = match w {
            1 => "Wave 1 -- Runtime Core",
            2 => "Wave 2 -- Gateway, Auto-Reply, Channels",
            _ => "Wave 3 -- Advanced Features",
        };
        println!("  {} ({} features)", label, wave_features.len());
        println!();
        for f in &wave_features {
            let status_tag = match f.parity_status.as_str() {
                "partial" => "[PARTIAL]",
                "missing" => "[MISSING]",
                _ => &f.parity_status,
            };
            let risk = if f.risk_level.is_empty() {
                String::new()
            } else {
                format!(" ({})", f.risk_level)
            };
            println!("    {} {}{}", status_tag, f.feature_id, risk);
            if !f.description.is_empty() {
                // Truncate long descriptions to one line.
                let desc = if f.description.len() > 70 {
                    format!("{}...", &f.description[..67])
                } else {
                    f.description.clone()
                };
                println!("      {}", desc);
            }
        }
        println!();
    }

    Ok(())
}

/// `aegis parity verify` -- Validate that completed features meet requirements.
///
/// Exit code 0 if all complete features have required_tests, security_controls,
/// and evidence_paths filled in. Non-zero otherwise (for CI gating).
pub fn verify(format: &str) -> anyhow::Result<()> {
    let path = features_path();
    let features = load_features(&path)?;

    let mut violations: Vec<serde_json::Value> = Vec::new();
    let mut checked = 0u32;

    for f in &features {
        if f.parity_status != "complete" {
            continue;
        }
        checked += 1;

        // Completed features should have at least one security control linked
        // (unless risk_level is "low").
        if f.security_controls.is_empty() && f.risk_level != "low" {
            violations.push(serde_json::json!({
                "feature_id": f.feature_id,
                "issue": "complete feature with non-low risk has no security_controls",
            }));
        }

        // Completed features should have evidence_paths.
        if f.evidence_paths.is_empty() && f.risk_level != "low" {
            violations.push(serde_json::json!({
                "feature_id": f.feature_id,
                "issue": "complete feature with non-low risk has no evidence_paths",
            }));
        }

        // Required tests should be listed for non-low-risk features.
        if f.required_tests.is_empty() && f.risk_level != "low" {
            violations.push(serde_json::json!({
                "feature_id": f.feature_id,
                "issue": "complete feature with non-low risk has no required_tests",
            }));
        }
    }

    if format == "json" {
        let report = serde_json::json!({
            "checked": checked,
            "violations": violations.len(),
            "details": violations,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Parity Verify  ({} complete features checked)", checked);
        println!();
        if violations.is_empty() {
            println!("All complete features pass verification.");
        } else {
            println!("{} violation(s) found:", violations.len());
            println!();
            for v in &violations {
                let fid = v["feature_id"].as_str().unwrap_or("?");
                let issue = v["issue"].as_str().unwrap_or("?");
                println!("  FAIL  {}  --  {}", fid, issue);
            }
        }
    }

    if !violations.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
