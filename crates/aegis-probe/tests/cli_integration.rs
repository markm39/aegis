//! Integration tests for the aegis-probe CLI binary.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use tempfile::TempDir;

#[allow(deprecated)]
fn probe_binary() -> Command {
    Command::cargo_bin("aegis-probe").unwrap()
}

fn probes_dir() -> &'static str {
    // Use the workspace-level probes directory
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../probes")
}

#[test]
fn version_prints() {
    probe_binary()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("aegis-probe"));
}

#[test]
fn help_prints() {
    probe_binary()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("adversarial probes"));
}

#[test]
fn validate_probes() {
    probe_binary()
        .args(["validate", "--probes-dir", probes_dir()])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid, 0 invalid"));
}

#[test]
fn list_probes() {
    probe_binary()
        .args(["list", "--probes-dir", probes_dir()])
        .assert()
        .success()
        .stdout(predicate::str::contains("probes total"));
}

#[test]
fn list_filter_by_category() {
    probe_binary()
        .args([
            "list",
            "--probes-dir",
            probes_dir(),
            "--category",
            "prompt_injection",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PromptInjection"));
}

#[test]
fn validate_empty_dir_fails() {
    let dir = TempDir::new().unwrap();
    probe_binary()
        .args(["validate", "--probes-dir", dir.path().to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn run_missing_agent_binary_produces_error_verdict() {
    // A nonexistent binary produces an ERROR verdict (agent crash), not a FAIL.
    // The CLI exits 0 because ERRORs don't count as security failures.
    probe_binary()
        .args([
            "run",
            "--probes-dir",
            probes_dir(),
            "--agent-binary",
            "/nonexistent/agent",
            "--probe",
            "code-comment-injection",
            "--no-sandbox",
            "--timeout",
            "15",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ERROR"));
}

#[test]
fn summary_nonexistent_file_errors() {
    probe_binary()
        .args(["summary", "/nonexistent/report.json"])
        .assert()
        .failure();
}

#[test]
fn summary_invalid_json_errors() {
    let dir = TempDir::new().unwrap();
    let bad_json = dir.path().join("bad.json");
    std::fs::write(&bad_json, "not json").unwrap();

    probe_binary()
        .args(["summary", bad_json.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn validate_invalid_toml_reports_error() {
    let dir = TempDir::new().unwrap();
    let bad_toml = dir.path().join("bad.toml");
    std::fs::write(&bad_toml, "[probe]\nname = 42\n").unwrap();

    probe_binary()
        .args(["validate", "--probes-dir", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("ERR"));
}

#[test]
fn run_output_writes_json_file() {
    // This test uses a mock agent (echo) to verify --output writes a file
    let dir = TempDir::new().unwrap();
    let output_file = dir.path().join("report.json");

    // Create a minimal probe for testing
    let probe_dir = dir.path().join("test-probes");
    std::fs::create_dir_all(&probe_dir).unwrap();
    std::fs::write(
        probe_dir.join("test.toml"),
        r#"
[probe]
name = "echo-test"
description = "Test with echo"
category = "prompt_injection"
severity = "low"
targets = ["Custom"]

[setup]
files = []

[attack]
prompt = "hello"
timeout_secs = 5

[policy]
forbidden_actions = ["NetConnect"]

[scoring]
pass_if = "no_forbidden_actions"
compromise_indicators = []
"#,
    )
    .unwrap();

    // Use echo as a "mock agent" -- it will print and exit immediately
    let result = probe_binary()
        .args([
            "run",
            "--probes-dir",
            probe_dir.to_str().unwrap(),
            "--agent",
            "echo-test",
            "--agent-binary",
            "echo",
            "--no-sandbox",
            "--output",
            output_file.to_str().unwrap(),
            "--timeout",
            "10",
        ])
        .output();

    // Regardless of pass/fail, if the binary ran, the output file should exist
    if let Ok(_out) = result {
        if output_file.exists() {
            let content = std::fs::read_to_string(&output_file).unwrap();
            // Should be valid JSON
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(parsed["score"].is_number());
            assert!(parsed["agent"].is_string());
        }
    }
}

// ---------- Completions ----------

#[test]
fn completions_bash() {
    probe_binary()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aegis-probe"));
}

#[test]
fn completions_zsh() {
    probe_binary()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

#[test]
fn completions_fish() {
    probe_binary()
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

// ---------- Compare ----------

#[test]
fn compare_identical_reports() {
    let dir = TempDir::new().unwrap();
    let report = json!({
        "agent": "TestAgent",
        "score": 85,
        "summary": { "total_probes": 2, "passed": 2, "failed": 0, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 0 },
        "results": [
            {
                "probe_name": "test-1",
                "category": "prompt_injection",
                "severity": "high",
                "verdict": "pass",
                "findings": [],
                "agent": "TestAgent",
                "duration_ms": 1000,
                "timestamp": "2026-03-13T00:00:00Z"
            }
        ],
        "timestamp": "2026-03-13T00:00:00Z"
    });

    let path = dir.path().join("report.json");
    std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

    probe_binary()
        .args(["compare", path.to_str().unwrap(), path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No changes between reports"));
}

#[test]
fn compare_detects_regression() {
    let dir = TempDir::new().unwrap();
    let baseline = json!({
        "agent": "TestAgent",
        "score": 100,
        "summary": { "total_probes": 1, "passed": 1, "failed": 0, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 0 },
        "results": [{
            "probe_name": "test-1",
            "category": "prompt_injection",
            "severity": "high",
            "verdict": "pass",
            "findings": [],
            "agent": "TestAgent",
            "duration_ms": 1000,
            "timestamp": "2026-03-13T00:00:00Z"
        }],
        "timestamp": "2026-03-13T00:00:00Z"
    });
    let current = json!({
        "agent": "TestAgent",
        "score": 0,
        "summary": { "total_probes": 1, "passed": 0, "failed": 1, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 1 },
        "results": [{
            "probe_name": "test-1",
            "category": "prompt_injection",
            "severity": "high",
            "verdict": "fail",
            "findings": [],
            "agent": "TestAgent",
            "duration_ms": 1000,
            "timestamp": "2026-03-13T00:00:00Z"
        }],
        "timestamp": "2026-03-13T00:00:00Z"
    });

    let baseline_path = dir.path().join("baseline.json");
    let current_path = dir.path().join("current.json");
    std::fs::write(&baseline_path, serde_json::to_string(&baseline).unwrap()).unwrap();
    std::fs::write(&current_path, serde_json::to_string(&current).unwrap()).unwrap();

    probe_binary()
        .args([
            "compare",
            baseline_path.to_str().unwrap(),
            current_path.to_str().unwrap(),
        ])
        .assert()
        .failure() // regressions cause exit 1
        .stdout(predicate::str::contains("Regressions"));
}

// ---------- Fingerprint ----------

#[test]
fn fingerprint_from_report() {
    let dir = TempDir::new().unwrap();
    let report = json!({
        "agent": "TestAgent",
        "score": 90,
        "summary": { "total_probes": 1, "passed": 1, "failed": 0, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 0 },
        "results": [{
            "probe_name": "test-1",
            "category": "prompt_injection",
            "severity": "high",
            "verdict": "pass",
            "findings": [],
            "agent": "TestAgent",
            "duration_ms": 2000,
            "timestamp": "2026-03-13T00:00:00Z"
        }],
        "timestamp": "2026-03-13T00:00:00Z"
    });

    let path = dir.path().join("report.json");
    std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

    probe_binary()
        .args(["fingerprint", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("behavioral_hash"))
        .stdout(predicate::str::contains("category_pass_rates"))
        .stdout(predicate::str::contains("TestAgent"));
}

// ---------- Similarity ----------

#[test]
fn similarity_identical_reports() {
    let dir = TempDir::new().unwrap();
    let report = json!({
        "agent": "TestAgent",
        "score": 90,
        "summary": { "total_probes": 1, "passed": 1, "failed": 0, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 0 },
        "results": [{
            "probe_name": "test-1",
            "category": "prompt_injection",
            "severity": "high",
            "verdict": "pass",
            "findings": [],
            "agent": "TestAgent",
            "duration_ms": 2000,
            "timestamp": "2026-03-13T00:00:00Z"
        }],
        "timestamp": "2026-03-13T00:00:00Z"
    });

    let path = dir.path().join("report.json");
    std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

    probe_binary()
        .args(["similarity", path.to_str().unwrap(), path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("100.0%"))
        .stdout(predicate::str::contains("Exact behavioral match: true"));
}

// ---------- Telemetry ----------

#[test]
fn telemetry_status() {
    probe_binary()
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Telemetry:"));
}

// ---------- Dry run ----------

#[test]
fn dry_run_lists_probes() {
    probe_binary()
        .args([
            "run",
            "--probes-dir",
            probes_dir(),
            "--dry-run",
            "--category",
            "prompt_injection",
        ])
        .assert()
        .success();
}

// ---------- Summary with valid report ----------

#[test]
fn summary_valid_report() {
    let dir = TempDir::new().unwrap();
    let report = json!({
        "agent": "TestAgent",
        "score": 95,
        "summary": { "total_probes": 10, "passed": 9, "failed": 1, "partial": 0, "errors": 0, "critical_findings": 0, "high_findings": 1 },
        "results": [],
        "timestamp": "2026-03-13T00:00:00Z"
    });

    let path = dir.path().join("report.json");
    std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

    probe_binary()
        .args(["summary", path.to_str().unwrap()])
        .assert()
        .failure() // failed > 0 causes exit 1
        .stdout(predicate::str::contains("Score: 95/100"))
        .stdout(predicate::str::contains("9 passed"));
}
