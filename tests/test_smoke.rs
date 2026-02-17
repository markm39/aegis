//! End-to-end smoke test that invokes the `aegis` binary.
//!
//! Uses `assert_cmd` to test the full CLI lifecycle with HOME overridden
//! to a temp directory for complete isolation from the user's real config.
//!
//! The `aegis` binary must be built before running these tests:
//!   cargo build -p aegis-cli && cargo test --test test_smoke

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Once;

static BUILD_ONCE: Once = Once::new();

/// Ensure the aegis binary is built, then return its path.
fn aegis_bin() -> PathBuf {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests/ should have a parent")
        .to_path_buf();

    BUILD_ONCE.call_once(|| {
        let status = std::process::Command::new("cargo")
            .args(["build", "-p", "aegis-cli"])
            .current_dir(&workspace_root)
            .status()
            .expect("failed to invoke cargo build");
        assert!(status.success(), "cargo build -p aegis-cli failed");
    });

    let bin = workspace_root.join("target").join("debug").join("aegis");
    assert!(bin.exists(), "aegis binary not found at {}", bin.display());
    bin
}

/// Get a Command for the `aegis` binary with HOME overridden.
fn aegis_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(aegis_bin());
    cmd.env("HOME", home);
    cmd
}

#[test]
fn smoke_test_full_lifecycle() {
    let tmpdir = tempfile::tempdir().expect("temp dir");
    let home = tmpdir.path();

    // 1. aegis setup
    aegis_cmd(home)
        .args(["setup"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Setup complete"));

    // 2. aegis init smoke-test --policy allow-read-only
    aegis_cmd(home)
        .args(["init", "smoke-test", "--policy", "allow-read-only"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized aegis configuration"));

    // 3. Pre-create a test file in the sandbox directory
    let sandbox_dir = home.join(".aegis").join("smoke-test").join("sandbox");
    let test_file = sandbox_dir.join("hello.txt");
    fs::write(&test_file, "hello aegis\n").expect("write test file");

    // 4. aegis run --config smoke-test -- cat <full-path>/hello.txt
    let hello_path = test_file.display().to_string();
    aegis_cmd(home)
        .args(["run", "--config", "smoke-test", "--", "cat", &hello_path])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("hello aegis")
                .and(predicate::str::contains("Session:")),
        );

    // 5. aegis audit query smoke-test --last 20
    aegis_cmd(home)
        .args(["audit", "query", "smoke-test", "--last", "20"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ENTRY ID")
                .and(predicate::str::contains("Allow")),
        );

    // 6. aegis audit sessions smoke-test
    aegis_cmd(home)
        .args(["audit", "sessions", "smoke-test"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("SESSION ID")
                .and(predicate::str::contains("cat")),
        );

    // 7. aegis audit export smoke-test --format jsonl
    let export_output = aegis_cmd(home)
        .args(["audit", "export", "smoke-test", "--format", "jsonl"])
        .assert()
        .success();

    // Each non-empty line should be valid JSON
    let export_stdout = String::from_utf8_lossy(
        &export_output.get_output().stdout,
    );
    for line in export_stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(trimmed);
            assert!(
                parsed.is_ok(),
                "JSONL line should be valid JSON: {trimmed}"
            );
        }
    }

    // 8. aegis audit verify smoke-test
    aegis_cmd(home)
        .args(["audit", "verify", "smoke-test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid:         YES"));

    // 9. aegis report smoke-test --format json
    let report_output = aegis_cmd(home)
        .args(["report", "smoke-test", "--format", "json"])
        .assert()
        .success();

    let report_stdout = String::from_utf8_lossy(
        &report_output.get_output().stdout,
    );
    let report_json: serde_json::Value =
        serde_json::from_str(&report_stdout).expect("report JSON should be valid");
    assert!(
        report_json["total_entries"].as_u64().unwrap_or(0) > 0,
        "report should have entries"
    );
    assert_eq!(
        report_json["integrity_valid"],
        serde_json::Value::Bool(true),
        "integrity should be valid"
    );

    // 10. aegis audit policy-history smoke-test
    aegis_cmd(home)
        .args(["audit", "policy-history", "smoke-test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SNAPSHOT ID"));

    // 11. aegis status smoke-test
    aegis_cmd(home)
        .args(["status", "smoke-test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    // 12. aegis policy validate --path <policy file>
    let policy_path = home
        .join(".aegis")
        .join("smoke-test")
        .join("policies")
        .join("default.cedar");
    aegis_cmd(home)
        .args([
            "policy",
            "validate",
            "--path",
            &policy_path.display().to_string(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // 13. aegis wrap --dir <tmpdir> -- sh -c 'echo wrapped > output.txt'
    let wrap_project = home.join("wrap-project");
    fs::create_dir_all(&wrap_project).expect("create wrap project dir");

    let output_path = wrap_project.join("output.txt");
    let script = format!("echo wrapped > {}", output_path.display());

    aegis_cmd(home)
        .args([
            "wrap",
            "--dir",
            &wrap_project.display().to_string(),
            "--",
            "sh",
            "-c",
            &script,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Session:"));

    assert!(output_path.exists(), "wrap should have created output.txt");
    let content = fs::read_to_string(&output_path).expect("read output.txt");
    assert_eq!(content.trim(), "wrapped");
}

#[test]
fn smoke_test_init_with_dir() {
    let tmpdir = tempfile::tempdir().expect("temp dir");
    let home = tmpdir.path();

    // Setup first
    aegis_cmd(home)
        .args(["setup"])
        .assert()
        .success();

    // Create a project directory
    let project_dir = home.join("my-project");
    fs::create_dir_all(&project_dir).expect("create project dir");

    // Init with --dir pointing to the project
    aegis_cmd(home)
        .args([
            "init",
            "dir-test",
            "--policy",
            "permit-all",
            "--dir",
            &project_dir.display().to_string(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized"));

    // Run a command in the project dir
    let test_file = project_dir.join("hello.txt");
    fs::write(&test_file, "hello from dir\n").expect("write test file");

    let hello_path = test_file.display().to_string();
    aegis_cmd(home)
        .args(["run", "--config", "dir-test", "--", "cat", &hello_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from dir"));
}

#[test]
fn smoke_test_run_auto_init() {
    let tmpdir = tempfile::tempdir().expect("temp dir");
    let home = tmpdir.path();

    // Setup first
    aegis_cmd(home).args(["setup"]).assert().success();

    // Run without prior init -- should auto-create config
    aegis_cmd(home)
        .args(["run", "--", "echo", "auto-init-works"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Auto-initialized")
                .and(predicate::str::contains("auto-init-works"))
                .and(predicate::str::contains("Session:")),
        );

    // Status should find the auto-created config
    aegis_cmd(home)
        .args(["status", "echo"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn smoke_test_wrap_then_query() {
    let tmpdir = tempfile::tempdir().expect("temp dir");
    let home = tmpdir.path();

    // Setup first
    aegis_cmd(home).args(["setup"]).assert().success();

    // Wrap a command
    let project_dir = home.join("wrap-query-project");
    fs::create_dir_all(&project_dir).expect("create project dir");

    aegis_cmd(home)
        .args([
            "wrap",
            "--dir",
            &project_dir.display().to_string(),
            "--",
            "echo",
            "wrap-test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Session:"));

    // Unified lookup: report should find the wrap config by name
    aegis_cmd(home)
        .args(["report", "echo", "--format", "json"])
        .assert()
        .success();
}
