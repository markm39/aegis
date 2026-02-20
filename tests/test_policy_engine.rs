//! Integration tests for cross-crate policy evaluation.
//!
//! Verifies that the policy engine (aegis-policy) correctly integrates with
//! the types crate (aegis-types) to produce expected verdicts.

mod common;

use std::path::PathBuf;

use tempfile::TempDir;

use aegis_policy::builtin::{
    ALLOW_READ_ONLY, ALLOW_READ_WRITE, CI_RUNNER, DATA_SCIENCE, DEFAULT_DENY,
    ORCHESTRATOR_COMPUTER_USE, PERMIT_ALL,
};
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, Decision};

use common::{dir_list_action, file_read_action, file_write_action, tool_call_action};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_policy_deny_all_blocks_read() {
    let engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");

    let action = file_read_action("test-agent", "/tmp/secret.txt");
    let verdict = engine.evaluate(&action);

    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "default-deny should block FileRead"
    );
}

#[test]
fn test_policy_deny_all_blocks_write() {
    let engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");

    let action = file_write_action("test-agent", "/tmp/output.txt");
    let verdict = engine.evaluate(&action);

    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "default-deny should block FileWrite"
    );
}

#[test]
fn test_policy_deny_all_blocks_net_connect() {
    let engine =
        PolicyEngine::from_policies(DEFAULT_DENY, None).expect("should create deny-all engine");

    let action = Action::new(
        "test-agent",
        ActionKind::NetConnect {
            host: "example.com".into(),
            port: 443,
        },
    );
    let verdict = engine.evaluate(&action);

    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "default-deny should block NetConnect"
    );
}

#[test]
fn test_permit_all_allows_file_read() {
    let engine =
        PolicyEngine::from_policies(PERMIT_ALL, None).expect("should create permit-all engine");

    let action = file_read_action("agent-1", "/tmp/data.csv");
    let verdict = engine.evaluate(&action);

    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "permit-all should allow FileRead"
    );
}

#[test]
fn test_permit_all_allows_file_write() {
    let engine =
        PolicyEngine::from_policies(PERMIT_ALL, None).expect("should create permit-all engine");

    let action = file_write_action("agent-1", "/tmp/output.txt");
    let verdict = engine.evaluate(&action);

    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "permit-all should allow FileWrite"
    );
}

#[test]
fn test_permit_all_allows_all_action_kinds() {
    let engine =
        PolicyEngine::from_policies(PERMIT_ALL, None).expect("should create permit-all engine");

    let actions: Vec<Action> = vec![
        Action::new(
            "a",
            ActionKind::FileRead {
                path: PathBuf::from("/f"),
            },
        ),
        Action::new(
            "a",
            ActionKind::FileWrite {
                path: PathBuf::from("/f"),
            },
        ),
        Action::new(
            "a",
            ActionKind::FileDelete {
                path: PathBuf::from("/f"),
            },
        ),
        Action::new(
            "a",
            ActionKind::DirCreate {
                path: PathBuf::from("/d"),
            },
        ),
        Action::new(
            "a",
            ActionKind::DirList {
                path: PathBuf::from("/d"),
            },
        ),
        Action::new(
            "a",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 80,
            },
        ),
        Action::new(
            "a",
            ActionKind::NetRequest {
                method: "GET".into(),
                url: "https://example.com".into(),
            },
        ),
        Action::new(
            "a",
            ActionKind::ToolCall {
                tool: "bash".into(),
                args: serde_json::json!({}),
            },
        ),
        Action::new(
            "a",
            ActionKind::ProcessSpawn {
                command: "echo".into(),
                args: vec!["hello".into()],
            },
        ),
        Action::new(
            "a",
            ActionKind::ProcessExit {
                command: "echo".into(),
                exit_code: 0,
            },
        ),
    ];

    for action in &actions {
        let verdict = engine.evaluate(action);
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "permit-all should allow {:?}",
            action.kind
        );
    }
}

#[test]
fn test_orchestrator_computer_use_policy_limits_tool_names() {
    let engine = PolicyEngine::from_policies(ORCHESTRATOR_COMPUTER_USE, None)
        .expect("should create orchestrator-computer-use engine");

    for tool in [
        "MouseClick",
        "BrowserNavigate",
        "BrowserEvaluate",
        "BrowserClick",
        "BrowserType",
        "InputBatch",
    ] {
        let allowed = tool_call_action("orch-1", tool);
        let allowed_verdict = engine.evaluate(&allowed);
        assert_eq!(
            allowed_verdict.decision,
            Decision::Allow,
            "known computer-use tool should be allowed: {tool}"
        );
    }

    let denied = tool_call_action("orch-1", "Bash");
    let denied_verdict = engine.evaluate(&denied);
    assert_eq!(
        denied_verdict.decision,
        Decision::Deny,
        "unknown tool call should be denied"
    );
}

#[test]
fn test_policy_reload_deny_to_permit() {
    let tmpdir = TempDir::new().expect("should create temp dir for policy reload test");

    // Start with empty dir -> default-deny
    let mut engine =
        PolicyEngine::new(tmpdir.path(), None).expect("should create engine from empty dir");

    let action = file_read_action("agent-1", "/tmp/test.txt");
    let verdict = engine.evaluate(&action);
    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "should deny before reload"
    );

    // Write a permit-all policy to the temp directory
    let policy_path = tmpdir.path().join("allow-all.cedar");
    std::fs::write(&policy_path, "permit(principal, action, resource);")
        .expect("should write permit policy file");

    // Reload and verify the new policy is picked up
    engine
        .reload(tmpdir.path())
        .expect("should reload policies successfully");

    let verdict = engine.evaluate(&action);
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "should allow after reloading permit-all policy"
    );
}

#[test]
fn test_cedar_schema_validation_rejects_invalid_policy() {
    // A syntactically broken Cedar policy should fail to parse
    let result = PolicyEngine::from_policies("this is not valid cedar {{{", None);
    assert!(
        result.is_err(),
        "invalid Cedar policy text should produce an error"
    );
}

#[test]
fn test_read_only_policy_allows_reads_denies_writes() {
    let engine =
        PolicyEngine::from_policies(ALLOW_READ_ONLY, None).expect("should create read-only engine");

    let read_action = file_read_action("agent-1", "/tmp/readme.txt");
    let verdict = engine.evaluate(&read_action);
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "read-only policy should allow FileRead"
    );

    let list_action = dir_list_action("agent-1", "/tmp");
    let verdict = engine.evaluate(&list_action);
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "read-only policy should allow DirList"
    );

    let write_action = file_write_action("agent-1", "/tmp/output.txt");
    let verdict = engine.evaluate(&write_action);
    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "read-only policy should deny FileWrite"
    );

    let delete_action = Action::new(
        "agent-1",
        ActionKind::FileDelete {
            path: PathBuf::from("/tmp/file.txt"),
        },
    );
    let verdict = engine.evaluate(&delete_action);
    assert_eq!(
        verdict.decision,
        Decision::Deny,
        "read-only policy should deny FileDelete"
    );
}

#[test]
fn test_allow_read_write_permits_files_denies_network() {
    let engine = PolicyEngine::from_policies(ALLOW_READ_WRITE, None)
        .expect("should create allow-read-write engine");

    // File operations should be allowed
    let read = engine.evaluate(&file_read_action("agent-1", "/tmp/data.csv"));
    assert_eq!(read.decision, Decision::Allow, "should allow FileRead");

    let write = engine.evaluate(&file_write_action("agent-1", "/tmp/out.txt"));
    assert_eq!(write.decision, Decision::Allow, "should allow FileWrite");

    let delete = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::FileDelete {
            path: PathBuf::from("/tmp/old.txt"),
        },
    ));
    assert_eq!(delete.decision, Decision::Allow, "should allow FileDelete");

    let dir_create = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::DirCreate {
            path: PathBuf::from("/tmp/newdir"),
        },
    ));
    assert_eq!(
        dir_create.decision,
        Decision::Allow,
        "should allow DirCreate"
    );

    // Network should be denied
    let net = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::NetConnect {
            host: "example.com".into(),
            port: 443,
        },
    ));
    assert_eq!(net.decision, Decision::Deny, "should deny NetConnect");

    // ToolCall should be denied
    let tool = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::ToolCall {
            tool: "bash".into(),
            args: serde_json::json!({}),
        },
    ));
    assert_eq!(tool.decision, Decision::Deny, "should deny ToolCall");
}

#[test]
fn test_ci_runner_matches_allow_read_write() {
    let rw_engine = PolicyEngine::from_policies(ALLOW_READ_WRITE, None)
        .expect("should create allow-read-write engine");
    let ci_engine =
        PolicyEngine::from_policies(CI_RUNNER, None).expect("should create ci-runner engine");

    // CI_RUNNER is defined as ALLOW_READ_WRITE; verify identical behavior
    let actions: Vec<Action> = vec![
        file_read_action("agent-1", "/tmp/f"),
        file_write_action("agent-1", "/tmp/f"),
        Action::new(
            "agent-1",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
        ),
        Action::new(
            "agent-1",
            ActionKind::ToolCall {
                tool: "bash".into(),
                args: serde_json::json!({}),
            },
        ),
    ];

    for action in &actions {
        let rw_verdict = rw_engine.evaluate(action);
        let ci_verdict = ci_engine.evaluate(action);
        assert_eq!(
            rw_verdict.decision, ci_verdict.decision,
            "CI_RUNNER and ALLOW_READ_WRITE should agree on {:?}",
            action.kind
        );
    }
}

#[test]
fn test_data_science_permits_network_denies_toolcall() {
    let engine =
        PolicyEngine::from_policies(DATA_SCIENCE, None).expect("should create data-science engine");

    // Files should be allowed
    let read = engine.evaluate(&file_read_action("agent-1", "/data/dataset.csv"));
    assert_eq!(read.decision, Decision::Allow, "should allow FileRead");

    let write = engine.evaluate(&file_write_action("agent-1", "/data/output.csv"));
    assert_eq!(write.decision, Decision::Allow, "should allow FileWrite");

    // Network should be allowed (unlike allow-read-write)
    let net = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::NetConnect {
            host: "api.openai.com".into(),
            port: 443,
        },
    ));
    assert_eq!(net.decision, Decision::Allow, "should allow NetConnect");

    // ToolCall should be denied
    let tool = engine.evaluate(&Action::new(
        "agent-1",
        ActionKind::ToolCall {
            tool: "shell".into(),
            args: serde_json::json!({}),
        },
    ));
    assert_eq!(tool.decision, Decision::Deny, "should deny ToolCall");
}

#[test]
fn test_policy_from_fixture_file() {
    let tmpdir = TempDir::new().expect("should create temp dir for fixture test");

    // Copy the read-only fixture policy into a temp dir
    let fixture_content = include_str!("../fixtures/policies/read-only.cedar");
    let policy_path = tmpdir.path().join("read-only.cedar");
    std::fs::write(&policy_path, fixture_content).expect("should write fixture policy");

    let engine = PolicyEngine::new(tmpdir.path(), None).expect("should create engine from fixture");

    let read_verdict = engine.evaluate(&file_read_action("agent-1", "/data/file.csv"));
    assert_eq!(
        read_verdict.decision,
        Decision::Allow,
        "fixture read-only policy should allow FileRead"
    );

    let write_verdict = engine.evaluate(&file_write_action("agent-1", "/data/file.csv"));
    assert_eq!(
        write_verdict.decision,
        Decision::Deny,
        "fixture read-only policy should deny FileWrite"
    );
}
