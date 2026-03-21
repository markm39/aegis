//! Integration and unit tests for the chat TUI.
//!
//! Tests live here rather than inline in mod.rs to keep that file focused
//! on the application logic. All items from mod.rs are in scope via `use super::*`.

use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::empty(),
    }
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::empty(),
    }
}

fn make_app() -> ChatApp {
    ChatApp::new(None, "claude-sonnet-4-20250514".into())
}

#[test]
fn chat_app_defaults() {
    let app = make_app();
    assert!(app.running);
    assert_eq!(app.input_mode, InputMode::Chat);
    assert!(app.messages.is_empty());
    assert_eq!(app.scroll_offset, 0);
    assert!(app.input_buffer.is_empty());
    assert_eq!(app.input_cursor, 0);
    assert!(!app.connected);
    assert_eq!(app.model, "claude-sonnet-4-20250514");
    assert!(app.conversation.is_empty());
    assert!(!app.awaiting_response);
}

#[test]
fn input_mode_transitions_escape_to_scroll() {
    let mut app = make_app();
    assert_eq!(app.input_mode, InputMode::Chat);
    app.handle_key(press(KeyCode::Esc));
    assert_eq!(app.input_mode, InputMode::Scroll);
}

#[test]
fn input_mode_escape_does_not_switch_when_buffer_has_text() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('a')));
    app.handle_key(press(KeyCode::Esc));
    // Should stay in Chat mode because buffer is not empty
    assert_eq!(app.input_mode, InputMode::Chat);
}

#[test]
fn input_mode_slash_enters_command() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('/')));
    assert_eq!(app.input_mode, InputMode::Command);
}

#[test]
fn input_mode_slash_inserts_when_buffer_not_empty() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('a')));
    app.handle_key(press(KeyCode::Char('/')));
    assert_eq!(app.input_mode, InputMode::Chat);
    assert_eq!(app.input_buffer, "a/");
}

#[test]
fn command_mode_escape_returns_to_chat() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('/')));
    assert_eq!(app.input_mode, InputMode::Command);
    app.handle_key(press(KeyCode::Esc));
    assert_eq!(app.input_mode, InputMode::Chat);
    assert!(app.command_buffer.is_empty());
}

#[test]
fn scroll_mode_escape_returns_to_chat() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Esc)); // -> Scroll
    assert_eq!(app.input_mode, InputMode::Scroll);
    app.handle_key(press(KeyCode::Esc)); // -> Chat
    assert_eq!(app.input_mode, InputMode::Chat);
}

#[test]
fn scroll_mode_printable_char_returns_to_chat() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Esc)); // -> Scroll
    assert_eq!(app.input_mode, InputMode::Scroll);
    app.handle_key(press(KeyCode::Char('h')));
    assert_eq!(app.input_mode, InputMode::Chat);
    assert_eq!(app.input_buffer, "h");
}

#[test]
fn scroll_mode_slash_enters_command() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Esc)); // -> Scroll
    app.handle_key(press(KeyCode::Char('/')));
    assert_eq!(app.input_mode, InputMode::Command);
}

#[test]
fn ctrl_c_clears_buffer_when_not_empty() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('h')));
    app.handle_key(press(KeyCode::Char('i')));
    assert_eq!(app.input_buffer, "hi");
    app.handle_key(ctrl('c'));
    assert!(app.input_buffer.is_empty());
    assert!(app.running); // should not quit
}

#[test]
fn ctrl_c_quits_when_buffer_empty() {
    let mut app = make_app();
    assert!(app.running);
    app.handle_key(ctrl('c'));
    assert!(!app.running);
}

#[test]
fn text_input_and_cursor() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('h')));
    app.handle_key(press(KeyCode::Char('i')));
    assert_eq!(app.input_buffer, "hi");
    assert_eq!(app.input_cursor, 2);

    app.handle_key(press(KeyCode::Left));
    assert_eq!(app.input_cursor, 1);

    app.handle_key(press(KeyCode::Home));
    assert_eq!(app.input_cursor, 0);

    app.handle_key(press(KeyCode::End));
    assert_eq!(app.input_cursor, 2);

    app.handle_key(press(KeyCode::Backspace));
    assert_eq!(app.input_buffer, "h");
}

#[test]
fn command_text_input() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('/')));
    app.handle_key(press(KeyCode::Char('h')));
    app.handle_key(press(KeyCode::Char('e')));
    app.handle_key(press(KeyCode::Char('l')));
    app.handle_key(press(KeyCode::Char('p')));
    assert_eq!(app.command_buffer, "help");
}

#[test]
fn command_enter_executes_and_returns_to_chat() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('/')));
    app.handle_key(press(KeyCode::Char('q')));
    app.handle_key(press(KeyCode::Char('u')));
    app.handle_key(press(KeyCode::Char('i')));
    app.handle_key(press(KeyCode::Char('t')));
    app.handle_key(press(KeyCode::Enter));
    assert_eq!(app.input_mode, InputMode::Chat);
    assert!(!app.running);
}

#[test]
fn release_events_are_ignored() {
    let mut app = make_app();
    let release = KeyEvent {
        code: KeyCode::Char('q'),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: crossterm::event::KeyEventState::empty(),
    };
    app.handle_key(release);
    assert!(app.running); // Should not have processed it
}

#[test]
fn enter_adds_to_conversation() {
    let mut app = make_app();
    // Type "hello"
    for c in "hello".chars() {
        app.handle_key(press(KeyCode::Char(c)));
    }
    assert_eq!(app.input_buffer, "hello");

    // Press enter -- no daemon client so LLM request will fail in thread,
    // but conversation and messages should be updated immediately.
    app.handle_key(press(KeyCode::Enter));

    assert!(app.input_buffer.is_empty());
    assert_eq!(app.conversation.len(), 1);
    assert_eq!(app.conversation[0].content, "hello");
    assert_eq!(app.messages.len(), 1);
    assert!(matches!(app.messages[0].role, MessageRole::User));
    assert_eq!(app.messages[0].content, "hello");
    assert!(app.awaiting_response);
}

#[test]
fn enter_ignored_when_awaiting_response() {
    let mut app = make_app();
    app.awaiting_response = true;
    app.input_buffer = "test".into();
    app.input_cursor = 4;
    app.handle_key(press(KeyCode::Enter));
    // Should not have been processed
    assert_eq!(app.input_buffer, "test");
    assert!(app.conversation.is_empty());
}

#[test]
fn clear_command_clears_conversation() {
    let mut app = make_app();
    app.conversation.push(LlmMessage::user("hello"));
    app.messages
        .push(ChatMessage::new(MessageRole::User, "hello".to_string()));
    app.scroll_offset = 5;

    app.execute_command("clear");

    assert!(app.messages.is_empty());
    assert!(app.conversation.is_empty());
    assert_eq!(app.scroll_offset, 0);
}

#[test]
fn model_command_opens_picker() {
    let mut app = make_app();
    app.execute_command("model");
    assert!(app.overlay.is_some());
    assert!(matches!(app.overlay, Some(Overlay::ModelPicker { .. })));
}

#[test]
fn model_command_sets_new_model() {
    let mut app = make_app();
    app.execute_command("model gpt-4o");
    assert_eq!(app.model, "gpt-4o");
    assert!(app.command_result.as_ref().unwrap().contains("gpt-4o"));
}

#[test]
fn unknown_command_shows_error() {
    let mut app = make_app();
    app.execute_command("foobar");
    assert!(
        app.command_result
            .as_ref()
            .unwrap()
            .contains("Unknown command")
    );
}

#[test]
fn paste_inserts_in_chat_mode() {
    let mut app = make_app();
    app.handle_paste("hello world");
    assert_eq!(app.input_buffer, "hello world");
}

#[test]
fn paste_inserts_in_command_mode() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Char('/')));
    app.handle_paste("status");
    assert_eq!(app.command_buffer, "status");
}

#[test]
fn paste_in_scroll_mode_switches_to_chat() {
    let mut app = make_app();
    app.handle_key(press(KeyCode::Esc)); // -> Scroll
    app.handle_paste("hello");
    assert_eq!(app.input_mode, InputMode::Chat);
    assert_eq!(app.input_buffer, "hello");
}

#[test]
fn input_history_navigation() {
    let mut app = make_app();
    app.input_history = vec!["first".into(), "second".into(), "third".into()];

    // History navigation requires a non-empty buffer (empty buffer scrolls).
    app.input_buffer = "draft".into();
    app.input_cursor = 5;

    // Up goes to latest entry.
    app.handle_key(press(KeyCode::Up));
    assert_eq!(app.input_buffer, "third");
    assert_eq!(app.history_index, Some(2));

    // Up again goes to "second".
    app.handle_key(press(KeyCode::Up));
    assert_eq!(app.input_buffer, "second");
    assert_eq!(app.history_index, Some(1));

    // Down goes forward back to "third".
    app.handle_key(press(KeyCode::Down));
    assert_eq!(app.input_buffer, "third");
    assert_eq!(app.history_index, Some(2));
}

#[test]
fn poll_llm_handles_response() {
    let mut app = make_app();
    let (tx, rx) = mpsc::channel();
    app.agent_rx = Some(rx);
    app.awaiting_response = true;

    // Simulate a response + done event
    tx.send(AgentLoopEvent::Response(LlmResponse {
        content: "Hello! How can I help?".into(),
        model: "claude-sonnet-4-20250514".into(),
        usage: aegis_types::llm::LlmUsage {
            input_tokens: 10,
            output_tokens: 8,
        },
        tool_calls: vec![],
        stop_reason: None,
    }))
    .unwrap();
    tx.send(AgentLoopEvent::Done).unwrap();

    app.poll_llm();

    assert!(!app.awaiting_response);
    assert_eq!(app.messages.len(), 1);
    assert!(matches!(app.messages[0].role, MessageRole::Assistant));
    assert_eq!(app.messages[0].content, "Hello! How can I help?");
    assert_eq!(app.conversation.len(), 1);
    assert_eq!(app.conversation[0].content, "Hello! How can I help?");
}

#[test]
fn poll_llm_handles_error() {
    let mut app = make_app();
    let (tx, rx) = mpsc::channel();
    app.agent_rx = Some(rx);
    app.awaiting_response = true;

    tx.send(AgentLoopEvent::Error("API key not set".into()))
        .unwrap();

    app.poll_llm();

    assert!(!app.awaiting_response);
    assert_eq!(app.messages.len(), 1);
    assert!(matches!(app.messages[0].role, MessageRole::System));
    assert!(app.messages[0].content.contains("API key not set"));
}

#[test]
fn poll_llm_handles_tool_calls() {
    let mut app = make_app();
    let (tx, rx) = mpsc::channel();
    app.agent_rx = Some(rx);
    app.awaiting_response = true;

    let tool_calls = vec![LlmToolCall {
        id: "call_1".into(),
        name: "read_file".into(),
        input: serde_json::json!({"file_path": "/tmp/test.txt"}),
    }];
    tx.send(AgentLoopEvent::ToolCalls(tool_calls)).unwrap();

    app.poll_llm();

    assert_eq!(app.messages.len(), 1);
    assert!(matches!(app.messages[0].role, MessageRole::ToolCall { .. }));
}

#[test]
fn poll_llm_handles_tool_result() {
    let mut app = make_app();
    let (tx, rx) = mpsc::channel();
    app.agent_rx = Some(rx);
    app.awaiting_response = true;

    tx.send(AgentLoopEvent::ToolResult {
        tool_call_id: "call_1".into(),
        tool_name: "read_file".into(),
        result: "file contents here".into(),
    })
    .unwrap();

    app.poll_llm();

    assert_eq!(app.messages.len(), 1);
    assert!(matches!(app.messages[0].role, MessageRole::System));
    assert!(app.messages[0].content.contains("file contents here"));
    // Tool result should be added to conversation
    assert_eq!(app.conversation.len(), 1);
    assert_eq!(app.conversation[0].role, aegis_types::llm::LlmRole::Tool);
}

#[test]
fn approval_keys_work() {
    let mut app = make_app();
    let (_, event_rx) = mpsc::channel();
    let (approval_tx, _approval_rx) = mpsc::channel();
    app.agent_rx = Some(event_rx);
    app.approval_tx = Some(approval_tx);
    app.awaiting_approval = true;
    app.pending_tool_desc = Some("bash: ls -la".into());
    app.messages.push(ChatMessage::new(
        MessageRole::Permission {
            prompt: "bash: ls -la".into(),
            resolved: None,
            diff_preview: vec![],
        },
        "Allow bash? [y]es / [n]o / [a]ll".into(),
    ));

    app.handle_key(press(KeyCode::Char('y')));

    assert!(!app.awaiting_approval);
    assert!(app.pending_tool_desc.is_none());
    // Permission message should be resolved
    if let MessageRole::Permission { resolved, .. } = &app.messages[0].role {
        assert_eq!(*resolved, Some(true));
    } else {
        panic!("expected Permission role");
    }
}

#[test]
fn approval_a_sets_auto_approve() {
    let mut app = make_app();
    let (_, event_rx) = mpsc::channel();
    let (approval_tx, _approval_rx) = mpsc::channel();
    app.agent_rx = Some(event_rx);
    app.approval_tx = Some(approval_tx);
    app.awaiting_approval = true;
    app.pending_tool_desc = Some("bash: ls -la".into());
    app.messages.push(ChatMessage::new(
        MessageRole::Permission {
            prompt: "bash: ls -la".into(),
            resolved: None,
            diff_preview: vec![],
        },
        "Allow bash?".into(),
    ));

    app.handle_key(press(KeyCode::Char('a')));

    assert!(!app.awaiting_approval);
    assert!(app.auto_approve_turn);
}

#[test]
fn safe_tools_identified_correctly() {
    assert!(is_safe_tool("read_file"));
    assert!(is_safe_tool("glob_search"));
    assert!(is_safe_tool("grep_search"));
    assert!(!is_safe_tool("bash"));
    assert!(!is_safe_tool("write_file"));
    assert!(!is_safe_tool("edit_file"));
}

#[test]
fn summarize_tool_input_formats_correctly() {
    assert_eq!(
        summarize_tool_input("bash", &serde_json::json!({"command": "ls -la"})),
        "ls -la"
    );
    assert_eq!(
        summarize_tool_input(
            "read_file",
            &serde_json::json!({"file_path": "/tmp/test.txt"})
        ),
        "/tmp/test.txt"
    );
    assert_eq!(
        summarize_tool_input("glob_search", &serde_json::json!({"pattern": "**/*.rs"})),
        "**/*.rs"
    );
}

#[test]
fn local_completions_filters() {
    let completions = local_completions("da", &[]);
    assert!(completions.contains(&"daemon start".to_string()));
    assert!(completions.contains(&"daemon stop".to_string()));
    assert!(completions.contains(&"daemon status".to_string()));
    assert!(!completions.contains(&"quit".to_string()));
}

#[test]
fn local_completions_empty_input() {
    let completions = local_completions("", &[]);
    assert_eq!(completions.len(), COMMANDS.len());
}

#[test]
fn y_inserts_char_normally() {
    let mut app = make_app();
    // No pending prompts -- y should just insert the character
    app.handle_key(press(KeyCode::Char('y')));
    assert_eq!(app.input_buffer, "y");
}

#[test]
fn detect_model_returns_fallback() {
    // In a test environment without daemon.toml or API keys, detect_model
    // should return a sensible default. We just verify it returns a
    // non-empty string.
    let model = detect_model();
    assert!(!model.is_empty());
}

// -- Risk classification ------------------------------------------------

#[test]
fn classify_read_file_is_informational() {
    let input = serde_json::json!({"file_path": "/tmp/test.rs"});
    assert_eq!(
        classify_tool_risk("read_file", &input),
        ActionRisk::Informational
    );
}

#[test]
fn classify_write_file_is_medium() {
    let input = serde_json::json!({"file_path": "/tmp/test.rs", "content": "hello"});
    assert_eq!(classify_tool_risk("write_file", &input), ActionRisk::Medium);
}

#[test]
fn classify_edit_file_is_medium() {
    let input = serde_json::json!({"file_path": "/tmp/test.rs"});
    assert_eq!(classify_tool_risk("edit_file", &input), ActionRisk::Medium);
}

#[test]
fn classify_bash_ls_is_low() {
    let input = serde_json::json!({"command": "ls -la /tmp"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
}

#[test]
fn classify_bash_git_status_is_low() {
    let input = serde_json::json!({"command": "git status"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
}

#[test]
fn classify_bash_cargo_test_is_low() {
    let input = serde_json::json!({"command": "cargo test --workspace"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
}

#[test]
fn classify_bash_rm_rf_is_high() {
    let input = serde_json::json!({"command": "rm -rf /tmp/project"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
}

#[test]
fn classify_bash_force_push_is_high() {
    let input = serde_json::json!({"command": "git push --force origin main"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
}

#[test]
fn classify_bash_sudo_is_high() {
    let input = serde_json::json!({"command": "sudo apt install foo"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
}

#[test]
fn classify_bash_git_commit_is_medium() {
    let input = serde_json::json!({"command": "git commit -m \"fix\""});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Medium);
}

#[test]
fn classify_bash_general_command_is_medium() {
    let input = serde_json::json!({"command": "make build"});
    assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Medium);
}

#[test]
fn classify_unknown_tool_is_high() {
    let input = serde_json::json!({});
    assert_eq!(
        classify_tool_risk("some_new_tool", &input),
        ActionRisk::High
    );
}

// -- Approval profile logic ---------------------------------------------

#[test]
fn manual_profile_only_approves_safe_tools() {
    let profile = ApprovalProfile::Manual;
    let bash_input = serde_json::json!({"command": "ls"});
    assert!(!should_auto_approve_tool(
        "bash",
        &bash_input,
        false,
        &profile
    ));
    assert!(should_auto_approve_tool(
        "read_file",
        &serde_json::json!({}),
        false,
        &profile
    ));
}

#[test]
fn full_auto_approves_everything() {
    let profile = ApprovalProfile::FullAuto;
    let input = serde_json::json!({"command": "rm -rf /"});
    assert!(should_auto_approve_tool("bash", &input, false, &profile));
}

#[test]
fn auto_edits_approves_medium_risk() {
    let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
    let write_input = serde_json::json!({"file_path": "/tmp/x", "content": "y"});
    assert!(should_auto_approve_tool(
        "write_file",
        &write_input,
        false,
        &profile
    ));
}

#[test]
fn auto_edits_blocks_high_risk() {
    let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
    let rm_input = serde_json::json!({"command": "rm -rf /tmp"});
    assert!(!should_auto_approve_tool(
        "bash", &rm_input, false, &profile
    ));
}

#[test]
fn auto_edits_approves_low_risk_bash() {
    let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
    let ls_input = serde_json::json!({"command": "ls -la"});
    assert!(should_auto_approve_tool("bash", &ls_input, false, &profile));
}

#[test]
fn auto_approve_all_overrides_profile() {
    let profile = ApprovalProfile::Manual;
    let bash_input = serde_json::json!({"command": "rm -rf /"});
    // When user pressed 'a', auto_approve_all is true -- overrides profile.
    assert!(should_auto_approve_tool(
        "bash",
        &bash_input,
        true,
        &profile
    ));
}

// -- Parse approval mode ------------------------------------------------

#[test]
fn parse_approval_mode_variants() {
    assert_eq!(parse_approval_mode("off"), ApprovalProfile::Manual);
    assert_eq!(parse_approval_mode("manual"), ApprovalProfile::Manual);
    assert_eq!(
        parse_approval_mode("edits"),
        ApprovalProfile::AutoApprove(ActionRisk::Medium)
    );
    assert_eq!(
        parse_approval_mode("high"),
        ApprovalProfile::AutoApprove(ActionRisk::High)
    );
    assert_eq!(parse_approval_mode("full"), ApprovalProfile::FullAuto);
    assert_eq!(parse_approval_mode("full-auto"), ApprovalProfile::FullAuto);
}

#[test]
fn parse_approval_mode_unknown_defaults_to_manual() {
    assert_eq!(parse_approval_mode("bogus"), ApprovalProfile::Manual);
}

// -- Approval profile label ---------------------------------------------

#[test]
fn approval_profile_labels() {
    assert_eq!(approval_profile_label(&ApprovalProfile::Manual), "manual");
    assert_eq!(
        approval_profile_label(&ApprovalProfile::AutoApprove(ActionRisk::Medium)),
        "auto-edits"
    );
    assert_eq!(
        approval_profile_label(&ApprovalProfile::AutoApprove(ActionRisk::High)),
        "auto-high"
    );
    assert_eq!(
        approval_profile_label(&ApprovalProfile::FullAuto),
        "full-auto"
    );
}

// -- /auto commands -----------------------------------------------------

#[test]
fn auto_command_sets_profile() {
    let mut app = make_app();
    assert_eq!(app.approval_profile, ApprovalProfile::Manual);

    app.execute_command("auto edits");
    assert_eq!(
        app.approval_profile,
        ApprovalProfile::AutoApprove(ActionRisk::Medium)
    );

    app.execute_command("auto high");
    assert_eq!(
        app.approval_profile,
        ApprovalProfile::AutoApprove(ActionRisk::High)
    );

    app.execute_command("auto full");
    assert_eq!(app.approval_profile, ApprovalProfile::FullAuto);

    app.execute_command("auto off");
    assert_eq!(app.approval_profile, ApprovalProfile::Manual);
}

#[test]
fn auto_command_shows_status() {
    let mut app = make_app();
    app.execute_command("auto");
    assert!(app.command_result.is_some());
    let result = app.command_result.unwrap();
    assert!(result.contains("manual"));
}
