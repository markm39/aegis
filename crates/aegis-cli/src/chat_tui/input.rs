//! User input handling for the chat TUI.
//!
//! Covers all three input modes (Chat, Scroll, Command), tab completion,
//! command history navigation, paste handling, and bang-command (`!cmd`)
//! execution. Extracted from `mod.rs` to keep `ChatApp`'s impl block focused
//! on application lifecycle.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::message::{ChatMessage, MessageRole};
use super::persistence;
use super::hooks;
use super::{ChatApp, InputMode, Overlay};
use super::COMMANDS;
use crate::tui_utils::delete_word_backward_pos;
use aegis_types::llm::LlmMessage;

/// Dispatch a key event to the appropriate input mode handler.
///
/// Called from `ChatApp::handle_key`. Only processes `KeyEventKind::Press`
/// events; ignores release and repeat.
pub fn handle_key(app: &mut ChatApp, key: KeyEvent) {
    // Only handle key press events (not release/repeat).
    if key.kind != KeyEventKind::Press {
        return;
    }

    // If an overlay is active, route all input there.
    if app.overlay.is_some() {
        app.handle_overlay_key(key);
        return;
    }

    // Ctrl+C: cancel or quit
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        match app.input_mode {
            InputMode::Command => {
                app.input_mode = InputMode::Chat;
                app.command_buffer.clear();
                app.command_cursor = 0;
                app.command_completions.clear();
                app.completion_idx = None;
            }
            InputMode::Chat if !app.input_buffer.is_empty() => {
                app.input_buffer.clear();
                app.input_cursor = 0;
            }
            InputMode::Scroll => {
                app.input_mode = InputMode::Chat;
            }
            _ => {
                // Auto-save on quit if conversation is non-empty.
                if !app.conversation.is_empty() {
                    let _ = persistence::save_conversation(
                        &app.session_id,
                        &app.conversation,
                        &app.model,
                    );
                }
                hooks::fire_hook_event(hooks::ChatHookEvent::SessionEnd {
                    session_id: app.session_id.clone(),
                    message_count: app.conversation.len(),
                });
                app.running = false;
            }
        }
        return;
    }

    app.clear_stale_result();

    // Handle Escape globally before per-mode dispatch.
    if key.code == KeyCode::Esc {
        let is_double = app
            .last_esc_at
            .is_some_and(|t| t.elapsed().as_millis() < 400);
        app.last_esc_at = Some(std::time::Instant::now());

        if is_double && !app.snapshots.is_empty() {
            // Double Esc: open the conversation restore picker.
            app.overlay = Some(Overlay::RestorePicker {
                snapshots: app.snapshots.clone(),
                selected: 0,
            });
            return;
        }

        if app.awaiting_response {
            app.abort_current_request();
            return;
        }

        if !app.input_buffer.is_empty() {
            // Clear the current input, discarding any history navigation.
            app.input_buffer.clear();
            app.input_cursor = 0;
            app.history_index = None;
            app.input_draft.clear();
            return;
        }
        // Buffer is empty -- fall through so per-mode handlers can switch
        // between Chat/Scroll as before.
    }

    match app.input_mode {
        InputMode::Chat => handle_chat_key(app, key),
        InputMode::Scroll => handle_scroll_key(app, key),
        InputMode::Command => handle_command_key(app, key),
    }
}

/// Handle keys in Chat mode (default, input focused).
pub fn handle_chat_key(app: &mut ChatApp, key: KeyEvent) {
    // Handle approval keys when waiting for tool approval.
    if app.awaiting_approval {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.handle_approval_key(true, false);
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                app.handle_approval_key(true, true);
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                app.handle_approval_key(false, false);
            }
            _ => {} // Ignore other keys during approval
        }
        return;
    }

    match key.code {
        KeyCode::Enter => {
            if app.awaiting_response {
                if app.heartbeat_in_flight && !app.input_buffer.is_empty() {
                    // User typed while heartbeat is running -- abort heartbeat.
                    app.abort_heartbeat_for_user_input();
                } else {
                    return; // Don't stack requests
                }
            }
            if !app.input_buffer.is_empty() {
                app.last_user_interaction = Instant::now();
                let text = app.input_buffer.clone();

                // Bang command: !<cmd> runs locally, not through the LLM.
                if text.starts_with('!') && text.len() > 1 {
                    execute_bang_command(app, &text[1..]);
                    if app.input_history.last().map(String::as_str) != Some(&text) {
                        app.input_history.push(text.clone());
                        persistence::append_history('>', &text);
                    }
                    app.history_index = None;
                    app.input_buffer.clear();
                    app.input_cursor = 0;
                    return;
                }

                // Add to conversation and display
                app.conversation.push(LlmMessage::user(text.clone()));
                app.messages
                    .push(ChatMessage::new(MessageRole::User, text.clone()));
                app.scroll_offset = 0;

                // Send to LLM
                app.awaiting_response = true;
                app.send_llm_request();

                // Update input state
                if app.input_history.last().map(String::as_str) != Some(&text) {
                    app.input_history.push(text.clone());
                    persistence::append_history('>', &text);
                }
                app.history_index = None;
                app.input_buffer.clear();
                app.input_cursor = 0;
            }
        }
        KeyCode::Up => {
            if app.input_buffer.is_empty() {
                // Scroll messages up (from wheel via \x1b[?1007h or direct keypress).
                app.scroll_offset = (app.scroll_offset + 3).min(app.max_scroll());
            } else {
                // Browse input history backward (shell-style).
                if !app.input_history.is_empty() {
                    if app.history_index.is_none() {
                        app.input_draft = app.input_buffer.clone();
                    }
                    let idx = match app.history_index {
                        Some(0) => 0,
                        Some(i) => i - 1,
                        None => app.input_history.len() - 1,
                    };
                    app.history_index = Some(idx);
                    app.input_buffer = app.input_history[idx].clone();
                    app.input_cursor = app.input_buffer.len();
                }
            }
        }
        KeyCode::Down => {
            if app.input_buffer.is_empty() && app.scroll_offset > 0 {
                // Scroll messages down (from wheel via \x1b[?1007h or direct keypress).
                app.scroll_offset = app.scroll_offset.saturating_sub(3);
            } else {
                // Browse input history forward (shell-style).
                match app.history_index {
                    Some(i) if i + 1 < app.input_history.len() => {
                        app.history_index = Some(i + 1);
                        app.input_buffer = app.input_history[i + 1].clone();
                        app.input_cursor = app.input_buffer.len();
                    }
                    Some(_) => {
                        app.history_index = None;
                        app.input_buffer = app.input_draft.clone();
                        app.input_cursor = app.input_buffer.len();
                        app.input_draft.clear();
                    }
                    None => {}
                }
            }
        }
        KeyCode::Char('/') if app.input_buffer.is_empty() => {
            enter_command_mode(app);
        }
        KeyCode::Esc if app.awaiting_response => {
            app.abort_current_request();
        }
        KeyCode::Esc if app.input_buffer.is_empty() => {
            app.input_mode = InputMode::Scroll;
        }
        // Text editing
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
            'a' => app.input_cursor = 0,
            'e' => app.input_cursor = app.input_buffer.len(),
            'u' => {
                app.input_buffer.drain(..app.input_cursor);
                app.input_cursor = 0;
            }
            'w' => {
                if app.input_cursor > 0 {
                    let new_pos =
                        delete_word_backward_pos(&app.input_buffer, app.input_cursor);
                    app.input_buffer.drain(new_pos..app.input_cursor);
                    app.input_cursor = new_pos;
                }
            }
            _ => {}
        },
        KeyCode::Char(c) => {
            app.input_buffer.insert(app.input_cursor, c);
            app.input_cursor += c.len_utf8();
        }
        KeyCode::Backspace => {
            if app.input_cursor > 0 {
                let prev = app.input_buffer[..app.input_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.input_buffer.remove(prev);
                app.input_cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.input_cursor > 0 {
                app.input_cursor = app.input_buffer[..app.input_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.input_cursor < app.input_buffer.len() {
                app.input_cursor = app.input_buffer[app.input_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.input_cursor + i)
                    .unwrap_or(app.input_buffer.len());
            }
        }
        KeyCode::Delete => {
            if app.input_cursor < app.input_buffer.len() {
                app.input_buffer.remove(app.input_cursor);
            }
        }
        KeyCode::Home => {
            app.input_cursor = 0;
        }
        KeyCode::End => {
            app.input_cursor = app.input_buffer.len();
        }
        _ => {}
    }
}

/// Handle keys in Scroll mode (message history navigation).
pub fn handle_scroll_key(app: &mut ChatApp, key: KeyEvent) {
    let max_scroll = app.max_scroll();
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            app.scroll_offset = app.scroll_offset.saturating_sub(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.scroll_offset = (app.scroll_offset + 1).min(max_scroll);
        }
        KeyCode::Char('g') | KeyCode::Home => {
            app.scroll_offset = max_scroll;
        }
        KeyCode::Char('G') | KeyCode::End => {
            app.scroll_offset = 0;
        }
        KeyCode::PageUp => {
            app.scroll_offset = (app.scroll_offset + 20).min(max_scroll);
        }
        KeyCode::PageDown => {
            app.scroll_offset = app.scroll_offset.saturating_sub(20);
        }
        KeyCode::Esc => {
            app.input_mode = InputMode::Chat;
            return; // don't update scroll timestamp
        }
        KeyCode::Char('/') => {
            enter_command_mode(app);
            return;
        }
        KeyCode::Char(c) => {
            app.input_mode = InputMode::Chat;
            app.input_buffer.insert(app.input_cursor, c);
            app.input_cursor += c.len_utf8();
            return;
        }
        _ => { return; }
    }
    app.last_scroll_at = Some(std::time::Instant::now());
}

/// Handle mouse events (scroll wheel).
pub fn handle_mouse(app: &mut ChatApp, mouse: crossterm::event::MouseEvent) {
    use crossterm::event::MouseEventKind;
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            app.scroll_offset = (app.scroll_offset + 1).min(app.max_scroll());
            app.last_scroll_at = Some(std::time::Instant::now());
        }
        MouseEventKind::ScrollDown => {
            app.scroll_offset = app.scroll_offset.saturating_sub(1);
            app.last_scroll_at = Some(std::time::Instant::now());
        }
        _ => {}
    }
}

/// Enter command mode (opens the `/` bar).
pub fn enter_command_mode(app: &mut ChatApp) {
    app.input_mode = InputMode::Command;
    app.command_buffer.clear();
    app.command_cursor = 0;
    app.command_completions.clear();
    app.completion_idx = None;
    app.command_result = None;
    app.command_result_at = None;
    app.command_history_index = None;
}

/// Handle keys in Command mode (/ bar).
pub fn handle_command_key(app: &mut ChatApp, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Chat;
            app.command_buffer.clear();
            app.command_cursor = 0;
            app.command_completions.clear();
            app.completion_idx = None;
        }
        KeyCode::Enter => {
            let buffer = app.command_buffer.clone();
            if !buffer.is_empty() {
                if app.command_history.last().map(String::as_str) != Some(&buffer) {
                    app.command_history.push(buffer.clone());
                    persistence::append_history('/', &buffer);
                }
                app.execute_command(&buffer);
            }
            app.input_mode = InputMode::Chat;
            app.command_buffer.clear();
            app.command_cursor = 0;
            app.command_completions.clear();
            app.completion_idx = None;
        }
        KeyCode::Tab => {
            cycle_completion(app);
        }
        KeyCode::BackTab => {
            cycle_completion_back(app);
        }
        KeyCode::Up => {
            command_history_prev(app);
        }
        KeyCode::Down => {
            command_history_next(app);
        }
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
            'a' => app.command_cursor = 0,
            'e' => app.command_cursor = app.command_buffer.len(),
            'u' => {
                app.command_buffer.drain(..app.command_cursor);
                app.command_cursor = 0;
                update_completions(app);
            }
            'w' => {
                if app.command_cursor > 0 {
                    let new_pos =
                        delete_word_backward_pos(&app.command_buffer, app.command_cursor);
                    app.command_buffer.drain(new_pos..app.command_cursor);
                    app.command_cursor = new_pos;
                    update_completions(app);
                }
            }
            _ => {}
        },
        KeyCode::Char(c) => {
            app.command_buffer.insert(app.command_cursor, c);
            app.command_cursor += c.len_utf8();
            update_completions(app);
        }
        KeyCode::Backspace => {
            if app.command_cursor > 0 {
                let prev = app.command_buffer[..app.command_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.command_buffer.remove(prev);
                app.command_cursor = prev;
                update_completions(app);
            }
        }
        KeyCode::Left => {
            if app.command_cursor > 0 {
                app.command_cursor = app.command_buffer[..app.command_cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.command_cursor < app.command_buffer.len() {
                app.command_cursor = app.command_buffer[app.command_cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.command_cursor + i)
                    .unwrap_or(app.command_buffer.len());
            }
        }
        KeyCode::Delete => {
            if app.command_cursor < app.command_buffer.len() {
                app.command_buffer.remove(app.command_cursor);
                update_completions(app);
            }
        }
        KeyCode::Home => {
            app.command_cursor = 0;
        }
        KeyCode::End => {
            app.command_cursor = app.command_buffer.len();
        }
        _ => {}
    }
}

/// Update tab completions based on current command buffer.
pub fn update_completions(app: &mut ChatApp) {
    app.command_completions =
        local_completions(&app.command_buffer, &app.skill_command_names);
    app.completion_idx = None;
}

/// Cycle to the next completion.
pub fn cycle_completion(app: &mut ChatApp) {
    if app.command_completions.is_empty() {
        update_completions(app);
        if app.command_completions.is_empty() {
            return;
        }
    }
    let idx = match app.completion_idx {
        Some(i) => (i + 1) % app.command_completions.len(),
        None => 0,
    };
    app.completion_idx = Some(idx);
    let completion = app.command_completions[idx].clone();
    app.command_buffer = apply_completion(&app.command_buffer, &completion);
    app.command_cursor = app.command_buffer.len();
}

/// Cycle to the previous completion.
pub fn cycle_completion_back(app: &mut ChatApp) {
    if app.command_completions.is_empty() {
        update_completions(app);
        if app.command_completions.is_empty() {
            return;
        }
    }
    let idx = match app.completion_idx {
        Some(0) | None => app.command_completions.len() - 1,
        Some(i) => i - 1,
    };
    app.completion_idx = Some(idx);
    let completion = app.command_completions[idx].clone();
    app.command_buffer = apply_completion(&app.command_buffer, &completion);
    app.command_cursor = app.command_buffer.len();
}

/// Navigate to previous command in history.
pub fn command_history_prev(app: &mut ChatApp) {
    if app.command_history.is_empty() {
        return;
    }
    let idx = match app.command_history_index {
        Some(0) => 0,
        Some(i) => i - 1,
        None => app.command_history.len() - 1,
    };
    app.command_history_index = Some(idx);
    app.command_buffer = app.command_history[idx].clone();
    app.command_cursor = app.command_buffer.len();
}

/// Navigate to next command in history.
pub fn command_history_next(app: &mut ChatApp) {
    match app.command_history_index {
        Some(i) if i + 1 < app.command_history.len() => {
            app.command_history_index = Some(i + 1);
            app.command_buffer = app.command_history[i + 1].clone();
            app.command_cursor = app.command_buffer.len();
        }
        Some(_) => {
            app.command_history_index = None;
            app.command_buffer.clear();
            app.command_cursor = 0;
        }
        None => {}
    }
}

/// Rebuild display messages from the LLM conversation history.
///
/// Used after loading a saved conversation to populate the chat view.
pub fn rebuild_display_messages(app: &mut ChatApp) {
    app.messages.clear();
    for msg in &app.conversation {
        match msg.role {
            aegis_types::llm::LlmRole::User => {
                app.messages
                    .push(ChatMessage::new(MessageRole::User, msg.content.clone()));
            }
            aegis_types::llm::LlmRole::Assistant => {
                app.messages.push(ChatMessage::new(
                    MessageRole::Assistant,
                    msg.content.clone(),
                ));
            }
            _ => {} // Skip tool results and system for now
        }
    }
    app.scroll_offset = 0;
}

/// Execute a bang command (`!<cmd>`) -- runs a shell command locally and
/// displays the output inline as a system message.
pub fn execute_bang_command(app: &mut ChatApp, cmd: &str) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }

    // Show the command in chat.
    app.messages
        .push(ChatMessage::new(MessageRole::User, format!("!{cmd}")));

    // Run locally via the user's shell.
    let output = std::process::Command::new("sh").arg("-c").arg(cmd).output();

    let result = match output {
        Ok(out) => {
            let mut text = String::new();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stdout.is_empty() {
                text.push_str(&stdout);
            }
            if !stderr.is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str("[stderr] ");
                text.push_str(&stderr);
            }
            if !out.status.success() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&format!("[exit {}]", out.status));
            }
            if text.is_empty() {
                text.push_str("[no output]");
            }
            // Truncate very long output.
            const MAX_BANG_OUTPUT: usize = 40_000;
            if text.len() > MAX_BANG_OUTPUT {
                text.truncate(MAX_BANG_OUTPUT);
                text.push_str("\n[...truncated]");
            }
            text
        }
        Err(e) => format!("[error] {e}"),
    };

    app.messages
        .push(ChatMessage::new(MessageRole::System, result));
    app.scroll_offset = 0;
}

/// Handle a paste event.
///
/// Routes the pasted text to the active input field: Login key input,
/// Setup wizard, command bar, or chat input.
pub fn handle_paste(app: &mut ChatApp, text: &str) {
    // If a Login overlay with key input is active, paste there.
    if let Some(Overlay::Login {
        key_input: Some(ref mut input),
        ..
    }) = app.overlay
    {
        let cleaned = text.replace(['\n', '\r'], "");
        input.buffer.insert_str(input.cursor, &cleaned);
        input.cursor += cleaned.len();
        input.error = None;
        return;
    }

    // If a Setup wizard overlay is active, simulate Char events.
    if let Some(Overlay::Setup { ref mut wizard }) = app.overlay {
        let cleaned = text.replace(['\n', '\r'], "");
        for c in cleaned.chars() {
            wizard.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        return;
    }

    match app.input_mode {
        InputMode::Command => {
            let cleaned = text.replace(['\n', '\r'], " ");
            app.command_buffer
                .insert_str(app.command_cursor, &cleaned);
            app.command_cursor += cleaned.len();
            update_completions(app);
        }
        InputMode::Chat => {
            let cleaned = text.replace(['\n', '\r'], " ");
            app.input_buffer.insert_str(app.input_cursor, &cleaned);
            app.input_cursor += cleaned.len();
        }
        InputMode::Scroll => {
            // Switch to chat mode and paste
            app.input_mode = InputMode::Chat;
            let cleaned = text.replace(['\n', '\r'], " ");
            app.input_buffer.insert_str(app.input_cursor, &cleaned);
            app.input_cursor += cleaned.len();
        }
    }
}

/// Build the list of completions for the current command buffer prefix.
///
/// Combines static known commands with dynamically discovered skill commands.
pub fn local_completions(input: &str, extra_commands: &[String]) -> Vec<String> {
    let static_iter = COMMANDS
        .iter()
        .filter(|c| c.starts_with(input))
        .map(|c| c.to_string());
    let dynamic_iter = extra_commands
        .iter()
        .filter(|c| c.starts_with(input))
        .cloned();
    static_iter.chain(dynamic_iter).collect()
}

/// Apply a completion to the command buffer.
///
/// Replaces the entire buffer with the completion text.
pub fn apply_completion(_buffer: &str, completion: &str) -> String {
    completion.to_string()
}
