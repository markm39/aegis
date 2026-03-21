//! Overlay key-handling logic for the chat TUI.
//!
//! Each overlay variant (model picker, session picker, login, settings,
//! restore picker, setup wizard) dispatches keystrokes here. Extracted from
//! `mod.rs` to keep `ChatApp`'s impl block focused on application lifecycle.

use crossterm::event::{KeyCode, KeyEvent};

use super::{ChatApp, LoginKeyInput, Overlay};
use super::persistence;

/// Dispatch a key event to the active overlay.
///
/// Called from `ChatApp::handle_overlay_key` when `self.overlay.is_some()`.
/// Returns without effect if no overlay is active.
pub fn handle_overlay_key(app: &mut ChatApp, key: KeyEvent) {
    // Take ownership temporarily so we can match and mutate.
    let Some(overlay) = app.overlay.take() else {
        return;
    };

    match overlay {
        Overlay::ModelPicker {
            items,
            mut filter,
            mut selected,
        } => match key.code {
            KeyCode::Esc => {
                // Close without changing model.
            }
            KeyCode::Enter => {
                let filtered = super::filter_model_items(&items, &filter);
                if let Some((model_id, _label)) = filtered.get(selected) {
                    let old = app.model.clone();
                    app.model = model_id.clone();
                    app.set_result(format!("Model: {old} -> {model_id}"));
                }
            }
            KeyCode::Up => {
                selected = selected.saturating_sub(1);
                app.overlay = Some(Overlay::ModelPicker {
                    items,
                    filter,
                    selected,
                });
            }
            KeyCode::Down => {
                let filtered_len = super::filter_model_items(&items, &filter).len();
                if selected + 1 < filtered_len {
                    selected += 1;
                }
                app.overlay = Some(Overlay::ModelPicker {
                    items,
                    filter,
                    selected,
                });
            }
            KeyCode::Backspace => {
                filter.pop();
                selected = 0;
                app.overlay = Some(Overlay::ModelPicker {
                    items,
                    filter,
                    selected,
                });
            }
            KeyCode::Char(c) => {
                filter.push(c);
                selected = 0;
                app.overlay = Some(Overlay::ModelPicker {
                    items,
                    filter,
                    selected,
                });
            }
            _ => {
                app.overlay = Some(Overlay::ModelPicker {
                    items,
                    filter,
                    selected,
                });
            }
        },
        Overlay::SessionPicker {
            items,
            mut selected,
        } => match key.code {
            KeyCode::Esc => {
                // Close without resuming.
            }
            KeyCode::Enter => {
                if let Some(meta) = items.get(selected) {
                    match persistence::load_conversation(&meta.id) {
                        Ok((messages, meta)) => {
                            app.conversation = messages;
                            app.model = meta.model.clone();
                            app.session_id = meta.id.clone();
                            app.audit_session_id = None;
                            app.register_audit_session();
                            app.rebuild_display_messages();
                            app.set_result(format!(
                                "Resumed {} ({}, {} messages)",
                                meta.id, meta.model, meta.message_count
                            ));
                        }
                        Err(e) => {
                            app.set_result(format!("Failed to resume: {e}"));
                        }
                    }
                }
            }
            KeyCode::Up => {
                selected = selected.saturating_sub(1);
                app.overlay = Some(Overlay::SessionPicker { items, selected });
            }
            KeyCode::Down => {
                if selected + 1 < items.len() {
                    selected += 1;
                }
                app.overlay = Some(Overlay::SessionPicker { items, selected });
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                // Delete the selected session file.
                if let Some(meta) = items.get(selected) {
                    let path =
                        persistence::conversations_dir().join(format!("{}.jsonl", meta.id));
                    let _ = std::fs::remove_file(&path);
                    // Rebuild the list.
                    let new_items: Vec<_> = items
                        .into_iter()
                        .enumerate()
                        .filter(|(i, _)| *i != selected)
                        .map(|(_, m)| m)
                        .collect();
                    let new_selected = selected.min(new_items.len().saturating_sub(1));
                    if new_items.is_empty() {
                        app.set_result("No saved sessions.");
                    } else {
                        app.overlay = Some(Overlay::SessionPicker {
                            items: new_items,
                            selected: new_selected,
                        });
                    }
                }
            }
            _ => {
                app.overlay = Some(Overlay::SessionPicker { items, selected });
            }
        },
        Overlay::Login {
            providers,
            selected,
            key_input,
        } => {
            if let Some(mut input) = key_input {
                // Key input sub-view
                match key.code {
                    KeyCode::Esc => {
                        // Cancel key input, go back to provider list.
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: None,
                        });
                    }
                    KeyCode::Enter => {
                        let trimmed_key = input.buffer.trim().to_string();
                        if trimmed_key.is_empty() {
                            input.error = Some("Key cannot be empty".to_string());
                            app.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        } else {
                            let mut store =
                                aegis_types::credentials::CredentialStore::load_default()
                                    .unwrap_or_default();
                            store.set(input.provider_id, trimmed_key, None, None);
                            if let Err(e) = store.save_default() {
                                input.error = Some(format!("Save failed: {e}"));
                                app.overlay = Some(Overlay::Login {
                                    providers,
                                    selected,
                                    key_input: Some(input),
                                });
                            } else {
                                let name = input.display_name.to_string();
                                app.open_login(None);
                                app.set_result(format!("Saved credential for {name}"));
                            }
                        }
                    }
                    KeyCode::Char('m')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        input.masked = !input.masked;
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::Char(c) => {
                        input.buffer.insert(input.cursor, c);
                        input.cursor += c.len_utf8();
                        input.error = None;
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::Backspace => {
                        if input.cursor > 0 {
                            let prev = input.buffer[..input.cursor]
                                .char_indices()
                                .next_back()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                            input.buffer.drain(prev..input.cursor);
                            input.cursor = prev;
                        }
                        input.error = None;
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::Left => {
                        if input.cursor > 0 {
                            input.cursor = input.buffer[..input.cursor]
                                .char_indices()
                                .next_back()
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                        }
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::Right => {
                        if input.cursor < input.buffer.len() {
                            input.cursor = input.buffer[input.cursor..]
                                .char_indices()
                                .nth(1)
                                .map(|(i, _)| input.cursor + i)
                                .unwrap_or(input.buffer.len());
                        }
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::Home => {
                        input.cursor = 0;
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    KeyCode::End => {
                        input.cursor = input.buffer.len();
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                    _ => {
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: Some(input),
                        });
                    }
                }
            } else {
                // Provider list mode
                let mut selected = selected;
                match key.code {
                    KeyCode::Esc => {
                        // Close login overlay.
                    }
                    KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: None,
                        });
                    }
                    KeyCode::Down => {
                        if selected + 1 < providers.len() {
                            selected += 1;
                        }
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: None,
                        });
                    }
                    KeyCode::Enter => {
                        if let Some(p) = providers.get(selected) {
                            let id = p.id;
                            let display_name = p.display_name;
                            app.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(LoginKeyInput {
                                    provider_id: id,
                                    display_name,
                                    buffer: String::new(),
                                    cursor: 0,
                                    masked: true,
                                    error: None,
                                }),
                            });
                        }
                    }
                    KeyCode::Char('d') => {
                        // Delete credential.
                        if let Some(p) = providers.get(selected) {
                            let mut store =
                                aegis_types::credentials::CredentialStore::load_default()
                                    .unwrap_or_default();
                            store.remove(p.id);
                            let _ = store.save_default();
                            let name = p.display_name.to_string();
                            app.open_login(None);
                            app.set_result(format!("Removed credential for {name}"));
                        }
                    }
                    _ => {
                        app.overlay = Some(Overlay::Login {
                            providers,
                            selected,
                            key_input: None,
                        });
                    }
                }
            }
        }
        Overlay::Settings { mut selected } => match key.code {
            KeyCode::Esc => {
                // Close settings.
            }
            KeyCode::Up => {
                selected = selected.saturating_sub(1);
                app.overlay = Some(Overlay::Settings { selected });
            }
            KeyCode::Down => {
                // 5 settings rows (0..4).
                if selected < 4 {
                    selected += 1;
                }
                app.overlay = Some(Overlay::Settings { selected });
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
                app.cycle_setting(selected, false);
                app.overlay = Some(Overlay::Settings { selected });
            }
            KeyCode::Left => {
                app.cycle_setting(selected, true);
                app.overlay = Some(Overlay::Settings { selected });
            }
            _ => {
                app.overlay = Some(Overlay::Settings { selected });
            }
        },
        Overlay::RestorePicker {
            snapshots,
            mut selected,
        } => match key.code {
            KeyCode::Esc => {
                // Close without restoring.
            }
            KeyCode::Up => {
                selected = selected.saturating_sub(1);
                app.overlay = Some(Overlay::RestorePicker { snapshots, selected });
            }
            KeyCode::Down => {
                if selected + 1 < snapshots.len() {
                    selected += 1;
                }
                app.overlay = Some(Overlay::RestorePicker { snapshots, selected });
            }
            KeyCode::Enter => {
                // selected = 0 is newest (displayed at top); original vec is oldest-first.
                let original_idx = snapshots.len().saturating_sub(1).saturating_sub(selected);
                if let Some(snap) = snapshots.get(original_idx) {
                    app.messages = snap.messages.clone();
                    app.conversation = snap.conversation.clone();
                    app.scroll_offset = 0;
                    app.set_result("Conversation restored.".to_string());
                }
            }
            _ => {
                app.overlay = Some(Overlay::RestorePicker { snapshots, selected });
            }
        },
        Overlay::Setup { mut wizard } => {
            let consumed = wizard.handle_key(key);
            if wizard.is_done() {
                let result = wizard.take_result();
                app.handle_setup_result(result);
            } else if consumed {
                app.overlay = Some(Overlay::Setup { wizard });
            }
            // If !consumed (Esc pressed), overlay is dropped (closed).
        }
    }
}
