//! Generic multi-field setup wizard.
//!
//! A data-driven wizard that collects multiple text fields from the user,
//! shows a confirmation summary, and produces a `ChannelConfig` via a
//! caller-provided builder function. Used by `channels.rs` to implement
//! setup wizards for all non-Telegram channel types.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use aegis_types::config::ChannelConfig;

use super::{SetupInputField, SetupResult, SetupStep, SetupWizard};

/// Builder function that converts field values into a `ChannelConfig`.
type ChannelBuilder = Box<dyn Fn(&[String]) -> ChannelConfig>;

/// Descriptor for a single input field in the wizard.
pub struct FieldDescriptor {
    /// Internal key used in confirmation display.
    pub key: &'static str,
    /// Label shown above the input (e.g., "Bot Token (xoxb-...):").
    pub label: &'static str,
    /// Whether to mask the input (show bullets).
    pub masked: bool,
    /// Whether this field can be left empty.
    pub optional: bool,
}

/// Shorthand constructor for a required field descriptor.
pub fn field(key: &'static str, label: &'static str, masked: bool) -> FieldDescriptor {
    FieldDescriptor {
        key,
        label,
        masked,
        optional: false,
    }
}

/// Shorthand constructor for an optional field descriptor.
pub fn optional_field(key: &'static str, label: &'static str, masked: bool) -> FieldDescriptor {
    FieldDescriptor {
        key,
        label,
        masked,
        optional: true,
    }
}

/// Phases of the generic setup flow.
enum Phase {
    /// User is entering values for each field.
    EnterFields,
    /// All fields filled; showing confirmation summary.
    Confirm,
    /// Done (completed or cancelled).
    Done(Option<Box<SetupResult>>),
}

/// A generic multi-field channel setup wizard.
///
/// Handles keyboard input (Tab/Shift-Tab between fields, text editing,
/// Enter to advance/confirm, Esc to go back/cancel) and produces a
/// `ChannelConfig` via the builder function on confirmation.
pub struct GenericChannelWizard {
    title: String,
    instructions: Vec<String>,
    fields: Vec<FieldDescriptor>,
    buffers: Vec<String>,
    cursors: Vec<usize>,
    active_field: usize,
    builder: ChannelBuilder,
    phase: Phase,
}

impl GenericChannelWizard {
    pub fn new(
        title: &str,
        instructions: &[&str],
        fields: Vec<FieldDescriptor>,
        builder: impl Fn(&[String]) -> ChannelConfig + 'static,
    ) -> Self {
        let n = fields.len();
        Self {
            title: title.to_string(),
            instructions: instructions.iter().map(|s| s.to_string()).collect(),
            fields,
            buffers: vec![String::new(); n],
            cursors: vec![0; n],
            active_field: 0,
            builder: Box::new(builder),
            phase: Phase::EnterFields,
        }
    }

    /// Handle text editing keys for the active field.
    fn handle_text_input(&mut self, key: KeyEvent) {
        let buf = &mut self.buffers[self.active_field];
        let cursor = &mut self.cursors[self.active_field];

        match key.code {
            KeyCode::Char(c) => {
                buf.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    let mut new_cursor = *cursor - 1;
                    while new_cursor > 0 && !buf.is_char_boundary(new_cursor) {
                        new_cursor -= 1;
                    }
                    buf.drain(new_cursor..*cursor);
                    *cursor = new_cursor;
                }
            }
            KeyCode::Delete => {
                if *cursor < buf.len() {
                    let mut end = *cursor + 1;
                    while end < buf.len() && !buf.is_char_boundary(end) {
                        end += 1;
                    }
                    buf.drain(*cursor..end);
                }
            }
            KeyCode::Left => {
                if *cursor > 0 {
                    *cursor -= 1;
                    while *cursor > 0 && !buf.is_char_boundary(*cursor) {
                        *cursor -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if *cursor < buf.len() {
                    *cursor += 1;
                    while *cursor < buf.len() && !buf.is_char_boundary(*cursor) {
                        *cursor += 1;
                    }
                }
            }
            KeyCode::Home => *cursor = 0,
            KeyCode::End => *cursor = buf.len(),
            _ => {}
        }
    }

    /// Check if all required fields have non-empty values.
    fn all_fields_filled(&self) -> bool {
        self.fields
            .iter()
            .zip(self.buffers.iter())
            .all(|(fd, b)| fd.optional || !b.trim().is_empty())
    }

    /// Build confirmation summary lines.
    fn confirm_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (i, fd) in self.fields.iter().enumerate() {
            let val = &self.buffers[i];
            let display = if val.is_empty() {
                "(not set)".to_string()
            } else if fd.masked {
                mask_value(val)
            } else {
                val.clone()
            };
            lines.push(format!("  {}: {display}", fd.key));
        }
        lines
    }
}

/// Mask a value for display: show last 4 chars, bullets for the rest.
fn mask_value(val: &str) -> String {
    let chars: Vec<char> = val.chars().collect();
    if chars.len() > 4 {
        let hidden = "\u{2022}".repeat(chars.len() - 4);
        let visible: String = chars[chars.len() - 4..].iter().collect();
        format!("{hidden}{visible}")
    } else {
        "\u{2022}".repeat(chars.len())
    }
}

impl SetupWizard for GenericChannelWizard {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Ctrl+C always cancels.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
            return true;
        }

        match &self.phase {
            Phase::EnterFields => match key.code {
                KeyCode::Enter => {
                    // Trim all buffers.
                    for (i, buf) in self.buffers.iter_mut().enumerate() {
                        let trimmed = buf.trim().to_string();
                        self.cursors[i] = trimmed.len();
                        *buf = trimmed;
                    }

                    if self.all_fields_filled() {
                        self.phase = Phase::Confirm;
                    }
                    // If not all filled, stay on current step (user sees empty fields).
                    true
                }
                KeyCode::Tab | KeyCode::Down => {
                    if self.active_field + 1 < self.fields.len() {
                        self.active_field += 1;
                    }
                    true
                }
                KeyCode::BackTab | KeyCode::Up => {
                    if self.active_field > 0 {
                        self.active_field -= 1;
                    }
                    true
                }
                KeyCode::Esc => {
                    self.phase = Phase::Done(Some(Box::new(SetupResult::Cancelled)));
                    false
                }
                _ => {
                    self.handle_text_input(key);
                    true
                }
            },
            Phase::Confirm => match key.code {
                KeyCode::Enter => {
                    let config = (self.builder)(&self.buffers);
                    self.phase =
                        Phase::Done(Some(Box::new(SetupResult::Channel(Box::new(config)))));
                    true
                }
                KeyCode::Esc => {
                    // Go back to editing.
                    self.phase = Phase::EnterFields;
                    true
                }
                _ => true,
            },
            Phase::Done(_) => false,
        }
    }

    fn tick(&mut self) {
        // No async operations for generic wizards.
    }

    fn current_step(&self) -> SetupStep {
        match &self.phase {
            Phase::EnterFields => {
                let inputs: Vec<SetupInputField> = self
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(i, fd)| SetupInputField {
                        label: fd.label.to_string(),
                        value: self.buffers[i].clone(),
                        cursor: self.cursors[i],
                        masked: fd.masked,
                    })
                    .collect();

                SetupStep {
                    title: self.title.clone(),
                    instructions: self.instructions.clone(),
                    inputs,
                    active_input: self.active_field,
                    status: None,
                    error: None,
                    is_waiting: false,
                    help: "Tab/Shift-Tab: switch fields | Enter: confirm | Esc: cancel"
                        .to_string(),
                }
            }
            Phase::Confirm => {
                let mut instructions = vec!["Configuration summary:".to_string(), String::new()];
                instructions.extend(self.confirm_lines());
                instructions.push(String::new());
                instructions.push("Press Enter to save this configuration.".to_string());

                SetupStep {
                    title: format!("{} -- Confirm", self.title),
                    instructions,
                    inputs: vec![],
                    active_input: 0,
                    status: Some("Ready to save".to_string()),
                    error: None,
                    is_waiting: false,
                    help: "Enter: confirm | Esc: go back and edit".to_string(),
                }
            }
            Phase::Done(_) => SetupStep {
                title: self.title.clone(),
                instructions: vec![],
                inputs: vec![],
                active_input: 0,
                status: Some("Done".to_string()),
                error: None,
                is_waiting: false,
                help: String::new(),
            },
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done(_))
    }

    fn take_result(&mut self) -> SetupResult {
        if let Phase::Done(ref mut result) = self.phase {
            result
                .take()
                .map(|b| *b)
                .unwrap_or(SetupResult::Cancelled)
        } else {
            SetupResult::Cancelled
        }
    }
}
