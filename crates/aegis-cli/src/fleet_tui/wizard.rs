//! Add-agent wizard: step-by-step inline wizard for adding new agents
//! to the fleet from within the fleet TUI.
//!
//! Steps:
//! 1. Tool selection (Claude Code, Codex, OpenClaw, Custom)
//! 2. Agent name (text input, auto-derived from working dir)
//! 3. Working directory (text input, defaults to CWD)
//! 4. Task / initial prompt (text input, optional)
//! 5. Role (text input, optional, e.g. "UX specialist")
//! 6. Agent goal (text input, optional, what the agent should achieve)
//! 7. Restart policy (select: Never, OnFailure, Always)
//! 8. Confirm summary

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig, RestartPolicy};

/// Wizard steps in order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WizardStep {
    Tool,
    CustomCommand,
    Name,
    WorkingDir,
    Task,
    Role,
    AgentGoal,
    RestartPolicy,
    Confirm,
}

impl WizardStep {
    /// All steps in order (including CustomCommand, which is conditionally shown).
    pub const ALL: &'static [WizardStep] = &[
        WizardStep::Tool,
        WizardStep::CustomCommand,
        WizardStep::Name,
        WizardStep::WorkingDir,
        WizardStep::Task,
        WizardStep::Role,
        WizardStep::AgentGoal,
        WizardStep::RestartPolicy,
        WizardStep::Confirm,
    ];

    /// Step number (1-based), adjusted to skip CustomCommand for non-Custom tools.
    pub fn number(&self, is_custom: bool) -> usize {
        Self::ALL
            .iter()
            .filter(|s| is_custom || **s != WizardStep::CustomCommand)
            .position(|s| s == self)
            .unwrap_or(0)
            + 1
    }

    /// Total steps, adjusted to skip CustomCommand for non-Custom tools.
    pub fn total(is_custom: bool) -> usize {
        if is_custom {
            Self::ALL.len()
        } else {
            Self::ALL.len() - 1
        }
    }
}

/// Tool choices for the first step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToolChoice {
    ClaudeCode,
    Codex,
    OpenClaw,
    Cursor,
    Custom,
}

impl ToolChoice {
    pub const ALL: &'static [ToolChoice] = &[
        ToolChoice::ClaudeCode,
        ToolChoice::Codex,
        ToolChoice::OpenClaw,
        ToolChoice::Cursor,
        ToolChoice::Custom,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ToolChoice::ClaudeCode => "Claude Code",
            ToolChoice::Codex => "Codex",
            ToolChoice::OpenClaw => "OpenClaw",
            ToolChoice::Cursor => "Cursor",
            ToolChoice::Custom => "Custom command",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ToolChoice::ClaudeCode => "Anthropic Claude Code CLI agent",
            ToolChoice::Codex => "OpenAI Codex CLI agent",
            ToolChoice::OpenClaw => "OpenClaw autonomous agent",
            ToolChoice::Cursor => "Cursor editor (observe-only monitoring)",
            ToolChoice::Custom => "Run a custom command with Aegis supervision",
        }
    }
}

/// Restart policy choices.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RestartChoice {
    OnFailure,
    Always,
    Never,
}

impl RestartChoice {
    pub const ALL: &'static [RestartChoice] = &[
        RestartChoice::OnFailure,
        RestartChoice::Always,
        RestartChoice::Never,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            RestartChoice::OnFailure => "On Failure (recommended)",
            RestartChoice::Always => "Always",
            RestartChoice::Never => "Never",
        }
    }

    pub fn to_policy(self) -> RestartPolicy {
        match self {
            RestartChoice::OnFailure => RestartPolicy::OnFailure,
            RestartChoice::Always => RestartPolicy::Always,
            RestartChoice::Never => RestartPolicy::Never,
        }
    }
}

/// The wizard state machine.
pub struct AddAgentWizard {
    /// Current step.
    pub step: WizardStep,
    /// Whether the wizard is still active (false = cancelled or completed).
    pub active: bool,
    /// Whether the wizard completed successfully.
    pub completed: bool,

    // Step 1: Tool
    pub tool_selected: usize,

    // Step 2: Name
    pub name: String,
    pub name_cursor: usize,

    // Step 3: Working dir
    pub working_dir: String,
    pub working_dir_cursor: usize,

    // Step 4: Task
    pub task: String,
    pub task_cursor: usize,

    // Step 5: Role
    pub role: String,
    pub role_cursor: usize,

    // Step 6: Agent goal
    pub agent_goal: String,
    pub agent_goal_cursor: usize,

    // Step 7: Restart policy
    pub restart_selected: usize,

    // Custom command (only if tool == Custom)
    pub custom_command: String,
    pub custom_command_cursor: usize,
}

impl AddAgentWizard {
    /// Create a new wizard with sensible defaults.
    pub fn new() -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".into());

        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "agent-1".into());

        Self {
            step: WizardStep::Tool,
            active: true,
            completed: false,
            tool_selected: 0,
            name: default_name,
            name_cursor: 0,
            working_dir: cwd,
            working_dir_cursor: 0,
            task: String::new(),
            task_cursor: 0,
            role: String::new(),
            role_cursor: 0,
            agent_goal: String::new(),
            agent_goal_cursor: 0,
            restart_selected: 0,
            custom_command: String::new(),
            custom_command_cursor: 0,
        }
    }

    /// Handle a key event. Returns true if the wizard consumed the key.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        // Esc goes back one step, or cancels at the first step
        if key.code == KeyCode::Esc {
            match self.step {
                WizardStep::Tool => {
                    self.active = false; // First step: cancel wizard
                }
                WizardStep::CustomCommand => self.step = WizardStep::Tool,
                WizardStep::Name => {
                    if self.is_custom_tool() {
                        self.custom_command_cursor = self.custom_command.len();
                        self.step = WizardStep::CustomCommand;
                    } else {
                        self.step = WizardStep::Tool;
                    }
                }
                WizardStep::WorkingDir => {
                    self.name_cursor = self.name.len();
                    self.step = WizardStep::Name;
                }
                WizardStep::Task => {
                    self.working_dir_cursor = self.working_dir.len();
                    self.step = WizardStep::WorkingDir;
                }
                WizardStep::Role => {
                    self.task_cursor = self.task.len();
                    self.step = WizardStep::Task;
                }
                WizardStep::AgentGoal => {
                    self.role_cursor = self.role.len();
                    self.step = WizardStep::Role;
                }
                WizardStep::RestartPolicy => {
                    self.agent_goal_cursor = self.agent_goal.len();
                    self.step = WizardStep::AgentGoal;
                }
                WizardStep::Confirm => self.step = WizardStep::RestartPolicy,
            }
            return true;
        }

        match self.step {
            WizardStep::Tool => self.handle_tool_key(key),
            WizardStep::CustomCommand => self.handle_text_key(key, TextTarget::CustomCommand),
            WizardStep::Name => self.handle_text_key(key, TextTarget::Name),
            WizardStep::WorkingDir => self.handle_text_key(key, TextTarget::WorkingDir),
            WizardStep::Task => self.handle_text_key(key, TextTarget::Task),
            WizardStep::Role => self.handle_text_key(key, TextTarget::Role),
            WizardStep::AgentGoal => self.handle_text_key(key, TextTarget::AgentGoal),
            WizardStep::RestartPolicy => self.handle_restart_key(key),
            WizardStep::Confirm => self.handle_confirm_key(key),
        }
    }

    /// Handle tool selection keys.
    fn handle_tool_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.tool_selected = (self.tool_selected + 1).min(ToolChoice::ALL.len() - 1);
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.tool_selected = self.tool_selected.saturating_sub(1);
                true
            }
            KeyCode::Enter => {
                if self.is_custom_tool() {
                    self.step = WizardStep::CustomCommand;
                    self.custom_command_cursor = self.custom_command.len();
                } else {
                    self.step = WizardStep::Name;
                    self.name_cursor = self.name.len();
                }
                true
            }
            _ => true,
        }
    }

    /// Handle restart policy selection keys.
    fn handle_restart_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.restart_selected =
                    (self.restart_selected + 1).min(RestartChoice::ALL.len() - 1);
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.restart_selected = self.restart_selected.saturating_sub(1);
                true
            }
            KeyCode::Enter => {
                self.step = WizardStep::Confirm;
                true
            }
            _ => true,
        }
    }

    /// Handle confirm step keys.
    fn handle_confirm_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                if self.is_valid() {
                    self.completed = true;
                    self.active = false;
                }
                true
            }
            KeyCode::Char('n') => {
                self.active = false;
                true
            }
            _ => true,
        }
    }

    /// Handle text input with cursor support.
    fn handle_text_key(&mut self, key: KeyEvent, target: TextTarget) -> bool {
        let (text, cursor) = match target {
            TextTarget::CustomCommand => (&mut self.custom_command, &mut self.custom_command_cursor),
            TextTarget::Name => (&mut self.name, &mut self.name_cursor),
            TextTarget::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            TextTarget::Task => (&mut self.task, &mut self.task_cursor),
            TextTarget::Role => (&mut self.role, &mut self.role_cursor),
            TextTarget::AgentGoal => (&mut self.agent_goal, &mut self.agent_goal_cursor),
        };

        match key.code {
            KeyCode::Enter => {
                // Advance to next step
                self.step = match self.step {
                    WizardStep::CustomCommand => {
                        if self.custom_command.trim().is_empty() {
                            return true; // Don't advance with empty command
                        }
                        self.name_cursor = self.name.len();
                        WizardStep::Name
                    }
                    WizardStep::Name => {
                        if self.name.trim().is_empty() {
                            return true; // Don't advance with empty name
                        }
                        WizardStep::WorkingDir
                    }
                    WizardStep::WorkingDir => {
                        self.working_dir_cursor = self.working_dir.len();
                        WizardStep::Task
                    }
                    WizardStep::Task => {
                        self.task_cursor = self.task.len();
                        WizardStep::Role
                    }
                    WizardStep::Role => {
                        self.role_cursor = self.role.len();
                        WizardStep::AgentGoal
                    }
                    WizardStep::AgentGoal => {
                        self.agent_goal_cursor = self.agent_goal.len();
                        WizardStep::RestartPolicy
                    }
                    _ => return true,
                };
                return true;
            }
            KeyCode::Tab => {
                // Same as Enter for text fields
                return self.handle_text_key(
                    KeyEvent::new(KeyCode::Enter, key.modifiers),
                    target,
                );
            }
            KeyCode::Char(c) => {
                text.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    let prev = text[..*cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    text.remove(prev);
                    *cursor = prev;
                }
            }
            KeyCode::Left => {
                if *cursor > 0 {
                    *cursor = text[..*cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if *cursor < text.len() {
                    *cursor = text[*cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| *cursor + i)
                        .unwrap_or(text.len());
                }
            }
            KeyCode::Delete => {
                if *cursor < text.len() {
                    text.remove(*cursor);
                }
            }
            KeyCode::Home => {
                *cursor = 0;
            }
            KeyCode::End => {
                *cursor = text.len();
            }
            _ => {}
        }

        true
    }

    /// Handle pasted text (from `Event::Paste` when bracketed paste is enabled).
    ///
    /// Inserts pasted text at the cursor of whichever text field is active.
    /// Single-line fields (name, dir) collapse newlines to spaces.
    /// Multi-line fields (task, role, goal) preserve newlines.
    pub fn handle_paste(&mut self, text: &str) -> bool {
        let (buf, cursor, multiline) = match self.step {
            WizardStep::CustomCommand => {
                (&mut self.custom_command, &mut self.custom_command_cursor, false)
            }
            WizardStep::Name => (&mut self.name, &mut self.name_cursor, false),
            WizardStep::WorkingDir => {
                (&mut self.working_dir, &mut self.working_dir_cursor, false)
            }
            WizardStep::Task => (&mut self.task, &mut self.task_cursor, true),
            WizardStep::Role => (&mut self.role, &mut self.role_cursor, true),
            WizardStep::AgentGoal => (&mut self.agent_goal, &mut self.agent_goal_cursor, true),
            _ => return false,
        };

        let cleaned = if multiline {
            text.replace('\r', "")
        } else {
            text.replace(['\n', '\r'], " ")
        };

        buf.insert_str(*cursor, &cleaned);
        *cursor += cleaned.len();
        true
    }

    /// Whether the selected tool is Custom (which needs the extra command step).
    pub fn is_custom_tool(&self) -> bool {
        self.tool_choice() == ToolChoice::Custom
    }

    /// Check if the wizard has enough data to produce a valid config.
    pub fn is_valid(&self) -> bool {
        let base = !self.name.trim().is_empty() && !self.working_dir.trim().is_empty();
        if self.is_custom_tool() {
            base && !self.custom_command.trim().is_empty()
        } else {
            base
        }
    }

    /// Get the selected tool choice.
    pub fn tool_choice(&self) -> ToolChoice {
        ToolChoice::ALL[self.tool_selected]
    }

    /// Get the selected restart choice.
    pub fn restart_choice(&self) -> RestartChoice {
        RestartChoice::ALL[self.restart_selected]
    }

    /// Build the AgentSlotConfig from wizard state.
    pub fn build_config(&self) -> AgentSlotConfig {
        let tool = match self.tool_choice() {
            ToolChoice::ClaudeCode => AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            ToolChoice::Codex => AgentToolConfig::Codex {
                approval_mode: "suggest".into(),
                one_shot: false,
                extra_args: vec![],
            },
            ToolChoice::OpenClaw => AgentToolConfig::OpenClaw {
                agent_name: None,
                extra_args: vec![],
            },
            ToolChoice::Cursor => AgentToolConfig::Cursor {
                assume_running: false,
            },
            ToolChoice::Custom => {
                // Split "command --flag1 --flag2" into command + args
                let parts: Vec<&str> = self.custom_command.split_whitespace().collect();
                let command = parts.first().map(|s| s.to_string()).unwrap_or_default();
                let args: Vec<String> = parts.iter().skip(1).map(|s| s.to_string()).collect();
                AgentToolConfig::Custom {
                    command,
                    args,
                    adapter: aegis_types::AdapterConfig::Auto,
                    env: vec![],
                }
            }
        };

        let task = if self.task.trim().is_empty() {
            None
        } else {
            Some(self.task.clone())
        };

        let role = if self.role.trim().is_empty() {
            None
        } else {
            Some(self.role.clone())
        };

        let agent_goal = if self.agent_goal.trim().is_empty() {
            None
        } else {
            Some(self.agent_goal.clone())
        };

        let mut config = crate::commands::build_agent_slot(
            self.name.trim().to_string(),
            tool,
            PathBuf::from(self.working_dir.trim()),
            task,
            self.restart_choice().to_policy(),
            5,
        );
        config.role = role;
        config.agent_goal = agent_goal;
        config
    }
}

/// Which text field the cursor belongs to.
enum TextTarget {
    CustomCommand,
    Name,
    WorkingDir,
    Task,
    Role,
    AgentGoal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventKind, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    #[test]
    fn wizard_initial_state() {
        let wiz = AddAgentWizard::new();
        assert_eq!(wiz.step, WizardStep::Tool);
        assert!(wiz.active);
        assert!(!wiz.completed);
        assert_eq!(wiz.tool_selected, 0);
    }

    #[test]
    fn wizard_step_numbers_non_custom() {
        // Non-custom: CustomCommand step is hidden
        assert_eq!(WizardStep::Tool.number(false), 1);
        assert_eq!(WizardStep::Name.number(false), 2);
        assert_eq!(WizardStep::Role.number(false), 5);
        assert_eq!(WizardStep::AgentGoal.number(false), 6);
        assert_eq!(WizardStep::Confirm.number(false), 8);
        assert_eq!(WizardStep::total(false), 8);
    }

    #[test]
    fn wizard_step_numbers_custom() {
        // Custom: CustomCommand step is visible
        assert_eq!(WizardStep::Tool.number(true), 1);
        assert_eq!(WizardStep::CustomCommand.number(true), 2);
        assert_eq!(WizardStep::Name.number(true), 3);
        assert_eq!(WizardStep::Confirm.number(true), 9);
        assert_eq!(WizardStep::total(true), 9);
    }

    #[test]
    fn wizard_tool_navigation() {
        let mut wiz = AddAgentWizard::new();
        assert_eq!(wiz.tool_selected, 0);

        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.tool_selected, 1);

        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.tool_selected, 2);

        wiz.handle_key(press(KeyCode::Char('k')));
        assert_eq!(wiz.tool_selected, 1);

        // Can't go below 0
        wiz.handle_key(press(KeyCode::Char('k')));
        wiz.handle_key(press(KeyCode::Char('k')));
        assert_eq!(wiz.tool_selected, 0);
    }

    #[test]
    fn wizard_tool_enter_advances() {
        let mut wiz = AddAgentWizard::new();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name);
    }

    #[test]
    fn wizard_name_typing() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name.clear();
        wiz.name_cursor = 0;

        wiz.handle_key(press(KeyCode::Char('t')));
        wiz.handle_key(press(KeyCode::Char('e')));
        wiz.handle_key(press(KeyCode::Char('s')));
        wiz.handle_key(press(KeyCode::Char('t')));
        assert_eq!(wiz.name, "test");
        assert_eq!(wiz.name_cursor, 4);
    }

    #[test]
    fn wizard_name_cursor_movement() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "hello".into();
        wiz.name_cursor = 5;

        wiz.handle_key(press(KeyCode::Left));
        assert_eq!(wiz.name_cursor, 4);

        wiz.handle_key(press(KeyCode::Home));
        assert_eq!(wiz.name_cursor, 0);

        wiz.handle_key(press(KeyCode::End));
        assert_eq!(wiz.name_cursor, 5);
    }

    #[test]
    fn wizard_name_backspace() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "test".into();
        wiz.name_cursor = 4;

        wiz.handle_key(press(KeyCode::Backspace));
        assert_eq!(wiz.name, "tes");
        assert_eq!(wiz.name_cursor, 3);

        // Backspace at position 0 does nothing
        wiz.name_cursor = 0;
        wiz.handle_key(press(KeyCode::Backspace));
        assert_eq!(wiz.name, "tes");
    }

    #[test]
    fn wizard_empty_name_does_not_advance() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name.clear();
        wiz.name_cursor = 0;

        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name, "empty name should not advance");
    }

    #[test]
    fn wizard_name_enter_advances() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "my-agent".into();

        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::WorkingDir);
    }

    #[test]
    fn wizard_step_progression() {
        let mut wiz = AddAgentWizard::new();

        // Step 1: Tool (Claude Code -- skips CustomCommand)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name);

        // Step 2: Name
        wiz.name = "test-agent".into();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::WorkingDir);

        // Step 3: Working dir
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Task);

        // Step 4: Task (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Role);

        // Step 5: Role (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::AgentGoal);

        // Step 6: Agent goal (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::RestartPolicy);

        // Step 7: Restart policy
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Confirm);

        // Step 8: Confirm
        wiz.handle_key(press(KeyCode::Enter));
        assert!(!wiz.active);
        assert!(wiz.completed);
    }

    #[test]
    fn wizard_custom_tool_step_progression() {
        let mut wiz = AddAgentWizard::new();

        // Select Custom (index 4)
        wiz.tool_selected = 4;
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::CustomCommand, "Custom should go to CustomCommand step");

        // Empty command should not advance
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::CustomCommand, "empty command should not advance");

        // Type a command and advance
        wiz.custom_command = "my-tool --verbose".into();
        wiz.custom_command_cursor = wiz.custom_command.len();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name);
    }

    #[test]
    fn wizard_esc_at_tool_cancels() {
        let mut wiz = AddAgentWizard::new();
        assert_eq!(wiz.step, WizardStep::Tool);

        wiz.handle_key(press(KeyCode::Esc));
        assert!(!wiz.active);
        assert!(!wiz.completed);
    }

    #[test]
    fn wizard_esc_goes_back_one_step() {
        let mut wiz = AddAgentWizard::new();

        // Name -> Tool (non-custom)
        wiz.step = WizardStep::Name;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Tool);
        assert!(wiz.active);

        // Name -> CustomCommand (when Custom tool is selected)
        wiz.tool_selected = 4; // Custom
        wiz.step = WizardStep::Name;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::CustomCommand);
        assert!(wiz.active);

        // CustomCommand -> Tool
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Tool);
        assert!(wiz.active);

        // WorkingDir -> Name
        wiz.step = WizardStep::WorkingDir;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Name);
        assert!(wiz.active);

        // Task -> WorkingDir
        wiz.step = WizardStep::Task;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::WorkingDir);
        assert!(wiz.active);

        // Role -> Task
        wiz.step = WizardStep::Role;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Task);
        assert!(wiz.active);

        // AgentGoal -> Role
        wiz.step = WizardStep::AgentGoal;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Role);
        assert!(wiz.active);

        // RestartPolicy -> AgentGoal
        wiz.step = WizardStep::RestartPolicy;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::AgentGoal);
        assert!(wiz.active);

        // Confirm -> RestartPolicy
        wiz.step = WizardStep::Confirm;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::RestartPolicy);
        assert!(wiz.active);
    }

    #[test]
    fn wizard_confirm_n_cancels() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Confirm;
        wiz.name = "test".into();

        wiz.handle_key(press(KeyCode::Char('n')));
        assert!(!wiz.active);
        assert!(!wiz.completed);
    }

    #[test]
    fn wizard_builds_valid_config() {
        let mut wiz = AddAgentWizard::new();
        wiz.tool_selected = 0; // ClaudeCode
        wiz.name = "my-agent".into();
        wiz.working_dir = "/home/user/project".into();
        wiz.task = "Build the feature".into();
        wiz.restart_selected = 0; // OnFailure

        let config = wiz.build_config();
        assert_eq!(config.name, "my-agent");
        assert!(matches!(config.tool, AgentToolConfig::ClaudeCode { .. }));
        assert_eq!(config.working_dir, PathBuf::from("/home/user/project"));
        assert_eq!(config.task, Some("Build the feature".into()));
        assert!(matches!(config.restart, RestartPolicy::OnFailure));
        assert!(config.enabled);
    }

    #[test]
    fn wizard_builds_codex_config() {
        let mut wiz = AddAgentWizard::new();
        wiz.tool_selected = 1; // Codex
        wiz.name = "codex-1".into();
        wiz.working_dir = "/tmp".into();

        let config = wiz.build_config();
        assert!(matches!(config.tool, AgentToolConfig::Codex { .. }));
    }

    #[test]
    fn wizard_custom_command_splits_args() {
        let mut wiz = AddAgentWizard::new();
        wiz.tool_selected = 4; // Custom
        wiz.custom_command = "my-agent --verbose --timeout 30".into();
        wiz.name = "custom-1".into();
        wiz.working_dir = "/tmp".into();

        let config = wiz.build_config();
        match &config.tool {
            AgentToolConfig::Custom { command, args, .. } => {
                assert_eq!(command, "my-agent");
                assert_eq!(args, &["--verbose", "--timeout", "30"]);
            }
            _ => panic!("expected Custom tool config"),
        }
    }

    #[test]
    fn wizard_empty_task_is_none() {
        let mut wiz = AddAgentWizard::new();
        wiz.name = "test".into();
        wiz.working_dir = "/tmp".into();
        wiz.task = "".into();

        let config = wiz.build_config();
        assert!(config.task.is_none());
    }

    #[test]
    fn wizard_restart_navigation() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::RestartPolicy;

        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.restart_selected, 1);

        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.restart_selected, 2);

        // Can't go past end
        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.restart_selected, 2);
    }

    #[test]
    fn wizard_tool_choice_labels() {
        for choice in ToolChoice::ALL {
            assert!(!choice.label().is_empty());
            assert!(!choice.description().is_empty());
        }
    }

    #[test]
    fn wizard_restart_choice_labels() {
        for choice in RestartChoice::ALL {
            assert!(!choice.label().is_empty());
        }
    }

    #[test]
    fn wizard_is_valid() {
        let mut wiz = AddAgentWizard::new();
        wiz.name = "test".into();
        wiz.working_dir = "/tmp".into();
        assert!(wiz.is_valid());

        wiz.name = "  ".into();
        assert!(!wiz.is_valid());

        wiz.name = "test".into();
        wiz.working_dir = "  ".into();
        assert!(!wiz.is_valid());
    }

    #[test]
    fn wizard_custom_is_valid_requires_command() {
        let mut wiz = AddAgentWizard::new();
        wiz.tool_selected = 4; // Custom
        wiz.name = "test".into();
        wiz.working_dir = "/tmp".into();
        wiz.custom_command = "".into();
        assert!(!wiz.is_valid(), "custom tool with empty command should be invalid");

        wiz.custom_command = "my-tool".into();
        assert!(wiz.is_valid(), "custom tool with command should be valid");
    }

    #[test]
    fn multibyte_text_input_cursor() {
        let mut wiz = AddAgentWizard::new();
        // Move to Name step (a text field) and clear default
        wiz.step = WizardStep::Name;
        wiz.name.clear();
        wiz.name_cursor = 0;

        // Type a multi-byte character (e-acute = 2 bytes)
        wiz.handle_key(press(KeyCode::Char('r')));
        wiz.handle_key(press(KeyCode::Char('\u{00e9}')));
        wiz.handle_key(press(KeyCode::Char('s')));
        assert_eq!(wiz.name, "r\u{00e9}s");
        assert_eq!(wiz.name_cursor, 4); // r(1) + e-acute(2) + s(1)

        // Left should skip past the 2-byte char properly
        wiz.handle_key(press(KeyCode::Left));
        assert_eq!(wiz.name_cursor, 3); // before 's'
        wiz.handle_key(press(KeyCode::Left));
        assert_eq!(wiz.name_cursor, 1); // before e-acute

        // Backspace should delete the multi-byte char
        wiz.handle_key(press(KeyCode::Right));
        assert_eq!(wiz.name_cursor, 3); // after e-acute
        wiz.handle_key(press(KeyCode::Backspace));
        assert_eq!(wiz.name, "rs");
        assert_eq!(wiz.name_cursor, 1);
    }
}
