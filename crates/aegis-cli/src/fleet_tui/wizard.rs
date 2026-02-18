//! Add-agent wizard: step-by-step inline wizard for adding new agents
//! to the fleet from within the fleet TUI.
//!
//! Steps:
//! 1. Tool selection (Claude Code, Codex, OpenClaw, Custom)
//! 2. Agent type (Worker vs Orchestrator)
//! 3. Agent name (text input, auto-derived from working dir)
//! 4. Working directory (text input, defaults to CWD)
//! 5. Task / initial prompt (text input, optional -- skipped for orchestrators)
//! 6. Role (text input, optional, e.g. "UX specialist")
//! 7. Agent goal (text input, optional, what the agent should achieve)
//! 8. Context (optional, constraints or instructions)
//! 9. Backlog path (orchestrators only, path to roadmap/backlog file)
//! 10. Review interval (orchestrators only, seconds between review cycles)
//! 11. Restart policy (select: Never, OnFailure, Always)
//! 12. Confirm summary

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig, OrchestratorConfig, RestartPolicy};

/// Wizard steps in order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WizardStep {
    Tool,
    CustomCommand,
    AgentType,
    Name,
    WorkingDir,
    Task,
    Role,
    AgentGoal,
    Context,
    BacklogPath,
    ReviewInterval,
    RestartPolicy,
    Confirm,
}

impl WizardStep {
    /// All steps in order (conditional steps included).
    pub const ALL: &'static [WizardStep] = &[
        WizardStep::Tool,
        WizardStep::CustomCommand,
        WizardStep::AgentType,
        WizardStep::Name,
        WizardStep::WorkingDir,
        WizardStep::Task,
        WizardStep::Role,
        WizardStep::AgentGoal,
        WizardStep::Context,
        WizardStep::BacklogPath,
        WizardStep::ReviewInterval,
        WizardStep::RestartPolicy,
        WizardStep::Confirm,
    ];

    /// Step number (1-based), adjusted to skip conditional steps.
    ///
    /// Conditional skips:
    /// - `CustomCommand` hidden unless tool is Custom
    /// - `Task` hidden for orchestrators (they don't get tasks)
    /// - `BacklogPath` and `ReviewInterval` hidden for workers
    pub fn number(&self, is_custom: bool, is_orchestrator: bool) -> usize {
        Self::ALL
            .iter()
            .filter(|s| Self::visible(s, is_custom, is_orchestrator))
            .position(|s| s == self)
            .unwrap_or(0)
            + 1
    }

    /// Total visible steps.
    pub fn total(is_custom: bool, is_orchestrator: bool) -> usize {
        Self::ALL
            .iter()
            .filter(|s| Self::visible(s, is_custom, is_orchestrator))
            .count()
    }

    fn visible(step: &WizardStep, is_custom: bool, is_orchestrator: bool) -> bool {
        match step {
            WizardStep::CustomCommand => is_custom,
            WizardStep::Task => !is_orchestrator,
            WizardStep::BacklogPath | WizardStep::ReviewInterval => is_orchestrator,
            _ => true,
        }
    }
}

/// Agent type choices.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AgentTypeChoice {
    Worker,
    Orchestrator,
}

impl AgentTypeChoice {
    pub const ALL: &'static [AgentTypeChoice] = &[
        AgentTypeChoice::Worker,
        AgentTypeChoice::Orchestrator,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            AgentTypeChoice::Worker => "Worker (recommended)",
            AgentTypeChoice::Orchestrator => "Orchestrator",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AgentTypeChoice::Worker => "Writes code, implements features, fixes bugs",
            AgentTypeChoice::Orchestrator => "Reviews worker output, assigns tasks, never writes code",
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

    // Step 2: Agent type (Worker vs Orchestrator)
    pub agent_type_selected: usize,

    // Step 3: Name
    pub name: String,
    pub name_cursor: usize,

    // Step 4: Working dir
    pub working_dir: String,
    pub working_dir_cursor: usize,

    // Step 5: Task (skipped for orchestrators)
    pub task: String,
    pub task_cursor: usize,

    // Step 6: Role
    pub role: String,
    pub role_cursor: usize,

    // Step 7: Agent goal
    pub agent_goal: String,
    pub agent_goal_cursor: usize,

    // Step 8: Context (constraints, knowledge, instructions)
    pub context: String,
    pub context_cursor: usize,

    // Step 9: Backlog path (orchestrators only)
    pub backlog_path: String,
    pub backlog_path_cursor: usize,

    // Step 10: Review interval (orchestrators only)
    pub review_interval: String,
    pub review_interval_cursor: usize,

    // Step 11: Restart policy
    pub restart_selected: usize,

    // Custom command (only if tool == Custom)
    pub custom_command: String,
    pub custom_command_cursor: usize,

    /// Validation error to display at current step (cleared on advance).
    pub validation_error: Option<String>,
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

        let name_len = default_name.len();
        let cwd_len = cwd.len();

        Self {
            step: WizardStep::Tool,
            active: true,
            completed: false,
            tool_selected: 0,
            agent_type_selected: 0,
            name: default_name,
            name_cursor: name_len,
            working_dir: cwd,
            working_dir_cursor: cwd_len,
            task: String::new(),
            task_cursor: 0,
            role: String::new(),
            role_cursor: 0,
            agent_goal: String::new(),
            agent_goal_cursor: 0,
            context: String::new(),
            context_cursor: 0,
            backlog_path: String::new(),
            backlog_path_cursor: 0,
            review_interval: "300".to_string(),
            review_interval_cursor: 3,
            restart_selected: 0,
            custom_command: String::new(),
            custom_command_cursor: 0,
            validation_error: None,
        }
    }

    /// Handle a key event. Returns true if the wizard consumed the key.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        // Esc or Shift+Tab goes back one step, or cancels at the first step
        if key.code == KeyCode::Esc || key.code == KeyCode::BackTab {
            match self.step {
                WizardStep::Tool => {
                    self.active = false; // First step: cancel wizard
                }
                WizardStep::CustomCommand => self.step = WizardStep::Tool,
                WizardStep::AgentType => {
                    if self.is_custom_tool() {
                        self.custom_command_cursor = self.custom_command.len();
                        self.step = WizardStep::CustomCommand;
                    } else {
                        self.step = WizardStep::Tool;
                    }
                }
                WizardStep::Name => {
                    self.step = WizardStep::AgentType;
                }
                WizardStep::WorkingDir => {
                    self.name_cursor = self.name.len();
                    self.step = WizardStep::Name;
                }
                WizardStep::Task => {
                    // Task is only shown for workers
                    self.working_dir_cursor = self.working_dir.len();
                    self.step = WizardStep::WorkingDir;
                }
                WizardStep::Role => {
                    if self.is_orchestrator() {
                        // Orchestrators skip Task
                        self.working_dir_cursor = self.working_dir.len();
                        self.step = WizardStep::WorkingDir;
                    } else {
                        self.task_cursor = self.task.len();
                        self.step = WizardStep::Task;
                    }
                }
                WizardStep::AgentGoal => {
                    self.role_cursor = self.role.len();
                    self.step = WizardStep::Role;
                }
                WizardStep::Context => {
                    self.agent_goal_cursor = self.agent_goal.len();
                    self.step = WizardStep::AgentGoal;
                }
                WizardStep::BacklogPath => {
                    // Only orchestrators see this
                    self.context_cursor = self.context.len();
                    self.step = WizardStep::Context;
                }
                WizardStep::ReviewInterval => {
                    self.backlog_path_cursor = self.backlog_path.len();
                    self.step = WizardStep::BacklogPath;
                }
                WizardStep::RestartPolicy => {
                    if self.is_orchestrator() {
                        self.review_interval_cursor = self.review_interval.len();
                        self.step = WizardStep::ReviewInterval;
                    } else {
                        self.context_cursor = self.context.len();
                        self.step = WizardStep::Context;
                    }
                }
                WizardStep::Confirm => self.step = WizardStep::RestartPolicy,
            }
            return true;
        }

        match self.step {
            WizardStep::Tool => self.handle_tool_key(key),
            WizardStep::CustomCommand => self.handle_text_key(key, TextTarget::CustomCommand),
            WizardStep::AgentType => self.handle_agent_type_key(key),
            WizardStep::Name => self.handle_text_key(key, TextTarget::Name),
            WizardStep::WorkingDir => self.handle_text_key(key, TextTarget::WorkingDir),
            WizardStep::Task => self.handle_text_key(key, TextTarget::Task),
            WizardStep::Role => self.handle_text_key(key, TextTarget::Role),
            WizardStep::AgentGoal => self.handle_text_key(key, TextTarget::AgentGoal),
            WizardStep::Context => self.handle_text_key(key, TextTarget::Context),
            WizardStep::BacklogPath => self.handle_text_key(key, TextTarget::BacklogPath),
            WizardStep::ReviewInterval => self.handle_text_key(key, TextTarget::ReviewInterval),
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
                    self.step = WizardStep::AgentType;
                }
                true
            }
            _ => true,
        }
    }

    /// Handle agent type selection keys (Worker vs Orchestrator).
    fn handle_agent_type_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.agent_type_selected =
                    (self.agent_type_selected + 1).min(AgentTypeChoice::ALL.len() - 1);
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.agent_type_selected = self.agent_type_selected.saturating_sub(1);
                true
            }
            KeyCode::Enter => {
                // When switching to orchestrator, default restart to Always (index 1)
                if self.is_orchestrator() {
                    self.restart_selected = 1; // Always
                }
                self.step = WizardStep::Name;
                self.name_cursor = self.name.len();
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
                } else {
                    self.validation_error = Some("invalid configuration -- please review all fields".into());
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
            TextTarget::Context => (&mut self.context, &mut self.context_cursor),
            TextTarget::BacklogPath => (&mut self.backlog_path, &mut self.backlog_path_cursor),
            TextTarget::ReviewInterval => (&mut self.review_interval, &mut self.review_interval_cursor),
        };

        match key.code {
            KeyCode::Enter => {
                // Advance to next step
                self.step = match self.step {
                    WizardStep::CustomCommand => {
                        if self.custom_command.trim().is_empty() {
                            self.validation_error = Some("command cannot be empty".into());
                            return true;
                        }
                        self.validation_error = None;
                        WizardStep::AgentType
                    }
                    WizardStep::Name => {
                        let trimmed = self.name.trim();
                        if let Err(e) = aegis_types::validate_config_name(trimmed) {
                            self.validation_error = Some(format!("{e}"));
                            return true;
                        }
                        self.validation_error = None;
                        self.working_dir_cursor = self.working_dir.len();
                        WizardStep::WorkingDir
                    }
                    WizardStep::WorkingDir => {
                        let trimmed = self.working_dir.trim();
                        if trimmed.is_empty() {
                            self.validation_error = Some("working directory cannot be empty".into());
                            return true;
                        }
                        let path = std::path::Path::new(trimmed);
                        if !path.exists() {
                            self.validation_error = Some(format!("path does not exist: {trimmed}"));
                            return true;
                        }
                        if !path.is_dir() {
                            self.validation_error = Some(format!("not a directory: {trimmed}"));
                            return true;
                        }
                        self.validation_error = None;
                        if self.is_orchestrator() {
                            // Orchestrators skip Task, go to Role
                            self.role_cursor = self.role.len();
                            WizardStep::Role
                        } else {
                            self.task_cursor = self.task.len();
                            WizardStep::Task
                        }
                    }
                    WizardStep::Task => {
                        self.role_cursor = self.role.len();
                        WizardStep::Role
                    }
                    WizardStep::Role => {
                        self.agent_goal_cursor = self.agent_goal.len();
                        WizardStep::AgentGoal
                    }
                    WizardStep::AgentGoal => {
                        self.context_cursor = self.context.len();
                        WizardStep::Context
                    }
                    WizardStep::Context => {
                        if self.is_orchestrator() {
                            self.backlog_path_cursor = self.backlog_path.len();
                            WizardStep::BacklogPath
                        } else {
                            WizardStep::RestartPolicy
                        }
                    }
                    WizardStep::BacklogPath => {
                        self.review_interval_cursor = self.review_interval.len();
                        WizardStep::ReviewInterval
                    }
                    WizardStep::ReviewInterval => {
                        // Validate interval is a number
                        let trimmed = self.review_interval.trim();
                        if !trimmed.is_empty() && trimmed.parse::<u64>().is_err() {
                            self.validation_error = Some("must be a number (seconds)".into());
                            return true;
                        }
                        self.validation_error = None;
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
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                match c {
                    'a' => *cursor = 0,
                    'e' => *cursor = text.len(),
                    'u' => {
                        text.drain(..*cursor);
                        *cursor = 0;
                    }
                    'w' => {
                        if *cursor > 0 {
                            let new_pos = super::delete_word_backward_pos(text, *cursor);
                            text.drain(new_pos..*cursor);
                            *cursor = new_pos;
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Char(c) => {
                text.insert(*cursor, c);
                *cursor += c.len_utf8();
                self.validation_error = None;
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
            WizardStep::Context => (&mut self.context, &mut self.context_cursor, true),
            WizardStep::BacklogPath => {
                (&mut self.backlog_path, &mut self.backlog_path_cursor, false)
            }
            WizardStep::ReviewInterval => {
                (&mut self.review_interval, &mut self.review_interval_cursor, false)
            }
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

    /// Whether this agent is being configured as an orchestrator.
    pub fn is_orchestrator(&self) -> bool {
        self.agent_type_choice() == AgentTypeChoice::Orchestrator
    }

    /// Get the selected agent type choice (bounds-checked).
    pub fn agent_type_choice(&self) -> AgentTypeChoice {
        AgentTypeChoice::ALL.get(self.agent_type_selected)
            .copied()
            .unwrap_or(AgentTypeChoice::Worker)
    }

    /// Check if the wizard has enough data to produce a valid config.
    pub fn is_valid(&self) -> bool {
        let wd = self.working_dir.trim();
        let name_valid = aegis_types::validate_config_name(self.name.trim()).is_ok();
        let base = name_valid
            && !wd.is_empty()
            && std::path::Path::new(wd).is_dir();
        if self.is_custom_tool() {
            base && !self.custom_command.trim().is_empty()
        } else {
            base
        }
    }

    /// Get the selected tool choice (bounds-checked).
    pub fn tool_choice(&self) -> ToolChoice {
        ToolChoice::ALL.get(self.tool_selected)
            .copied()
            .unwrap_or(ToolChoice::ClaudeCode)
    }

    /// Get the selected restart choice (bounds-checked).
    pub fn restart_choice(&self) -> RestartChoice {
        RestartChoice::ALL.get(self.restart_selected)
            .copied()
            .unwrap_or(RestartChoice::OnFailure)
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

        let context = if self.context.trim().is_empty() {
            None
        } else {
            Some(self.context.clone())
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
        config.context = context;

        if self.is_orchestrator() {
            let backlog = if self.backlog_path.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(self.backlog_path.trim()))
            };
            let interval = self.review_interval.trim()
                .parse::<u64>()
                .unwrap_or(300);
            config.orchestrator = Some(OrchestratorConfig {
                review_interval_secs: interval,
                backlog_path: backlog,
                managed_agents: vec![], // empty = manage all non-orchestrator agents
            });
        }

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
    Context,
    BacklogPath,
    ReviewInterval,
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
    fn wizard_step_numbers_worker_non_custom() {
        // Non-custom worker: CustomCommand, BacklogPath, ReviewInterval hidden
        assert_eq!(WizardStep::Tool.number(false, false), 1);
        assert_eq!(WizardStep::AgentType.number(false, false), 2);
        assert_eq!(WizardStep::Name.number(false, false), 3);
        assert_eq!(WizardStep::Role.number(false, false), 6);
        assert_eq!(WizardStep::AgentGoal.number(false, false), 7);
        assert_eq!(WizardStep::Context.number(false, false), 8);
        assert_eq!(WizardStep::Confirm.number(false, false), 10);
        assert_eq!(WizardStep::total(false, false), 10);
    }

    #[test]
    fn wizard_step_numbers_custom_worker() {
        // Custom worker: CustomCommand visible, BacklogPath/ReviewInterval hidden
        assert_eq!(WizardStep::Tool.number(true, false), 1);
        assert_eq!(WizardStep::CustomCommand.number(true, false), 2);
        assert_eq!(WizardStep::AgentType.number(true, false), 3);
        assert_eq!(WizardStep::Name.number(true, false), 4);
        assert_eq!(WizardStep::Confirm.number(true, false), 11);
        assert_eq!(WizardStep::total(true, false), 11);
    }

    #[test]
    fn wizard_step_numbers_orchestrator() {
        // Orchestrator: Task hidden, BacklogPath/ReviewInterval visible
        assert_eq!(WizardStep::Tool.number(false, true), 1);
        assert_eq!(WizardStep::AgentType.number(false, true), 2);
        assert_eq!(WizardStep::Name.number(false, true), 3);
        assert_eq!(WizardStep::BacklogPath.number(false, true), 8);
        assert_eq!(WizardStep::ReviewInterval.number(false, true), 9);
        assert_eq!(WizardStep::Confirm.number(false, true), 11);
        assert_eq!(WizardStep::total(false, true), 11);
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
        assert_eq!(wiz.step, WizardStep::AgentType);
    }

    #[test]
    fn wizard_cursors_start_at_end_of_default_text() {
        let wiz = AddAgentWizard::new();
        assert_eq!(wiz.name_cursor, wiz.name.len());
        assert_eq!(wiz.working_dir_cursor, wiz.working_dir.len());
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
        assert_eq!(wiz.step, WizardStep::AgentType);

        // Step 2: Agent type (Worker -- default)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name);

        // Step 3: Name
        wiz.name = "test-agent".into();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::WorkingDir);

        // Step 4: Working dir
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Task);

        // Step 5: Task (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Role);

        // Step 6: Role (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::AgentGoal);

        // Step 7: Agent goal (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Context);

        // Step 8: Context (optional, enter to skip)
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::RestartPolicy);

        // Step 9: Restart policy
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Confirm);

        // Step 10: Confirm
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

        // Type a command and advance to AgentType
        wiz.custom_command = "my-tool --verbose".into();
        wiz.custom_command_cursor = wiz.custom_command.len();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::AgentType);
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

        // Name -> AgentType
        wiz.step = WizardStep::Name;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::AgentType);
        assert!(wiz.active);

        // AgentType -> Tool (non-custom)
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Tool);
        assert!(wiz.active);

        // AgentType -> CustomCommand (when Custom tool is selected)
        wiz.tool_selected = 4; // Custom
        wiz.step = WizardStep::AgentType;
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

        // Context -> AgentGoal
        wiz.step = WizardStep::Context;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::AgentGoal);
        assert!(wiz.active);

        // RestartPolicy -> Context
        wiz.step = WizardStep::RestartPolicy;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Context);
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
    fn wizard_is_valid_rejects_invalid_name_format() {
        let mut wiz = AddAgentWizard::new();
        wiz.working_dir = "/tmp".into();

        // Names with spaces should be invalid
        wiz.name = "has spaces".into();
        assert!(!wiz.is_valid(), "name with spaces should be invalid");

        // Names with special chars should be invalid
        wiz.name = "bad@name!".into();
        assert!(!wiz.is_valid(), "name with special chars should be invalid");

        // Valid kebab-case name
        wiz.name = "my-agent".into();
        assert!(wiz.is_valid());
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

    #[test]
    fn wizard_backtab_goes_back() {
        let mut wiz = AddAgentWizard::new();

        // Name -> AgentType
        wiz.step = WizardStep::Name;
        wiz.handle_key(press(KeyCode::BackTab));
        assert_eq!(wiz.step, WizardStep::AgentType);

        // AgentType -> Tool
        wiz.handle_key(press(KeyCode::BackTab));
        assert_eq!(wiz.step, WizardStep::Tool);

        // WorkingDir -> Name
        wiz.step = WizardStep::WorkingDir;
        wiz.handle_key(press(KeyCode::BackTab));
        assert_eq!(wiz.step, WizardStep::Name);

        // Task -> WorkingDir
        wiz.step = WizardStep::Task;
        wiz.handle_key(press(KeyCode::BackTab));
        assert_eq!(wiz.step, WizardStep::WorkingDir);
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    #[test]
    fn wizard_ctrl_a_e_u_w() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "hello world".into();
        wiz.name_cursor = 11;

        // Ctrl+A -> beginning
        wiz.handle_key(ctrl(KeyCode::Char('a')));
        assert_eq!(wiz.name_cursor, 0);

        // Ctrl+E -> end
        wiz.handle_key(ctrl(KeyCode::Char('e')));
        assert_eq!(wiz.name_cursor, 11);

        // Ctrl+W -> delete word backward
        wiz.handle_key(ctrl(KeyCode::Char('w')));
        assert_eq!(wiz.name, "hello ");
        assert_eq!(wiz.name_cursor, 6);

        // Ctrl+U -> clear to beginning
        wiz.handle_key(ctrl(KeyCode::Char('u')));
        assert_eq!(wiz.name, "");
        assert_eq!(wiz.name_cursor, 0);
    }

    #[test]
    fn wizard_tool_choice_bounds_checked() {
        let mut wiz = AddAgentWizard::new();
        wiz.tool_selected = 999; // out of bounds
        assert_eq!(wiz.tool_choice(), ToolChoice::ClaudeCode); // should fallback
    }

    #[test]
    fn wizard_restart_choice_bounds_checked() {
        let mut wiz = AddAgentWizard::new();
        wiz.restart_selected = 999; // out of bounds
        assert_eq!(wiz.restart_choice(), RestartChoice::OnFailure); // should fallback
    }

    #[test]
    fn wizard_name_validation_rejects_special_chars() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "bad name with spaces".into();
        wiz.name_cursor = wiz.name.len();
        // Try to advance
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name); // should NOT advance
        assert!(wiz.validation_error.is_some());

        // Fix the name
        wiz.name = "good-name_1".into();
        wiz.name_cursor = wiz.name.len();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::WorkingDir); // should advance
        assert!(wiz.validation_error.is_none());
    }

    #[test]
    fn wizard_name_validation_clears_on_typing() {
        let mut wiz = AddAgentWizard::new();
        wiz.step = WizardStep::Name;
        wiz.name = "bad[name".into();
        wiz.name_cursor = wiz.name.len();
        wiz.handle_key(press(KeyCode::Enter));
        assert!(wiz.validation_error.is_some());

        // Typing clears error
        wiz.handle_key(press(KeyCode::Char('x')));
        assert!(wiz.validation_error.is_none());
    }

    #[test]
    fn wizard_orchestrator_step_progression() {
        let mut wiz = AddAgentWizard::new();

        // Step 1: Tool
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::AgentType);

        // Step 2: Select Orchestrator (index 1)
        wiz.handle_key(press(KeyCode::Char('j')));
        assert_eq!(wiz.agent_type_selected, 1);
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Name);
        assert!(wiz.is_orchestrator());
        // Restart should auto-default to Always (index 1)
        assert_eq!(wiz.restart_selected, 1);

        // Step 3: Name
        wiz.name = "director".into();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::WorkingDir);

        // Step 4: Working dir
        wiz.handle_key(press(KeyCode::Enter));
        // Orchestrators skip Task, go to Role
        assert_eq!(wiz.step, WizardStep::Role);

        // Step 5: Role
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::AgentGoal);

        // Step 6: Agent goal
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Context);

        // Step 7: Context
        wiz.handle_key(press(KeyCode::Enter));
        // Orchestrators see BacklogPath next
        assert_eq!(wiz.step, WizardStep::BacklogPath);

        // Step 8: Backlog path
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::ReviewInterval);

        // Step 9: Review interval
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::RestartPolicy);

        // Step 10: Restart policy
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::Confirm);

        // Step 11: Confirm
        wiz.handle_key(press(KeyCode::Enter));
        assert!(!wiz.active);
        assert!(wiz.completed);
    }

    #[test]
    fn wizard_orchestrator_builds_config_with_orchestrator_field() {
        let mut wiz = AddAgentWizard::new();
        wiz.agent_type_selected = 1; // Orchestrator
        wiz.name = "orch-1".into();
        wiz.working_dir = "/tmp".into();
        wiz.backlog_path = "./BACKLOG.md".into();
        wiz.review_interval = "120".into();

        let config = wiz.build_config();
        assert_eq!(config.name, "orch-1");
        let orch = config.orchestrator.expect("should have orchestrator config");
        assert_eq!(orch.review_interval_secs, 120);
        assert_eq!(orch.backlog_path, Some(PathBuf::from("./BACKLOG.md")));
        assert!(orch.managed_agents.is_empty());
    }

    #[test]
    fn wizard_worker_builds_config_without_orchestrator_field() {
        let mut wiz = AddAgentWizard::new();
        wiz.agent_type_selected = 0; // Worker
        wiz.name = "worker-1".into();
        wiz.working_dir = "/tmp".into();

        let config = wiz.build_config();
        assert!(config.orchestrator.is_none());
    }

    #[test]
    fn wizard_orchestrator_esc_back_navigation() {
        let mut wiz = AddAgentWizard::new();
        wiz.agent_type_selected = 1; // Orchestrator

        // Role -> WorkingDir (skips Task for orchestrators)
        wiz.step = WizardStep::Role;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::WorkingDir);

        // BacklogPath -> Context
        wiz.step = WizardStep::BacklogPath;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::Context);

        // ReviewInterval -> BacklogPath
        wiz.step = WizardStep::ReviewInterval;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::BacklogPath);

        // RestartPolicy -> ReviewInterval (for orchestrators)
        wiz.step = WizardStep::RestartPolicy;
        wiz.handle_key(press(KeyCode::Esc));
        assert_eq!(wiz.step, WizardStep::ReviewInterval);
    }

    #[test]
    fn wizard_agent_type_choice_bounds_checked() {
        let mut wiz = AddAgentWizard::new();
        wiz.agent_type_selected = 999;
        assert_eq!(wiz.agent_type_choice(), AgentTypeChoice::Worker); // fallback
    }

    #[test]
    fn wizard_review_interval_validation() {
        let mut wiz = AddAgentWizard::new();
        wiz.agent_type_selected = 1;
        wiz.step = WizardStep::ReviewInterval;
        wiz.review_interval = "not-a-number".into();
        wiz.review_interval_cursor = wiz.review_interval.len();

        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::ReviewInterval, "invalid interval should not advance");
        assert!(wiz.validation_error.is_some());

        // Valid number should advance
        wiz.review_interval = "60".into();
        wiz.review_interval_cursor = wiz.review_interval.len();
        wiz.handle_key(press(KeyCode::Enter));
        assert_eq!(wiz.step, WizardStep::RestartPolicy);
    }
}
