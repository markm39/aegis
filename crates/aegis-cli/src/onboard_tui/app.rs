//! Onboarding wizard state machine.
//!
//! Manages the current step, handles keyboard input, and tracks all user
//! selections for the first-run onboarding wizard.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::config::ChannelConfig;
use aegis_types::daemon::{
    AgentSlotConfig, AgentToolConfig, OrchestratorConfig, SecurityPresetKind,
};

use crate::fleet_tui::wizard::{RestartChoice, ToolChoice};
use crate::tui_utils::delete_word_backward_pos;
use crate::wizard::model::{self, ActionEntry, ActionPermission, SecurityPreset};

/// How the user wants to organize their fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowChoice {
    /// A single agent working on its own.
    Solo,
    /// Multiple workers with a shared fleet goal.
    Team,
    /// An orchestrator agent directing worker agents.
    Orchestrated,
}

impl WorkflowChoice {
    pub const ALL: &'static [WorkflowChoice] = &[
        WorkflowChoice::Solo,
        WorkflowChoice::Team,
        WorkflowChoice::Orchestrated,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            WorkflowChoice::Solo => "Solo Agent",
            WorkflowChoice::Team => "Team",
            WorkflowChoice::Orchestrated => "Orchestrated Team",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            WorkflowChoice::Solo => "One agent, one task",
            WorkflowChoice::Team => "Multiple workers sharing a fleet goal",
            WorkflowChoice::Orchestrated => "An orchestrator directing worker agents",
        }
    }
}

/// Steps in the onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardStep {
    /// Welcome screen with system check results.
    Welcome,
    /// Choose fleet workflow: Solo, Team, or Orchestrated.
    Workflow,
    /// Fleet-wide goal (Team and Orchestrated only).
    FleetGoal,
    /// Select agent tool.
    Tool,
    /// Custom command path (only when tool == Custom).
    CustomCommand,
    /// Agent name.
    Name,
    /// Working directory.
    WorkingDir,
    /// Task / initial prompt (workers only).
    Task,
    /// Restart policy selection.
    RestartPolicy,
    /// Security preset selection (Observe Only, Read-only, etc.).
    SecurityPreset,
    /// Per-action Allow/Deny configuration (only when Custom selected).
    SecurityDetail,
    /// Informational screen explaining monitoring capabilities.
    MonitoringInfo,
    /// Backlog file path (orchestrator only).
    OrchestratorBacklog,
    /// Review interval in seconds (orchestrator only).
    OrchestratorInterval,
    /// Ask whether to add another worker (multi-agent only).
    AddMore,
    /// Ask whether to set up Telegram.
    TelegramOffer,
    /// Telegram bot token input.
    TelegramToken,
    /// Async validation and chat discovery.
    TelegramProgress,
    /// Review and confirm.
    Summary,
    /// Completed.
    Done,
    /// Cancelled.
    Cancelled,
}

impl OnboardStep {
    /// Label for the progress display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Welcome => "Welcome",
            Self::Workflow => "Workflow",
            Self::FleetGoal => "Fleet Goal",
            Self::Tool | Self::CustomCommand => "Agent Tool",
            Self::Name => "Agent Name",
            Self::WorkingDir => "Working Directory",
            Self::Task => "Task",
            Self::RestartPolicy => "Restart Policy",
            Self::SecurityPreset | Self::SecurityDetail => "Security",
            Self::MonitoringInfo => "Monitoring",
            Self::OrchestratorBacklog => "Backlog Path",
            Self::OrchestratorInterval => "Review Interval",
            Self::AddMore => "Add Agent",
            Self::TelegramOffer | Self::TelegramToken | Self::TelegramProgress => "Telegram",
            Self::Summary => "Summary",
            Self::Done | Self::Cancelled => "Complete",
        }
    }
}

/// Events received from the Telegram background worker.
pub enum TelegramEvent {
    /// Bot token validated successfully.
    TokenValid { bot_username: String },
    /// Bot token is invalid.
    TokenInvalid(String),
    /// Chat ID discovered from user message.
    ChatDiscovered { chat_id: i64 },
    /// Confirmation message sent.
    ConfirmationSent,
    /// An error occurred.
    Error(String),
}

/// Telegram setup status for the progress step.
#[derive(Debug, Clone, PartialEq)]
pub enum TelegramStatus {
    Idle,
    ValidatingToken,
    WaitingForChat { bot_username: String },
    SendingConfirmation,
    Complete { bot_username: String, chat_id: i64 },
    Failed(String),
}

/// Result returned after the wizard completes.
pub struct OnboardResult {
    pub cancelled: bool,
    pub fleet_goal: Option<String>,
    pub agents: Vec<AgentSlotConfig>,
    pub channel: Option<ChannelConfig>,
    pub start_daemon: bool,
    /// Selected security preset for each agent.
    pub security_preset: SecurityPresetKind,
    /// Generated Cedar policy text (None for ObserveOnly).
    pub policy_text: Option<String>,
    /// Isolation config derived from security preset.
    pub security_isolation: Option<aegis_types::IsolationConfig>,
}

/// The onboarding wizard state.
pub struct OnboardApp {
    /// Current step.
    pub step: OnboardStep,
    /// Whether the event loop should keep running.
    pub running: bool,

    // -- Welcome --
    pub aegis_dir_ok: bool,
    pub aegis_dir_path: String,

    // -- Workflow --
    pub workflow_selected: usize,

    // -- Fleet Goal (Team/Orchestrated) --
    pub fleet_goal: String,
    pub fleet_goal_cursor: usize,

    // -- Tool --
    pub tool_selected: usize,

    // -- Custom command --
    pub custom_command: String,
    pub custom_cursor: usize,

    // -- Name --
    pub name: String,
    pub name_cursor: usize,
    pub name_error: Option<String>,

    // -- Working dir --
    pub working_dir: String,
    pub working_dir_cursor: usize,
    pub working_dir_error: Option<String>,

    // -- Task --
    pub task: String,
    pub task_cursor: usize,

    // -- Restart policy --
    pub restart_selected: usize,

    // -- Orchestrator-specific --
    pub backlog_path: String,
    pub backlog_path_cursor: usize,
    pub review_interval: String,
    pub review_interval_cursor: usize,

    // -- Multi-agent --
    pub completed_agents: Vec<AgentSlotConfig>,
    pub configuring_orchestrator: bool,
    pub add_more_selected: usize,

    // -- Security --
    pub security_preset_selected: usize,
    pub security_actions: Vec<ActionEntry>,
    pub security_action_selected: usize,

    // -- Telegram offer --
    pub telegram_offer_selected: usize, // 0 = Yes, 1 = No

    // -- Telegram token --
    pub telegram_token: String,
    pub telegram_token_cursor: usize,
    pub telegram_status: TelegramStatus,

    // -- Telegram async --
    pub telegram_evt_rx: Option<mpsc::Receiver<TelegramEvent>>,
    pub telegram_result: Option<(String, i64, String)>, // (token, chat_id, bot_username)
    /// When Telegram validation started (for elapsed time display).
    pub telegram_started_at: Option<Instant>,

    // -- Summary --
    pub start_daemon: bool,

    // -- Paste indicator --
    /// Temporary paste notification: (message, when).
    pub paste_indicator: Option<(String, Instant)>,
}

impl OnboardApp {
    /// Create a new wizard with sensible defaults.
    pub fn new() -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".into());

        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "my-agent".into());

        let (aegis_dir_ok, aegis_dir_path) = match crate::commands::init::ensure_aegis_dir() {
            Ok(p) => (true, p.display().to_string()),
            Err(_) => (false, "~/.aegis".into()),
        };

        Self {
            step: OnboardStep::Welcome,
            running: true,
            aegis_dir_ok,
            aegis_dir_path,
            workflow_selected: 0,
            fleet_goal: String::new(),
            fleet_goal_cursor: 0,
            tool_selected: 0,
            custom_command: String::new(),
            custom_cursor: 0,
            name_cursor: default_name.len(),
            name: default_name,
            name_error: None,
            working_dir_cursor: cwd.len(),
            working_dir: cwd,
            working_dir_error: None,
            task: String::new(),
            task_cursor: 0,
            restart_selected: 0,
            backlog_path: String::new(),
            backlog_path_cursor: 0,
            review_interval: "300".into(),
            review_interval_cursor: 3,
            completed_agents: Vec::new(),
            configuring_orchestrator: false,
            add_more_selected: 0,
            security_preset_selected: 0, // ObserveOnly
            security_actions: model::default_action_entries(),
            security_action_selected: 0,
            telegram_offer_selected: 1, // default to No
            telegram_token: String::new(),
            telegram_token_cursor: 0,
            telegram_status: TelegramStatus::Idle,
            telegram_evt_rx: None,
            telegram_result: None,
            telegram_started_at: None,
            start_daemon: true,
            paste_indicator: None,
        }
    }

    /// Get the selected workflow choice (bounds-checked).
    pub fn workflow_choice(&self) -> WorkflowChoice {
        WorkflowChoice::ALL
            .get(self.workflow_selected)
            .copied()
            .unwrap_or(WorkflowChoice::Solo)
    }

    /// Whether the workflow involves multiple agents.
    pub fn is_multi_agent(&self) -> bool {
        self.workflow_choice() != WorkflowChoice::Solo
    }

    /// Number of non-orchestrator agents saved so far.
    fn worker_count(&self) -> usize {
        self.completed_agents
            .iter()
            .filter(|a| a.orchestrator.is_none())
            .count()
    }

    /// Progress label for the title bar.
    pub fn progress_text(&self) -> String {
        match self.step {
            OnboardStep::Welcome | OnboardStep::Workflow => {
                format!("Setup: {}", self.step.label())
            }
            OnboardStep::Done | OnboardStep::Cancelled => String::new(),
            _ if !self.is_multi_agent() => {
                format!("Setup: {}", self.step.label())
            }
            _ if matches!(self.step, OnboardStep::FleetGoal) => "Fleet: Fleet Goal".into(),
            _ if self.configuring_orchestrator => {
                format!("Orchestrator: {}", self.step.label())
            }
            _ if matches!(self.step, OnboardStep::AddMore) => "Fleet: Add Another?".into(),
            _ if matches!(
                self.step,
                OnboardStep::SecurityPreset
                    | OnboardStep::SecurityDetail
                    | OnboardStep::MonitoringInfo
            ) =>
            {
                format!("Security: {}", self.step.label())
            }
            _ if matches!(
                self.step,
                OnboardStep::TelegramOffer
                    | OnboardStep::TelegramToken
                    | OnboardStep::TelegramProgress
            ) =>
            {
                format!("Notifications: {}", self.step.label())
            }
            _ if matches!(self.step, OnboardStep::Summary) => "Review: Summary".into(),
            _ => {
                let n = self.worker_count() + 1;
                format!("Worker {n}: {}", self.step.label())
            }
        }
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always cancels the wizard (raw mode captures the signal).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.step = OnboardStep::Cancelled;
            self.running = false;
            return;
        }

        match self.step {
            OnboardStep::Welcome => self.handle_welcome(key),
            OnboardStep::Workflow => self.handle_workflow(key),
            OnboardStep::FleetGoal => self.handle_text(key, TextField::FleetGoal),
            OnboardStep::Tool => self.handle_tool(key),
            OnboardStep::CustomCommand => self.handle_text(key, TextField::CustomCommand),
            OnboardStep::Name => self.handle_name(key),
            OnboardStep::WorkingDir => self.handle_working_dir(key),
            OnboardStep::Task => self.handle_text(key, TextField::Task),
            OnboardStep::RestartPolicy => self.handle_restart(key),
            OnboardStep::SecurityPreset => self.handle_security_preset(key),
            OnboardStep::SecurityDetail => self.handle_security_detail(key),
            OnboardStep::MonitoringInfo => self.handle_monitoring_info(key),
            OnboardStep::OrchestratorBacklog => self.handle_text(key, TextField::BacklogPath),
            OnboardStep::OrchestratorInterval => self.handle_text(key, TextField::ReviewInterval),
            OnboardStep::AddMore => self.handle_add_more(key),
            OnboardStep::TelegramOffer => self.handle_telegram_offer(key),
            OnboardStep::TelegramToken => self.handle_text(key, TextField::TelegramToken),
            OnboardStep::TelegramProgress => self.handle_telegram_progress(key),
            OnboardStep::Summary => self.handle_summary(key),
            OnboardStep::Done | OnboardStep::Cancelled => {}
        }
    }

    /// Handle pasted text (from `Event::Paste` when bracketed paste is enabled).
    ///
    /// Inserts the pasted text at the cursor position of whichever text field
    /// is currently active. For single-line fields (name, dir, token), newlines
    /// are collapsed to spaces. The task field preserves newlines.
    pub fn handle_paste(&mut self, text: &str) {
        let (buf, cursor) = match self.step {
            OnboardStep::FleetGoal => (&mut self.fleet_goal, &mut self.fleet_goal_cursor),
            OnboardStep::CustomCommand => (&mut self.custom_command, &mut self.custom_cursor),
            OnboardStep::Name => (&mut self.name, &mut self.name_cursor),
            OnboardStep::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            OnboardStep::Task => (&mut self.task, &mut self.task_cursor),
            OnboardStep::OrchestratorBacklog => {
                (&mut self.backlog_path, &mut self.backlog_path_cursor)
            }
            OnboardStep::OrchestratorInterval => {
                (&mut self.review_interval, &mut self.review_interval_cursor)
            }
            OnboardStep::TelegramToken => {
                (&mut self.telegram_token, &mut self.telegram_token_cursor)
            }
            _ => return, // Not a text input step
        };

        // Task keeps newlines; other fields collapse them
        let cleaned = if self.step == OnboardStep::Task {
            text.replace('\r', "")
        } else {
            text.replace(['\n', '\r'], " ")
        };

        buf.insert_str(*cursor, &cleaned);
        *cursor += cleaned.len();

        // Show paste indicator for large pastes
        if cleaned.len() > 20 {
            self.paste_indicator =
                Some((format!("[pasted {} chars]", cleaned.len()), Instant::now()));
        }
    }

    /// Poll for async Telegram events (called each tick from the event loop).
    pub fn poll_telegram(&mut self) {
        let evt = match &self.telegram_evt_rx {
            Some(rx) => rx.try_recv().ok(),
            None => None,
        };
        if let Some(evt) = evt {
            self.process_telegram_event(evt);
        }
    }

    /// Process a single Telegram event, updating status and result.
    fn process_telegram_event(&mut self, evt: TelegramEvent) {
        match evt {
            TelegramEvent::TokenValid { bot_username } => {
                self.telegram_status = TelegramStatus::WaitingForChat { bot_username };
            }
            TelegramEvent::TokenInvalid(e) => {
                self.telegram_status = TelegramStatus::Failed(format!("Invalid token: {e}"));
            }
            TelegramEvent::ChatDiscovered { chat_id } => {
                let bot_username = match &self.telegram_status {
                    TelegramStatus::WaitingForChat { bot_username } => bot_username.clone(),
                    _ => "bot".into(),
                };
                self.telegram_status = TelegramStatus::SendingConfirmation;
                self.telegram_result = Some((self.telegram_token.clone(), chat_id, bot_username));
            }
            TelegramEvent::ConfirmationSent => {
                if let Some((_, chat_id, ref bot_username)) = self.telegram_result {
                    self.telegram_status = TelegramStatus::Complete {
                        bot_username: bot_username.clone(),
                        chat_id,
                    };
                }
            }
            TelegramEvent::Error(e) => {
                self.telegram_status = TelegramStatus::Failed(e);
            }
        }
    }

    /// Build the result from current state.
    pub fn result(&self) -> OnboardResult {
        if self.step == OnboardStep::Cancelled {
            return OnboardResult {
                cancelled: true,
                fleet_goal: None,
                agents: vec![],
                channel: None,
                start_daemon: false,
                security_preset: SecurityPresetKind::ObserveOnly,
                policy_text: None,
                security_isolation: None,
            };
        }

        let channel = self.telegram_result.as_ref().map(|(token, chat_id, _)| {
            ChannelConfig::Telegram(aegis_types::config::TelegramConfig {
                bot_token: token.clone(),
                chat_id: *chat_id,
                poll_timeout_secs: 30,
                allow_group_commands: false,
            })
        });

        let fleet_goal = if self.fleet_goal.trim().is_empty() {
            None
        } else {
            Some(self.fleet_goal.trim().to_string())
        };

        // Solo: build from current fields. Multi-agent: use completed_agents.
        let agents = if self.is_multi_agent() {
            self.completed_agents.clone()
        } else {
            vec![self.build_agent_slot()]
        };

        let preset = self.selected_security_preset();
        let preset_kind = self.selected_security_preset_kind();
        let policy_text = if preset == SecurityPreset::ObserveOnly {
            None
        } else {
            Some(crate::wizard::policy_gen::generate_policy(
                &self.security_actions,
            ))
        };
        let security_isolation = if preset == SecurityPreset::ObserveOnly {
            None
        } else {
            Some(preset.isolation())
        };

        OnboardResult {
            cancelled: false,
            fleet_goal,
            agents,
            channel,
            start_daemon: self.start_daemon,
            security_preset: preset_kind,
            policy_text,
            security_isolation,
        }
    }

    /// Get the selected tool choice (bounds-checked).
    fn tool_choice(&self) -> ToolChoice {
        ToolChoice::ALL
            .get(self.tool_selected)
            .copied()
            .unwrap_or(ToolChoice::ClaudeCode)
    }

    fn build_agent_slot(&self) -> AgentSlotConfig {
        let tool = self.build_tool_config();
        let task = if self.task.trim().is_empty() {
            None
        } else {
            Some(self.task.clone())
        };
        crate::commands::build_agent_slot(
            self.name.trim().to_string(),
            tool,
            PathBuf::from(self.working_dir.trim()),
            task,
            RestartChoice::ALL
                .get(self.restart_selected)
                .copied()
                .unwrap_or(RestartChoice::OnFailure)
                .to_policy(),
            5,
        )
    }

    fn build_tool_config(&self) -> AgentToolConfig {
        match ToolChoice::ALL
            .get(self.tool_selected)
            .copied()
            .unwrap_or(ToolChoice::ClaudeCode)
        {
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
            ToolChoice::Custom => {
                // Split "command --flag1 --flag2" into command + args
                let parts: Vec<&str> = self.custom_command.split_whitespace().collect();
                let command = parts.first().map(|s| s.to_string()).unwrap_or_default();
                let args: Vec<String> = parts.iter().skip(1).map(|s| s.to_string()).collect();
                AgentToolConfig::Custom {
                    command,
                    args,
                    adapter: Default::default(),
                    env: vec![],
                }
            }
        }
    }

    /// Save the current fields as a worker agent to completed_agents.
    fn save_current_agent(&mut self) {
        let slot = self.build_agent_slot();
        self.completed_agents.push(slot);
    }

    /// Save the current fields as an orchestrator agent to completed_agents.
    fn save_orchestrator(&mut self) {
        let tool = self.build_tool_config();
        let backlog = if self.backlog_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(self.backlog_path.trim()))
        };
        let interval = self.review_interval.trim().parse::<u64>().unwrap_or(300);

        let config = AgentSlotConfig {
            name: self.name.trim().to_string(),
            tool,
            working_dir: PathBuf::from(self.working_dir.trim()),
            role: Some("Orchestrator".into()),
            agent_goal: Some(
                "Keep coding agents focused on high-value backlog items. Verify their work.".into(),
            ),
            context: None,
            task: None,
            pilot: None,
            restart: aegis_types::daemon::RestartPolicy::Always,
            max_restarts: 0,
            enabled: true,
            orchestrator: Some(OrchestratorConfig {
                review_interval_secs: interval,
                backlog_path: backlog,
                managed_agents: vec![],
            }),
            security_preset: None,
            policy_dir: None,
            isolation: None,
        };
        self.completed_agents.push(config);
    }

    /// Reset agent fields for configuring the next agent.
    fn reset_agent_fields(&mut self) {
        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "worker".into());

        self.tool_selected = 0;
        self.custom_command.clear();
        self.custom_cursor = 0;
        self.name = default_name;
        self.name_cursor = self.name.len();
        self.name_error = None;
        // Keep working_dir -- agents likely share the same project
        self.working_dir_cursor = self.working_dir.len();
        self.working_dir_error = None;
        self.task.clear();
        self.task_cursor = 0;
        self.restart_selected = 0;
        self.configuring_orchestrator = false;
    }

    // -- Step handlers --

    fn handle_welcome(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.step = OnboardStep::Workflow,
            KeyCode::Esc | KeyCode::Char('q') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    fn handle_workflow(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.workflow_selected =
                    (self.workflow_selected + 1).min(WorkflowChoice::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.workflow_selected = self.workflow_selected.saturating_sub(1);
            }
            KeyCode::Enter => match self.workflow_choice() {
                WorkflowChoice::Solo => {
                    self.configuring_orchestrator = false;
                    self.step = OnboardStep::Tool;
                }
                WorkflowChoice::Team | WorkflowChoice::Orchestrated => {
                    self.fleet_goal_cursor = self.fleet_goal.len();
                    self.step = OnboardStep::FleetGoal;
                }
            },
            KeyCode::Esc => self.step = OnboardStep::Welcome,
            _ => {}
        }
    }

    fn handle_tool(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.tool_selected = (self.tool_selected + 1).min(ToolChoice::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.tool_selected = self.tool_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.tool_choice() == ToolChoice::Custom {
                    self.custom_cursor = self.custom_command.len();
                    self.step = OnboardStep::CustomCommand;
                } else {
                    self.name_cursor = self.name.len();
                    self.step = OnboardStep::Name;
                }
            }
            KeyCode::Esc => {
                if self.configuring_orchestrator {
                    self.step = OnboardStep::FleetGoal;
                } else if !self.is_multi_agent() {
                    self.step = OnboardStep::Workflow;
                } else if self.completed_agents.is_empty() {
                    // Team mode, first worker: back to fleet goal
                    self.step = OnboardStep::FleetGoal;
                } else {
                    // Additional worker: done adding, go to telegram
                    self.step = OnboardStep::TelegramOffer;
                }
            }
            _ => {}
        }
    }

    fn handle_name(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let trimmed = self.name.trim();
                if trimmed.is_empty() {
                    self.name_error = Some("Name cannot be empty".into());
                    return;
                }
                match aegis_types::validate_config_name(trimmed) {
                    Ok(()) => {
                        self.name_error = None;
                        self.working_dir_cursor = self.working_dir.len();
                        self.step = OnboardStep::WorkingDir;
                    }
                    Err(e) => {
                        self.name_error = Some(e.to_string());
                    }
                }
            }
            KeyCode::Esc => {
                self.name_error = None;
                if self.tool_choice() == ToolChoice::Custom {
                    self.step = OnboardStep::CustomCommand;
                } else {
                    self.step = OnboardStep::Tool;
                }
            }
            _ => {
                self.name_error = None;
                self.edit_text(key, TextField::Name);
            }
        }
    }

    fn handle_working_dir(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                let trimmed = self.working_dir.trim();
                if trimmed.is_empty() {
                    self.working_dir_error = Some("Directory cannot be empty".into());
                    return;
                }
                if !Path::new(trimmed).is_dir() {
                    self.working_dir_error = Some(format!("Not a directory: {trimmed}"));
                    return;
                }
                self.working_dir_error = None;
                if self.configuring_orchestrator {
                    self.backlog_path_cursor = self.backlog_path.len();
                    self.step = OnboardStep::OrchestratorBacklog;
                } else {
                    self.task_cursor = self.task.len();
                    self.step = OnboardStep::Task;
                }
            }
            KeyCode::Esc => {
                self.working_dir_error = None;
                self.step = OnboardStep::Name;
            }
            _ => {
                self.working_dir_error = None;
                self.edit_text(key, TextField::WorkingDir);
            }
        }
    }

    fn handle_restart(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.restart_selected =
                    (self.restart_selected + 1).min(RestartChoice::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.restart_selected = self.restart_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.is_multi_agent() {
                    self.save_current_agent();
                    self.reset_agent_fields();
                    self.add_more_selected = 0;
                    self.step = OnboardStep::AddMore;
                } else {
                    self.step = OnboardStep::SecurityPreset;
                }
            }
            KeyCode::Esc => self.step = OnboardStep::Task,
            _ => {}
        }
    }

    fn handle_add_more(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.add_more_selected = (self.add_more_selected + 1).min(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.add_more_selected = self.add_more_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.add_more_selected == 0 {
                    // Yes, add another worker
                    self.reset_agent_fields();
                    self.step = OnboardStep::Tool;
                } else {
                    // No, done adding -- configure security
                    self.step = OnboardStep::SecurityPreset;
                }
            }
            KeyCode::Esc => {
                // Same as "No"
                self.step = OnboardStep::SecurityPreset;
            }
            _ => {}
        }
    }

    fn handle_security_preset(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.security_preset_selected =
                    (self.security_preset_selected + 1).min(SecurityPreset::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.security_preset_selected = self.security_preset_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let preset = self.selected_security_preset();
                model::apply_preset(&mut self.security_actions, preset);

                if preset == SecurityPreset::Custom {
                    self.security_action_selected = 0;
                    self.step = OnboardStep::SecurityDetail;
                } else {
                    self.step = OnboardStep::MonitoringInfo;
                }
            }
            KeyCode::Esc => {
                if self.is_multi_agent() {
                    self.step = OnboardStep::AddMore;
                } else {
                    self.step = OnboardStep::RestartPolicy;
                }
            }
            _ => {}
        }
    }

    fn handle_security_detail(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if self.security_action_selected < self.security_actions.len() - 1 {
                    self.security_action_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.security_action_selected = self.security_action_selected.saturating_sub(1);
            }
            KeyCode::Char(' ') => {
                // Toggle allow/deny (skip infrastructure actions)
                let idx = self.security_action_selected;
                if !self.security_actions[idx].meta.infrastructure {
                    self.security_actions[idx].permission =
                        match &self.security_actions[idx].permission {
                            ActionPermission::Allow | ActionPermission::Scoped(_) => {
                                ActionPermission::Deny
                            }
                            ActionPermission::Deny => ActionPermission::Allow,
                        };
                }
            }
            KeyCode::Enter | KeyCode::Tab => {
                self.step = OnboardStep::MonitoringInfo;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::SecurityPreset;
            }
            _ => {}
        }
    }

    fn handle_monitoring_info(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::SecurityPreset;
            }
            _ => {}
        }
    }

    /// Map the selected preset index to a `SecurityPreset` enum.
    pub fn selected_security_preset(&self) -> SecurityPreset {
        SecurityPreset::ALL
            .get(self.security_preset_selected)
            .copied()
            .unwrap_or(SecurityPreset::ObserveOnly)
    }

    /// Map the selected preset to the `SecurityPresetKind` for daemon config.
    fn selected_security_preset_kind(&self) -> SecurityPresetKind {
        match self.selected_security_preset() {
            SecurityPreset::ObserveOnly => SecurityPresetKind::ObserveOnly,
            SecurityPreset::ReadOnly => SecurityPresetKind::ReadOnly,
            SecurityPreset::FullLockdown => SecurityPresetKind::FullLockdown,
            SecurityPreset::Custom => SecurityPresetKind::Custom,
        }
    }

    fn handle_telegram_offer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.telegram_offer_selected = (self.telegram_offer_selected + 1).min(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.telegram_offer_selected = self.telegram_offer_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.telegram_offer_selected == 0 {
                    // Yes
                    self.telegram_token_cursor = self.telegram_token.len();
                    self.step = OnboardStep::TelegramToken;
                } else {
                    // No
                    self.step = OnboardStep::Summary;
                }
            }
            KeyCode::Esc => {
                self.step = OnboardStep::MonitoringInfo;
            }
            _ => {}
        }
    }

    fn handle_telegram_progress(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                // Cancel and go back
                self.telegram_status = TelegramStatus::Idle;
                self.telegram_evt_rx = None;
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Enter => {
                // If complete or failed, advance/retry
                match &self.telegram_status {
                    TelegramStatus::Complete { .. } => {
                        self.step = OnboardStep::Summary;
                    }
                    TelegramStatus::Failed(_) => {
                        // Go back to token input to retry
                        self.telegram_status = TelegramStatus::Idle;
                        self.step = OnboardStep::TelegramToken;
                    }
                    _ => {} // Waiting -- do nothing
                }
            }
            _ => {}
        }
    }

    fn handle_summary(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                self.step = OnboardStep::Done;
                self.running = false;
            }
            KeyCode::Char('d') => {
                // Toggle start daemon
                self.start_daemon = !self.start_daemon;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::TelegramOffer;
            }
            KeyCode::Char('q') | KeyCode::Char('n') => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    /// Generic text input handler for fields that don't need special Enter logic.
    fn handle_text(&mut self, key: KeyEvent, field: TextField) {
        match key.code {
            KeyCode::Enter => {
                match field {
                    TextField::FleetGoal => {
                        // Fleet goal is optional -- allow empty
                        if self.workflow_choice() == WorkflowChoice::Orchestrated {
                            self.configuring_orchestrator = true;
                            self.name = "orchestrator".into();
                            self.name_cursor = self.name.len();
                        } else {
                            self.configuring_orchestrator = false;
                        }
                        self.step = OnboardStep::Tool;
                    }
                    TextField::CustomCommand => {
                        if self.custom_command.trim().is_empty() {
                            return; // Don't advance with empty command
                        }
                        self.name_cursor = self.name.len();
                        self.step = OnboardStep::Name;
                    }
                    TextField::Task => {
                        self.step = OnboardStep::RestartPolicy;
                    }
                    TextField::BacklogPath => {
                        self.review_interval_cursor = self.review_interval.len();
                        self.step = OnboardStep::OrchestratorInterval;
                    }
                    TextField::ReviewInterval => {
                        // Save orchestrator and start first worker
                        self.save_orchestrator();
                        self.reset_agent_fields();
                        self.step = OnboardStep::Tool;
                    }
                    TextField::TelegramToken => {
                        if self.telegram_token.trim().is_empty() {
                            return;
                        }
                        self.start_telegram_validation();
                        self.step = OnboardStep::TelegramProgress;
                    }
                    _ => {}
                }
            }
            KeyCode::Esc => match field {
                TextField::FleetGoal => self.step = OnboardStep::Workflow,
                TextField::CustomCommand => self.step = OnboardStep::Tool,
                TextField::Task => self.step = OnboardStep::WorkingDir,
                TextField::BacklogPath => self.step = OnboardStep::WorkingDir,
                TextField::ReviewInterval => self.step = OnboardStep::OrchestratorBacklog,
                TextField::TelegramToken => {
                    self.step = OnboardStep::TelegramOffer;
                }
                _ => {}
            },
            _ => self.edit_text(key, field),
        }
    }

    /// Apply a key to a text field (character insert, backspace, cursor movement).
    fn edit_text(&mut self, key: KeyEvent, field: TextField) {
        let (text, cursor) = match field {
            TextField::FleetGoal => (&mut self.fleet_goal, &mut self.fleet_goal_cursor),
            TextField::CustomCommand => (&mut self.custom_command, &mut self.custom_cursor),
            TextField::Name => (&mut self.name, &mut self.name_cursor),
            TextField::WorkingDir => (&mut self.working_dir, &mut self.working_dir_cursor),
            TextField::Task => (&mut self.task, &mut self.task_cursor),
            TextField::BacklogPath => (&mut self.backlog_path, &mut self.backlog_path_cursor),
            TextField::ReviewInterval => {
                (&mut self.review_interval, &mut self.review_interval_cursor)
            }
            TextField::TelegramToken => (&mut self.telegram_token, &mut self.telegram_token_cursor),
        };

        match key.code {
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => *cursor = 0,
                'e' => *cursor = text.len(),
                'u' => {
                    text.drain(..*cursor);
                    *cursor = 0;
                }
                'w' => {
                    if *cursor > 0 {
                        let new_pos = delete_word_backward_pos(text, *cursor);
                        text.drain(new_pos..*cursor);
                        *cursor = new_pos;
                    }
                }
                _ => {}
            },
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
    }

    /// Launch the Telegram background worker.
    fn start_telegram_validation(&mut self) {
        let token = self.telegram_token.trim().to_string();
        self.telegram_status = TelegramStatus::ValidatingToken;
        self.telegram_started_at = Some(Instant::now());

        let (evt_tx, evt_rx) = mpsc::channel::<TelegramEvent>();
        self.telegram_evt_rx = Some(evt_rx);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = evt_tx.send(TelegramEvent::Error(format!(
                        "Failed to create runtime: {e}"
                    )));
                    return;
                }
            };

            rt.block_on(async move {
                run_telegram_worker(token, evt_tx).await;
            });
        });
    }
}

/// Which text field is being edited.
#[derive(Debug, Clone, Copy)]
enum TextField {
    FleetGoal,
    CustomCommand,
    Name,
    WorkingDir,
    Task,
    BacklogPath,
    ReviewInterval,
    TelegramToken,
}

/// Run the Telegram validation and chat discovery flow.
async fn run_telegram_worker(token: String, tx: mpsc::Sender<TelegramEvent>) {
    use aegis_channel::telegram::api::TelegramApi;

    let api = TelegramApi::new(&token);

    // Validate token
    let user = match api.get_me().await {
        Ok(u) => u,
        Err(e) => {
            let _ = tx.send(TelegramEvent::TokenInvalid(e.to_string()));
            return;
        }
    };

    let bot_username = user.username.unwrap_or_else(|| "bot".into());
    let _ = tx.send(TelegramEvent::TokenValid {
        bot_username: bot_username.clone(),
    });

    // Discover chat ID (use poll_for_chat_id to avoid println in raw mode)
    let chat_id = match crate::commands::telegram::poll_for_chat_id(&api, 60).await {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.send(TelegramEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(TelegramEvent::ChatDiscovered { chat_id });

    // Send confirmation
    let msg =
        format!("Aegis connected! This chat will receive agent notifications.\nChat ID: {chat_id}");
    match api.send_message(chat_id, &msg, None, None, false).await {
        Ok(_) => {
            let _ = tx.send(TelegramEvent::ConfirmationSent);
        }
        Err(e) => {
            let _ = tx.send(TelegramEvent::Error(format!(
                "Failed to send confirmation: {e}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn initial_state() {
        let app = OnboardApp::new();
        assert_eq!(app.step, OnboardStep::Welcome);
        assert!(app.running);
        assert!(app.start_daemon);
        assert_eq!(app.workflow_selected, 0);
        assert!(app.completed_agents.is_empty());
    }

    #[test]
    fn welcome_enter_advances_to_workflow() {
        let mut app = OnboardApp::new();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Workflow);
    }

    #[test]
    fn welcome_esc_cancels() {
        let mut app = OnboardApp::new();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn workflow_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Workflow;
        assert_eq!(app.workflow_selected, 0);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.workflow_selected, 1);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.workflow_selected, 2);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.workflow_selected, 2); // clamped
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.workflow_selected, 1);
    }

    #[test]
    fn workflow_solo_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Workflow;
        app.workflow_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(!app.configuring_orchestrator);
    }

    #[test]
    fn workflow_team_goes_to_fleet_goal() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Workflow;
        app.workflow_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::FleetGoal);
    }

    #[test]
    fn workflow_orchestrated_goes_to_fleet_goal() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Workflow;
        app.workflow_selected = 2;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::FleetGoal);
    }

    #[test]
    fn workflow_esc_goes_to_welcome() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Workflow;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Welcome);
    }

    #[test]
    fn fleet_goal_orchestrated_starts_orchestrator() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::FleetGoal;
        app.workflow_selected = 2;
        app.fleet_goal = "Build a chess app".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(app.configuring_orchestrator);
        assert_eq!(app.name, "orchestrator");
    }

    #[test]
    fn fleet_goal_team_starts_worker() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::FleetGoal;
        app.workflow_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(!app.configuring_orchestrator);
    }

    #[test]
    fn fleet_goal_esc_goes_to_workflow() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::FleetGoal;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Workflow);
    }

    #[test]
    fn tool_jk_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        assert_eq!(app.tool_selected, 0);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.tool_selected, 1);
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0);
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.tool_selected, 0);
    }

    #[test]
    fn tool_enter_advances_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.tool_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn tool_enter_custom_goes_to_custom_command() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.tool_selected = ToolChoice::ALL
            .iter()
            .position(|t| *t == ToolChoice::Custom)
            .unwrap();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn tool_esc_solo_goes_to_workflow() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.workflow_selected = 0;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Workflow);
    }

    #[test]
    fn tool_esc_orchestrator_goes_to_fleet_goal() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Tool;
        app.workflow_selected = 2;
        app.configuring_orchestrator = true;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::FleetGoal);
    }

    #[test]
    fn custom_command_enter_empty_does_not_advance() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.custom_command.clear();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn custom_command_enter_advances_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.custom_command = "/usr/bin/my-tool".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn custom_command_esc_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::CustomCommand;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn name_typing() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name.clear();
        app.name_cursor = 0;
        app.handle_key(press(KeyCode::Char('t')));
        app.handle_key(press(KeyCode::Char('e')));
        app.handle_key(press(KeyCode::Char('s')));
        app.handle_key(press(KeyCode::Char('t')));
        assert_eq!(app.name, "test");
        assert_eq!(app.name_cursor, 4);
    }

    #[test]
    fn name_cursor_movement() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "hello".into();
        app.name_cursor = 5;
        app.handle_key(press(KeyCode::Left));
        assert_eq!(app.name_cursor, 4);
        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.name_cursor, 0);
        app.handle_key(press(KeyCode::End));
        assert_eq!(app.name_cursor, 5);
    }

    #[test]
    fn name_backspace() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "test".into();
        app.name_cursor = 4;
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes");
        app.name_cursor = 0;
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.name, "tes");
    }

    #[test]
    fn name_empty_does_not_advance() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "  ".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);
        assert!(app.name_error.is_some());
    }

    #[test]
    fn name_enter_advances_to_working_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.name = "my-agent".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);
        assert!(app.name_error.is_none());
    }

    #[test]
    fn name_esc_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn name_esc_goes_to_custom_if_custom_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Name;
        app.tool_selected = ToolChoice::ALL
            .iter()
            .position(|t| *t == ToolChoice::Custom)
            .unwrap();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::CustomCommand);
    }

    #[test]
    fn working_dir_enter_with_valid_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Task);
    }

    #[test]
    fn working_dir_orchestrator_goes_to_backlog() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.configuring_orchestrator = true;
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::OrchestratorBacklog);
    }

    #[test]
    fn working_dir_enter_with_invalid_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.working_dir = "/nonexistent/path/unlikely".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);
        assert!(app.working_dir_error.is_some());
    }

    #[test]
    fn working_dir_esc_goes_to_name() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::WorkingDir;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Name);
    }

    #[test]
    fn task_enter_advances_to_restart() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Task;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::RestartPolicy);
    }

    #[test]
    fn task_esc_goes_to_working_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Task;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::WorkingDir);
    }

    #[test]
    fn backlog_enter_advances_to_interval() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::OrchestratorBacklog;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::OrchestratorInterval);
    }

    #[test]
    fn backlog_esc_goes_to_working_dir() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::OrchestratorBacklog;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::WorkingDir);
    }

    #[test]
    fn interval_enter_saves_orchestrator() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::OrchestratorInterval;
        app.workflow_selected = 2;
        app.configuring_orchestrator = true;
        app.name = "orchestrator".into();
        app.working_dir = "/tmp".into();
        app.review_interval = "300".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(!app.configuring_orchestrator);
        assert_eq!(app.completed_agents.len(), 1);
        assert!(app.completed_agents[0].orchestrator.is_some());
    }

    #[test]
    fn interval_esc_goes_to_backlog() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::OrchestratorInterval;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::OrchestratorBacklog);
    }

    #[test]
    fn restart_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        assert_eq!(app.restart_selected, 0);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 1);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 2);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.restart_selected, 2);
    }

    #[test]
    fn restart_solo_goes_to_security_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        app.workflow_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityPreset);
    }

    #[test]
    fn restart_multi_agent_saves_and_goes_to_add_more() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        app.workflow_selected = 1;
        app.name = "worker-1".into();
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::AddMore);
        assert_eq!(app.completed_agents.len(), 1);
    }

    #[test]
    fn restart_esc_goes_to_task() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::RestartPolicy;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Task);
    }

    #[test]
    fn add_more_yes_resets_and_goes_to_tool() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::AddMore;
        app.workflow_selected = 1;
        app.add_more_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
    }

    #[test]
    fn add_more_no_goes_to_security_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::AddMore;
        app.add_more_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityPreset);
    }

    #[test]
    fn add_more_esc_goes_to_security_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::AddMore;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::SecurityPreset);
    }

    #[test]
    fn security_preset_navigation() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityPreset;
        assert_eq!(app.security_preset_selected, 0);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.security_preset_selected, 1);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.security_preset_selected, 2);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.security_preset_selected, 3);
        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.security_preset_selected, 3); // clamped
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.security_preset_selected, 2);
    }

    #[test]
    fn security_preset_observe_skips_detail() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityPreset;
        app.security_preset_selected = 0; // ObserveOnly
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);
    }

    #[test]
    fn security_preset_custom_goes_to_detail() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityPreset;
        app.security_preset_selected = 3; // Custom
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityDetail);
    }

    #[test]
    fn security_preset_esc_solo_goes_to_restart() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityPreset;
        app.workflow_selected = 0;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::RestartPolicy);
    }

    #[test]
    fn security_preset_esc_multi_goes_to_add_more() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityPreset;
        app.workflow_selected = 1;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::AddMore);
    }

    #[test]
    fn security_detail_toggle() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityDetail;
        // First non-infrastructure action (FileRead) starts as Allow
        app.security_action_selected = 0;
        assert_eq!(app.security_actions[0].permission, ActionPermission::Allow);
        app.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(app.security_actions[0].permission, ActionPermission::Deny);
        app.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(app.security_actions[0].permission, ActionPermission::Allow);
    }

    #[test]
    fn security_detail_infrastructure_cannot_toggle() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityDetail;
        // ProcessSpawn (index 7) is infrastructure
        app.security_action_selected = 7;
        let before = app.security_actions[7].permission.clone();
        app.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(app.security_actions[7].permission, before);
    }

    #[test]
    fn security_detail_enter_goes_to_monitoring() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityDetail;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);
    }

    #[test]
    fn security_detail_esc_goes_to_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::SecurityDetail;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::SecurityPreset);
    }

    #[test]
    fn monitoring_info_enter_goes_to_telegram() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::MonitoringInfo;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);
    }

    #[test]
    fn monitoring_info_esc_goes_to_security_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::MonitoringInfo;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::SecurityPreset);
    }

    #[test]
    fn result_has_security_preset() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Done;
        app.workflow_selected = 0;
        app.name = "test".into();
        app.working_dir = "/tmp".into();
        app.security_preset_selected = 1; // ReadOnly
        model::apply_preset(&mut app.security_actions, SecurityPreset::ReadOnly);

        let result = app.result();
        assert_eq!(result.security_preset, SecurityPresetKind::ReadOnly);
        assert!(result.policy_text.is_some());
        assert!(result.security_isolation.is_some());
    }

    #[test]
    fn result_observe_only_has_no_policy() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Done;
        app.workflow_selected = 0;
        app.name = "test".into();
        app.working_dir = "/tmp".into();
        app.security_preset_selected = 0; // ObserveOnly

        let result = app.result();
        assert_eq!(result.security_preset, SecurityPresetKind::ObserveOnly);
        assert!(result.policy_text.is_none());
        assert!(result.security_isolation.is_none());
    }

    #[test]
    fn telegram_offer_no_goes_to_summary() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.telegram_offer_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);
    }

    #[test]
    fn telegram_offer_yes_goes_to_token() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.telegram_offer_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramToken);
    }

    #[test]
    fn telegram_offer_esc_goes_to_monitoring_info() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::TelegramOffer;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);
    }

    #[test]
    fn summary_enter_completes() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.name = "test".into();
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    #[test]
    fn summary_esc_goes_to_telegram_offer() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::TelegramOffer);
    }

    #[test]
    fn summary_q_cancels() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        app.handle_key(press(KeyCode::Char('q')));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn summary_d_toggles_daemon() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Summary;
        assert!(app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(!app.start_daemon);
        app.handle_key(press(KeyCode::Char('d')));
        assert!(app.start_daemon);
    }

    #[test]
    fn result_cancelled() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Cancelled;
        let result = app.result();
        assert!(result.cancelled);
        assert!(result.agents.is_empty());
    }

    #[test]
    fn result_solo_builds_single_agent() {
        let mut app = OnboardApp::new();
        app.step = OnboardStep::Done;
        app.workflow_selected = 0;
        app.tool_selected = 0;
        app.name = "my-agent".into();
        app.working_dir = "/tmp/project".into();
        app.task = "Build it".into();
        app.restart_selected = 0;

        let result = app.result();
        assert!(!result.cancelled);
        assert_eq!(result.agents.len(), 1);
        assert_eq!(result.agents[0].name, "my-agent");
        assert!(matches!(
            result.agents[0].tool,
            AgentToolConfig::ClaudeCode { .. }
        ));
        assert_eq!(result.agents[0].task, Some("Build it".into()));
        assert!(result.fleet_goal.is_none());
        assert!(result.start_daemon);
    }

    #[test]
    fn full_solo_flow_skip_telegram() {
        let mut app = OnboardApp::new();

        // Welcome -> Workflow
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Workflow);

        // Workflow (Solo) -> Tool
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);

        // Tool -> Name
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Name);

        // Name -> WorkingDir
        app.name = "test-agent".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::WorkingDir);

        // WorkingDir -> Task
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Task);

        // Task -> RestartPolicy
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::RestartPolicy);

        // RestartPolicy -> SecurityPreset
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityPreset);

        // SecurityPreset (ObserveOnly) -> MonitoringInfo
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);

        // MonitoringInfo -> TelegramOffer
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);

        // TelegramOffer (No) -> Summary
        app.telegram_offer_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);

        // Summary -> Done
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);
        assert!(!app.running);
    }

    #[test]
    fn full_orchestrated_flow() {
        let mut app = OnboardApp::new();

        // Welcome -> Workflow
        app.handle_key(press(KeyCode::Enter));

        // Select Orchestrated
        app.workflow_selected = 2;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::FleetGoal);

        // Fleet Goal
        app.fleet_goal = "Build chess app".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(app.configuring_orchestrator);
        assert_eq!(app.name, "orchestrator");

        // Orchestrator: Tool -> Name -> WorkDir -> Backlog -> Interval
        app.handle_key(press(KeyCode::Enter)); // Tool
        assert_eq!(app.step, OnboardStep::Name);
        app.handle_key(press(KeyCode::Enter)); // Name = "orchestrator"
        assert_eq!(app.step, OnboardStep::WorkingDir);
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter)); // WorkDir
        assert_eq!(app.step, OnboardStep::OrchestratorBacklog);
        app.handle_key(press(KeyCode::Enter)); // Backlog (empty = skip)
        assert_eq!(app.step, OnboardStep::OrchestratorInterval);
        app.handle_key(press(KeyCode::Enter)); // Interval (default 300)
        assert_eq!(app.step, OnboardStep::Tool);
        assert!(!app.configuring_orchestrator);
        assert_eq!(app.completed_agents.len(), 1);

        // Worker: Tool -> Name -> WorkDir -> Task -> Restart
        app.handle_key(press(KeyCode::Enter)); // Tool
        app.name = "frontend".into();
        app.handle_key(press(KeyCode::Enter)); // Name
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter)); // WorkDir
        assert_eq!(app.step, OnboardStep::Task);
        app.task = "Build the UI".into();
        app.handle_key(press(KeyCode::Enter)); // Task
        assert_eq!(app.step, OnboardStep::RestartPolicy);
        app.handle_key(press(KeyCode::Enter)); // Restart
        assert_eq!(app.step, OnboardStep::AddMore);
        assert_eq!(app.completed_agents.len(), 2);

        // No more agents -> SecurityPreset
        app.add_more_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityPreset);

        // SecurityPreset (ObserveOnly) -> MonitoringInfo -> TelegramOffer
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);

        // Skip telegram -> Summary -> Done
        app.telegram_offer_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Summary);
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Done);

        let result = app.result();
        assert!(!result.cancelled);
        assert_eq!(result.fleet_goal, Some("Build chess app".into()));
        assert_eq!(result.agents.len(), 2);
        assert!(result.agents[0].orchestrator.is_some());
        assert_eq!(result.agents[0].name, "orchestrator");
        assert!(result.agents[1].orchestrator.is_none());
        assert_eq!(result.agents[1].name, "frontend");
    }

    #[test]
    fn full_team_flow_two_workers() {
        let mut app = OnboardApp::new();

        // Welcome -> Workflow -> Team -> FleetGoal
        app.handle_key(press(KeyCode::Enter));
        app.workflow_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::FleetGoal);
        app.fleet_goal = "Ship v1".into();
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);

        // Worker 1
        app.handle_key(press(KeyCode::Enter)); // Tool
        app.name = "backend".into();
        app.handle_key(press(KeyCode::Enter)); // Name
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter)); // WorkDir
        app.handle_key(press(KeyCode::Enter)); // Task (empty)
        app.handle_key(press(KeyCode::Enter)); // Restart
        assert_eq!(app.step, OnboardStep::AddMore);
        assert_eq!(app.completed_agents.len(), 1);

        // Yes, add another
        app.add_more_selected = 0;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Tool);

        // Worker 2
        app.handle_key(press(KeyCode::Enter)); // Tool
        app.name = "frontend".into();
        app.handle_key(press(KeyCode::Enter)); // Name
        app.working_dir = "/tmp".into();
        app.handle_key(press(KeyCode::Enter)); // WorkDir
        app.handle_key(press(KeyCode::Enter)); // Task
        app.handle_key(press(KeyCode::Enter)); // Restart
        assert_eq!(app.step, OnboardStep::AddMore);
        assert_eq!(app.completed_agents.len(), 2);

        // Done adding -> SecurityPreset
        app.add_more_selected = 1;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::SecurityPreset);

        // SecurityPreset -> MonitoringInfo -> TelegramOffer
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::MonitoringInfo);
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::TelegramOffer);

        let result = app.result();
        assert_eq!(result.fleet_goal, Some("Ship v1".into()));
        assert_eq!(result.agents.len(), 2);
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn ctrl_c_cancels_from_welcome() {
        let mut app = OnboardApp::new();
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_cancels_from_any_step() {
        for step in [
            OnboardStep::Workflow,
            OnboardStep::FleetGoal,
            OnboardStep::Tool,
            OnboardStep::Name,
            OnboardStep::WorkingDir,
            OnboardStep::Task,
            OnboardStep::RestartPolicy,
            OnboardStep::SecurityPreset,
            OnboardStep::SecurityDetail,
            OnboardStep::MonitoringInfo,
            OnboardStep::OrchestratorBacklog,
            OnboardStep::OrchestratorInterval,
            OnboardStep::AddMore,
            OnboardStep::TelegramOffer,
            OnboardStep::Summary,
        ] {
            let mut app = OnboardApp::new();
            app.step = step;
            app.handle_key(ctrl_c());
            assert_eq!(
                app.step,
                OnboardStep::Cancelled,
                "Ctrl+C should cancel at {:?}",
                step
            );
            assert!(!app.running);
        }
    }
}
