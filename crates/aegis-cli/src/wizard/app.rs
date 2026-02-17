//! Wizard application state machine.
//!
//! Manages the current wizard step, handles keyboard input, and tracks
//! all user selections. Follows the same state machine pattern as
//! `aegis-monitor`'s `App`.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};

use aegis_types::IsolationConfig;

use super::model::{
    apply_preset, default_action_entries, ActionEntry, ActionPermission, ScopeRule,
    SecurityPreset, WizardResult,
};
use super::policy_gen;

/// The current step of the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    /// Text input for the configuration name.
    ConfigName,
    /// Select a security preset or go custom.
    SecurityPreset,
    /// Per-action allow/deny/scope configuration.
    ActionConfig,
    /// Edit scope rules for a specific action.
    ScopeEditor,
    /// Select the project directory.
    ProjectDir,
    /// Review and confirm.
    Summary,
    /// Wizard completed successfully.
    Done,
    /// User cancelled the wizard.
    Cancelled,
}

/// Wizard application state.
pub struct WizardApp {
    /// Current step.
    pub step: WizardStep,
    /// Whether the event loop should keep running.
    pub running: bool,

    // -- ConfigName --
    /// Text buffer for config name input.
    pub name_input: String,
    /// Cursor position in name input.
    pub name_cursor: usize,

    // -- SecurityPreset --
    /// Selected preset index.
    pub preset_selected: usize,
    /// Whether the user went through custom config (vs preset).
    pub used_custom: bool,

    // -- ActionConfig --
    /// Per-action configuration.
    pub actions: Vec<ActionEntry>,
    /// Selected action index.
    pub action_selected: usize,

    // -- ScopeEditor --
    /// Index of the action being scoped.
    pub scope_action_index: usize,
    /// Selected scope rule index.
    pub scope_selected: usize,
    /// Text buffer for adding a new scope rule.
    pub scope_input: String,
    /// Whether currently typing a new scope rule.
    pub scope_editing: bool,

    // -- ProjectDir --
    /// Available directory choices.
    pub dir_choices: Vec<(String, PathBuf)>,
    /// Selected directory index.
    pub dir_selected: usize,
    /// Text buffer for custom path input.
    pub dir_input: String,
    /// Whether currently typing a custom path.
    pub dir_editing: bool,

    // -- Result --
    /// Selected isolation config.
    pub isolation: IsolationConfig,
}

impl WizardApp {
    /// Create a new wizard with sensible defaults.
    pub fn new() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let default_name = cwd
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "my-project".to_string());

        let home_dir =
            std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"));

        let dir_choices = vec![
            (format!("Current directory: {}", cwd.display()), cwd),
            (
                format!("Home directory:    {}", home_dir.display()),
                home_dir,
            ),
            ("Custom path".to_string(), PathBuf::new()),
        ];

        Self {
            step: WizardStep::ConfigName,
            running: true,
            name_input: default_name.clone(),
            name_cursor: default_name.len(),
            preset_selected: 0,
            used_custom: false,
            actions: default_action_entries(),
            action_selected: 0,
            scope_action_index: 0,
            scope_selected: 0,
            scope_input: String::new(),
            scope_editing: false,
            dir_choices,
            dir_selected: 0,
            dir_input: String::new(),
            dir_editing: false,
            isolation: IsolationConfig::Process,
        }
    }

    /// Build the final wizard result.
    pub fn result(&self) -> WizardResult {
        let cancelled = matches!(self.step, WizardStep::Cancelled);
        let policy_text = if cancelled {
            String::new()
        } else {
            policy_gen::generate_policy(&self.actions)
        };

        let project_dir = if self.dir_selected < self.dir_choices.len() - 1 {
            self.dir_choices[self.dir_selected].1.clone()
        } else {
            PathBuf::from(&self.dir_input)
        };

        WizardResult {
            cancelled,
            name: self.name_input.clone(),
            policy_text,
            project_dir,
            isolation: self.isolation.clone(),
        }
    }

    /// Handle a key event, dispatching to the current step's handler.
    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.step {
            WizardStep::ConfigName => self.handle_config_name(key),
            WizardStep::SecurityPreset => self.handle_security_preset(key),
            WizardStep::ActionConfig => self.handle_action_config(key),
            WizardStep::ScopeEditor => self.handle_scope_editor(key),
            WizardStep::ProjectDir => self.handle_project_dir(key),
            WizardStep::Summary => self.handle_summary(key),
            WizardStep::Done | WizardStep::Cancelled => {}
        }
    }

    /// Total number of user-visible steps (for progress display).
    pub fn step_number(&self) -> (usize, usize) {
        let current = match self.step {
            WizardStep::ConfigName => 1,
            WizardStep::SecurityPreset => 2,
            WizardStep::ActionConfig => 3,
            WizardStep::ScopeEditor => 3, // sub-step of ActionConfig
            WizardStep::ProjectDir => 4,
            WizardStep::Summary => 5,
            WizardStep::Done | WizardStep::Cancelled => 5,
        };
        (current, 5)
    }

    // -- Step handlers --

    fn handle_config_name(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.step = WizardStep::Cancelled;
                self.running = false;
            }
            KeyCode::Enter => {
                if !self.name_input.trim().is_empty() {
                    self.step = WizardStep::SecurityPreset;
                }
            }
            KeyCode::Char(c) => {
                self.name_input.insert(self.name_cursor, c);
                self.name_cursor += 1;
            }
            KeyCode::Backspace => {
                if self.name_cursor > 0 {
                    self.name_cursor -= 1;
                    self.name_input.remove(self.name_cursor);
                }
            }
            KeyCode::Left => {
                self.name_cursor = self.name_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if self.name_cursor < self.name_input.len() {
                    self.name_cursor += 1;
                }
            }
            KeyCode::Home => {
                self.name_cursor = 0;
            }
            KeyCode::End => {
                self.name_cursor = self.name_input.len();
            }
            _ => {}
        }
    }

    fn handle_security_preset(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.step = WizardStep::ConfigName;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.preset_selected = self.preset_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.preset_selected < SecurityPreset::ALL.len() - 1 {
                    self.preset_selected += 1;
                }
            }
            KeyCode::Enter => {
                let preset = SecurityPreset::ALL[self.preset_selected];
                apply_preset(&mut self.actions, preset);

                if matches!(preset, SecurityPreset::Custom) {
                    self.used_custom = true;
                    self.step = WizardStep::ActionConfig;
                } else {
                    self.used_custom = false;
                    self.isolation = preset.isolation();
                    self.step = WizardStep::ProjectDir;
                }
            }
            _ => {}
        }
    }

    fn handle_action_config(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.step = WizardStep::SecurityPreset;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.action_selected = self.action_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.action_selected < self.actions.len() - 1 {
                    self.action_selected += 1;
                }
            }
            KeyCode::Char(' ') => {
                // Toggle allow/deny (skip infrastructure actions)
                let entry = &mut self.actions[self.action_selected];
                if !entry.meta.infrastructure {
                    entry.permission = match &entry.permission {
                        ActionPermission::Allow | ActionPermission::Scoped(_) => {
                            ActionPermission::Deny
                        }
                        ActionPermission::Deny => ActionPermission::Allow,
                    };
                }
            }
            KeyCode::Enter => {
                // Open scope editor for selected action (if allowed)
                let entry = &self.actions[self.action_selected];
                if !entry.meta.infrastructure
                    && !matches!(entry.permission, ActionPermission::Deny)
                {
                    self.scope_action_index = self.action_selected;
                    self.scope_selected = 0;
                    self.scope_input.clear();
                    self.scope_editing = false;
                    self.step = WizardStep::ScopeEditor;
                }
            }
            KeyCode::Tab => {
                // Advance to project dir
                self.update_isolation_from_actions();
                self.step = WizardStep::ProjectDir;
            }
            _ => {}
        }
    }

    fn handle_scope_editor(&mut self, key: KeyEvent) {
        let entry = &self.actions[self.scope_action_index];
        let is_network = entry.meta.action == "NetConnect";

        if self.scope_editing {
            match key.code {
                KeyCode::Esc => {
                    self.scope_editing = false;
                    self.scope_input.clear();
                }
                KeyCode::Enter => {
                    let text = self.scope_input.trim().to_string();
                    if !text.is_empty() {
                        let rule = if is_network {
                            parse_network_rule(&text)
                        } else {
                            ScopeRule::PathPattern(text)
                        };

                        let entry = &mut self.actions[self.scope_action_index];
                        match &mut entry.permission {
                            ActionPermission::Scoped(rules) => {
                                rules.push(rule);
                            }
                            ActionPermission::Allow => {
                                entry.permission = ActionPermission::Scoped(vec![rule]);
                            }
                            ActionPermission::Deny => {}
                        }
                    }
                    self.scope_editing = false;
                    self.scope_input.clear();
                }
                KeyCode::Char(c) => {
                    self.scope_input.push(c);
                }
                KeyCode::Backspace => {
                    self.scope_input.pop();
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.step = WizardStep::ActionConfig;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scope_selected = self.scope_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.current_scope_count();
                if len > 0 && self.scope_selected < len - 1 {
                    self.scope_selected += 1;
                }
            }
            KeyCode::Char('a') => {
                // Add new scope rule
                self.scope_editing = true;
                self.scope_input.clear();
            }
            KeyCode::Char('d') => {
                // Delete selected scope rule
                let entry = &mut self.actions[self.scope_action_index];
                if let ActionPermission::Scoped(rules) = &mut entry.permission {
                    if self.scope_selected < rules.len() {
                        rules.remove(self.scope_selected);
                        if self.scope_selected > 0 {
                            self.scope_selected -= 1;
                        }
                        if rules.is_empty() {
                            entry.permission = ActionPermission::Allow;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_project_dir(&mut self, key: KeyEvent) {
        if self.dir_editing {
            match key.code {
                KeyCode::Esc => {
                    self.dir_editing = false;
                    self.dir_input.clear();
                }
                KeyCode::Enter => {
                    if !self.dir_input.trim().is_empty() {
                        self.dir_editing = false;
                        self.step = WizardStep::Summary;
                    }
                }
                KeyCode::Char(c) => {
                    self.dir_input.push(c);
                }
                KeyCode::Backspace => {
                    self.dir_input.pop();
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                if self.used_custom {
                    self.step = WizardStep::ActionConfig;
                } else {
                    self.step = WizardStep::SecurityPreset;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.dir_selected = self.dir_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.dir_selected < self.dir_choices.len() - 1 {
                    self.dir_selected += 1;
                }
            }
            KeyCode::Enter => {
                let is_custom = self.dir_selected == self.dir_choices.len() - 1;
                if is_custom {
                    self.dir_editing = true;
                    self.dir_input.clear();
                } else {
                    self.step = WizardStep::Summary;
                }
            }
            _ => {}
        }
    }

    fn handle_summary(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.step = WizardStep::Cancelled;
                self.running = false;
            }
            KeyCode::Esc => {
                if self.used_custom {
                    self.step = WizardStep::ActionConfig;
                } else {
                    self.step = WizardStep::ProjectDir;
                }
            }
            KeyCode::Enter => {
                self.step = WizardStep::Done;
                self.running = false;
            }
            _ => {}
        }
    }

    // -- Helpers --

    fn current_scope_count(&self) -> usize {
        match &self.actions[self.scope_action_index].permission {
            ActionPermission::Scoped(rules) => rules.len(),
            _ => 0,
        }
    }

    fn update_isolation_from_actions(&mut self) {
        if policy_gen::needs_kernel_enforcement(&self.actions) {
            self.isolation = if cfg!(target_os = "macos") {
                IsolationConfig::Seatbelt {
                    profile_overrides: None,
                }
            } else {
                IsolationConfig::Process
            };
        } else {
            self.isolation = IsolationConfig::Process;
        }
    }
}

fn parse_network_rule(text: &str) -> ScopeRule {
    if let Some((host, port_str)) = text.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return ScopeRule::HostPort(host.to_string(), port);
        }
    }
    ScopeRule::Host(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: crossterm::event::KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn initial_step_is_config_name() {
        let app = WizardApp::new();
        assert_eq!(app.step, WizardStep::ConfigName);
        assert!(app.running);
    }

    #[test]
    fn config_name_enter_advances() {
        let mut app = WizardApp::new();
        // Default name is non-empty (CWD basename)
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::SecurityPreset);
    }

    #[test]
    fn config_name_esc_cancels() {
        let mut app = WizardApp::new();
        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.step, WizardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn config_name_typing() {
        let mut app = WizardApp::new();
        app.name_input.clear();
        app.name_cursor = 0;
        app.handle_key(make_key(KeyCode::Char('a')));
        app.handle_key(make_key(KeyCode::Char('b')));
        assert_eq!(app.name_input, "ab");
        assert_eq!(app.name_cursor, 2);

        app.handle_key(make_key(KeyCode::Backspace));
        assert_eq!(app.name_input, "a");
        assert_eq!(app.name_cursor, 1);
    }

    #[test]
    fn empty_name_does_not_advance() {
        let mut app = WizardApp::new();
        app.name_input.clear();
        app.name_cursor = 0;
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::ConfigName);
    }

    #[test]
    fn preset_navigation() {
        let mut app = WizardApp::new();
        app.step = WizardStep::SecurityPreset;
        assert_eq!(app.preset_selected, 0);

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.preset_selected, 1);

        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.preset_selected, 0);

        // Should not go below 0
        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.preset_selected, 0);
    }

    #[test]
    fn preset_enter_non_custom_goes_to_project_dir() {
        let mut app = WizardApp::new();
        app.step = WizardStep::SecurityPreset;
        app.preset_selected = 0; // ObserveOnly
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::ProjectDir);
        assert!(!app.used_custom);
    }

    #[test]
    fn preset_custom_goes_to_action_config() {
        let mut app = WizardApp::new();
        app.step = WizardStep::SecurityPreset;
        app.preset_selected = 3; // Custom
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::ActionConfig);
        assert!(app.used_custom);
    }

    #[test]
    fn action_config_toggle() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ActionConfig;
        app.action_selected = 1; // FileWrite

        let was_deny = matches!(app.actions[1].permission, ActionPermission::Deny);
        app.handle_key(make_key(KeyCode::Char(' ')));
        if was_deny {
            assert!(matches!(app.actions[1].permission, ActionPermission::Allow));
        } else {
            assert!(matches!(app.actions[1].permission, ActionPermission::Deny));
        }
    }

    #[test]
    fn infrastructure_cannot_be_toggled() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ActionConfig;
        // ProcessSpawn is infrastructure (index 7)
        app.action_selected = 7;
        assert!(app.actions[7].meta.infrastructure);
        app.handle_key(make_key(KeyCode::Char(' ')));
        // Should still be allowed
        assert!(matches!(app.actions[7].permission, ActionPermission::Allow));
    }

    #[test]
    fn action_config_tab_advances() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ActionConfig;
        app.handle_key(make_key(KeyCode::Tab));
        assert_eq!(app.step, WizardStep::ProjectDir);
    }

    #[test]
    fn action_config_enter_opens_scope_editor() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ActionConfig;
        app.action_selected = 0; // FileRead (allowed, not infra)
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::ScopeEditor);
    }

    #[test]
    fn action_config_enter_denied_stays() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ActionConfig;
        app.action_selected = 1; // FileWrite (denied by default)
        assert!(matches!(app.actions[1].permission, ActionPermission::Deny));
        app.handle_key(make_key(KeyCode::Enter));
        // Should stay in ActionConfig since action is denied
        assert_eq!(app.step, WizardStep::ActionConfig);
    }

    #[test]
    fn scope_editor_add_rule() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ScopeEditor;
        app.scope_action_index = 0; // FileRead

        // Press 'a' to start editing
        app.handle_key(make_key(KeyCode::Char('a')));
        assert!(app.scope_editing);

        // Type a path pattern
        for c in "/tmp/test/*".chars() {
            app.handle_key(make_key(KeyCode::Char(c)));
        }
        assert_eq!(app.scope_input, "/tmp/test/*");

        // Press Enter to add
        app.handle_key(make_key(KeyCode::Enter));
        assert!(!app.scope_editing);

        // Verify rule was added
        match &app.actions[0].permission {
            ActionPermission::Scoped(rules) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(
                    rules[0],
                    ScopeRule::PathPattern("/tmp/test/*".to_string())
                );
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    #[test]
    fn scope_editor_esc_returns() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ScopeEditor;
        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.step, WizardStep::ActionConfig);
    }

    #[test]
    fn project_dir_navigation() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ProjectDir;
        assert_eq!(app.dir_selected, 0);

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.dir_selected, 1);

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.dir_selected, 2);

        // Should not go past last
        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.dir_selected, 2);
    }

    #[test]
    fn project_dir_enter_non_custom_advances() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ProjectDir;
        app.dir_selected = 0;
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::Summary);
    }

    #[test]
    fn project_dir_enter_custom_starts_editing() {
        let mut app = WizardApp::new();
        app.step = WizardStep::ProjectDir;
        app.dir_selected = 2; // Custom path
        app.handle_key(make_key(KeyCode::Enter));
        assert!(app.dir_editing);
        assert_eq!(app.step, WizardStep::ProjectDir);
    }

    #[test]
    fn summary_enter_completes() {
        let mut app = WizardApp::new();
        app.step = WizardStep::Summary;
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.step, WizardStep::Done);
        assert!(!app.running);
    }

    #[test]
    fn summary_q_cancels() {
        let mut app = WizardApp::new();
        app.step = WizardStep::Summary;
        app.handle_key(make_key(KeyCode::Char('q')));
        assert_eq!(app.step, WizardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn summary_esc_goes_back() {
        let mut app = WizardApp::new();
        app.step = WizardStep::Summary;
        app.used_custom = true;
        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.step, WizardStep::ActionConfig);
    }

    #[test]
    fn parse_network_rule_host_only() {
        assert_eq!(
            parse_network_rule("api.openai.com"),
            ScopeRule::Host("api.openai.com".to_string())
        );
    }

    #[test]
    fn parse_network_rule_host_port() {
        assert_eq!(
            parse_network_rule("api.openai.com:443"),
            ScopeRule::HostPort("api.openai.com".to_string(), 443)
        );
    }

    #[test]
    fn parse_network_rule_invalid_port_treated_as_host() {
        assert_eq!(
            parse_network_rule("host:notaport"),
            ScopeRule::Host("host:notaport".to_string())
        );
    }

    #[test]
    fn step_numbers_are_consistent() {
        let mut app = WizardApp::new();
        let (n, total) = app.step_number();
        assert_eq!(n, 1);
        assert_eq!(total, 5);

        app.step = WizardStep::Summary;
        let (n, total) = app.step_number();
        assert_eq!(n, 5);
        assert_eq!(total, 5);
    }

    #[test]
    fn result_reflects_cancelled_state() {
        let mut app = WizardApp::new();
        app.step = WizardStep::Cancelled;
        let result = app.result();
        assert!(result.cancelled);
    }

    #[test]
    fn result_reflects_completed_state() {
        let mut app = WizardApp::new();
        app.name_input = "test-config".to_string();
        app.step = WizardStep::Done;
        let result = app.result();
        assert!(!result.cancelled);
        assert_eq!(result.name, "test-config");
    }
}
