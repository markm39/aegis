//! Onboarding wizard state machine.
//!
//! A minimal 3-step wizard: Welcome (environment scan) -> ProviderSelection
//! (pick an LLM provider) -> Done (write config, start daemon).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::daemon::{
    DaemonConfig, DaemonControlConfig, DashboardConfig, PersistenceConfig,
};

// ---------------------------------------------------------------------------
// Step enum
// ---------------------------------------------------------------------------

/// Steps in the onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardStep {
    /// Environment scan results.
    Welcome,
    /// Pick an LLM provider.
    ProviderSelection,
    /// Completed successfully.
    Done,
    /// Cancelled by user.
    Cancelled,
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Environment scan results.
#[derive(Debug, Clone)]
pub struct EnvScanResult {
    pub api_keys: Vec<DetectedProvider>,
    pub ollama_running: bool,
    pub aegis_dir_ok: bool,
    pub aegis_dir_path: String,
}

/// A detected API key provider.
#[derive(Debug, Clone)]
pub struct DetectedProvider {
    pub env_var: &'static str,
    pub label: &'static str,
    pub default_model: &'static str,
    pub present: bool,
}

/// Result returned after the wizard completes.
pub struct OnboardResult {
    pub cancelled: bool,
}

// ---------------------------------------------------------------------------
// Main state
// ---------------------------------------------------------------------------

/// The onboarding wizard state.
pub struct OnboardApp {
    /// Current step.
    pub step: OnboardStep,
    /// Whether the event loop should keep running.
    pub running: bool,
    /// Environment scan results.
    pub env_scan: EnvScanResult,
    /// Index into the full provider list (api_keys + ollama).
    pub provider_selected: usize,
    /// Error message shown when user tries to select unavailable provider.
    pub selection_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Environment scan
// ---------------------------------------------------------------------------

/// Returns the full list of providers, including Ollama.
pub fn all_providers(scan: &EnvScanResult) -> Vec<DetectedProvider> {
    let mut providers = scan.api_keys.clone();
    providers.push(DetectedProvider {
        env_var: "localhost:11434",
        label: "Ollama",
        default_model: "llama3.2",
        present: scan.ollama_running,
    });
    providers
}

fn scan_environment() -> EnvScanResult {
    let api_keys = vec![
        DetectedProvider {
            env_var: "ANTHROPIC_API_KEY",
            label: "Anthropic",
            default_model: "claude-sonnet-4-20250514",
            present: std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
        DetectedProvider {
            env_var: "OPENAI_API_KEY",
            label: "OpenAI",
            default_model: "gpt-4o",
            present: std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
        DetectedProvider {
            env_var: "GOOGLE_API_KEY",
            label: "Google Gemini",
            default_model: "gemini-2.0-flash",
            present: std::env::var("GOOGLE_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some()
                || std::env::var("GEMINI_API_KEY")
                    .ok()
                    .filter(|k| !k.is_empty())
                    .is_some(),
        },
        DetectedProvider {
            env_var: "OPENROUTER_API_KEY",
            label: "OpenRouter",
            default_model: "openrouter/auto",
            present: std::env::var("OPENROUTER_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .is_some(),
        },
    ];

    let ollama_running = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:11434".parse().unwrap(),
        std::time::Duration::from_millis(200),
    )
    .is_ok();

    let (aegis_dir_ok, aegis_dir_path) = match crate::commands::init::ensure_aegis_dir() {
        Ok(p) => (true, p.display().to_string()),
        Err(_) => (false, "~/.aegis".into()),
    };

    EnvScanResult {
        api_keys,
        ollama_running,
        aegis_dir_ok,
        aegis_dir_path,
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl OnboardApp {
    /// Create a new wizard with sensible defaults.
    pub fn new() -> Self {
        let env_scan = scan_environment();

        // Pre-select first available provider.
        let providers = all_providers(&env_scan);
        let provider_selected = providers
            .iter()
            .position(|p| p.present)
            .unwrap_or(0);

        Self {
            step: OnboardStep::Welcome,
            running: true,
            env_scan,
            provider_selected,
            selection_error: None,
        }
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Progress label for the title bar.
    pub fn progress_text(&self) -> String {
        match self.step {
            OnboardStep::Welcome => "Environment".into(),
            OnboardStep::ProviderSelection => "Provider".into(),
            OnboardStep::Done | OnboardStep::Cancelled => String::new(),
        }
    }

    /// Build the result from current state.
    pub fn result(&self) -> OnboardResult {
        OnboardResult {
            cancelled: self.step == OnboardStep::Cancelled,
        }
    }

    // -----------------------------------------------------------------------
    // Key handling
    // -----------------------------------------------------------------------

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always cancels.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.step = OnboardStep::Cancelled;
            self.running = false;
            return;
        }

        match self.step {
            OnboardStep::Welcome => self.handle_welcome(key),
            OnboardStep::ProviderSelection => self.handle_provider_selection(key),
            OnboardStep::Done | OnboardStep::Cancelled => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step handlers
    // -----------------------------------------------------------------------

    fn handle_welcome(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.step = OnboardStep::ProviderSelection,
            KeyCode::Esc => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    fn handle_provider_selection(&mut self, key: KeyEvent) {
        let providers = all_providers(&self.env_scan);
        let count = providers.len();
        if count == 0 {
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.selection_error = None;
                self.provider_selected = (self.provider_selected + 1).min(count - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selection_error = None;
                self.provider_selected = self.provider_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let selected = &providers[self.provider_selected];
                if !selected.present {
                    self.selection_error = Some(format!(
                        "{} is not available. Set {} or start the service first.",
                        selected.label, selected.env_var,
                    ));
                    return;
                }
                self.selection_error = None;
                self.finalize_selection();
            }
            KeyCode::Esc => {
                self.selection_error = None;
                self.step = OnboardStep::Welcome;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Finalization
    // -----------------------------------------------------------------------

    /// Write config, start daemon, transition to Done.
    fn finalize_selection(&mut self) {
        let config = self.build_daemon_config();

        // Ensure daemon directory exists.
        let dir = aegis_types::daemon::daemon_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.selection_error = Some(format!("Failed to create dir: {e}"));
            return;
        }

        // Write daemon.toml.
        let config_path = aegis_types::daemon::daemon_config_path();
        match config.to_toml() {
            Ok(toml_str) => {
                if let Err(e) = std::fs::write(&config_path, &toml_str) {
                    self.selection_error = Some(format!("Failed to write config: {e}"));
                    return;
                }
            }
            Err(e) => {
                self.selection_error = Some(format!("Failed to serialize config: {e}"));
                return;
            }
        }

        // Start daemon.
        if let Err(e) = crate::commands::daemon::start_quiet() {
            self.selection_error = Some(format!("Daemon failed to start: {e:#}"));
            return;
        }

        self.step = OnboardStep::Done;
        self.running = false;
    }

    // -----------------------------------------------------------------------
    // Config building
    // -----------------------------------------------------------------------

    fn build_daemon_config(&self) -> DaemonConfig {
        let providers = all_providers(&self.env_scan);
        let selected = &providers[self.provider_selected];

        DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: DashboardConfig::default(),
            alerts: vec![],
            agents: vec![],
            channel: None,
            channel_routing: None,
            toolkit: Default::default(),
            memory: Default::default(),
            session_files: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: Default::default(),
            acp_server: None,
            default_model: Some(selected.default_model.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Create a test app with a known environment (Anthropic + OpenAI present).
    fn test_app() -> OnboardApp {
        let mut app = OnboardApp::new();
        // Reset all providers to not present, then enable specific ones.
        for p in &mut app.env_scan.api_keys {
            p.present = false;
        }
        app.env_scan.ollama_running = false;
        // Enable Anthropic (index 0) and OpenAI (index 1).
        app.env_scan.api_keys[0].present = true;
        app.env_scan.api_keys[1].present = true;
        app.provider_selected = 0;
        app
    }

    // -- scan_detects_anthropic_key --

    #[test]
    fn scan_detects_anthropic_key() {
        // The scan reads from environment. We can at least verify the structure
        // includes Anthropic as the first provider with the right env_var.
        let scan = scan_environment();
        assert_eq!(scan.api_keys[0].env_var, "ANTHROPIC_API_KEY");
        assert_eq!(scan.api_keys[0].label, "Anthropic");
        assert_eq!(scan.api_keys[0].default_model, "claude-sonnet-4-20250514");
    }

    // -- welcome_enter_goes_to_provider --

    #[test]
    fn welcome_enter_goes_to_provider() {
        let mut app = test_app();
        assert_eq!(app.step, OnboardStep::Welcome);
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ProviderSelection);
    }

    // -- provider_nav_jk --

    #[test]
    fn provider_nav_jk() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.provider_selected, 1);

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.provider_selected, 2);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.provider_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.provider_selected, 0);

        // Clamp at 0
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.provider_selected, 0);
    }

    #[test]
    fn provider_nav_arrows() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_selected = 0;

        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.provider_selected, 1);

        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.provider_selected, 0);
    }

    #[test]
    fn provider_nav_clamps_at_max() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        let count = all_providers(&app.env_scan).len();
        app.provider_selected = count - 1;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.provider_selected, count - 1);
    }

    // -- provider_select_available --

    #[test]
    fn provider_select_available() {
        // We cannot actually write config + start daemon in tests, so we
        // verify the build_daemon_config path instead. The finalize_selection
        // will fail on I/O, but we test the config building separately.
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_selected = 0; // Anthropic, which is present

        let providers = all_providers(&app.env_scan);
        assert!(providers[0].present);

        // Verify Enter on available provider attempts finalization
        // (it will fail because no daemon dir in test env, but it should
        // not show the "not available" error).
        app.handle_key(press(KeyCode::Enter));
        // Should have attempted finalization -- either Done or a filesystem error.
        // It should NOT be ProviderSelection with an "is not available" error.
        if app.step == OnboardStep::ProviderSelection {
            assert!(
                !app.selection_error
                    .as_ref()
                    .map(|e| e.contains("is not available"))
                    .unwrap_or(false),
                "Should not get 'not available' error for present provider"
            );
        }
    }

    // -- provider_select_unavailable --

    #[test]
    fn provider_select_unavailable() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        // Google Gemini is index 2 (not present in test_app)
        app.provider_selected = 2;

        let providers = all_providers(&app.env_scan);
        assert!(!providers[2].present);

        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ProviderSelection);
        assert!(app.selection_error.is_some());
        assert!(app
            .selection_error
            .as_ref()
            .unwrap()
            .contains("is not available"));
    }

    // -- esc_cancels --

    #[test]
    fn esc_cancels_from_welcome() {
        let mut app = test_app();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn esc_from_provider_goes_to_welcome() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Welcome);
        assert!(app.running);
    }

    #[test]
    fn ctrl_c_cancels_from_welcome() {
        let mut app = test_app();
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_cancels_from_provider() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    // -- build_config_sets_model --

    #[test]
    fn build_config_sets_model() {
        let mut app = test_app();
        // Select Anthropic (index 0)
        app.provider_selected = 0;
        let config = app.build_daemon_config();
        assert_eq!(
            config.default_model,
            Some("claude-sonnet-4-20250514".to_string())
        );
        assert!(config.agents.is_empty());

        // Select OpenAI (index 1)
        app.provider_selected = 1;
        let config = app.build_daemon_config();
        assert_eq!(config.default_model, Some("gpt-4o".to_string()));
    }

    #[test]
    fn build_config_sets_ollama_model() {
        let mut app = test_app();
        app.env_scan.ollama_running = true;
        // Ollama is last in the full list (after 4 API key providers)
        app.provider_selected = 4;
        let config = app.build_daemon_config();
        assert_eq!(config.default_model, Some("llama3.2".to_string()));
    }

    // -- progress_text --

    #[test]
    fn progress_text_for_each_step() {
        let mut app = test_app();

        app.step = OnboardStep::Welcome;
        assert_eq!(app.progress_text(), "Environment");

        app.step = OnboardStep::ProviderSelection;
        assert_eq!(app.progress_text(), "Provider");

        app.step = OnboardStep::Done;
        assert_eq!(app.progress_text(), "");

        app.step = OnboardStep::Cancelled;
        assert_eq!(app.progress_text(), "");
    }

    // -- result --

    #[test]
    fn result_cancelled_when_step_is_cancelled() {
        let mut app = test_app();
        app.step = OnboardStep::Cancelled;
        assert!(app.result().cancelled);
    }

    #[test]
    fn result_not_cancelled_when_step_is_done() {
        let mut app = test_app();
        app.step = OnboardStep::Done;
        assert!(!app.result().cancelled);
    }

    // -- navigation clears error --

    #[test]
    fn navigation_clears_selection_error() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.selection_error = Some("some error".into());

        app.handle_key(press(KeyCode::Char('j')));
        assert!(app.selection_error.is_none());
    }

    // -- initial state --

    #[test]
    fn initial_state() {
        let app = OnboardApp::new();
        assert_eq!(app.step, OnboardStep::Welcome);
        assert!(app.running);
        assert!(!app.env_scan.api_keys.is_empty());
        assert!(app.selection_error.is_none());
    }

    // -- all_providers includes ollama --

    #[test]
    fn all_providers_includes_ollama() {
        let app = test_app();
        let providers = all_providers(&app.env_scan);
        assert_eq!(providers.len(), 5); // 4 API + Ollama
        assert_eq!(providers[4].label, "Ollama");
    }
}
