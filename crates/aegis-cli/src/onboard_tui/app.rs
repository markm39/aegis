//! Onboarding wizard state machine.
//!
//! A 9-step wizard that guides users through full Aegis setup: config detection,
//! provider selection (25+ providers with manual API key entry), workspace config,
//! gateway config, channel selection, service installation, health check, skill
//! installation, and a finish screen.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_types::daemon::{DaemonConfig, DaemonControlConfig, DashboardConfig, PersistenceConfig};
use aegis_types::provider_auth::{
    auth_flows_for, has_multiple_auth_flows, needs_auth, AuthFlowKind,
};
use aegis_types::providers::{
    scan_providers, ApiType, DiscoveredModel, ProviderInfo, ProviderTier, ALL_PROVIDERS,
    discover_ollama_models, discover_openai_compat_models,
};
use aegis_types::CredentialStore;

use super::auth_flow::{self, AuthToken, AuthTokenType, DevicePollResult};

// ---------------------------------------------------------------------------
// Step enum
// ---------------------------------------------------------------------------

/// Steps in the onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardStep {
    /// Step 1: Check for existing configuration.
    ConfigDetection,
    /// Step 2: Select AI provider, model, and enter API key.
    ProviderSelection,
    /// Step 3: Workspace directory configuration.
    WorkspaceConfig,
    /// Step 4: Gateway / control server configuration.
    GatewayConfig,
    /// Step 5: Messaging channel selection.
    ChannelSelection,
    /// Step 6: Daemon service installation (launchd/systemd).
    ServiceInstall,
    /// Step 7: Health verification.
    HealthCheck,
    /// Step 8: Skill installation.
    SkillSelection,
    /// Step 9: Summary and finish.
    Finish,
    /// User cancelled.
    Cancelled,
}

impl OnboardStep {
    /// 1-based step number for display (used by tests and UI).
    #[allow(dead_code)]
    pub fn number(&self) -> usize {
        match self {
            Self::ConfigDetection => 1,
            Self::ProviderSelection => 2,
            Self::WorkspaceConfig => 3,
            Self::GatewayConfig => 4,
            Self::ChannelSelection => 5,
            Self::ServiceInstall => 6,
            Self::HealthCheck => 7,
            Self::SkillSelection => 8,
            Self::Finish => 9,
            Self::Cancelled => 0,
        }
    }

    /// Total number of wizard steps.
    #[allow(dead_code)]
    pub const TOTAL: usize = 9;
}

// ---------------------------------------------------------------------------
// Sub-step enums
// ---------------------------------------------------------------------------

/// Sub-steps within provider selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSubStep {
    /// Select a provider from the list.
    SelectProvider,
    /// Choose between multiple auth methods for this provider.
    SelectAuthMethod,
    /// Enter API key manually.
    EnterApiKey,
    /// Paste a setup token (e.g., `claude setup-token` output).
    SetupTokenInput,
    /// Show result of CLI token extraction attempt.
    CliExtractResult,
    /// Device flow in progress -- shows user code, polls for auth.
    DeviceFlowWaiting,
    /// PKCE browser flow in progress -- browser opened, waiting for callback.
    PkceBrowserWaiting,
    /// Select a model for the chosen provider.
    SelectModel,
}

/// What to do with existing configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    Keep,
    Modify,
    Reset,
}

impl ConfigAction {
    pub const ALL: [ConfigAction; 3] = [Self::Keep, Self::Modify, Self::Reset];

    pub fn label(&self) -> &'static str {
        match self {
            Self::Keep => "Keep existing configuration",
            Self::Modify => "Modify configuration",
            Self::Reset => "Reset and start fresh",
        }
    }
}

// ---------------------------------------------------------------------------
// Gateway config fields
// ---------------------------------------------------------------------------

/// Which field is currently active in gateway configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayField {
    Port,
    BindAddress,
    AuthToken,
}

impl GatewayField {
    #[allow(dead_code)]
    pub const ALL: [GatewayField; 3] = [Self::Port, Self::BindAddress, Self::AuthToken];
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// A provider entry for the wizard, combining static info with detection status.
#[derive(Debug, Clone)]
pub struct ProviderEntry {
    pub info: &'static ProviderInfo,
    pub available: bool,
    pub detection_label: &'static str,
}

/// A channel option for the wizard.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChannelEntry {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub selected: bool,
}

/// A skill entry for the wizard.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SkillEntry {
    pub name: String,
    pub description: String,
    pub category: String,
    pub selected: bool,
    pub installed: bool,
}

/// Health check result.
#[derive(Debug, Clone)]
pub struct HealthResult {
    pub label: String,
    pub passed: bool,
    pub message: String,
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
    // Core state
    pub step: OnboardStep,
    pub running: bool,
    pub error_message: Option<String>,

    // Step 1: Config Detection
    pub existing_config: bool,
    pub config_action_selected: usize,

    // Step 2: Provider Selection
    pub providers: Vec<ProviderEntry>,
    pub provider_selected: usize,
    pub provider_scroll_offset: usize,
    pub provider_search: String,
    pub provider_search_cursor: usize,
    pub provider_searching: bool,
    pub provider_sub_step: ProviderSubStep,
    pub model_selected: usize,
    pub model_manual_input: String,
    pub model_manual_cursor: usize,
    pub model_manual_active: bool,
    pub model_loading: bool,
    pub model_loading_error: Option<String>,
    pub discovered_models: Vec<DiscoveredModel>,
    pub api_key_input: String,
    pub api_key_cursor: usize,

    // Auth flow state
    pub auth_flow_selected: usize,
    pub device_flow: Option<auth_flow::DeviceFlowState>,
    pub device_flow_error: Option<String>,
    pub pkce_receiver: Option<std::sync::mpsc::Receiver<anyhow::Result<AuthToken>>>,
    pub pkce_auth_url: Option<String>,
    pub pkce_error: Option<String>,
    pub setup_token_input: String,
    pub setup_token_cursor: usize,
    pub setup_token_instructions: String,
    pub cli_extract_result: Option<(String, Option<AuthToken>)>,
    pub auth_token: Option<AuthToken>,

    // Step 3: Workspace Config
    pub workspace_path: String,
    pub workspace_cursor: usize,

    // Step 4: Gateway Config
    pub gateway_port: String,
    pub gateway_port_cursor: usize,
    pub gateway_bind_selected: usize,
    pub gateway_token: String,
    pub gateway_token_cursor: usize,
    pub gateway_field: GatewayField,

    // Step 5: Channel Selection
    pub channels: Vec<ChannelEntry>,
    pub channel_selected: usize,

    // Step 6: Service Install
    pub service_action_selected: usize,
    pub service_status: Option<String>,

    // Step 7: Health Check
    pub health_results: Vec<HealthResult>,
    pub health_checked: bool,

    // Step 8: Skill Selection
    pub skills: Vec<SkillEntry>,
    pub skill_selected: usize,
    pub skill_scroll_offset: usize,

    // Credential store
    pub credential_store: CredentialStore,
}

// ---------------------------------------------------------------------------
// Bind address options
// ---------------------------------------------------------------------------

pub const BIND_OPTIONS: [(&str, &str); 3] = [
    ("127.0.0.1", "Loopback (local only)"),
    ("0.0.0.0", "All interfaces (LAN)"),
    ("tailscale", "Tailscale IP"),
];

// ---------------------------------------------------------------------------
// Channel definitions
// ---------------------------------------------------------------------------

fn default_channels() -> Vec<ChannelEntry> {
    vec![
        ChannelEntry {
            name: "telegram",
            label: "Telegram",
            description: "Bot token from @BotFather",
            selected: false,
        },
        ChannelEntry {
            name: "discord",
            label: "Discord",
            description: "Bot token from Developer Portal",
            selected: false,
        },
        ChannelEntry {
            name: "slack",
            label: "Slack",
            description: "Bot token and channel ID",
            selected: false,
        },
        ChannelEntry {
            name: "whatsapp",
            label: "WhatsApp",
            description: "API URL and access token",
            selected: false,
        },
        ChannelEntry {
            name: "signal",
            label: "Signal",
            description: "Phone number (E.164) and signal-cli",
            selected: false,
        },
        ChannelEntry {
            name: "imessage",
            label: "iMessage",
            description: "macOS only, Full Disk Access required",
            selected: false,
        },
        ChannelEntry {
            name: "matrix",
            label: "Matrix",
            description: "Homeserver URL and access token",
            selected: false,
        },
        ChannelEntry {
            name: "irc",
            label: "IRC",
            description: "Server, port, nick, and channels",
            selected: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Skill discovery
// ---------------------------------------------------------------------------

fn discover_skills() -> Vec<SkillEntry> {
    // Try to find bundled skills from the project root.
    let skills_dir = aegis_types::daemon::daemon_dir()
        .parent()
        .map(|p| p.join("skills"))
        .unwrap_or_else(|| PathBuf::from("skills"));

    // Also check the cargo manifest dir for development builds.
    let project_skills = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("skills"));

    let search_dir = if skills_dir.is_dir() {
        skills_dir
    } else if let Some(ref p) = project_skills {
        if p.is_dir() {
            p.clone()
        } else {
            return Vec::new();
        }
    } else {
        return Vec::new();
    };

    let Ok(discovered) = aegis_skills::discover_skills(&search_dir) else {
        return Vec::new();
    };

    let mut entries: Vec<SkillEntry> = discovered
        .into_iter()
        .map(|skill| {
            let category = skill
                .manifest
                .category
                .clone()
                .unwrap_or_else(|| "misc".into());
            let installed = skill
                .manifest
                .required_bins
                .iter()
                .all(|bin| aegis_skills::binary_exists(bin));
            SkillEntry {
                name: skill.manifest.name.clone(),
                description: skill.manifest.description.clone(),
                category,
                selected: false,
                installed,
            }
        })
        .collect();

    // Sort by category then name.
    entries.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    entries
}

// ---------------------------------------------------------------------------
// Provider list building
// ---------------------------------------------------------------------------

fn build_provider_entries() -> Vec<ProviderEntry> {
    let detected = scan_providers();
    let mut entries: Vec<ProviderEntry> = Vec::with_capacity(ALL_PROVIDERS.len());

    for dp in &detected {
        let label = if dp.available {
            match dp.info.tier {
                ProviderTier::Local => "[Running]",
                _ => "[Key Set]",
            }
        } else {
            "[--]"
        };
        entries.push(ProviderEntry {
            info: dp.info,
            available: dp.available,
            detection_label: label,
        });
    }

    // Put available providers first within each tier.
    entries.sort_by(|a, b| {
        a.info
            .tier
            .cmp(&b.info.tier)
            .then(b.available.cmp(&a.available))
            .then(a.info.display_name.cmp(b.info.display_name))
    });

    entries
}

/// Get the filtered provider list based on search query.
pub fn filtered_providers(app: &OnboardApp) -> Vec<usize> {
    if app.provider_search.is_empty() {
        return (0..app.providers.len()).collect();
    }
    let query = app.provider_search.to_lowercase();
    app.providers
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.info.display_name.to_lowercase().contains(&query)
                || p.info.id.to_lowercase().contains(&query)
                || format!("{:?}", p.info.tier).to_lowercase().contains(&query)
        })
        .map(|(i, _)| i)
        .collect()
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl OnboardApp {
    /// Create a new wizard with environment detection.
    pub fn new() -> Self {
        let existing_config = aegis_types::daemon::daemon_config_path().exists();
        let providers = build_provider_entries();
        let skills = discover_skills();
        let credential_store =
            CredentialStore::load_default().unwrap_or_else(|_| CredentialStore::default());

        // Pre-select first available provider.
        let provider_selected = providers
            .iter()
            .position(|p| p.available)
            .unwrap_or(0);

        // Default workspace path.
        let workspace_path = home_dir()
            .map(|h| h.join(".aegis").join("workspace"))
            .unwrap_or_else(|| PathBuf::from("~/.aegis/workspace"))
            .display()
            .to_string();

        // Generate a random API token.
        let gateway_token = generate_token();

        Self {
            step: OnboardStep::ConfigDetection,
            running: true,
            error_message: None,

            existing_config,
            config_action_selected: 0,

            providers,
            provider_selected,
            provider_scroll_offset: 0,
            provider_search: String::new(),
            provider_search_cursor: 0,
            provider_searching: false,
            provider_sub_step: ProviderSubStep::SelectProvider,
            model_selected: 0,
            model_manual_input: String::new(),
            model_manual_cursor: 0,
            model_manual_active: false,
            model_loading: false,
            model_loading_error: None,
            discovered_models: vec![],
            api_key_input: String::new(),
            api_key_cursor: 0,

            auth_flow_selected: 0,
            device_flow: None,
            device_flow_error: None,
            pkce_receiver: None,
            pkce_auth_url: None,
            pkce_error: None,
            setup_token_input: String::new(),
            setup_token_cursor: 0,
            setup_token_instructions: String::new(),
            cli_extract_result: None,
            auth_token: None,

            workspace_path,
            workspace_cursor: 0,

            gateway_port: "3100".into(),
            gateway_port_cursor: 4,
            gateway_bind_selected: 0,
            gateway_token,
            gateway_token_cursor: 0,
            gateway_field: GatewayField::Port,

            channels: default_channels(),
            channel_selected: 0,

            service_action_selected: 0,
            service_status: None,

            health_results: Vec::new(),
            health_checked: false,

            skills,
            skill_selected: 0,
            skill_scroll_offset: 0,

            credential_store,
        }
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Progress label for the title bar.
    pub fn progress_text(&self) -> String {
        let label = match self.step {
            OnboardStep::ConfigDetection => "Configuration",
            OnboardStep::ProviderSelection => "AI Provider",
            OnboardStep::WorkspaceConfig => "Workspace",
            OnboardStep::GatewayConfig => "Gateway",
            OnboardStep::ChannelSelection => "Channels",
            OnboardStep::ServiceInstall => "Service",
            OnboardStep::HealthCheck => "Health",
            OnboardStep::SkillSelection => "Skills",
            OnboardStep::Finish => "Finish",
            OnboardStep::Cancelled => return String::new(),
        };
        format!(
            "Step {}/{}: {label}",
            self.step.number(),
            OnboardStep::TOTAL,
        )
    }

    /// Build the result from current state.
    pub fn result(&self) -> OnboardResult {
        OnboardResult {
            cancelled: self.step == OnboardStep::Cancelled,
        }
    }

    /// Get the currently selected provider info (if any).
    pub fn selected_provider(&self) -> Option<&ProviderEntry> {
        self.providers.get(self.provider_selected)
    }

    /// Get the selected model name.
    pub fn selected_model(&self) -> String {
        // Manual input takes priority.
        if self.model_manual_active && !self.model_manual_input.is_empty() {
            return self.model_manual_input.clone();
        }

        if let Some(provider) = self.selected_provider() {
            let static_count = provider.info.models.len();

            if self.model_selected < static_count {
                // Selected a static model.
                return provider.info.models[self.model_selected].id.to_string();
            }

            let discovered_idx = self.model_selected - static_count;
            if discovered_idx < self.discovered_models.len() {
                // Selected a discovered model.
                return self.discovered_models[discovered_idx].id.clone();
            }

            // Fallback to default model.
            provider.info.default_model.to_string()
        } else {
            String::new()
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

        self.error_message = None;

        match self.step {
            OnboardStep::ConfigDetection => self.handle_config_detection(key),
            OnboardStep::ProviderSelection => self.handle_provider_selection(key),
            OnboardStep::WorkspaceConfig => self.handle_workspace_config(key),
            OnboardStep::GatewayConfig => self.handle_gateway_config(key),
            OnboardStep::ChannelSelection => self.handle_channel_selection(key),
            OnboardStep::ServiceInstall => self.handle_service_install(key),
            OnboardStep::HealthCheck => self.handle_health_check(key),
            OnboardStep::SkillSelection => self.handle_skill_selection(key),
            OnboardStep::Finish => self.handle_finish(key),
            OnboardStep::Cancelled => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 1: Config Detection
    // -----------------------------------------------------------------------

    fn handle_config_detection(&mut self, key: KeyEvent) {
        if !self.existing_config {
            // No existing config -- Enter to proceed, Esc to cancel.
            match key.code {
                KeyCode::Enter => self.step = OnboardStep::ProviderSelection,
                KeyCode::Esc => {
                    self.step = OnboardStep::Cancelled;
                    self.running = false;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.config_action_selected =
                    (self.config_action_selected + 1).min(ConfigAction::ALL.len() - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.config_action_selected = self.config_action_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let action = ConfigAction::ALL[self.config_action_selected];
                match action {
                    ConfigAction::Keep => {
                        self.step = OnboardStep::Finish;
                    }
                    ConfigAction::Modify => {
                        self.step = OnboardStep::ProviderSelection;
                    }
                    ConfigAction::Reset => {
                        // Delete existing config and proceed.
                        let _ = std::fs::remove_file(aegis_types::daemon::daemon_config_path());
                        self.step = OnboardStep::ProviderSelection;
                    }
                }
            }
            KeyCode::Esc => {
                self.step = OnboardStep::Cancelled;
                self.running = false;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Provider Selection
    // -----------------------------------------------------------------------

    fn handle_provider_selection(&mut self, key: KeyEvent) {
        match self.provider_sub_step {
            ProviderSubStep::SelectProvider => self.handle_provider_list(key),
            ProviderSubStep::SelectAuthMethod => self.handle_auth_method_selection(key),
            ProviderSubStep::EnterApiKey => self.handle_api_key_input(key),
            ProviderSubStep::SetupTokenInput => self.handle_setup_token_input(key),
            ProviderSubStep::CliExtractResult => self.handle_cli_extract_result(key),
            ProviderSubStep::DeviceFlowWaiting => self.handle_device_flow_waiting(key),
            ProviderSubStep::PkceBrowserWaiting => self.handle_pkce_browser_waiting(key),
            ProviderSubStep::SelectModel => self.handle_model_selection(key),
        }
    }

    fn handle_provider_list(&mut self, key: KeyEvent) {
        // If searching, handle text input.
        if self.provider_searching {
            match key.code {
                KeyCode::Esc => {
                    self.provider_searching = false;
                    self.provider_search.clear();
                    self.provider_search_cursor = 0;
                    self.provider_scroll_offset = 0;
                }
                KeyCode::Enter => {
                    self.provider_searching = false;
                }
                KeyCode::Char(c) => {
                    self.provider_search
                        .insert(self.provider_search_cursor, c);
                    self.provider_search_cursor += c.len_utf8();
                    self.provider_scroll_offset = 0;
                }
                KeyCode::Backspace => {
                    if self.provider_search_cursor > 0 {
                        let prev = self.provider_search[..self.provider_search_cursor]
                            .char_indices()
                            .next_back()
                            .map(|(i, _)| i)
                            .unwrap_or(0);
                        self.provider_search.remove(prev);
                        self.provider_search_cursor = prev;
                        self.provider_scroll_offset = 0;
                    }
                }
                _ => {}
            }
            return;
        }

        let filtered = filtered_providers(self);
        let count = filtered.len();
        if count == 0 && key.code == KeyCode::Esc {
            self.step = OnboardStep::ConfigDetection;
            return;
        }

        match key.code {
            KeyCode::Char('/') => {
                self.provider_searching = true;
                self.provider_search.clear();
                self.provider_search_cursor = 0;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if count > 0 {
                    let current_pos = filtered
                        .iter()
                        .position(|&i| i == self.provider_selected)
                        .unwrap_or(0);
                    let next_pos = (current_pos + 1).min(count - 1);
                    self.provider_selected = filtered[next_pos];
                    if next_pos >= self.provider_scroll_offset + 15 {
                        self.provider_scroll_offset = next_pos.saturating_sub(14);
                    }
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if count > 0 {
                    let current_pos = filtered
                        .iter()
                        .position(|&i| i == self.provider_selected)
                        .unwrap_or(0);
                    let next_pos = current_pos.saturating_sub(1);
                    self.provider_selected = filtered[next_pos];
                    if next_pos < self.provider_scroll_offset {
                        self.provider_scroll_offset = next_pos;
                    }
                }
            }
            KeyCode::Enter => {
                if count == 0 {
                    return;
                }
                let provider = &self.providers[self.provider_selected];
                let provider_id = provider.info.id;

                if provider.available {
                    // Provider already available -- go to model selection.
                    self.provider_sub_step = ProviderSubStep::SelectModel;
                    self.start_model_discovery();
                } else if !needs_auth(provider_id) {
                    // No auth needed (local provider) -- go to model selection.
                    self.provider_sub_step = ProviderSubStep::SelectModel;
                    self.start_model_discovery();
                } else {
                    self.route_to_auth_flow();
                }
            }
            KeyCode::Char('a') => {
                // Quick jump to auth for selected provider.
                if count > 0 {
                    self.route_to_auth_flow();
                }
            }
            KeyCode::Esc => {
                self.step = OnboardStep::ConfigDetection;
            }
            _ => {}
        }
    }

    /// Total number of entries in the model list (static + discovered + 1 manual row).
    pub fn model_entry_count(&self) -> usize {
        let static_count = self
            .selected_provider()
            .map(|p| p.info.models.len())
            .unwrap_or(0);
        static_count + self.discovered_models.len() + 1
    }

    /// Run model discovery for the current provider (synchronous, bounded timeout).
    fn start_model_discovery(&mut self) {
        self.discovered_models.clear();
        self.model_loading_error = None;
        self.model_manual_active = false;
        self.model_manual_input.clear();
        self.model_manual_cursor = 0;
        self.model_selected = 0;

        // Extract provider info before mutating self.
        let (dynamic_discovery, api_type, base_url, provider_id, static_empty) =
            match self.selected_provider() {
                Some(p) => (
                    p.info.dynamic_discovery,
                    p.info.api_type,
                    p.info.base_url,
                    p.info.id,
                    p.info.models.is_empty(),
                ),
                None => return,
            };

        if !dynamic_discovery {
            return;
        }

        self.model_loading = true;

        let models = match api_type {
            ApiType::Ollama => discover_ollama_models(base_url),
            _ => {
                let api_key = self.credential_store.get(provider_id).map(|c| c.api_key.clone());
                discover_openai_compat_models(base_url, api_key.as_deref())
            }
        };

        self.model_loading = false;

        if models.is_empty() && static_empty {
            self.model_loading_error =
                Some("No models discovered. Enter a model ID manually or check the service.".into());
        }

        self.discovered_models = models;
    }

    fn handle_model_selection(&mut self, key: KeyEvent) {
        if self.model_manual_active {
            // Manual input mode.
            match key.code {
                KeyCode::Enter => {
                    if self.model_manual_input.is_empty() {
                        self.error_message = Some("Model ID cannot be empty".into());
                        return;
                    }
                    self.save_provider_credential();
                    self.step = OnboardStep::WorkspaceConfig;
                }
                KeyCode::Esc => {
                    self.model_manual_active = false;
                }
                _ => {
                    self.handle_text_input(key.code, TextInputTarget::ModelManual);
                }
            }
            return;
        }

        // List mode.
        let count = self.model_entry_count();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.model_selected = (self.model_selected + 1).min(count.saturating_sub(1));
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.model_selected = self.model_selected.saturating_sub(1);
            }
            KeyCode::Char('r') => {
                self.start_model_discovery();
            }
            KeyCode::Enter => {
                // Check if the manual entry row is selected (last row).
                if self.model_selected == count - 1 {
                    self.model_manual_active = true;
                    self.model_manual_input.clear();
                    self.model_manual_cursor = 0;
                } else {
                    self.save_provider_credential();
                    self.step = OnboardStep::WorkspaceConfig;
                }
            }
            KeyCode::Esc => {
                self.go_back_from_auth();
            }
            _ => {}
        }
    }

    fn handle_api_key_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if self.api_key_input.is_empty() {
                    self.error_message = Some("API key cannot be empty".into());
                    return;
                }
                // Store the API key and mark provider as available.
                let provider_id = self.providers[self.provider_selected].info.id;
                self.credential_store.set(
                    provider_id,
                    self.api_key_input.clone(),
                    None,
                    None,
                );
                self.providers[self.provider_selected].available = true;
                self.providers[self.provider_selected].detection_label = "[Key Set]";
                // Go to model selection.
                self.provider_sub_step = ProviderSubStep::SelectModel;
                self.start_model_discovery();
            }
            KeyCode::Esc => {
                self.provider_sub_step = ProviderSubStep::SelectProvider;
            }
            KeyCode::Char(c) => {
                self.api_key_input.insert(self.api_key_cursor, c);
                self.api_key_cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.api_key_cursor > 0 {
                    let prev = self.api_key_input[..self.api_key_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.api_key_input.remove(prev);
                    self.api_key_cursor = prev;
                }
            }
            KeyCode::Left => {
                if self.api_key_cursor > 0 {
                    self.api_key_cursor = self.api_key_input[..self.api_key_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.api_key_cursor < self.api_key_input.len() {
                    self.api_key_cursor = self.api_key_input[self.api_key_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.api_key_cursor + i)
                        .unwrap_or(self.api_key_input.len());
                }
            }
            KeyCode::Home => self.api_key_cursor = 0,
            KeyCode::End => self.api_key_cursor = self.api_key_input.len(),
            _ => {}
        }
    }

    /// Save the selected provider credential to the store.
    fn save_provider_credential(&mut self) {
        let provider = &self.providers[self.provider_selected];
        let model = self.selected_model();

        let base = if provider.info.base_url.is_empty() {
            None
        } else {
            Some(provider.info.base_url.to_string())
        };

        if let Some(ref token) = self.auth_token {
            // Store token obtained from an auth flow.
            let base_override = token.base_url_override.clone().or(base);
            let cred_type = match token.token_type {
                AuthTokenType::ApiKey => aegis_types::provider_auth::CredentialType::ApiKey,
                AuthTokenType::OAuthAccess => {
                    aegis_types::provider_auth::CredentialType::OAuthToken
                }
                AuthTokenType::SetupToken => {
                    aegis_types::provider_auth::CredentialType::SetupToken
                }
                AuthTokenType::CliExtracted => {
                    aegis_types::provider_auth::CredentialType::CliExtracted
                }
            };
            self.credential_store.set_with_type(
                provider.info.id,
                token.token.clone(),
                Some(model),
                base_override,
                cred_type,
            );
            self.auth_token = None;
        } else if !self.api_key_input.is_empty() {
            self.credential_store.set(
                provider.info.id,
                self.api_key_input.clone(),
                Some(model.clone()),
                base,
            );
        } else if let Some(existing) = self.credential_store.get(provider.info.id).cloned() {
            // Credential already stored (e.g. from a prior auth step). Update only
            // the model preference without overwriting the api_key.
            self.credential_store.set_with_type(
                provider.info.id,
                existing.api_key,
                Some(model),
                existing.base_url.or(base),
                existing.credential_type,
            );
        } else {
            // No credential stored yet -- store model preference only.
            self.credential_store.set(
                provider.info.id,
                String::new(),
                Some(model),
                None,
            );
        }

        // Save credentials to disk (best effort).
        let _ = self.credential_store.save_default();
    }

    // -----------------------------------------------------------------------
    // Auth flow routing and handlers
    // -----------------------------------------------------------------------

    /// Route the user to the appropriate auth flow for the selected provider.
    fn route_to_auth_flow(&mut self) {
        let provider_id = self.providers[self.provider_selected].info.id;
        let flows = auth_flows_for(provider_id);

        if flows.len() > 1 {
            self.auth_flow_selected = 0;
            self.provider_sub_step = ProviderSubStep::SelectAuthMethod;
        } else if flows.len() == 1 {
            self.start_auth_flow(&flows[0]);
        } else {
            // Fallback: API key entry.
            self.api_key_input.clear();
            self.api_key_cursor = 0;
            self.provider_sub_step = ProviderSubStep::EnterApiKey;
        }
    }

    /// Go back from an auth sub-step to the right parent.
    fn go_back_from_auth(&mut self) {
        let provider_id = self.providers[self.provider_selected].info.id;
        if has_multiple_auth_flows(provider_id) {
            self.provider_sub_step = ProviderSubStep::SelectAuthMethod;
        } else {
            self.provider_sub_step = ProviderSubStep::SelectProvider;
        }
    }

    /// Start a specific auth flow.
    fn start_auth_flow(&mut self, flow: &'static AuthFlowKind) {
        match flow {
            AuthFlowKind::ApiKey => {
                self.api_key_input.clear();
                self.api_key_cursor = 0;
                self.provider_sub_step = ProviderSubStep::EnterApiKey;
            }
            AuthFlowKind::SetupToken { instructions } => {
                self.setup_token_input.clear();
                self.setup_token_cursor = 0;
                self.setup_token_instructions = instructions.to_string();
                self.provider_sub_step = ProviderSubStep::SetupTokenInput;
            }
            AuthFlowKind::CliExtract { cli_name, .. } => {
                let name = cli_name.to_string();
                match auth_flow::extract_cli_token(flow) {
                    Ok(token) => {
                        self.cli_extract_result = Some((name, token));
                    }
                    Err(e) => {
                        self.cli_extract_result = Some((name, None));
                        self.error_message = Some(format!("Extraction failed: {e}"));
                    }
                }
                self.provider_sub_step = ProviderSubStep::CliExtractResult;
            }
            AuthFlowKind::DeviceFlow { .. } => {
                match auth_flow::start_device_flow(flow) {
                    Ok(state) => {
                        self.device_flow = Some(state);
                        self.device_flow_error = None;
                        self.provider_sub_step = ProviderSubStep::DeviceFlowWaiting;
                    }
                    Err(e) => {
                        self.error_message =
                            Some(format!("Failed to start device flow: {e}"));
                    }
                }
            }
            AuthFlowKind::PkceBrowser { .. } => {
                match auth_flow::start_pkce_browser_flow(flow) {
                    Ok(state) => {
                        let auth_url = state.auth_url.clone();
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            let result = auth_flow::complete_pkce_browser_flow(&state);
                            let _ = tx.send(result);
                        });
                        self.pkce_auth_url = Some(auth_url);
                        self.pkce_receiver = Some(rx);
                        self.pkce_error = None;
                        self.provider_sub_step = ProviderSubStep::PkceBrowserWaiting;
                    }
                    Err(e) => {
                        self.error_message =
                            Some(format!("Failed to start browser auth: {e}"));
                    }
                }
            }
        }
    }

    fn handle_auth_method_selection(&mut self, key: KeyEvent) {
        let provider_id = self.providers[self.provider_selected].info.id;
        let flows = auth_flows_for(provider_id);
        let count = flows.len();

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.auth_flow_selected = (self.auth_flow_selected + 1).min(count.saturating_sub(1));
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.auth_flow_selected = self.auth_flow_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.auth_flow_selected < count {
                    self.start_auth_flow(&flows[self.auth_flow_selected]);
                }
            }
            KeyCode::Esc => {
                self.provider_sub_step = ProviderSubStep::SelectProvider;
            }
            _ => {}
        }
    }

    fn handle_setup_token_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if self.setup_token_input.is_empty() {
                    self.error_message = Some("Token cannot be empty".into());
                    return;
                }
                self.auth_token = Some(AuthToken {
                    token: self.setup_token_input.clone(),
                    token_type: AuthTokenType::SetupToken,
                    refresh_token: None,
                    base_url_override: None,
                });
                self.providers[self.provider_selected].available = true;
                self.providers[self.provider_selected].detection_label = "[Token]";
                self.save_provider_credential();
                self.provider_sub_step = ProviderSubStep::SelectModel;
                self.start_model_discovery();
            }
            KeyCode::Esc => {
                self.go_back_from_auth();
            }
            _ => {
                self.handle_text_input(key.code, TextInputTarget::SetupToken);
            }
        }
    }

    fn handle_cli_extract_result(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if let Some((_, Some(ref token))) = self.cli_extract_result {
                    self.auth_token = Some(token.clone());
                    self.providers[self.provider_selected].available = true;
                    self.providers[self.provider_selected].detection_label = "[Token]";
                    self.save_provider_credential();
                    self.cli_extract_result = None;
                    self.provider_sub_step = ProviderSubStep::SelectModel;
                    self.start_model_discovery();
                } else {
                    // No token found -- go back to try another method.
                    self.cli_extract_result = None;
                    self.go_back_from_auth();
                }
            }
            KeyCode::Esc => {
                self.cli_extract_result = None;
                self.go_back_from_auth();
            }
            _ => {}
        }
    }

    fn handle_device_flow_waiting(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.device_flow = None;
            self.device_flow_error = None;
            self.go_back_from_auth();
        }
    }

    fn handle_pkce_browser_waiting(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.pkce_receiver = None;
            self.pkce_auth_url = None;
            self.pkce_error = None;
            self.go_back_from_auth();
        }
    }

    // -----------------------------------------------------------------------
    // Background polling (called on each tick)
    // -----------------------------------------------------------------------

    /// Handle background polling for device flows and PKCE browser flows.
    pub fn tick(&mut self) {
        if self.step != OnboardStep::ProviderSelection {
            return;
        }
        match self.provider_sub_step {
            ProviderSubStep::DeviceFlowWaiting => self.tick_device_flow(),
            ProviderSubStep::PkceBrowserWaiting => self.tick_pkce_browser(),
            _ => {}
        }
    }

    fn tick_device_flow(&mut self) {
        let flow = match self.device_flow.as_mut() {
            Some(f) => f,
            None => return,
        };

        let result = flow.poll_tick();
        match result {
            DevicePollResult::Pending | DevicePollResult::TooSoon => {}
            DevicePollResult::Success(token) => {
                let provider_id = self.providers[self.provider_selected].info.id;
                // For GitHub Copilot, exchange the GitHub token for a Copilot session token.
                let final_token = if provider_id == "github-copilot" {
                    match auth_flow::exchange_copilot_token(&token.token) {
                        Ok(copilot_token) => copilot_token,
                        Err(e) => {
                            self.device_flow_error =
                                Some(format!("Copilot token exchange failed: {e}"));
                            return;
                        }
                    }
                } else {
                    token
                };

                self.auth_token = Some(final_token);
                self.device_flow = None;
                self.providers[self.provider_selected].available = true;
                self.providers[self.provider_selected].detection_label = "[OAuth]";
                self.save_provider_credential();
                self.provider_sub_step = ProviderSubStep::SelectModel;
                self.start_model_discovery();
            }
            DevicePollResult::Expired => {
                self.device_flow_error =
                    Some("Device code expired. Press Esc and try again.".into());
            }
            DevicePollResult::Denied => {
                self.device_flow_error = Some("Authorization denied.".into());
            }
            DevicePollResult::Error(msg) => {
                self.device_flow_error = Some(msg);
            }
        }
    }

    fn tick_pkce_browser(&mut self) {
        let rx = match self.pkce_receiver.as_ref() {
            Some(r) => r,
            None => return,
        };

        match rx.try_recv() {
            Ok(Ok(token)) => {
                self.auth_token = Some(token);
                self.pkce_receiver = None;
                self.pkce_auth_url = None;
                self.providers[self.provider_selected].available = true;
                self.providers[self.provider_selected].detection_label = "[OAuth]";
                self.save_provider_credential();
                self.provider_sub_step = ProviderSubStep::SelectModel;
                self.start_model_discovery();
            }
            Ok(Err(e)) => {
                self.pkce_error = Some(format!("OAuth failed: {e}"));
                self.pkce_receiver = None;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // Still waiting for callback.
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.pkce_error =
                    Some("OAuth callback thread terminated unexpectedly.".into());
                self.pkce_receiver = None;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Workspace Config
    // -----------------------------------------------------------------------

    fn handle_workspace_config(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if self.workspace_path.is_empty() {
                    self.error_message = Some("Workspace path cannot be empty".into());
                    return;
                }
                // Create workspace directory.
                let expanded = expand_tilde(&self.workspace_path);
                let path = PathBuf::from(expanded);
                if let Err(e) = std::fs::create_dir_all(&path) {
                    self.error_message = Some(format!("Failed to create directory: {e}"));
                    return;
                }
                self.step = OnboardStep::GatewayConfig;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::ProviderSelection;
                self.provider_sub_step = ProviderSubStep::SelectProvider;
            }
            KeyCode::Char(c) => {
                self.workspace_path.insert(self.workspace_cursor, c);
                self.workspace_cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.workspace_cursor > 0 {
                    let prev = self.workspace_path[..self.workspace_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.workspace_path.remove(prev);
                    self.workspace_cursor = prev;
                }
            }
            KeyCode::Left => {
                if self.workspace_cursor > 0 {
                    self.workspace_cursor = self.workspace_path[..self.workspace_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.workspace_cursor < self.workspace_path.len() {
                    self.workspace_cursor = self.workspace_path[self.workspace_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.workspace_cursor + i)
                        .unwrap_or(self.workspace_path.len());
                }
            }
            KeyCode::Home => self.workspace_cursor = 0,
            KeyCode::End => self.workspace_cursor = self.workspace_path.len(),
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 4: Gateway Config
    // -----------------------------------------------------------------------

    fn handle_gateway_config(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => {
                self.gateway_field = match self.gateway_field {
                    GatewayField::Port => GatewayField::BindAddress,
                    GatewayField::BindAddress => GatewayField::AuthToken,
                    GatewayField::AuthToken => GatewayField::Port,
                };
            }
            KeyCode::BackTab => {
                self.gateway_field = match self.gateway_field {
                    GatewayField::Port => GatewayField::AuthToken,
                    GatewayField::BindAddress => GatewayField::Port,
                    GatewayField::AuthToken => GatewayField::BindAddress,
                };
            }
            KeyCode::Enter => {
                self.step = OnboardStep::ChannelSelection;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::WorkspaceConfig;
            }
            _ => {
                // Delegate to the active field.
                match self.gateway_field {
                    GatewayField::Port => {
                        self.handle_text_input(
                            key.code,
                            TextInputTarget::GatewayPort,
                        );
                    }
                    GatewayField::BindAddress => match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            self.gateway_bind_selected =
                                (self.gateway_bind_selected + 1).min(BIND_OPTIONS.len() - 1);
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.gateway_bind_selected =
                                self.gateway_bind_selected.saturating_sub(1);
                        }
                        _ => {}
                    },
                    GatewayField::AuthToken => {
                        self.handle_text_input(
                            key.code,
                            TextInputTarget::GatewayToken,
                        );
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 5: Channel Selection
    // -----------------------------------------------------------------------

    fn handle_channel_selection(&mut self, key: KeyEvent) {
        let count = self.channels.len();
        if count == 0 {
            if key.code == KeyCode::Enter || key.code == KeyCode::Esc {
                self.step = if key.code == KeyCode::Enter {
                    OnboardStep::ServiceInstall
                } else {
                    OnboardStep::GatewayConfig
                };
            }
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.channel_selected = (self.channel_selected + 1).min(count - 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.channel_selected = self.channel_selected.saturating_sub(1);
            }
            KeyCode::Char(' ') => {
                // Toggle selection.
                self.channels[self.channel_selected].selected =
                    !self.channels[self.channel_selected].selected;
            }
            KeyCode::Enter => {
                self.step = OnboardStep::ServiceInstall;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::GatewayConfig;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: Service Install
    // -----------------------------------------------------------------------

    fn handle_service_install(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.service_action_selected = (self.service_action_selected + 1).min(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.service_action_selected = self.service_action_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.service_action_selected == 0 {
                    // Install service using the current binary path.
                    let binary = std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "aegis".to_string());
                    let result = aegis_daemon::service::install(&binary);
                    if result.success {
                        self.service_status = Some(result.message);
                    } else {
                        self.service_status =
                            Some(format!("Install failed: {}", result.message));
                    }
                }
                self.step = OnboardStep::HealthCheck;
            }
            KeyCode::Esc => {
                self.step = OnboardStep::ChannelSelection;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 7: Health Check
    // -----------------------------------------------------------------------

    fn handle_health_check(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') | KeyCode::Enter => {
                if !self.health_checked || key.code == KeyCode::Char('r') {
                    self.run_health_checks();
                    self.health_checked = true;
                } else {
                    self.step = OnboardStep::SkillSelection;
                }
            }
            KeyCode::Esc => {
                self.step = OnboardStep::ServiceInstall;
            }
            _ => {}
        }
    }

    fn run_health_checks(&mut self) {
        self.health_results.clear();

        // Check aegis directory.
        let aegis_dir = aegis_types::daemon::daemon_dir();
        self.health_results.push(HealthResult {
            label: "Aegis directory".into(),
            passed: aegis_dir.is_dir(),
            message: if aegis_dir.is_dir() {
                aegis_dir.display().to_string()
            } else {
                "Not found".into()
            },
        });

        // Check config file.
        let config_path = aegis_types::daemon::daemon_config_path();
        self.health_results.push(HealthResult {
            label: "Configuration".into(),
            passed: config_path.exists(),
            message: if config_path.exists() {
                "daemon.toml found".into()
            } else {
                "daemon.toml missing".into()
            },
        });

        // Check daemon connectivity.
        let daemon_running = std::net::TcpStream::connect_timeout(
            &"127.0.0.1:3100".parse().unwrap(),
            std::time::Duration::from_millis(500),
        )
        .is_ok();
        self.health_results.push(HealthResult {
            label: "Daemon".into(),
            passed: daemon_running,
            message: if daemon_running {
                "Responding on port 3100".into()
            } else {
                "Not reachable (will start on finish)".into()
            },
        });

        // Check credentials.
        let has_creds = !self.credential_store.providers.is_empty()
            || self
                .providers
                .iter()
                .any(|p| p.available);
        self.health_results.push(HealthResult {
            label: "Credentials".into(),
            passed: has_creds,
            message: if has_creds {
                "Provider credentials configured".into()
            } else {
                "No provider credentials found".into()
            },
        });
    }

    // -----------------------------------------------------------------------
    // Step 8: Skill Selection
    // -----------------------------------------------------------------------

    fn handle_skill_selection(&mut self, key: KeyEvent) {
        let count = self.skills.len();
        if count == 0 {
            match key.code {
                KeyCode::Enter => self.step = OnboardStep::Finish,
                KeyCode::Esc => self.step = OnboardStep::HealthCheck,
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.skill_selected = (self.skill_selected + 1).min(count - 1);
                // Scroll to keep selected in view.
                if self.skill_selected >= self.skill_scroll_offset + 15 {
                    self.skill_scroll_offset = self.skill_selected.saturating_sub(14);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.skill_selected = self.skill_selected.saturating_sub(1);
                if self.skill_selected < self.skill_scroll_offset {
                    self.skill_scroll_offset = self.skill_selected;
                }
            }
            KeyCode::Char(' ') => {
                self.skills[self.skill_selected].selected =
                    !self.skills[self.skill_selected].selected;
            }
            KeyCode::Char('a') => {
                // Select all.
                let all_selected = self.skills.iter().all(|s| s.selected);
                for s in &mut self.skills {
                    s.selected = !all_selected;
                }
            }
            KeyCode::Enter => {
                self.finalize_wizard();
            }
            KeyCode::Esc => {
                self.step = OnboardStep::HealthCheck;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Step 9: Finish
    // -----------------------------------------------------------------------

    fn handle_finish(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('q') => {
                self.running = false;
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Finalization
    // -----------------------------------------------------------------------

    /// Write all configuration and start the daemon.
    fn finalize_wizard(&mut self) {
        let config = self.build_daemon_config();

        // Ensure daemon directory exists.
        let dir = aegis_types::daemon::daemon_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.error_message = Some(format!("Failed to create dir: {e}"));
            return;
        }

        // Write daemon.toml.
        let config_path = aegis_types::daemon::daemon_config_path();
        match config.to_toml() {
            Ok(toml_str) => {
                if let Err(e) = std::fs::write(&config_path, &toml_str) {
                    self.error_message = Some(format!("Failed to write config: {e}"));
                    return;
                }
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to serialize config: {e}"));
                return;
            }
        }

        // Save credentials.
        if let Err(e) = self.credential_store.save_default() {
            self.error_message = Some(format!("Failed to save credentials: {e}"));
            return;
        }

        // Start daemon.
        if let Err(e) = crate::commands::daemon::start_quiet() {
            self.error_message = Some(format!("Daemon failed to start: {e:#}"));
            return;
        }

        self.step = OnboardStep::Finish;
    }

    // -----------------------------------------------------------------------
    // Config building
    // -----------------------------------------------------------------------

    fn build_daemon_config(&self) -> DaemonConfig {
        let model = self.selected_model();
        let bind = BIND_OPTIONS
            .get(self.gateway_bind_selected)
            .map(|(addr, _)| *addr)
            .unwrap_or("127.0.0.1");
        let port = self.gateway_port.parse::<u16>().unwrap_or(3100);
        let http_listen = format!("{bind}:{port}");

        DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig {
                http_listen,
                api_key: self.gateway_token.clone(),
                ..Default::default()
            },
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
            default_model: Some(model),
            skills: self
                .skills
                .iter()
                .filter(|s| s.selected)
                .map(|s| s.name.clone())
                .collect(),
        }
    }

    // -----------------------------------------------------------------------
    // Text input helper
    // -----------------------------------------------------------------------

    fn handle_text_input(&mut self, code: KeyCode, target: TextInputTarget) {
        let (text, cursor) = match target {
            TextInputTarget::GatewayPort => (&mut self.gateway_port, &mut self.gateway_port_cursor),
            TextInputTarget::GatewayToken => {
                (&mut self.gateway_token, &mut self.gateway_token_cursor)
            }
            TextInputTarget::SetupToken => {
                (&mut self.setup_token_input, &mut self.setup_token_cursor)
            }
            TextInputTarget::ModelManual => {
                (&mut self.model_manual_input, &mut self.model_manual_cursor)
            }
        };

        match code {
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
            KeyCode::Home => *cursor = 0,
            KeyCode::End => *cursor = text.len(),
            _ => {}
        }
    }
}

/// Which text field is being edited.
enum TextInputTarget {
    GatewayPort,
    GatewayToken,
    SetupToken,
    ModelManual,
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Get the user's home directory from the HOME environment variable.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest).display().to_string();
        }
    } else if path == "~" {
        if let Some(home) = home_dir() {
            return home.display().to_string();
        }
    }
    path.to_string()
}

/// Generate a random 32-character hex token for API auth.
fn generate_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", seed)
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

    /// Create a test app with known state.
    fn test_app() -> OnboardApp {
        let mut app = OnboardApp::new();
        // Ensure we start at config detection.
        app.step = OnboardStep::ConfigDetection;
        app.existing_config = false;
        app
    }

    #[test]
    fn initial_state() {
        let app = OnboardApp::new();
        assert_eq!(app.step, OnboardStep::ConfigDetection);
        assert!(app.running);
        assert!(!app.providers.is_empty());
        assert!(app.error_message.is_none());
    }

    #[test]
    fn step_numbers() {
        assert_eq!(OnboardStep::ConfigDetection.number(), 1);
        assert_eq!(OnboardStep::ProviderSelection.number(), 2);
        assert_eq!(OnboardStep::WorkspaceConfig.number(), 3);
        assert_eq!(OnboardStep::GatewayConfig.number(), 4);
        assert_eq!(OnboardStep::ChannelSelection.number(), 5);
        assert_eq!(OnboardStep::ServiceInstall.number(), 6);
        assert_eq!(OnboardStep::HealthCheck.number(), 7);
        assert_eq!(OnboardStep::SkillSelection.number(), 8);
        assert_eq!(OnboardStep::Finish.number(), 9);
    }

    #[test]
    fn config_detection_no_existing() {
        let mut app = test_app();
        app.existing_config = false;
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ProviderSelection);
    }

    #[test]
    fn config_detection_existing_keep() {
        let mut app = test_app();
        app.existing_config = true;
        app.config_action_selected = 0; // Keep
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::Finish);
    }

    #[test]
    fn config_detection_existing_modify() {
        let mut app = test_app();
        app.existing_config = true;
        app.config_action_selected = 1; // Modify
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.step, OnboardStep::ProviderSelection);
    }

    #[test]
    fn config_detection_esc_cancels() {
        let mut app = test_app();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn ctrl_c_always_cancels() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.handle_key(ctrl_c());
        assert_eq!(app.step, OnboardStep::Cancelled);
        assert!(!app.running);
    }

    #[test]
    fn provider_nav_jk() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::SelectProvider;
        let initial = app.provider_selected;

        if app.providers.len() > 1 {
            app.handle_key(press(KeyCode::Char('j')));
            assert!(app.provider_selected > initial || app.providers.len() == 1);
        }
    }

    #[test]
    fn provider_nav_clamps() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::SelectProvider;
        app.provider_selected = 0;

        // Up from 0 should stay at 0.
        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.provider_selected, 0);
    }

    #[test]
    fn provider_search_toggle() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::SelectProvider;

        // Enter search mode.
        app.handle_key(press(KeyCode::Char('/')));
        assert!(app.provider_searching);

        // Type a query.
        app.handle_key(press(KeyCode::Char('o')));
        assert_eq!(app.provider_search, "o");

        // Esc exits search.
        app.handle_key(press(KeyCode::Esc));
        assert!(!app.provider_searching);
        assert!(app.provider_search.is_empty());
    }

    #[test]
    fn esc_from_provider_goes_to_config() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::SelectProvider;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::ConfigDetection);
    }

    #[test]
    fn model_selection_esc_goes_back() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::SelectModel;
        app.handle_key(press(KeyCode::Esc));
        // Goes back to auth method selection or provider list depending on provider.
        assert_ne!(app.provider_sub_step, ProviderSubStep::SelectModel);
    }

    #[test]
    fn api_key_input_basic() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::EnterApiKey;

        // Type a key.
        app.handle_key(press(KeyCode::Char('t')));
        app.handle_key(press(KeyCode::Char('e')));
        app.handle_key(press(KeyCode::Char('s')));
        app.handle_key(press(KeyCode::Char('t')));
        assert_eq!(app.api_key_input, "test");
        assert_eq!(app.api_key_cursor, 4);

        // Backspace.
        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.api_key_input, "tes");
        assert_eq!(app.api_key_cursor, 3);
    }

    #[test]
    fn api_key_empty_rejected() {
        let mut app = test_app();
        app.step = OnboardStep::ProviderSelection;
        app.provider_sub_step = ProviderSubStep::EnterApiKey;
        app.api_key_input.clear();

        app.handle_key(press(KeyCode::Enter));
        assert!(app.error_message.is_some());
        assert_eq!(app.provider_sub_step, ProviderSubStep::EnterApiKey);
    }

    #[test]
    fn workspace_esc_goes_back() {
        let mut app = test_app();
        app.step = OnboardStep::WorkspaceConfig;
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.step, OnboardStep::ProviderSelection);
    }

    #[test]
    fn gateway_tab_cycles_fields() {
        let mut app = test_app();
        app.step = OnboardStep::GatewayConfig;

        assert_eq!(app.gateway_field, GatewayField::Port);
        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.gateway_field, GatewayField::BindAddress);
        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.gateway_field, GatewayField::AuthToken);
        app.handle_key(press(KeyCode::Tab));
        assert_eq!(app.gateway_field, GatewayField::Port);
    }

    #[test]
    fn channel_toggle_selection() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSelection;
        assert!(!app.channels[0].selected);

        app.handle_key(press(KeyCode::Char(' ')));
        assert!(app.channels[0].selected);

        app.handle_key(press(KeyCode::Char(' ')));
        assert!(!app.channels[0].selected);
    }

    #[test]
    fn channel_nav() {
        let mut app = test_app();
        app.step = OnboardStep::ChannelSelection;
        app.channel_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.channel_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.channel_selected, 0);
    }

    #[test]
    fn service_install_nav() {
        let mut app = test_app();
        app.step = OnboardStep::ServiceInstall;
        app.service_action_selected = 0;

        app.handle_key(press(KeyCode::Char('j')));
        assert_eq!(app.service_action_selected, 1);

        app.handle_key(press(KeyCode::Char('k')));
        assert_eq!(app.service_action_selected, 0);
    }

    #[test]
    fn skill_toggle_selection() {
        let mut app = test_app();
        app.step = OnboardStep::SkillSelection;
        if !app.skills.is_empty() {
            assert!(!app.skills[0].selected);
            app.handle_key(press(KeyCode::Char(' ')));
            assert!(app.skills[0].selected);
        }
    }

    #[test]
    fn skill_select_all() {
        let mut app = test_app();
        app.step = OnboardStep::SkillSelection;
        if !app.skills.is_empty() {
            app.handle_key(press(KeyCode::Char('a')));
            assert!(app.skills.iter().all(|s| s.selected));
            // Toggle off.
            app.handle_key(press(KeyCode::Char('a')));
            assert!(app.skills.iter().all(|s| !s.selected));
        }
    }

    #[test]
    fn progress_text_for_each_step() {
        let mut app = test_app();

        for step in [
            OnboardStep::ConfigDetection,
            OnboardStep::ProviderSelection,
            OnboardStep::WorkspaceConfig,
            OnboardStep::GatewayConfig,
            OnboardStep::ChannelSelection,
            OnboardStep::ServiceInstall,
            OnboardStep::HealthCheck,
            OnboardStep::SkillSelection,
            OnboardStep::Finish,
        ] {
            app.step = step;
            let text = app.progress_text();
            assert!(!text.is_empty(), "progress text empty for {step:?}");
            assert!(text.contains(&step.number().to_string()));
        }
    }

    #[test]
    fn result_cancelled() {
        let mut app = test_app();
        app.step = OnboardStep::Cancelled;
        assert!(app.result().cancelled);
    }

    #[test]
    fn result_not_cancelled() {
        let mut app = test_app();
        app.step = OnboardStep::Finish;
        assert!(!app.result().cancelled);
    }

    #[test]
    fn build_daemon_config_has_model() {
        let app = test_app();
        let config = app.build_daemon_config();
        assert!(config.default_model.is_some());
    }

    #[test]
    fn build_daemon_config_has_gateway() {
        let app = test_app();
        let config = app.build_daemon_config();
        assert!(!config.control.http_listen.is_empty());
        assert!(!config.control.api_key.is_empty());
    }

    #[test]
    fn provider_count() {
        let app = test_app();
        assert!(
            app.providers.len() >= 20,
            "expected at least 20 providers, got {}",
            app.providers.len()
        );
    }

    #[test]
    fn filtered_providers_no_search() {
        let app = test_app();
        let filtered = filtered_providers(&app);
        assert_eq!(filtered.len(), app.providers.len());
    }

    #[test]
    fn generate_token_not_empty() {
        let token = generate_token();
        assert!(!token.is_empty());
        assert!(token.len() >= 16);
    }
}
