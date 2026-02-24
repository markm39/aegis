//! Core types shared across all Aegis crates.
//!
//! Defines actions, verdicts, configuration, and error types used by the
//! policy engine, audit ledger, sandbox, and CLI.

pub mod action;
pub mod config;
pub mod config_loader;
pub mod copilot;
pub mod credentials;
pub mod daemon;
pub mod error;
pub mod google_ai;
pub mod ids;
pub mod llm;
pub mod oauth;
pub mod provider_auth;
pub mod providers;
pub mod tool_classification;
pub mod verdict;

pub use action::{Action, ActionKind};
pub use config::{
    validate_config_name, ActiveHoursConfig, AdapterConfig, AegisConfig, AlertRule,
    ChannelCommandSetConfig, ChannelConfig, ChannelRoutingConfig, ControlConfig,
    DiscordChannelConfig, DockerSandboxConfig, FeishuChannelConfig, GmailChannelConfig,
    GooglechatChannelConfig, ImessageChannelConfig, IrcChannelConfig, IsolationConfig,
    LineChannelConfig, MatrixChannelConfig, MattermostChannelConfig, MsteamsChannelConfig,
    NetworkRule, NostrChannelConfig, ObserverConfig, PilotConfig, PromptPatternConfig, Protocol,
    SignalChannelConfig, SlackConfig, StallConfig, TelegramConfig, UncertainAction,
    UsageProxyConfig, VoiceCallChannelConfig, WebhookChannelConfig, WhatsappChannelConfig,
    CONFIG_FILENAME, DEFAULT_POLICY_FILENAME, LEDGER_FILENAME,
};
pub use config_loader::{
    discover_layers, flatten_toml, format_toml_value, get_dot_value, is_sensitive_field,
    mask_sensitive, set_dot_value, ConfigLayerInfo, ConfigLoader, ConfigSource, EffectiveConfig,
    CONFIG_KEY_NAMES,
};
pub use credentials::CredentialStore;
pub use daemon::{
    AcpServerConfig, AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig,
    DaemonControlConfig, PersistenceConfig, RestartPolicy,
};
pub use ids::AgentName;
pub use error::AegisError;
pub use provider_auth::{
    auth_flows_for, has_multiple_auth_flows, needs_auth, AuthFlowKind, ClientIdSource,
    CredentialType, DeviceFlowPollStyle, TokenExtraction,
};
pub use providers::{
    discover_ollama_models, discover_openai_compat_models, format_context_window, provider_by_id,
    providers_by_tier, scan_providers, DetectedProvider, DiscoveredModel, ProviderInfo,
    ProviderTier, ALL_PROVIDERS,
};
pub use verdict::{Decision, Verdict};
