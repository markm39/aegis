//! Core types shared across all Aegis crates.
//!
//! Defines actions, verdicts, configuration, and error types used by the
//! policy engine, audit ledger, sandbox, and probe runner.

pub mod action;
pub mod config;
pub mod error;
pub mod ids;
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
pub use error::AegisError;
pub use ids::AgentName;
pub use verdict::{Decision, Verdict};
