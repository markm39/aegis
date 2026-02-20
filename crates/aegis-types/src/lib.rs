//! Core types shared across all Aegis crates.
//!
//! Defines actions, verdicts, configuration, and error types used by the
//! policy engine, audit ledger, sandbox, and CLI.

pub mod action;
pub mod config;
pub mod daemon;
pub mod error;
pub mod verdict;

pub use action::{Action, ActionKind};
pub use config::{
    validate_config_name, ActiveHoursConfig, AdapterConfig, AegisConfig, AlertRule, ChannelConfig,
    ControlConfig, IsolationConfig, NetworkRule, ObserverConfig, PilotConfig, PromptPatternConfig,
    Protocol, StallConfig, TelegramConfig, UncertainAction, UsageProxyConfig, CONFIG_FILENAME,
    DEFAULT_POLICY_FILENAME, LEDGER_FILENAME,
};
pub use daemon::{
    AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig, DaemonControlConfig,
    PersistenceConfig, RestartPolicy,
};
pub use error::AegisError;
pub use verdict::{Decision, Verdict};
