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
#[doc(hidden)]
pub use config::PilotConfig;
pub use config::{
    validate_config_name, AdapterConfig, AegisConfig, AlertRule, DockerSandboxConfig,
    IsolationConfig, NetworkRule, ObserverConfig, PromptPatternConfig, Protocol, SessionConfig,
    StallConfig, UncertainAction, CONFIG_FILENAME, DEFAULT_POLICY_FILENAME, LEDGER_FILENAME,
};
pub use error::AegisError;
pub use ids::AgentName;
pub use verdict::{Decision, Verdict};
