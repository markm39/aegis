//! Core types shared across all Aegis crates.
//!
//! Defines actions, verdicts, configuration, and error types used by the
//! policy engine, audit ledger, sandbox, and CLI.

pub mod action;
pub mod config;
pub mod error;
pub mod verdict;

pub use action::{Action, ActionKind};
pub use config::{AegisConfig, IsolationConfig, NetworkRule, ObserverConfig, Protocol};
pub use error::AegisError;
pub use verdict::{Decision, Verdict};
