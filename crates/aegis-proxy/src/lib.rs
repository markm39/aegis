//! Aegis proxy: process audit logging, Seatbelt violation harvesting,
//! and API usage tracking.
//!
//! This crate provides audit logging for process lifecycle events (spawn/exit),
//! harvests macOS Seatbelt sandbox violation logs, and includes an HTTP reverse
//! proxy for API usage tracking (Anthropic/OpenAI token counting).

pub mod audit;
pub mod budget;
pub mod pricing;
pub mod profiles;
pub mod usage;

#[cfg(target_os = "macos")]
pub use audit::harvest_seatbelt_violations;
pub use audit::{log_process_exit, log_process_spawn};
pub use usage::{UsageProxy, UsageProxyHandle};
