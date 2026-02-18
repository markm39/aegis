//! Aegis proxy: process audit logging, Seatbelt violation harvesting,
//! network proxy, and API usage tracking.
//!
//! This crate provides audit logging for process lifecycle events (spawn/exit),
//! harvests macOS Seatbelt sandbox violation logs, includes a network proxy
//! for TCP interception, and an HTTP reverse proxy for API usage tracking.

pub mod audit;
pub mod net;
pub mod usage;

pub use audit::{log_process_exit, log_process_spawn};
#[cfg(target_os = "macos")]
pub use audit::harvest_seatbelt_violations;
pub use net::NetworkProxy;
pub use usage::{UsageProxy, UsageProxyHandle};
