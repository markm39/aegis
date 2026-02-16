/// Aegis proxy: process audit logging, Seatbelt violation harvesting,
/// and transparent network proxy.
///
/// This crate provides audit logging for process lifecycle events (spawn/exit),
/// harvests macOS Seatbelt sandbox violation logs, and includes a network proxy
/// for future TCP interception.
pub mod audit;
pub mod net;

pub use audit::{log_process_exit, log_process_spawn};
#[cfg(target_os = "macos")]
pub use audit::harvest_seatbelt_violations;
pub use net::NetworkProxy;
