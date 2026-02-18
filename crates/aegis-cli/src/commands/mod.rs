//! CLI command implementations for the `aegis` binary.

/// Short datetime format for listings and summaries (e.g., "2024-01-15 10:30").
pub const DATETIME_SHORT_FMT: &str = "%Y-%m-%d %H:%M";

/// Full datetime format with seconds for detailed views (e.g., "2024-01-15 10:30:45").
pub const DATETIME_FULL_FMT: &str = "%Y-%m-%d %H:%M:%S";

pub mod alerts;
pub mod audit;
pub mod config;
pub mod daemon;
pub mod default_action;
pub mod diff;
pub mod init;
pub mod list;
pub mod monitor;
pub mod pilot;
pub mod pipeline;
pub mod policy;
pub mod report;
pub mod run;
pub mod setup;
pub mod status;
pub mod telegram;
pub mod use_config;
pub mod watch;
pub mod wrap;
