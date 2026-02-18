//! CLI command implementations for the `aegis` binary.

use std::path::PathBuf;

use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig, RestartPolicy};

/// Short datetime format for listings and summaries (e.g., "2024-01-15 10:30").
pub const DATETIME_SHORT_FMT: &str = "%Y-%m-%d %H:%M";

/// Full datetime format with seconds for detailed views (e.g., "2024-01-15 10:30:45").
pub const DATETIME_FULL_FMT: &str = "%Y-%m-%d %H:%M:%S";

/// Build an `AgentSlotConfig` with standard defaults.
///
/// Centralizes construction so that new fields only need to be added here.
pub(crate) fn build_agent_slot(
    name: String,
    tool: AgentToolConfig,
    working_dir: PathBuf,
    task: Option<String>,
    restart: RestartPolicy,
    max_restarts: u32,
) -> AgentSlotConfig {
    AgentSlotConfig {
        name,
        tool,
        working_dir,
        role: None,
        agent_goal: None,
        context: None,
        task,
        pilot: None,
        restart,
        max_restarts,
        enabled: true,
    }
}

pub mod alerts;
pub mod audit;
pub mod config;
pub mod daemon;
pub mod default_action;
pub mod hook;
pub mod diff;
pub mod init;
pub mod list;
pub mod monitor;
pub mod onboard;
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
