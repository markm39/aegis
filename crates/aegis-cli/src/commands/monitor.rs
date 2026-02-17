//! Launch the ratatui terminal dashboard for real-time audit monitoring.

use anyhow::{Context, Result};

use crate::commands::init::load_config;

/// Run the `aegis monitor` command.
///
/// Loads the config and launches the ratatui TUI monitor for the audit ledger.
pub fn run(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;

    aegis_monitor::run_monitor(config.ledger_path).context("monitor exited with error")
}
