//! Current config management.
//!
//! Tracks which aegis configuration is "active" so that commands like
//! `aegis monitor`, `aegis log`, and `aegis status` work without
//! specifying a config name every time.
//!
//! The current config name is stored at `~/.aegis/current`.

use std::fs;

use anyhow::{bail, Context, Result};
use dialoguer::Select;

use crate::commands::init::dirs_from_env;

/// File name for the current config pointer.
const CURRENT_FILE: &str = "current";

/// Set the current active config.
pub fn set_current(name: &str) -> Result<()> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");
    fs::create_dir_all(&aegis_dir)
        .with_context(|| format!("failed to create {}", aegis_dir.display()))?;
    let path = aegis_dir.join(CURRENT_FILE);
    fs::write(&path, name)
        .with_context(|| format!("failed to write current config to {}", path.display()))?;
    Ok(())
}

/// Get the current active config name.
///
/// Reads from `~/.aegis/current`. If that file doesn't exist, falls back
/// to the most recently used config. If no configs exist at all, returns
/// an error with a helpful message.
pub fn get_current() -> Result<String> {
    let home = dirs_from_env()?;
    let path = home.join(".aegis").join(CURRENT_FILE);

    if let Ok(name) = fs::read_to_string(&path) {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return Ok(name);
        }
    }

    // Fall back to most recently used config
    crate::commands::default_action::most_recent_config()
}

/// Interactively prompt the user to select a config from available options.
pub fn pick_current() -> Result<String> {
    let names = list_config_names()?;
    if names.is_empty() {
        bail!("no configurations found; run `aegis init` to create one");
    }

    let selection = Select::new()
        .with_prompt("Select a configuration")
        .items(&names)
        .default(0)
        .interact()
        .context("failed to read selection")?;

    let name = &names[selection];
    set_current(name)?;
    Ok(name.clone())
}

/// Run `aegis use [NAME]`.
///
/// With a name: sets it as the current config.
/// Without: shows the current config or prompts to pick one.
pub fn run(name: Option<&str>) -> Result<()> {
    match name {
        Some(n) => {
            // Verify the config exists
            let names = list_config_names()?;
            if !names.iter().any(|existing| existing == n) {
                bail!(
                    "configuration '{}' not found; available: {}",
                    n,
                    names.join(", ")
                );
            }
            set_current(n)?;
            println!("Active configuration: {n}");
        }
        None => {
            match get_current() {
                Ok(name) => println!("Active configuration: {name}"),
                Err(_) => {
                    let picked = pick_current()?;
                    println!("Active configuration: {picked}");
                }
            }
        }
    }
    Ok(())
}

/// List all config names (init + wrap).
fn list_config_names() -> Result<Vec<String>> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");
    let mut names = Vec::new();

    // Init configs
    if let Ok(entries) = fs::read_dir(&aegis_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if name != "wraps"
                    && name != CURRENT_FILE
                    && path.join(aegis_types::CONFIG_FILENAME).exists()
                {
                    names.push(name);
                }
            }
        }
    }

    // Wrap configs
    let wraps_dir = aegis_dir.join("wraps");
    if let Ok(entries) = fs::read_dir(wraps_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(aegis_types::CONFIG_FILENAME).exists() {
                if let Some(name) = path.file_name() {
                    names.push(name.to_string_lossy().into_owned());
                }
            }
        }
    }

    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_config_names_returns_sorted() {
        // This just tests that it doesn't panic; actual configs depend on the system
        let result = list_config_names();
        assert!(result.is_ok());
    }
}
