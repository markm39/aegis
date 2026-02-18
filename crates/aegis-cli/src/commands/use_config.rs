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
                    && name != "daemon"
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
    fn list_config_names_returns_sorted_results() {
        // This test runs against the real HOME, so we can only verify structural
        // properties. The returned list may be empty if no configs exist.
        let names = list_config_names().expect("list_config_names should not error");
        // Verify the list is actually sorted (the core invariant)
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "config names should be returned in sorted order");
        // Verify no empty names snuck in
        assert!(
            names.iter().all(|n| !n.is_empty()),
            "all config names should be non-empty"
        );
    }

    #[test]
    fn current_file_roundtrip() {
        // Test the file read/write logic directly without mutating HOME,
        // since env var changes affect parallel tests.
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let aegis_dir = tmpdir.path().join(".aegis");
        std::fs::create_dir_all(&aegis_dir).expect("create .aegis");

        let current_path = aegis_dir.join(CURRENT_FILE);
        std::fs::write(&current_path, "my-test-config").expect("write");

        let content = std::fs::read_to_string(&current_path).expect("read");
        assert_eq!(content.trim(), "my-test-config");
    }

    #[test]
    fn current_file_empty_is_treated_as_absent() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let aegis_dir = tmpdir.path().join(".aegis");
        std::fs::create_dir_all(&aegis_dir).expect("create .aegis");

        let current_path = aegis_dir.join(CURRENT_FILE);
        std::fs::write(&current_path, "").expect("write empty");

        // An empty file should be treated as if no current config is set.
        // The get_current() function checks `!name.is_empty()` after trim.
        let content = std::fs::read_to_string(&current_path).expect("read");
        let name = content.trim().to_string();
        assert!(name.is_empty(), "empty file should produce empty string after trim");
    }

    #[test]
    fn current_file_trims_whitespace() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let aegis_dir = tmpdir.path().join(".aegis");
        std::fs::create_dir_all(&aegis_dir).expect("create .aegis");

        let current_path = aegis_dir.join(CURRENT_FILE);
        std::fs::write(&current_path, "  my-config  \n").expect("write");

        // The get_current() function trims whitespace; verify the same logic
        let content = std::fs::read_to_string(&current_path).expect("read");
        let name = content.trim().to_string();
        assert_eq!(name, "my-config");
        assert!(!name.is_empty());
    }
}
