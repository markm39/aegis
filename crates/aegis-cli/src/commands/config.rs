//! Configuration management commands.
//!
//! `aegis config show NAME`   -- display all settings
//! `aegis config path NAME`   -- print the config file path
//! `aegis config edit NAME`   -- open config in $EDITOR

use std::fs;

use anyhow::{bail, Context, Result};

use aegis_types::{AegisConfig, CONFIG_FILENAME};

use crate::commands::init::{load_config, resolve_config_dir};

/// Run `aegis config show NAME`.
pub fn show(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let config_dir = resolve_config_dir(config_name)?;

    // Determine config type
    let config_type = if config_dir
        .to_string_lossy()
        .contains(".aegis/wraps/")
    {
        "wrap"
    } else {
        "init"
    };

    println!("Configuration: {}", config.name);
    println!("  Type:       {config_type}");
    println!("  Directory:  {}", config.sandbox_dir.display());

    // Show policy paths and their contents
    for (i, path) in config.policy_paths.iter().enumerate() {
        if i == 0 {
            println!("  Policies:   {}", path.display());
        } else {
            println!("              {}", path.display());
        }
        // List .cedar files in the policy directory
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "cedar") {
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    println!("    - {name}");
                }
            }
        }
    }

    println!("  Ledger:     {}", config.ledger_path.display());
    println!("  Isolation:  {}", describe_isolation(&config));
    println!("  Observer:   {}", config.observer);

    if config.allowed_network.is_empty() {
        println!("  Network:    (no rules)");
    } else {
        println!("  Network:");
        for rule in &config.allowed_network {
            println!("    - {rule}");
        }
    }

    if let Some(schema) = &config.schema_path {
        println!("  Schema:     {}", schema.display());
    }

    println!("  Config at:  {}", config_dir.join(CONFIG_FILENAME).display());

    Ok(())
}

/// Run `aegis config path NAME`.
///
/// Prints the path to the aegis.toml file for scripting/piping.
pub fn path(config_name: &str) -> Result<()> {
    let config_dir = resolve_config_dir(config_name)?;
    let config_path = config_dir.join(CONFIG_FILENAME);

    if !config_path.exists() {
        bail!(
            "configuration '{}' not found; run 'aegis init {}' to create it",
            config_name,
            config_name
        );
    }

    println!("{}", config_path.display());
    Ok(())
}

/// Run `aegis config edit NAME`.
///
/// Opens the config file in the user's `$EDITOR` (falls back to `vi`).
pub fn edit(config_name: &str) -> Result<()> {
    let config_dir = resolve_config_dir(config_name)?;
    let config_path = config_dir.join(CONFIG_FILENAME);

    if !config_path.exists() {
        bail!(
            "configuration '{}' not found; run 'aegis init {}' to create it",
            config_name,
            config_name
        );
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("failed to launch editor '{editor}'"))?;

    if !status.success() {
        bail!("editor exited with code {}", status.code().unwrap_or(-1));
    }

    // Validate the edited config
    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    match AegisConfig::from_toml(&content) {
        Ok(_) => println!("Configuration saved and validated."),
        Err(e) => {
            println!("WARNING: config may be invalid after editing: {e}");
            println!("Run 'aegis config show {config_name}' to inspect.");
        }
    }

    Ok(())
}

fn describe_isolation(config: &AegisConfig) -> String {
    match &config.isolation {
        aegis_types::IsolationConfig::Seatbelt { profile_overrides } => {
            if let Some(path) = profile_overrides {
                format!("Seatbelt (custom profile: {})", path.display())
            } else {
                "Seatbelt (macOS kernel sandbox)".to_string()
            }
        }
        aegis_types::IsolationConfig::Process => "Process (no kernel enforcement)".to_string(),
        aegis_types::IsolationConfig::None => "None".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_isolation_variants() {
        let seatbelt = aegis_types::AegisConfig {
            name: "test".into(),
            sandbox_dir: "/tmp".into(),
            policy_paths: vec![],
            schema_path: None,
            ledger_path: "/tmp/audit.db".into(),
            allowed_network: vec![],
            isolation: aegis_types::IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
            observer: aegis_types::ObserverConfig::default(),
            alerts: Vec::new(),
        };
        assert!(describe_isolation(&seatbelt).contains("Seatbelt"));

        let process = aegis_types::AegisConfig {
            isolation: aegis_types::IsolationConfig::Process,
            ..seatbelt.clone()
        };
        assert!(describe_isolation(&process).contains("Process"));

        let none = aegis_types::AegisConfig {
            isolation: aegis_types::IsolationConfig::None,
            ..seatbelt
        };
        assert_eq!(none.observer.to_string(), "FsEvents (snapshots: enabled)");
    }

    #[test]
    fn describe_observer_variants() {
        assert_eq!(aegis_types::ObserverConfig::None.to_string(), "None");
        assert!(
            aegis_types::ObserverConfig::FsEvents { enable_snapshots: false }
                .to_string()
                .contains("disabled")
        );
        assert!(
            aegis_types::ObserverConfig::EndpointSecurity
                .to_string()
                .contains("Endpoint")
        );
    }
}
