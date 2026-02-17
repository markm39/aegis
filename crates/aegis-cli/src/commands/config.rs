/// Display the full configuration for a named Aegis config.
///
/// `aegis config show NAME` loads the config from either the init or wrap
/// namespace and prints all fields in a human-readable format.
use std::fs;

use anyhow::Result;

use aegis_types::AegisConfig;

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
    println!("  Observer:   {}", describe_observer(&config));

    if config.allowed_network.is_empty() {
        println!("  Network:    (no rules)");
    } else {
        println!("  Network:");
        for rule in &config.allowed_network {
            let port = rule
                .port
                .map(|p| format!(":{p}"))
                .unwrap_or_default();
            println!("    - {:?} {}{}", rule.protocol, rule.host, port);
        }
    }

    if let Some(schema) = &config.schema_path {
        println!("  Schema:     {}", schema.display());
    }

    println!("  Config at:  {}", config_dir.join("aegis.toml").display());

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

fn describe_observer(config: &AegisConfig) -> String {
    match &config.observer {
        aegis_types::ObserverConfig::None => "None".to_string(),
        aegis_types::ObserverConfig::FsEvents { enable_snapshots } => {
            if *enable_snapshots {
                "FsEvents (snapshots: enabled)".to_string()
            } else {
                "FsEvents (snapshots: disabled)".to_string()
            }
        }
        aegis_types::ObserverConfig::EndpointSecurity => "Endpoint Security".to_string(),
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
        assert_eq!(describe_observer(&none), "FsEvents (snapshots: enabled)");
    }

    #[test]
    fn describe_observer_variants() {
        let config = aegis_types::AegisConfig {
            name: "test".into(),
            sandbox_dir: "/tmp".into(),
            policy_paths: vec![],
            schema_path: None,
            ledger_path: "/tmp/audit.db".into(),
            allowed_network: vec![],
            isolation: aegis_types::IsolationConfig::Process,
            observer: aegis_types::ObserverConfig::None,
        };
        assert_eq!(describe_observer(&config), "None");

        let fsevents = aegis_types::AegisConfig {
            observer: aegis_types::ObserverConfig::FsEvents {
                enable_snapshots: false,
            },
            ..config.clone()
        };
        assert!(describe_observer(&fsevents).contains("disabled"));

        let es = aegis_types::AegisConfig {
            observer: aegis_types::ObserverConfig::EndpointSecurity,
            ..config
        };
        assert!(describe_observer(&es).contains("Endpoint"));
    }
}
