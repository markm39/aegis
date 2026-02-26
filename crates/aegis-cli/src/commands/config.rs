//! Configuration management commands.
//!
//! `aegis config show NAME`   -- display all settings
//! `aegis config path NAME`   -- print the config file path
//! `aegis config edit NAME`   -- open config in $EDITOR
//! `aegis config get KEY`     -- read a value using dot-notation
//! `aegis config set KEY VAL` -- write a value using dot-notation
//! `aegis config list`        -- show all effective config key-value pairs
//! `aegis config layers`      -- show which config files are active

use std::fs;

use anyhow::{Context, Result, bail};

use aegis_types::{AegisConfig, CONFIG_FILENAME};
use aegis_types::{
    ConfigLoader, flatten_toml, format_toml_value, get_dot_value, is_sensitive_field,
    mask_sensitive, set_dot_value,
};

use crate::commands::init::{load_config, resolve_config_dir};

/// Run `aegis config show NAME`.
pub fn show(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let config_dir = resolve_config_dir(config_name)?;

    // Determine config type
    let config_type = if config_dir.to_string_lossy().contains(".aegis/wraps/") {
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

    println!(
        "  Config at:  {}",
        config_dir.join(CONFIG_FILENAME).display()
    );

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

    // Save original content so we can restore on validation failure
    let original = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

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
            // Restore the original valid config. Save the invalid edit to .bak.
            let bak_path = config_path.with_extension("toml.bak");
            let _ = fs::write(&bak_path, &content);
            fs::write(&config_path, &original)?;
            bail!(
                "Invalid config: {e}\n\
                 Original config restored. Your edit saved to {}.",
                bak_path.display()
            );
        }
    }

    Ok(())
}

/// Run `aegis config get KEY`.
///
/// Reads a value from the effective (merged) configuration using dot-notation.
/// Example: `aegis config get pilot.stall.timeout_secs`
pub fn get(key: &str) -> Result<()> {
    let loader = ConfigLoader::new();
    let effective = loader
        .load()
        .map_err(|e| anyhow::anyhow!("failed to load config: {e}"))?;

    let toml_value = toml::Value::try_from(&effective.config)
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;

    match get_dot_value(&toml_value, key) {
        Some(val) => {
            let display = if is_sensitive_field(key) {
                match &val {
                    toml::Value::String(s) => mask_sensitive(s),
                    other => format_toml_value(other),
                }
            } else {
                format_toml_value(&val)
            };
            println!("{display}");
        }
        None => {
            bail!("key '{key}' not found in effective config");
        }
    }

    // Show provenance if available
    if let Some(source) = effective.sources.get(key) {
        eprintln!("  (source: {source})");
    }

    Ok(())
}

/// Run `aegis config set KEY VALUE`.
///
/// Writes a value to the workspace config file (.aegis/config.toml) using
/// dot-notation. Creates the file if it doesn't exist.
/// Example: `aegis config set pilot.stall.timeout_secs 60`
pub fn set(key: &str, value: &str) -> Result<()> {
    let workspace_path = std::path::PathBuf::from(".aegis/config.toml");

    // Read existing workspace config or start from empty table
    let mut toml_value = if workspace_path.exists() {
        let content = fs::read_to_string(&workspace_path)
            .with_context(|| format!("failed to read {}", workspace_path.display()))?;
        content
            .parse::<toml::Value>()
            .map_err(|e| anyhow::anyhow!("invalid workspace config: {e}"))?
    } else {
        // Ensure parent directory exists
        if let Some(parent) = workspace_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        toml::Value::Table(toml::map::Map::new())
    };

    set_dot_value(&mut toml_value, key, value)
        .map_err(|e| anyhow::anyhow!("failed to set value: {e}"))?;

    // Serialize back to TOML
    let output = toml::to_string_pretty(&toml_value)
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;
    fs::write(&workspace_path, &output)
        .with_context(|| format!("failed to write {}", workspace_path.display()))?;

    println!("Set {key} = {value} in {}", workspace_path.display());
    Ok(())
}

/// Run `aegis config list`.
///
/// Shows all effective configuration values as dot-separated key-value pairs.
/// Sensitive fields (tokens, keys) are masked.
pub fn list() -> Result<()> {
    let loader = ConfigLoader::new();
    let effective = loader
        .load()
        .map_err(|e| anyhow::anyhow!("failed to load config: {e}"))?;

    let toml_value = toml::Value::try_from(&effective.config)
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;

    let mut entries = Vec::new();
    flatten_toml(&toml_value, "", &mut entries);

    if entries.is_empty() {
        println!("(no configuration values)");
        return Ok(());
    }

    // Find the longest key for alignment
    let max_key_len = entries.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

    for (key, value) in &entries {
        let source_tag = effective
            .sources
            .get(key)
            .map(|s| format!("  [{s}]"))
            .unwrap_or_default();
        println!("{key:<max_key_len$}  {value}{source_tag}");
    }

    Ok(())
}

/// Run `aegis config layers`.
///
/// Shows which config files exist and how many keys each defines.
pub fn layers() -> Result<()> {
    let loader = ConfigLoader::new();
    let layer_infos = loader.discover_layers();

    println!("Config layers (lowest to highest priority):\n");

    for (i, info) in layer_infos.iter().enumerate() {
        let priority = i + 1;
        let status = if info.exists {
            format!("active ({} keys)", info.key_count)
        } else {
            "not found".to_string()
        };
        println!("  {priority}. {}", info.source);
        println!("     Status: {status}");
        println!();
    }

    // Also show env var overrides
    let env_count = aegis_types::config_loader::ENV_MAPPINGS
        .iter()
        .filter(|m| std::env::var(m.env_var).is_ok())
        .count();
    if env_count > 0 {
        println!("  4. Environment variables");
        println!("     Status: {env_count} override(s) active");
        println!();
    }

    Ok(())
}

fn describe_isolation(config: &AegisConfig) -> String {
    match &config.isolation {
        aegis_types::IsolationConfig::Seatbelt { profile_overrides, .. } => {
            if let Some(path) = profile_overrides {
                format!("Seatbelt (custom profile: {})", path.display())
            } else {
                "Seatbelt (macOS kernel sandbox)".to_string()
            }
        }
        aegis_types::IsolationConfig::Docker(cfg) => {
            format!("Docker (image: {}, network: {})", cfg.image, cfg.network)
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
                deny_paths: vec![],
            },
            observer: aegis_types::ObserverConfig::default(),
            alerts: Vec::new(),
            pilot: None,
            channel: None,
            usage_proxy: None,
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
            aegis_types::ObserverConfig::FsEvents {
                enable_snapshots: false
            }
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
