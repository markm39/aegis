use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context, Result};

use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::default_schema;

use crate::commands::init::load_config;

/// Run `aegis policy validate --path FILE`.
///
/// Reads a .cedar file, parses it as a PolicySet, loads the default schema,
/// and validates.
pub fn validate(path: &Path) -> Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    // Attempt to parse as a PolicySet
    let policy_set = match cedar_policy::PolicySet::from_str(&content) {
        Ok(ps) => ps,
        Err(e) => {
            println!("INVALID: failed to parse policy file");
            println!("  Error: {e}");
            return Ok(());
        }
    };

    let policy_count = policy_set.policies().count();

    // Load the default schema and validate
    let schema = default_schema().context("failed to load Aegis schema")?;
    let validation_result =
        cedar_policy::Validator::new(schema).validate(&policy_set, cedar_policy::ValidationMode::Strict);

    if validation_result.validation_passed() {
        println!("VALID: {} policies parsed and validated successfully", policy_count);
    } else {
        println!("INVALID: policy parsed but has validation errors:");
        for error in validation_result.validation_errors() {
            println!("  - {error}");
        }
    }

    Ok(())
}

/// Run `aegis policy list --config NAME`.
///
/// Lists all .cedar files in the first policy path, showing filenames and
/// first lines.
pub fn list(config_name: &str) -> Result<()> {
    let config = load_config(config_name)?;

    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;

    if !policy_dir.exists() {
        println!("No policy directory found at {}", policy_dir.display());
        return Ok(());
    }

    let entries = fs::read_dir(policy_dir)
        .with_context(|| format!("failed to read directory: {}", policy_dir.display()))?;

    let mut found = false;
    for entry in entries {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "cedar") {
            found = true;
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();

            let first_line = fs::read_to_string(&path)
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|line| !line.trim().is_empty())
                        .map(|line| line.trim().to_string())
                })
                .unwrap_or_else(|| "(empty)".to_string());

            println!("  {filename}: {first_line}");
        }
    }

    if !found {
        println!("No .cedar files found in {}", policy_dir.display());
    }

    Ok(())
}

/// Run `aegis policy generate --template NAME`.
///
/// Looks up a builtin policy by name and prints it to stdout.
pub fn generate(template_name: &str) -> Result<()> {
    match get_builtin_policy(template_name) {
        Some(policy_text) => {
            print!("{policy_text}");
            Ok(())
        }
        None => {
            bail!(
                "unknown policy template '{template_name}'; valid options: default-deny, allow-read-only"
            );
        }
    }
}
