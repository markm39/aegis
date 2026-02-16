use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use aegis_policy::builtin::get_builtin_policy;
use aegis_types::AegisConfig;

/// Run the `aegis init` command.
///
/// Creates the directory structure at `~/.aegis/NAME/` with a config file,
/// policies directory containing the selected builtin policy, and a sandbox
/// directory.
pub fn run(name: &str, policy_template: &str) -> Result<()> {
    let base_dir = aegis_base_dir(name)?;
    run_in_dir(name, policy_template, &base_dir)
}

/// Inner init logic that operates on an explicit base directory.
/// This allows tests to provide a custom directory without modifying HOME.
pub fn run_in_dir(name: &str, policy_template: &str, base_dir: &Path) -> Result<()> {
    if base_dir.exists() {
        bail!(
            "configuration directory already exists: {}",
            base_dir.display()
        );
    }

    // Look up the builtin policy text
    let policy_text = get_builtin_policy(policy_template).with_context(|| {
        format!(
            "unknown policy template '{policy_template}'; valid options: default-deny, allow-read-only"
        )
    })?;

    // Create directory structure
    let policies_dir = base_dir.join("policies");
    let sandbox_dir = base_dir.join("sandbox");

    fs::create_dir_all(&policies_dir)
        .with_context(|| format!("failed to create policies dir: {}", policies_dir.display()))?;
    fs::create_dir_all(&sandbox_dir)
        .with_context(|| format!("failed to create sandbox dir: {}", sandbox_dir.display()))?;

    // Write the builtin policy as default.cedar
    let policy_file = policies_dir.join("default.cedar");
    fs::write(&policy_file, policy_text)
        .with_context(|| format!("failed to write policy file: {}", policy_file.display()))?;

    // Generate and write the config
    let config = AegisConfig::default_for(name, base_dir);
    let toml_content = config
        .to_toml()
        .context("failed to serialize config to TOML")?;

    let config_path = base_dir.join("aegis.toml");
    fs::write(&config_path, &toml_content)
        .with_context(|| format!("failed to write config: {}", config_path.display()))?;

    println!("Initialized aegis configuration at {}", base_dir.display());
    println!("  Config:  {}", config_path.display());
    println!("  Policy:  {} ({})", policy_file.display(), policy_template);
    println!("  Sandbox: {}", sandbox_dir.display());

    Ok(())
}

/// Resolve the base directory for a named aegis configuration: `~/.aegis/NAME/`.
pub fn aegis_base_dir(name: &str) -> Result<PathBuf> {
    let home = dirs_from_env()?;
    Ok(home.join(".aegis").join(name))
}

/// Get the user's home directory from the HOME environment variable.
fn dirs_from_env() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable is not set")
}

/// Load an AegisConfig by name from `~/.aegis/NAME/aegis.toml`.
pub fn load_config(name: &str) -> Result<AegisConfig> {
    let base_dir = aegis_base_dir(name)?;
    load_config_from_dir(&base_dir)
}

/// Load an AegisConfig from an explicit base directory.
pub fn load_config_from_dir(base_dir: &Path) -> Result<AegisConfig> {
    let config_path = base_dir.join("aegis.toml");

    let content = fs::read_to_string(&config_path).with_context(|| {
        format!(
            "failed to read config file: {}",
            config_path.display(),
        )
    })?;

    AegisConfig::from_toml(&content).context("failed to parse aegis.toml")
}
