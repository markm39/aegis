//! Configuration initialization and interactive setup wizard.
//!
//! `aegis init [NAME]` creates a new configuration at `~/.aegis/NAME/` with
//! a policy file, sandbox directory, and TOML config. Without arguments,
//! launches an interactive wizard for guided setup.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dialoguer::{Confirm, Input, Select};

use aegis_policy::builtin::get_builtin_policy;
use aegis_types::{AegisConfig, IsolationConfig, CONFIG_FILENAME, DEFAULT_POLICY_FILENAME};

/// Run the `aegis init` command.
///
/// Creates the directory structure at `~/.aegis/NAME/` with a config file,
/// policies directory containing the selected builtin policy, and a sandbox
/// directory.
///
/// If `name` is `None`, launches the interactive setup wizard.
/// If `project_dir` is provided, the sandbox directory is set to it instead
/// of the default `~/.aegis/NAME/sandbox/`.
pub fn run(name: Option<&str>, policy_template: &str, project_dir: Option<&Path>) -> Result<()> {
    let name = match name {
        Some(n) => n,
        None => return run_wizard(),
    };
    ensure_aegis_dir()?;
    let base_dir = aegis_base_dir(name)?;
    run_in_dir(name, policy_template, &base_dir, project_dir)?;
    // Auto-set as current config
    crate::commands::use_config::set_current(name)?;
    Ok(())
}

/// Security mode options for the interactive wizard.
#[derive(Debug, Clone, Copy)]
pub enum SecurityMode {
    /// Log all file activity, enforce nothing
    ObserveOnly,
    /// Allow reads, block writes (Seatbelt)
    ReadOnlySandbox,
    /// Block everything by default (Seatbelt)
    FullLockdown,
}

impl SecurityMode {
    /// Map a security mode to its policy template name and isolation config.
    pub fn to_config(self) -> (&'static str, IsolationConfig) {
        match self {
            SecurityMode::ObserveOnly => ("permit-all", IsolationConfig::Process),
            SecurityMode::ReadOnlySandbox => (
                "allow-read-only",
                IsolationConfig::Seatbelt {
                    profile_overrides: None,
                },
            ),
            SecurityMode::FullLockdown => (
                "default-deny",
                IsolationConfig::Seatbelt {
                    profile_overrides: None,
                },
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            SecurityMode::ObserveOnly => "Observe only       -- Log all file activity, enforce nothing",
            SecurityMode::ReadOnlySandbox => "Read-only sandbox  -- Allow reads, block writes (Seatbelt)",
            SecurityMode::FullLockdown => "Full lockdown      -- Block everything by default (Seatbelt)",
        }
    }
}

const SECURITY_MODES: [SecurityMode; 3] = [
    SecurityMode::ObserveOnly,
    SecurityMode::ReadOnlySandbox,
    SecurityMode::FullLockdown,
];

/// Interactive setup wizard for `aegis init` with no arguments.
fn run_wizard() -> Result<()> {
    println!("Aegis Setup Wizard");
    println!("==================\n");

    // Default name from CWD basename
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let default_name = cwd
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "my-project".to_string());

    let name: String = Input::new()
        .with_prompt("Configuration name")
        .default(default_name)
        .interact_text()
        .context("failed to read configuration name")?;

    // Security mode selection
    let mode_labels: Vec<&str> = SECURITY_MODES.iter().map(|m| m.label()).collect();
    let mode_index = Select::new()
        .with_prompt("Security mode")
        .items(&mode_labels)
        .default(0)
        .interact()
        .context("failed to read security mode")?;

    let mode = SECURITY_MODES[mode_index];
    let (policy, isolation) = mode.to_config();

    // Project directory
    let default_dir = cwd.display().to_string();
    let dir_str: String = Input::new()
        .with_prompt("Project directory")
        .default(default_dir)
        .interact_text()
        .context("failed to read project directory")?;

    let project_dir = PathBuf::from(&dir_str);

    // Summary
    let isolation_desc = match &isolation {
        IsolationConfig::Process => "Process (no kernel enforcement)",
        IsolationConfig::Seatbelt { .. } => "Seatbelt (macOS kernel sandbox)",
        IsolationConfig::None => "None",
    };

    println!("\nSummary:");
    println!("  Name:      {name}");
    println!("  Mode:      {}", SECURITY_MODES[mode_index].label().split("  --").next().unwrap_or(""));
    println!("  Policy:    {policy}");
    println!("  Isolation: {isolation_desc}");
    println!("  Directory: {dir_str}");
    println!("  Config at: ~/.aegis/{name}/");

    let confirmed = Confirm::new()
        .with_prompt("\nCreate this configuration?")
        .default(true)
        .interact()
        .context("failed to read confirmation")?;

    if !confirmed {
        println!("Aborted.");
        return Ok(());
    }

    // Create the config
    ensure_aegis_dir()?;
    let base_dir = aegis_base_dir(&name)?;

    // Use run_in_dir_with_isolation to create with the chosen isolation mode
    run_in_dir_with_isolation(&name, policy, &base_dir, Some(&project_dir), isolation)?;

    // Auto-set as current config
    crate::commands::use_config::set_current(&name)?;

    println!("\nNext steps:");
    println!("  aegis run echo hello          # sandbox a command");
    println!("  aegis wrap claude             # observe an agent");
    println!("  aegis monitor {name}      # live dashboard");
    println!("  aegis audit query {name}  # query audit trail");

    Ok(())
}

/// Inner init logic that operates on an explicit base directory.
/// This allows tests to provide a custom directory without modifying HOME.
///
/// If `project_dir` is `Some`, the sandbox directory is set to that path
/// instead of the default `base_dir/sandbox/`.
pub fn run_in_dir(
    name: &str,
    policy_template: &str,
    base_dir: &Path,
    project_dir: Option<&Path>,
) -> Result<()> {
    run_in_dir_with_isolation(name, policy_template, base_dir, project_dir, IsolationConfig::Seatbelt { profile_overrides: None })
}

/// Inner init logic with explicit isolation config.
///
/// Used by the wizard to create configs with non-default isolation modes.
pub fn run_in_dir_with_isolation(
    name: &str,
    policy_template: &str,
    base_dir: &Path,
    project_dir: Option<&Path>,
    isolation: IsolationConfig,
) -> Result<()> {
    if base_dir.exists() {
        bail!(
            "configuration directory already exists: {}",
            base_dir.display()
        );
    }

    // Look up the builtin policy text
    let policy_text = get_builtin_policy(policy_template).with_context(|| {
        format!(
            "unknown policy template '{policy_template}'; valid options: {}", aegis_policy::builtin::list_builtin_policies().join(", ")
        )
    })?;

    // Resolve sandbox directory
    let sandbox_dir = match project_dir {
        Some(dir) => {
            let canonical = dir
                .canonicalize()
                .with_context(|| format!("--dir path does not exist: {}", dir.display()))?;
            if !canonical.is_dir() {
                bail!("--dir path is not a directory: {}", canonical.display());
            }
            canonical
        }
        None => base_dir.join("sandbox"),
    };

    // Create directory structure
    let policies_dir = base_dir.join("policies");

    fs::create_dir_all(&policies_dir)
        .with_context(|| format!("failed to create policies dir: {}", policies_dir.display()))?;
    fs::create_dir_all(&sandbox_dir)
        .with_context(|| format!("failed to create sandbox dir: {}", sandbox_dir.display()))?;

    // Write the builtin policy as default.cedar
    let policy_file = policies_dir.join(DEFAULT_POLICY_FILENAME);
    fs::write(&policy_file, policy_text)
        .with_context(|| format!("failed to write policy file: {}", policy_file.display()))?;

    // Generate and write the config with specified isolation
    let mut config = AegisConfig::default_for_with_sandbox(name, base_dir, sandbox_dir.clone());
    config.isolation = isolation;
    let toml_content = config
        .to_toml()
        .context("failed to serialize config to TOML")?;

    let config_path = base_dir.join(CONFIG_FILENAME);
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

/// Ensure `~/.aegis/` exists, creating it if needed.
///
/// Replaces the requirement to run `aegis setup` before using other commands.
pub fn ensure_aegis_dir() -> Result<PathBuf> {
    let home = dirs_from_env()?;
    let aegis_dir = home.join(".aegis");
    fs::create_dir_all(&aegis_dir)
        .with_context(|| format!("failed to create directory: {}", aegis_dir.display()))?;
    Ok(aegis_dir)
}

/// Resolve the config directory for a named configuration.
///
/// Searches init configs (`~/.aegis/NAME/`) first, then wrap configs
/// (`~/.aegis/wraps/NAME/`). Falls through to the init path for error
/// messages if neither exists.
pub fn resolve_config_dir(name: &str) -> Result<PathBuf> {
    let init_dir = aegis_base_dir(name)?;
    if init_dir.join(CONFIG_FILENAME).exists() {
        return Ok(init_dir);
    }
    let wrap_dir = super::wrap::wraps_base_dir()?.join(name);
    if wrap_dir.join(CONFIG_FILENAME).exists() {
        return Ok(wrap_dir);
    }
    Ok(init_dir) // fall through for error messages
}

/// Get the user's home directory from the HOME environment variable.
pub fn dirs_from_env() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable is not set")
}

/// Load an AegisConfig by name.
///
/// Searches init configs (`~/.aegis/NAME/`) first, then wrap configs
/// (`~/.aegis/wraps/NAME/`), allowing unified queries across both namespaces.
pub fn load_config(name: &str) -> Result<AegisConfig> {
    let config_dir = resolve_config_dir(name)?;
    load_config_from_dir(&config_dir)
}

/// Load config by name and open the audit store in one step.
///
/// Nearly every CLI subcommand starts with this exact 2-line pattern, so
/// centralizing it eliminates 13+ repeated `.context("failed to open audit store")` calls.
pub fn open_store(config_name: &str) -> Result<(AegisConfig, aegis_ledger::AuditStore)> {
    let config = load_config(config_name)?;
    let store = aegis_ledger::AuditStore::open(&config.ledger_path)
        .context("failed to open audit store")?;
    Ok((config, store))
}

/// Load an AegisConfig from an explicit base directory.
pub fn load_config_from_dir(base_dir: &Path) -> Result<AegisConfig> {
    let config_path = base_dir.join(CONFIG_FILENAME);

    let content = fs::read_to_string(&config_path).with_context(|| {
        format!(
            "configuration '{}' not found at {}\n  \
             Hint: run 'aegis init {}' to create it, or 'aegis list' to see existing configs",
            base_dir.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
            config_path.display(),
            base_dir.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
        )
    })?;

    AegisConfig::from_toml(&content).with_context(|| {
        format!("failed to parse {}", config_path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_mode_observe_only_config() {
        let (policy, isolation) = SecurityMode::ObserveOnly.to_config();
        assert_eq!(policy, "permit-all");
        assert!(matches!(isolation, IsolationConfig::Process));
    }

    #[test]
    fn security_mode_read_only_config() {
        let (policy, isolation) = SecurityMode::ReadOnlySandbox.to_config();
        assert_eq!(policy, "allow-read-only");
        assert!(matches!(isolation, IsolationConfig::Seatbelt { .. }));
    }

    #[test]
    fn security_mode_full_lockdown_config() {
        let (policy, isolation) = SecurityMode::FullLockdown.to_config();
        assert_eq!(policy, "default-deny");
        assert!(matches!(isolation, IsolationConfig::Seatbelt { .. }));
    }

    #[test]
    fn run_in_dir_creates_config_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("test-cfg");

        run_in_dir("test-cfg", "permit-all", &base_dir, None).unwrap();

        // Config file should exist
        assert!(base_dir.join(CONFIG_FILENAME).exists());
        // Policy file should exist
        assert!(base_dir.join("policies").join(DEFAULT_POLICY_FILENAME).exists());
        // Sandbox dir should exist
        assert!(base_dir.join("sandbox").is_dir());
    }

    #[test]
    fn run_in_dir_fails_if_dir_exists() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("existing");
        fs::create_dir_all(&base_dir).unwrap();

        let result = run_in_dir("existing", "permit-all", &base_dir, None);
        assert!(result.is_err());
    }

    #[test]
    fn run_in_dir_with_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("my-cfg");
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();

        run_in_dir("my-cfg", "allow-read-only", &base_dir, Some(&project)).unwrap();

        // Config should reference the project directory as sandbox
        let config = load_config_from_dir(&base_dir).unwrap();
        assert_eq!(config.sandbox_dir, project.canonicalize().unwrap());
    }

    #[test]
    fn run_in_dir_unknown_template_fails() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("bad-template");

        let result = run_in_dir("bad-template", "nonexistent", &base_dir, None);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_from_dir_nonexistent_fails() {
        let result = load_config_from_dir(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn load_config_from_dir_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("roundtrip");

        run_in_dir("roundtrip", "default-deny", &base_dir, None).unwrap();

        let config = load_config_from_dir(&base_dir).unwrap();
        assert_eq!(config.name, "roundtrip");
    }
}
