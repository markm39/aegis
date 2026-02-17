//! Configuration initialization and interactive setup wizard.
//!
//! `aegis init [NAME]` creates a new configuration at `~/.aegis/NAME/` with
//! a policy file, sandbox directory, and TOML config. Without arguments,
//! launches an interactive wizard for guided setup.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};

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

    // Security mode selection (presets + custom option)
    let mut choices: Vec<String> = SECURITY_MODES
        .iter()
        .map(|m| m.label().to_string())
        .collect();
    choices.push("Custom             -- Pick specific capabilities".to_string());
    let choice_refs: Vec<&str> = choices.iter().map(|s| s.as_str()).collect();

    let mode_index = Select::new()
        .with_prompt("Security mode")
        .items(&choice_refs)
        .default(0)
        .interact()
        .context("failed to read security mode")?;

    let (policy_text, isolation) = if mode_index < SECURITY_MODES.len() {
        let mode = SECURITY_MODES[mode_index];
        let (template, isolation) = mode.to_config();
        let text = get_builtin_policy(template).unwrap().to_string();
        (text, isolation)
    } else {
        build_custom_policy()?
    };

    // Project directory selection
    let home_dir = dirs_from_env()?;
    let cwd_label = format!("Current directory: {}", cwd.display());
    let home_label = format!("Home directory:    {}", home_dir.display());
    let custom_label = "Custom path (type a path)".to_string();
    let dir_choices = vec![&cwd_label, &home_label, &custom_label];
    let dir_index = Select::new()
        .with_prompt("Project directory")
        .items(&dir_choices)
        .default(0)
        .interact()
        .context("failed to read directory selection")?;

    let project_dir = match dir_index {
        0 => cwd.clone(),
        1 => home_dir,
        _ => {
            let dir_str: String = Input::new()
                .with_prompt("Enter path")
                .interact_text()
                .context("failed to read directory path")?;
            PathBuf::from(dir_str)
        }
    };
    let dir_str = project_dir.display().to_string();

    // Summary
    let isolation_desc = match &isolation {
        IsolationConfig::Process => "Process (no kernel enforcement)",
        IsolationConfig::Seatbelt { .. } => "Seatbelt (macOS kernel sandbox)",
        IsolationConfig::None => "None",
    };

    let mode_desc = if mode_index < SECURITY_MODES.len() {
        SECURITY_MODES[mode_index]
            .label()
            .split("  --")
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        "Custom".to_string()
    };

    println!("\nSummary:");
    println!("  Name:      {name}");
    println!("  Mode:      {mode_desc}");
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
    create_config(&name, &policy_text, &base_dir, Some(&project_dir), isolation)?;

    // Auto-set as current config
    crate::commands::use_config::set_current(&name)?;

    println!("\nYou're all set. Active config: {name}");
    println!("\nNext steps:");
    println!("  aegis wrap claude    # observe an AI agent");
    println!("  aegis monitor        # live TUI dashboard");
    println!("  aegis log            # view audit trail");

    Ok(())
}

/// Capability labels shown in the interactive MultiSelect.
const CAPABILITY_LABELS: &[&str] = &[
    "Read files in the project directory",
    "Write/modify files",
    "Delete files",
    "Create new directories",
    "Access the network",
];

/// Cedar action names corresponding to each capability.
const CAPABILITY_ACTIONS: &[&[&str]] = &[
    &["FileRead"],
    &["FileWrite"],
    &["FileDelete"],
    &["DirCreate"],
    &["NetConnect"],
];

/// Build a Cedar policy from user-selected capabilities.
///
/// Shows a MultiSelect checklist of capabilities. Selected items become
/// Cedar `permit` statements. DirList, ProcessSpawn, and ProcessExit are
/// always included (required for basic Aegis operation).
///
/// Returns `(policy_text, isolation_config)`. Uses Seatbelt when any
/// capability is denied; Process when everything is permitted.
fn build_custom_policy() -> Result<(String, IsolationConfig)> {
    let defaults = vec![true, false, false, false, false];
    let selected = MultiSelect::new()
        .with_prompt("What should this agent be allowed to do?")
        .items(CAPABILITY_LABELS)
        .defaults(&defaults)
        .interact()
        .context("failed to read capability selection")?;

    // Collect all permitted actions (always include infrastructure actions)
    let mut actions: Vec<&str> = vec!["DirList", "ProcessSpawn", "ProcessExit"];
    let mut allowed_display: Vec<&str> = Vec::new();
    let mut denied_display: Vec<&str> = Vec::new();

    for (i, &label) in CAPABILITY_LABELS.iter().enumerate() {
        if selected.contains(&i) {
            for &action in CAPABILITY_ACTIONS[i] {
                actions.push(action);
            }
            allowed_display.push(label);
        } else {
            denied_display.push(label);
        }
    }

    actions.sort();
    actions.dedup();

    // Generate Cedar policy text
    let policy_text = generate_cedar_policy(&actions);

    // Show summary
    if !allowed_display.is_empty() {
        println!("\n  ALLOW: {}", allowed_display.join(", "));
    }
    if !denied_display.is_empty() {
        println!("  DENY:  {}", denied_display.join(", "));
    }

    // If everything is allowed, no need for kernel enforcement
    let all_allowed = selected.len() == CAPABILITY_LABELS.len();
    let isolation = if all_allowed {
        IsolationConfig::Process
    } else {
        IsolationConfig::Seatbelt {
            profile_overrides: None,
        }
    };

    Ok((policy_text, isolation))
}

/// Generate Cedar policy text from a list of action names.
pub fn generate_cedar_policy(actions: &[&str]) -> String {
    let mut policy = String::new();
    for action in actions {
        policy.push_str(&format!(
            "permit(\n    principal,\n    action == Aegis::Action::\"{action}\",\n    resource\n);\n\n"
        ));
    }
    policy
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
    let policy_text = get_builtin_policy(policy_template).with_context(|| {
        format!(
            "unknown policy template '{policy_template}'; valid options: {}", aegis_policy::builtin::list_builtin_policies().join(", ")
        )
    })?;

    create_config(name, policy_text, base_dir, project_dir, isolation)
}

/// Create a config directory with explicit policy text and isolation config.
///
/// Core init logic shared by `run_in_dir_with_isolation` (builtin templates)
/// and the wizard's custom capability builder (generated Cedar text).
fn create_config(
    name: &str,
    policy_text: &str,
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

    // Write the policy as default.cedar
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
    println!("  Policy:  {}", policy_file.display());
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

    #[test]
    fn generate_cedar_policy_produces_valid_cedar() {
        let actions = ["FileRead", "DirList", "ProcessSpawn", "ProcessExit"];
        let policy_text = generate_cedar_policy(&actions);

        // Should parse as valid Cedar
        let pset: Result<cedar_policy::PolicySet, _> = policy_text.parse();
        assert!(pset.is_ok(), "generated policy should parse: {pset:?}");
        assert_eq!(pset.unwrap().policies().count(), 4);
    }

    #[test]
    fn generate_cedar_policy_empty_actions() {
        let policy_text = generate_cedar_policy(&[]);
        assert!(policy_text.is_empty());
    }

    #[test]
    fn create_config_with_custom_policy() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("custom-cfg");

        let actions = ["FileRead", "DirList", "ProcessSpawn", "ProcessExit"];
        let policy_text = generate_cedar_policy(&actions);

        create_config(
            "custom-cfg",
            &policy_text,
            &base_dir,
            None,
            IsolationConfig::Seatbelt { profile_overrides: None },
        )
        .unwrap();

        assert!(base_dir.join(CONFIG_FILENAME).exists());
        assert!(base_dir.join("policies").join(DEFAULT_POLICY_FILENAME).exists());

        // Verify the policy file contains our generated Cedar
        let saved_policy = fs::read_to_string(
            base_dir.join("policies").join(DEFAULT_POLICY_FILENAME),
        )
        .unwrap();
        assert!(saved_policy.contains("FileRead"));
        assert!(saved_policy.contains("DirList"));
    }

    #[test]
    fn capability_arrays_match_length() {
        assert_eq!(
            CAPABILITY_LABELS.len(),
            CAPABILITY_ACTIONS.len(),
            "labels and actions arrays must have same length"
        );
    }
}
