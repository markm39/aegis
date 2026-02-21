//! Configuration initialization and interactive setup wizard.
//!
//! `aegis init [NAME]` creates a new configuration at `~/.aegis/NAME/` with
//! a policy file, sandbox directory, and TOML config. Without arguments,
//! launches an interactive wizard for guided setup.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dialoguer::Confirm;

use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::PolicyEngine;

/// Maximum display width for a resource path before truncation.
const MAX_RESOURCE_DISPLAY_LEN: usize = 40;
use aegis_types::{
    Action, ActionKind, AegisConfig, Decision, IsolationConfig, CONFIG_FILENAME,
    DEFAULT_POLICY_FILENAME,
};

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

/// Return the strongest available isolation for this platform.
///
/// On macOS, this returns Seatbelt (kernel sandbox). On other platforms,
/// Seatbelt is unavailable so we fall back to Process isolation.
fn platform_isolation() -> IsolationConfig {
    if cfg!(target_os = "macos") {
        IsolationConfig::Seatbelt {
            profile_overrides: None,
        }
    } else {
        IsolationConfig::Process
    }
}

/// Interactive TUI setup wizard for `aegis init` with no arguments.
///
/// Launches a ratatui-based wizard that matches the visual style of the
/// Aegis monitor dashboard. Returns the user's selections which are then
/// used to create the config via `create_config()`.
fn run_wizard() -> Result<()> {
    let result = crate::wizard::run_wizard().context("wizard failed")?;

    if result.cancelled {
        println!("Aborted.");
        return Ok(());
    }

    // Create the config
    ensure_aegis_dir()?;
    let base_dir = aegis_base_dir(&result.name)?;
    create_config(
        &result.name,
        &result.policy_text,
        &base_dir,
        Some(&result.project_dir),
        result.isolation,
    )?;

    // Auto-set as current config
    crate::commands::use_config::set_current(&result.name)?;

    // Offer policy demo (in CLI mode, after TUI closes)
    run_policy_demo(&result.name, &result.policy_text, &result.project_dir)?;

    println!("\nYou're all set. Active config: {}", result.name);
    println!("\nNext steps:");
    println!("  aegis wrap claude    # observe an AI agent");
    println!("  aegis monitor        # live TUI dashboard");
    println!("  aegis log            # view audit trail");

    Ok(())
}

/// Run a policy demo showing what actions would be allowed or denied.
///
/// Creates a temporary PolicyEngine from the policy text and tests
/// representative actions against it. Only runs if the user opts in.
fn run_policy_demo(agent_name: &str, policy_text: &str, project_dir: &Path) -> Result<()> {
    let demo = Confirm::new()
        .with_prompt("Test this policy? (shows what would be allowed/denied)")
        .default(true)
        .interact()
        .context("failed to read demo preference")?;

    if !demo {
        return Ok(());
    }

    let engine = match PolicyEngine::from_policies(policy_text, None) {
        Ok(e) => e,
        Err(e) => {
            println!("  (skipping demo: {e})");
            return Ok(());
        }
    };

    let sample_file = project_dir.join("README.md");

    let test_actions: Vec<(&str, ActionKind)> = vec![
        (
            "FileRead",
            ActionKind::FileRead {
                path: sample_file.clone(),
            },
        ),
        (
            "FileWrite",
            ActionKind::FileWrite {
                path: sample_file.clone(),
            },
        ),
        ("FileDelete", ActionKind::FileDelete { path: sample_file }),
        (
            "DirCreate",
            ActionKind::DirCreate {
                path: project_dir.join("new-dir"),
            },
        ),
        (
            "NetConnect",
            ActionKind::NetConnect {
                host: "api.openai.com".to_string(),
                port: 443,
            },
        ),
        (
            "ProcessSpawn",
            ActionKind::ProcessSpawn {
                command: "/usr/bin/python3".to_string(),
                args: vec![],
            },
        ),
    ];

    println!("\nPolicy demo:");
    for (label, kind) in &test_actions {
        let action = Action::new(agent_name, kind.clone());
        let verdict = engine.evaluate(&action);
        let symbol = if verdict.decision == Decision::Allow {
            "ALLOW"
        } else {
            "DENY "
        };

        let resource = match kind {
            ActionKind::FileRead { path }
            | ActionKind::FileWrite { path }
            | ActionKind::FileDelete { path }
            | ActionKind::DirCreate { path } => path.display().to_string(),
            ActionKind::NetConnect { host, port } => format!("{host}:{port}"),
            ActionKind::ProcessSpawn { command, .. } => command.clone(),
            _ => String::new(),
        };

        let display_resource = if resource.len() > MAX_RESOURCE_DISPLAY_LEN {
            let tail: String = resource
                .chars()
                .rev()
                .take(MAX_RESOURCE_DISPLAY_LEN - 3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("...{tail}")
        } else {
            resource
        };
        println!("  [{symbol}] {label:<14} {display_resource}");
    }

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
    run_in_dir_with_isolation(
        name,
        policy_template,
        base_dir,
        project_dir,
        platform_isolation(),
    )
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
            "unknown policy template '{policy_template}'; valid options: {}",
            aegis_policy::builtin::list_builtin_policies().join(", ")
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
    aegis_types::validate_config_name(name)
        .with_context(|| format!("invalid config name: {name:?}"))?;
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
            base_dir
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            config_path.display(),
            base_dir
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
        )
    })?;

    AegisConfig::from_toml(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_in_dir_creates_config_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let base_dir = dir.path().join("test-cfg");

        run_in_dir("test-cfg", "permit-all", &base_dir, None).unwrap();

        // Config file should exist
        assert!(base_dir.join(CONFIG_FILENAME).exists());
        // Policy file should exist
        assert!(base_dir
            .join("policies")
            .join(DEFAULT_POLICY_FILENAME)
            .exists());
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
