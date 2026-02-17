//! Zero-friction agent wrapping with full observability.
//!
//! `aegis wrap [--dir PATH] [--policy POLICY] [--name NAME] -- command [args...]`
//!
//! Wraps any command with Aegis filesystem observation and audit logging.
//! Uses Process isolation (no Seatbelt) to avoid conflicting with the
//! agent's own sandboxing. Config is stored at `~/.aegis/wraps/<name>/`
//! and reused on subsequent invocations (same ledger, accumulating sessions).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::info;

use aegis_policy::builtin::get_builtin_policy;
use aegis_types::{
    AegisConfig, IsolationConfig, ObserverConfig, CONFIG_FILENAME, DEFAULT_POLICY_FILENAME,
    LEDGER_FILENAME,
};

use crate::commands::init::dirs_from_env;
use crate::commands::pipeline::{self, PipelineOptions};

/// Run the `aegis wrap` command.
pub fn run(
    dir: Option<&Path>,
    policy: &str,
    name: Option<&str>,
    command: &str,
    args: &[String],
    tag: Option<&str>,
) -> Result<()> {
    let project_dir = match dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("--dir path does not exist: {}", d.display()))?,
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    if !project_dir.is_dir() {
        bail!("--dir is not a directory: {}", project_dir.display());
    }

    let derived_name = match name {
        Some(n) => n.to_string(),
        None => derive_name(command),
    };

    aegis_types::validate_config_name(&derived_name)
        .with_context(|| format!("invalid config name: {derived_name:?}"))?;
    let wrap_dir = wraps_base_dir()?.join(&derived_name);

    let config = ensure_wrap_config(&wrap_dir, &derived_name, policy, &project_dir)?;

    // Auto-set as current config
    crate::commands::use_config::set_current(&derived_name)?;

    // Wrap always uses ProcessBackend (no Seatbelt) and skips violation harvesting
    let backend = Box::new(aegis_sandbox::ProcessBackend);

    pipeline::execute(
        &config,
        command,
        args,
        PipelineOptions {
            backend,
            harvest_violations: false,
            tag,
        },
    )?;

    Ok(())
}

/// Derive a config name from a command path.
///
/// Strips path components: `/usr/local/bin/claude` -> `claude`
pub fn derive_name(command: &str) -> String {
    Path::new(command)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string())
}

/// Base directory for wrap configs: `$HOME/.aegis/wraps/`
pub fn wraps_base_dir() -> Result<PathBuf> {
    let home = dirs_from_env()?;
    Ok(home.join(".aegis").join("wraps"))
}

/// Ensure a wrap config exists at `wrap_dir`, creating it if needed.
///
/// If the directory already exists, loads the existing config and updates
/// `sandbox_dir` to the current project directory. If it doesn't exist,
/// creates a new config with the specified policy template.
pub fn ensure_wrap_config(
    wrap_dir: &Path,
    name: &str,
    policy_template: &str,
    project_dir: &Path,
) -> Result<AegisConfig> {
    if wrap_dir.exists() {
        // Reuse existing config, update sandbox_dir
        let config_path = wrap_dir.join(CONFIG_FILENAME);
        let content = fs::read_to_string(&config_path).with_context(|| {
            format!("failed to read wrap config: {}", config_path.display())
        })?;
        let mut config = AegisConfig::from_toml(&content).context("failed to parse wrap config")?;
        config.sandbox_dir = project_dir.to_path_buf();
        config.isolation = IsolationConfig::Process;

        // Write updated config back
        let toml_content = config
            .to_toml()
            .context("failed to serialize wrap config")?;
        fs::write(&config_path, &toml_content)
            .with_context(|| format!("failed to write wrap config: {}", config_path.display()))?;

        info!(name, wrap_dir = %wrap_dir.display(), "reusing existing wrap config");
        Ok(config)
    } else {
        // Create new wrap config
        let policy_text = get_builtin_policy(policy_template).with_context(|| {
            format!(
                "unknown policy template '{policy_template}'; valid options: {}", aegis_policy::builtin::list_builtin_policies().join(", ")
            )
        })?;

        let policies_dir = wrap_dir.join("policies");
        fs::create_dir_all(&policies_dir).with_context(|| {
            format!("failed to create wrap policies dir: {}", policies_dir.display())
        })?;

        let policy_file = policies_dir.join(DEFAULT_POLICY_FILENAME);
        fs::write(&policy_file, policy_text).with_context(|| {
            format!("failed to write policy file: {}", policy_file.display())
        })?;

        let config = AegisConfig {
            name: name.to_string(),
            sandbox_dir: project_dir.to_path_buf(),
            policy_paths: vec![policies_dir],
            schema_path: None,
            ledger_path: wrap_dir.join(LEDGER_FILENAME),
            allowed_network: Vec::new(),
            isolation: IsolationConfig::Process,
            observer: ObserverConfig::default(),
            alerts: Vec::new(),
        };

        let toml_content = config
            .to_toml()
            .context("failed to serialize wrap config")?;
        let config_path = wrap_dir.join(CONFIG_FILENAME);
        fs::write(&config_path, &toml_content)
            .with_context(|| format!("failed to write wrap config: {}", config_path.display()))?;

        info!(name, wrap_dir = %wrap_dir.display(), "created new wrap config");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_name_strips_path() {
        assert_eq!(derive_name("/usr/local/bin/claude"), "claude");
        assert_eq!(derive_name("/usr/bin/python3"), "python3");
        assert_eq!(derive_name("node"), "node");
    }

    #[test]
    fn derive_name_handles_edge_cases() {
        assert_eq!(derive_name("./script.sh"), "script.sh");
        assert_eq!(derive_name(""), "");
    }

    #[test]
    fn wraps_base_dir_under_aegis() {
        let base = wraps_base_dir().expect("should resolve wraps base dir");
        assert!(
            base.to_string_lossy().contains(".aegis/wraps"),
            "wraps dir should be under .aegis: {base:?}"
        );
    }

    #[test]
    fn ensure_wrap_config_creates_new() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("test-wrap");
        let project_dir = tmpdir.path().join("project");
        fs::create_dir_all(&project_dir).expect("create project dir");

        let config = ensure_wrap_config(&wrap_dir, "test-wrap", "permit-all", &project_dir)
            .expect("should create new wrap config");

        assert_eq!(config.name, "test-wrap");
        assert_eq!(config.sandbox_dir, project_dir);
        assert_eq!(config.isolation, IsolationConfig::Process);
        assert!(wrap_dir.join(CONFIG_FILENAME).exists());
        assert!(wrap_dir.join("policies").join(DEFAULT_POLICY_FILENAME).exists());
    }

    #[test]
    fn ensure_wrap_config_reuses_existing() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("reuse-wrap");
        let project_dir1 = tmpdir.path().join("project1");
        let project_dir2 = tmpdir.path().join("project2");
        fs::create_dir_all(&project_dir1).expect("create project dir1");
        fs::create_dir_all(&project_dir2).expect("create project dir2");

        // First call creates
        let config1 = ensure_wrap_config(&wrap_dir, "reuse-wrap", "permit-all", &project_dir1)
            .expect("first call");
        assert_eq!(config1.sandbox_dir, project_dir1);

        // Second call reuses and updates sandbox_dir
        let config2 = ensure_wrap_config(&wrap_dir, "reuse-wrap", "permit-all", &project_dir2)
            .expect("second call");
        assert_eq!(config2.sandbox_dir, project_dir2);
        assert_eq!(config2.name, "reuse-wrap");
    }

    #[test]
    fn ensure_wrap_config_unknown_policy_fails() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let wrap_dir = tmpdir.path().join("bad-policy");
        let project_dir = tmpdir.path().join("project");
        fs::create_dir_all(&project_dir).expect("create project dir");

        let result = ensure_wrap_config(&wrap_dir, "bad", "nonexistent-policy", &project_dir);
        assert!(result.is_err(), "unknown policy should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown policy template"),
        );
    }
}
