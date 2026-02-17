use std::fs;

use anyhow::{Context, Result};
use tracing::info;

use aegis_policy::builtin::get_builtin_policy;
use aegis_policy::PolicyEngine;
use aegis_sandbox::SandboxBackend;
use aegis_types::{AegisConfig, IsolationConfig, ObserverConfig};

use crate::commands::init::{ensure_aegis_dir, load_config, resolve_config_dir};
use crate::commands::pipeline::{self, PipelineOptions};

/// Run the `aegis run` command.
///
/// If no config exists for `config_name`, auto-creates one with Process
/// isolation and the specified policy template. Seatbelt enforcement
/// requires explicit opt-in via `aegis init` or the wizard.
pub fn run(config_name: &str, policy: &str, command: &str, args: &[String], tag: Option<&str>) -> Result<()> {
    let config = ensure_run_config(config_name, policy)?;
    info!(config_name, "loaded config for run");

    // Create sandbox backend, compiling Cedar policies to SBPL on macOS if needed
    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;
    let policy_engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;

    let backend = create_backend(&config.isolation, &config, &policy_engine);
    let harvest_violations = matches!(config.isolation, IsolationConfig::Seatbelt { .. });

    pipeline::execute(
        &config,
        command,
        args,
        PipelineOptions {
            backend,
            harvest_violations,
            tag,
        },
    )?;

    Ok(())
}

/// Ensure a run config exists, auto-creating one if needed.
///
/// If the config already exists (in either init or wrap namespace), loads it.
/// Otherwise, creates a new config with Process isolation (no Seatbelt) and
/// the specified policy template, using the current directory as the sandbox root.
fn ensure_run_config(name: &str, policy: &str) -> Result<AegisConfig> {
    // Try loading existing config first
    let config_dir = resolve_config_dir(name)?;
    if config_dir.join("aegis.toml").exists() {
        return load_config(name);
    }

    // Auto-create a new config
    ensure_aegis_dir()?;

    let cwd = std::env::current_dir().context("failed to get current directory")?;

    let policy_text = get_builtin_policy(policy).with_context(|| {
        format!(
            "unknown policy template '{policy}'; valid options: {}", aegis_policy::builtin::list_builtin_policies().join(", ")
        )
    })?;

    // Create directory structure
    let policies_dir = config_dir.join("policies");
    fs::create_dir_all(&policies_dir)
        .with_context(|| format!("failed to create policies dir: {}", policies_dir.display()))?;

    let policy_file = policies_dir.join("default.cedar");
    fs::write(&policy_file, policy_text)
        .with_context(|| format!("failed to write policy file: {}", policy_file.display()))?;

    let config = AegisConfig {
        name: name.to_string(),
        sandbox_dir: cwd.clone(),
        policy_paths: vec![policies_dir],
        schema_path: None,
        ledger_path: config_dir.join("audit.db"),
        allowed_network: Vec::new(),
        isolation: IsolationConfig::Process,
        observer: ObserverConfig::default(),
    };

    let toml_content = config
        .to_toml()
        .context("failed to serialize config to TOML")?;
    let config_path = config_dir.join("aegis.toml");
    fs::write(&config_path, &toml_content)
        .with_context(|| format!("failed to write config: {}", config_path.display()))?;

    println!(
        "Auto-initialized '{}' (policy: {}, dir: {})",
        name,
        policy,
        cwd.display()
    );

    Ok(config)
}

/// Create the sandbox backend, compiling Cedar policies to SBPL on macOS.
fn create_backend(
    isolation: &IsolationConfig,
    config: &aegis_types::AegisConfig,
    engine: &PolicyEngine,
) -> Box<dyn SandboxBackend> {
    match isolation {
        #[cfg(target_os = "macos")]
        IsolationConfig::Seatbelt { .. } => {
            let sbpl = aegis_sandbox::compile_cedar_to_sbpl(config, engine);
            info!("compiled Cedar policies to SBPL profile");
            Box::new(aegis_sandbox::SeatbeltBackend::with_profile(sbpl))
        }
        #[cfg(not(target_os = "macos"))]
        IsolationConfig::Seatbelt { .. } => {
            tracing::warn!("Seatbelt is only available on macOS; falling back to ProcessBackend");
            Box::new(aegis_sandbox::ProcessBackend)
        }
        IsolationConfig::Process | IsolationConfig::None => {
            info!("using Process sandbox backend (no OS-level isolation)");
            Box::new(aegis_sandbox::ProcessBackend)
        }
    }
}
