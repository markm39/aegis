//! Shared hook settings for Claude Code integration and user-extensible hooks.
//!
//! Claude Code's `PreToolUse` and `PostToolUse` hooks let Aegis intercept tool
//! calls at two lifecycle points:
//! - **PreToolUse**: evaluates each tool call against Cedar policy before execution
//! - **PostToolUse**: observes tool results after execution for audit/telemetry
//!
//! These functions generate and install the hook configuration that registers
//! `aegis hook pre-tool-use` and `aegis hook post-tool-use` as hook handlers.
//!
//! Two install targets:
//! - `.claude/settings.json` -- project-level, committed to VCS (manual install via CLI)
//! - `.claude/settings.local.json` -- local override, not committed (daemon-managed)
//!
//! ## User-Extensible Hooks
//!
//! Users can install custom hooks under `~/.aegis/hooks/<hook-name>/manifest.toml`.
//! Each hook directory contains a `manifest.toml` describing the hook and an
//! entry point script. Hooks are loaded into the [`HookRegistry`], executed as
//! sandboxed subprocesses with restricted environments, and verified via SHA-256
//! integrity checks on every execution.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// Generate the Claude Code settings JSON fragment that registers aegis hooks.
///
/// Returns a JSON object suitable for merging into `.claude/settings.json` or
/// `.claude/settings.local.json`. Both `PreToolUse` and `PostToolUse` arrays
/// contain matcher groups, each with an inner `hooks` array of handlers --
/// this is the three-level nesting that Claude Code requires
/// (event -> matcher group -> handler).
///
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       { "hooks": [{ "type": "command", "command": "aegis hook pre-tool-use" }] }
///     ],
///     "PostToolUse": [
///       { "hooks": [{ "type": "command", "command": "aegis hook post-tool-use" }] }
///     ]
///   }
/// }
/// ```
pub fn generate_hook_settings() -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [
                pre_tool_use_matcher_group()
            ],
            "PostToolUse": [
                post_tool_use_matcher_group()
            ],
            "Stop": [
                stop_matcher_group()
            ]
        }
    })
}

/// A matcher group entry for the Stop array.
///
/// The `Stop` hook fires when a Claude Code session ends. Aegis records
/// the session end event in the audit ledger for lifecycle tracking.
fn stop_matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook session-end"
            }
        ]
    })
}

/// A matcher group entry for the PreToolUse array.
///
/// No `matcher` field means "match all tools." The inner `hooks` array
/// contains one handler that calls `aegis hook pre-tool-use`.
fn pre_tool_use_matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook pre-tool-use"
            }
        ]
    })
}

/// A matcher group entry for the PostToolUse array.
///
/// No `matcher` field means "match all tools." The inner `hooks` array
/// contains one handler that calls `aegis hook post-tool-use`.
pub fn post_tool_use_matcher_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            {
                "type": "command",
                "command": "aegis hook post-tool-use"
            }
        ]
    })
}

/// Check if the aegis hook is already registered in a PreToolUse array.
///
/// Handles both the correct nested format (matcher groups with inner `hooks`)
/// and the legacy flat format (bare handler objects) for robustness.
fn is_aegis_hook_installed(pre_tool_use_array: &[serde_json::Value]) -> bool {
    pre_tool_use_array.iter().any(|entry| {
        // Check nested format: entry.hooks[].command
        if let Some(inner_hooks) = entry.get("hooks").and_then(|v| v.as_array()) {
            return inner_hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|cmd| cmd.contains("aegis hook"))
            });
        }
        // Check legacy flat format: entry.command
        entry
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|cmd| cmd.contains("aegis hook"))
    })
}

/// Install hook settings for a daemon-managed agent.
///
/// Writes to `.claude/settings.local.json` in the given working directory.
/// This file is a local override that is not committed to version control,
/// making it safe for the daemon to own without affecting project settings.
///
/// The function is idempotent: if the aegis hook is already registered, it
/// does nothing. Existing settings keys (model, other hooks) are preserved.
pub fn install_daemon_hooks(working_dir: &Path) -> Result<(), String> {
    let claude_dir = working_dir.join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .map_err(|e| format!("failed to create .claude directory: {e}"))?;

    let settings_path = claude_dir.join("settings.local.json");

    // Load existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("invalid JSON in {}: {e}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    // Ensure settings is an object
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.local.json is not a JSON object".to_string())?;

    // Navigate to hooks object, creating intermediate keys as needed
    let hooks = obj.entry("hooks").or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let mut changed = false;

    // Install PreToolUse hook
    {
        let pre_tool_use = hooks_obj
            .entry("PreToolUse")
            .or_insert(serde_json::json!([]));
        let pre_array = pre_tool_use
            .as_array_mut()
            .ok_or_else(|| "PreToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(pre_array) {
            pre_array.push(pre_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install PostToolUse hook
    {
        let post_tool_use = hooks_obj
            .entry("PostToolUse")
            .or_insert(serde_json::json!([]));
        let post_array = post_tool_use
            .as_array_mut()
            .ok_or_else(|| "PostToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(post_array) {
            post_array.push(post_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install Stop hook (session end lifecycle)
    {
        let stop = hooks_obj.entry("Stop").or_insert(serde_json::json!([]));
        let stop_array = stop
            .as_array_mut()
            .ok_or_else(|| "Stop is not an array".to_string())?;
        if !is_aegis_hook_installed(stop_array) {
            stop_array.push(stop_matcher_group());
            changed = true;
        }
    }

    if !changed {
        return Ok(());
    }

    // Write back
    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// Install hook settings into a project's `.claude/settings.json`.
///
/// Unlike `install_daemon_hooks` (which targets `settings.local.json`),
/// this targets the project-level settings file that may be committed to
/// version control. Used by the `aegis hook install` CLI command.
///
/// The function is idempotent and preserves existing settings.
pub fn install_project_hooks(project_dir: &Path) -> Result<(), String> {
    let claude_dir = project_dir.join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .map_err(|e| format!("failed to create .claude directory: {e}"))?;

    let settings_path = claude_dir.join("settings.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("invalid JSON in {}: {e}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| "settings.json is not a JSON object".to_string())?;

    let hooks = obj.entry("hooks").or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "hooks is not a JSON object".to_string())?;

    let mut changed = false;

    // Install PreToolUse hook
    {
        let pre_tool_use = hooks_obj
            .entry("PreToolUse")
            .or_insert(serde_json::json!([]));
        let pre_array = pre_tool_use
            .as_array_mut()
            .ok_or_else(|| "PreToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(pre_array) {
            pre_array.push(pre_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install PostToolUse hook
    {
        let post_tool_use = hooks_obj
            .entry("PostToolUse")
            .or_insert(serde_json::json!([]));
        let post_array = post_tool_use
            .as_array_mut()
            .ok_or_else(|| "PostToolUse is not an array".to_string())?;
        if !is_aegis_hook_installed(post_array) {
            post_array.push(post_tool_use_matcher_group());
            changed = true;
        }
    }

    // Install Stop hook (session end lifecycle)
    {
        let stop = hooks_obj.entry("Stop").or_insert(serde_json::json!([]));
        let stop_array = stop
            .as_array_mut()
            .ok_or_else(|| "Stop is not an array".to_string())?;
        if !is_aegis_hook_installed(stop_array) {
            stop_array.push(stop_matcher_group());
            changed = true;
        }
    }

    if !changed {
        return Ok(());
    }

    let output = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    std::fs::write(&settings_path, output)
        .map_err(|e| format!("failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// Current schema version for daemon-managed OpenClaw bridge metadata.
pub const OPENCLAW_BRIDGE_VERSION: u32 = 1;

/// Path to daemon-managed OpenClaw bridge marker JSON.
pub fn openclaw_bridge_marker_path(working_dir: &Path) -> PathBuf {
    working_dir
        .join(".aegis")
        .join("openclaw")
        .join("bridge.json")
}

/// Path to daemon-managed OpenClaw config JSON.
pub fn openclaw_bridge_config_path(working_dir: &Path) -> PathBuf {
    working_dir
        .join(".aegis")
        .join("openclaw")
        .join("openclaw.json")
}

/// Return true when the daemon-managed OpenClaw bridge marker is present and valid.
pub fn openclaw_bridge_connected(working_dir: &Path) -> bool {
    let marker_path = openclaw_bridge_marker_path(working_dir);
    let Ok(raw) = std::fs::read_to_string(marker_path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let connected = value
        .get("connected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    version == OPENCLAW_BRIDGE_VERSION as u64 && connected
}

/// Return true when daemon-managed OpenClaw bridge artifacts are present.
pub fn openclaw_bridge_installed(working_dir: &Path) -> bool {
    let marker_path = openclaw_bridge_marker_path(working_dir);
    let config_path = openclaw_bridge_config_path(working_dir);
    let hook_md = working_dir
        .join("hooks")
        .join("aegis-policy-gate")
        .join("HOOK.md");
    let hook_handler = working_dir
        .join("hooks")
        .join("aegis-policy-gate")
        .join("handler.ts");
    marker_path.exists() && config_path.exists() && hook_md.exists() && hook_handler.exists()
}

/// Install a daemon-managed OpenClaw bridge bundle for strict policy mediation.
///
/// This creates:
/// - workspace hook metadata/handler under `hooks/aegis-policy-gate/`
/// - a daemon-owned OpenClaw config at `.aegis/openclaw/openclaw.json`
/// - a bridge marker file at `.aegis/openclaw/bridge.json`
pub fn install_openclaw_daemon_bridge(working_dir: &Path, agent_name: &str) -> Result<(), String> {
    let hook_dir = working_dir.join("hooks").join("aegis-policy-gate");
    std::fs::create_dir_all(&hook_dir)
        .map_err(|e| format!("failed to create OpenClaw hook dir: {e}"))?;

    let hook_md = hook_dir.join("HOOK.md");
    let hook_md_body = r#"---
name: aegis-policy-gate
description: "Aegis daemon policy bridge for OpenClaw"
metadata: { "openclaw": { "events": ["command:new", "gateway:startup"] } }
---

# Aegis Policy Gate

Managed by Aegis daemon. Do not edit manually.
"#;
    std::fs::write(&hook_md, hook_md_body)
        .map_err(|e| format!("failed to write {}: {e}", hook_md.display()))?;

    let hook_handler = hook_dir.join("handler.ts");
    let hook_handler_body = r#"const handler = async (event) => {
  if (!event || typeof event !== "object") {
    return;
  }
  const marker = process.env.AEGIS_OPENCLAW_BRIDGE_MARKER;
  if (!marker) {
    return;
  }
  try {
    const fs = await import("node:fs/promises");
    const payload = JSON.stringify(
      {
        version: 1,
        connected: true,
        updated_at_utc: new Date().toISOString(),
      },
      null,
      2,
    );
    await fs.writeFile(marker, payload, "utf8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[aegis-policy-gate] marker update failed: ${msg}`);
  }
};

export default handler;
"#;
    std::fs::write(&hook_handler, hook_handler_body)
        .map_err(|e| format!("failed to write {}: {e}", hook_handler.display()))?;

    let bridge_dir = working_dir.join(".aegis").join("openclaw");
    std::fs::create_dir_all(&bridge_dir)
        .map_err(|e| format!("failed to create OpenClaw bridge dir: {e}"))?;

    let marker_path = openclaw_bridge_marker_path(working_dir);
    let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");
    let marker = serde_json::json!({
        "version": OPENCLAW_BRIDGE_VERSION,
        "connected": false,
        "installed": true,
        "agent": agent_name,
        "socket_path": socket_path.to_string_lossy(),
        "installed_at_utc": chrono::Utc::now().to_rfc3339(),
    });
    let marker_json = serde_json::to_string_pretty(&marker)
        .map_err(|e| format!("failed to serialize OpenClaw bridge marker: {e}"))?;
    std::fs::write(&marker_path, marker_json)
        .map_err(|e| format!("failed to write {}: {e}", marker_path.display()))?;

    let config_path = openclaw_bridge_config_path(working_dir);
    let config = serde_json::json!({
        "hooks": {
            "internal": {
                "enabled": true,
                "entries": {
                    "aegis-policy-gate": {
                        "enabled": true,
                        "env": {
                            "AEGIS_AGENT_NAME": agent_name,
                            "AEGIS_SOCKET_PATH": socket_path.to_string_lossy(),
                            "AEGIS_OPENCLAW_BRIDGE_MARKER": marker_path.to_string_lossy(),
                            "AEGIS_OPENCLAW_BRIDGE_REQUIRED": "1"
                        }
                    }
                }
            }
        }
    });
    let config_json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed to serialize OpenClaw bridge config: {e}"))?;
    std::fs::write(&config_path, config_json)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// User-extensible hook system
// ---------------------------------------------------------------------------

/// Default hooks directory under the user's home.
pub fn default_hooks_dir() -> PathBuf {
    dirs_home().join(".aegis").join("hooks")
}

/// Resolve the user's home directory. Falls back to `/tmp` if unresolvable.
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Maximum length (bytes) for sanitized hook output.
const MAX_HOOK_OUTPUT_BYTES: usize = 64 * 1024;

/// Trigger event that causes a hook to fire.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTrigger {
    PreToolUse,
    PostToolUse,
    OnApproval,
    OnDeny,
    OnStall,
    OnExit,
    Custom(String),
}

impl std::fmt::Display for HookTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookTrigger::PreToolUse => write!(f, "pre_tool_use"),
            HookTrigger::PostToolUse => write!(f, "post_tool_use"),
            HookTrigger::OnApproval => write!(f, "on_approval"),
            HookTrigger::OnDeny => write!(f, "on_deny"),
            HookTrigger::OnStall => write!(f, "on_stall"),
            HookTrigger::OnExit => write!(f, "on_exit"),
            HookTrigger::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// Manifest describing a user-installed hook.
///
/// Parsed from `manifest.toml` inside each hook directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookManifest {
    /// Human-readable hook name (must match directory name).
    pub name: String,
    /// Semantic version string.
    #[serde(default = "default_version")]
    pub version: String,
    /// Short description of the hook's purpose.
    #[serde(default)]
    pub description: String,
    /// Event that triggers this hook.
    pub trigger: HookTrigger,
    /// Relative path to the entry-point script within the hook directory.
    pub entry_point: PathBuf,
    /// Maximum execution time in seconds (default: 30).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Required capability permissions (informational, checked at install time).
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Workspace path this hook is scoped to (set at runtime, not from TOML).
    #[serde(skip)]
    pub workspace_path: Option<PathBuf>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

fn default_timeout() -> u64 {
    30
}

/// Action returned by a hook script to influence the triggering operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    Allow,
    Block,
    Modify,
}

/// Structured result from executing a hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    /// The action the hook wants to take.
    pub action: HookAction,
    /// Optional message from the hook.
    #[serde(default)]
    pub message: String,
    /// Optional modified data (for action = modify).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Per-hook runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    Installed,
    Active,
    Disabled,
    Error(String),
}

impl std::fmt::Display for HookState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookState::Installed => write!(f, "installed"),
            HookState::Active => write!(f, "active"),
            HookState::Disabled => write!(f, "disabled"),
            HookState::Error(e) => write!(f, "error: {e}"),
        }
    }
}

/// Status tracking for a single hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookStatus {
    pub name: String,
    pub state: HookState,
    pub last_run: Option<DateTime<Utc>>,
    pub last_success: bool,
    pub error_count: u64,
    pub run_count: u64,
}

/// Where a hook was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookSource {
    /// Global hooks directory (`~/.aegis/hooks/`).
    Global,
    /// Workspace-local `.aegis/hooks/` directory.
    Workspace(PathBuf),
}

/// A loaded hook with its manifest, resolved paths, and integrity hash.
#[derive(Debug, Clone)]
pub struct LoadedHook {
    pub manifest: HookManifest,
    /// Absolute path to the hook directory.
    pub hook_dir: PathBuf,
    /// Absolute path to the entry-point script.
    pub entry_point_abs: PathBuf,
    /// SHA-256 hash of the entry-point script at load time.
    pub script_hash: String,
    /// Runtime status.
    pub status: HookStatus,
    /// Where this hook was loaded from.
    pub source: HookSource,
}

/// In-memory registry of loaded user hooks.
///
/// Provides methods to load hooks from disk, query by trigger, execute hooks,
/// and enable/disable individual hooks.
pub struct HookRegistry {
    hooks: HashMap<String, LoadedHook>,
    hooks_dir: PathBuf,
}

impl HookRegistry {
    /// Create a new empty registry rooted at the given hooks directory.
    pub fn new(hooks_dir: PathBuf) -> Self {
        Self {
            hooks: HashMap::new(),
            hooks_dir,
        }
    }

    /// Create a registry using the default `~/.aegis/hooks/` directory.
    pub fn with_default_dir() -> Self {
        Self::new(default_hooks_dir())
    }

    /// Load all hooks from the hooks directory.
    ///
    /// Scans each subdirectory for a `manifest.toml`, parses it, validates the
    /// entry point path, computes the SHA-256 integrity hash, and registers the
    /// hook as `Installed`.
    pub fn load_all(&mut self) -> Result<usize, String> {
        self.hooks.clear();

        if !self.hooks_dir.exists() {
            tracing::info!(
                path = %self.hooks_dir.display(),
                "hooks directory does not exist, no user hooks loaded"
            );
            return Ok(0);
        }

        let entries = std::fs::read_dir(&self.hooks_dir)
            .map_err(|e| format!("failed to read hooks directory: {e}"))?;

        let mut loaded = 0;
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read directory entry: {e}"))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let manifest_path = path.join("manifest.toml");
            if !manifest_path.exists() {
                tracing::debug!(
                    dir = %path.display(),
                    "skipping hook directory without manifest.toml"
                );
                continue;
            }

            match self.load_single_hook(&path, &manifest_path) {
                Ok(name) => {
                    tracing::info!(hook = %name, "loaded user hook");
                    loaded += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        dir = %path.display(),
                        error = %e,
                        "failed to load hook"
                    );
                }
            }
        }

        Ok(loaded)
    }

    /// Load a single hook from its directory and manifest path.
    fn load_single_hook(
        &mut self,
        hook_dir: &Path,
        manifest_path: &Path,
    ) -> Result<String, String> {
        let content = std::fs::read_to_string(manifest_path)
            .map_err(|e| format!("failed to read manifest: {e}"))?;
        let manifest: HookManifest =
            toml::from_str(&content).map_err(|e| format!("failed to parse manifest.toml: {e}"))?;

        // Validate entry_point: must not contain path traversal components.
        validate_entry_point(&manifest.entry_point)?;

        let entry_point_abs = hook_dir.join(&manifest.entry_point);

        // Resolve to canonical path and verify it stays within the hook directory.
        let canonical_hook_dir = hook_dir
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize hook dir: {e}"))?;
        let canonical_entry = entry_point_abs
            .canonicalize()
            .map_err(|e| format!("entry point does not exist or cannot be resolved: {e}"))?;

        if !canonical_entry.starts_with(&canonical_hook_dir) {
            return Err(format!(
                "entry point escapes hook directory: {} is not under {}",
                canonical_entry.display(),
                canonical_hook_dir.display()
            ));
        }

        // Compute SHA-256 of the script.
        let script_bytes = std::fs::read(&canonical_entry)
            .map_err(|e| format!("failed to read entry point script: {e}"))?;
        let script_hash = compute_sha256(&script_bytes);

        let name = manifest.name.clone();
        let loaded = LoadedHook {
            manifest,
            hook_dir: hook_dir.to_path_buf(),
            entry_point_abs: canonical_entry,
            script_hash,
            status: HookStatus {
                name: name.clone(),
                state: HookState::Installed,
                last_run: None,
                last_success: false,
                error_count: 0,
                run_count: 0,
            },
            source: HookSource::Global,
        };

        self.hooks.insert(name.clone(), loaded);
        Ok(name)
    }

    /// Install a hook from an external path by copying it into the hooks directory.
    ///
    /// The source path must be a directory containing a `manifest.toml`.
    pub fn install_hook(&mut self, source_path: &Path) -> Result<String, String> {
        if !source_path.is_dir() {
            return Err("source path must be a directory".to_string());
        }

        let manifest_path = source_path.join("manifest.toml");
        if !manifest_path.exists() {
            return Err("source directory must contain manifest.toml".to_string());
        }

        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("failed to read manifest: {e}"))?;
        let manifest: HookManifest =
            toml::from_str(&content).map_err(|e| format!("failed to parse manifest.toml: {e}"))?;

        validate_entry_point(&manifest.entry_point)?;

        let dest_dir = self.hooks_dir.join(&manifest.name);
        if dest_dir.exists() {
            return Err(format!("hook '{}' is already installed", manifest.name));
        }

        // Create hooks directory if needed.
        std::fs::create_dir_all(&self.hooks_dir)
            .map_err(|e| format!("failed to create hooks directory: {e}"))?;

        // Copy hook directory contents.
        copy_dir_recursive(source_path, &dest_dir)?;

        let new_manifest_path = dest_dir.join("manifest.toml");
        self.load_single_hook(&dest_dir, &new_manifest_path)
    }

    /// Get all hooks registered for a specific trigger event.
    pub fn get_hooks_for_trigger(&self, trigger: &HookTrigger) -> Vec<&LoadedHook> {
        self.hooks
            .values()
            .filter(|h| h.manifest.trigger == *trigger && h.status.state == HookState::Active)
            .collect()
    }

    /// Execute a hook with structured JSON input.
    ///
    /// The hook script receives input on stdin and writes a JSON result to stdout.
    /// Execution is bounded by `tokio::time::timeout`. The script runs in a
    /// restricted environment (only PATH, HOME, and AEGIS_HOOK_* variables).
    ///
    /// On every execution, the entry point's SHA-256 is re-verified against the
    /// stored hash. If it has changed, execution is blocked (fail-closed).
    pub async fn execute_hook(
        &mut self,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<HookResult, String> {
        let hook = self
            .hooks
            .get(name)
            .ok_or_else(|| format!("hook '{}' not found", name))?;

        if hook.status.state != HookState::Active {
            return Err(format!(
                "hook '{}' is not active (state: {})",
                name, hook.status.state
            ));
        }

        // Verify integrity before execution.
        let current_bytes = std::fs::read(&hook.entry_point_abs)
            .map_err(|e| format!("failed to read hook script for integrity check: {e}"))?;
        let current_hash = compute_sha256(&current_bytes);

        if current_hash != hook.script_hash {
            let msg = format!(
                "hook '{}' integrity check failed: script modified since installation \
                 (expected {}, got {})",
                name, hook.script_hash, current_hash
            );
            tracing::error!(%name, "hook integrity violation");
            // Update status to Error.
            if let Some(h) = self.hooks.get_mut(name) {
                h.status.state = HookState::Error(msg.clone());
                h.status.error_count += 1;
            }
            return Err(msg);
        }

        let timeout_duration = std::time::Duration::from_secs(hook.manifest.timeout_secs);
        let entry_point = hook.entry_point_abs.clone();
        let hook_dir = hook.hook_dir.clone();
        let hook_name = hook.manifest.name.clone();

        // Build restricted environment (includes AEGIS_HOOK_WORKSPACE for workspace hooks).
        let workspace_path = hook.manifest.workspace_path.clone();
        let env = build_workspace_hook_env(&hook_name, &hook_dir, workspace_path.as_deref());

        let input_json = serde_json::to_string(input)
            .map_err(|e| format!("failed to serialize hook input: {e}"))?;

        // Spawn the subprocess.
        let result = tokio::time::timeout(timeout_duration, async {
            run_hook_process(&entry_point, &hook_dir, &env, &input_json).await
        })
        .await;

        let now = Utc::now();

        match result {
            Ok(Ok(hook_result)) => {
                if let Some(h) = self.hooks.get_mut(name) {
                    h.status.last_run = Some(now);
                    h.status.last_success = true;
                    h.status.run_count += 1;
                }
                Ok(hook_result)
            }
            Ok(Err(e)) => {
                if let Some(h) = self.hooks.get_mut(name) {
                    h.status.last_run = Some(now);
                    h.status.last_success = false;
                    h.status.error_count += 1;
                    h.status.state = HookState::Error(e.clone());
                }
                Err(e)
            }
            Err(_elapsed) => {
                let msg = format!(
                    "hook '{}' timed out after {}s",
                    name,
                    timeout_duration.as_secs()
                );
                if let Some(h) = self.hooks.get_mut(name) {
                    h.status.last_run = Some(now);
                    h.status.last_success = false;
                    h.status.error_count += 1;
                    h.status.state = HookState::Error(msg.clone());
                }
                Err(msg)
            }
        }
    }

    /// Enable a hook by name. Transitions from Installed or Disabled to Active.
    pub fn enable(&mut self, name: &str) -> Result<(), String> {
        let hook = self
            .hooks
            .get_mut(name)
            .ok_or_else(|| format!("hook '{}' not found", name))?;
        match &hook.status.state {
            HookState::Installed | HookState::Disabled | HookState::Error(_) => {
                hook.status.state = HookState::Active;
                Ok(())
            }
            HookState::Active => Ok(()), // already active, idempotent
        }
    }

    /// Disable a hook by name.
    pub fn disable(&mut self, name: &str) -> Result<(), String> {
        let hook = self
            .hooks
            .get_mut(name)
            .ok_or_else(|| format!("hook '{}' not found", name))?;
        hook.status.state = HookState::Disabled;
        Ok(())
    }

    /// Get the status of a specific hook.
    pub fn get_status(&self, name: &str) -> Option<&HookStatus> {
        self.hooks.get(name).map(|h| &h.status)
    }

    /// List all loaded hooks.
    pub fn list_hooks(&self) -> Vec<&LoadedHook> {
        self.hooks.values().collect()
    }

    /// Get a reference to a loaded hook by name.
    pub fn get_hook(&self, name: &str) -> Option<&LoadedHook> {
        self.hooks.get(name)
    }

    /// Get the total number of loaded hooks.
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }
}

/// Validate that an entry point path contains no traversal components.
///
/// Rejects paths containing `..`, absolute paths, and paths with null bytes.
fn validate_entry_point(entry_point: &Path) -> Result<(), String> {
    let s = entry_point.to_string_lossy();

    // Reject null bytes.
    if s.contains('\0') {
        return Err("entry point contains null bytes".to_string());
    }

    // Reject absolute paths (entry point must be relative to hook dir).
    if entry_point.is_absolute() {
        return Err("entry point must be a relative path".to_string());
    }

    // Reject path traversal.
    for component in entry_point.components() {
        if let std::path::Component::ParentDir = component {
            return Err("entry point must not contain '..' (path traversal)".to_string());
        }
    }

    Ok(())
}

/// Compute the hex-encoded SHA-256 digest of a byte slice.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Build a restricted environment for hook execution.
///
/// Only PATH and HOME from the parent environment are inherited.
/// Additional AEGIS_HOOK_* variables provide context.
fn build_restricted_env(hook_name: &str, hook_dir: &Path) -> Vec<(String, String)> {
    let mut env = Vec::new();

    if let Ok(path) = std::env::var("PATH") {
        env.push(("PATH".to_string(), path));
    }
    if let Ok(home) = std::env::var("HOME") {
        env.push(("HOME".to_string(), home));
    }

    env.push(("AEGIS_HOOK_NAME".to_string(), hook_name.to_string()));
    env.push((
        "AEGIS_HOOK_DIR".to_string(),
        hook_dir.to_string_lossy().to_string(),
    ));
    env.push((
        "AEGIS_HOOK_VERSION".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    ));

    env
}

/// Run a hook script as a subprocess.
///
/// Passes `input_json` on stdin, reads stdout as a JSON `HookResult`, and
/// captures stderr for error reporting. Output is truncated to prevent
/// memory exhaustion.
async fn run_hook_process(
    entry_point: &Path,
    working_dir: &Path,
    env: &[(String, String)],
    input_json: &str,
) -> Result<HookResult, String> {
    let mut cmd = tokio::process::Command::new(entry_point);
    cmd.current_dir(working_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_clear();

    for (key, val) in env {
        cmd.env(key, val);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn hook process: {e}"))?;

    // Write input to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input_json.as_bytes())
            .await
            .map_err(|e| format!("failed to write to hook stdin: {e}"))?;
        // Drop stdin to signal EOF.
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for hook process: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_truncated = sanitize_hook_output(&stderr);
        return Err(format!(
            "hook process exited with status {}: {}",
            output.status, stderr_truncated
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_sanitized = sanitize_hook_output(&stdout);

    if stdout_sanitized.is_empty() {
        // Default to allow if hook produces no output.
        return Ok(HookResult {
            action: HookAction::Allow,
            message: String::new(),
            data: None,
        });
    }

    serde_json::from_str::<HookResult>(&stdout_sanitized).map_err(|e| {
        format!(
            "hook produced invalid JSON output: {e} (output: {})",
            truncate_str(&stdout_sanitized, 200)
        )
    })
}

/// Sanitize hook output: strip control characters (except newline/tab),
/// truncate to MAX_HOOK_OUTPUT_BYTES.
fn sanitize_hook_output(raw: &str) -> String {
    let truncated = truncate_str(raw, MAX_HOOK_OUTPUT_BYTES);
    truncated
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Truncate a string to at most `max_bytes` bytes at a valid UTF-8 boundary.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Find the last char boundary at or before max_bytes.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Recursively copy a directory and its contents.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("failed to create directory {}: {e}", dst.display()))?;

    for entry in
        std::fs::read_dir(src).map_err(|e| format!("failed to read dir {}: {e}", src.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read entry: {e}"))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                format!(
                    "failed to copy {} to {}: {e}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Workspace-scoped hooks
// ---------------------------------------------------------------------------

/// Compute the workspace hooks directory for a given working directory.
///
/// Returns `<working_dir>/.aegis/hooks/`.
pub fn workspace_hooks_dir(working_dir: &Path) -> PathBuf {
    working_dir.join(".aegis").join("hooks")
}

/// Validate that a workspace hooks directory is genuinely within the
/// agent's working directory. Prevents path traversal attacks where
/// symlinks or `..` segments could escape the workspace boundary.
///
/// Both paths are canonicalized before comparison. Returns an error
/// string if validation fails.
pub fn validate_workspace_hooks_dir(
    hooks_dir: &Path,
    working_dir: &Path,
) -> Result<PathBuf, String> {
    // The working directory must exist for canonicalize to succeed.
    let canonical_working_dir = working_dir.canonicalize().map_err(|e| {
        format!(
            "cannot canonicalize working dir {}: {e}",
            working_dir.display()
        )
    })?;

    // The hooks dir may not exist yet; validate the parent chain.
    let canonical_hooks_dir = hooks_dir
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize hooks dir {}: {e}", hooks_dir.display()))?;

    if !canonical_hooks_dir.starts_with(&canonical_working_dir) {
        return Err(format!(
            "workspace hooks dir {} is not within working dir {}",
            canonical_hooks_dir.display(),
            canonical_working_dir.display()
        ));
    }

    Ok(canonical_hooks_dir)
}

/// Load hooks from a workspace `.aegis/hooks/` directory.
///
/// Returns a Vec of loaded hooks, each tagged with `HookSource::Workspace`.
/// All hooks undergo the same validation as global hooks: entry-point path
/// traversal checks and SHA-256 integrity hashing.
///
/// The `workspace_path` field on each hook's manifest is set to the
/// canonicalized working directory.
pub fn load_workspace_hooks(working_dir: &Path) -> Result<Vec<LoadedHook>, String> {
    let hooks_dir = workspace_hooks_dir(working_dir);
    if !hooks_dir.exists() {
        return Ok(Vec::new());
    }

    // Security: validate the hooks dir is actually within the working dir.
    let canonical_hooks_dir = validate_workspace_hooks_dir(&hooks_dir, working_dir)?;

    let canonical_working_dir = working_dir
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize working dir: {e}"))?;

    let entries = std::fs::read_dir(&canonical_hooks_dir)
        .map_err(|e| format!("failed to read workspace hooks directory: {e}"))?;

    let mut loaded = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read directory entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let manifest_path = path.join("manifest.toml");
        if !manifest_path.exists() {
            tracing::debug!(
                dir = %path.display(),
                "skipping workspace hook directory without manifest.toml"
            );
            continue;
        }

        match load_workspace_hook(&path, &manifest_path, &canonical_working_dir) {
            Ok(hook) => {
                tracing::info!(
                    hook = %hook.manifest.name,
                    workspace = %canonical_working_dir.display(),
                    "loaded workspace hook"
                );
                loaded.push(hook);
            }
            Err(e) => {
                tracing::warn!(
                    dir = %path.display(),
                    error = %e,
                    "failed to load workspace hook"
                );
            }
        }
    }

    Ok(loaded)
}

/// Load a single workspace hook from its directory and manifest.
fn load_workspace_hook(
    hook_dir: &Path,
    manifest_path: &Path,
    workspace_path: &Path,
) -> Result<LoadedHook, String> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read manifest: {e}"))?;
    let mut manifest: HookManifest =
        toml::from_str(&content).map_err(|e| format!("failed to parse manifest.toml: {e}"))?;

    // Set workspace path on the manifest.
    manifest.workspace_path = Some(workspace_path.to_path_buf());

    // Validate entry_point: must not contain path traversal components.
    validate_entry_point(&manifest.entry_point)?;

    let entry_point_abs = hook_dir.join(&manifest.entry_point);

    // Resolve to canonical path and verify it stays within the hook directory.
    let canonical_hook_dir = hook_dir
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize hook dir: {e}"))?;
    let canonical_entry = entry_point_abs
        .canonicalize()
        .map_err(|e| format!("entry point does not exist or cannot be resolved: {e}"))?;

    if !canonical_entry.starts_with(&canonical_hook_dir) {
        return Err(format!(
            "entry point escapes hook directory: {} is not under {}",
            canonical_entry.display(),
            canonical_hook_dir.display()
        ));
    }

    // Compute SHA-256 of the script.
    let script_bytes = std::fs::read(&canonical_entry)
        .map_err(|e| format!("failed to read entry point script: {e}"))?;
    let script_hash = compute_sha256(&script_bytes);

    let name = manifest.name.clone();
    Ok(LoadedHook {
        manifest,
        hook_dir: hook_dir.to_path_buf(),
        entry_point_abs: canonical_entry,
        script_hash,
        status: HookStatus {
            name: name.clone(),
            state: HookState::Installed,
            last_run: None,
            last_success: false,
            error_count: 0,
            run_count: 0,
        },
        source: HookSource::Workspace(workspace_path.to_path_buf()),
    })
}

/// Merge global and workspace hooks into a single list.
///
/// Merge semantics:
/// - Workspace hooks override global hooks with the same name (unless reserved).
/// - Workspace hooks can add new hooks not present globally.
/// - Global hooks not overridden are preserved.
/// - The result is ordered: workspace-specific hooks first, then remaining globals.
/// - Reserved hook names cannot be overridden by workspace hooks; an attempt
///   to do so is logged as a warning and the workspace hook is dropped.
pub fn merge_hooks(
    global: Vec<LoadedHook>,
    workspace: Vec<LoadedHook>,
    reserved_names: &[String],
) -> Vec<LoadedHook> {
    let global_names: std::collections::HashSet<String> =
        global.iter().map(|h| h.manifest.name.clone()).collect();

    let mut result: Vec<LoadedHook> = Vec::new();
    let mut overridden: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Add workspace hooks first.
    for hook in workspace {
        if reserved_names.contains(&hook.manifest.name) {
            tracing::warn!(
                hook = %hook.manifest.name,
                "workspace hook cannot override reserved hook name; skipping"
            );
            continue;
        }
        if global_names.contains(&hook.manifest.name) {
            tracing::info!(
                hook = %hook.manifest.name,
                "workspace hook overrides global hook"
            );
            overridden.insert(hook.manifest.name.clone());
        }
        result.push(hook);
    }

    // Add remaining global hooks that were not overridden.
    for hook in global {
        if !overridden.contains(&hook.manifest.name) {
            result.push(hook);
        }
    }

    result
}

/// Check whether a loaded hook should activate for a given agent working directory.
///
/// - Global hooks always match.
/// - Workspace hooks only match if the agent's working directory is within
///   (or equal to) the workspace that the hook was loaded from.
pub fn matches_workspace(hook: &LoadedHook, agent_working_dir: &Path) -> bool {
    match &hook.source {
        HookSource::Global => true,
        HookSource::Workspace(workspace_path) => {
            // Try canonicalizing both for accurate comparison.
            let canonical_agent = agent_working_dir
                .canonicalize()
                .unwrap_or_else(|_| agent_working_dir.to_path_buf());
            let canonical_workspace = workspace_path
                .canonicalize()
                .unwrap_or_else(|_| workspace_path.to_path_buf());
            canonical_agent.starts_with(&canonical_workspace)
        }
    }
}

/// Sanitize a workspace path string for use as an environment variable value.
///
/// Rejects null bytes and control characters (except space). Returns the
/// sanitized string or an error if the path contains forbidden characters.
pub fn sanitize_workspace_env(path: &Path) -> Result<String, String> {
    let s = path.to_string_lossy();
    if s.contains('\0') {
        return Err("workspace path contains null bytes".to_string());
    }
    // Reject control characters (anything below 0x20 except nothing --
    // we do not allow any control chars including \t \n in paths).
    if s.chars().any(|c| c.is_control()) {
        return Err("workspace path contains control characters".to_string());
    }
    Ok(s.to_string())
}

/// Build a restricted environment for workspace hook execution.
///
/// Extends the base restricted environment with AEGIS_HOOK_WORKSPACE
/// pointing to the sanitized workspace path.
pub fn build_workspace_hook_env(
    hook_name: &str,
    hook_dir: &Path,
    workspace_path: Option<&Path>,
) -> Vec<(String, String)> {
    let mut env = build_restricted_env(hook_name, hook_dir);
    if let Some(ws) = workspace_path {
        if let Ok(sanitized) = sanitize_workspace_env(ws) {
            env.push(("AEGIS_HOOK_WORKSPACE".to_string(), sanitized));
        } else {
            tracing::warn!(
                path = %ws.display(),
                "workspace path failed sanitization; AEGIS_HOOK_WORKSPACE not set"
            );
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hook_settings_structure() {
        let settings = generate_hook_settings();
        let hooks = settings.get("hooks").expect("should have hooks key");

        // Verify PreToolUse
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let pre_arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(pre_arr.len(), 1);
        let pre_group = &pre_arr[0];
        let pre_inner = pre_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let pre_handlers = pre_inner.as_array().expect("hooks should be array");
        assert_eq!(pre_handlers.len(), 1);
        assert_eq!(
            pre_handlers[0].get("type").unwrap().as_str().unwrap(),
            "command"
        );
        assert!(pre_handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook pre-tool-use"));

        // Verify PostToolUse
        let post = hooks.get("PostToolUse").expect("should have PostToolUse");
        let post_arr = post.as_array().expect("PostToolUse should be array");
        assert_eq!(post_arr.len(), 1);
        let post_group = &post_arr[0];
        let post_inner = post_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let post_handlers = post_inner.as_array().expect("hooks should be array");
        assert_eq!(post_handlers.len(), 1);
        assert_eq!(
            post_handlers[0].get("type").unwrap().as_str().unwrap(),
            "command"
        );
        assert!(post_handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook post-tool-use"));

        // Verify Stop
        let stop = hooks.get("Stop").expect("should have Stop");
        let stop_arr = stop.as_array().expect("Stop should be array");
        assert_eq!(stop_arr.len(), 1);
        let stop_group = &stop_arr[0];
        let stop_inner = stop_group
            .get("hooks")
            .expect("matcher group should have hooks array");
        let stop_handlers = stop_inner.as_array().expect("hooks should be array");
        assert_eq!(stop_handlers.len(), 1);
        assert_eq!(
            stop_handlers[0].get("type").unwrap().as_str().unwrap(),
            "command"
        );
        assert!(stop_handlers[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("aegis hook session-end"));
    }

    #[test]
    fn install_daemon_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.local.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // PreToolUse installed
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        let pre_handlers = pre[0]["hooks"].as_array().unwrap();
        assert_eq!(pre_handlers.len(), 1);
        assert!(pre_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook pre-tool-use"));

        // PostToolUse installed
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1);
        let post_handlers = post[0]["hooks"].as_array().unwrap();
        assert_eq!(post_handlers.len(), 1);
        assert!(post_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook post-tool-use"));

        // Stop installed
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
        let stop_handlers = stop[0]["hooks"].as_array().unwrap();
        assert_eq!(stop_handlers.len(), 1);
        assert!(stop_handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("aegis hook session-end"));
    }

    #[test]
    fn install_daemon_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_daemon_hooks(tmpdir.path()).expect("first install");
        install_daemon_hooks(tmpdir.path()).expect("second install");

        let content =
            std::fs::read_to_string(tmpdir.path().join(".claude").join("settings.local.json"))
                .unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate PreToolUse hook entry");
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1, "should not duplicate PostToolUse hook entry");
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1, "should not duplicate Stop hook entry");
    }

    #[test]
    fn install_daemon_hooks_preserves_existing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let claude_dir = tmpdir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Write existing settings with other config and a non-aegis PostToolUse hook
        let existing = serde_json::json!({
            "model": "claude-sonnet-4-5-20250929",
            "hooks": {
                "PostToolUse": [
                    {"type": "command", "command": "echo done"}
                ]
            }
        });
        std::fs::write(
            claude_dir.join("settings.local.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_daemon_hooks(tmpdir.path()).expect("should install");

        let content = std::fs::read_to_string(claude_dir.join("settings.local.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Model should be preserved
        assert_eq!(
            settings["model"].as_str().unwrap(),
            "claude-sonnet-4-5-20250929"
        );
        // PostToolUse should have the existing non-aegis entry plus the new aegis entry
        assert_eq!(
            settings["hooks"]["PostToolUse"].as_array().unwrap().len(),
            2,
            "should have both existing and aegis PostToolUse entries"
        );
        // PreToolUse hook should be added
        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn install_project_hooks_creates_file() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_project_hooks(tmpdir.path()).expect("should install");

        let settings_path = tmpdir.path().join(".claude").join("settings.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1);
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
    }

    #[test]
    fn install_project_hooks_idempotent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_project_hooks(tmpdir.path()).expect("first install");
        install_project_hooks(tmpdir.path()).expect("second install");

        let content =
            std::fs::read_to_string(tmpdir.path().join(".claude").join("settings.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should not duplicate PreToolUse hook entry");
        let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1, "should not duplicate PostToolUse hook entry");
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1, "should not duplicate Stop hook entry");
    }

    #[test]
    fn is_aegis_hook_installed_detection() {
        // Nested format (correct)
        let hooks = vec![serde_json::json!({
            "hooks": [{
                "type": "command",
                "command": "aegis hook pre-tool-use"
            }]
        })];
        assert!(is_aegis_hook_installed(&hooks));

        // Legacy flat format (still detected for robustness)
        let flat = vec![serde_json::json!({
            "type": "command",
            "command": "aegis hook pre-tool-use"
        })];
        assert!(is_aegis_hook_installed(&flat));

        let empty: Vec<serde_json::Value> = vec![];
        assert!(!is_aegis_hook_installed(&empty));

        let other = vec![serde_json::json!({
            "hooks": [{
                "type": "command",
                "command": "echo hello"
            }]
        })];
        assert!(!is_aegis_hook_installed(&other));
    }

    #[test]
    fn openclaw_bridge_connected_false_when_missing() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        assert!(!openclaw_bridge_connected(tmpdir.path()));
    }

    #[test]
    fn install_openclaw_daemon_bridge_creates_bundle() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        install_openclaw_daemon_bridge(tmpdir.path(), "openclaw-1").expect("install bridge");

        let marker = openclaw_bridge_marker_path(tmpdir.path());
        let config = openclaw_bridge_config_path(tmpdir.path());
        let hook_md = tmpdir
            .path()
            .join("hooks")
            .join("aegis-policy-gate")
            .join("HOOK.md");
        let hook_handler = tmpdir
            .path()
            .join("hooks")
            .join("aegis-policy-gate")
            .join("handler.ts");

        assert!(marker.exists(), "marker should exist");
        assert!(config.exists(), "bridge config should exist");
        assert!(hook_md.exists(), "hook metadata should exist");
        assert!(hook_handler.exists(), "hook handler should exist");
        assert!(openclaw_bridge_installed(tmpdir.path()));
        assert!(!openclaw_bridge_connected(tmpdir.path()));

        let config_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
        assert_eq!(
            config_json["hooks"]["internal"]["enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            config_json["hooks"]["internal"]["entries"]["aegis-policy-gate"]["enabled"].as_bool(),
            Some(true)
        );
    }

    // -----------------------------------------------------------------------
    // User-extensible hook system tests
    // -----------------------------------------------------------------------

    /// Helper: create a hook directory with manifest.toml and a script.
    fn create_test_hook(
        hooks_dir: &Path,
        name: &str,
        trigger: &str,
        script_content: &str,
    ) -> PathBuf {
        let hook_dir = hooks_dir.join(name);
        std::fs::create_dir_all(&hook_dir).unwrap();

        let manifest = format!(
            r#"name = "{name}"
version = "1.0.0"
description = "Test hook"
trigger = "{trigger}"
entry_point = "hook.sh"
timeout_secs = 5
permissions = ["read"]
"#
        );
        std::fs::write(hook_dir.join("manifest.toml"), manifest).unwrap();

        let script_path = hook_dir.join("hook.sh");
        std::fs::write(&script_path, script_content).unwrap();

        // Make the script executable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        hook_dir
    }

    #[test]
    fn test_hook_manifest_parsing() {
        let toml_str = r#"
name = "my-hook"
version = "2.0.0"
description = "A test hook"
trigger = "pre_tool_use"
entry_point = "run.sh"
timeout_secs = 10
permissions = ["read", "net"]
"#;
        let manifest: HookManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.name, "my-hook");
        assert_eq!(manifest.version, "2.0.0");
        assert_eq!(manifest.description, "A test hook");
        assert_eq!(manifest.trigger, HookTrigger::PreToolUse);
        assert_eq!(manifest.entry_point, PathBuf::from("run.sh"));
        assert_eq!(manifest.timeout_secs, 10);
        assert_eq!(manifest.permissions, vec!["read", "net"]);
    }

    #[test]
    fn test_hook_manifest_defaults() {
        let toml_str = r#"
name = "minimal"
trigger = "on_exit"
entry_point = "hook.sh"
"#;
        let manifest: HookManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.timeout_secs, 30);
        assert!(manifest.permissions.is_empty());
    }

    #[test]
    fn test_hook_manifest_custom_trigger() {
        let toml_str = r#"
name = "custom-hook"
trigger = { "custom" = "my_event" }
entry_point = "hook.sh"
"#;
        let manifest: HookManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(
            manifest.trigger,
            HookTrigger::Custom("my_event".to_string())
        );
    }

    #[test]
    fn test_hook_discovery_from_filesystem() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(
            &hooks_dir,
            "hook-a",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );
        create_test_hook(
            &hooks_dir,
            "hook-b",
            "on_exit",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        let count = registry.load_all().expect("should load hooks");
        assert_eq!(count, 2);
        assert_eq!(registry.hook_count(), 2);

        let hook_a = registry.get_hook("hook-a").expect("hook-a should exist");
        assert_eq!(hook_a.manifest.trigger, HookTrigger::PreToolUse);
        assert_eq!(hook_a.status.state, HookState::Installed);

        let hook_b = registry.get_hook("hook-b").expect("hook-b should exist");
        assert_eq!(hook_b.manifest.trigger, HookTrigger::OnExit);
    }

    #[test]
    fn test_hook_discovery_empty_dir() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        let mut registry = HookRegistry::new(hooks_dir);
        let count = registry.load_all().expect("should load");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_hook_discovery_missing_dir() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("nonexistent");

        let mut registry = HookRegistry::new(hooks_dir);
        let count = registry.load_all().expect("should succeed with 0");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_hook_execution_with_timeout() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        // Create a hook that sleeps longer than its timeout.
        create_test_hook(
            &hooks_dir,
            "slow-hook",
            "pre_tool_use",
            "#!/bin/sh\nsleep 30\necho '{\"action\":\"allow\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");
        registry.enable("slow-hook").expect("should enable");

        // Override timeout to 1 second for test speed.
        if let Some(hook) = registry.hooks.get_mut("slow-hook") {
            hook.manifest.timeout_secs = 1;
        }

        let input = serde_json::json!({"event": "test"});
        let result = registry.execute_hook("slow-hook", &input).await;

        assert!(result.is_err(), "should timeout");
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out"),
            "error should mention timeout: {err}"
        );

        // Status should reflect the error.
        let status = registry.get_status("slow-hook").unwrap();
        assert_eq!(status.error_count, 1);
    }

    #[tokio::test]
    async fn test_hook_can_block_action() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(
            &hooks_dir,
            "blocker",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"block\",\"message\":\"denied by hook\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");
        registry.enable("blocker").expect("should enable");

        let input = serde_json::json!({"tool": "bash", "args": {"command": "rm -rf /"}});
        let result = registry.execute_hook("blocker", &input).await;

        let hook_result = result.expect("should succeed");
        assert_eq!(hook_result.action, HookAction::Block);
        assert_eq!(hook_result.message, "denied by hook");
    }

    #[tokio::test]
    async fn test_hook_allow_action() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(
            &hooks_dir,
            "allower",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\",\"message\":\"ok\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");
        registry.enable("allower").expect("should enable");

        let input = serde_json::json!({"tool": "read"});
        let result = registry.execute_hook("allower", &input).await;

        let hook_result = result.expect("should succeed");
        assert_eq!(hook_result.action, HookAction::Allow);
    }

    #[test]
    fn test_hook_integrity_check_detects_changes() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        let hook_dir = create_test_hook(
            &hooks_dir,
            "integrity-hook",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");
        registry.enable("integrity-hook").expect("should enable");

        // Record original hash.
        let original_hash = registry
            .get_hook("integrity-hook")
            .unwrap()
            .script_hash
            .clone();

        // Tamper with the script.
        let script_path = hook_dir.join("hook.sh");
        std::fs::write(&script_path, "#!/bin/sh\necho HACKED").unwrap();

        // Verify hash changed.
        let tampered_bytes = std::fs::read(&script_path).unwrap();
        let tampered_hash = compute_sha256(&tampered_bytes);
        assert_ne!(original_hash, tampered_hash);

        // Execute should fail due to integrity check.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let input = serde_json::json!({"test": true});
        let result = rt.block_on(registry.execute_hook("integrity-hook", &input));
        assert!(result.is_err(), "should fail integrity check");
        let err = result.unwrap_err();
        assert!(
            err.contains("integrity check failed"),
            "error should mention integrity: {err}"
        );
    }

    #[test]
    fn test_hook_status_tracking() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(
            &hooks_dir,
            "status-hook",
            "on_approval",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");

        // Initially Installed.
        let status = registry.get_status("status-hook").unwrap();
        assert_eq!(status.state, HookState::Installed);

        // Enable -> Active.
        registry.enable("status-hook").unwrap();
        let status = registry.get_status("status-hook").unwrap();
        assert_eq!(status.state, HookState::Active);

        // Disable -> Disabled.
        registry.disable("status-hook").unwrap();
        let status = registry.get_status("status-hook").unwrap();
        assert_eq!(status.state, HookState::Disabled);

        // Enable again -> Active.
        registry.enable("status-hook").unwrap();
        let status = registry.get_status("status-hook").unwrap();
        assert_eq!(status.state, HookState::Active);

        // Simulate error state by manually setting it, then enable recovers.
        if let Some(h) = registry.hooks.get_mut("status-hook") {
            h.status.state = HookState::Error("test error".to_string());
        }
        let status = registry.get_status("status-hook").unwrap();
        assert!(matches!(status.state, HookState::Error(_)));

        registry.enable("status-hook").unwrap();
        let status = registry.get_status("status-hook").unwrap();
        assert_eq!(status.state, HookState::Active);
    }

    #[test]
    fn test_hook_path_traversal_rejected() {
        // Direct validation.
        assert!(validate_entry_point(Path::new("../escape.sh")).is_err());
        assert!(validate_entry_point(Path::new("subdir/../escape.sh")).is_err());
        assert!(validate_entry_point(Path::new("/absolute/path.sh")).is_err());
        assert!(validate_entry_point(Path::new("hook.sh")).is_ok());
        assert!(validate_entry_point(Path::new("subdir/hook.sh")).is_ok());

        // Full manifest loading with traversal should fail.
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");
        let hook_dir = hooks_dir.join("evil-hook");
        std::fs::create_dir_all(&hook_dir).unwrap();

        let manifest = r#"
name = "evil-hook"
trigger = "pre_tool_use"
entry_point = "../../../etc/passwd"
"#;
        std::fs::write(hook_dir.join("manifest.toml"), manifest).unwrap();
        // Create a dummy script so directory exists (won't be used).
        std::fs::write(hook_dir.join("hook.sh"), "#!/bin/sh").unwrap();

        let mut registry = HookRegistry::new(hooks_dir);
        let count = registry.load_all().expect("load_all should not panic");
        assert_eq!(count, 0, "hook with path traversal should not be loaded");
    }

    #[test]
    fn test_hook_trigger_filtering() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(&hooks_dir, "pre-a", "pre_tool_use", "#!/bin/sh\ntrue");
        create_test_hook(&hooks_dir, "pre-b", "pre_tool_use", "#!/bin/sh\ntrue");
        create_test_hook(&hooks_dir, "post-c", "post_tool_use", "#!/bin/sh\ntrue");

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");

        // Enable all hooks.
        registry.enable("pre-a").unwrap();
        registry.enable("pre-b").unwrap();
        registry.enable("post-c").unwrap();

        let pre_hooks = registry.get_hooks_for_trigger(&HookTrigger::PreToolUse);
        assert_eq!(pre_hooks.len(), 2);

        let post_hooks = registry.get_hooks_for_trigger(&HookTrigger::PostToolUse);
        assert_eq!(post_hooks.len(), 1);

        let exit_hooks = registry.get_hooks_for_trigger(&HookTrigger::OnExit);
        assert_eq!(exit_hooks.len(), 0);
    }

    #[test]
    fn test_hook_disabled_not_in_trigger_results() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(&hooks_dir, "hook-x", "pre_tool_use", "#!/bin/sh\ntrue");

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");

        // Not enabled: should not appear in trigger results.
        let hooks = registry.get_hooks_for_trigger(&HookTrigger::PreToolUse);
        assert_eq!(
            hooks.len(),
            0,
            "installed-but-not-active hooks should be excluded"
        );

        // Enable, then disable.
        registry.enable("hook-x").unwrap();
        let hooks = registry.get_hooks_for_trigger(&HookTrigger::PreToolUse);
        assert_eq!(hooks.len(), 1);

        registry.disable("hook-x").unwrap();
        let hooks = registry.get_hooks_for_trigger(&HookTrigger::PreToolUse);
        assert_eq!(hooks.len(), 0);
    }

    #[test]
    fn test_sha256_computation() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        // Known SHA-256 of "hello world".
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_validate_entry_point_null_bytes() {
        let path = PathBuf::from("hook\0.sh");
        assert!(validate_entry_point(&path).is_err());
    }

    #[test]
    fn test_hook_result_serialization() {
        let result = HookResult {
            action: HookAction::Block,
            message: "not allowed".to_string(),
            data: Some(serde_json::json!({"reason": "policy"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: HookResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, HookAction::Block);
        assert_eq!(back.message, "not allowed");
    }

    #[test]
    fn test_sanitize_hook_output() {
        let raw = "normal text\nwith newlines\tand tabs\x07but no bells";
        let clean = sanitize_hook_output(raw);
        assert!(clean.contains("normal text"));
        assert!(clean.contains('\n'));
        assert!(clean.contains('\t'));
        assert!(!clean.contains('\x07'));
    }

    #[test]
    fn test_hook_install_from_external_path() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("installed_hooks");
        let source_dir = tmpdir.path().join("source");

        // Create source hook.
        std::fs::create_dir_all(&source_dir).unwrap();
        let manifest = r#"
name = "ext-hook"
trigger = "on_stall"
entry_point = "run.sh"
"#;
        std::fs::write(source_dir.join("manifest.toml"), manifest).unwrap();
        let script = "#!/bin/sh\necho '{\"action\":\"allow\"}'";
        std::fs::write(source_dir.join("run.sh"), script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                source_dir.join("run.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        let mut registry = HookRegistry::new(hooks_dir.clone());
        let name = registry.install_hook(&source_dir).expect("should install");
        assert_eq!(name, "ext-hook");

        // Verify the hook was copied into the hooks directory.
        assert!(hooks_dir.join("ext-hook").join("manifest.toml").exists());
        assert!(hooks_dir.join("ext-hook").join("run.sh").exists());

        // Verify it was loaded into the registry.
        let hook = registry.get_hook("ext-hook").expect("should be loaded");
        assert_eq!(hook.manifest.trigger, HookTrigger::OnStall);
    }

    #[tokio::test]
    async fn test_hook_inactive_cannot_execute() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let hooks_dir = tmpdir.path().join("hooks");

        create_test_hook(
            &hooks_dir,
            "inactive-hook",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let mut registry = HookRegistry::new(hooks_dir);
        registry.load_all().expect("should load");
        // Do NOT enable -- state is Installed, not Active.

        let input = serde_json::json!({"test": true});
        let result = registry.execute_hook("inactive-hook", &input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not active"));
    }

    #[test]
    fn test_restricted_env_only_safe_vars() {
        let env = build_restricted_env("test-hook", Path::new("/tmp/hooks/test"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();

        // Should contain only safe vars.
        for key in &keys {
            assert!(
                *key == "PATH" || *key == "HOME" || key.starts_with("AEGIS_HOOK_"),
                "unexpected env var: {key}"
            );
        }

        // Must contain AEGIS_HOOK_NAME and AEGIS_HOOK_DIR.
        assert!(keys.contains(&"AEGIS_HOOK_NAME"));
        assert!(keys.contains(&"AEGIS_HOOK_DIR"));
    }

    // -----------------------------------------------------------------------
    // Workspace hook tests
    // -----------------------------------------------------------------------

    /// Helper: create a hook directory with manifest.toml and a script inside
    /// a workspace `.aegis/hooks/` structure.
    fn create_workspace_hook(
        working_dir: &Path,
        name: &str,
        trigger: &str,
        script_content: &str,
    ) -> PathBuf {
        let hooks_dir = working_dir.join(".aegis").join("hooks");
        create_test_hook(&hooks_dir, name, trigger, script_content)
    }

    #[test]
    fn test_workspace_hooks_discovered() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let working_dir = tmpdir.path();

        create_workspace_hook(
            working_dir,
            "ws-hook-a",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );
        create_workspace_hook(
            working_dir,
            "ws-hook-b",
            "on_exit",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let hooks = load_workspace_hooks(working_dir).expect("should load workspace hooks");
        assert_eq!(hooks.len(), 2);

        let names: Vec<&str> = hooks.iter().map(|h| h.manifest.name.as_str()).collect();
        assert!(names.contains(&"ws-hook-a"));
        assert!(names.contains(&"ws-hook-b"));

        // All should be tagged as workspace hooks.
        for hook in &hooks {
            assert!(
                matches!(&hook.source, HookSource::Workspace(_)),
                "hook should have workspace source"
            );
        }

        // workspace_path should be set on manifests.
        for hook in &hooks {
            assert!(
                hook.manifest.workspace_path.is_some(),
                "workspace_path should be set"
            );
        }
    }

    #[test]
    fn test_workspace_hooks_override_global() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let global_hooks_dir = tmpdir.path().join("global_hooks");
        let working_dir = tmpdir.path().join("workspace");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create a global hook named "shared-hook".
        create_test_hook(
            &global_hooks_dir,
            "shared-hook",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\",\"message\":\"global\"}'",
        );

        // Create a workspace hook with the same name.
        create_workspace_hook(
            &working_dir,
            "shared-hook",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"block\",\"message\":\"workspace\"}'",
        );

        // Load both.
        let mut global_registry = HookRegistry::new(global_hooks_dir);
        global_registry.load_all().expect("load global");
        let global: Vec<LoadedHook> = global_registry.hooks.into_values().collect();

        let workspace = load_workspace_hooks(&working_dir).expect("load workspace");

        let merged = merge_hooks(global, workspace, &[]);
        assert_eq!(merged.len(), 1, "should have one merged hook, not two");

        let hook = &merged[0];
        assert!(
            matches!(&hook.source, HookSource::Workspace(_)),
            "merged hook should be the workspace version"
        );
    }

    #[test]
    fn test_workspace_scope_respects_working_dir() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let workspace_a = tmpdir.path().join("workspace_a");
        let workspace_b = tmpdir.path().join("workspace_b");
        std::fs::create_dir_all(&workspace_a).unwrap();
        std::fs::create_dir_all(&workspace_b).unwrap();

        // Create a hook in workspace_a.
        create_workspace_hook(&workspace_a, "ws-a-hook", "pre_tool_use", "#!/bin/sh\ntrue");

        let hooks = load_workspace_hooks(&workspace_a).expect("load");
        assert_eq!(hooks.len(), 1);

        let hook = &hooks[0];

        // Should match an agent working in workspace_a.
        assert!(matches_workspace(hook, &workspace_a));

        // Should match an agent working in a subdirectory of workspace_a.
        let subdir = workspace_a.join("subproject");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(matches_workspace(hook, &subdir));

        // Should NOT match an agent working in workspace_b.
        assert!(!matches_workspace(hook, &workspace_b));
    }

    #[test]
    fn test_workspace_hooks_still_security_scanned() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let working_dir = tmpdir.path();

        // Create a workspace hook.
        create_workspace_hook(
            working_dir,
            "secure-hook",
            "pre_tool_use",
            "#!/bin/sh\necho '{\"action\":\"allow\"}'",
        );

        let hooks = load_workspace_hooks(working_dir).expect("load");
        assert_eq!(hooks.len(), 1);

        // Verify SHA-256 hash is computed.
        let hook = &hooks[0];
        assert!(
            !hook.script_hash.is_empty(),
            "SHA-256 hash should be computed"
        );

        // Verify the hash is correct.
        let script_path = hook.entry_point_abs.clone();
        let script_bytes = std::fs::read(&script_path).unwrap();
        let expected_hash = compute_sha256(&script_bytes);
        assert_eq!(hook.script_hash, expected_hash);
    }

    #[test]
    fn test_merge_preserves_global_only_hooks() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let global_hooks_dir = tmpdir.path().join("global_hooks");
        let working_dir = tmpdir.path().join("workspace");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create two global hooks.
        create_test_hook(
            &global_hooks_dir,
            "global-only",
            "pre_tool_use",
            "#!/bin/sh\ntrue",
        );
        create_test_hook(&global_hooks_dir, "shared", "on_exit", "#!/bin/sh\ntrue");

        // Create one workspace hook that overrides "shared".
        create_workspace_hook(&working_dir, "shared", "on_exit", "#!/bin/sh\ntrue");

        let mut global_registry = HookRegistry::new(global_hooks_dir);
        global_registry.load_all().expect("load global");
        let global: Vec<LoadedHook> = global_registry.hooks.into_values().collect();

        let workspace = load_workspace_hooks(&working_dir).expect("load workspace");

        let merged = merge_hooks(global, workspace, &[]);
        assert_eq!(merged.len(), 2, "global-only + overridden shared = 2");

        let names: Vec<&str> = merged.iter().map(|h| h.manifest.name.as_str()).collect();
        assert!(names.contains(&"global-only"));
        assert!(names.contains(&"shared"));

        // The "global-only" hook should have Global source.
        let global_only = merged
            .iter()
            .find(|h| h.manifest.name == "global-only")
            .unwrap();
        assert_eq!(global_only.source, HookSource::Global);
    }

    #[test]
    fn test_merge_adds_workspace_only_hooks() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let global_hooks_dir = tmpdir.path().join("global_hooks");
        let working_dir = tmpdir.path().join("workspace");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create one global hook.
        create_test_hook(
            &global_hooks_dir,
            "global-hook",
            "pre_tool_use",
            "#!/bin/sh\ntrue",
        );

        // Create a workspace-only hook (no global counterpart).
        create_workspace_hook(&working_dir, "ws-only-hook", "on_stall", "#!/bin/sh\ntrue");

        let mut global_registry = HookRegistry::new(global_hooks_dir);
        global_registry.load_all().expect("load global");
        let global: Vec<LoadedHook> = global_registry.hooks.into_values().collect();

        let workspace = load_workspace_hooks(&working_dir).expect("load workspace");

        let merged = merge_hooks(global, workspace, &[]);
        assert_eq!(merged.len(), 2, "global + workspace-only = 2");

        let names: Vec<&str> = merged.iter().map(|h| h.manifest.name.as_str()).collect();
        assert!(names.contains(&"global-hook"));
        assert!(names.contains(&"ws-only-hook"));

        // Workspace-only hook should appear first in the result.
        assert_eq!(merged[0].manifest.name, "ws-only-hook");
    }

    #[test]
    fn test_workspace_hooks_path_traversal() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let working_dir = tmpdir.path().join("workspace");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create a hooks directory that tries to escape via symlink.
        let evil_dir = tmpdir.path().join("evil_hooks");
        std::fs::create_dir_all(&evil_dir).unwrap();

        let workspace_aegis = working_dir.join(".aegis");
        std::fs::create_dir_all(&workspace_aegis).unwrap();

        // Create a symlink: workspace/.aegis/hooks -> ../../evil_hooks
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&evil_dir, workspace_aegis.join("hooks")).unwrap();
        }

        // validate_workspace_hooks_dir should reject this.
        #[cfg(unix)]
        {
            let result = validate_workspace_hooks_dir(&workspace_aegis.join("hooks"), &working_dir);
            assert!(
                result.is_err(),
                "symlink escaping workspace should be rejected"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("not within working dir"),
                "error should mention containment: {err}"
            );
        }

        // Also test that the entry point path traversal within a workspace hook is rejected.
        let hooks_dir_real = working_dir.join(".aegis").join("hooks_real");
        std::fs::create_dir_all(&hooks_dir_real).unwrap();
        let hook_dir = hooks_dir_real.join("evil-hook");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let manifest = r#"
name = "evil-hook"
trigger = "pre_tool_use"
entry_point = "../../../etc/passwd"
"#;
        std::fs::write(hook_dir.join("manifest.toml"), manifest).unwrap();
        std::fs::write(hook_dir.join("hook.sh"), "#!/bin/sh").unwrap();

        // The entry-point validation should catch the ../ traversal.
        let result = load_workspace_hook(&hook_dir, &hook_dir.join("manifest.toml"), &working_dir);
        assert!(
            result.is_err(),
            "path traversal in entry point should be rejected"
        );
    }

    #[test]
    fn test_reserved_hook_names_cannot_be_overridden() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let global_hooks_dir = tmpdir.path().join("global_hooks");
        let working_dir = tmpdir.path().join("workspace");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create a global hook named "system-audit" (reserved).
        create_test_hook(
            &global_hooks_dir,
            "system-audit",
            "post_tool_use",
            "#!/bin/sh\ntrue",
        );

        // Create a workspace hook that tries to override "system-audit".
        create_workspace_hook(
            &working_dir,
            "system-audit",
            "post_tool_use",
            "#!/bin/sh\necho HACKED",
        );

        let mut global_registry = HookRegistry::new(global_hooks_dir);
        global_registry.load_all().expect("load global");
        let global: Vec<LoadedHook> = global_registry.hooks.into_values().collect();

        let workspace = load_workspace_hooks(&working_dir).expect("load workspace");

        let reserved = vec!["system-audit".to_string()];
        let merged = merge_hooks(global, workspace, &reserved);

        // Should have exactly one hook: the global one.
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].manifest.name, "system-audit");
        assert_eq!(merged[0].source, HookSource::Global);
    }

    #[test]
    fn test_workspace_hook_env_includes_workspace() {
        let env = build_workspace_hook_env(
            "test-hook",
            Path::new("/tmp/hooks/test"),
            Some(Path::new("/home/user/project")),
        );
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();

        assert!(keys.contains(&"AEGIS_HOOK_WORKSPACE"));

        let ws_val = env
            .iter()
            .find(|(k, _)| k == "AEGIS_HOOK_WORKSPACE")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(ws_val, "/home/user/project");
    }

    #[test]
    fn test_workspace_hook_env_without_workspace() {
        let env = build_workspace_hook_env("test-hook", Path::new("/tmp/hooks/test"), None);
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"AEGIS_HOOK_WORKSPACE"));
    }

    #[test]
    fn test_sanitize_workspace_env_rejects_null() {
        let path = PathBuf::from("/home/user/project\0evil");
        assert!(sanitize_workspace_env(&path).is_err());
    }

    #[test]
    fn test_sanitize_workspace_env_rejects_control_chars() {
        let path = PathBuf::from("/home/user/project\x07bell");
        assert!(sanitize_workspace_env(&path).is_err());
    }

    #[test]
    fn test_sanitize_workspace_env_accepts_valid_path() {
        let path = PathBuf::from("/home/user/my project/src");
        let result = sanitize_workspace_env(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/home/user/my project/src");
    }

    #[test]
    fn test_workspace_hooks_empty_when_no_dir() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        // No .aegis/hooks/ directory exists.
        let hooks = load_workspace_hooks(tmpdir.path()).expect("should return empty");
        assert!(hooks.is_empty());
    }

    #[test]
    fn test_global_hook_matches_any_workspace() {
        let hook = LoadedHook {
            manifest: HookManifest {
                name: "global-test".to_string(),
                version: "1.0.0".to_string(),
                description: String::new(),
                trigger: HookTrigger::PreToolUse,
                entry_point: PathBuf::from("hook.sh"),
                timeout_secs: 30,
                permissions: vec![],
                workspace_path: None,
            },
            hook_dir: PathBuf::from("/tmp/hooks/global-test"),
            entry_point_abs: PathBuf::from("/tmp/hooks/global-test/hook.sh"),
            script_hash: "abc123".to_string(),
            status: HookStatus {
                name: "global-test".to_string(),
                state: HookState::Installed,
                last_run: None,
                last_success: false,
                error_count: 0,
                run_count: 0,
            },
            source: HookSource::Global,
        };

        // Global hooks match any directory.
        assert!(matches_workspace(&hook, Path::new("/home/user/project-a")));
        assert!(matches_workspace(&hook, Path::new("/home/user/project-b")));
        assert!(matches_workspace(&hook, Path::new("/tmp/random")));
    }
}
