//! Hook discovery: scan `.aegis/hooks/` directories for hook handler files.
//!
//! Supports two discovery modes:
//! 1. **Convention-based**: Individual script files where the filename (without
//!    extension) maps to an event name. E.g., `pre_tool_use.sh` handles the
//!    `pre_tool_use` event.
//! 2. **Manifest-based**: A `hooks.toml` file that explicitly maps events to
//!    scripts with per-hook configuration (timeouts, enable/disable, globs).
//!
//! Convention-based hooks use a default 10-second timeout and are always enabled
//! unless overridden by a manifest entry for the same script.

use std::path::{Path, PathBuf};

use crate::config::{self, HookEntry, HooksManifest};

/// Supported script file extensions for convention-based discovery.
const SUPPORTED_EXTENSIONS: &[&str] = &["js", "ts", "sh", "py"];

/// A discovered hook script ready for execution.
#[derive(Debug, Clone)]
pub struct DiscoveredHook {
    /// The event name this hook handles (e.g., `pre_tool_use`).
    pub event: String,

    /// Absolute path to the script file.
    pub script_path: PathBuf,

    /// Script language determined from the file extension.
    pub language: ScriptLanguage,

    /// Maximum execution time in milliseconds.
    pub timeout_ms: u64,

    /// Whether this hook is enabled.
    pub enabled: bool,

    /// Whether this hook was discovered via manifest or convention.
    pub source: DiscoverySource,
}

/// How a hook was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Discovered by filename convention (e.g., `pre_tool_use.sh`).
    Convention,
    /// Explicitly defined in `hooks.toml`.
    Manifest,
}

/// Script language, determined from the file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    /// JavaScript (`.js`) -- executed via `node`.
    JavaScript,
    /// TypeScript (`.ts`) -- executed via `npx tsx`, `deno`, or `bun`.
    TypeScript,
    /// Shell script (`.sh`) -- executed via `sh -c`.
    Shell,
    /// Python (`.py`) -- executed via `python3`.
    Python,
}

impl ScriptLanguage {
    /// Determine the script language from a file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "js" => Some(ScriptLanguage::JavaScript),
            "ts" => Some(ScriptLanguage::TypeScript),
            "sh" => Some(ScriptLanguage::Shell),
            "py" => Some(ScriptLanguage::Python),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptLanguage::JavaScript => write!(f, "javascript"),
            ScriptLanguage::TypeScript => write!(f, "typescript"),
            ScriptLanguage::Shell => write!(f, "shell"),
            ScriptLanguage::Python => write!(f, "python"),
        }
    }
}

/// Discover all hook scripts in a hooks directory.
///
/// Scans for both manifest-based hooks (`hooks.toml`) and convention-based
/// hooks (individual script files). If both exist, manifest entries take
/// precedence over convention-discovered hooks for the same script file.
///
/// Returns an error only for I/O failures on the directory itself.
/// Individual hook parsing errors are logged and skipped.
pub fn discover_hooks(hooks_dir: &Path) -> Result<Vec<DiscoveredHook>, String> {
    if !hooks_dir.exists() {
        tracing::debug!(
            path = %hooks_dir.display(),
            "hooks directory does not exist, no hooks discovered"
        );
        return Ok(Vec::new());
    }

    if !hooks_dir.is_dir() {
        return Err(format!(
            "hooks path is not a directory: {}",
            hooks_dir.display()
        ));
    }

    let mut hooks = Vec::new();

    // Phase 1: Load manifest-based hooks.
    let manifest_path = hooks_dir.join("hooks.toml");
    let manifest_scripts: Vec<PathBuf>;

    if manifest_path.exists() {
        match config::load_manifest(&manifest_path) {
            Ok(manifest) => {
                let (manifest_hooks, scripts) = discover_from_manifest(&manifest, hooks_dir);
                hooks.extend(manifest_hooks);
                manifest_scripts = scripts;
            }
            Err(e) => {
                tracing::warn!(
                    path = %manifest_path.display(),
                    error = %e,
                    "failed to load hooks.toml, falling back to convention-only"
                );
                manifest_scripts = Vec::new();
            }
        }
    } else {
        manifest_scripts = Vec::new();
    }

    // Phase 2: Discover convention-based hooks from individual script files.
    let convention_hooks = discover_by_convention(hooks_dir, &manifest_scripts)?;
    hooks.extend(convention_hooks);

    Ok(hooks)
}

/// Discover hooks from a parsed `hooks.toml` manifest.
///
/// Returns the discovered hooks and a list of script paths that were
/// covered by manifest entries (used to avoid duplicate convention discovery).
fn discover_from_manifest(
    manifest: &HooksManifest,
    hooks_dir: &Path,
) -> (Vec<DiscoveredHook>, Vec<PathBuf>) {
    let mut hooks = Vec::new();
    let mut covered_scripts = Vec::new();

    for entry in &manifest.hooks {
        let script_path = hooks_dir.join(&entry.script);

        if !script_path.exists() {
            tracing::warn!(
                script = %entry.script.display(),
                event = %entry.event,
                "manifest references non-existent script, skipping"
            );
            continue;
        }

        let ext = script_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let language = match ScriptLanguage::from_extension(ext) {
            Some(lang) => lang,
            None => {
                tracing::warn!(
                    script = %entry.script.display(),
                    extension = ext,
                    "unsupported script extension in manifest, skipping"
                );
                continue;
            }
        };

        covered_scripts.push(script_path.clone());
        hooks.push(DiscoveredHook {
            event: entry.event.clone(),
            script_path,
            language,
            timeout_ms: entry.timeout_ms,
            enabled: entry.enabled,
            source: DiscoverySource::Manifest,
        });
    }

    (hooks, covered_scripts)
}

/// Discover hooks by filename convention: `<event_name>.<ext>`.
///
/// Only files with supported extensions (`.js`, `.ts`, `.sh`, `.py`) are
/// considered. Files already covered by manifest entries are skipped.
fn discover_by_convention(
    hooks_dir: &Path,
    manifest_scripts: &[PathBuf],
) -> Result<Vec<DiscoveredHook>, String> {
    let entries =
        std::fs::read_dir(hooks_dir).map_err(|e| format!("failed to read hooks directory: {e}"))?;

    let mut hooks = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read directory entry: {e}"))?;
        let path = entry.path();

        // Skip directories and the hooks.toml file itself.
        if path.is_dir() || path.file_name().is_some_and(|n| n == "hooks.toml") {
            continue;
        }

        // Check if this file has a supported extension.
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) if SUPPORTED_EXTENSIONS.contains(&ext) => ext,
            _ => continue,
        };

        // Skip files already covered by manifest.
        if manifest_scripts.contains(&path) {
            continue;
        }

        let language = match ScriptLanguage::from_extension(ext) {
            Some(lang) => lang,
            None => continue,
        };

        // Event name is the file stem (filename without extension).
        let event_name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        hooks.push(DiscoveredHook {
            event: event_name,
            script_path: path,
            language,
            timeout_ms: 10_000,
            enabled: true,
            source: DiscoverySource::Convention,
        });
    }

    Ok(hooks)
}

/// Discover hooks from multiple directories, merging results.
///
/// Later directories take precedence: if the same event name appears in
/// multiple directories, the last one wins (workspace hooks override globals).
pub fn discover_hooks_merged(dirs: &[&Path]) -> Result<Vec<DiscoveredHook>, String> {
    let mut all_hooks = Vec::new();

    for dir in dirs {
        let hooks = discover_hooks(dir)?;
        all_hooks.extend(hooks);
    }

    // Deduplicate: if multiple hooks target the same event from the same
    // script path, keep only the last one (later dirs have higher priority).
    // But allow multiple hooks for the same event from different scripts.
    let mut seen: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    let mut result = Vec::new();

    // Process in reverse so later-discovered hooks take precedence.
    for hook in all_hooks.into_iter().rev() {
        let paths = seen.entry(hook.event.clone()).or_default();
        if !paths.contains(&hook.script_path) {
            paths.push(hook.script_path.clone());
            result.push(hook);
        }
    }

    // Reverse back to original order.
    result.reverse();
    Ok(result)
}

/// Check whether a given event name matches any of the provided hook entries.
///
/// Uses the glob matching from [`HookEntry::matches_event`] for manifest hooks,
/// and exact name matching for convention hooks.
pub fn hooks_for_event<'a>(
    hooks: &'a [DiscoveredHook],
    event_name: &str,
) -> Vec<&'a DiscoveredHook> {
    hooks
        .iter()
        .filter(|h| {
            if !h.enabled {
                return false;
            }
            match h.source {
                DiscoverySource::Convention => h.event == event_name,
                DiscoverySource::Manifest => {
                    // Build a temporary HookEntry to reuse glob matching.
                    let entry = HookEntry {
                        event: h.event.clone(),
                        script: h.script_path.clone(),
                        timeout_ms: h.timeout_ms,
                        enabled: h.enabled,
                    };
                    entry.matches_event(event_name)
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = discover_hooks(dir.path()).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn discover_nonexistent_dir() {
        let hooks = discover_hooks(Path::new("/nonexistent/path")).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn discover_convention_scripts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pre_tool_use.sh"), "#!/bin/sh\nexit 0").unwrap();
        std::fs::write(dir.path().join("on_message.py"), "import sys").unwrap();
        std::fs::write(dir.path().join("on_error.js"), "process.exit(0)").unwrap();
        std::fs::write(dir.path().join("README.md"), "# ignore me").unwrap();

        let hooks = discover_hooks(dir.path()).unwrap();
        assert_eq!(hooks.len(), 3);

        let names: Vec<&str> = hooks.iter().map(|h| h.event.as_str()).collect();
        assert!(names.contains(&"pre_tool_use"));
        assert!(names.contains(&"on_message"));
        assert!(names.contains(&"on_error"));
    }

    #[test]
    fn discover_manifest_hooks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("checker.sh"), "#!/bin/sh\nexit 0").unwrap();

        let manifest = r#"
[[hooks]]
event = "pre_tool_use"
script = "checker.sh"
timeout_ms = 3000
"#;
        std::fs::write(dir.path().join("hooks.toml"), manifest).unwrap();

        let hooks = discover_hooks(dir.path()).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].event, "pre_tool_use");
        assert_eq!(hooks[0].timeout_ms, 3000);
        assert_eq!(hooks[0].source, DiscoverySource::Manifest);
    }

    #[test]
    fn manifest_overrides_convention() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pre_tool_use.sh"), "#!/bin/sh\nexit 0").unwrap();

        // Manifest references the same script, so convention discovery should skip it.
        let manifest = r#"
[[hooks]]
event = "pre_*"
script = "pre_tool_use.sh"
timeout_ms = 5000
"#;
        std::fs::write(dir.path().join("hooks.toml"), manifest).unwrap();

        let hooks = discover_hooks(dir.path()).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].timeout_ms, 5000);
        assert_eq!(hooks[0].source, DiscoverySource::Manifest);
    }

    #[test]
    fn language_detection() {
        assert_eq!(
            ScriptLanguage::from_extension("js"),
            Some(ScriptLanguage::JavaScript)
        );
        assert_eq!(
            ScriptLanguage::from_extension("ts"),
            Some(ScriptLanguage::TypeScript)
        );
        assert_eq!(
            ScriptLanguage::from_extension("sh"),
            Some(ScriptLanguage::Shell)
        );
        assert_eq!(
            ScriptLanguage::from_extension("py"),
            Some(ScriptLanguage::Python)
        );
        assert_eq!(ScriptLanguage::from_extension("rb"), None);
    }

    #[test]
    fn hooks_for_event_filters_correctly() {
        let hooks = vec![
            DiscoveredHook {
                event: "pre_tool_use".to_string(),
                script_path: PathBuf::from("/a.sh"),
                language: ScriptLanguage::Shell,
                timeout_ms: 10_000,
                enabled: true,
                source: DiscoverySource::Convention,
            },
            DiscoveredHook {
                event: "on_*".to_string(),
                script_path: PathBuf::from("/b.py"),
                language: ScriptLanguage::Python,
                timeout_ms: 10_000,
                enabled: true,
                source: DiscoverySource::Manifest,
            },
            DiscoveredHook {
                event: "on_message".to_string(),
                script_path: PathBuf::from("/c.js"),
                language: ScriptLanguage::JavaScript,
                timeout_ms: 10_000,
                enabled: false,
                source: DiscoverySource::Convention,
            },
        ];

        let matched = hooks_for_event(&hooks, "on_message");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].script_path, PathBuf::from("/b.py"));

        let matched = hooks_for_event(&hooks, "pre_tool_use");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].script_path, PathBuf::from("/a.sh"));
    }

    #[test]
    fn typescript_extension() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("on_agent_start.ts"), "export default {}").unwrap();

        let hooks = discover_hooks(dir.path()).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].language, ScriptLanguage::TypeScript);
    }
}
