//! Plugin manifest discovery and lifecycle management.
//!
//! Plugins are external processes that communicate via stdin/stdout JSON-RPC.
//! Each plugin directory contains a manifest.toml describing the plugin's
//! capabilities and how to run it.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A plugin manifest loaded from `manifest.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    /// Plugin display name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Command to execute (e.g., "python3", "./my-plugin").
    pub command: String,
    /// Arguments to pass to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to set for the plugin process.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Action identifiers this plugin handles (e.g., ["tool.custom_search", "tool.deploy"]).
    #[serde(default)]
    pub actions: Vec<String>,
}

/// Registry of discovered and loaded plugins.
pub struct PluginRegistry {
    plugins: Vec<PluginManifest>,
}

impl PluginRegistry {
    /// Scan a directory for plugin manifests.
    ///
    /// Expects the directory structure:
    /// ```text
    /// plugin_dir/
    ///   plugin-a/
    ///     manifest.toml
    ///   plugin-b/
    ///     manifest.toml
    /// ```
    ///
    /// Skips subdirectories that do not contain a `manifest.toml` file.
    /// Returns an error only if the plugin directory itself cannot be read.
    pub fn discover(plugin_dir: &Path) -> Result<Self> {
        let mut plugins = Vec::new();

        let entries = std::fs::read_dir(plugin_dir)
            .with_context(|| format!("read plugin directory: {}", plugin_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let manifest_path = path.join("manifest.toml");
            if !manifest_path.exists() {
                continue;
            }

            match Self::load_manifest(&manifest_path) {
                Ok(manifest) => plugins.push(manifest),
                Err(e) => {
                    tracing::warn!(
                        path = %manifest_path.display(),
                        error = %e,
                        "skipping plugin with invalid manifest"
                    );
                }
            }
        }

        Ok(Self { plugins })
    }

    /// Load a single plugin manifest from a TOML file.
    pub fn load_manifest(path: &Path) -> Result<PluginManifest> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read manifest: {}", path.display()))?;

        let manifest: PluginManifest = toml::from_str(&content)
            .with_context(|| format!("parse manifest: {}", path.display()))?;

        Ok(manifest)
    }

    /// List all loaded plugins.
    pub fn list(&self) -> &[PluginManifest] {
        &self.plugins
    }

    /// Find a plugin by name.
    pub fn find(&self, name: &str) -> Option<&PluginManifest> {
        self.plugins.iter().find(|p| p.name == name)
    }

    /// Unload (remove) a plugin by name. Returns `true` if found and removed.
    pub fn unload(&mut self, name: &str) -> bool {
        let before = self.plugins.len();
        self.plugins.retain(|p| p.name != name);
        self.plugins.len() < before
    }

    /// Manually add a loaded manifest to the registry.
    pub fn add(&mut self, manifest: PluginManifest) {
        self.plugins.push(manifest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_manifest(dir: &Path, plugin_name: &str, content: &str) {
        let plugin_dir = dir.join(plugin_name);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join("manifest.toml"), content).unwrap();
    }

    #[test]
    fn manifest_parsing() {
        let dir = TempDir::new().unwrap();
        let manifest_content = r#"
            name = "my-search"
            version = "1.0.0"
            command = "python3"
            args = ["search.py", "--mode", "fast"]
            env = [["API_KEY", "secret123"]]
            actions = ["tool.custom_search", "tool.index"]
        "#;

        write_manifest(dir.path(), "my-search", manifest_content);

        let manifest =
            PluginRegistry::load_manifest(&dir.path().join("my-search").join("manifest.toml"))
                .unwrap();

        assert_eq!(manifest.name, "my-search");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.command, "python3");
        assert_eq!(manifest.args, vec!["search.py", "--mode", "fast"]);
        assert_eq!(manifest.env, vec![("API_KEY".into(), "secret123".into())]);
        assert_eq!(
            manifest.actions,
            vec!["tool.custom_search", "tool.index"]
        );
    }

    #[test]
    fn manifest_minimal() {
        let dir = TempDir::new().unwrap();
        let manifest_content = r#"
            name = "simple"
            version = "0.1.0"
            command = "./run.sh"
        "#;

        write_manifest(dir.path(), "simple", manifest_content);

        let manifest =
            PluginRegistry::load_manifest(&dir.path().join("simple").join("manifest.toml"))
                .unwrap();

        assert_eq!(manifest.name, "simple");
        assert!(manifest.args.is_empty());
        assert!(manifest.env.is_empty());
        assert!(manifest.actions.is_empty());
    }

    #[test]
    fn discovery_scan() {
        let dir = TempDir::new().unwrap();

        write_manifest(
            dir.path(),
            "plugin-a",
            r#"
            name = "plugin-a"
            version = "1.0.0"
            command = "./a"
        "#,
        );

        write_manifest(
            dir.path(),
            "plugin-b",
            r#"
            name = "plugin-b"
            version = "2.0.0"
            command = "./b"
            actions = ["tool.deploy"]
        "#,
        );

        // Create a directory without a manifest (should be skipped).
        std::fs::create_dir_all(dir.path().join("no-manifest")).unwrap();

        // Create a regular file (not a directory, should be skipped).
        std::fs::write(dir.path().join("readme.txt"), "hello").unwrap();

        let registry = PluginRegistry::discover(dir.path()).unwrap();
        assert_eq!(registry.list().len(), 2);

        // Both should be found (order not guaranteed from readdir).
        let names: Vec<&str> = registry.list().iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"plugin-a"));
        assert!(names.contains(&"plugin-b"));
    }

    #[test]
    fn find_by_name() {
        let dir = TempDir::new().unwrap();

        write_manifest(
            dir.path(),
            "finder",
            r#"
            name = "finder"
            version = "1.0.0"
            command = "./find"
        "#,
        );

        let registry = PluginRegistry::discover(dir.path()).unwrap();
        assert!(registry.find("finder").is_some());
        assert!(registry.find("nonexistent").is_none());
    }

    #[test]
    fn unload_plugin() {
        let dir = TempDir::new().unwrap();

        write_manifest(
            dir.path(),
            "removable",
            r#"
            name = "removable"
            version = "1.0.0"
            command = "./rm"
        "#,
        );

        let mut registry = PluginRegistry::discover(dir.path()).unwrap();
        assert_eq!(registry.list().len(), 1);

        assert!(registry.unload("removable"));
        assert_eq!(registry.list().len(), 0);

        // Double unload returns false.
        assert!(!registry.unload("removable"));
    }

    #[test]
    fn invalid_manifest_skipped_during_discovery() {
        let dir = TempDir::new().unwrap();

        // Valid plugin.
        write_manifest(
            dir.path(),
            "good",
            r#"
            name = "good"
            version = "1.0.0"
            command = "./good"
        "#,
        );

        // Invalid plugin (missing required fields).
        write_manifest(dir.path(), "bad", "this is not valid toml [[[ nope");

        let registry = PluginRegistry::discover(dir.path()).unwrap();
        // Only the good plugin should be loaded.
        assert_eq!(registry.list().len(), 1);
        assert_eq!(registry.list()[0].name, "good");
    }

    #[test]
    fn manifest_json_roundtrip() {
        let manifest = PluginManifest {
            name: "test-plugin".into(),
            version: "1.2.3".into(),
            command: "node".into(),
            args: vec!["index.js".into()],
            env: vec![("PORT".into(), "8080".into())],
            actions: vec!["tool.test".into()],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let back: PluginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn discover_nonexistent_dir() {
        let result = PluginRegistry::discover(Path::new("/nonexistent/path/here"));
        assert!(result.is_err());
    }
}
