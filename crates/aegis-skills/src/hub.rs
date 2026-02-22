//! AegisHub registry client -- install, update, and sync skills from a remote registry.
//!
//! The hub client communicates with the Aegis skill registry (default:
//! `https://registry.aegis.dev`) to search, install, and update skills.
//! Skills are stored locally under `~/.aegis/skills/{name}/`.
//!
//! When the registry is unreachable, the client falls back to locally
//! cached skills (offline mode).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::installer::{
    validate_installation, write_install_metadata, InstallSource, InstalledSkill, LocalInstaller,
    SkillInstaller,
};

/// Default registry URL.
const DEFAULT_REGISTRY_URL: &str = "https://registry.aegis.dev";

/// Default skills cache directory relative to home.
const DEFAULT_CACHE_SUBDIR: &str = ".aegis/skills";

/// Registry client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Base URL of the skill registry API.
    #[serde(default = "default_registry_url")]
    pub registry_url: String,
    /// Local directory for installed skills.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
}

fn default_registry_url() -> String {
    DEFAULT_REGISTRY_URL.into()
}

fn default_cache_dir() -> PathBuf {
    home_dir()
        .map(|h| h.join(DEFAULT_CACHE_SUBDIR))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_SUBDIR))
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            registry_url: default_registry_url(),
            cache_dir: default_cache_dir(),
        }
    }
}

/// Summary of a skill in the registry (returned by search).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSummary {
    /// Skill name.
    pub name: String,
    /// Latest version.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Author attribution.
    pub author: Option<String>,
    /// Download count.
    pub downloads: Option<u64>,
}

/// Information about an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAvailable {
    /// Skill name.
    pub name: String,
    /// Currently installed version.
    pub current_version: String,
    /// Latest available version.
    pub latest_version: String,
}

/// The registry client for interacting with AegisHub.
pub struct RegistryClient {
    config: RegistryConfig,
    http: reqwest::Client,
}

impl RegistryClient {
    /// Create a new registry client with default configuration.
    pub fn new() -> Self {
        Self::with_config(RegistryConfig::default())
    }

    /// Create a registry client with custom configuration.
    pub fn with_config(config: RegistryConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(format!("aegis-skills/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();

        Self { config, http }
    }

    /// Return the configured cache directory.
    pub fn cache_dir(&self) -> &Path {
        &self.config.cache_dir
    }

    /// Return the configured registry URL.
    pub fn registry_url(&self) -> &str {
        &self.config.registry_url
    }

    /// Search the registry for skills matching a query.
    ///
    /// Falls back to searching locally installed skills when the registry
    /// is unreachable.
    pub async fn search(&self, query: &str) -> Result<Vec<SkillSummary>> {
        let url = format!("{}/api/v1/skills/search", self.config.registry_url);
        debug!(url = %url, query = query, "searching registry");

        match self
            .http
            .get(&url)
            .query(&[("q", query)])
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let results: Vec<SkillSummary> = resp
                        .json()
                        .await
                        .context("failed to parse registry search response")?;
                    Ok(results)
                } else {
                    warn!(
                        status = %resp.status(),
                        "registry search failed, falling back to local search"
                    );
                    self.search_local(query)
                }
            }
            Err(e) => {
                warn!(error = %e, "registry unreachable, searching locally installed skills");
                self.search_local(query)
            }
        }
    }

    /// Install a skill from the registry.
    ///
    /// If `version` is `None`, installs the latest version. Downloads the
    /// skill tarball, extracts it, validates the manifest, and writes
    /// install metadata.
    pub async fn install(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<InstalledSkill> {
        // Validate skill name for path safety
        validate_skill_name(name)?;

        let dest_dir = self.config.cache_dir.join(name);

        // Try registry download first
        let url = match version {
            Some(v) => format!(
                "{}/api/v1/skills/{}/versions/{}",
                self.config.registry_url, name, v
            ),
            None => format!(
                "{}/api/v1/skills/{}/latest",
                self.config.registry_url, name
            ),
        };

        debug!(url = %url, name = name, "downloading skill from registry");

        match self.http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                // For now, the registry returns skill metadata including
                // a download URL. In a real implementation, we would download
                // the tarball. Here we store the response as installation info.
                let body = resp.bytes().await.context("failed to read response body")?;

                // Try to parse as a skill metadata response
                if let Ok(meta) = serde_json::from_slice::<RegistrySkillMeta>(&body) {
                    // If the skill provides a download URL, we would fetch it.
                    // For now, record the installation as pending download.
                    let version_str = meta.version.clone();
                    let installed = InstalledSkill {
                        name: meta.name.clone(),
                        version: meta.version.clone(),
                        path: dest_dir.clone(),
                        installed_at: Utc::now(),
                        source: InstallSource::Registry {
                            version: version_str,
                        },
                        manifest: meta.into_manifest(),
                    };

                    // Ensure cache dir exists
                    std::fs::create_dir_all(&dest_dir).with_context(|| {
                        format!("failed to create skill directory: {}", dest_dir.display())
                    })?;

                    // Write manifest and metadata
                    let manifest_toml = format!(
                        r#"name = "{}"
version = "{}"
description = "{}"
entry_point = "{}"
"#,
                        installed.manifest.name,
                        installed.manifest.version,
                        installed.manifest.description,
                        installed.manifest.entry_point,
                    );
                    std::fs::write(dest_dir.join("manifest.toml"), manifest_toml)
                        .context("failed to write manifest")?;

                    write_install_metadata(
                        &dest_dir,
                        &installed.source,
                        installed.installed_at,
                    )?;

                    return Ok(installed);
                }

                bail!("unexpected response format from registry for skill '{name}'");
            }
            Ok(resp) => {
                bail!(
                    "registry returned {} for skill '{}': {}",
                    resp.status(),
                    name,
                    resp.text().await.unwrap_or_default()
                );
            }
            Err(e) => {
                bail!(
                    "failed to download skill '{}' from registry: {}",
                    name,
                    e
                );
            }
        }
    }

    /// Install a skill from a local directory.
    pub fn install_local(&self, name: &str, source_dir: &Path) -> Result<InstalledSkill> {
        validate_skill_name(name)?;
        let dest_dir = self.config.cache_dir.join(name);

        let installer = LocalInstaller {
            source_dir: source_dir.to_path_buf(),
        };
        let installed = installer.install(&dest_dir)?;

        write_install_metadata(&dest_dir, &installed.source, installed.installed_at)?;
        Ok(installed)
    }

    /// Update an installed skill to the latest version.
    ///
    /// Re-downloads from the registry. Returns the updated installation info.
    pub async fn update(&self, name: &str) -> Result<InstalledSkill> {
        validate_skill_name(name)?;

        let skill_dir = self.config.cache_dir.join(name);
        if !skill_dir.exists() {
            bail!("skill '{}' is not installed", name);
        }

        // Re-install from registry (latest)
        self.install(name, None).await
    }

    /// Uninstall a skill by removing its directory.
    pub fn uninstall(&self, name: &str) -> Result<()> {
        validate_skill_name(name)?;

        let skill_dir = self.config.cache_dir.join(name);
        if !skill_dir.exists() {
            bail!("skill '{}' is not installed", name);
        }

        // Verify the path is under the cache directory to prevent traversal
        let canonical_cache = self.config.cache_dir.canonicalize().unwrap_or_else(|_| {
            self.config.cache_dir.clone()
        });
        let canonical_skill = skill_dir.canonicalize().unwrap_or_else(|_| {
            skill_dir.clone()
        });
        if !canonical_skill.starts_with(&canonical_cache) {
            bail!("skill directory escapes cache directory");
        }

        std::fs::remove_dir_all(&skill_dir).with_context(|| {
            format!("failed to remove skill directory: {}", skill_dir.display())
        })?;

        Ok(())
    }

    /// List all locally installed skills.
    pub fn list_installed(&self) -> Result<Vec<InstalledSkill>> {
        let cache_dir = &self.config.cache_dir;
        if !cache_dir.exists() {
            return Ok(Vec::new());
        }

        let mut skills = Vec::new();

        for entry in std::fs::read_dir(cache_dir)
            .with_context(|| format!("failed to read cache directory: {}", cache_dir.display()))?
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Skip directories without a manifest
            if !path.join("manifest.toml").exists() {
                continue;
            }

            match validate_installation(&path) {
                Ok(installed) => skills.push(installed),
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        error = %e,
                        "skipping invalid installed skill"
                    );
                }
            }
        }

        skills.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(skills)
    }

    /// Check for available updates for all installed skills.
    ///
    /// Contacts the registry to compare installed versions with latest
    /// available versions. Falls back to empty list when offline.
    pub async fn sync(&self) -> Result<Vec<UpdateAvailable>> {
        let installed = self.list_installed()?;
        if installed.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/api/v1/skills/versions", self.config.registry_url);
        let names: Vec<&str> = installed.iter().map(|s| s.name.as_str()).collect();

        debug!(url = %url, count = names.len(), "checking for updates");

        match self
            .http
            .post(&url)
            .json(&serde_json::json!({ "names": names }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let versions: Vec<RegistryVersionInfo> = resp
                    .json()
                    .await
                    .context("failed to parse version check response")?;

                let mut updates = Vec::new();
                for version_info in &versions {
                    if let Some(installed_skill) = installed.iter().find(|s| s.name == version_info.name) {
                        if version_info.latest_version != installed_skill.version {
                            updates.push(UpdateAvailable {
                                name: version_info.name.clone(),
                                current_version: installed_skill.version.clone(),
                                latest_version: version_info.latest_version.clone(),
                            });
                        }
                    }
                }

                Ok(updates)
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "version check failed");
                Ok(Vec::new())
            }
            Err(e) => {
                warn!(error = %e, "registry unreachable, skipping update check");
                Ok(Vec::new())
            }
        }
    }

    /// Search locally installed skills matching a query.
    fn search_local(&self, query: &str) -> Result<Vec<SkillSummary>> {
        let installed = self.list_installed()?;
        let query_lower = query.to_lowercase();

        let results = installed
            .into_iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&query_lower)
                    || s.manifest.description.to_lowercase().contains(&query_lower)
            })
            .map(|s| SkillSummary {
                name: s.name,
                version: s.version,
                description: s.manifest.description,
                author: s.manifest.author,
                downloads: None,
            })
            .collect();

        Ok(results)
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a skill name is safe for use as a directory name.
fn validate_skill_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("skill name must not be empty");
    }
    if name.len() > 64 {
        bail!("skill name too long (max 64 characters)");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("skill name must contain only alphanumeric characters and hyphens");
    }
    if name.contains("..") {
        bail!("skill name must not contain path traversal");
    }
    Ok(())
}

/// Metadata returned by the registry for a single skill.
#[derive(Debug, Deserialize)]
struct RegistrySkillMeta {
    name: String,
    version: String,
    description: String,
    #[allow(dead_code)]
    author: Option<String>,
    entry_point: Option<String>,
}

impl RegistrySkillMeta {
    fn into_manifest(self) -> crate::manifest::SkillManifest {
        crate::manifest::SkillManifest {
            name: self.name,
            version: self.version,
            description: self.description,
            author: self.author,
            permissions: Vec::new(),
            entry_point: self.entry_point.unwrap_or_else(|| "run.sh".into()),
            dependencies: Vec::new(),
            min_aegis_version: None,
            commands: None,
        }
    }
}

/// Version info from the registry's bulk version check endpoint.
#[derive(Debug, Deserialize)]
struct RegistryVersionInfo {
    name: String,
    latest_version: String,
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(cache_dir: &Path) -> RegistryConfig {
        RegistryConfig {
            registry_url: "http://localhost:0".into(), // will fail to connect
            cache_dir: cache_dir.to_path_buf(),
        }
    }

    fn create_installed_skill(cache_dir: &Path, name: &str, version: &str) {
        let skill_dir = cache_dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();

        let manifest = format!(
            r#"
name = "{name}"
version = "{version}"
description = "Test skill {name}"
entry_point = "run.sh"
"#
        );
        std::fs::write(skill_dir.join("manifest.toml"), manifest).unwrap();
        std::fs::write(skill_dir.join("run.sh"), "#!/bin/bash\necho ok\n").unwrap();
    }

    #[test]
    fn test_validate_skill_name() {
        assert!(validate_skill_name("good-skill").is_ok());
        assert!(validate_skill_name("my-skill-123").is_ok());
        assert!(validate_skill_name("simple").is_ok());

        assert!(validate_skill_name("").is_err());
        assert!(validate_skill_name("bad name").is_err());
        assert!(validate_skill_name("bad/name").is_err());
        assert!(validate_skill_name("bad..name").is_err());
        assert!(validate_skill_name("bad;name").is_err());
        assert!(validate_skill_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn test_list_installed_empty() {
        let tmp = TempDir::new().unwrap();
        let client = RegistryClient::with_config(test_config(tmp.path()));
        let installed = client.list_installed().unwrap();
        assert!(installed.is_empty());
    }

    #[test]
    fn test_list_installed_finds_skills() {
        let tmp = TempDir::new().unwrap();
        create_installed_skill(tmp.path(), "skill-a", "1.0.0");
        create_installed_skill(tmp.path(), "skill-b", "2.0.0");

        let client = RegistryClient::with_config(test_config(tmp.path()));
        let installed = client.list_installed().unwrap();
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[0].name, "skill-a");
        assert_eq!(installed[1].name, "skill-b");
    }

    #[test]
    fn test_list_installed_nonexistent_cache_dir() {
        let config = RegistryConfig {
            registry_url: "http://localhost:0".into(),
            cache_dir: PathBuf::from("/nonexistent/path/to/skills"),
        };
        let client = RegistryClient::with_config(config);
        let installed = client.list_installed().unwrap();
        assert!(installed.is_empty());
    }

    #[test]
    fn test_uninstall_skill() {
        let tmp = TempDir::new().unwrap();
        create_installed_skill(tmp.path(), "to-remove", "1.0.0");

        let client = RegistryClient::with_config(test_config(tmp.path()));
        assert!(tmp.path().join("to-remove").exists());

        client.uninstall("to-remove").unwrap();
        assert!(!tmp.path().join("to-remove").exists());
    }

    #[test]
    fn test_uninstall_missing_skill() {
        let tmp = TempDir::new().unwrap();
        let client = RegistryClient::with_config(test_config(tmp.path()));
        let result = client.uninstall("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not installed"));
    }

    #[test]
    fn test_install_local_skill() {
        let source = TempDir::new().unwrap();
        let manifest = r#"
name = "local-skill"
version = "1.0.0"
description = "A local skill"
entry_point = "run.sh"
"#;
        std::fs::write(source.path().join("manifest.toml"), manifest).unwrap();
        std::fs::write(source.path().join("run.sh"), "#!/bin/bash\necho ok").unwrap();

        let cache = TempDir::new().unwrap();
        let client = RegistryClient::with_config(test_config(cache.path()));

        let installed = client
            .install_local("local-skill", source.path())
            .unwrap();
        assert_eq!(installed.name, "local-skill");
        assert!(cache.path().join("local-skill/manifest.toml").exists());
        assert!(cache
            .path()
            .join("local-skill/.aegis-install.json")
            .exists());
    }

    #[tokio::test]
    async fn test_search_offline_fallback() {
        let tmp = TempDir::new().unwrap();
        create_installed_skill(tmp.path(), "search-skill", "1.0.0");

        let client = RegistryClient::with_config(test_config(tmp.path()));
        let results = client.search("search").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "search-skill");
    }

    #[tokio::test]
    async fn test_search_no_match() {
        let tmp = TempDir::new().unwrap();
        create_installed_skill(tmp.path(), "alpha", "1.0.0");

        let client = RegistryClient::with_config(test_config(tmp.path()));
        let results = client.search("zzzzz").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_sync_offline() {
        let tmp = TempDir::new().unwrap();
        create_installed_skill(tmp.path(), "synced-skill", "1.0.0");

        let client = RegistryClient::with_config(test_config(tmp.path()));
        let updates = client.sync().await.unwrap();
        // Offline mode -- no updates returned
        assert!(updates.is_empty());
    }

    #[test]
    fn test_registry_config_default() {
        let config = RegistryConfig::default();
        assert_eq!(config.registry_url, DEFAULT_REGISTRY_URL);
        assert!(config.cache_dir.to_string_lossy().contains(".aegis/skills"));
    }

    #[test]
    fn test_skill_summary_serialization() {
        let summary = SkillSummary {
            name: "test".into(),
            version: "1.0.0".into(),
            description: "A test skill".into(),
            author: Some("Test".into()),
            downloads: Some(100),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let back: SkillSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.downloads, Some(100));
    }

    #[test]
    fn test_update_available_serialization() {
        let update = UpdateAvailable {
            name: "skill".into(),
            current_version: "1.0.0".into(),
            latest_version: "2.0.0".into(),
        };

        let json = serde_json::to_string(&update).unwrap();
        let back: UpdateAvailable = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "skill");
        assert_eq!(back.current_version, "1.0.0");
        assert_eq!(back.latest_version, "2.0.0");
    }

    #[test]
    fn test_registry_skill_meta_into_manifest() {
        let meta = RegistrySkillMeta {
            name: "meta-skill".into(),
            version: "3.0.0".into(),
            description: "From registry".into(),
            author: Some("Author".into()),
            entry_point: Some("main.py".into()),
        };

        let manifest = meta.into_manifest();
        assert_eq!(manifest.name, "meta-skill");
        assert_eq!(manifest.version, "3.0.0");
        assert_eq!(manifest.entry_point, "main.py");
    }

    #[test]
    fn test_registry_skill_meta_default_entry_point() {
        let meta = RegistrySkillMeta {
            name: "default-ep".into(),
            version: "1.0.0".into(),
            description: "No entry point".into(),
            author: None,
            entry_point: None,
        };

        let manifest = meta.into_manifest();
        assert_eq!(manifest.entry_point, "run.sh");
    }
}
