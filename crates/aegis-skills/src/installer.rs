//! Skill installers -- download, extract, and validate skill packages.
//!
//! Supports multiple installation sources:
//! - Tarballs (`.tar.gz` from a URL or local path)
//! - Git repositories (clone a repo)
//! - Local directories (copy from a local path)

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::manifest::{parse_manifest_file, validate_manifest, SkillManifest};

/// Where a skill was installed from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum InstallSource {
    /// Downloaded tarball from a URL.
    Tarball { url: String },
    /// Cloned from a Git repository.
    Git { url: String, branch: Option<String> },
    /// Copied from a local directory.
    Local { path: PathBuf },
    /// Installed from the registry.
    Registry { version: String },
}

impl std::fmt::Display for InstallSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallSource::Tarball { url } => write!(f, "tarball: {url}"),
            InstallSource::Git { url, branch } => {
                write!(f, "git: {url}")?;
                if let Some(b) = branch {
                    write!(f, " (branch: {b})")?;
                }
                Ok(())
            }
            InstallSource::Local { path } => write!(f, "local: {}", path.display()),
            InstallSource::Registry { version } => write!(f, "registry: v{version}"),
        }
    }
}

/// Metadata about an installed skill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledSkill {
    /// Skill name.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// Path to the installed skill directory.
    pub path: PathBuf,
    /// When the skill was installed.
    pub installed_at: DateTime<Utc>,
    /// Installation source.
    pub source: InstallSource,
    /// The parsed manifest.
    pub manifest: SkillManifest,
}

/// Trait for skill installers.
///
/// Each installer handles a different source type (tarball, git, local).
/// All installers extract/copy the skill into `dest_dir` and validate the
/// manifest after installation.
pub trait SkillInstaller {
    /// Install a skill into `dest_dir`.
    ///
    /// `dest_dir` is the target directory (e.g., `~/.aegis/skills/<name>/`).
    /// The installer should create this directory if it does not exist.
    fn install(&self, dest_dir: &Path) -> Result<InstalledSkill>;
}

/// Install a skill from a local directory by copying it.
pub struct LocalInstaller {
    /// Source directory containing the skill.
    pub source_dir: PathBuf,
}

impl SkillInstaller for LocalInstaller {
    fn install(&self, dest_dir: &Path) -> Result<InstalledSkill> {
        if !self.source_dir.is_dir() {
            bail!(
                "source directory does not exist: {}",
                self.source_dir.display()
            );
        }

        // Check for manifest in source
        let source_manifest_path = self.source_dir.join("manifest.toml");
        if !source_manifest_path.exists() {
            bail!(
                "no manifest.toml found in source directory: {}",
                self.source_dir.display()
            );
        }

        let manifest = parse_manifest_file(&source_manifest_path)
            .context("failed to parse source manifest")?;
        validate_manifest(&manifest).context("source manifest validation failed")?;

        // Copy the directory contents
        if dest_dir.exists() {
            std::fs::remove_dir_all(dest_dir)
                .with_context(|| format!("failed to clean destination: {}", dest_dir.display()))?;
        }
        copy_dir_recursive(&self.source_dir, dest_dir)
            .context("failed to copy skill directory")?;

        // Validate the installed manifest
        let installed_manifest_path = dest_dir.join("manifest.toml");
        let installed_manifest = parse_manifest_file(&installed_manifest_path)
            .context("installed manifest validation failed")?;
        validate_manifest(&installed_manifest)?;

        // Verify entry point exists
        let entry_point = dest_dir.join(&installed_manifest.entry_point);
        if !entry_point.exists() {
            bail!(
                "entry point '{}' not found after install in {}",
                installed_manifest.entry_point,
                dest_dir.display()
            );
        }

        Ok(InstalledSkill {
            name: installed_manifest.name.clone(),
            version: installed_manifest.version.clone(),
            path: dest_dir.to_path_buf(),
            installed_at: Utc::now(),
            source: InstallSource::Local {
                path: self.source_dir.clone(),
            },
            manifest: installed_manifest,
        })
    }
}

/// Install a skill from a Git repository by cloning it.
pub struct GitInstaller {
    /// Git repository URL.
    pub repo_url: String,
    /// Optional branch/tag to checkout.
    pub branch: Option<String>,
}

impl SkillInstaller for GitInstaller {
    fn install(&self, dest_dir: &Path) -> Result<InstalledSkill> {
        if dest_dir.exists() {
            std::fs::remove_dir_all(dest_dir)
                .with_context(|| format!("failed to clean destination: {}", dest_dir.display()))?;
        }

        let mut cmd = std::process::Command::new("git");
        cmd.args(["clone", "--depth", "1"]);

        if let Some(ref branch) = self.branch {
            cmd.args(["--branch", branch]);
        }

        cmd.arg(&self.repo_url);
        cmd.arg(dest_dir);

        let output = cmd.output().context("failed to run git clone")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git clone failed: {}", stderr.trim());
        }

        // Validate the cloned repo has a manifest
        let manifest_path = dest_dir.join("manifest.toml");
        if !manifest_path.exists() {
            bail!(
                "cloned repository has no manifest.toml: {}",
                self.repo_url
            );
        }

        let manifest =
            parse_manifest_file(&manifest_path).context("failed to parse cloned manifest")?;
        validate_manifest(&manifest).context("cloned manifest validation failed")?;

        // Verify entry point exists
        let entry_point = dest_dir.join(&manifest.entry_point);
        if !entry_point.exists() {
            bail!(
                "entry point '{}' not found in cloned repo",
                manifest.entry_point
            );
        }

        Ok(InstalledSkill {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            path: dest_dir.to_path_buf(),
            installed_at: Utc::now(),
            source: InstallSource::Git {
                url: self.repo_url.clone(),
                branch: self.branch.clone(),
            },
            manifest,
        })
    }
}

/// Validate a skill installation in an existing directory.
///
/// Checks that the manifest exists, parses correctly, validates, and that
/// the entry point file is present.
pub fn validate_installation(skill_dir: &Path) -> Result<InstalledSkill> {
    let manifest_path = skill_dir.join("manifest.toml");
    if !manifest_path.exists() {
        bail!(
            "no manifest.toml in skill directory: {}",
            skill_dir.display()
        );
    }

    let manifest =
        parse_manifest_file(&manifest_path).context("failed to parse installed manifest")?;
    validate_manifest(&manifest).context("installed manifest validation failed")?;

    let entry_point = skill_dir.join(&manifest.entry_point);
    if !entry_point.exists() {
        bail!(
            "entry point '{}' missing in {}",
            manifest.entry_point,
            skill_dir.display()
        );
    }

    // Read the install metadata if present
    let meta_path = skill_dir.join(".aegis-install.json");
    let (installed_at, source) = if meta_path.exists() {
        let content = std::fs::read_to_string(&meta_path)
            .context("failed to read install metadata")?;
        let meta: InstallMetadata =
            serde_json::from_str(&content).context("failed to parse install metadata")?;
        (meta.installed_at, meta.source)
    } else {
        (Utc::now(), InstallSource::Local {
            path: skill_dir.to_path_buf(),
        })
    };

    Ok(InstalledSkill {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        path: skill_dir.to_path_buf(),
        installed_at,
        source,
        manifest,
    })
}

/// Write install metadata to the skill directory.
///
/// Called after successful installation to record provenance.
pub fn write_install_metadata(
    skill_dir: &Path,
    source: &InstallSource,
    installed_at: DateTime<Utc>,
) -> Result<()> {
    let meta = InstallMetadata {
        installed_at,
        source: source.clone(),
    };
    let content = serde_json::to_string_pretty(&meta)
        .context("failed to serialize install metadata")?;
    std::fs::write(skill_dir.join(".aegis-install.json"), content)
        .context("failed to write install metadata")?;
    Ok(())
}

/// Serializable install metadata stored in `.aegis-install.json`.
#[derive(Debug, Serialize, Deserialize)]
struct InstallMetadata {
    installed_at: DateTime<Utc>,
    source: InstallSource,
}

/// Recursively copy a directory and all its contents.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("failed to create directory: {}", dst.display()))?;

    for entry in std::fs::read_dir(src)
        .with_context(|| format!("failed to read directory: {}", src.display()))?
    {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // Skip symlinks for security
        if src_path.is_symlink() {
            continue;
        }

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "failed to copy {} -> {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_skill_source(name: &str) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let manifest = format!(
            r#"
name = "{name}"
version = "1.0.0"
description = "Test skill"
entry_point = "run.sh"
"#
        );
        std::fs::write(tmp.path().join("manifest.toml"), manifest).unwrap();
        std::fs::write(tmp.path().join("run.sh"), "#!/bin/bash\necho ok\n").unwrap();
        tmp
    }

    #[test]
    fn test_local_installer() {
        let source = create_skill_source("local-skill");
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path().join("local-skill");

        let installer = LocalInstaller {
            source_dir: source.path().to_path_buf(),
        };

        let installed = installer.install(&dest_path).unwrap();
        assert_eq!(installed.name, "local-skill");
        assert_eq!(installed.version, "1.0.0");
        assert!(installed.path.join("manifest.toml").exists());
        assert!(installed.path.join("run.sh").exists());
        assert!(matches!(installed.source, InstallSource::Local { .. }));
    }

    #[test]
    fn test_local_installer_missing_source() {
        let dest = TempDir::new().unwrap();
        let installer = LocalInstaller {
            source_dir: PathBuf::from("/nonexistent/path"),
        };
        let result = installer.install(&dest.path().join("test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_local_installer_no_manifest() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("run.sh"), "echo hi").unwrap();

        let dest = TempDir::new().unwrap();
        let installer = LocalInstaller {
            source_dir: tmp.path().to_path_buf(),
        };
        let result = installer.install(&dest.path().join("test"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("manifest.toml"));
    }

    #[test]
    fn test_local_installer_replaces_existing() {
        let source = create_skill_source("replace-skill");
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path().join("replace-skill");

        // Install once
        let installer = LocalInstaller {
            source_dir: source.path().to_path_buf(),
        };
        installer.install(&dest_path).unwrap();

        // Install again (should replace)
        let installed = installer.install(&dest_path).unwrap();
        assert_eq!(installed.name, "replace-skill");
    }

    #[test]
    fn test_validate_installation() {
        let source = create_skill_source("validate-skill");
        let result = validate_installation(source.path()).unwrap();
        assert_eq!(result.name, "validate-skill");
        assert_eq!(result.version, "1.0.0");
    }

    #[test]
    fn test_validate_installation_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let result = validate_installation(tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("manifest.toml"));
    }

    #[test]
    fn test_validate_installation_missing_entry_point() {
        let tmp = TempDir::new().unwrap();
        let manifest = r#"
name = "no-entry"
version = "1.0.0"
description = "Missing entry point"
entry_point = "missing.sh"
"#;
        std::fs::write(tmp.path().join("manifest.toml"), manifest).unwrap();
        let result = validate_installation(tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing"));
    }

    #[test]
    fn test_install_metadata_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let source = InstallSource::Registry {
            version: "1.2.3".into(),
        };
        let now = Utc::now();
        write_install_metadata(tmp.path(), &source, now).unwrap();

        let meta_path = tmp.path().join(".aegis-install.json");
        assert!(meta_path.exists());

        let content = std::fs::read_to_string(&meta_path).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(meta["source"]["type"], "Registry");
        assert_eq!(meta["source"]["version"], "1.2.3");
    }

    #[test]
    fn test_install_source_display() {
        let tarball = InstallSource::Tarball {
            url: "https://example.com/skill.tar.gz".into(),
        };
        assert!(tarball.to_string().contains("tarball"));

        let git = InstallSource::Git {
            url: "https://github.com/user/skill.git".into(),
            branch: Some("main".into()),
        };
        assert!(git.to_string().contains("git"));
        assert!(git.to_string().contains("main"));

        let local = InstallSource::Local {
            path: PathBuf::from("/tmp/skill"),
        };
        assert!(local.to_string().contains("local"));

        let registry = InstallSource::Registry {
            version: "2.0.0".into(),
        };
        assert!(registry.to_string().contains("registry"));
    }

    #[test]
    fn test_copy_dir_recursive() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().join("copy-test");

        // Create a directory structure
        std::fs::write(src.path().join("file1.txt"), "hello").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/file2.txt"), "world").unwrap();

        copy_dir_recursive(src.path(), &dst_path).unwrap();

        assert!(dst_path.join("file1.txt").exists());
        assert!(dst_path.join("sub/file2.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dst_path.join("file1.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read_to_string(dst_path.join("sub/file2.txt")).unwrap(),
            "world"
        );
    }
}
