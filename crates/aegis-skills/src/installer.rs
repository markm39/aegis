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

use crate::manifest::{parse_manifest_file, validate_manifest, InstallMethod, SkillManifest};

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
    /// Installed via a system package manager (brew, npm, go, apt, uv).
    PackageManager { method: String, target: String },
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
            InstallSource::PackageManager { method, target } => {
                write!(f, "{method}: {target}")
            }
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
        copy_dir_recursive(&self.source_dir, dest_dir).context("failed to copy skill directory")?;

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
            bail!("cloned repository has no manifest.toml: {}", self.repo_url);
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

/// Install a skill whose system dependencies come from a package manager.
///
/// This installer first installs the required system tool (e.g., `brew install gh`),
/// verifies it is available in PATH, then copies the skill files (manifest + entry
/// script) from `source_dir` into `dest_dir`.
pub struct PackageManagerInstaller {
    /// Which package manager to use.
    pub method: InstallMethod,
    /// The package/formula/module name to install.
    pub target: String,
    /// Directory containing the skill's manifest and entry script.
    pub source_dir: PathBuf,
    /// Binaries that must exist in PATH after installation.
    pub required_bins: Vec<String>,
}

impl PackageManagerInstaller {
    /// Check if all required binaries are already available.
    pub fn prerequisites_met(&self) -> bool {
        self.required_bins.iter().all(|bin| binary_exists(bin))
    }

    /// Install the system dependency only (without copying skill files).
    pub fn install_dependency(&self) -> Result<()> {
        if self.prerequisites_met() {
            return Ok(());
        }

        let manager_bin = self.method.binary_name();
        if !binary_exists(manager_bin) {
            bail!(
                "package manager '{}' is not installed (need '{}' in PATH)",
                self.method,
                manager_bin
            );
        }

        let (program, args) = self.method.install_command(&self.target);
        let output = std::process::Command::new(&program)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .with_context(|| format!("failed to run: {} {}", program, args.join(" ")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "{} install of '{}' failed: {}",
                self.method,
                self.target,
                stderr.trim()
            );
        }

        // Verify required binaries are now available
        for bin in &self.required_bins {
            if !binary_exists(bin) {
                bail!(
                    "'{}' was installed via {} but '{}' is still not found in PATH",
                    self.target,
                    self.method,
                    bin
                );
            }
        }

        Ok(())
    }
}

impl SkillInstaller for PackageManagerInstaller {
    fn install(&self, dest_dir: &Path) -> Result<InstalledSkill> {
        // Install system dependency first
        self.install_dependency()?;

        // Then copy skill files (manifest + entry script) from source
        let local = LocalInstaller {
            source_dir: self.source_dir.clone(),
        };
        let mut installed = local.install(dest_dir)?;

        // Override the source metadata to reflect the package manager origin
        installed.source = InstallSource::PackageManager {
            method: self.method.to_string(),
            target: self.target.clone(),
        };

        Ok(installed)
    }
}

impl InstallMethod {
    /// The binary name of this package manager.
    pub fn binary_name(&self) -> &'static str {
        match self {
            InstallMethod::Brew => "brew",
            InstallMethod::Npm => "npm",
            InstallMethod::Go => "go",
            InstallMethod::Apt => "apt-get",
            InstallMethod::Uv => "uv",
            InstallMethod::Download => "curl",
            InstallMethod::Config => "true",
        }
    }

    /// Build the command and arguments to install a package.
    pub fn install_command(&self, target: &str) -> (String, Vec<String>) {
        match self {
            InstallMethod::Brew => ("brew".into(), vec!["install".into(), target.into()]),
            InstallMethod::Npm => (
                "npm".into(),
                vec!["install".into(), "-g".into(), target.into()],
            ),
            InstallMethod::Go => {
                let target_with_version = if target.contains('@') {
                    target.to_string()
                } else {
                    format!("{target}@latest")
                };
                ("go".into(), vec!["install".into(), target_with_version])
            }
            InstallMethod::Apt => (
                "sudo".into(),
                vec![
                    "apt-get".into(),
                    "install".into(),
                    "-y".into(),
                    target.into(),
                ],
            ),
            InstallMethod::Uv => (
                "uv".into(),
                vec!["tool".into(), "install".into(), target.into()],
            ),
            InstallMethod::Download => {
                // Download expects target to be a URL; use curl -LO
                ("curl".into(), vec!["-LO".into(), target.into()])
            }
            InstallMethod::Config => {
                // Config-only skills have no install step
                ("true".into(), vec![])
            }
        }
    }
}

/// Check if a binary exists in PATH.
pub fn binary_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if all required binaries for a manifest are available.
pub fn check_prerequisites(manifest: &SkillManifest) -> Vec<String> {
    let mut missing = Vec::new();
    for bin in &manifest.required_bins {
        if !binary_exists(bin) {
            missing.push(bin.clone());
        }
    }
    missing
}

/// Check if a manifest's OS constraints match the current platform.
pub fn is_supported_os(manifest: &SkillManifest) -> bool {
    if manifest.os.is_empty() {
        return true;
    }
    let current = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };
    manifest.os.iter().any(|os| os == current)
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
        let content =
            std::fs::read_to_string(&meta_path).context("failed to read install metadata")?;
        let meta: InstallMetadata =
            serde_json::from_str(&content).context("failed to parse install metadata")?;
        (meta.installed_at, meta.source)
    } else {
        (
            Utc::now(),
            InstallSource::Local {
                path: skill_dir.to_path_buf(),
            },
        )
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
    let content =
        serde_json::to_string_pretty(&meta).context("failed to serialize install metadata")?;
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
    fn test_install_source_display_package_manager() {
        let pm = InstallSource::PackageManager {
            method: "brew".into(),
            target: "gh".into(),
        };
        assert!(pm.to_string().contains("brew"));
        assert!(pm.to_string().contains("gh"));
    }

    #[test]
    fn test_install_method_binary_name() {
        assert_eq!(InstallMethod::Brew.binary_name(), "brew");
        assert_eq!(InstallMethod::Npm.binary_name(), "npm");
        assert_eq!(InstallMethod::Go.binary_name(), "go");
        assert_eq!(InstallMethod::Apt.binary_name(), "apt-get");
        assert_eq!(InstallMethod::Uv.binary_name(), "uv");
    }

    #[test]
    fn test_install_method_install_command() {
        let (prog, args) = InstallMethod::Brew.install_command("gh");
        assert_eq!(prog, "brew");
        assert_eq!(args, vec!["install", "gh"]);

        let (prog, args) = InstallMethod::Npm.install_command("typescript");
        assert_eq!(prog, "npm");
        assert_eq!(args, vec!["install", "-g", "typescript"]);

        let (prog, args) = InstallMethod::Go.install_command("github.com/cli/cli/v2");
        assert_eq!(prog, "go");
        assert_eq!(args, vec!["install", "github.com/cli/cli/v2@latest"]);

        // Go target with existing version specifier
        let (prog, args) = InstallMethod::Go.install_command("example.com/tool@v1.2.3");
        assert_eq!(prog, "go");
        assert_eq!(args, vec!["install", "example.com/tool@v1.2.3"]);

        let (prog, args) = InstallMethod::Apt.install_command("curl");
        assert_eq!(prog, "sudo");
        assert_eq!(args, vec!["apt-get", "install", "-y", "curl"]);

        let (prog, args) = InstallMethod::Uv.install_command("ruff");
        assert_eq!(prog, "uv");
        assert_eq!(args, vec!["tool", "install", "ruff"]);
    }

    #[test]
    fn test_binary_exists_known() {
        // `sh` should exist on any Unix system
        assert!(binary_exists("sh"));
        // Something that definitely doesn't exist
        assert!(!binary_exists("definitely-not-a-real-binary-xyz-123"));
    }

    #[test]
    fn test_check_prerequisites() {
        let manifest = crate::manifest::parse_manifest(
            r#"
name = "test-skill"
version = "1.0.0"
description = "Test"
entry_point = "run.sh"
required_bins = ["sh", "nonexistent-binary-xyz"]
"#,
        )
        .unwrap();

        let missing = check_prerequisites(&manifest);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "nonexistent-binary-xyz");
    }

    #[test]
    fn test_is_supported_os() {
        let mut manifest = crate::manifest::parse_manifest(
            r#"
name = "test-skill"
version = "1.0.0"
description = "Test"
entry_point = "run.sh"
"#,
        )
        .unwrap();

        // Empty os list means all platforms
        assert!(is_supported_os(&manifest));

        // Current platform should match
        manifest.os = vec!["darwin".into(), "linux".into()];
        assert!(is_supported_os(&manifest));

        // Windows-only should not match on macOS/Linux
        manifest.os = vec!["windows".into()];
        assert!(!is_supported_os(&manifest));
    }

    #[test]
    fn test_package_manager_installer_prerequisites_met() {
        let tmp = create_skill_source("pm-test");
        let installer = PackageManagerInstaller {
            method: InstallMethod::Brew,
            target: "gh".into(),
            source_dir: tmp.path().to_path_buf(),
            required_bins: vec!["sh".into()], // sh always exists
        };
        assert!(installer.prerequisites_met());

        let installer2 = PackageManagerInstaller {
            method: InstallMethod::Brew,
            target: "gh".into(),
            source_dir: tmp.path().to_path_buf(),
            required_bins: vec!["nonexistent-xyz".into()],
        };
        assert!(!installer2.prerequisites_met());
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

    /// Install every bundled skill from the project's skills/ directory into a
    /// temp directory and verify each one succeeds. This catches bad manifests,
    /// missing entry points, and other packaging issues.
    #[test]
    fn test_all_bundled_skills_install() {
        let project_skills_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent() // crates/
            .and_then(|p| p.parent()) // project root
            .map(|p| p.join("skills"));

        let skills_dir = match project_skills_dir {
            Some(ref p) if p.is_dir() => p.as_path(),
            _ => {
                eprintln!("skipping test: project skills/ directory not found");
                return;
            }
        };

        let dest_root = TempDir::new().unwrap();
        let discovered = crate::discover_skills(skills_dir).unwrap();
        assert!(
            !discovered.is_empty(),
            "expected bundled skills in {}",
            skills_dir.display()
        );

        let mut failures: Vec<String> = Vec::new();
        let mut success_count = 0;

        for skill in &discovered {
            let dest = dest_root.path().join(&skill.manifest.name);
            let installer = LocalInstaller {
                source_dir: skill.path.clone(),
            };

            match installer.install(&dest) {
                Ok(installed) => {
                    // Verify manifest exists at destination.
                    assert!(
                        dest.join("manifest.toml").exists(),
                        "manifest.toml missing for '{}'",
                        skill.manifest.name
                    );
                    // Verify entry point exists at destination.
                    assert!(
                        dest.join(&installed.manifest.entry_point).exists(),
                        "entry point '{}' missing for '{}'",
                        installed.manifest.entry_point,
                        skill.manifest.name
                    );
                    // Verify install metadata can be written.
                    write_install_metadata(
                        &dest,
                        &installed.source,
                        installed.installed_at,
                    )
                    .unwrap_or_else(|e| {
                        failures.push(format!(
                            "{}: metadata write failed: {e}",
                            skill.manifest.name
                        ));
                    });
                    success_count += 1;
                }
                Err(e) => {
                    failures.push(format!("{}: {e:#}", skill.manifest.name));
                }
            }
        }

        if !failures.is_empty() {
            panic!(
                "{} of {} skills failed to install:\n  - {}",
                failures.len(),
                discovered.len(),
                failures.join("\n  - ")
            );
        }

        assert_eq!(
            success_count,
            discovered.len(),
            "all discovered skills should install successfully"
        );
    }
}
