//! Skill manifest parsing and validation.
//!
//! A skill manifest is a TOML file (`manifest.toml`) that declares the skill's
//! metadata, required permissions, entry point, and dependencies.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Maximum allowed length for a skill name.
const MAX_NAME_LEN: usize = 64;

/// A parsed skill manifest.
///
/// Deserialized from a `manifest.toml` file inside a skill directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillManifest {
    /// Unique skill name (alphanumeric + hyphens, 1-64 chars).
    pub name: String,
    /// Semantic version string (X.Y.Z).
    pub version: String,
    /// Human-readable description of what the skill does.
    pub description: String,
    /// Optional author attribution.
    pub author: Option<String>,
    /// Cedar action names the skill requires.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Relative path to the skill's executable or script.
    pub entry_point: String,
    /// Names of other skills this skill depends on.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Minimum Aegis version required to run this skill.
    pub min_aegis_version: Option<String>,
}

/// Validate a parsed manifest for security and correctness constraints.
///
/// Checks:
/// - Name is alphanumeric + hyphens, 1-64 chars, no shell metacharacters
/// - Version matches semver X.Y.Z pattern
/// - Entry point contains no path traversal (`..`)
/// - No empty permission entries
/// - No duplicate permission entries
pub fn validate_manifest(manifest: &SkillManifest) -> Result<()> {
    // -- Name validation --
    if manifest.name.is_empty() {
        bail!("skill name must not be empty");
    }
    if manifest.name.len() > MAX_NAME_LEN {
        bail!(
            "skill name exceeds maximum length of {MAX_NAME_LEN} characters: {}",
            manifest.name
        );
    }
    if !manifest
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!(
            "skill name must contain only alphanumeric characters and hyphens: {}",
            manifest.name
        );
    }

    // -- Version validation (semver X.Y.Z) --
    validate_semver(&manifest.version)?;

    // -- Entry point: reject path traversal --
    validate_entry_point(&manifest.entry_point)?;

    // -- Permissions: no empties, no duplicates --
    validate_permissions(&manifest.permissions)?;

    Ok(())
}

/// Parse a skill manifest from a TOML string.
pub fn parse_manifest(toml_str: &str) -> Result<SkillManifest> {
    let manifest: SkillManifest =
        toml::from_str(toml_str).context("failed to parse skill manifest TOML")?;
    Ok(manifest)
}

/// Parse a skill manifest from a file path.
pub fn parse_manifest_file(path: &Path) -> Result<SkillManifest> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_manifest(&content)
}

/// Validate that a version string matches the semver X.Y.Z pattern.
fn validate_semver(version: &str) -> Result<()> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        bail!("version must be semver (X.Y.Z), got: {version}");
    }
    for part in &parts {
        if part.is_empty() {
            bail!("version must be semver (X.Y.Z), got: {version}");
        }
        if part.parse::<u64>().is_err() {
            bail!("version must be semver (X.Y.Z), got: {version}");
        }
    }
    Ok(())
}

/// Validate that an entry point does not contain path traversal sequences.
fn validate_entry_point(entry_point: &str) -> Result<()> {
    if entry_point.is_empty() {
        bail!("entry_point must not be empty");
    }
    // Check for `..` anywhere in the path (covers `../`, `..\`, embedded `..`)
    if entry_point.contains("..") {
        bail!("entry_point must not contain path traversal (..): {entry_point}");
    }
    Ok(())
}

/// Validate that permissions contain no empty entries and no duplicates.
fn validate_permissions(permissions: &[String]) -> Result<()> {
    let mut seen = HashSet::new();
    for perm in permissions {
        if perm.is_empty() {
            bail!("permissions must not contain empty entries");
        }
        if !seen.insert(perm.as_str()) {
            bail!("duplicate permission: {perm}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> &'static str {
        r#"
name = "my-skill"
version = "1.0.0"
description = "A test skill"
author = "Test Author"
permissions = ["action::read", "action::write"]
entry_point = "run.sh"
dependencies = ["other-skill"]
min_aegis_version = "0.1.0"
"#
    }

    fn minimal_toml() -> &'static str {
        r#"
name = "minimal"
version = "0.1.0"
description = "Minimal skill"
entry_point = "main.py"
"#
    }

    #[test]
    fn test_manifest_parse_valid() {
        let manifest = parse_manifest(valid_toml()).unwrap();
        assert_eq!(manifest.name, "my-skill");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.description, "A test skill");
        assert_eq!(manifest.author.as_deref(), Some("Test Author"));
        assert_eq!(manifest.permissions, vec!["action::read", "action::write"]);
        assert_eq!(manifest.entry_point, "run.sh");
        assert_eq!(manifest.dependencies, vec!["other-skill"]);
        assert_eq!(manifest.min_aegis_version.as_deref(), Some("0.1.0"));

        validate_manifest(&manifest).unwrap();
    }

    #[test]
    fn test_manifest_parse_minimal() {
        let manifest = parse_manifest(minimal_toml()).unwrap();
        assert_eq!(manifest.name, "minimal");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.description, "Minimal skill");
        assert!(manifest.author.is_none());
        assert!(manifest.permissions.is_empty());
        assert_eq!(manifest.entry_point, "main.py");
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.min_aegis_version.is_none());

        validate_manifest(&manifest).unwrap();
    }

    #[test]
    fn test_manifest_validate_rejects_traversal() {
        let mut manifest = parse_manifest(valid_toml()).unwrap();
        manifest.entry_point = "../../../etc/passwd".to_string();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "expected traversal error, got: {err}"
        );
    }

    #[test]
    fn test_manifest_validate_rejects_empty_name() {
        let mut manifest = parse_manifest(valid_toml()).unwrap();
        manifest.name = String::new();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "expected empty name error, got: {err}"
        );
    }

    #[test]
    fn test_manifest_validate_rejects_bad_version() {
        let mut manifest = parse_manifest(valid_toml()).unwrap();
        manifest.version = "not-semver".to_string();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("semver"),
            "expected semver error, got: {err}"
        );
    }

    #[test]
    fn test_manifest_validate_rejects_duplicate_permissions() {
        let mut manifest = parse_manifest(valid_toml()).unwrap();
        manifest.permissions = vec!["action::read".into(), "action::read".into()];
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("duplicate permission"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn test_manifest_entry_point_no_traversal() {
        let base = parse_manifest(valid_toml()).unwrap();

        let traversal_patterns = [
            "../run.sh",
            "../../run.sh",
            "foo/../bar/run.sh",
            "..\\run.sh",
            "foo\\..\\bar",
            "....", // contains ..
        ];

        for pattern in &traversal_patterns {
            let mut m = base.clone();
            m.entry_point = pattern.to_string();
            let err = validate_manifest(&m).unwrap_err();
            assert!(
                err.to_string().contains("path traversal"),
                "expected traversal rejection for {pattern:?}, got: {err}"
            );
        }

        // Valid paths that should pass
        let valid_paths = ["run.sh", "bin/run", "scripts/start.py", "a.b.c"];
        for path in &valid_paths {
            let mut m = base.clone();
            m.entry_point = path.to_string();
            validate_manifest(&m).unwrap();
        }
    }

    #[test]
    fn test_manifest_name_injection() {
        let base = parse_manifest(valid_toml()).unwrap();

        let injection_names = [
            "bad;name",
            "bad|name",
            "bad&name",
            "bad`name",
            "bad$(cmd)",
            "bad name",
            "bad\tname",
            "bad\nname",
            "bad/name",
            "bad\\name",
            "../etc",
            "bad'name",
            "bad\"name",
        ];

        for name in &injection_names {
            let mut m = base.clone();
            m.name = name.to_string();
            let err = validate_manifest(&m).unwrap_err();
            assert!(
                err.to_string().contains("alphanumeric")
                    || err.to_string().contains("must not be empty"),
                "expected name rejection for {name:?}, got: {err}"
            );
        }
    }
}
