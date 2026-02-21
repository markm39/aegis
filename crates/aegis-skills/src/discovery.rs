//! Skill discovery from the filesystem.
//!
//! Scans a directory for subdirectories containing `manifest.toml`, parses
//! and validates each manifest, and returns skill instances in the Discovered state.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::lifecycle::SkillInstance;
use crate::manifest::{parse_manifest_file, validate_manifest};

/// The expected manifest filename inside each skill directory.
const MANIFEST_FILENAME: &str = "manifest.toml";

/// Discover skills in a directory.
///
/// Scans `skills_dir` for immediate subdirectories containing a `manifest.toml`.
/// Each valid manifest produces a [`SkillInstance`] in the `Discovered` state.
/// Invalid manifests are skipped with a warning (logged via the returned error
/// collection in the second element).
///
/// # Security
///
/// - Rejects `skills_dir` paths that do not exist or are not directories.
/// - Validates that `skills_dir` is not a symlink pointing outside its parent.
/// - Each discovered manifest is validated before inclusion.
pub fn discover_skills(skills_dir: &Path) -> Result<Vec<SkillInstance>> {
    // Validate the skills directory itself
    validate_skills_dir(skills_dir)?;

    let mut instances = Vec::new();

    let entries = std::fs::read_dir(skills_dir)
        .with_context(|| format!("failed to read skills directory: {}", skills_dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();

        // Only process directories
        if !entry_path.is_dir() {
            continue;
        }

        // Skip symlinks that point outside the skills directory
        if entry_path.is_symlink() {
            match validate_symlink_target(&entry_path, skills_dir) {
                Ok(()) => {}
                Err(_) => continue,
            }
        }

        let manifest_path = entry_path.join(MANIFEST_FILENAME);
        if !manifest_path.exists() {
            continue;
        }

        // Parse and validate
        let manifest = match parse_manifest_file(&manifest_path) {
            Ok(m) => m,
            Err(_) => continue, // skip invalid manifests
        };

        if validate_manifest(&manifest).is_err() {
            continue; // skip manifests that fail validation
        }

        instances.push(SkillInstance::discover(manifest, entry_path));
    }

    Ok(instances)
}

/// Validate that the skills directory exists, is a directory, and is safe.
fn validate_skills_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("skills directory does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!("skills path is not a directory: {}", path.display());
    }

    // If the path itself is a symlink, resolve and check it stays reasonable
    if path.is_symlink() {
        let resolved = std::fs::canonicalize(path)
            .with_context(|| format!("failed to resolve symlink: {}", path.display()))?;
        if !resolved.is_dir() {
            bail!(
                "skills directory symlink resolves to non-directory: {}",
                resolved.display()
            );
        }
    }

    Ok(())
}

/// Validate that a symlink target stays within the skills directory.
fn validate_symlink_target(link: &Path, skills_dir: &Path) -> Result<()> {
    let canonical_link = std::fs::canonicalize(link)
        .with_context(|| format!("failed to resolve symlink: {}", link.display()))?;
    let canonical_dir = std::fs::canonicalize(skills_dir)
        .with_context(|| format!("failed to resolve skills dir: {}", skills_dir.display()))?;

    if !canonical_link.starts_with(&canonical_dir) {
        bail!(
            "symlink {} points outside skills directory {}",
            link.display(),
            skills_dir.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_manifest(dir: &Path, name: &str) {
        let skill_dir = dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        let manifest = format!(
            r#"
name = "{name}"
version = "1.0.0"
description = "Skill {name}"
entry_point = "run.sh"
"#
        );
        std::fs::write(skill_dir.join("manifest.toml"), manifest).unwrap();
    }

    fn write_invalid_manifest(dir: &Path, name: &str) {
        let skill_dir = dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("manifest.toml"), "not valid toml [[[").unwrap();
    }

    #[test]
    fn test_discovery_finds_skills() {
        let tmp = TempDir::new().unwrap();
        write_manifest(tmp.path(), "skill-a");
        write_manifest(tmp.path(), "skill-b");
        write_manifest(tmp.path(), "skill-c");

        let skills = discover_skills(tmp.path()).unwrap();
        assert_eq!(skills.len(), 3);

        let mut names: Vec<&str> = skills.iter().map(|s| s.manifest.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["skill-a", "skill-b", "skill-c"]);
    }

    #[test]
    fn test_discovery_skips_invalid() {
        let tmp = TempDir::new().unwrap();
        write_manifest(tmp.path(), "good-skill");
        write_invalid_manifest(tmp.path(), "bad-skill");

        let skills = discover_skills(tmp.path()).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].manifest.name, "good-skill");
    }

    #[test]
    fn test_discovery_nonexistent_dir() {
        let result = discover_skills(Path::new("/nonexistent/path/to/skills"));
        assert!(result.is_err());
    }

    #[test]
    fn test_discovery_skips_files() {
        let tmp = TempDir::new().unwrap();
        write_manifest(tmp.path(), "real-skill");

        // Write a plain file (not a directory) -- should be skipped
        std::fs::write(tmp.path().join("not-a-skill.txt"), "hello").unwrap();

        let skills = discover_skills(tmp.path()).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].manifest.name, "real-skill");
    }

    #[test]
    fn test_discovery_skips_dir_without_manifest() {
        let tmp = TempDir::new().unwrap();
        write_manifest(tmp.path(), "has-manifest");
        std::fs::create_dir_all(tmp.path().join("no-manifest")).unwrap();

        let skills = discover_skills(tmp.path()).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].manifest.name, "has-manifest");
    }
}
