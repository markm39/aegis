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

/// Names of the core bundled skills shipped with Aegis.
const BUNDLED_SKILL_NAMES: &[&str] = &[
    "calculator",
    "code-review",
    "file-manager",
    "git-operations",
    "http-client",
    "json-tools",
    "shell-exec",
    "system-info",
    "text-transform",
    "web-search",
];

/// Discover skills bundled with the Aegis installation.
///
/// Looks for a `skills/` directory relative to the running binary, then
/// falls back to common install locations. Returns all valid bundled skill
/// manifests found, skipping any that fail to parse or validate.
///
/// Search order:
/// 1. `<binary_dir>/../skills/` (standard install layout)
/// 2. `<binary_dir>/skills/` (dev/local builds)
/// 3. Current working directory `./skills/`
pub fn discover_bundled_skills() -> Result<Vec<SkillInstance>> {
    let candidates = bundled_skills_candidates();

    for candidate in &candidates {
        if candidate.is_dir() {
            let instances = discover_skills(candidate)?;
            if !instances.is_empty() {
                return Ok(instances);
            }
        }
    }

    bail!(
        "no bundled skills directory found; searched: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Return the list of expected bundled skill names.
pub fn bundled_skill_names() -> &'static [&'static str] {
    BUNDLED_SKILL_NAMES
}

/// Build the list of candidate directories to search for bundled skills.
fn bundled_skills_candidates() -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();

    // Relative to the binary location.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Standard install: <prefix>/bin/aegis -> <prefix>/skills/
            candidates.push(exe_dir.join("../skills"));
            // Dev build: target/debug/aegis -> skills/ next to binary
            candidates.push(exe_dir.join("skills"));
        }
    }

    // Relative to the current working directory.
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("skills"));
    }

    candidates
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

    #[test]
    fn test_bundled_skill_names_list() {
        let names = bundled_skill_names();
        assert_eq!(names.len(), 10);
        assert!(names.contains(&"calculator"));
        assert!(names.contains(&"web-search"));
        assert!(names.contains(&"file-manager"));
        assert!(names.contains(&"git-operations"));
        assert!(names.contains(&"code-review"));
        assert!(names.contains(&"shell-exec"));
        assert!(names.contains(&"http-client"));
        assert!(names.contains(&"json-tools"));
        assert!(names.contains(&"text-transform"));
        assert!(names.contains(&"system-info"));
    }

    #[test]
    fn test_discover_bundled_skills_from_dir() {
        // Build a temporary skills directory matching bundled layout.
        let tmp = TempDir::new().unwrap();
        for name in bundled_skill_names() {
            write_manifest(tmp.path(), name);
        }

        let skills = discover_skills(tmp.path()).unwrap();
        assert_eq!(skills.len(), 10, "should discover all 10 bundled skills");

        let mut names: Vec<&str> = skills.iter().map(|s| s.manifest.name.as_str()).collect();
        names.sort();
        let mut expected: Vec<&str> = bundled_skill_names().to_vec();
        expected.sort();
        assert_eq!(names, expected);
    }

    /// Parse every bundled manifest.toml shipped in the project's skills/ directory.
    /// This test verifies that the actual files on disk are valid.
    #[test]
    fn test_bundled_manifests_parse_and_validate() {
        // Walk up from the test binary to find the project root skills/ dir.
        let project_skills_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()  // crates/
            .and_then(|p| p.parent())  // project root
            .map(|p| p.join("skills"));

        let skills_dir = match project_skills_dir {
            Some(ref p) if p.is_dir() => p.as_path(),
            _ => {
                eprintln!("skipping test: project skills/ directory not found");
                return;
            }
        };

        let skills = discover_skills(skills_dir).unwrap();
        assert_eq!(
            skills.len(),
            10,
            "expected 10 bundled skills in {}, found {}",
            skills_dir.display(),
            skills.len()
        );

        // Verify each manifest validates.
        for skill in &skills {
            crate::manifest::validate_manifest(&skill.manifest)
                .unwrap_or_else(|e| panic!("manifest for '{}' failed validation: {e}", skill.manifest.name));
        }
    }

    /// Verify that discover_bundled_skills candidates list is non-empty.
    #[test]
    fn test_bundled_skills_candidates_not_empty() {
        let candidates = super::bundled_skills_candidates();
        assert!(!candidates.is_empty(), "should have at least one candidate path");
    }
}
