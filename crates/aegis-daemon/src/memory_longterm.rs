//! Curated permanent notes file (`MEMORY.md`).
//!
//! Provides a structured, agent-writable long-term memory file with
//! merge semantics. Sections are appended to (never overwritten) so
//! multiple agents can contribute notes without losing each other's
//! work.
//!
//! ## File Format
//!
//! ```text
//! # MEMORY
//!
//! ## Preferences
//! - User prefers Rust for systems programming.
//! - Dark mode for all TUI interfaces.
//!
//! ## Decisions
//! - Chose PostgreSQL for the database layer.
//!
//! ## Facts
//! - API endpoint: /v1/users
//! - Server port: 8080
//!
//! ## Instructions
//! - Always run tests before committing.
//!
//! ## Notes
//! - Project uses workspace-level Cargo.toml.
//! ```
//!
//! ## Merge Semantics
//!
//! When writing to a section, existing content is preserved and new
//! entries are appended. Duplicate entries (exact text match) are
//! skipped to prevent bloat.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Well-known sections in the MEMORY.md file.
pub const KNOWN_SECTIONS: &[&str] = &[
    "Preferences",
    "Decisions",
    "Facts",
    "Instructions",
    "Notes",
];

/// Configuration for the long-term memory file.
#[derive(Debug, Clone)]
pub struct LongtermMemoryConfig {
    /// Path to the MEMORY.md file.
    pub file_path: PathBuf,
}

impl Default for LongtermMemoryConfig {
    fn default() -> Self {
        Self {
            file_path: PathBuf::from("MEMORY.md"),
        }
    }
}

/// A parsed section from the MEMORY.md file.
#[derive(Debug, Clone, PartialEq)]
pub struct MemorySection {
    /// Section name (e.g., "Preferences", "Decisions").
    pub name: String,
    /// List of entries in this section.
    pub entries: Vec<String>,
}

/// Manager for the long-term MEMORY.md file.
pub struct LongtermMemoryManager {
    config: LongtermMemoryConfig,
}

impl LongtermMemoryManager {
    /// Create a new long-term memory manager.
    pub fn new(config: LongtermMemoryConfig) -> Self {
        Self { config }
    }

    /// Return the path to the MEMORY.md file.
    pub fn file_path(&self) -> &Path {
        &self.config.file_path
    }

    /// Load and parse the MEMORY.md file.
    ///
    /// Returns an empty vec of sections if the file does not exist.
    pub fn load(&self) -> Result<Vec<MemorySection>> {
        if !self.config.file_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.config.file_path).with_context(|| {
            format!(
                "read long-term memory: {}",
                self.config.file_path.display()
            )
        })?;

        Ok(parse_memory_md(&content))
    }

    /// Load the raw content of the MEMORY.md file for context injection.
    ///
    /// Returns an empty string if the file does not exist.
    pub fn load_raw(&self) -> Result<String> {
        if !self.config.file_path.exists() {
            return Ok(String::new());
        }

        fs::read_to_string(&self.config.file_path).with_context(|| {
            format!(
                "read long-term memory: {}",
                self.config.file_path.display()
            )
        })
    }

    /// Append an entry to a section using merge semantics.
    ///
    /// If the section does not exist, it is created. If the entry already
    /// exists in the section (exact match), it is skipped. The file is
    /// rewritten atomically.
    pub fn append_to_section(&self, section: &str, entry: &str) -> Result<bool> {
        let mut sections = self.load()?;

        // Find or create the section.
        let section_idx = sections.iter().position(|s| s.name == section);

        let section_entries = match section_idx {
            Some(idx) => &mut sections[idx].entries,
            None => {
                sections.push(MemorySection {
                    name: section.to_string(),
                    entries: Vec::new(),
                });
                let last_idx = sections.len() - 1;
                &mut sections[last_idx].entries
            }
        };

        // Check for duplicate.
        let trimmed_entry = entry.trim();
        let already_exists = section_entries.iter().any(|e| e.trim() == trimmed_entry);
        if already_exists {
            return Ok(false);
        }

        section_entries.push(trimmed_entry.to_string());

        // Write back.
        self.write_sections(&sections)?;
        Ok(true)
    }

    /// Merge multiple entries into a section at once.
    ///
    /// Returns the number of new entries actually added (duplicates skipped).
    pub fn merge_entries(&self, section: &str, entries: &[String]) -> Result<usize> {
        let mut sections = self.load()?;

        // Find or create the section.
        let section_idx = sections.iter().position(|s| s.name == section);
        let section_entries = match section_idx {
            Some(idx) => &mut sections[idx].entries,
            None => {
                sections.push(MemorySection {
                    name: section.to_string(),
                    entries: Vec::new(),
                });
                let last_idx = sections.len() - 1;
                &mut sections[last_idx].entries
            }
        };

        let mut added = 0;
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let already_exists = section_entries.iter().any(|e| e.trim() == trimmed);
            if !already_exists {
                section_entries.push(trimmed.to_string());
                added += 1;
            }
        }

        if added > 0 {
            self.write_sections(&sections)?;
        }

        Ok(added)
    }

    /// Get all entries from a specific section.
    pub fn get_section(&self, section: &str) -> Result<Vec<String>> {
        let sections = self.load()?;
        Ok(sections
            .into_iter()
            .find(|s| s.name == section)
            .map(|s| s.entries)
            .unwrap_or_default())
    }

    /// Format the MEMORY.md content for context injection.
    ///
    /// Returns the raw file content wrapped in a heading, or empty
    /// string if the file does not exist.
    pub fn format_for_context(&self) -> Result<String> {
        let raw = self.load_raw()?;
        if raw.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("## Long-term Memory\n\n{raw}"))
    }

    /// Write sections back to the MEMORY.md file.
    fn write_sections(&self, sections: &[MemorySection]) -> Result<()> {
        // Ensure parent directory exists.
        if let Some(parent) = self.config.file_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create directory for MEMORY.md: {}", parent.display())
            })?;
        }

        let content = format_memory_md(sections);
        fs::write(&self.config.file_path, content).with_context(|| {
            format!(
                "write long-term memory: {}",
                self.config.file_path.display()
            )
        })
    }
}

/// Parse a MEMORY.md file into sections.
fn parse_memory_md(content: &str) -> Vec<MemorySection> {
    let mut sections = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_entries: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Top-level header (# MEMORY) -- skip.
        if trimmed.starts_with("# ") && !trimmed.starts_with("## ") {
            continue;
        }

        // Section header (## SectionName).
        if let Some(section_name) = trimmed.strip_prefix("## ") {
            // Flush previous section.
            if let Some(ref name) = current_section {
                if !current_entries.is_empty() {
                    sections.push(MemorySection {
                        name: name.clone(),
                        entries: current_entries.clone(),
                    });
                    current_entries.clear();
                } else {
                    // Section with no entries still gets recorded.
                    sections.push(MemorySection {
                        name: name.clone(),
                        entries: Vec::new(),
                    });
                }
            }
            current_section = Some(section_name.trim().to_string());
            continue;
        }

        // List entry (- text).
        if let Some(entry_text) = trimmed.strip_prefix("- ") {
            if current_section.is_some() {
                current_entries.push(entry_text.to_string());
            }
        }
    }

    // Flush last section.
    if let Some(name) = current_section {
        sections.push(MemorySection {
            name,
            entries: current_entries,
        });
    }

    sections
}

/// Format sections into MEMORY.md content.
fn format_memory_md(sections: &[MemorySection]) -> String {
    let mut output = String::from("# MEMORY\n\n");

    for section in sections {
        output.push_str(&format!("## {}\n", section.name));
        for entry in &section.entries {
            output.push_str(&format!("- {}\n", entry));
        }
        output.push('\n');
    }

    output
}

/// Build a lookup map from section name to entries for quick access.
pub fn sections_to_map(sections: &[MemorySection]) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for section in sections {
        map.insert(section.name.clone(), section.entries.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_manager() -> (LongtermMemoryManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let config = LongtermMemoryConfig {
            file_path: dir.path().join("MEMORY.md"),
        };
        let manager = LongtermMemoryManager::new(config);
        (manager, dir)
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let (manager, _dir) = test_manager();
        let sections = manager.load().unwrap();
        assert!(sections.is_empty());
    }

    #[test]
    fn test_append_creates_file() {
        let (manager, _dir) = test_manager();

        let added = manager
            .append_to_section("Preferences", "User prefers Rust.")
            .unwrap();
        assert!(added);

        assert!(manager.file_path().exists());

        let sections = manager.load().unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].name, "Preferences");
        assert_eq!(sections[0].entries, vec!["User prefers Rust."]);
    }

    #[test]
    fn test_append_deduplicates() {
        let (manager, _dir) = test_manager();

        let added1 = manager
            .append_to_section("Facts", "Server runs on port 8080.")
            .unwrap();
        assert!(added1);

        // Same entry should be skipped.
        let added2 = manager
            .append_to_section("Facts", "Server runs on port 8080.")
            .unwrap();
        assert!(!added2);

        let entries = manager.get_section("Facts").unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_append_preserves_existing() {
        let (manager, _dir) = test_manager();

        manager
            .append_to_section("Preferences", "Likes Rust.")
            .unwrap();
        manager
            .append_to_section("Preferences", "Prefers dark mode.")
            .unwrap();
        manager
            .append_to_section("Facts", "Port 8080.")
            .unwrap();

        let sections = manager.load().unwrap();
        assert_eq!(sections.len(), 2);

        let prefs = sections.iter().find(|s| s.name == "Preferences").unwrap();
        assert_eq!(prefs.entries.len(), 2);
        assert_eq!(prefs.entries[0], "Likes Rust.");
        assert_eq!(prefs.entries[1], "Prefers dark mode.");

        let facts = sections.iter().find(|s| s.name == "Facts").unwrap();
        assert_eq!(facts.entries.len(), 1);
    }

    #[test]
    fn test_merge_entries() {
        let (manager, _dir) = test_manager();

        manager
            .append_to_section("Notes", "First note.")
            .unwrap();

        let new_entries = vec![
            "First note.".into(),  // duplicate
            "Second note.".into(), // new
            "Third note.".into(),  // new
        ];

        let added = manager.merge_entries("Notes", &new_entries).unwrap();
        assert_eq!(added, 2);

        let entries = manager.get_section("Notes").unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_merge_empty_entries() {
        let (manager, _dir) = test_manager();

        let added = manager.merge_entries("Notes", &[]).unwrap();
        assert_eq!(added, 0);
    }

    #[test]
    fn test_merge_skips_blank_entries() {
        let (manager, _dir) = test_manager();

        let entries = vec!["  ".into(), "".into(), "Valid entry.".into()];
        let added = manager.merge_entries("Notes", &entries).unwrap();
        assert_eq!(added, 1);

        let loaded = manager.get_section("Notes").unwrap();
        assert_eq!(loaded, vec!["Valid entry."]);
    }

    #[test]
    fn test_get_nonexistent_section() {
        let (manager, _dir) = test_manager();
        manager
            .append_to_section("Facts", "Something.")
            .unwrap();

        let entries = manager.get_section("Nonexistent").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_memory_md_roundtrip() {
        let content = r#"# MEMORY

## Preferences
- User prefers Rust.
- Dark mode for TUI.

## Decisions
- Chose PostgreSQL.

## Facts
- API at /v1/users.
- Server port: 8080.

"#;

        let sections = parse_memory_md(content);
        assert_eq!(sections.len(), 3);

        assert_eq!(sections[0].name, "Preferences");
        assert_eq!(sections[0].entries.len(), 2);

        assert_eq!(sections[1].name, "Decisions");
        assert_eq!(sections[1].entries.len(), 1);

        assert_eq!(sections[2].name, "Facts");
        assert_eq!(sections[2].entries.len(), 2);

        // Re-format and re-parse should be stable.
        let formatted = format_memory_md(&sections);
        let reparsed = parse_memory_md(&formatted);
        assert_eq!(sections, reparsed);
    }

    #[test]
    fn test_format_for_context() {
        let (manager, _dir) = test_manager();

        // Empty file returns empty string.
        let ctx = manager.format_for_context().unwrap();
        assert!(ctx.is_empty());

        // With content.
        manager
            .append_to_section("Facts", "Port 8080.")
            .unwrap();
        let ctx = manager.format_for_context().unwrap();
        assert!(ctx.contains("## Long-term Memory"));
        assert!(ctx.contains("Port 8080."));
    }

    #[test]
    fn test_sections_to_map() {
        let sections = vec![
            MemorySection {
                name: "Preferences".into(),
                entries: vec!["Rust.".into()],
            },
            MemorySection {
                name: "Facts".into(),
                entries: vec!["Port 8080.".into(), "API v1.".into()],
            },
        ];

        let map = sections_to_map(&sections);
        assert_eq!(map.len(), 2);
        assert_eq!(map["Preferences"], vec!["Rust."]);
        assert_eq!(map["Facts"], vec!["Port 8080.", "API v1."]);
    }

    #[test]
    fn test_load_raw_nonexistent() {
        let (manager, _dir) = test_manager();
        let raw = manager.load_raw().unwrap();
        assert!(raw.is_empty());
    }

    #[test]
    fn test_known_sections_constant() {
        assert_eq!(KNOWN_SECTIONS.len(), 5);
        assert!(KNOWN_SECTIONS.contains(&"Preferences"));
        assert!(KNOWN_SECTIONS.contains(&"Decisions"));
        assert!(KNOWN_SECTIONS.contains(&"Facts"));
        assert!(KNOWN_SECTIONS.contains(&"Instructions"));
        assert!(KNOWN_SECTIONS.contains(&"Notes"));
    }
}
