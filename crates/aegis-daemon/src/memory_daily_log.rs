//! Daily memory log files at `memory/YYYY-MM-DD.md`.
//!
//! Provides append-only date-stamped markdown files for durable memory
//! persistence. Events are written as timestamped entries within daily
//! files. On session start, today's log and recent days' logs are
//! automatically loaded to restore context.
//!
//! ## File Format
//!
//! Each daily log is a markdown file with entries:
//!
//! ```text
//! # 2026-02-21
//!
//! ## 14:30:05 [decision]
//! Chose PostgreSQL for the database layer.
//!
//! ## 14:35:12 [preference]
//! User prefers dark mode for all TUI interfaces.
//! ```
//!
//! ## Retention
//!
//! Configurable retention period controls how many days of logs are
//! kept. Older files are pruned on startup. Default: 30 days.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};

/// Configuration for daily memory logs.
#[derive(Debug, Clone)]
pub struct DailyLogConfig {
    /// Root directory for memory log files. Each day gets a `YYYY-MM-DD.md` file.
    pub log_dir: PathBuf,
    /// Number of days of logs to retain. Older files are pruned on startup.
    /// Default: 30.
    pub retention_days: u32,
    /// Number of recent days to auto-load on session start. Default: 3.
    pub load_recent_days: u32,
}

impl Default for DailyLogConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("memory"),
            retention_days: 30,
            load_recent_days: 3,
        }
    }
}

/// A single entry in a daily memory log.
#[derive(Debug, Clone, PartialEq)]
pub struct DailyLogEntry {
    /// ISO 8601 timestamp of the entry.
    pub timestamp: String,
    /// Category of the entry (e.g., "decision", "preference", "fact").
    pub category: String,
    /// The content of the entry.
    pub content: String,
}

/// Manager for daily memory log files.
pub struct DailyLogManager {
    config: DailyLogConfig,
}

impl DailyLogManager {
    /// Create a new daily log manager with the given configuration.
    ///
    /// Creates the log directory if it does not exist.
    pub fn new(config: DailyLogConfig) -> Result<Self> {
        fs::create_dir_all(&config.log_dir)
            .with_context(|| format!("create daily log directory: {}", config.log_dir.display()))?;
        Ok(Self { config })
    }

    /// Return the file path for a given date's log.
    pub fn log_path_for_date(&self, date: NaiveDate) -> PathBuf {
        self.config
            .log_dir
            .join(format!("{}.md", date.format("%Y-%m-%d")))
    }

    /// Append an entry to today's daily log file.
    ///
    /// Creates the file with a date header if it does not exist.
    /// Writes are atomic at the entry level (single write call).
    pub fn append_entry(&self, entry: &DailyLogEntry) -> Result<()> {
        let today = Utc::now().date_naive();
        self.append_entry_for_date(entry, today)
    }

    /// Append an entry to a specific date's log file.
    fn append_entry_for_date(&self, entry: &DailyLogEntry, date: NaiveDate) -> Result<()> {
        let path = self.log_path_for_date(date);
        let file_exists = path.exists();

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open daily log: {}", path.display()))?;

        // Write date header if this is a new file.
        if !file_exists {
            writeln!(file, "# {}\n", date.format("%Y-%m-%d"))?;
        }

        // Write the entry.
        writeln!(
            file,
            "## {} [{}]\n{}\n",
            entry.timestamp, entry.category, entry.content
        )?;

        Ok(())
    }

    /// Load entries from a specific date's log file.
    ///
    /// Returns an empty vec if the file does not exist.
    pub fn load_date(&self, date: NaiveDate) -> Result<Vec<DailyLogEntry>> {
        let path = self.log_path_for_date(date);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("read daily log: {}", path.display()))?;

        Ok(parse_daily_log(&content))
    }

    /// Load today's log and the configured number of recent days' logs.
    ///
    /// Returns entries from all loaded days, oldest first.
    pub fn load_recent(&self) -> Result<Vec<(NaiveDate, Vec<DailyLogEntry>)>> {
        let today = Utc::now().date_naive();
        let mut results = Vec::new();

        for days_ago in (0..self.config.load_recent_days).rev() {
            if let Some(date) = today.checked_sub_signed(chrono::Duration::days(days_ago as i64)) {
                let entries = self.load_date(date)?;
                if !entries.is_empty() {
                    results.push((date, entries));
                }
            }
        }

        Ok(results)
    }

    /// Prune log files older than the retention period.
    ///
    /// Returns the number of files removed.
    pub fn prune_old_logs(&self) -> Result<usize> {
        let today = Utc::now().date_naive();
        let cutoff = today
            .checked_sub_signed(chrono::Duration::days(self.config.retention_days as i64))
            .unwrap_or(today);

        let mut removed = 0;

        let entries = fs::read_dir(&self.config.log_dir)
            .with_context(|| format!("read log directory: {}", self.config.log_dir.display()))?;

        for dir_entry in entries {
            let dir_entry = dir_entry?;
            let file_name = dir_entry.file_name();
            let name = file_name.to_string_lossy();

            // Only process files matching YYYY-MM-DD.md pattern.
            if let Some(date_str) = name.strip_suffix(".md") {
                if let Ok(file_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    if file_date < cutoff {
                        fs::remove_file(dir_entry.path()).with_context(|| {
                            format!("remove old log: {}", dir_entry.path().display())
                        })?;
                        removed += 1;
                    }
                }
            }
        }

        Ok(removed)
    }

    /// Format loaded log entries as a markdown block suitable for context injection.
    pub fn format_for_context(logs: &[(NaiveDate, Vec<DailyLogEntry>)]) -> String {
        if logs.is_empty() {
            return String::new();
        }

        let mut output = String::from("## Daily Memory Log\n\n");

        for (date, entries) in logs {
            output.push_str(&format!("### {}\n\n", date.format("%Y-%m-%d")));
            for entry in entries {
                output.push_str(&format!(
                    "- **[{}]** {} {}\n",
                    entry.category, entry.timestamp, entry.content
                ));
            }
            output.push('\n');
        }

        output
    }

    /// Return a reference to the underlying config.
    pub fn config(&self) -> &DailyLogConfig {
        &self.config
    }

    /// Return the log directory path.
    pub fn log_dir(&self) -> &Path {
        &self.config.log_dir
    }
}

/// Parse a daily log markdown file into structured entries.
///
/// Expects the format:
/// ```text
/// # 2026-02-21
///
/// ## 14:30:05 [decision]
/// Content here.
/// ```
fn parse_daily_log(content: &str) -> Vec<DailyLogEntry> {
    let mut entries = Vec::new();
    let mut current_timestamp = String::new();
    let mut current_category = String::new();
    let mut current_content = Vec::new();
    let mut in_entry = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip the date header line (# YYYY-MM-DD).
        if trimmed.starts_with("# ") && !trimmed.starts_with("## ") {
            continue;
        }

        // Entry header: ## HH:MM:SS [category]
        if let Some(rest) = trimmed.strip_prefix("## ") {
            // Flush previous entry.
            if in_entry && !current_content.is_empty() {
                entries.push(DailyLogEntry {
                    timestamp: current_timestamp.clone(),
                    category: current_category.clone(),
                    content: current_content.join("\n").trim().to_string(),
                });
                current_content.clear();
            }

            // Parse timestamp and category from "HH:MM:SS [category]".
            if let Some(bracket_start) = rest.find('[') {
                if let Some(bracket_end) = rest.find(']') {
                    current_timestamp = rest[..bracket_start].trim().to_string();
                    current_category = rest[bracket_start + 1..bracket_end].trim().to_string();
                    in_entry = true;
                    continue;
                }
            }
        }

        // Content lines.
        if in_entry && !trimmed.is_empty() {
            current_content.push(trimmed.to_string());
        }
    }

    // Flush the last entry.
    if in_entry && !current_content.is_empty() {
        entries.push(DailyLogEntry {
            timestamp: current_timestamp,
            category: current_category,
            content: current_content.join("\n").trim().to_string(),
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_manager() -> (DailyLogManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let config = DailyLogConfig {
            log_dir: dir.path().join("memory"),
            retention_days: 30,
            load_recent_days: 3,
        };
        let manager = DailyLogManager::new(config).unwrap();
        (manager, dir)
    }

    #[test]
    fn test_append_and_load_entry() {
        let (manager, _dir) = test_manager();
        let today = Utc::now().date_naive();

        let entry = DailyLogEntry {
            timestamp: "14:30:05".into(),
            category: "decision".into(),
            content: "Chose PostgreSQL for the database.".into(),
        };

        manager.append_entry_for_date(&entry, today).unwrap();

        let loaded = manager.load_date(today).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].category, "decision");
        assert_eq!(loaded[0].content, "Chose PostgreSQL for the database.");
        assert_eq!(loaded[0].timestamp, "14:30:05");
    }

    #[test]
    fn test_append_multiple_entries() {
        let (manager, _dir) = test_manager();
        let today = Utc::now().date_naive();

        let entries = vec![
            DailyLogEntry {
                timestamp: "10:00:00".into(),
                category: "preference".into(),
                content: "Prefers Rust over Go.".into(),
            },
            DailyLogEntry {
                timestamp: "10:05:00".into(),
                category: "fact".into(),
                content: "Server runs on port 8080.".into(),
            },
            DailyLogEntry {
                timestamp: "10:10:00".into(),
                category: "instruction".into(),
                content: "Always run tests before committing.".into(),
            },
        ];

        for e in &entries {
            manager.append_entry_for_date(e, today).unwrap();
        }

        let loaded = manager.load_date(today).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].category, "preference");
        assert_eq!(loaded[1].category, "fact");
        assert_eq!(loaded[2].category, "instruction");
    }

    #[test]
    fn test_load_nonexistent_date_returns_empty() {
        let (manager, _dir) = test_manager();
        let date = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        let loaded = manager.load_date(date).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_load_recent_includes_today() {
        let (manager, _dir) = test_manager();
        let today = Utc::now().date_naive();

        let entry = DailyLogEntry {
            timestamp: "12:00:00".into(),
            category: "fact".into(),
            content: "Test fact.".into(),
        };

        manager.append_entry_for_date(&entry, today).unwrap();

        let recent = manager.load_recent().unwrap();
        assert!(!recent.is_empty());

        // Today's entries should be present.
        let today_entries = recent.iter().find(|(d, _)| *d == today);
        assert!(
            today_entries.is_some(),
            "today's entries should be in recent logs"
        );
    }

    #[test]
    fn test_prune_old_logs() {
        let (manager, _dir) = test_manager();
        let today = Utc::now().date_naive();

        // Create an old log file (40 days ago, beyond 30-day retention).
        let old_date = today
            .checked_sub_signed(chrono::Duration::days(40))
            .unwrap();
        let entry = DailyLogEntry {
            timestamp: "09:00:00".into(),
            category: "fact".into(),
            content: "Old fact.".into(),
        };
        manager.append_entry_for_date(&entry, old_date).unwrap();

        // Create a recent log file (5 days ago, within retention).
        let recent_date = today.checked_sub_signed(chrono::Duration::days(5)).unwrap();
        manager.append_entry_for_date(&entry, recent_date).unwrap();

        // Prune should remove the old file.
        let removed = manager.prune_old_logs().unwrap();
        assert_eq!(removed, 1);

        // Old file should be gone.
        assert!(!manager.log_path_for_date(old_date).exists());

        // Recent file should remain.
        assert!(manager.log_path_for_date(recent_date).exists());
    }

    #[test]
    fn test_log_path_format() {
        let (manager, _dir) = test_manager();
        let date = NaiveDate::from_ymd_opt(2026, 2, 21).unwrap();
        let path = manager.log_path_for_date(date);
        assert!(path.to_string_lossy().ends_with("2026-02-21.md"));
    }

    #[test]
    fn test_parse_daily_log_roundtrip() {
        let content = r#"# 2026-02-21

## 14:30:05 [decision]
Chose PostgreSQL for the database.

## 14:35:12 [preference]
User prefers dark mode for all TUI interfaces.

## 15:00:00 [fact]
The API endpoint is at /v1/users.
"#;

        let entries = parse_daily_log(content);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].timestamp, "14:30:05");
        assert_eq!(entries[0].category, "decision");
        assert_eq!(entries[0].content, "Chose PostgreSQL for the database.");

        assert_eq!(entries[1].timestamp, "14:35:12");
        assert_eq!(entries[1].category, "preference");
        assert_eq!(
            entries[1].content,
            "User prefers dark mode for all TUI interfaces."
        );

        assert_eq!(entries[2].timestamp, "15:00:00");
        assert_eq!(entries[2].category, "fact");
        assert_eq!(entries[2].content, "The API endpoint is at /v1/users.");
    }

    #[test]
    fn test_format_for_context() {
        let today = NaiveDate::from_ymd_opt(2026, 2, 21).unwrap();
        let entries = vec![DailyLogEntry {
            timestamp: "14:30:05".into(),
            category: "decision".into(),
            content: "Chose PostgreSQL.".into(),
        }];

        let logs = vec![(today, entries)];
        let formatted = DailyLogManager::format_for_context(&logs);

        assert!(formatted.contains("## Daily Memory Log"));
        assert!(formatted.contains("### 2026-02-21"));
        assert!(formatted.contains("[decision]"));
        assert!(formatted.contains("Chose PostgreSQL."));
    }

    #[test]
    fn test_format_empty_logs() {
        let formatted = DailyLogManager::format_for_context(&[]);
        assert!(formatted.is_empty());
    }

    #[test]
    fn test_append_creates_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("deep").join("nested").join("memory");
        let config = DailyLogConfig {
            log_dir: nested.clone(),
            ..Default::default()
        };
        let manager = DailyLogManager::new(config).unwrap();
        assert!(nested.exists());

        let entry = DailyLogEntry {
            timestamp: "10:00:00".into(),
            category: "fact".into(),
            content: "Test.".into(),
        };
        manager.append_entry(&entry).unwrap();
    }

    #[test]
    fn test_parse_empty_content() {
        let entries = parse_daily_log("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_only_header() {
        let content = "# 2026-02-21\n\n";
        let entries = parse_daily_log(content);
        assert!(entries.is_empty());
    }
}
