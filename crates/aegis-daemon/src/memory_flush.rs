//! Auto-flush pre-compaction: persist durable memories before context window compaction.
//!
//! When the context window approaches its limit, a "silent flush" writes
//! important context to the daily memory log and long-term MEMORY.md
//! before compaction discards it. This prevents loss of critical information
//! during context window management.
//!
//! ## How It Works
//!
//! 1. Monitor context window usage (token count vs. capacity).
//! 2. When usage exceeds the flush threshold (default: 80%), trigger a flush.
//! 3. The flush extracts important memories from the current context.
//! 4. Memories are written to the daily log and optionally to MEMORY.md.
//! 5. A cooldown period prevents repeated flushes in quick succession.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::memory_capture::{ExtractionCategory, MemoryCapturer};
use crate::memory_daily_log::{DailyLogEntry, DailyLogManager};
use crate::memory_longterm::LongtermMemoryManager;

/// Configuration for the auto-flush mechanism.
#[derive(Debug, Clone)]
pub struct FlushConfig {
    /// Fraction of context window capacity that triggers a flush.
    /// Default: 0.80 (80%).
    pub flush_threshold: f64,
    /// Minimum interval between flushes to prevent thrashing.
    /// Default: 60 seconds.
    pub cooldown_secs: u64,
    /// Whether to also write flushed memories to MEMORY.md.
    /// Default: true.
    pub write_to_longterm: bool,
    /// Maximum number of entries to flush in one pass.
    /// Default: 10.
    pub max_entries_per_flush: usize,
}

impl Default for FlushConfig {
    fn default() -> Self {
        Self {
            flush_threshold: 0.80,
            cooldown_secs: 60,
            write_to_longterm: true,
            max_entries_per_flush: 10,
        }
    }
}

/// Result of a flush operation.
#[derive(Debug, Clone, PartialEq)]
pub struct FlushResult {
    /// Number of entries written to the daily log.
    pub daily_log_entries: usize,
    /// Number of entries written to MEMORY.md.
    pub longterm_entries: usize,
    /// Whether the flush was skipped due to cooldown.
    pub skipped_cooldown: bool,
    /// Whether the flush was skipped because usage is below threshold.
    pub skipped_below_threshold: bool,
}

/// Manager for auto-flushing durable memories before context compaction.
pub struct MemoryFlusher {
    config: FlushConfig,
    last_flush: Option<Instant>,
}

impl MemoryFlusher {
    /// Create a new memory flusher with the given configuration.
    pub fn new(config: FlushConfig) -> Self {
        Self {
            config,
            last_flush: None,
        }
    }

    /// Check whether a flush should be triggered based on context window usage.
    ///
    /// Returns `true` if:
    /// - `current_tokens / max_tokens` exceeds the flush threshold
    /// - The cooldown period has elapsed since the last flush
    pub fn should_flush(&self, current_tokens: usize, max_tokens: usize) -> bool {
        if max_tokens == 0 {
            return false;
        }

        let usage = current_tokens as f64 / max_tokens as f64;
        if usage < self.config.flush_threshold {
            return false;
        }

        // Check cooldown.
        if let Some(last) = &self.last_flush {
            if last.elapsed() < Duration::from_secs(self.config.cooldown_secs) {
                return false;
            }
        }

        true
    }

    /// Perform a flush: extract important context and write to durable storage.
    ///
    /// The `context_text` is the current conversation context that may be
    /// about to be compacted. Important information is extracted and written
    /// to the daily log and optionally to MEMORY.md.
    ///
    /// Returns a [`FlushResult`] describing what was flushed.
    pub fn flush(
        &mut self,
        context_text: &str,
        current_tokens: usize,
        max_tokens: usize,
        daily_log: &DailyLogManager,
        longterm: Option<&LongtermMemoryManager>,
    ) -> Result<FlushResult> {
        // Check threshold.
        if max_tokens > 0 {
            let usage = current_tokens as f64 / max_tokens as f64;
            if usage < self.config.flush_threshold {
                return Ok(FlushResult {
                    daily_log_entries: 0,
                    longterm_entries: 0,
                    skipped_cooldown: false,
                    skipped_below_threshold: true,
                });
            }
        }

        // Check cooldown.
        if let Some(last) = &self.last_flush {
            if last.elapsed() < Duration::from_secs(self.config.cooldown_secs) {
                return Ok(FlushResult {
                    daily_log_entries: 0,
                    longterm_entries: 0,
                    skipped_cooldown: true,
                    skipped_below_threshold: false,
                });
            }
        }

        // Extract important entries from the context.
        let extractions = MemoryCapturer::extract_from_conversation(context_text);

        let now = chrono::Utc::now();
        let timestamp = now.format("%H:%M:%S").to_string();

        let mut daily_count = 0;
        let mut longterm_count = 0;

        let limit = self.config.max_entries_per_flush.min(extractions.len());

        for entry in extractions.iter().take(limit) {
            // Write to daily log.
            let log_entry = DailyLogEntry {
                timestamp: timestamp.clone(),
                category: entry.category.as_str().to_string(),
                content: entry.value.clone(),
            };

            if daily_log.append_entry(&log_entry).is_ok() {
                daily_count += 1;
            }

            // Write to MEMORY.md if configured.
            if self.config.write_to_longterm {
                if let Some(lt) = longterm {
                    let section = category_to_section(entry.category);
                    if lt.append_to_section(section, &entry.value).unwrap_or(false) {
                        longterm_count += 1;
                    }
                }
            }
        }

        self.last_flush = Some(Instant::now());

        Ok(FlushResult {
            daily_log_entries: daily_count,
            longterm_entries: longterm_count,
            skipped_cooldown: false,
            skipped_below_threshold: false,
        })
    }

    /// Reset the cooldown timer, allowing an immediate flush.
    pub fn reset_cooldown(&mut self) {
        self.last_flush = None;
    }

    /// Return a reference to the flush configuration.
    pub fn config(&self) -> &FlushConfig {
        &self.config
    }
}

/// Map an extraction category to a MEMORY.md section name.
fn category_to_section(category: ExtractionCategory) -> &'static str {
    match category {
        ExtractionCategory::Preference => "Preferences",
        ExtractionCategory::Decision => "Decisions",
        ExtractionCategory::Fact => "Facts",
        ExtractionCategory::Instruction => "Instructions",
        ExtractionCategory::Entity => "Facts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_daily_log::DailyLogConfig;
    use crate::memory_longterm::LongtermMemoryConfig;
    use tempfile::TempDir;

    fn test_setup() -> (DailyLogManager, LongtermMemoryManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let daily_config = DailyLogConfig {
            log_dir: dir.path().join("memory"),
            retention_days: 30,
            load_recent_days: 3,
        };
        let daily = DailyLogManager::new(daily_config).unwrap();

        let longterm_config = LongtermMemoryConfig {
            file_path: dir.path().join("MEMORY.md"),
        };
        let longterm = LongtermMemoryManager::new(longterm_config);

        (daily, longterm, dir)
    }

    #[test]
    fn test_should_flush_below_threshold() {
        let flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.80,
            ..Default::default()
        });

        // 50% usage -- should not flush.
        assert!(!flusher.should_flush(5000, 10000));

        // 79% usage -- should not flush.
        assert!(!flusher.should_flush(7900, 10000));
    }

    #[test]
    fn test_should_flush_above_threshold() {
        let flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.80,
            ..Default::default()
        });

        // 80% usage -- should flush.
        assert!(flusher.should_flush(8000, 10000));

        // 95% usage -- should flush.
        assert!(flusher.should_flush(9500, 10000));
    }

    #[test]
    fn test_should_flush_zero_max() {
        let flusher = MemoryFlusher::new(Default::default());
        // Zero max tokens should never trigger.
        assert!(!flusher.should_flush(1000, 0));
    }

    #[test]
    fn test_should_flush_respects_cooldown() {
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 3600, // 1 hour cooldown
            ..Default::default()
        });

        // First check should pass.
        assert!(flusher.should_flush(8000, 10000));

        // Simulate a flush.
        flusher.last_flush = Some(Instant::now());

        // Within cooldown -- should not flush.
        assert!(!flusher.should_flush(8000, 10000));
    }

    #[test]
    fn test_flush_below_threshold_returns_skipped() {
        let (daily, longterm, _dir) = test_setup();
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.80,
            ..Default::default()
        });

        let result = flusher
            .flush("some context", 1000, 10000, &daily, Some(&longterm))
            .unwrap();

        assert!(result.skipped_below_threshold);
        assert!(!result.skipped_cooldown);
        assert_eq!(result.daily_log_entries, 0);
    }

    #[test]
    fn test_flush_within_cooldown_returns_skipped() {
        let (daily, longterm, _dir) = test_setup();
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 3600,
            ..Default::default()
        });

        // Set a recent flush time.
        flusher.last_flush = Some(Instant::now());

        let result = flusher
            .flush("some context", 8000, 10000, &daily, Some(&longterm))
            .unwrap();

        assert!(result.skipped_cooldown);
        assert!(!result.skipped_below_threshold);
        assert_eq!(result.daily_log_entries, 0);
    }

    #[test]
    fn test_flush_extracts_and_writes() {
        let (daily, longterm, _dir) = test_setup();
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 0, // no cooldown for test
            write_to_longterm: true,
            max_entries_per_flush: 10,
        });

        let context = concat!(
            "I prefer using Rust for systems programming.\n",
            "We decided to use PostgreSQL for the database.\n",
            "Remember to always run tests before committing.\n",
        );

        let result = flusher
            .flush(context, 8000, 10000, &daily, Some(&longterm))
            .unwrap();

        assert!(!result.skipped_below_threshold);
        assert!(!result.skipped_cooldown);
        assert!(
            result.daily_log_entries > 0,
            "should have written at least one daily log entry"
        );

        // Verify daily log has entries.
        let today = chrono::Utc::now().date_naive();
        let loaded = daily.load_date(today).unwrap();
        assert!(
            !loaded.is_empty(),
            "daily log should have entries after flush"
        );
    }

    #[test]
    fn test_flush_without_longterm() {
        let (daily, _longterm, _dir) = test_setup();
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 0,
            write_to_longterm: true,
            max_entries_per_flush: 10,
        });

        let context = "I prefer Rust.\n";

        // Pass None for longterm -- should still work.
        let result = flusher
            .flush(context, 8000, 10000, &daily, None)
            .unwrap();

        assert!(!result.skipped_below_threshold);
        assert_eq!(result.longterm_entries, 0);
    }

    #[test]
    fn test_flush_respects_max_entries() {
        let (daily, _longterm, _dir) = test_setup();
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 0,
            write_to_longterm: false,
            max_entries_per_flush: 1,
        });

        let context = concat!(
            "I prefer Rust.\n",
            "I prefer Go.\n",
            "I prefer Python.\n",
            "I prefer Java.\n",
        );

        let result = flusher.flush(context, 8000, 10000, &daily, None).unwrap();

        assert!(
            result.daily_log_entries <= 1,
            "should respect max_entries_per_flush=1, got {}",
            result.daily_log_entries
        );
    }

    #[test]
    fn test_reset_cooldown() {
        let mut flusher = MemoryFlusher::new(FlushConfig {
            flush_threshold: 0.50,
            cooldown_secs: 3600,
            ..Default::default()
        });

        flusher.last_flush = Some(Instant::now());
        assert!(!flusher.should_flush(8000, 10000));

        flusher.reset_cooldown();
        assert!(flusher.should_flush(8000, 10000));
    }

    #[test]
    fn test_category_to_section_mapping() {
        assert_eq!(
            category_to_section(ExtractionCategory::Preference),
            "Preferences"
        );
        assert_eq!(
            category_to_section(ExtractionCategory::Decision),
            "Decisions"
        );
        assert_eq!(category_to_section(ExtractionCategory::Fact), "Facts");
        assert_eq!(
            category_to_section(ExtractionCategory::Instruction),
            "Instructions"
        );
        assert_eq!(category_to_section(ExtractionCategory::Entity), "Facts");
    }

    #[test]
    fn test_config_defaults() {
        let config = FlushConfig::default();
        assert!((config.flush_threshold - 0.80).abs() < f64::EPSILON);
        assert_eq!(config.cooldown_secs, 60);
        assert!(config.write_to_longterm);
        assert_eq!(config.max_entries_per_flush, 10);
    }
}
