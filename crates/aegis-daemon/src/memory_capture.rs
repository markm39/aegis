//! Automatic memory capture from agent conversations.
//!
//! Extracts structured information (preferences, decisions, facts, entities,
//! instructions) from conversation text using keyword/pattern-based heuristics
//! and stores them in the [`MemoryStore`].
//!
//! ## Security
//!
//! - All extracted content is sanitized: control characters stripped, length
//!   capped at [`MAX_CONTENT_LENGTH`] bytes.
//! - Rate limiting prevents runaway extraction from flooding the store.
//! - Path traversal sequences (`../`, `..\\`) are rejected in keys and values.
//! - Namespace format is strictly `{agent_id}:{category}` to prevent
//!   cross-agent contamination.

use crate::memory::MemoryStore;
use aegis_types::daemon::AutoCaptureConfig;

/// Maximum length (in characters) for any extracted content value.
const MAX_CONTENT_LENGTH: usize = 4096;

/// Categories of information that can be extracted from conversation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtractionCategory {
    /// User preference ("I prefer", "I like", "I always").
    Preference,
    /// A decision made ("decided to", "going with", "chose").
    Decision,
    /// A factual statement ("is located at", "the answer is", "it means").
    Fact,
    /// A named entity: proper noun, email address, or URL.
    Entity,
    /// An instruction or rule ("remember to", "always do", "never").
    Instruction,
}

impl ExtractionCategory {
    /// Return the string name used in namespace keys and config lists.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtractionCategory::Preference => "preference",
            ExtractionCategory::Decision => "decision",
            ExtractionCategory::Fact => "fact",
            ExtractionCategory::Entity => "entity",
            ExtractionCategory::Instruction => "instruction",
        }
    }

    /// Parse from a category string. Returns `None` for unknown categories.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "preference" => Some(ExtractionCategory::Preference),
            "decision" => Some(ExtractionCategory::Decision),
            "fact" => Some(ExtractionCategory::Fact),
            "entity" => Some(ExtractionCategory::Entity),
            "instruction" => Some(ExtractionCategory::Instruction),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExtractionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single extracted memory entry from conversation text.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionEntry {
    /// The category of information extracted.
    pub category: ExtractionCategory,
    /// A short identifier for this piece of information.
    pub key: String,
    /// The extracted content value.
    pub value: String,
    /// Confidence score in the range [0.0, 1.0].
    pub confidence: f32,
}

/// Automatic memory capturer that extracts and stores information
/// from agent conversation text.
pub struct MemoryCapturer {
    config: AutoCaptureConfig,
    /// Number of writes performed in the current session/turn.
    writes_this_turn: usize,
}

impl MemoryCapturer {
    /// Create a new capturer from the given configuration.
    pub fn new(config: AutoCaptureConfig) -> Self {
        Self {
            config,
            writes_this_turn: 0,
        }
    }

    /// Reset the per-turn write counter. Call this at the start of each turn.
    pub fn reset_turn_counter(&mut self) {
        self.writes_this_turn = 0;
    }

    /// Extract structured entries from conversation text using pattern matching.
    ///
    /// Returns all entries that match configured categories, regardless of
    /// confidence threshold. Use [`Self::extract_filtered`] to get only
    /// entries above the confidence threshold.
    pub fn extract_from_conversation(text: &str) -> Vec<ExtractionEntry> {
        let mut entries = Vec::new();

        // Process each line independently to get better key/value separation.
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Preference patterns: "I prefer", "I like", "I always"
            Self::extract_preference(trimmed, &mut entries);

            // Decision patterns: "decided to", "going with", "chose"
            Self::extract_decision(trimmed, &mut entries);

            // Fact patterns: "is located at", "the answer is", "it means"
            Self::extract_fact(trimmed, &mut entries);

            // Entity patterns: emails, URLs
            Self::extract_entity(trimmed, &mut entries);

            // Instruction patterns: "remember to", "always do", "never"
            Self::extract_instruction(trimmed, &mut entries);
        }

        entries
    }

    /// Extract entries filtered by confidence threshold and configured categories.
    pub fn extract_filtered(&self, text: &str) -> Vec<ExtractionEntry> {
        if !self.config.enabled {
            return Vec::new();
        }

        let entries = Self::extract_from_conversation(text);

        entries
            .into_iter()
            .filter(|e| e.confidence >= self.config.confidence_threshold)
            .filter(|e| self.config.categories.contains(&e.category.as_str().to_string()))
            .take(self.config.max_per_turn)
            .collect()
    }

    /// Store extracted entries in the memory store.
    ///
    /// Applies rate limiting, sanitization, and security checks before writing.
    /// Returns the number of entries successfully stored.
    pub fn store_extractions(
        &mut self,
        store: &MemoryStore,
        agent_id: &str,
        entries: &[ExtractionEntry],
    ) -> usize {
        let mut stored = 0;

        for entry in entries {
            // Rate limit check.
            if self.writes_this_turn >= self.config.max_per_turn {
                break;
            }

            let sanitized_key = sanitize_content(&entry.key);
            let sanitized_value = sanitize_content(&entry.value);

            // Security: reject path traversal in keys and values.
            if contains_path_traversal(&sanitized_key) || contains_path_traversal(&sanitized_value)
            {
                continue;
            }

            // Security: reject empty keys after sanitization.
            if sanitized_key.is_empty() {
                continue;
            }

            let namespace = format!("{}:{}", agent_id, entry.category.as_str());

            if store.set(&namespace, &sanitized_key, &sanitized_value).is_ok() {
                self.writes_this_turn += 1;
                stored += 1;
            }
        }

        stored
    }

    // -- Private extraction helpers --

    fn extract_preference(line: &str, entries: &mut Vec<ExtractionEntry>) {
        let lower = line.to_lowercase();
        let patterns: &[(&str, f32)] = &[
            ("i prefer ", 0.85),
            ("i like ", 0.75),
            ("i always ", 0.80),
            ("my preference is ", 0.90),
        ];

        for &(pattern, confidence) in patterns {
            if let Some(pos) = lower.find(pattern) {
                let after = &line[pos + pattern.len()..];
                let value = truncate_to_sentence(after);
                if !value.is_empty() {
                    let key = generate_key(&value);
                    entries.push(ExtractionEntry {
                        category: ExtractionCategory::Preference,
                        key,
                        value: sanitize_content(&value),
                        confidence,
                    });
                }
            }
        }
    }

    fn extract_decision(line: &str, entries: &mut Vec<ExtractionEntry>) {
        let lower = line.to_lowercase();
        let patterns: &[(&str, f32)] = &[
            ("decided to ", 0.85),
            ("going with ", 0.80),
            ("chose ", 0.80),
            ("we decided ", 0.85),
        ];

        for &(pattern, confidence) in patterns {
            if let Some(pos) = lower.find(pattern) {
                let after = &line[pos + pattern.len()..];
                let value = truncate_to_sentence(after);
                if !value.is_empty() {
                    let key = generate_key(&value);
                    entries.push(ExtractionEntry {
                        category: ExtractionCategory::Decision,
                        key,
                        value: sanitize_content(&value),
                        confidence,
                    });
                }
            }
        }
    }

    fn extract_fact(line: &str, entries: &mut Vec<ExtractionEntry>) {
        let lower = line.to_lowercase();
        let patterns: &[(&str, f32)] = &[
            ("is located at ", 0.85),
            ("the answer is ", 0.80),
            ("it means ", 0.75),
            ("is defined as ", 0.85),
        ];

        for &(pattern, confidence) in patterns {
            if let Some(pos) = lower.find(pattern) {
                let after = &line[pos + pattern.len()..];
                let value = truncate_to_sentence(after);
                if !value.is_empty() {
                    // Try to use the text before the pattern as the key.
                    let before = line[..pos].trim();
                    let key = if before.is_empty() {
                        generate_key(&value)
                    } else {
                        generate_key(before)
                    };
                    entries.push(ExtractionEntry {
                        category: ExtractionCategory::Fact,
                        key,
                        value: sanitize_content(&value),
                        confidence,
                    });
                }
            }
        }
    }

    fn extract_entity(line: &str, entries: &mut Vec<ExtractionEntry>) {
        // Email pattern: simple heuristic, not a full RFC 5322 parser.
        for word in line.split_whitespace() {
            let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_' && c != '+');
            if is_email_like(clean) {
                entries.push(ExtractionEntry {
                    category: ExtractionCategory::Entity,
                    key: format!("email_{}", clean.split('@').next().unwrap_or("unknown")),
                    value: sanitize_content(clean),
                    confidence: 0.90,
                });
            } else if is_url_like(clean) {
                entries.push(ExtractionEntry {
                    category: ExtractionCategory::Entity,
                    key: format!("url_{}", generate_key(clean)),
                    value: sanitize_content(clean),
                    confidence: 0.85,
                });
            }
        }
    }

    fn extract_instruction(line: &str, entries: &mut Vec<ExtractionEntry>) {
        let lower = line.to_lowercase();
        let patterns: &[(&str, f32)] = &[
            ("remember to ", 0.85),
            ("always do ", 0.80),
            ("never ", 0.80),
            ("make sure to ", 0.80),
            ("don't forget to ", 0.85),
        ];

        for &(pattern, confidence) in patterns {
            if let Some(pos) = lower.find(pattern) {
                let after = &line[pos + pattern.len()..];
                let value = truncate_to_sentence(after);
                if !value.is_empty() {
                    let key = generate_key(&value);
                    entries.push(ExtractionEntry {
                        category: ExtractionCategory::Instruction,
                        key,
                        value: sanitize_content(&format!("{}{}", pattern, value)),
                        confidence,
                    });
                }
            }
        }
    }
}

// -- Utility functions --

/// Sanitize content by stripping control characters and truncating to max length.
fn sanitize_content(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(MAX_CONTENT_LENGTH)
        .collect();
    cleaned
}

/// Check for path traversal sequences.
fn contains_path_traversal(input: &str) -> bool {
    input.contains("../") || input.contains("..\\")
}

/// Check if a string looks like an email address.
fn is_email_like(s: &str) -> bool {
    let at_pos = match s.find('@') {
        Some(p) => p,
        None => return false,
    };
    // Must have something before and after @.
    if at_pos == 0 || at_pos >= s.len() - 1 {
        return false;
    }
    // Must have a dot after @.
    let domain = &s[at_pos + 1..];
    let dot_pos = match domain.find('.') {
        Some(p) => p,
        None => return false,
    };
    // Domain part after dot must have at least 2 chars.
    dot_pos > 0 && domain.len() - dot_pos > 2
}

/// Check if a string looks like a URL.
fn is_url_like(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

/// Truncate a string at the first sentence boundary (period, exclamation, question mark,
/// newline) or at MAX_CONTENT_LENGTH, whichever comes first.
fn truncate_to_sentence(s: &str) -> String {
    let trimmed = s.trim();
    // Find the first sentence-ending punctuation.
    let end = trimmed
        .find(['.', '!', '?', '\n'])
        .map(|pos| pos + 1) // Include the punctuation.
        .unwrap_or(trimmed.len());

    let result = &trimmed[..end];
    if result.len() > MAX_CONTENT_LENGTH {
        result[..MAX_CONTENT_LENGTH].to_string()
    } else {
        result.to_string()
    }
}

/// Generate a short, sanitized key from a value string.
///
/// Takes the first few significant words, lowercases them, and joins with underscores.
fn generate_key(value: &str) -> String {
    let key: String = value
        .split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join("_")
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect();

    if key.is_empty() {
        "unknown".to_string()
    } else {
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (MemoryStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        (store, dir)
    }

    fn enabled_config() -> AutoCaptureConfig {
        AutoCaptureConfig {
            enabled: true,
            categories: vec![
                "preference".into(),
                "decision".into(),
                "fact".into(),
                "entity".into(),
                "instruction".into(),
            ],
            confidence_threshold: 0.7,
            max_per_turn: 5,
        }
    }

    fn disabled_config() -> AutoCaptureConfig {
        AutoCaptureConfig {
            enabled: false,
            ..Default::default()
        }
    }

    // -- test_extraction_prompt_parsing --

    #[test]
    fn test_extraction_prompt_parsing() {
        let text = concat!(
            "I prefer using Rust for systems programming.\n",
            "We decided to use PostgreSQL for the database.\n",
            "The server is located at 192.168.1.100.\n",
            "Contact us at admin@example.com for support.\n",
            "Remember to always run tests before committing.\n",
        );

        let entries = MemoryCapturer::extract_from_conversation(text);

        // Should extract at least one entry per category present.
        let has_preference = entries.iter().any(|e| e.category == ExtractionCategory::Preference);
        let has_decision = entries.iter().any(|e| e.category == ExtractionCategory::Decision);
        let has_fact = entries.iter().any(|e| e.category == ExtractionCategory::Fact);
        let has_entity = entries.iter().any(|e| e.category == ExtractionCategory::Entity);
        let has_instruction = entries.iter().any(|e| e.category == ExtractionCategory::Instruction);

        assert!(has_preference, "should extract a preference from 'I prefer'");
        assert!(has_decision, "should extract a decision from 'decided to'");
        assert!(has_fact, "should extract a fact from 'is located at'");
        assert!(has_entity, "should extract an entity from email address");
        assert!(has_instruction, "should extract an instruction from 'Remember to'");

        // Verify content is sane.
        let pref = entries.iter().find(|e| e.category == ExtractionCategory::Preference).unwrap();
        assert!(
            pref.value.contains("Rust") || pref.value.contains("rust"),
            "preference should mention Rust, got: {}",
            pref.value
        );
    }

    // -- test_confidence_filtering --

    #[test]
    fn test_confidence_filtering() {
        let text = "I prefer tabs over spaces.\nI like dark themes.";

        // With high threshold, only strong matches survive.
        let config = AutoCaptureConfig {
            enabled: true,
            confidence_threshold: 0.80,
            ..enabled_config()
        };
        let capturer = MemoryCapturer::new(config);
        let filtered = capturer.extract_filtered(text);

        // "I prefer" has confidence 0.85, "I like" has 0.75 -- only "I prefer" should survive.
        assert!(
            filtered.iter().all(|e| e.confidence >= 0.80),
            "all entries must be at or above threshold 0.80"
        );

        // With threshold of 0.70, both should be included.
        let config_low = AutoCaptureConfig {
            enabled: true,
            confidence_threshold: 0.70,
            ..enabled_config()
        };
        let capturer_low = MemoryCapturer::new(config_low);
        let filtered_low = capturer_low.extract_filtered(text);
        assert!(
            filtered_low.len() >= 2,
            "lower threshold should allow more entries, got {}",
            filtered_low.len()
        );
    }

    // -- test_category_namespace_mapping --

    #[test]
    fn test_category_namespace_mapping() {
        let (store, _dir) = test_store();
        let mut capturer = MemoryCapturer::new(enabled_config());

        let entries = vec![
            ExtractionEntry {
                category: ExtractionCategory::Preference,
                key: "editor".into(),
                value: "vim".into(),
                confidence: 0.9,
            },
            ExtractionEntry {
                category: ExtractionCategory::Decision,
                key: "database".into(),
                value: "postgres".into(),
                confidence: 0.85,
            },
        ];

        let stored = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored, 2);

        // Verify namespace format: "{agent_id}:{category}"
        let pref_val = store.get("agent-1:preference", "editor").unwrap();
        assert_eq!(pref_val, Some("vim".into()));

        let dec_val = store.get("agent-1:decision", "database").unwrap();
        assert_eq!(dec_val, Some("postgres".into()));

        // Wrong namespace should return None.
        let wrong_ns = store.get("agent-1:fact", "editor").unwrap();
        assert_eq!(wrong_ns, None);
    }

    // -- test_rate_limiting_per_session --

    #[test]
    fn test_rate_limiting_per_session() {
        let (store, _dir) = test_store();
        let config = AutoCaptureConfig {
            enabled: true,
            max_per_turn: 2,
            ..enabled_config()
        };
        let mut capturer = MemoryCapturer::new(config);

        let entries: Vec<ExtractionEntry> = (0..5)
            .map(|i| ExtractionEntry {
                category: ExtractionCategory::Fact,
                key: format!("fact_{i}"),
                value: format!("value {i}"),
                confidence: 0.9,
            })
            .collect();

        let stored = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored, 2, "should be capped at max_per_turn=2");

        // Attempting to store more should be rejected.
        let stored2 = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored2, 0, "further writes should be blocked by rate limit");

        // After reset, writing should work again.
        capturer.reset_turn_counter();
        let stored3 = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored3, 2, "after reset, should allow max_per_turn writes again");
    }

    // -- test_sanitization_of_extracted_content --

    #[test]
    fn test_sanitization_of_extracted_content() {
        // Test that control characters are stripped.
        let dirty = "hello\x00world\x07\x1b[31mred\x1b[0m text\ttab\nnewline";
        let clean = sanitize_content(dirty);

        // Null and bell should be gone.
        assert!(!clean.contains('\x00'), "null byte should be stripped");
        assert!(!clean.contains('\x07'), "bell should be stripped");

        // Tab and newline preserved.
        assert!(clean.contains('\t'), "tab should be preserved");
        assert!(clean.contains('\n'), "newline should be preserved");

        // ANSI escape should be stripped (it is a control char).
        assert!(!clean.contains('\x1b'), "ANSI escape should be stripped");

        // Test length truncation.
        let long_input: String = "x".repeat(MAX_CONTENT_LENGTH + 100);
        let truncated = sanitize_content(&long_input);
        assert_eq!(
            truncated.len(),
            MAX_CONTENT_LENGTH,
            "content should be truncated to MAX_CONTENT_LENGTH"
        );
    }

    // -- test_auto_capture_disabled --

    #[test]
    fn test_auto_capture_disabled() {
        let capturer = MemoryCapturer::new(disabled_config());
        let text = "I prefer using Rust. Remember to run tests.";
        let entries = capturer.extract_filtered(text);
        assert!(entries.is_empty(), "disabled capturer should return empty vec");
    }

    // -- Security test: injection/traversal --

    #[test]
    fn test_path_traversal_rejected() {
        let (store, _dir) = test_store();
        let mut capturer = MemoryCapturer::new(enabled_config());

        let entries = vec![
            ExtractionEntry {
                category: ExtractionCategory::Fact,
                key: "../../../etc/passwd".into(),
                value: "root:x:0:0".into(),
                confidence: 0.9,
            },
            ExtractionEntry {
                category: ExtractionCategory::Fact,
                key: "safe_key".into(),
                value: "content with ../../../etc/shadow traversal".into(),
                confidence: 0.9,
            },
            ExtractionEntry {
                category: ExtractionCategory::Fact,
                key: "..\\windows\\system32".into(),
                value: "cmd.exe".into(),
                confidence: 0.9,
            },
        ];

        let stored = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored, 0, "path traversal entries should be rejected");
    }

    #[test]
    fn test_empty_key_rejected() {
        let (store, _dir) = test_store();
        let mut capturer = MemoryCapturer::new(enabled_config());

        let entries = vec![ExtractionEntry {
            category: ExtractionCategory::Fact,
            key: "\x00\x01\x02".into(), // All control chars -> empty after sanitization.
            value: "some value".into(),
            confidence: 0.9,
        }];

        let stored = capturer.store_extractions(&store, "agent-1", &entries);
        assert_eq!(stored, 0, "entries with empty key after sanitization should be rejected");
    }

    #[test]
    fn test_entity_email_extraction() {
        let text = "Send it to user@example.com please.";
        let entries = MemoryCapturer::extract_from_conversation(text);

        let email_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.category == ExtractionCategory::Entity)
            .collect();

        assert!(!email_entries.is_empty(), "should extract email entity");
        assert!(
            email_entries[0].value.contains("user@example.com"),
            "entity value should contain the email"
        );
    }

    #[test]
    fn test_entity_url_extraction() {
        let text = "Check out https://example.com/docs for more info.";
        let entries = MemoryCapturer::extract_from_conversation(text);

        let url_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.category == ExtractionCategory::Entity)
            .collect();

        assert!(!url_entries.is_empty(), "should extract URL entity");
        assert!(
            url_entries[0].value.contains("https://example.com/docs"),
            "entity value should contain the URL"
        );
    }

    #[test]
    fn test_category_filtering() {
        let text = "I prefer Rust. Remember to test.";

        let config = AutoCaptureConfig {
            enabled: true,
            categories: vec!["preference".into()], // Only preferences.
            confidence_threshold: 0.7,
            max_per_turn: 5,
        };
        let capturer = MemoryCapturer::new(config);
        let entries = capturer.extract_filtered(text);

        for entry in &entries {
            assert_eq!(
                entry.category,
                ExtractionCategory::Preference,
                "should only return preference entries when category filter is set"
            );
        }
    }

    #[test]
    fn test_extract_filtered_respects_max_per_turn() {
        // Create text with many extractable entries.
        let text = concat!(
            "I prefer Rust.\n",
            "I like Python.\n",
            "I prefer Go.\n",
            "I prefer Java.\n",
            "I prefer C++.\n",
            "I prefer TypeScript.\n",
            "I prefer Haskell.\n",
        );

        let config = AutoCaptureConfig {
            enabled: true,
            confidence_threshold: 0.0, // Accept everything.
            max_per_turn: 3,
            ..enabled_config()
        };
        let capturer = MemoryCapturer::new(config);
        let entries = capturer.extract_filtered(text);

        assert!(
            entries.len() <= 3,
            "extract_filtered should cap at max_per_turn=3, got {}",
            entries.len()
        );
    }

    #[test]
    fn test_confidence_score_range() {
        let text = concat!(
            "I prefer Rust.\n",
            "I like dark mode.\n",
            "I always use vim.\n",
            "We decided to use Postgres.\n",
            "The server is located at 10.0.0.1.\n",
            "Contact admin@test.com.\n",
            "Remember to backup daily.\n",
        );

        let entries = MemoryCapturer::extract_from_conversation(text);

        for entry in &entries {
            assert!(
                (0.0..=1.0).contains(&entry.confidence),
                "confidence must be in [0.0, 1.0], got {} for {:?}",
                entry.confidence,
                entry.category,
            );
        }
    }
}
