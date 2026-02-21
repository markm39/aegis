//! Content sanitization for external/untrusted text.
//!
//! Detects and redacts sensitive patterns (API keys, PII, credentials)
//! from text before it enters audit logs or response payloads.

use regex::Regex;

/// Result of sanitizing a text string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeResult {
    /// The text with sensitive content redacted.
    pub clean_text: String,
    /// Number of individual redactions made.
    pub redacted_count: usize,
    /// Names of patterns that matched (deduplicated).
    pub patterns_matched: Vec<String>,
}

/// Sanitizes text by detecting and redacting sensitive patterns.
///
/// Uses a configurable set of regex patterns to find and replace
/// sensitive data (API keys, PII, credentials) with redaction markers.
pub struct ContentSanitizer {
    patterns: Vec<(String, Regex)>,
}

impl ContentSanitizer {
    /// Create a sanitizer with the default built-in patterns.
    pub fn new() -> Self {
        let defaults = default_patterns();
        let patterns = defaults
            .into_iter()
            .filter_map(|(name, pat)| {
                Regex::new(&pat).ok().map(|re| (name.to_string(), re))
            })
            .collect();
        Self { patterns }
    }

    /// Create a sanitizer with custom patterns.
    ///
    /// Each entry is `(pattern_name, regex_string)`. Returns an error
    /// if any regex fails to compile.
    pub fn with_patterns(patterns: Vec<(String, String)>) -> Result<Self, String> {
        let compiled: Result<Vec<_>, _> = patterns
            .into_iter()
            .map(|(name, pat)| {
                Regex::new(&pat)
                    .map(|re| (name.clone(), re))
                    .map_err(|e| format!("invalid regex for pattern '{name}': {e}"))
            })
            .collect();
        Ok(Self {
            patterns: compiled?,
        })
    }

    /// Sanitize text by replacing all matches with `[REDACTED:{pattern_name}]`.
    pub fn sanitize(&self, text: &str) -> SanitizeResult {
        let mut result = text.to_string();
        let mut redacted_count = 0usize;
        let mut patterns_matched = Vec::new();

        for (name, re) in &self.patterns {
            let count_before = redacted_count;
            let replacement = format!("[REDACTED:{name}]");
            let new_result = re.replace_all(&result, replacement.as_str());
            // Count replacements by checking how many times the replacement appears
            // that weren't there before.
            let occurrences = new_result.matches(&replacement).count();
            let prior_occurrences = result.matches(&replacement).count();
            let new_matches = occurrences.saturating_sub(prior_occurrences);
            redacted_count += new_matches;
            if (new_matches > 0 || redacted_count > count_before)
                && !patterns_matched.contains(name)
            {
                patterns_matched.push(name.clone());
            }
            result = new_result.into_owned();
        }

        SanitizeResult {
            clean_text: result,
            redacted_count,
            patterns_matched,
        }
    }

    /// Quick check whether the text contains any sensitive content.
    ///
    /// More efficient than `sanitize()` when you only need a boolean answer,
    /// since it stops at the first match.
    pub fn is_sensitive(&self, text: &str) -> bool {
        self.patterns.iter().any(|(_, re)| re.is_match(text))
    }
}

impl Default for ContentSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in deny patterns for common secret and PII formats.
fn default_patterns() -> Vec<(&'static str, String)> {
    vec![
        ("anthropic_key", r"sk-ant-[a-zA-Z0-9\-_]{20,}".into()),
        ("openai_key", r"sk-[a-zA-Z0-9]{20,}".into()),
        ("github_token", r"ghp_[a-zA-Z0-9]{36}".into()),
        ("github_pat", r"github_pat_[a-zA-Z0-9_]{22,}".into()),
        ("aws_access_key", r"AKIA[0-9A-Z]{16}".into()),
        (
            "aws_secret_key",
            r"(?i)secret[_\s]*[:=]?\s*[a-zA-Z0-9/+]{40}".into(),
        ),
        (
            "generic_api_key",
            r#"(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?"#.into(),
        ),
        (
            "email",
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}".into(),
        ),
        ("phone_us", r"\b\d{3}[\-.\s]?\d{3}[\-.\s]?\d{4}\b".into()),
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b".into()),
        (
            "private_key",
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----".into(),
        ),
        (
            "jwt",
            r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+".into(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitizer() -> ContentSanitizer {
        ContentSanitizer::new()
    }

    #[test]
    fn detects_anthropic_key() {
        let s = sanitizer();
        let text = "key: sk-ant-abcdefghijklmnopqrst1234";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:anthropic_key]"));
        assert!(!result.clean_text.contains("sk-ant-"));
        assert!(result.patterns_matched.contains(&"anthropic_key".into()));
    }

    #[test]
    fn detects_openai_key() {
        let s = sanitizer();
        let text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:openai_key]"));
    }

    #[test]
    fn detects_github_token() {
        let s = sanitizer();
        let text = "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:github_token]"));
    }

    #[test]
    fn detects_github_pat() {
        let s = sanitizer();
        let text = "pat: github_pat_abcdefghijklmnopqrstuv";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:github_pat]"));
    }

    #[test]
    fn detects_aws_access_key() {
        let s = sanitizer();
        let text = "aws_key: AKIAIOSFODNN7EXAMPLE";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:aws_access_key]"));
    }

    #[test]
    fn detects_aws_secret_key_with_context() {
        let s = sanitizer();
        let text = "secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:aws_secret_key]"));
    }

    #[test]
    fn detects_generic_api_key() {
        let s = sanitizer();
        let text = "api_key = \"abcdef1234567890abcd\"";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:generic_api_key]"));
    }

    #[test]
    fn detects_email() {
        let s = sanitizer();
        let text = "contact: user@example.com for info";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:email]"));
        assert!(!result.clean_text.contains("user@example.com"));
    }

    #[test]
    fn detects_us_phone() {
        let s = sanitizer();
        let text = "Call me at 555-123-4567 please";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:phone_us]"));
    }

    #[test]
    fn detects_ssn() {
        let s = sanitizer();
        let text = "SSN: 123-45-6789";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:ssn]"));
    }

    #[test]
    fn detects_private_key() {
        let s = sanitizer();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:private_key]"));
    }

    #[test]
    fn detects_jwt() {
        let s = sanitizer();
        let text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 1);
        assert!(result.clean_text.contains("[REDACTED:jwt]"));
    }

    #[test]
    fn no_false_positives_on_normal_text() {
        let s = sanitizer();
        let text = "Hello world, this is a normal message with no secrets. The score is 42.";
        let result = s.sanitize(text);
        assert_eq!(result.redacted_count, 0);
        assert!(result.patterns_matched.is_empty());
        assert_eq!(result.clean_text, text);
    }

    #[test]
    fn mixed_content_multiple_patterns() {
        let s = sanitizer();
        let text = "key=sk-ant-abcdefghijklmnopqrst1234 email: admin@secret.org call 555-123-4567";
        let result = s.sanitize(text);
        assert!(result.redacted_count >= 3);
        assert!(result.clean_text.contains("[REDACTED:anthropic_key]"));
        assert!(result.clean_text.contains("[REDACTED:email]"));
        assert!(result.clean_text.contains("[REDACTED:phone_us]"));
    }

    #[test]
    fn custom_patterns() {
        let custom = vec![("my_secret".into(), r"SECRET_\d{4}".into())];
        let s = ContentSanitizer::with_patterns(custom).unwrap();
        let result = s.sanitize("the code is SECRET_1234 ok");
        assert_eq!(result.redacted_count, 1);
        assert!(result.clean_text.contains("[REDACTED:my_secret]"));
    }

    #[test]
    fn invalid_custom_pattern_returns_error() {
        let bad = vec![("bad".into(), r"[invalid".into())];
        assert!(ContentSanitizer::with_patterns(bad).is_err());
    }

    #[test]
    fn is_sensitive_quick_check() {
        let s = sanitizer();
        assert!(s.is_sensitive("key: sk-ant-abcdefghijklmnopqrst1234"));
        assert!(!s.is_sensitive("Hello world, nothing sensitive here."));
    }

    #[test]
    fn performance_10kb_text() {
        let s = sanitizer();
        let text = "a".repeat(10_000);
        let start = std::time::Instant::now();
        let result = s.sanitize(&text);
        let elapsed = start.elapsed();
        assert_eq!(result.redacted_count, 0);
        // Should complete well under 1 second for 10KB of clean text
        assert!(elapsed.as_millis() < 1000, "took too long: {elapsed:?}");
    }

    #[test]
    fn empty_text() {
        let s = sanitizer();
        let result = s.sanitize("");
        assert_eq!(result.redacted_count, 0);
        assert!(result.patterns_matched.is_empty());
        assert_eq!(result.clean_text, "");
    }
}
