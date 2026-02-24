//! Pattern-based PII redaction for audit log entries.
//!
//! When enabled, the [`PiiRedactor`] applies regex-based replacements to
//! text fields before they are stored in the audit ledger. Built-in
//! patterns cover common PII types (email, phone, IPv4/IPv6); custom
//! patterns can be added via configuration.

use regex::Regex;

/// A compiled redaction rule.
struct RedactionRule {
    pattern: Regex,
    replacement: String,
}

/// PII redactor that applies pattern-based replacements.
pub struct PiiRedactor {
    rules: Vec<RedactionRule>,
    enabled: bool,
}

impl PiiRedactor {
    /// Create a new redactor with the built-in patterns.
    ///
    /// If `enabled` is false, `redact()` returns the input unchanged.
    pub fn new(enabled: bool) -> Self {
        let mut rules = Vec::new();

        if enabled {
            // Email addresses: user@domain.tld
            if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
                rules.push(RedactionRule {
                    pattern: re,
                    replacement: "[EMAIL]".to_string(),
                });
            }

            // Phone numbers: +1-234-567-8900, (234) 567-8900, 234.567.8900, etc.
            if let Ok(re) =
                Regex::new(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
            {
                rules.push(RedactionRule {
                    pattern: re,
                    replacement: "[PHONE]".to_string(),
                });
            }

            // IPv4 addresses.
            if let Ok(re) = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") {
                rules.push(RedactionRule {
                    pattern: re,
                    replacement: "[IP]".to_string(),
                });
            }

            // IPv6 addresses (simplified: 4+ colon-separated hex groups).
            if let Ok(re) = Regex::new(r"\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){3,7}\b") {
                rules.push(RedactionRule {
                    pattern: re,
                    replacement: "[IP]".to_string(),
                });
            }
        }

        Self { rules, enabled }
    }

    /// Add a custom redaction pattern.
    ///
    /// Returns an error if the regex is invalid.
    pub fn add_pattern(&mut self, pattern: &str, replacement: &str) -> Result<(), String> {
        let re = Regex::new(pattern).map_err(|e| format!("invalid redaction pattern: {e}"))?;
        self.rules.push(RedactionRule {
            pattern: re,
            replacement: replacement.to_string(),
        });
        Ok(())
    }

    /// Build a [`PiiRedactor`] from a [`RedactionConfig`].
    ///
    /// Compiles the built-in patterns (when `config.enabled` is true) and
    /// all custom patterns.  Returns an error if any custom pattern
    /// contains an invalid regex.
    pub fn from_config(config: &aegis_types::config::RedactionConfig) -> Result<Self, String> {
        let mut redactor = Self::new(config.enabled);
        for pat in &config.custom_patterns {
            redactor.add_pattern(&pat.pattern, &pat.replacement)?;
        }
        Ok(redactor)
    }

    /// Apply all redaction rules to the input text.
    ///
    /// Returns the input unchanged if redaction is disabled.
    pub fn redact(&self, input: &str) -> String {
        if !self.enabled || self.rules.is_empty() {
            return input.to_string();
        }

        let mut result = input.to_string();
        for rule in &self.rules {
            result = rule
                .pattern
                .replace_all(&result, rule.replacement.as_str())
                .to_string();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_redactor_passes_through() {
        let redactor = PiiRedactor::new(false);
        let input = "contact user@example.com for details";
        assert_eq!(redactor.redact(input), input);
    }

    #[test]
    fn redacts_email_addresses() {
        let redactor = PiiRedactor::new(true);
        assert_eq!(
            redactor.redact("email is user@example.com ok?"),
            "email is [EMAIL] ok?"
        );
        assert_eq!(
            redactor.redact("two: a@b.io and c@d.org"),
            "two: [EMAIL] and [EMAIL]"
        );
    }

    #[test]
    fn redacts_phone_numbers() {
        let redactor = PiiRedactor::new(true);
        assert_eq!(
            redactor.redact("call +1-555-123-4567 now"),
            "call [PHONE] now"
        );
        assert_eq!(redactor.redact("fax (555) 123-4567"), "fax [PHONE]");
    }

    #[test]
    fn redacts_ipv4_addresses() {
        let redactor = PiiRedactor::new(true);
        assert_eq!(
            redactor.redact("from 192.168.1.100 to 10.0.0.1"),
            "from [IP] to [IP]"
        );
    }

    #[test]
    fn custom_pattern_works() {
        let mut redactor = PiiRedactor::new(true);
        redactor
            .add_pattern(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]")
            .unwrap();
        assert_eq!(redactor.redact("ssn is 123-45-6789"), "ssn is [SSN]");
    }

    #[test]
    fn invalid_custom_pattern_returns_error() {
        let mut redactor = PiiRedactor::new(true);
        assert!(redactor.add_pattern("[invalid", "[BAD]").is_err());
    }

    #[test]
    fn no_pii_unchanged() {
        let redactor = PiiRedactor::new(true);
        let input = "FileWrite /tmp/output.txt";
        assert_eq!(redactor.redact(input), input);
    }

    #[test]
    fn from_config_with_custom_patterns() {
        use aegis_types::config::{RedactionConfig, RedactionPattern};
        let config = RedactionConfig {
            enabled: true,
            custom_patterns: vec![RedactionPattern {
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                replacement: "[SSN]".to_string(),
            }],
        };
        let redactor = PiiRedactor::from_config(&config).unwrap();
        assert_eq!(redactor.redact("ssn is 123-45-6789"), "ssn is [SSN]");
        assert_eq!(
            redactor.redact("email user@example.com"),
            "email [EMAIL]"
        );
    }

    #[test]
    fn from_config_disabled() {
        let config = aegis_types::config::RedactionConfig::default();
        let redactor = PiiRedactor::from_config(&config).unwrap();
        assert_eq!(redactor.redact("user@example.com"), "user@example.com");
    }

    #[test]
    fn from_config_rejects_bad_regex() {
        use aegis_types::config::{RedactionConfig, RedactionPattern};
        let config = RedactionConfig {
            enabled: true,
            custom_patterns: vec![RedactionPattern {
                pattern: "[invalid".to_string(),
                replacement: "[BAD]".to_string(),
            }],
        };
        assert!(PiiRedactor::from_config(&config).is_err());
    }
}
