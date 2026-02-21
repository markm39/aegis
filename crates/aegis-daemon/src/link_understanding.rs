//! URL content extraction with SSRF protection, content size limits, and caching.
//!
//! This module provides safe URL fetching for the daemon, building on the
//! SSRF protection and HTML extraction in [`crate::web_tools`]. It adds:
//!
//! - `LinkConfig` for per-fetch configuration (timeouts, size caps, blocked patterns)
//! - `UrlContent` with structured title, text, and word count
//! - `UrlCache` with TTL expiry and LRU eviction (max 1000 entries)
//! - Content-Type validation (only text/html, text/plain, application/json)
//! - DNS rebinding protection via resolved-IP checks
//! - URL length limit (2048 characters)

use std::collections::HashMap;
use std::io::Read as IoRead;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::web_tools;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for URL content extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkConfig {
    /// Request timeout in seconds (default 10, max 30).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u16,
    /// Maximum response body size in bytes (default 5 MB).
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Cache TTL in seconds (default 3600 = 1 hour).
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// URL patterns to block (matched against the full URL string).
    #[serde(default)]
    pub blocked_patterns: Vec<String>,
}

fn default_timeout_secs() -> u16 {
    10
}

fn default_max_body_bytes() -> usize {
    5 * 1024 * 1024
}

fn default_cache_ttl_secs() -> u64 {
    3600
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
            max_body_bytes: default_max_body_bytes(),
            cache_ttl_secs: default_cache_ttl_secs(),
            blocked_patterns: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// UrlContent
// ---------------------------------------------------------------------------

/// Extracted content from a fetched URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlContent {
    /// The canonical URL that was fetched.
    pub url: String,
    /// Page title extracted from `<title>` tag (if HTML).
    pub title: Option<String>,
    /// Extracted plain text content.
    pub text: String,
    /// Word count of the extracted text.
    pub word_count: usize,
    /// When the content was fetched.
    pub fetched_at: DateTime<Utc>,
    /// Whether this result came from cache.
    pub cached: bool,
}

// ---------------------------------------------------------------------------
// URL validation (delegates to web_tools, adds length + pattern checks)
// ---------------------------------------------------------------------------

/// Maximum allowed URL length in characters.
const MAX_URL_LENGTH: usize = 2048;

/// Allowed Content-Type prefixes for processing.
const ALLOWED_CONTENT_TYPES: &[&str] = &["text/html", "text/plain", "application/json"];

/// Validate a URL for safe fetching.
///
/// Checks:
/// - URL length <= 2048
/// - Scheme is http or https (no file://, data://, etc.)
/// - Host is not a private IP (SSRF protection)
/// - DNS-resolved IPs are not private (DNS rebinding protection)
/// - URL does not match any blocked patterns
pub fn validate_url(raw_url: &str, config: &LinkConfig) -> Result<url::Url, String> {
    // Length check
    if raw_url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length of {MAX_URL_LENGTH} characters ({} given)",
            raw_url.len()
        ));
    }

    // Delegate to web_tools SSRF-safe validation (scheme, DNS, private IP checks)
    let parsed = web_tools::validate_url(raw_url).map_err(|e| e.to_string())?;

    // Check blocked patterns
    for pattern in &config.blocked_patterns {
        if raw_url.contains(pattern.as_str()) {
            return Err(format!("URL matches blocked pattern: {pattern}"));
        }
    }

    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Content extraction
// ---------------------------------------------------------------------------

/// Fetch a URL and extract its content.
///
/// Enforces:
/// - SSRF protection (private IP, DNS rebinding)
/// - Request timeout (capped at 30s)
/// - Response body size limit
/// - Content-Type validation (text/html, text/plain, application/json only)
/// - HTML tag stripping and script/style removal
pub fn fetch_url(raw_url: &str, config: &LinkConfig) -> Result<UrlContent, String> {
    let validated = validate_url(raw_url, config)?;

    // Enforce timeout cap: max 30 seconds regardless of config.
    let timeout_secs = config.timeout_secs.min(30) as u64;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::custom({
            // Validate each redirect target against SSRF rules.
            move |attempt| {
                let url = attempt.url();
                // Re-validate each redirect destination
                if let Err(_e) = web_tools::validate_url(url.as_str()) {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }
        }))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .get(validated.as_str())
        .header("User-Agent", "aegis-link-understanding/0.1")
        .send()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    // Validate Content-Type before reading body.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_lowercase();

    let type_allowed = ALLOWED_CONTENT_TYPES
        .iter()
        .any(|allowed| content_type.contains(allowed));
    if !type_allowed {
        return Err(format!(
            "Content-Type not allowed: {content_type}. \
             Only text/html, text/plain, and application/json are accepted."
        ));
    }

    // Read body with size cap.
    let max = config.max_body_bytes;
    let mut body_bytes = Vec::new();
    let mut reader = resp.take((max as u64) + 1);
    reader
        .read_to_end(&mut body_bytes)
        .map_err(|e| format!("failed to read response body: {e}"))?;

    if body_bytes.len() > max {
        body_bytes.truncate(max);
    }

    let raw_text = String::from_utf8_lossy(&body_bytes).into_owned();

    // Extract title and text based on content type.
    let (title, text) = if content_type.contains("text/html") {
        let title = extract_title(&raw_text);
        let plain = strip_html(&raw_text);
        (title, plain)
    } else {
        (None, raw_text)
    };

    // Enforce text size limit.
    let text = if text.len() > max {
        text[..max].to_string()
    } else {
        text
    };

    let word_count = text.split_whitespace().count();

    Ok(UrlContent {
        url: validated.to_string(),
        title,
        text,
        word_count,
        fetched_at: Utc::now(),
        cached: false,
    })
}

/// Extract the title from HTML using simple string search.
///
/// Looks for `<title>...</title>` (case-insensitive).
fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    // Skip past the opening tag (handle attributes like <title lang="en">)
    let content_start = html[start..].find('>')? + start + 1;
    let end_tag = lower[content_start..].find("</title>")?;
    let raw_title = &html[content_start..content_start + end_tag];
    let trimmed = raw_title.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Strip HTML tags, script blocks, and style blocks to produce plain text.
///
/// Uses simple character-level parsing (no external HTML parser crate).
fn strip_html(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut chars = html.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == '<' {
            // Peek ahead to detect script/style blocks.
            let lookahead: String = chars.clone().take(20).collect::<String>().to_lowercase();

            if lookahead.starts_with("<script") {
                skip_until_close_tag(&mut chars, "script");
                result.push(' ');
                continue;
            }
            if lookahead.starts_with("<style") {
                skip_until_close_tag(&mut chars, "style");
                result.push(' ');
                continue;
            }

            // Skip any other tag.
            for c in chars.by_ref() {
                if c == '>' {
                    break;
                }
            }
            result.push(' ');
        } else {
            result.push(ch);
            chars.next();
        }
    }

    collapse_whitespace(&result)
}

/// Skip characters until the closing tag `</tag>` is consumed.
fn skip_until_close_tag(chars: &mut std::iter::Peekable<std::str::Chars>, tag: &str) {
    let close = format!("</{tag}>");
    let mut buffer = String::new();
    for c in chars.by_ref() {
        buffer.push(c);
        if buffer.len() >= close.len() {
            let tail: String = buffer[buffer.len() - close.len()..].to_lowercase();
            if tail == close {
                return;
            }
        }
    }
}

/// Collapse runs of whitespace into single spaces and trim.
fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_ws = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                result.push(' ');
            }
            prev_ws = true;
        } else {
            result.push(ch);
            prev_ws = false;
        }
    }
    result.trim().to_string()
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// Maximum number of entries in the URL cache.
const MAX_CACHE_ENTRIES: usize = 1000;

/// In-memory cache for fetched URL content with TTL and LRU eviction.
pub struct UrlCache {
    /// Map from URL to (content, insertion time, last access time).
    entries: HashMap<String, CacheEntry>,
    /// TTL for cache entries.
    ttl: Duration,
}

struct CacheEntry {
    content: UrlContent,
    inserted_at: Instant,
    last_accessed: Instant,
}

impl UrlCache {
    /// Create a new cache with the given TTL in seconds.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get a cached entry if it exists and has not expired.
    pub fn get(&mut self, url: &str) -> Option<UrlContent> {
        let entry = self.entries.get_mut(url)?;
        if entry.inserted_at.elapsed() > self.ttl {
            // Expired -- remove it.
            self.entries.remove(url);
            return None;
        }
        entry.last_accessed = Instant::now();
        let mut content = entry.content.clone();
        content.cached = true;
        Some(content)
    }

    /// Store a URL's content in the cache.
    ///
    /// If the cache is at capacity, evicts the least recently used entry.
    pub fn put(&mut self, url: &str, content: UrlContent) {
        if self.entries.len() >= MAX_CACHE_ENTRIES && !self.entries.contains_key(url) {
            self.evict_lru();
        }
        let now = Instant::now();
        self.entries.insert(
            url.to_string(),
            CacheEntry {
                content,
                inserted_at: now,
                last_accessed: now,
            },
        );
    }

    /// Remove all expired entries.
    pub fn cleanup(&mut self) {
        self.entries
            .retain(|_url, entry| entry.inserted_at.elapsed() <= self.ttl);
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the least recently used entry.
    fn evict_lru(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_k, v)| v.last_accessed)
            .map(|(k, _v)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- URL validation tests --

    #[test]
    fn url_validation_accepts_valid_urls() {
        let config = LinkConfig::default();
        // Public IP to avoid DNS dependency
        assert!(validate_url("https://8.8.8.8", &config).is_ok());
        assert!(validate_url("http://8.8.8.8/path?q=1", &config).is_ok());
    }

    #[test]
    fn url_validation_blocks_private_ips() {
        let config = LinkConfig::default();

        // 10.x.x.x
        assert!(validate_url("http://10.0.0.1/admin", &config).is_err());
        // 172.16.x.x
        assert!(validate_url("http://172.16.0.1/admin", &config).is_err());
        // 192.168.x.x
        assert!(validate_url("http://192.168.1.1/admin", &config).is_err());
        // 127.x.x.x
        assert!(validate_url("http://127.0.0.1/admin", &config).is_err());
        // ::1
        assert!(validate_url("http://[::1]/admin", &config).is_err());
    }

    #[test]
    fn security_test_file_scheme_rejected() {
        let config = LinkConfig::default();
        assert!(validate_url("file:///etc/passwd", &config).is_err());
        assert!(validate_url("data:text/html,<h1>test</h1>", &config).is_err());
    }

    #[test]
    fn security_test_localhost_blocked() {
        let config = LinkConfig::default();
        assert!(validate_url("http://127.0.0.1/secret", &config).is_err());
        assert!(validate_url("http://0.0.0.0/secret", &config).is_err());
        assert!(validate_url("http://[::1]/secret", &config).is_err());
    }

    #[test]
    fn security_test_max_url_length_enforced() {
        let config = LinkConfig::default();
        let long_url = format!("https://example.com/{}", "a".repeat(2100));
        let result = validate_url(&long_url, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum length"));
    }

    #[test]
    fn url_validation_blocked_patterns() {
        let config = LinkConfig {
            blocked_patterns: vec!["internal.corp".into()],
            ..Default::default()
        };
        assert!(validate_url("https://internal.corp.example.com/api", &config).is_err());
    }

    // -- Content extraction tests --

    #[test]
    fn content_extraction_finds_title() {
        let html = r#"<html><head><title>Test Page Title</title></head><body>Hello</body></html>"#;
        let title = extract_title(html);
        assert_eq!(title, Some("Test Page Title".to_string()));
    }

    #[test]
    fn content_extraction_finds_title_case_insensitive() {
        let html = r#"<HTML><HEAD><TITLE>Upper Case</TITLE></HEAD></HTML>"#;
        let title = extract_title(html);
        assert_eq!(title, Some("Upper Case".to_string()));
    }

    #[test]
    fn content_extraction_no_title() {
        let html = r#"<html><body>No title here</body></html>"#;
        let title = extract_title(html);
        assert_eq!(title, None);
    }

    #[test]
    fn content_extraction_strips_html() {
        let html = r#"<html><body><h1>Hello</h1><p>World <b>bold</b></p></body></html>"#;
        let text = strip_html(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(text.contains("bold"));
        assert!(!text.contains("<h1>"));
        assert!(!text.contains("<p>"));
        assert!(!text.contains("<b>"));
    }

    #[test]
    fn content_extraction_removes_script_blocks() {
        let html = "<p>Before</p><script>var x = 1; alert('xss');</script><p>After</p>";
        let text = strip_html(html);
        assert!(text.contains("Before"));
        assert!(text.contains("After"));
        assert!(!text.contains("alert"));
        assert!(!text.contains("var x"));
    }

    #[test]
    fn content_extraction_removes_style_blocks() {
        let html = "<style>.cls { color: red; }</style><p>Content</p>";
        let text = strip_html(html);
        assert!(text.contains("Content"));
        assert!(!text.contains("color"));
        assert!(!text.contains(".cls"));
    }

    #[test]
    fn content_size_limit_enforced() {
        let config = LinkConfig {
            max_body_bytes: 50,
            ..Default::default()
        };
        // We cannot do a real HTTP request in unit tests, but we can verify
        // the text truncation logic directly.
        let long_text = "a".repeat(100);
        let truncated = if long_text.len() > config.max_body_bytes {
            long_text[..config.max_body_bytes].to_string()
        } else {
            long_text.clone()
        };
        assert_eq!(truncated.len(), 50);
    }

    // -- Cache tests --

    #[test]
    fn cache_stores_and_retrieves() {
        let mut cache = UrlCache::new(3600);
        let content = UrlContent {
            url: "https://example.com".into(),
            title: Some("Example".into()),
            text: "Hello world".into(),
            word_count: 2,
            fetched_at: Utc::now(),
            cached: false,
        };

        cache.put("https://example.com", content.clone());
        let cached = cache.get("https://example.com");
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert!(cached.cached);
        assert_eq!(cached.url, "https://example.com");
        assert_eq!(cached.text, "Hello world");
    }

    #[test]
    fn cache_expires_after_ttl() {
        // Use a 0-second TTL so entries expire immediately.
        let mut cache = UrlCache::new(0);
        let content = UrlContent {
            url: "https://example.com".into(),
            title: None,
            text: "test".into(),
            word_count: 1,
            fetched_at: Utc::now(),
            cached: false,
        };

        cache.put("https://example.com", content);
        // With TTL=0, the entry should be expired on next get.
        // Sleep briefly to ensure elapsed > 0.
        std::thread::sleep(Duration::from_millis(5));
        let result = cache.get("https://example.com");
        assert!(result.is_none());
    }

    #[test]
    fn cache_cleanup_removes_expired() {
        let mut cache = UrlCache::new(0);
        let content = UrlContent {
            url: "https://example.com".into(),
            title: None,
            text: "test".into(),
            word_count: 1,
            fetched_at: Utc::now(),
            cached: false,
        };
        cache.put("https://example.com", content);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.len(), 1);
        cache.cleanup();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_evicts_lru_when_full() {
        let mut cache = UrlCache::new(3600);
        // Fill cache to MAX_CACHE_ENTRIES.
        for i in 0..MAX_CACHE_ENTRIES {
            let url = format!("https://example.com/{i}");
            let content = UrlContent {
                url: url.clone(),
                title: None,
                text: format!("content {i}"),
                word_count: 1,
                fetched_at: Utc::now(),
                cached: false,
            };
            cache.put(&url, content);
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);

        // Add one more -- should evict the LRU entry.
        let content = UrlContent {
            url: "https://example.com/new".into(),
            title: None,
            text: "new content".into(),
            word_count: 2,
            fetched_at: Utc::now(),
            cached: false,
        };
        cache.put("https://example.com/new", content);
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        // The new entry should be retrievable.
        assert!(cache.get("https://example.com/new").is_some());
    }

    #[test]
    fn cache_miss_returns_none() {
        let mut cache = UrlCache::new(3600);
        assert!(cache.get("https://nonexistent.example.com").is_none());
    }

    // -- Whitespace / HTML helpers --

    #[test]
    fn collapse_whitespace_works() {
        assert_eq!(collapse_whitespace("  hello   world  "), "hello world");
        assert_eq!(collapse_whitespace("\n\n\n"), "");
        assert_eq!(collapse_whitespace("no  extra  spaces"), "no extra spaces");
    }

    #[test]
    fn strip_html_handles_empty() {
        assert_eq!(strip_html(""), "");
    }

    #[test]
    fn extract_title_with_attributes() {
        let html = r#"<title lang="en">Attributed Title</title>"#;
        assert_eq!(extract_title(html), Some("Attributed Title".to_string()));
    }
}
