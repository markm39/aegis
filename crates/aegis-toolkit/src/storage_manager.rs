//! Browser storage management for cookies, localStorage, and sessionStorage.
//!
//! This module provides a [`StorageManager`] that builds Chrome DevTools Protocol
//! (CDP) parameters for cookie and web storage operations, enforces domain-level
//! security policies, and produces audit-safe redacted copies of storage data.
//!
//! Security properties:
//! - Cookie domains are restricted to the navigation history (no cross-site injection).
//! - HttpOnly cookie writes are rejected (browser-managed flag).
//! - Values are redacted in audit output (show key + domain only, first 4 chars + "***").
//! - Storage values are size-limited to prevent memory exhaustion.
//! - Origins are validated (http/https only, no file://).
//! - Subdomain validation prevents cookie tossing attacks.
//! - Sensitive cookie names (session, token, auth, csrf) receive extra redaction.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by storage management operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("domain not in navigation history: {domain}")]
    DomainNotVisited { domain: String },

    #[error("domain not in allowed list: {domain}")]
    DomainNotAllowed { domain: String },

    #[error("invalid origin: {reason}")]
    InvalidOrigin { reason: String },

    #[error("HttpOnly cookies cannot be set via CDP (browser-managed)")]
    HttpOnlyWriteBlocked,

    #[error("cookie value too large: {size} bytes, limit is {limit}")]
    CookieValueTooLarge { size: usize, limit: usize },

    #[error("storage value too large: {size} bytes, limit is {limit}")]
    StorageValueTooLarge { size: usize, limit: usize },
}

// ---------------------------------------------------------------------------
// CookieInfo
// ---------------------------------------------------------------------------

/// Metadata for a browser cookie, as returned by CDP `Storage.getCookies`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain the cookie belongs to.
    pub domain: String,
    /// URL path scope.
    pub path: String,
    /// Whether the cookie is HttpOnly (inaccessible to JavaScript).
    pub http_only: bool,
    /// Whether the cookie requires HTTPS.
    pub secure: bool,
    /// SameSite attribute ("Strict", "Lax", or "None").
    pub same_site: String,
    /// Expiration as seconds since Unix epoch, or `None` for session cookies.
    pub expires: Option<f64>,
}

// ---------------------------------------------------------------------------
// CookieParams
// ---------------------------------------------------------------------------

/// Parameters for setting a cookie via CDP `Network.setCookie`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieParams {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain the cookie belongs to.
    pub domain: String,
    /// URL path scope (default: "/").
    #[serde(default = "default_path")]
    pub path: String,
    /// HttpOnly flag (default: false).
    #[serde(default)]
    pub http_only: bool,
    /// Secure flag (default: false).
    #[serde(default)]
    pub secure: bool,
    /// SameSite attribute (default: "Lax").
    #[serde(default = "default_same_site")]
    pub same_site: String,
    /// Expiration as seconds since Unix epoch, or `None` for session cookies.
    #[serde(default)]
    pub expires: Option<f64>,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_same_site() -> String {
    "Lax".to_string()
}

// ---------------------------------------------------------------------------
// StorageEntry
// ---------------------------------------------------------------------------

/// A key-value entry from localStorage or sessionStorage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    /// Storage key.
    pub key: String,
    /// Storage value.
    pub value: String,
    /// Origin (scheme + host + port) the storage belongs to.
    pub origin: String,
}

// ---------------------------------------------------------------------------
// StorageType
// ---------------------------------------------------------------------------

/// Which web storage API to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageType {
    /// `window.localStorage`.
    LocalStorage,
    /// `window.sessionStorage`.
    SessionStorage,
}

impl StorageType {
    /// Returns the JavaScript object name for this storage type.
    fn js_name(self) -> &'static str {
        match self {
            StorageType::LocalStorage => "localStorage",
            StorageType::SessionStorage => "sessionStorage",
        }
    }
}

// ---------------------------------------------------------------------------
// StorageConfig
// ---------------------------------------------------------------------------

/// Default maximum cookie value length: 4096 bytes.
const DEFAULT_MAX_COOKIE_VALUE_LEN: usize = 4096;

/// Default maximum storage value length: 1 MB.
const DEFAULT_MAX_STORAGE_VALUE_LEN: usize = 1024 * 1024;

/// Configuration for the storage manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum allowed cookie value length in bytes.
    pub max_cookie_value_len: usize,
    /// Maximum allowed storage value length in bytes.
    pub max_storage_value_len: usize,
    /// If non-empty, only these domains are allowed for cookie/storage operations.
    /// Checked in addition to navigation history.
    pub allowed_domains: Vec<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_cookie_value_len: DEFAULT_MAX_COOKIE_VALUE_LEN,
            max_storage_value_len: DEFAULT_MAX_STORAGE_VALUE_LEN,
            allowed_domains: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sensitive cookie detection
// ---------------------------------------------------------------------------

/// Cookie name substrings that indicate sensitive authentication material.
const SENSITIVE_COOKIE_PATTERNS: &[&str] = &["session", "token", "auth", "csrf"];

/// Returns `true` if the cookie name suggests it carries sensitive material.
fn is_sensitive_cookie(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_COOKIE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

// ---------------------------------------------------------------------------
// StorageManager
// ---------------------------------------------------------------------------

/// Manages browser storage operations with domain validation and audit redaction.
///
/// Builds CDP parameters for cookie and web storage operations. Does **not**
/// perform actual CDP communication -- that responsibility lies with the
/// browser/CDP layer. This module is purely a validation, parameter-building,
/// and audit-redaction layer.
pub struct StorageManager {
    config: StorageConfig,
    /// Domains the browser has navigated to. Cookie writes are restricted to
    /// domains in this set (or parent domains thereof).
    navigation_history: HashSet<String>,
}

impl StorageManager {
    /// Create a new storage manager with the given configuration.
    pub fn new(config: StorageConfig) -> Self {
        Self {
            config,
            navigation_history: HashSet::new(),
        }
    }

    /// Record that the browser navigated to the given domain.
    ///
    /// This expands the set of domains that are valid targets for cookie writes.
    pub fn record_navigation(&mut self, domain: &str) {
        self.navigation_history.insert(domain.to_ascii_lowercase());
    }

    /// Check whether a domain is allowed for storage operations.
    ///
    /// A domain is allowed if:
    /// 1. It appears in the navigation history **or** is a parent domain of a visited domain.
    /// 2. If `allowed_domains` is non-empty, the domain must also appear in that list.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();

        // Check navigation history (exact or parent-domain match).
        let in_history = self.navigation_history.iter().any(|visited| {
            visited == &domain_lower || visited.ends_with(&format!(".{domain_lower}"))
        });

        if !in_history {
            return false;
        }

        // If an explicit allowlist is configured, also check that.
        if !self.config.allowed_domains.is_empty() {
            return self
                .config
                .allowed_domains
                .iter()
                .any(|d| d.to_ascii_lowercase() == domain_lower);
        }

        true
    }

    // -- Cookie operations --------------------------------------------------

    /// Build CDP `Storage.getCookies` parameters.
    ///
    /// If `domain` is `Some`, filters cookies to that domain. Otherwise returns
    /// parameters to fetch all cookies.
    pub fn build_get_cookies_params(&self, domain: Option<&str>) -> serde_json::Value {
        match domain {
            Some(d) => serde_json::json!({
                "urls": [format!("https://{d}")]
            }),
            None => serde_json::json!({}),
        }
    }

    /// Parse a CDP `Storage.getCookies` response into [`CookieInfo`] entries.
    pub fn parse_cookies_response(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<CookieInfo>, StorageError> {
        let cookies = response
            .get("cookies")
            .and_then(|v| v.as_array())
            .unwrap_or(&Vec::new())
            .iter()
            .map(|c| CookieInfo {
                name: c
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                value: c
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                domain: c
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                path: c
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string(),
                http_only: c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
                secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                same_site: c
                    .get("sameSite")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Lax")
                    .to_string(),
                expires: c.get("expires").and_then(|v| v.as_f64()),
            })
            .collect();
        Ok(cookies)
    }

    /// Build CDP `Network.setCookie` parameters.
    ///
    /// Validates:
    /// - The domain is in the navigation history (prevents cross-site cookie injection).
    /// - The `http_only` flag is `false` (HttpOnly is browser-managed, cannot be set via CDP).
    /// - The cookie value does not exceed the configured maximum length.
    pub fn build_set_cookie_params(
        &self,
        params: &CookieParams,
    ) -> Result<serde_json::Value, StorageError> {
        // Block HttpOnly cookie writes.
        if params.http_only {
            return Err(StorageError::HttpOnlyWriteBlocked);
        }

        // Validate domain against navigation history.
        validate_cookie_domain(&params.domain, &self.navigation_history)?;

        // Check domain against allowlist if configured.
        if !self.config.allowed_domains.is_empty() {
            let domain_lower = params.domain.to_ascii_lowercase();
            if !self
                .config
                .allowed_domains
                .iter()
                .any(|d| d.to_ascii_lowercase() == domain_lower)
            {
                return Err(StorageError::DomainNotAllowed {
                    domain: params.domain.clone(),
                });
            }
        }

        // Enforce cookie value size limit.
        if params.value.len() > self.config.max_cookie_value_len {
            return Err(StorageError::CookieValueTooLarge {
                size: params.value.len(),
                limit: self.config.max_cookie_value_len,
            });
        }

        let mut json = serde_json::json!({
            "name": params.name,
            "value": params.value,
            "domain": params.domain,
            "path": params.path,
            "secure": params.secure,
            "sameSite": params.same_site,
        });

        if let Some(expires) = params.expires {
            json["expires"] = serde_json::json!(expires);
        }

        Ok(json)
    }

    /// Build CDP `Network.deleteCookies` parameters.
    pub fn build_delete_cookie_params(&self, name: &str, domain: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "domain": domain,
        })
    }

    // -- Storage operations -------------------------------------------------

    /// Build CDP `Runtime.evaluate` parameters to enumerate all keys in storage.
    ///
    /// The expression returns a JSON string of all key-value pairs.
    pub fn build_get_storage_params(
        &self,
        origin: &str,
        storage_type: StorageType,
    ) -> serde_json::Value {
        let js_name = storage_type.js_name();
        let expression = format!(
            "JSON.stringify(Object.keys({js_name}).reduce((acc, k) => {{ acc[k] = {js_name}.getItem(k); return acc; }}, {{}}))"
        );
        serde_json::json!({
            "expression": expression,
            "returnByValue": true,
            "contextId": origin,
        })
    }

    /// Build CDP `Runtime.evaluate` parameters to set a storage key.
    ///
    /// Validates the origin and enforces value size limits.
    pub fn build_set_storage_params(
        &self,
        origin: &str,
        key: &str,
        value: &str,
        storage_type: StorageType,
    ) -> Result<serde_json::Value, StorageError> {
        validate_origin(origin)?;

        // Enforce value size limit.
        if value.len() > self.config.max_storage_value_len {
            return Err(StorageError::StorageValueTooLarge {
                size: value.len(),
                limit: self.config.max_storage_value_len,
            });
        }

        let js_name = storage_type.js_name();
        // Escape the key and value for safe embedding in JavaScript.
        let escaped_key = escape_js_string(key);
        let escaped_value = escape_js_string(value);
        let expression = format!("{js_name}.setItem('{escaped_key}', '{escaped_value}')");

        Ok(serde_json::json!({
            "expression": expression,
            "returnByValue": true,
            "contextId": origin,
        }))
    }

    /// Build CDP `Runtime.evaluate` parameters to clear all entries in storage.
    pub fn build_clear_storage_params(
        &self,
        origin: &str,
        storage_type: StorageType,
    ) -> serde_json::Value {
        let js_name = storage_type.js_name();
        let expression = format!("{js_name}.clear()");
        serde_json::json!({
            "expression": expression,
            "returnByValue": true,
            "contextId": origin,
        })
    }

    // -- Audit redaction ----------------------------------------------------

    /// Return a redacted copy of a cookie for audit logging.
    ///
    /// The value is replaced with the first 4 characters followed by "***".
    /// Sensitive cookies (session, token, auth, csrf) get fully redacted values ("***").
    pub fn redact_cookie_value(&self, cookie: &CookieInfo) -> CookieInfo {
        let redacted_value = if is_sensitive_cookie(&cookie.name) {
            "***".to_string()
        } else {
            redact_value(&cookie.value)
        };
        CookieInfo {
            name: cookie.name.clone(),
            value: redacted_value,
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            http_only: cookie.http_only,
            secure: cookie.secure,
            same_site: cookie.same_site.clone(),
            expires: cookie.expires,
        }
    }

    /// Return a redacted copy of a storage entry for audit logging.
    ///
    /// The value is replaced with the first 4 characters followed by "***".
    pub fn redact_storage_value(&self, entry: &StorageEntry) -> StorageEntry {
        StorageEntry {
            key: entry.key.clone(),
            value: redact_value(&entry.value),
            origin: entry.origin.clone(),
        }
    }

    /// Batch-redact cookies for audit logging.
    pub fn for_audit(&self, cookies: &[CookieInfo]) -> Vec<CookieInfo> {
        cookies
            .iter()
            .map(|c| self.redact_cookie_value(c))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

/// Validate that a cookie domain matches a visited domain in the navigation history.
///
/// A cookie domain is valid if:
/// - It exactly matches a visited domain, OR
/// - It is a parent domain of a visited domain (e.g., ".example.com" when
///   "sub.example.com" was visited).
///
/// This prevents cross-site cookie injection: an agent cannot set cookies for
/// domains the browser has not navigated to.
pub fn validate_cookie_domain(
    domain: &str,
    navigation_history: &HashSet<String>,
) -> Result<(), StorageError> {
    let domain_lower = domain.trim_start_matches('.').to_ascii_lowercase();

    if domain_lower.is_empty() {
        return Err(StorageError::DomainNotVisited {
            domain: domain.to_string(),
        });
    }

    // Check exact match or parent-domain match.
    let is_valid = navigation_history.iter().any(|visited| {
        let visited_lower = visited.to_ascii_lowercase();
        // Exact match: cookie domain == visited domain.
        if visited_lower == domain_lower {
            return true;
        }
        // Parent domain match: visited "sub.example.com", cookie domain "example.com".
        if visited_lower.ends_with(&format!(".{domain_lower}")) {
            return true;
        }
        false
    });

    if !is_valid {
        return Err(StorageError::DomainNotVisited {
            domain: domain.to_string(),
        });
    }

    Ok(())
}

/// Validate that an origin is a well-formed http or https URL.
///
/// Rejects:
/// - Origins that cannot be parsed as a URL.
/// - Non-http/https schemes (blocks file://, data://, etc.).
/// - Origins without a host.
pub fn validate_origin(origin: &str) -> Result<(), StorageError> {
    let parsed = Url::parse(origin).map_err(|e| StorageError::InvalidOrigin {
        reason: format!("failed to parse origin: {e}"),
    })?;

    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(StorageError::InvalidOrigin {
            reason: format!("scheme '{scheme}' is not allowed; only http and https are permitted"),
        });
    }

    if parsed.host_str().is_none() {
        return Err(StorageError::InvalidOrigin {
            reason: "origin has no host".to_string(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Redact a value for audit logging: first 4 characters + "***".
///
/// If the value is 4 characters or fewer, the entire value is replaced with "***".
fn redact_value(value: &str) -> String {
    if value.len() <= 4 {
        "***".to_string()
    } else {
        let prefix: String = value.chars().take(4).collect();
        format!("{prefix}***")
    }
}

/// Escape a string for safe embedding in a JavaScript single-quoted string literal.
fn escape_js_string(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\'' => escaped.push_str("\\'"),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\0' => escaped.push_str("\\0"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_manager() -> StorageManager {
        StorageManager::new(StorageConfig::default())
    }

    fn manager_with_navigation(domains: &[&str]) -> StorageManager {
        let mut mgr = default_manager();
        for d in domains {
            mgr.record_navigation(d);
        }
        mgr
    }

    // -- Cookie get params --------------------------------------------------

    #[test]
    fn test_get_cookies_params_all() {
        let mgr = default_manager();
        let params = mgr.build_get_cookies_params(None);
        // No domain filter -- should be an empty object.
        assert_eq!(params, serde_json::json!({}));
    }

    #[test]
    fn test_get_cookies_params_filtered_by_domain() {
        let mgr = default_manager();
        let params = mgr.build_get_cookies_params(Some("example.com"));
        assert_eq!(
            params,
            serde_json::json!({ "urls": ["https://example.com"] })
        );
    }

    // -- Cookie set params / domain validation ------------------------------

    #[test]
    fn test_set_cookie_validates_domain() {
        let mgr = manager_with_navigation(&["example.com"]);

        let params = CookieParams {
            name: "my_cookie".into(),
            value: "some_value".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: true,
            same_site: "Lax".into(),
            expires: None,
        };

        let result = mgr.build_set_cookie_params(&params);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert_eq!(json["name"], "my_cookie");
        assert_eq!(json["value"], "some_value");
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["path"], "/");
        assert_eq!(json["secure"], true);
        assert_eq!(json["sameSite"], "Lax");
        // No expires key when None.
        assert!(json.get("expires").is_none());
    }

    #[test]
    fn test_set_cookie_with_expires() {
        let mgr = manager_with_navigation(&["example.com"]);

        let params = CookieParams {
            name: "expiring".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "Strict".into(),
            expires: Some(1700000000.0),
        };

        let json = mgr.build_set_cookie_params(&params).unwrap();
        assert_eq!(json["expires"], 1700000000.0);
    }

    // -- Storage params roundtrip -------------------------------------------

    #[test]
    fn test_local_storage_params_roundtrip() {
        let mgr = default_manager();

        // Get params.
        let get_params =
            mgr.build_get_storage_params("https://example.com", StorageType::LocalStorage);
        let expr = get_params["expression"].as_str().unwrap();
        assert!(expr.contains("localStorage"));
        assert!(expr.contains("JSON.stringify"));

        // Set params.
        let set_params = mgr
            .build_set_storage_params(
                "https://example.com",
                "myKey",
                "myValue",
                StorageType::LocalStorage,
            )
            .unwrap();
        let expr = set_params["expression"].as_str().unwrap();
        assert!(expr.contains("localStorage.setItem"));
        assert!(expr.contains("myKey"));
        assert!(expr.contains("myValue"));

        // Clear params.
        let clear_params =
            mgr.build_clear_storage_params("https://example.com", StorageType::LocalStorage);
        let expr = clear_params["expression"].as_str().unwrap();
        assert!(expr.contains("localStorage.clear()"));
    }

    #[test]
    fn test_session_storage_params_roundtrip() {
        let mgr = default_manager();

        // Get params.
        let get_params =
            mgr.build_get_storage_params("https://example.com", StorageType::SessionStorage);
        let expr = get_params["expression"].as_str().unwrap();
        assert!(expr.contains("sessionStorage"));

        // Set params.
        let set_params = mgr
            .build_set_storage_params(
                "https://example.com",
                "sessKey",
                "sessVal",
                StorageType::SessionStorage,
            )
            .unwrap();
        let expr = set_params["expression"].as_str().unwrap();
        assert!(expr.contains("sessionStorage.setItem"));

        // Clear params.
        let clear_params =
            mgr.build_clear_storage_params("https://example.com", StorageType::SessionStorage);
        let expr = clear_params["expression"].as_str().unwrap();
        assert!(expr.contains("sessionStorage.clear()"));
    }

    // -- Audit redaction ----------------------------------------------------

    #[test]
    fn test_audit_log_redacts_values() {
        let mgr = default_manager();

        let cookies = vec![
            CookieInfo {
                name: "preference".into(),
                value: "dark_mode_enabled".into(),
                domain: "example.com".into(),
                path: "/".into(),
                http_only: false,
                secure: true,
                same_site: "Lax".into(),
                expires: None,
            },
            CookieInfo {
                name: "tracking_id".into(),
                value: "abc123def456".into(),
                domain: "example.com".into(),
                path: "/".into(),
                http_only: false,
                secure: true,
                same_site: "Lax".into(),
                expires: None,
            },
        ];

        let redacted = mgr.for_audit(&cookies);
        assert_eq!(redacted.len(), 2);

        // First cookie: "dark" + "***"
        assert_eq!(redacted[0].name, "preference");
        assert_eq!(redacted[0].value, "dark***");
        assert_eq!(redacted[0].domain, "example.com");

        // Second cookie: "abc1" + "***"
        assert_eq!(redacted[1].name, "tracking_id");
        assert_eq!(redacted[1].value, "abc1***");
    }

    #[test]
    fn test_redact_storage_value() {
        let mgr = default_manager();
        let entry = StorageEntry {
            key: "user_data".into(),
            value: "sensitive_information_here".into(),
            origin: "https://example.com".into(),
        };

        let redacted = mgr.redact_storage_value(&entry);
        assert_eq!(redacted.key, "user_data");
        assert_eq!(redacted.value, "sens***");
        assert_eq!(redacted.origin, "https://example.com");
    }

    #[test]
    fn test_redact_short_value() {
        let mgr = default_manager();
        let cookie = CookieInfo {
            name: "x".into(),
            value: "ab".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "Lax".into(),
            expires: None,
        };

        let redacted = mgr.redact_cookie_value(&cookie);
        // Value <= 4 chars: fully redacted.
        assert_eq!(redacted.value, "***");
    }

    // -- HttpOnly write prevention ------------------------------------------

    #[test]
    fn test_httponly_write_rejected() {
        let mgr = manager_with_navigation(&["example.com"]);

        let params = CookieParams {
            name: "session_id".into(),
            value: "secret".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: true, // This should be rejected.
            secure: true,
            same_site: "Strict".into(),
            expires: None,
        };

        let result = mgr.build_set_cookie_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::HttpOnlyWriteBlocked => {} // Expected.
            other => panic!("expected HttpOnlyWriteBlocked, got: {other:?}"),
        }
    }

    // -- Domain validation / navigation history -----------------------------

    #[test]
    fn test_domain_validation_navigation_history() {
        let mut history = HashSet::new();
        history.insert("sub.example.com".to_string());
        history.insert("other.org".to_string());

        // Exact match.
        assert!(validate_cookie_domain("sub.example.com", &history).is_ok());
        assert!(validate_cookie_domain("other.org", &history).is_ok());

        // Parent domain of visited domain.
        assert!(validate_cookie_domain("example.com", &history).is_ok());

        // Leading dot (common in cookies) should also work.
        assert!(validate_cookie_domain(".example.com", &history).is_ok());

        // Unvisited domain should fail.
        assert!(validate_cookie_domain("evil.com", &history).is_err());
    }

    // -- Security tests -----------------------------------------------------

    #[test]
    fn security_test_cross_site_cookie_blocked() {
        let mgr = manager_with_navigation(&["safe.example.com"]);

        // Attempt to set cookie for a domain not in navigation history.
        let params = CookieParams {
            name: "evil_cookie".into(),
            value: "payload".into(),
            domain: "evil.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "None".into(),
            expires: None,
        };

        let result = mgr.build_set_cookie_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::DomainNotVisited { domain } => {
                assert_eq!(domain, "evil.com");
            }
            other => panic!("expected DomainNotVisited, got: {other:?}"),
        }
    }

    #[test]
    fn security_test_sensitive_cookie_detection() {
        let mgr = default_manager();

        let sensitive_names = vec![
            "session_id",
            "auth_token",
            "csrf_token",
            "my_SESSION_cookie",
            "x-auth-header",
            "TOKEN_value",
        ];

        for name in &sensitive_names {
            let cookie = CookieInfo {
                name: name.to_string(),
                value: "super_secret_value_12345".into(),
                domain: "example.com".into(),
                path: "/".into(),
                http_only: true,
                secure: true,
                same_site: "Strict".into(),
                expires: None,
            };

            let redacted = mgr.redact_cookie_value(&cookie);
            assert_eq!(
                redacted.value, "***",
                "sensitive cookie '{name}' should be fully redacted"
            );
        }

        // Non-sensitive cookie should show partial value.
        let normal = CookieInfo {
            name: "theme_preference".into(),
            value: "dark_mode".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "Lax".into(),
            expires: None,
        };
        let redacted = mgr.redact_cookie_value(&normal);
        assert_eq!(redacted.value, "dark***");
    }

    #[test]
    fn security_test_origin_validation() {
        // Valid origins.
        assert!(validate_origin("https://example.com").is_ok());
        assert!(validate_origin("http://example.com").is_ok());
        assert!(validate_origin("https://example.com:8080").is_ok());

        // Invalid: file scheme.
        let result = validate_origin("file:///etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::InvalidOrigin { reason } => {
                assert!(reason.contains("scheme"));
            }
            other => panic!("expected InvalidOrigin, got: {other:?}"),
        }

        // Invalid: data scheme.
        assert!(validate_origin("data:text/html,<h1>x</h1>").is_err());

        // Invalid: javascript scheme (url crate may fail to parse, which is fine).
        assert!(validate_origin("javascript:alert(1)").is_err());

        // Invalid: not a URL at all.
        assert!(validate_origin("not-a-url").is_err());

        // Invalid: empty string.
        assert!(validate_origin("").is_err());

        // Invalid: ftp scheme.
        assert!(validate_origin("ftp://example.com").is_err());
    }

    #[test]
    fn security_test_storage_value_size_limit() {
        let config = StorageConfig {
            max_storage_value_len: 100,
            ..Default::default()
        };
        let mgr = StorageManager::new(config);

        // Within limit.
        let result = mgr.build_set_storage_params(
            "https://example.com",
            "key",
            &"x".repeat(100),
            StorageType::LocalStorage,
        );
        assert!(result.is_ok());

        // Exceeds limit.
        let result = mgr.build_set_storage_params(
            "https://example.com",
            "key",
            &"x".repeat(101),
            StorageType::LocalStorage,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::StorageValueTooLarge { size, limit } => {
                assert_eq!(size, 101);
                assert_eq!(limit, 100);
            }
            other => panic!("expected StorageValueTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn security_test_cookie_value_size_limit() {
        let config = StorageConfig {
            max_cookie_value_len: 50,
            ..Default::default()
        };
        let mut mgr = StorageManager::new(config);
        mgr.record_navigation("example.com");

        let params = CookieParams {
            name: "big_cookie".into(),
            value: "x".repeat(51),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "Lax".into(),
            expires: None,
        };

        let result = mgr.build_set_cookie_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::CookieValueTooLarge { size, limit } => {
                assert_eq!(size, 51);
                assert_eq!(limit, 50);
            }
            other => panic!("expected CookieValueTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn security_test_invalid_origin_blocks_storage_set() {
        let mgr = default_manager();

        // file:// origin should be rejected.
        let result = mgr.build_set_storage_params(
            "file:///tmp/local.html",
            "key",
            "value",
            StorageType::LocalStorage,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cookies_response() {
        let mgr = default_manager();
        let response = serde_json::json!({
            "cookies": [
                {
                    "name": "session",
                    "value": "abc123",
                    "domain": ".example.com",
                    "path": "/",
                    "httpOnly": true,
                    "secure": true,
                    "sameSite": "Strict",
                    "expires": 1700000000.0
                },
                {
                    "name": "theme",
                    "value": "dark",
                    "domain": "example.com",
                    "path": "/app",
                    "httpOnly": false,
                    "secure": false,
                    "sameSite": "Lax"
                }
            ]
        });

        let cookies = mgr.parse_cookies_response(&response).unwrap();
        assert_eq!(cookies.len(), 2);

        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[0].domain, ".example.com");
        assert!(cookies[0].http_only);
        assert!(cookies[0].secure);
        assert_eq!(cookies[0].same_site, "Strict");
        assert_eq!(cookies[0].expires, Some(1700000000.0));

        assert_eq!(cookies[1].name, "theme");
        assert_eq!(cookies[1].value, "dark");
        assert!(!cookies[1].http_only);
        assert!(cookies[1].expires.is_none());
    }

    #[test]
    fn test_parse_empty_cookies_response() {
        let mgr = default_manager();
        let response = serde_json::json!({});
        let cookies = mgr.parse_cookies_response(&response).unwrap();
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_delete_cookie_params() {
        let mgr = default_manager();
        let params = mgr.build_delete_cookie_params("session_id", "example.com");
        assert_eq!(params["name"], "session_id");
        assert_eq!(params["domain"], "example.com");
    }

    #[test]
    fn test_is_domain_allowed_with_allowlist() {
        let config = StorageConfig {
            allowed_domains: vec!["example.com".into(), "trusted.org".into()],
            ..Default::default()
        };
        let mut mgr = StorageManager::new(config);
        mgr.record_navigation("example.com");
        mgr.record_navigation("evil.com");

        // In both navigation history and allowlist.
        assert!(mgr.is_domain_allowed("example.com"));

        // In navigation history but NOT in allowlist.
        assert!(!mgr.is_domain_allowed("evil.com"));

        // In allowlist but NOT in navigation history.
        assert!(!mgr.is_domain_allowed("trusted.org"));
    }

    #[test]
    fn test_subdomain_cookie_tossing_prevention() {
        let mut history = HashSet::new();
        history.insert("example.com".to_string());

        // Cannot set cookie for a sibling subdomain that was never visited.
        // "attacker.example.com" was not visited -- only "example.com" was.
        // The cookie domain "attacker.example.com" is not a parent of any visited domain,
        // nor is it exactly visited.
        assert!(validate_cookie_domain("attacker.example.com", &history).is_err());

        // Can set cookie for the exact visited domain.
        assert!(validate_cookie_domain("example.com", &history).is_ok());
    }

    #[test]
    fn test_escape_js_string_special_chars() {
        assert_eq!(escape_js_string("hello"), "hello");
        assert_eq!(escape_js_string("it's"), "it\\'s");
        assert_eq!(escape_js_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_js_string("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_js_string("tab\there"), "tab\\there");
        assert_eq!(escape_js_string("null\0byte"), "null\\0byte");
    }

    #[test]
    fn test_record_navigation_case_insensitive() {
        let mut mgr = default_manager();
        mgr.record_navigation("Example.COM");

        assert!(mgr.is_domain_allowed("example.com"));
    }

    #[test]
    fn test_parent_domain_cookie_allowed() {
        // Visited sub.example.com, should be able to set cookie for example.com (parent).
        let mgr = manager_with_navigation(&["sub.example.com"]);

        let params = CookieParams {
            name: "parent_cookie".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: false,
            secure: false,
            same_site: "Lax".into(),
            expires: None,
        };

        assert!(mgr.build_set_cookie_params(&params).is_ok());
    }
}
