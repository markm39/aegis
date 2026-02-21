//! Browser tab management with CRUD operations, URL validation, and state tracking.
//!
//! This module provides a [`TabManager`] that tracks open browser tabs,
//! enforces URL security policies, and maintains state suitable for audit
//! logging. It does not interact with CDP directly -- that wiring lives in
//! `toolkit_runtime.rs`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during tab management operations.
#[derive(Debug, Error)]
pub enum TabError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("blocked URL: {0}")]
    BlockedUrl(String),

    #[error("tab limit reached (max {max})")]
    TabLimitReached { max: usize },

    #[error("tab not found: {0}")]
    TabNotFound(String),

    #[error("invalid tab ID: {0}")]
    InvalidTabId(String),
}

// ---------------------------------------------------------------------------
// TabInfo
// ---------------------------------------------------------------------------

/// Metadata for a single tracked browser tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabInfo {
    /// Unique tab identifier (alphanumeric + dashes).
    pub id: String,
    /// The URL loaded in this tab.
    pub url: String,
    /// Human-readable title (may be empty until page loads).
    pub title: String,
    /// Whether this tab is the currently active/focused tab.
    pub active: bool,
    /// When the tab was first opened.
    pub created_at: DateTime<Utc>,
    /// When the tab was last made active.
    pub last_active: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// TabConfig
// ---------------------------------------------------------------------------

/// Configuration for tab management limits and URL blocking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabConfig {
    /// Maximum number of simultaneously open tabs (prevents resource exhaustion).
    pub max_tabs: usize,
    /// URL substring patterns that are blocked from opening.
    pub blocked_url_patterns: Vec<String>,
}

impl Default for TabConfig {
    fn default() -> Self {
        Self {
            max_tabs: 20,
            blocked_url_patterns: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// TabManager
// ---------------------------------------------------------------------------

/// Tracks open browser tabs with URL validation and state management.
///
/// All tab-open operations go through URL validation that blocks dangerous
/// schemes, private/internal IP addresses, and configurable URL patterns.
pub struct TabManager {
    config: TabConfig,
    tabs: HashMap<String, TabInfo>,
    next_id: u64,
}

impl TabManager {
    /// Create a new tab manager with the given configuration.
    pub fn new(config: TabConfig) -> Self {
        Self {
            config,
            tabs: HashMap::new(),
            next_id: 1,
        }
    }

    /// Open a new tab at the given URL.
    ///
    /// Validates the URL against security policies, checks the tab limit,
    /// and creates a new tracked tab entry. The new tab becomes active.
    pub fn open_tab(&mut self, url: &str) -> Result<TabInfo, TabError> {
        validate_tab_url(url, &self.config.blocked_url_patterns)?;

        if self.tabs.len() >= self.config.max_tabs {
            return Err(TabError::TabLimitReached {
                max: self.config.max_tabs,
            });
        }

        let id = format!("tab-{}", self.next_id);
        self.next_id += 1;

        let now = Utc::now();

        // Deactivate all existing tabs.
        for tab in self.tabs.values_mut() {
            tab.active = false;
        }

        let tab = TabInfo {
            id: id.clone(),
            url: url.to_string(),
            title: String::new(),
            active: true,
            created_at: now,
            last_active: now,
        };

        self.tabs.insert(id, tab.clone());
        Ok(tab)
    }

    /// Close (remove) a tab by its ID.
    pub fn close_tab(&mut self, tab_id: &str) -> Result<(), TabError> {
        validate_tab_id(tab_id)?;
        if self.tabs.remove(tab_id).is_none() {
            return Err(TabError::TabNotFound(tab_id.to_string()));
        }
        Ok(())
    }

    /// Switch to a tab, marking it active and deactivating all others.
    ///
    /// Updates the `last_active` timestamp on the target tab.
    pub fn switch_tab(&mut self, tab_id: &str) -> Result<(), TabError> {
        validate_tab_id(tab_id)?;
        if !self.tabs.contains_key(tab_id) {
            return Err(TabError::TabNotFound(tab_id.to_string()));
        }

        let now = Utc::now();
        for (id, tab) in self.tabs.iter_mut() {
            if id == tab_id {
                tab.active = true;
                tab.last_active = now;
            } else {
                tab.active = false;
            }
        }
        Ok(())
    }

    /// Return all tracked tabs.
    pub fn list_tabs(&self) -> Vec<&TabInfo> {
        self.tabs.values().collect()
    }

    /// Search tabs whose URL contains the given pattern substring.
    pub fn find_tab_by_url(&self, pattern: &str) -> Vec<&TabInfo> {
        self.tabs
            .values()
            .filter(|tab| tab.url.contains(pattern))
            .collect()
    }

    /// Get a tab by its ID.
    pub fn get_tab(&self, tab_id: &str) -> Option<&TabInfo> {
        self.tabs.get(tab_id)
    }

    /// Return the currently active tab, if any.
    pub fn active_tab(&self) -> Option<&TabInfo> {
        self.tabs.values().find(|tab| tab.active)
    }

    /// Return the number of open tabs.
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// Dangerous URI schemes that must never be opened in a browser tab.
const BLOCKED_SCHEMES: &[&str] = &[
    "file",
    "data",
    "javascript",
    "chrome",
    "chrome-extension",
    "about",
    "blob",
    "vbscript",
];

/// Validate a URL for tab opening.
///
/// Rejects:
/// - Non-http/https schemes (and explicit blocklist of dangerous schemes)
/// - URLs pointing to private/internal IP addresses (SSRF protection)
/// - URLs matching any configured blocked patterns
pub fn validate_tab_url(raw_url: &str, blocked_patterns: &[String]) -> Result<(), TabError> {
    let parsed =
        Url::parse(raw_url).map_err(|e| TabError::InvalidUrl(format!("parse error: {e}")))?;

    let scheme = parsed.scheme().to_lowercase();

    // Block dangerous schemes explicitly.
    if BLOCKED_SCHEMES.contains(&scheme.as_str()) {
        return Err(TabError::BlockedUrl(format!(
            "scheme '{scheme}' is not allowed"
        )));
    }

    // Only allow http and https.
    if scheme != "http" && scheme != "https" {
        return Err(TabError::InvalidUrl(format!(
            "scheme '{scheme}' is not allowed; only http and https are permitted"
        )));
    }

    // Require a host.
    let host = parsed
        .host()
        .ok_or_else(|| TabError::InvalidUrl("URL has no host".to_string()))?;

    // Check IP addresses (both v4 and v6) against private ranges.
    match &host {
        url::Host::Ipv4(ip) => {
            if is_private_ipv4(ip) {
                return Err(TabError::BlockedUrl(format!(
                    "private/internal IP address: {ip}"
                )));
            }
        }
        url::Host::Ipv6(ip) => {
            if is_private_ipv6(ip) {
                return Err(TabError::BlockedUrl(format!(
                    "private/internal IP address: {ip}"
                )));
            }
        }
        url::Host::Domain(domain) => {
            // Block known localhost aliases.
            if domain.eq_ignore_ascii_case("localhost") {
                return Err(TabError::BlockedUrl(
                    "localhost is not allowed".to_string(),
                ));
            }
        }
    }

    // Check against user-configured blocked URL patterns.
    for pattern in blocked_patterns {
        if raw_url.contains(pattern.as_str()) {
            return Err(TabError::BlockedUrl(format!(
                "URL matches blocked pattern: {pattern}"
            )));
        }
    }

    Ok(())
}

/// Validate that a tab ID contains only safe characters (alphanumeric + dash).
///
/// Prevents path traversal or injection through tab IDs.
fn validate_tab_id(tab_id: &str) -> Result<(), TabError> {
    if tab_id.is_empty() {
        return Err(TabError::InvalidTabId("tab ID is empty".to_string()));
    }
    if !tab_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(TabError::InvalidTabId(format!(
            "tab ID contains invalid characters: {tab_id}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Private IP detection (mirrors aegis-daemon/web_tools.rs logic)
// ---------------------------------------------------------------------------

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 0.0.0.0
    if octets == [0, 0, 0, 0] {
        return true;
    }
    false
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // ::1 (loopback)
    if ip.is_loopback() {
        return true;
    }
    // :: (unspecified)
    if ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    // fc00::/7 (unique local)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // fe80::/10 (link-local)
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // IPv4-mapped IPv6: ::ffff:a.b.c.d
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&v4);
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_manager() -> TabManager {
        TabManager::new(TabConfig::default())
    }

    // -- CRUD tests --------------------------------------------------------

    #[test]
    fn test_open_tab_creates_entry() {
        let mut mgr = default_manager();
        let tab = mgr.open_tab("https://example.com").unwrap();
        assert_eq!(tab.url, "https://example.com");
        assert!(tab.active);
        assert!(!tab.id.is_empty());
        assert_eq!(mgr.tab_count(), 1);
        assert!(mgr.get_tab(&tab.id).is_some());
    }

    #[test]
    fn test_close_tab_removes_entry() {
        let mut mgr = default_manager();
        let tab = mgr.open_tab("https://example.com").unwrap();
        let id = tab.id.clone();
        assert_eq!(mgr.tab_count(), 1);

        mgr.close_tab(&id).unwrap();
        assert_eq!(mgr.tab_count(), 0);
        assert!(mgr.get_tab(&id).is_none());
    }

    #[test]
    fn test_close_nonexistent_tab_fails() {
        let mut mgr = default_manager();
        let result = mgr.close_tab("tab-999");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TabError::TabNotFound(_)));
    }

    #[test]
    fn test_switch_tab_updates_active() {
        let mut mgr = default_manager();
        let tab1 = mgr.open_tab("https://example.com").unwrap();
        let tab2 = mgr.open_tab("https://other.com").unwrap();

        // tab2 should be active after opening.
        assert!(!mgr.get_tab(&tab1.id).unwrap().active);
        assert!(mgr.get_tab(&tab2.id).unwrap().active);

        // Switch to tab1.
        mgr.switch_tab(&tab1.id).unwrap();
        assert!(mgr.get_tab(&tab1.id).unwrap().active);
        assert!(!mgr.get_tab(&tab2.id).unwrap().active);

        // last_active should be updated.
        let t1 = mgr.get_tab(&tab1.id).unwrap();
        assert!(t1.last_active >= t1.created_at);
    }

    #[test]
    fn test_switch_nonexistent_tab_fails() {
        let mut mgr = default_manager();
        let result = mgr.switch_tab("tab-999");
        assert!(matches!(result.unwrap_err(), TabError::TabNotFound(_)));
    }

    #[test]
    fn test_find_tab_by_url_pattern() {
        let mut mgr = default_manager();
        mgr.open_tab("https://example.com/page1").unwrap();
        mgr.open_tab("https://other.com/page2").unwrap();
        mgr.open_tab("https://example.com/page3").unwrap();

        let found = mgr.find_tab_by_url("example.com");
        assert_eq!(found.len(), 2);

        let found = mgr.find_tab_by_url("other.com");
        assert_eq!(found.len(), 1);

        let found = mgr.find_tab_by_url("nonexistent.com");
        assert!(found.is_empty());
    }

    #[test]
    fn test_list_tabs_returns_all() {
        let mut mgr = default_manager();
        mgr.open_tab("https://a.com").unwrap();
        mgr.open_tab("https://b.com").unwrap();
        mgr.open_tab("https://c.com").unwrap();

        let all = mgr.list_tabs();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_active_tab() {
        let mut mgr = default_manager();
        assert!(mgr.active_tab().is_none());

        let tab = mgr.open_tab("https://example.com").unwrap();
        let active = mgr.active_tab().unwrap();
        assert_eq!(active.id, tab.id);
    }

    #[test]
    fn test_tab_count() {
        let mut mgr = default_manager();
        assert_eq!(mgr.tab_count(), 0);
        mgr.open_tab("https://example.com").unwrap();
        assert_eq!(mgr.tab_count(), 1);
        mgr.open_tab("https://other.com").unwrap();
        assert_eq!(mgr.tab_count(), 2);
    }

    // -- Limit enforcement -------------------------------------------------

    #[test]
    fn test_max_tabs_limit_enforced() {
        let config = TabConfig {
            max_tabs: 2,
            ..Default::default()
        };
        let mut mgr = TabManager::new(config);

        mgr.open_tab("https://a.com").unwrap();
        mgr.open_tab("https://b.com").unwrap();

        let result = mgr.open_tab("https://c.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            TabError::TabLimitReached { max } => assert_eq!(max, 2),
            other => panic!("expected TabLimitReached, got: {other:?}"),
        }
    }

    // -- URL validation (blocked patterns) ---------------------------------

    #[test]
    fn test_blocked_url_rejected() {
        let config = TabConfig {
            blocked_url_patterns: vec!["evil.corp".to_string(), "malware.io".to_string()],
            ..Default::default()
        };
        let mut mgr = TabManager::new(config);

        let result = mgr.open_tab("https://evil.corp/payload");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TabError::BlockedUrl(_)));

        let result = mgr.open_tab("https://malware.io/download");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TabError::BlockedUrl(_)));

        // Non-blocked URL should succeed.
        assert!(mgr.open_tab("https://safe-site.com").is_ok());
    }

    // -- Security tests ----------------------------------------------------

    #[test]
    fn security_test_internal_ip_blocked() {
        let mut mgr = default_manager();

        // Loopback.
        assert!(mgr.open_tab("http://127.0.0.1/admin").is_err());
        assert!(mgr.open_tab("http://127.255.255.255/admin").is_err());

        // 10.x.x.x
        assert!(mgr.open_tab("http://10.0.0.1/internal").is_err());

        // 172.16-31.x.x
        assert!(mgr.open_tab("http://172.16.0.1/internal").is_err());
        assert!(mgr.open_tab("http://172.31.255.255/internal").is_err());

        // 192.168.x.x
        assert!(mgr.open_tab("http://192.168.1.1/router").is_err());

        // 169.254.x.x (link-local)
        assert!(mgr.open_tab("http://169.254.0.1/internal").is_err());

        // 0.0.0.0
        assert!(mgr.open_tab("http://0.0.0.0/internal").is_err());

        // IPv6 loopback.
        assert!(mgr.open_tab("http://[::1]/admin").is_err());

        // localhost alias.
        assert!(mgr.open_tab("http://localhost/admin").is_err());

        // Public IPs should succeed.
        assert!(mgr.open_tab("https://8.8.8.8").is_ok());
    }

    #[test]
    fn security_test_dangerous_scheme_blocked() {
        let mut mgr = default_manager();

        assert!(mgr.open_tab("file:///etc/passwd").is_err());
        assert!(mgr.open_tab("data:text/html,<h1>xss</h1>").is_err());
        assert!(mgr.open_tab("javascript:alert(1)").is_err());
        assert!(mgr.open_tab("chrome://settings").is_err());
        assert!(mgr.open_tab("about:blank").is_err());

        // Invalid URL (no scheme) should also fail.
        assert!(mgr.open_tab("not-a-url").is_err());
    }

    #[test]
    fn security_test_tab_id_validated() {
        let mut mgr = default_manager();

        // Path traversal in tab ID.
        let result = mgr.close_tab("../../../etc/passwd");
        assert!(matches!(result.unwrap_err(), TabError::InvalidTabId(_)));

        // Spaces.
        let result = mgr.close_tab("tab with spaces");
        assert!(matches!(result.unwrap_err(), TabError::InvalidTabId(_)));

        // Empty.
        let result = mgr.close_tab("");
        assert!(matches!(result.unwrap_err(), TabError::InvalidTabId(_)));

        // Special characters.
        let result = mgr.close_tab("tab;rm -rf /");
        assert!(matches!(result.unwrap_err(), TabError::InvalidTabId(_)));

        // Valid tab IDs should pass validation (though tab won't exist).
        let result = mgr.close_tab("tab-1");
        assert!(matches!(result.unwrap_err(), TabError::TabNotFound(_)));
    }

    #[test]
    fn security_test_ipv6_mapped_private_blocked() {
        let mut mgr = default_manager();
        // ::ffff:127.0.0.1
        assert!(mgr.open_tab("http://[::ffff:127.0.0.1]/admin").is_err());
        // ::ffff:10.0.0.1
        assert!(mgr.open_tab("http://[::ffff:10.0.0.1]/admin").is_err());
        // ::ffff:192.168.1.1
        assert!(mgr
            .open_tab("http://[::ffff:192.168.1.1]/admin")
            .is_err());
    }

    #[test]
    fn test_unique_tab_ids() {
        let mut mgr = default_manager();
        let t1 = mgr.open_tab("https://a.com").unwrap();
        let t2 = mgr.open_tab("https://b.com").unwrap();
        let t3 = mgr.open_tab("https://c.com").unwrap();
        assert_ne!(t1.id, t2.id);
        assert_ne!(t2.id, t3.id);
        assert_ne!(t1.id, t3.id);
    }

    #[test]
    fn test_open_tab_deactivates_others() {
        let mut mgr = default_manager();
        let t1 = mgr.open_tab("https://a.com").unwrap();
        assert!(mgr.get_tab(&t1.id).unwrap().active);

        let t2 = mgr.open_tab("https://b.com").unwrap();
        assert!(!mgr.get_tab(&t1.id).unwrap().active);
        assert!(mgr.get_tab(&t2.id).unwrap().active);
    }

    // -- validate_tab_url unit tests ---------------------------------------

    #[test]
    fn test_validate_tab_url_accepts_https() {
        assert!(validate_tab_url("https://example.com", &[]).is_ok());
        assert!(validate_tab_url("http://example.com", &[]).is_ok());
    }

    #[test]
    fn test_validate_tab_url_rejects_ftp() {
        let result = validate_tab_url("ftp://example.com", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tab_url_rejects_empty() {
        let result = validate_tab_url("", &[]);
        assert!(result.is_err());
    }

    // -- validate_tab_id unit tests ----------------------------------------

    #[test]
    fn test_validate_tab_id_accepts_valid() {
        assert!(validate_tab_id("tab-1").is_ok());
        assert!(validate_tab_id("tab-abc-123").is_ok());
        assert!(validate_tab_id("abc").is_ok());
    }

    #[test]
    fn test_validate_tab_id_rejects_invalid() {
        assert!(validate_tab_id("").is_err());
        assert!(validate_tab_id("../etc").is_err());
        assert!(validate_tab_id("tab id").is_err());
        assert!(validate_tab_id("tab\x00id").is_err());
        assert!(validate_tab_id("tab/id").is_err());
    }
}
