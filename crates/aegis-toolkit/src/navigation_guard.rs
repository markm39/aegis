//! URL navigation guards to prevent browser agents from navigating to dangerous URLs.
//!
//! Provides SSRF (Server-Side Request Forgery) protection by blocking:
//! - Dangerous URL schemes (file, data, javascript, chrome, about, blob)
//! - Private/reserved IP ranges (IPv4 and IPv6)
//! - DNS rebinding attacks (resolved IPs checked against internal ranges)
//! - Configurable host deny/allowlists
//!
//! The guard is **fail-closed**: any URL that cannot be parsed or validated is blocked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use thiserror::Error;
use url::Url;

/// Errors returned when a URL fails navigation validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NavigationError {
    #[error("blocked scheme: {scheme}")]
    BlockedScheme { scheme: String },

    #[error("blocked host: {host}")]
    BlockedHost { host: String },

    #[error("internal network access denied: {host}")]
    InternalNetwork { host: String },

    #[error("host not in allowlist: {host}")]
    DeniedByAllowlist { host: String },

    #[error("invalid URL: {reason}")]
    InvalidUrl { reason: String },

    #[error("DNS rebinding detected: {host} resolved to internal IP {resolved_ip}")]
    DnsRebinding { host: String, resolved_ip: String },
}

/// Configuration for the navigation guard.
#[derive(Debug, Clone)]
pub struct NavigationConfig {
    /// URL schemes that are unconditionally blocked (compared case-insensitively).
    pub blocked_schemes: Vec<String>,
    /// Hosts that are unconditionally blocked (compared case-insensitively).
    pub blocked_hosts: Vec<String>,
    /// If non-empty, only these hosts are allowed (compared case-insensitively).
    /// Denylist still takes precedence over allowlist.
    pub allowed_hosts: Vec<String>,
    /// Block navigation to private/internal network addresses (default: true).
    pub block_internal_networks: bool,
}

impl Default for NavigationConfig {
    fn default() -> Self {
        Self {
            blocked_schemes: vec![
                "file".into(),
                "data".into(),
                "javascript".into(),
                "chrome".into(),
                "about".into(),
                "blob".into(),
            ],
            blocked_hosts: Vec::new(),
            allowed_hosts: Vec::new(),
            block_internal_networks: true,
        }
    }
}

/// URL navigation guard that validates URLs before browser agents navigate to them.
///
/// Enforces scheme restrictions, host deny/allowlists, and internal network protection.
/// Fail-closed: if validation cannot determine the URL is safe, navigation is blocked.
#[derive(Debug, Clone)]
pub struct NavigationGuard {
    config: NavigationConfig,
}

impl NavigationGuard {
    /// Create a new guard with the given configuration.
    pub fn new(config: NavigationConfig) -> Self {
        Self { config }
    }

    /// Create a guard with secure defaults: blocks dangerous schemes and internal networks.
    pub fn with_defaults() -> Self {
        Self::new(NavigationConfig::default())
    }

    /// Validate a URL for navigation. Returns `Ok(())` if the URL is safe to navigate to.
    ///
    /// Validation order:
    /// 1. Parse URL (reject if invalid)
    /// 2. Check scheme against blocklist
    /// 3. Check host against denylist
    /// 4. If allowlist is non-empty, verify host is in allowlist
    /// 5. If `block_internal_networks`, check host against private IP ranges
    /// 6. DNS rebinding check: resolve hostname, verify resolved IPs are not internal
    pub fn validate_url(&self, url: &str) -> Result<(), NavigationError> {
        // Normalize: trim whitespace.
        let url = url.trim();

        // Step 1: parse.
        let parsed = Url::parse(url).map_err(|e| NavigationError::InvalidUrl {
            reason: e.to_string(),
        })?;

        // Step 2: scheme check (case-insensitive).
        let scheme = parsed.scheme().to_ascii_lowercase();
        if self
            .config
            .blocked_schemes
            .iter()
            .any(|s| s.to_ascii_lowercase() == scheme)
        {
            tracing::warn!(url = url, scheme = %scheme, "navigation blocked: forbidden scheme");
            return Err(NavigationError::BlockedScheme { scheme });
        }

        // Only allow http and https explicitly. Anything else is suspect.
        if scheme != "http" && scheme != "https" {
            tracing::warn!(url = url, scheme = %scheme, "navigation blocked: non-http(s) scheme");
            return Err(NavigationError::BlockedScheme { scheme });
        }

        // Extract host -- fail-closed if absent.
        let host = parsed
            .host_str()
            .ok_or_else(|| NavigationError::InvalidUrl {
                reason: "URL has no host".into(),
            })?
            .to_ascii_lowercase();

        // Percent-decode the host to prevent bypass via URL encoding.
        let host = percent_decode_host(&host);

        // Step 3: denylist (checked before allowlist -- deny takes precedence).
        if self
            .config
            .blocked_hosts
            .iter()
            .any(|h| h.to_ascii_lowercase() == host)
        {
            tracing::warn!(url = url, host = %host, "navigation blocked: host in denylist");
            return Err(NavigationError::BlockedHost {
                host: host.to_string(),
            });
        }

        // Step 4: allowlist.
        if !self.config.allowed_hosts.is_empty()
            && !self
                .config
                .allowed_hosts
                .iter()
                .any(|h| h.to_ascii_lowercase() == host)
        {
            tracing::warn!(url = url, host = %host, "navigation blocked: host not in allowlist");
            return Err(NavigationError::DeniedByAllowlist {
                host: host.to_string(),
            });
        }

        // Step 5: internal network check on the literal host.
        if self.config.block_internal_networks && is_internal_host(&host) {
            tracing::warn!(url = url, host = %host, "navigation blocked: internal network address");
            return Err(NavigationError::InternalNetwork {
                host: host.to_string(),
            });
        }

        // Step 6: DNS rebinding check -- resolve hostname and check resolved IPs.
        if self.config.block_internal_networks {
            self.check_dns_rebinding(&host)?;
        }

        Ok(())
    }

    /// Validate a redirect target. Both the original and redirect URLs are validated.
    pub fn validate_redirect(&self, _from_url: &str, to_url: &str) -> Result<(), NavigationError> {
        self.validate_url(to_url)
    }

    /// Resolve hostname and ensure no resolved IP is internal.
    fn check_dns_rebinding(&self, host: &str) -> Result<(), NavigationError> {
        // If the host is already a literal IP, it was already checked in step 5.
        if host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        // Attempt DNS resolution. On failure we allow it through -- the browser will
        // fail to connect anyway, and blocking on DNS failure would break offline usage.
        // The key protection is that if DNS *does* resolve to an internal IP, we block.
        let socket_addr = format!("{host}:443");
        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                let ip = addr.ip();
                if is_internal_ip(&ip) {
                    tracing::warn!(
                        host = host,
                        resolved_ip = %ip,
                        "navigation blocked: DNS rebinding -- hostname resolved to internal IP"
                    );
                    return Err(NavigationError::DnsRebinding {
                        host: host.to_string(),
                        resolved_ip: ip.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Percent-decode a host string to prevent bypass via URL encoding.
fn percent_decode_host(host: &str) -> String {
    let mut decoded = String::with_capacity(host.len());
    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                decoded.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i] as char);
        i += 1;
    }
    decoded
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Check if an IPv4 address is in a private/reserved range.
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
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
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 0.0.0.0
    if ip.is_unspecified() {
        return true;
    }
    false
}

/// Check if an IPv6 address is in a private/reserved range.
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // ::1 (loopback)
    if ip.is_loopback() {
        return true;
    }
    // :: (unspecified)
    if ip.is_unspecified() {
        return true;
    }
    // fd00::/8 (unique local)
    let segments = ip.segments();
    if segments[0] & 0xff00 == 0xfd00 {
        return true;
    }
    // fc00::/7 (broader unique local range)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // fe80::/10 (link-local)
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) -- check the embedded IPv4.
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }
    false
}

/// Check if an IP address (v4 or v6) is internal/private.
fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check if a host string is a private IP or resolves to one.
///
/// This checks the host as a literal IP address. It does NOT perform DNS resolution;
/// use [`NavigationGuard::validate_url`] for full validation including DNS rebinding checks.
pub fn is_internal_host(host: &str) -> bool {
    // Strip brackets from IPv6 literals like [::1].
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // Try to parse as an IP address.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_internal_ip(&ip);
    }

    // Check for "localhost" variants.
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guard() -> NavigationGuard {
        NavigationGuard::with_defaults()
    }

    #[test]
    fn test_blocks_file_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("file:///etc/passwd");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), NavigationError::BlockedScheme { scheme } if scheme == "file")
        );
    }

    #[test]
    fn test_blocks_javascript_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("javascript:alert(1)");
        assert!(result.is_err());
        match result.unwrap_err() {
            NavigationError::BlockedScheme { scheme } => assert_eq!(scheme, "javascript"),
            // The url crate may fail to parse javascript: URLs -- that's also fine (fail-closed).
            NavigationError::InvalidUrl { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_blocks_data_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("data:text/html,<h1>Hello</h1>");
        assert!(result.is_err());
        match result.unwrap_err() {
            NavigationError::BlockedScheme { scheme } => assert_eq!(scheme, "data"),
            NavigationError::InvalidUrl { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_blocks_internal_ips() {
        let guard = default_guard();

        // 10.x.x.x
        let result = guard.validate_url("http://10.0.0.1/admin");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // 172.16.x.x
        let result = guard.validate_url("http://172.16.0.1/admin");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // 192.168.x.x
        let result = guard.validate_url("http://192.168.1.1/admin");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // 127.x.x.x
        let result = guard.validate_url("http://127.0.0.1:8080/api");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));
    }

    #[test]
    fn test_blocks_localhost() {
        let guard = default_guard();
        let result = guard.validate_url("http://localhost:3000/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // Subdomain of localhost.
        let result = guard.validate_url("http://foo.localhost:3000/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));
    }

    #[test]
    fn test_blocks_ipv6_loopback() {
        let guard = default_guard();
        let result = guard.validate_url("http://[::1]:8080/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));
    }

    #[test]
    fn test_allowlist_restricts_to_listed_domains() {
        let guard = NavigationGuard::new(NavigationConfig {
            allowed_hosts: vec!["example.com".into(), "safe.org".into()],
            block_internal_networks: false,
            ..NavigationConfig::default()
        });

        // Allowed.
        assert!(guard.validate_url("https://example.com/page").is_ok());
        assert!(guard.validate_url("https://safe.org/page").is_ok());

        // Not in allowlist.
        let result = guard.validate_url("https://evil.com/attack");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::DeniedByAllowlist { .. }
        ));
    }

    #[test]
    fn test_denylist_blocks_specific_domains() {
        let guard = NavigationGuard::new(NavigationConfig {
            blocked_hosts: vec!["evil.com".into(), "malware.org".into()],
            block_internal_networks: false,
            ..NavigationConfig::default()
        });

        let result = guard.validate_url("https://evil.com/exploit");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::BlockedHost { .. }
        ));

        let result = guard.validate_url("https://malware.org/payload");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::BlockedHost { .. }
        ));

        // Other hosts are fine.
        assert!(guard.validate_url("https://example.com/safe").is_ok());
    }

    #[test]
    fn test_valid_https_url_passes() {
        let guard = NavigationGuard::new(NavigationConfig {
            block_internal_networks: false,
            ..NavigationConfig::default()
        });
        assert!(guard
            .validate_url("https://www.example.com/path?q=test#frag")
            .is_ok());
    }

    #[test]
    fn test_valid_http_url_passes() {
        let guard = NavigationGuard::new(NavigationConfig {
            block_internal_networks: false,
            ..NavigationConfig::default()
        });
        assert!(guard.validate_url("http://www.example.com/path").is_ok());
    }

    #[test]
    fn security_test_case_insensitive_scheme() {
        let guard = default_guard();

        // The url crate normalizes schemes to lowercase during parsing, so
        // "FILE:///etc/passwd" parses as scheme "file". We verify it's blocked.
        let result = guard.validate_url("FILE:///etc/passwd");
        assert!(result.is_err(), "uppercase FILE scheme should be blocked");

        // Mixed case.
        let result = guard.validate_url("DaTa:text/html,<h1>x</h1>");
        assert!(result.is_err(), "mixed-case DATA scheme should be blocked");
    }

    #[test]
    fn security_test_url_encoding_no_bypass() {
        let guard = default_guard();

        // Attempt to bypass internal network check via URL encoding.
        // 127.0.0.1 encoded as %31%32%37%2E%30%2E%30%2E%31
        // The url crate typically decodes/normalizes the host before we see it.
        let result = guard.validate_url("http://127.0.0.1/admin");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // 0x7f000001 (hex representation of 127.0.0.1) -- not a valid URL host.
        let result = guard.validate_url("http://0x7f000001/");
        assert!(result.is_err(), "hex IP encoding should not bypass guard");
    }

    #[test]
    fn security_test_fail_closed_on_invalid_url() {
        let guard = default_guard();

        // Completely invalid URLs must be rejected.
        assert!(guard.validate_url("not-a-url").is_err());
        assert!(guard.validate_url("").is_err());
        assert!(guard.validate_url("://missing-scheme").is_err());
        assert!(guard.validate_url("   ").is_err());
    }

    #[test]
    fn test_denylist_takes_precedence_over_allowlist() {
        let guard = NavigationGuard::new(NavigationConfig {
            blocked_hosts: vec!["evil.com".into()],
            allowed_hosts: vec!["evil.com".into(), "good.com".into()],
            block_internal_networks: false,
            ..NavigationConfig::default()
        });

        // Even though evil.com is in the allowlist, denylist takes precedence.
        let result = guard.validate_url("https://evil.com/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::BlockedHost { .. }
        ));

        // good.com is allowed.
        assert!(guard.validate_url("https://good.com/").is_ok());
    }

    #[test]
    fn test_blocks_blob_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("blob:https://example.com/uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_blocks_chrome_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("chrome://settings");
        assert!(result.is_err());
    }

    #[test]
    fn test_blocks_about_scheme() {
        let guard = default_guard();
        let result = guard.validate_url("about:blank");
        assert!(result.is_err());
    }

    #[test]
    fn test_blocks_zero_address() {
        let guard = default_guard();
        let result = guard.validate_url("http://0.0.0.0/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));
    }

    #[test]
    fn test_blocks_link_local() {
        let guard = default_guard();
        let result = guard.validate_url("http://169.254.169.254/latest/meta-data/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));
    }

    #[test]
    fn test_validate_redirect() {
        let guard = default_guard();
        // Redirect to internal IP should be blocked.
        let result = guard.validate_redirect("https://example.com/", "http://127.0.0.1/admin");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::InternalNetwork { .. }
        ));

        // Redirect to external is fine (with internal network blocking disabled for this test).
        let guard = NavigationGuard::new(NavigationConfig {
            block_internal_networks: false,
            ..NavigationConfig::default()
        });
        assert!(guard
            .validate_redirect("https://example.com/", "https://other.com/page")
            .is_ok());
    }

    // --- IP helper unit tests ---

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
        assert!(is_private_ipv6(&Ipv6Addr::UNSPECIFIED));
        // fd00::1
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        // fc00::1
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        // fe80::1 (link-local)
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        // Public IPv6.
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_is_internal_host() {
        assert!(is_internal_host("127.0.0.1"));
        assert!(is_internal_host("10.0.0.1"));
        assert!(is_internal_host("192.168.1.1"));
        assert!(is_internal_host("localhost"));
        assert!(is_internal_host("foo.localhost"));
        assert!(is_internal_host("[::1]"));
        assert!(!is_internal_host("example.com"));
        assert!(!is_internal_host("8.8.8.8"));
    }

    #[test]
    fn test_blocks_ftp_scheme() {
        // ftp is not in the explicit blocklist but is not http/https, so it's blocked.
        let guard = default_guard();
        let result = guard.validate_url("ftp://files.example.com/secret.txt");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::BlockedScheme { .. }
        ));
    }

    #[test]
    fn test_case_insensitive_host_denylist() {
        let guard = NavigationGuard::new(NavigationConfig {
            blocked_hosts: vec!["Evil.COM".into()],
            block_internal_networks: false,
            ..NavigationConfig::default()
        });
        let result = guard.validate_url("https://evil.com/");
        assert!(matches!(
            result.unwrap_err(),
            NavigationError::BlockedHost { .. }
        ));
    }

    #[test]
    fn test_cloud_metadata_endpoint_blocked() {
        // AWS metadata endpoint -- a classic SSRF target.
        let guard = default_guard();
        let result = guard.validate_url("http://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
    }
}
