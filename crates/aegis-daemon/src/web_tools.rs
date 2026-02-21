// Web fetch and search tools with SSRF protection.

use std::fmt;
use std::io::Read as IoRead;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::Url;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum WebToolError {
    SsrfBlocked(String),
    InvalidUrl(String),
    DnsResolutionFailed(String),
    RequestFailed(String),
    ResponseTooLarge(usize),
    BlockedDomain(String),
    MissingApiKey(&'static str),
    SearchError(String),
}

impl fmt::Display for WebToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SsrfBlocked(msg) => write!(f, "SSRF blocked: {msg}"),
            Self::InvalidUrl(msg) => write!(f, "invalid URL: {msg}"),
            Self::DnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {msg}"),
            Self::RequestFailed(msg) => write!(f, "HTTP request failed: {msg}"),
            Self::ResponseTooLarge(max) => write!(f, "response too large (>{max} bytes)"),
            Self::BlockedDomain(domain) => write!(f, "blocked domain: {domain}"),
            Self::MissingApiKey(msg) => write!(f, "missing API key: {msg}"),
            Self::SearchError(msg) => write!(f, "search backend error: {msg}"),
        }
    }
}

impl std::error::Error for WebToolError {}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_timeout() -> u64 {
    30
}

fn default_max_bytes() -> usize {
    5 * 1024 * 1024 // 5 MB
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebToolsConfig {
    /// Request timeout in seconds (default 30).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Max response body size in bytes (default 5 MB).
    #[serde(default = "default_max_bytes")]
    pub max_response_bytes: usize,
    /// Search backend to use.
    #[serde(default)]
    pub search_backend: SearchBackend,
    /// API key for search backend (or AEGIS_SEARCH_API_KEY env var).
    #[serde(default)]
    pub search_api_key: Option<String>,
    /// Domains to always block.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
}

impl Default for WebToolsConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout(),
            max_response_bytes: default_max_bytes(),
            search_backend: SearchBackend::default(),
            search_api_key: None,
            blocked_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SearchBackend {
    #[default]
    Perplexity,
    DuckDuckGo,
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Check if an IP address is in a private/reserved range that should be blocked.
fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 10.0.0.0/8 (private)
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 (private) -- 172.16.x.x through 172.31.x.x
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16 (private)
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 0.0.0.0/8 (current network)
    if octets[0] == 0 {
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
    // fd00::/8 (unique local)
    if segments[0] & 0xff00 == 0xfd00 {
        return true;
    }
    // fc00::/7 (unique local -- includes fd00::/8)
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

/// Validate a URL for safety: parse, resolve DNS, check IPs against blocklist.
pub fn validate_url(raw_url: &str) -> Result<Url, WebToolError> {
    let parsed = Url::parse(raw_url).map_err(|e| WebToolError::InvalidUrl(e.to_string()))?;

    // Require http or https
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(WebToolError::InvalidUrl(format!(
                "unsupported scheme: {other}"
            )));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| WebToolError::InvalidUrl("no host in URL".into()))?;

    // If the host is already an IP literal, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(WebToolError::SsrfBlocked(format!(
                "private IP address: {ip}"
            )));
        }
        return Ok(parsed);
    }

    // DNS resolution
    let port = parsed.port().unwrap_or(match parsed.scheme() {
        "https" => 443,
        _ => 80,
    });
    let socket_addr = format!("{host}:{port}");
    let addrs: Vec<_> = socket_addr
        .to_socket_addrs()
        .map_err(|e| WebToolError::DnsResolutionFailed(format!("{host}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(WebToolError::DnsResolutionFailed(format!(
            "{host}: no addresses returned"
        )));
    }

    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(WebToolError::SsrfBlocked(format!(
                "host {host} resolves to private address {}",
                addr.ip()
            )));
        }
    }

    Ok(parsed)
}

// ---------------------------------------------------------------------------
// web_fetch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFetchResult {
    pub url: String,
    pub status_code: u16,
    pub content_type: String,
    pub body_text: String,
    pub truncated: bool,
}

/// Fetch a URL with SSRF protection and content extraction.
pub fn web_fetch(url: &str, config: &WebToolsConfig) -> Result<WebFetchResult, WebToolError> {
    let validated = validate_url(url)?;

    // Check blocked domains
    if let Some(host) = validated.host_str() {
        let host_lower = host.to_lowercase();
        for blocked in &config.blocked_domains {
            let blocked_lower = blocked.to_lowercase();
            if host_lower == blocked_lower || host_lower.ends_with(&format!(".{blocked_lower}")) {
                return Err(WebToolError::BlockedDomain(host.to_string()));
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| WebToolError::RequestFailed(e.to_string()))?;

    let resp = client
        .get(validated.as_str())
        .header("User-Agent", "aegis-web-tools/0.1")
        .send()
        .map_err(|e| WebToolError::RequestFailed(e.to_string()))?;

    let status_code = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Read body up to max_response_bytes
    let max = config.max_response_bytes;
    let mut body_bytes = Vec::new();
    let mut reader = resp.take(max as u64 + 1);
    reader
        .read_to_end(&mut body_bytes)
        .map_err(|e| WebToolError::RequestFailed(format!("reading body: {e}")))?;

    let truncated = body_bytes.len() > max;
    if truncated {
        body_bytes.truncate(max);
    }

    let raw_text = String::from_utf8_lossy(&body_bytes).into_owned();

    // If HTML, convert to plain text
    let body_text = if content_type.contains("text/html") {
        simple_html_to_text(&raw_text)
    } else {
        raw_text
    };

    Ok(WebFetchResult {
        url: validated.to_string(),
        status_code,
        content_type,
        body_text,
        truncated,
    })
}

/// Simple HTML-to-text conversion by stripping tags.
fn simple_html_to_text(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut chars = html.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == '<' {
            // Check if this is a script or style opening tag
            let tag_start: String = chars.clone().take(20).collect::<String>().to_lowercase();
            if tag_start.starts_with("<script") {
                // Skip until </script>
                skip_until_closing_tag(&mut chars, "script");
                result.push(' ');
                continue;
            }
            if tag_start.starts_with("<style") {
                // Skip until </style>
                skip_until_closing_tag(&mut chars, "style");
                result.push(' ');
                continue;
            }
            // Skip the tag, insert space so adjacent text doesn't merge
            for c in chars.by_ref() {
                if c == '>' {
                    break;
                }
            }
            result.push(' ');
        } else if ch == '&' {
            // Decode HTML entity
            let entity = decode_html_entity(&mut chars);
            result.push_str(&entity);
        } else {
            result.push(ch);
            chars.next();
        }
    }

    collapse_whitespace(&result)
}

fn skip_until_closing_tag(chars: &mut std::iter::Peekable<std::str::Chars>, tag: &str) {
    let close = format!("</{tag}>");
    let close_upper = close.to_uppercase();
    let mut buffer = String::new();
    for c in chars.by_ref() {
        buffer.push(c);
        if buffer.len() >= close.len() {
            let tail: String = buffer[buffer.len() - close.len()..].to_lowercase();
            if tail == close || tail == close_upper.to_lowercase() {
                return;
            }
        }
    }
}

fn decode_html_entity(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    // Consume the '&'
    chars.next();
    let mut entity = String::new();
    for c in chars.by_ref() {
        if c == ';' {
            break;
        }
        entity.push(c);
        // Limit entity length to avoid runaway
        if entity.len() > 10 {
            return format!("&{entity}");
        }
    }
    match entity.as_str() {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        "nbsp" => " ".to_string(),
        _ if entity.starts_with('#') => {
            decode_numeric_entity(&entity[1..]).unwrap_or_else(|| format!("&{entity};"))
        }
        _ => format!("&{entity};"),
    }
}

fn decode_numeric_entity(s: &str) -> Option<String> {
    let code = if let Some(hex) = s.strip_prefix('x').or_else(|| s.strip_prefix('X')) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        s.parse::<u32>().ok()?
    };
    char::from_u32(code).map(|c| c.to_string())
}

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
// web_search
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSearchResult {
    pub query: String,
    pub results: Vec<SearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Search the web via configured backend.
pub fn web_search(query: &str, config: &WebToolsConfig) -> Result<WebSearchResult, WebToolError> {
    let api_key = config
        .search_api_key
        .clone()
        .or_else(|| std::env::var("AEGIS_SEARCH_API_KEY").ok());

    match config.search_backend {
        SearchBackend::Perplexity => search_perplexity(query, &api_key, config),
        SearchBackend::DuckDuckGo => search_duckduckgo(query, config),
    }
}

fn search_perplexity(
    query: &str,
    api_key: &Option<String>,
    config: &WebToolsConfig,
) -> Result<WebSearchResult, WebToolError> {
    let key = api_key
        .as_deref()
        .ok_or(WebToolError::MissingApiKey("Perplexity requires AEGIS_SEARCH_API_KEY or search_api_key in config"))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| WebToolError::RequestFailed(e.to_string()))?;

    let body = serde_json::json!({
        "model": "sonar",
        "messages": [
            {
                "role": "system",
                "content": "Return concise search results with source URLs."
            },
            {
                "role": "user",
                "content": query
            }
        ],
        "max_tokens": 1024
    });

    let resp = client
        .post("https://api.perplexity.ai/chat/completions")
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| WebToolError::SearchError(format!("Perplexity request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        return Err(WebToolError::SearchError(format!(
            "Perplexity returned {status}: {body_text}"
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .map_err(|e| WebToolError::SearchError(format!("failed to parse Perplexity response: {e}")))?;

    // Extract citations and content from the Perplexity response.
    // Perplexity returns citations as an array of URLs alongside the answer.
    let citations: Vec<String> = json
        .pointer("/citations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let answer = json
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut results = Vec::new();

    if citations.is_empty() {
        // No citations -- return the answer as a single result.
        if !answer.is_empty() {
            results.push(SearchHit {
                title: format!("Perplexity answer for: {query}"),
                url: String::new(),
                snippet: answer.to_string(),
            });
        }
    } else {
        for (i, citation_url) in citations.iter().enumerate() {
            results.push(SearchHit {
                title: format!("Result {}", i + 1),
                url: citation_url.clone(),
                snippet: if i == 0 {
                    answer.to_string()
                } else {
                    String::new()
                },
            });
        }
    }

    Ok(WebSearchResult {
        query: query.to_string(),
        results,
    })
}

fn search_duckduckgo(
    query: &str,
    config: &WebToolsConfig,
) -> Result<WebSearchResult, WebToolError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| WebToolError::RequestFailed(e.to_string()))?;

    let resp = client
        .get("https://html.duckduckgo.com/html/")
        .query(&[("q", query)])
        .header("User-Agent", "aegis-web-tools/0.1")
        .send()
        .map_err(|e| WebToolError::SearchError(format!("DuckDuckGo request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(WebToolError::SearchError(format!(
            "DuckDuckGo returned {status}"
        )));
    }

    let html = resp
        .text()
        .map_err(|e| WebToolError::SearchError(format!("failed to read DuckDuckGo response: {e}")))?;

    let results = parse_duckduckgo_html(&html);

    Ok(WebSearchResult {
        query: query.to_string(),
        results,
    })
}

/// Parse DuckDuckGo HTML search results page.
/// Looks for result links in the class="result__a" anchor tags
/// and snippets in class="result__snippet".
fn parse_duckduckgo_html(html: &str) -> Vec<SearchHit> {
    let mut results = Vec::new();

    // DuckDuckGo HTML results have a pattern:
    //   <a class="result__a" href="URL">TITLE</a>
    //   <a class="result__snippet" href="...">SNIPPET</a>
    //
    // We do a simple line-by-line parse to extract these.
    let mut current_title = String::new();
    let mut current_url = String::new();

    for line in html.lines() {
        let trimmed = line.trim();

        // Look for result link
        if trimmed.contains("class=\"result__a\"") {
            if let Some(href) = extract_attr(trimmed, "href") {
                current_url = resolve_ddg_redirect(&href);
            }
            current_title = extract_tag_text(trimmed);
        }

        // Look for snippet
        if trimmed.contains("class=\"result__snippet\"") {
            let snippet = extract_tag_text(trimmed);
            if !current_url.is_empty() {
                results.push(SearchHit {
                    title: std::mem::take(&mut current_title),
                    url: std::mem::take(&mut current_url),
                    snippet,
                });
            }
        }
    }

    // Cap at 10 results
    results.truncate(10);
    results
}

/// Extract the value of an HTML attribute from a tag string.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    let start = tag.find(&pattern)? + pattern.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract text content from an HTML tag, stripping inner tags.
fn extract_tag_text(tag: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    // Find the first > to skip the opening tag
    let content_start = tag.find('>').map(|i| i + 1).unwrap_or(0);
    for ch in tag[content_start..].chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }
    result.trim().to_string()
}

/// Resolve DuckDuckGo redirect URLs.
/// DDG wraps links like: //duckduckgo.com/l/?uddg=ENCODED_URL&...
fn resolve_ddg_redirect(href: &str) -> String {
    if href.contains("uddg=") {
        if let Some(start) = href.find("uddg=") {
            let rest = &href[start + 5..];
            let end = rest.find('&').unwrap_or(rest.len());
            let encoded = &rest[..end];
            if let Ok(decoded) = urlencoding_decode(encoded) {
                return decoded;
            }
        }
    }
    // If not a redirect, return as-is (prepend https: if starts with //)
    if let Some(stripped) = href.strip_prefix("//") {
        format!("https://{stripped}")
    } else {
        href.to_string()
    }
}

/// Simple percent-decoding (enough for URL redirect values).
fn urlencoding_decode(s: &str) -> Result<String, ()> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| ())?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| ())?;
            result.push(byte);
            i += 3;
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_private_ip tests --

    #[test]
    fn test_private_ipv4_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "127.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv4_10_range() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv4_172_range() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "172.31.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
        // 172.15.x and 172.32.x should NOT be private
        let ip: IpAddr = "172.15.0.1".parse().unwrap();
        assert!(!is_private_ip(&ip));
        let ip: IpAddr = "172.32.0.1".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv4_192_168() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv4_link_local() {
        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "169.254.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv4_zero() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_public_ipv4() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&ip));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_private_ip(&ip));
        let ip: IpAddr = "142.250.80.46".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv6_unique_local() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "fd12:3456::1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_private_ipv6_mapped_v4() {
        // ::ffff:127.0.0.1
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        // ::ffff:10.0.0.1
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        // ::ffff:192.168.1.1
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_public_ipv6() {
        let ip: IpAddr = "2607:f8b0:4004:800::200e".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_ipv6_mapped_public_v4() {
        // ::ffff:8.8.8.8 should be public
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    // -- validate_url tests --

    #[test]
    fn test_validate_url_rejects_ftp() {
        let result = validate_url("ftp://example.com/file.txt");
        assert!(matches!(result, Err(WebToolError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_url_rejects_file() {
        let result = validate_url("file:///etc/passwd");
        assert!(matches!(result, Err(WebToolError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_url_rejects_javascript() {
        let result = validate_url("javascript:alert(1)");
        assert!(matches!(result, Err(WebToolError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_url_rejects_private_ip_host() {
        let result = validate_url("http://127.0.0.1/admin");
        assert!(matches!(result, Err(WebToolError::SsrfBlocked(_))));

        let result = validate_url("http://10.0.0.1/internal");
        assert!(matches!(result, Err(WebToolError::SsrfBlocked(_))));

        let result = validate_url("http://192.168.1.1/router");
        assert!(matches!(result, Err(WebToolError::SsrfBlocked(_))));

        let result = validate_url("http://[::1]/admin");
        assert!(matches!(result, Err(WebToolError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_url_accepts_https() {
        // Use a public IP to avoid DNS resolution dependency in tests.
        let result = validate_url("https://8.8.8.8");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_rejects_no_host() {
        let result = validate_url("http://");
        assert!(result.is_err());
    }

    // -- simple_html_to_text tests --

    #[test]
    fn test_strip_basic_tags() {
        let html = "<p>Hello <b>world</b></p>";
        let text = simple_html_to_text(html);
        assert_eq!(text, "Hello world");
    }

    #[test]
    fn test_strip_script_blocks() {
        let html = "<p>Before</p><script>var x = 1;</script><p>After</p>";
        let text = simple_html_to_text(html);
        assert_eq!(text, "Before After");
    }

    #[test]
    fn test_strip_style_blocks() {
        let html = "<style>.cls { color: red; }</style><p>Content</p>";
        let text = simple_html_to_text(html);
        assert_eq!(text, "Content");
    }

    #[test]
    fn test_decode_html_entities() {
        let html = "&amp; &lt; &gt; &quot;";
        let text = simple_html_to_text(html);
        assert_eq!(text, "& < > \"");
    }

    #[test]
    fn test_collapse_whitespace() {
        let html = "<p>  Hello   world  </p>";
        let text = simple_html_to_text(html);
        assert_eq!(text, "Hello world");
    }

    #[test]
    fn test_numeric_entity() {
        let html = "&#65;&#x42;";
        let text = simple_html_to_text(html);
        assert_eq!(text, "AB");
    }

    #[test]
    fn test_nbsp_entity() {
        let html = "Hello&nbsp;World";
        let text = simple_html_to_text(html);
        assert_eq!(text, "Hello World");
    }

    // -- WebToolsConfig tests --

    #[test]
    fn test_config_defaults() {
        let config = WebToolsConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_response_bytes, 5 * 1024 * 1024);
        assert_eq!(config.search_backend, SearchBackend::Perplexity);
        assert!(config.search_api_key.is_none());
        assert!(config.blocked_domains.is_empty());
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = WebToolsConfig {
            timeout_secs: 15,
            max_response_bytes: 1024,
            search_backend: SearchBackend::DuckDuckGo,
            search_api_key: Some("test-key".into()),
            blocked_domains: vec!["evil.com".into()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: WebToolsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.timeout_secs, 15);
        assert_eq!(deserialized.max_response_bytes, 1024);
        assert_eq!(deserialized.search_backend, SearchBackend::DuckDuckGo);
        assert_eq!(deserialized.search_api_key.as_deref(), Some("test-key"));
        assert_eq!(deserialized.blocked_domains, vec!["evil.com"]);
    }

    #[test]
    fn test_config_deserialize_with_defaults() {
        let json = "{}";
        let config: WebToolsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_response_bytes, 5 * 1024 * 1024);
        assert_eq!(config.search_backend, SearchBackend::Perplexity);
    }

    // -- DuckDuckGo HTML parser tests --

    #[test]
    fn test_extract_attr() {
        let tag = r#"<a class="result__a" href="https://example.com">Title</a>"#;
        assert_eq!(
            extract_attr(tag, "href"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            extract_attr(tag, "class"),
            Some("result__a".to_string())
        );
        assert_eq!(extract_attr(tag, "id"), None);
    }

    #[test]
    fn test_extract_tag_text() {
        let tag = r#"<a class="result__a" href="https://example.com">Hello <b>World</b></a>"#;
        assert_eq!(extract_tag_text(tag), "Hello World");
    }

    #[test]
    fn test_resolve_ddg_redirect() {
        let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc";
        assert_eq!(resolve_ddg_redirect(href), "https://example.com/page");
    }

    #[test]
    fn test_resolve_ddg_redirect_plain_url() {
        let href = "https://example.com/direct";
        assert_eq!(resolve_ddg_redirect(href), "https://example.com/direct");
    }

    #[test]
    fn test_resolve_ddg_protocol_relative() {
        let href = "//example.com/page";
        assert_eq!(resolve_ddg_redirect(href), "https://example.com/page");
    }

    #[test]
    fn test_urlencoding_decode() {
        assert_eq!(
            urlencoding_decode("hello%20world").unwrap(),
            "hello world"
        );
        assert_eq!(
            urlencoding_decode("hello+world").unwrap(),
            "hello world"
        );
        assert_eq!(
            urlencoding_decode("https%3A%2F%2Fexample.com").unwrap(),
            "https://example.com"
        );
    }

    // -- web_search error handling --

    #[test]
    fn test_search_perplexity_missing_key() {
        let config = WebToolsConfig {
            search_backend: SearchBackend::Perplexity,
            search_api_key: None,
            ..Default::default()
        };
        // Temporarily unset the env var to ensure the test is deterministic
        let saved = std::env::var("AEGIS_SEARCH_API_KEY").ok();
        std::env::remove_var("AEGIS_SEARCH_API_KEY");
        let result = web_search("test query", &config);
        // Restore
        if let Some(val) = saved {
            std::env::set_var("AEGIS_SEARCH_API_KEY", val);
        }
        assert!(matches!(result, Err(WebToolError::MissingApiKey(_))));
    }
}
