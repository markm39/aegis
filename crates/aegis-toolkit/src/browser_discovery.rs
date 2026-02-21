//! Cross-platform Chrome/Chromium binary discovery with security validation.
//!
//! Discovers installed Chrome-family browsers, parses their version strings,
//! validates binary paths against directory-traversal and symlink attacks,
//! and selects the best candidate (preferring Stable, then Chromium, etc.).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during browser discovery.
#[derive(Debug, Error)]
pub enum BrowserDiscoveryError {
    #[error("no Chrome or Chromium binary found on this system")]
    NoChromeFound,
    #[error("invalid binary path `{path}`: {reason}")]
    InvalidBinaryPath { path: String, reason: String },
    #[error("failed to parse version output")]
    VersionParseFailed,
    #[error("failed to execute binary: {0}")]
    ExecutionFailed(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Chrome channel enum
// ---------------------------------------------------------------------------

/// Release channel of a Chrome-family browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChromeChannel {
    Stable,
    Beta,
    Dev,
    Canary,
    Chromium,
    Unknown,
}

impl ChromeChannel {
    /// Lower number = higher preference when selecting the best candidate.
    fn preference_rank(self) -> u8 {
        match self {
            ChromeChannel::Stable => 0,
            ChromeChannel::Chromium => 1,
            ChromeChannel::Beta => 2,
            ChromeChannel::Dev => 3,
            ChromeChannel::Canary => 4,
            ChromeChannel::Unknown => 5,
        }
    }
}

impl std::fmt::Display for ChromeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChromeChannel::Stable => write!(f, "Stable"),
            ChromeChannel::Beta => write!(f, "Beta"),
            ChromeChannel::Dev => write!(f, "Dev"),
            ChromeChannel::Canary => write!(f, "Canary"),
            ChromeChannel::Chromium => write!(f, "Chromium"),
            ChromeChannel::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChromeInfo struct
// ---------------------------------------------------------------------------

/// Information about a discovered Chrome/Chromium binary.
#[derive(Debug, Clone)]
pub struct ChromeInfo {
    /// Absolute path to the binary.
    pub path: PathBuf,
    /// Parsed version string (e.g. "120.0.6099.109"), if available.
    pub version: Option<String>,
    /// Detected release channel.
    pub channel: ChromeChannel,
}

// ---------------------------------------------------------------------------
// Platform-specific candidate paths
// ---------------------------------------------------------------------------

/// Returns the list of well-known Chrome/Chromium binary paths for the
/// current platform. All paths are absolute.
pub fn platform_candidate_paths() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/opt/homebrew/bin/chromium",
        ]
    }

    #[cfg(target_os = "linux")]
    {
        &[
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
            "/usr/lib/chromium/chromium",
        ]
    }

    #[cfg(target_os = "windows")]
    {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        &[]
    }
}

// ---------------------------------------------------------------------------
// Version parsing
// ---------------------------------------------------------------------------

/// Parse the output of `chrome --version` into a (version, channel) pair.
///
/// Handles formats such as:
/// - "Google Chrome 120.0.6099.109"
/// - "Google Chrome Canary 121.0.6143.2"
/// - "Google Chrome Beta 121.0.6143.0"
/// - "Google Chrome Dev 122.0.6150.0"
/// - "Chromium 120.0.6099.0"
pub fn parse_chrome_version(output: &str) -> Option<(String, ChromeChannel)> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    // The version number is always the last whitespace-delimited token that
    // looks like a dotted numeric sequence (e.g. "120.0.6099.109").
    let version_str = trimmed
        .split_whitespace()
        .rev()
        .find(|token| is_version_token(token))?;

    let channel = detect_channel_from_output(trimmed);

    Some((version_str.to_string(), channel))
}

/// Returns true if `token` looks like a version number (digits and dots, at
/// least one dot).
fn is_version_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let has_dot = token.contains('.');
    let all_valid = token.chars().all(|c| c.is_ascii_digit() || c == '.');
    has_dot && all_valid
}

/// Determine the Chrome channel from the human-readable version string.
fn detect_channel_from_output(output: &str) -> ChromeChannel {
    let lower = output.to_ascii_lowercase();
    if lower.contains("canary") {
        ChromeChannel::Canary
    } else if lower.contains("dev") {
        ChromeChannel::Dev
    } else if lower.contains("beta") {
        ChromeChannel::Beta
    } else if lower.starts_with("chromium") {
        ChromeChannel::Chromium
    } else if lower.contains("chrome") {
        ChromeChannel::Stable
    } else {
        ChromeChannel::Unknown
    }
}

// ---------------------------------------------------------------------------
// Security validation
// ---------------------------------------------------------------------------

/// Validate a binary path for security before execution.
///
/// Rejects:
/// - Paths containing `..` (directory traversal).
/// - Paths inside temp directories (`/tmp`, `/var/tmp`, system temp on Windows).
/// - On Unix: symlinks whose resolved target is outside expected directories.
pub fn validate_binary_path(path: &Path) -> Result<(), BrowserDiscoveryError> {
    let path_str = path.to_string_lossy();

    // Reject directory traversal.
    if path.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(BrowserDiscoveryError::InvalidBinaryPath {
            path: path_str.into_owned(),
            reason: "path contains directory traversal (..)".to_string(),
        });
    }

    // Reject temp directories.
    let forbidden_prefixes: &[&str] = &[
        "/tmp",
        "/var/tmp",
        #[cfg(target_os = "windows")]
        r"C:\Windows\Temp",
    ];
    for prefix in forbidden_prefixes {
        if path_str.starts_with(prefix) {
            return Err(BrowserDiscoveryError::InvalidBinaryPath {
                path: path_str.into_owned(),
                reason: format!("path is inside a temp directory ({prefix})"),
            });
        }
    }

    // On Unix: if the path is a symlink, verify the target resolves to a
    // sensible location (not in /tmp, not traversal-based).
    #[cfg(unix)]
    {
        if path.is_symlink() {
            match std::fs::read_link(path) {
                Ok(target) => {
                    let resolved = if target.is_absolute() {
                        target
                    } else {
                        // Resolve relative symlinks against the link's parent.
                        path.parent()
                            .map(|p| p.join(&target))
                            .unwrap_or(target)
                    };
                    let resolved_str = resolved.to_string_lossy();

                    if resolved.components().any(|c| c == std::path::Component::ParentDir) {
                        return Err(BrowserDiscoveryError::InvalidBinaryPath {
                            path: path_str.into_owned(),
                            reason: format!(
                                "symlink target contains directory traversal: {}",
                                resolved_str
                            ),
                        });
                    }

                    for prefix in &["/tmp", "/var/tmp"] {
                        if resolved_str.starts_with(prefix) {
                            return Err(BrowserDiscoveryError::InvalidBinaryPath {
                                path: path_str.into_owned(),
                                reason: format!(
                                    "symlink target is inside a temp directory: {}",
                                    resolved_str
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(BrowserDiscoveryError::InvalidBinaryPath {
                        path: path_str.into_owned(),
                        reason: format!("failed to read symlink target: {e}"),
                    });
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery logic
// ---------------------------------------------------------------------------

/// Probe a single binary: validate it, run `--version`, and parse the output.
fn probe_binary(path: &Path) -> Result<ChromeInfo, BrowserDiscoveryError> {
    validate_binary_path(path)?;

    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(BrowserDiscoveryError::ExecutionFailed)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (version, channel) = parse_chrome_version(&stdout).unwrap_or_else(|| {
        // Fall back to channel detection from the path name itself.
        let path_lower = path.to_string_lossy().to_ascii_lowercase();
        let channel = if path_lower.contains("canary") {
            ChromeChannel::Canary
        } else if path_lower.contains("chromium") {
            ChromeChannel::Chromium
        } else if path_lower.contains("chrome") {
            ChromeChannel::Stable
        } else {
            ChromeChannel::Unknown
        };
        (String::new(), channel)
    });

    let version_opt = if version.is_empty() {
        None
    } else {
        Some(version)
    };

    Ok(ChromeInfo {
        path: path.to_path_buf(),
        version: version_opt,
        channel,
    })
}

/// Compare two candidates and return the better one.
///
/// Preference: lower channel rank wins; ties broken by higher version.
fn is_better_candidate(current: &ChromeInfo, challenger: &ChromeInfo) -> bool {
    let cur_rank = current.channel.preference_rank();
    let new_rank = challenger.channel.preference_rank();
    if new_rank < cur_rank {
        return true;
    }
    if new_rank > cur_rank {
        return false;
    }
    // Same channel -- prefer higher version.
    match (&challenger.version, &current.version) {
        (Some(new_v), Some(cur_v)) => compare_version_strings(new_v, cur_v) == std::cmp::Ordering::Greater,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Lexicographic numeric comparison of dotted version strings.
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a_parts = a.split('.');
    let mut b_parts = b.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (Some(ap), Some(bp)) => {
                let an: u64 = ap.parse().unwrap_or(0);
                let bn: u64 = bp.parse().unwrap_or(0);
                match an.cmp(&bn) {
                    std::cmp::Ordering::Equal => continue,
                    other => return other,
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

/// Discover the best Chrome/Chromium binary on this system.
///
/// If `configured_path` is `Some` and the file exists, it is used directly
/// (user configuration takes priority). Otherwise the platform candidate
/// list is searched and the best match is returned.
///
/// The discovered binary path and version are logged at `info` level for
/// audit trail purposes.
pub fn discover_chrome(
    configured_path: Option<&Path>,
) -> Result<ChromeInfo, BrowserDiscoveryError> {
    // User-configured path takes priority.
    if let Some(path) = configured_path {
        if path.exists() {
            let info = probe_binary(path)?;
            tracing::info!(
                path = %info.path.display(),
                version = ?info.version,
                channel = %info.channel,
                "chrome discovery: using user-configured binary"
            );
            return Ok(info);
        }
    }

    // Search platform candidates.
    let mut best: Option<ChromeInfo> = None;

    for candidate_str in platform_candidate_paths() {
        let candidate = Path::new(candidate_str);
        if !candidate.exists() {
            continue;
        }
        match probe_binary(candidate) {
            Ok(info) => {
                tracing::debug!(
                    path = %info.path.display(),
                    version = ?info.version,
                    channel = %info.channel,
                    "chrome discovery: found candidate"
                );
                let dominated = best
                    .as_ref()
                    .is_none_or(|current| is_better_candidate(current, &info));
                if dominated {
                    best = Some(info);
                }
            }
            Err(e) => {
                tracing::debug!(
                    path = candidate_str,
                    error = %e,
                    "chrome discovery: skipping candidate"
                );
            }
        }
    }

    match best {
        Some(info) => {
            tracing::info!(
                path = %info.path.display(),
                version = ?info.version,
                channel = %info.channel,
                "chrome discovery: selected best binary"
            );
            Ok(info)
        }
        None => Err(BrowserDiscoveryError::NoChromeFound),
    }
}

// ---------------------------------------------------------------------------
// Process-lifetime cache
// ---------------------------------------------------------------------------

/// Cached discovery result. The `OnceLock` is initialized on first call to
/// `discover_chrome_cached` and persists for the lifetime of the process.
static CACHED_CHROME: OnceLock<Result<ChromeInfo, String>> = OnceLock::new();

/// Like [`discover_chrome`], but caches the result for the process lifetime.
///
/// On success the same [`ChromeInfo`] is returned on every subsequent call.
/// On failure the error message is cached so we do not repeatedly re-scan.
pub fn discover_chrome_cached(
    configured_path: Option<&Path>,
) -> Result<&'static ChromeInfo, BrowserDiscoveryError> {
    let result = CACHED_CHROME.get_or_init(|| {
        discover_chrome(configured_path).map_err(|e| e.to_string())
    });

    match result {
        Ok(info) => Ok(info),
        Err(msg) => {
            // Reconstruct the most appropriate error variant from the cached
            // message. Since we lost the original enum variant, we match on
            // the message text.
            if msg.contains("no Chrome") {
                Err(BrowserDiscoveryError::NoChromeFound)
            } else {
                Err(BrowserDiscoveryError::VersionParseFailed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Candidate path tests -----------------------------------------------

    #[test]
    fn test_macos_candidate_paths() {
        // Verify the candidate list for macOS contains expected paths.
        #[cfg(target_os = "macos")]
        {
            let paths = platform_candidate_paths();
            assert!(paths.iter().any(|p| p.contains("Google Chrome.app")));
            assert!(paths.iter().any(|p| p.contains("Google Chrome Canary.app")));
            assert!(paths.iter().any(|p| p.contains("Chromium.app")));
            assert!(paths.iter().any(|p| *p == "/opt/homebrew/bin/chromium"));
            // All must be absolute.
            for p in paths {
                assert!(
                    p.starts_with('/'),
                    "candidate path is not absolute: {p}"
                );
            }
        }
    }

    #[test]
    fn test_linux_candidate_paths() {
        // Verify the candidate list for Linux contains expected paths.
        #[cfg(target_os = "linux")]
        {
            let paths = platform_candidate_paths();
            assert!(paths.iter().any(|p| *p == "/usr/bin/google-chrome-stable"));
            assert!(paths.iter().any(|p| *p == "/usr/bin/google-chrome"));
            assert!(paths.iter().any(|p| *p == "/usr/bin/chromium-browser"));
            assert!(paths.iter().any(|p| *p == "/usr/bin/chromium"));
            assert!(paths.iter().any(|p| *p == "/snap/bin/chromium"));
            assert!(paths.iter().any(|p| *p == "/usr/lib/chromium/chromium"));
            for p in paths {
                assert!(
                    p.starts_with('/'),
                    "candidate path is not absolute: {p}"
                );
            }
        }
    }

    // -- Version parsing tests ----------------------------------------------

    #[test]
    fn test_version_parsing() {
        let cases = vec![
            (
                "Google Chrome 120.0.6099.109",
                Some(("120.0.6099.109".to_string(), ChromeChannel::Stable)),
            ),
            (
                "Chromium 120.0.6099.0",
                Some(("120.0.6099.0".to_string(), ChromeChannel::Chromium)),
            ),
            (
                "Google Chrome Canary 121.0.6143.2",
                Some(("121.0.6143.2".to_string(), ChromeChannel::Canary)),
            ),
            (
                "Google Chrome Beta 121.0.6143.0",
                Some(("121.0.6143.0".to_string(), ChromeChannel::Beta)),
            ),
            (
                "Google Chrome Dev 122.0.6150.0",
                Some(("122.0.6150.0".to_string(), ChromeChannel::Dev)),
            ),
        ];

        for (input, expected) in cases {
            let result = parse_chrome_version(input);
            assert_eq!(
                result, expected,
                "parse_chrome_version({input:?}) mismatch"
            );
        }
    }

    #[test]
    fn test_version_parsing_edge_cases() {
        // Empty string.
        assert_eq!(parse_chrome_version(""), None);
        // Whitespace only.
        assert_eq!(parse_chrome_version("   "), None);
        // Garbage input with no version-like token.
        assert_eq!(parse_chrome_version("not a browser"), None);
        // Partial version (no dots) -- not a valid version token.
        assert_eq!(parse_chrome_version("Chrome 120"), None);
        // Leading/trailing whitespace should be handled.
        let result = parse_chrome_version("  Google Chrome 120.0.6099.109  ");
        assert!(result.is_some());
        let (ver, ch) = result.unwrap();
        assert_eq!(ver, "120.0.6099.109");
        assert_eq!(ch, ChromeChannel::Stable);
    }

    // -- Best-candidate selection -------------------------------------------

    #[test]
    fn test_best_candidate_prefers_stable() {
        let stable = ChromeInfo {
            path: PathBuf::from("/usr/bin/google-chrome-stable"),
            version: Some("120.0.6099.109".to_string()),
            channel: ChromeChannel::Stable,
        };
        let canary = ChromeInfo {
            path: PathBuf::from("/usr/bin/google-chrome-canary"),
            version: Some("121.0.6143.2".to_string()),
            channel: ChromeChannel::Canary,
        };
        // Stable should be preferred over Canary even though Canary has a
        // higher version number.
        assert!(!is_better_candidate(&stable, &canary));
    }

    #[test]
    fn test_best_candidate_same_channel_prefers_higher_version() {
        let older = ChromeInfo {
            path: PathBuf::from("/usr/bin/chrome-a"),
            version: Some("119.0.0.0".to_string()),
            channel: ChromeChannel::Stable,
        };
        let newer = ChromeInfo {
            path: PathBuf::from("/usr/bin/chrome-b"),
            version: Some("120.0.0.0".to_string()),
            channel: ChromeChannel::Stable,
        };
        assert!(is_better_candidate(&older, &newer));
        assert!(!is_better_candidate(&newer, &older));
    }

    // -- Configured path priority -------------------------------------------

    #[test]
    fn test_configured_path_takes_priority() {
        // When configured_path is set and exists, discover_chrome should use
        // it. We use an existing binary (/bin/echo) to verify the path is
        // accepted (its --version output won't parse as Chrome, but the
        // function should still succeed and return the configured path).
        #[cfg(unix)]
        {
            let echo_path = Path::new("/bin/echo");
            if echo_path.exists() {
                let result = discover_chrome(Some(echo_path));
                // The function should succeed (echo is a valid binary).
                assert!(result.is_ok());
                let info = result.unwrap();
                assert_eq!(info.path, echo_path);
            }
        }
    }

    // -- Security validation tests ------------------------------------------

    #[test]
    fn test_path_traversal_rejected() {
        let bad_path = Path::new("/usr/bin/../tmp/evil");
        let result = validate_binary_path(bad_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            BrowserDiscoveryError::InvalidBinaryPath { reason, .. } => {
                assert!(reason.contains("traversal"));
            }
            other => panic!("expected InvalidBinaryPath, got: {other:?}"),
        }
    }

    #[test]
    fn test_temp_directory_rejected() {
        let tmp_path = Path::new("/tmp/chrome");
        let result = validate_binary_path(tmp_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            BrowserDiscoveryError::InvalidBinaryPath { reason, .. } => {
                assert!(reason.contains("temp directory"));
            }
            other => panic!("expected InvalidBinaryPath, got: {other:?}"),
        }

        let var_tmp_path = Path::new("/var/tmp/chrome");
        let result2 = validate_binary_path(var_tmp_path);
        assert!(result2.is_err());
    }

    #[test]
    fn test_no_chrome_found_error() {
        // When no candidates exist and no configured path is given, we should
        // get NoChromeFound. We can't easily control the filesystem, so we
        // test with a nonexistent configured path and rely on the candidate
        // list (which may or may not find something). Instead, test the error
        // variant directly.
        let err = BrowserDiscoveryError::NoChromeFound;
        assert!(err.to_string().contains("no Chrome"));
    }

    // -- Version comparison -------------------------------------------------

    #[test]
    fn test_compare_version_strings() {
        assert_eq!(
            compare_version_strings("120.0.6099.109", "120.0.6099.109"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_version_strings("121.0.0.0", "120.0.6099.109"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("119.9.9999.9999", "120.0.0.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_version_strings("120.0.6099.110", "120.0.6099.109"),
            std::cmp::Ordering::Greater
        );
    }

    // -- Channel preference rank --------------------------------------------

    #[test]
    fn test_channel_preference_order() {
        assert!(ChromeChannel::Stable.preference_rank() < ChromeChannel::Chromium.preference_rank());
        assert!(ChromeChannel::Chromium.preference_rank() < ChromeChannel::Beta.preference_rank());
        assert!(ChromeChannel::Beta.preference_rank() < ChromeChannel::Dev.preference_rank());
        assert!(ChromeChannel::Dev.preference_rank() < ChromeChannel::Canary.preference_rank());
        assert!(ChromeChannel::Canary.preference_rank() < ChromeChannel::Unknown.preference_rank());
    }

    // -- Validate known-good paths ------------------------------------------

    #[test]
    fn test_valid_path_accepted() {
        let good_path = Path::new("/usr/bin/google-chrome-stable");
        assert!(validate_binary_path(good_path).is_ok());

        let mac_path = Path::new(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        );
        assert!(validate_binary_path(mac_path).is_ok());
    }
}
