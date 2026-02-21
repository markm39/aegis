//! Reusable OAuth2 framework for provider integrations.
//!
//! Provides a secure, generic OAuth2 authorization code flow with PKCE support.
//!
//! # Security
//!
//! - Client secrets are **never** stored directly; `client_secret_env` names the
//!   environment variable that holds the secret at runtime.
//! - Tokens are stored on disk with `0600` permissions (owner read/write only).
//! - Access tokens and refresh tokens are masked in all `Debug` and `Display` output.
//! - Token endpoint URLs are validated against SSRF (private/loopback IPs blocked).
//! - All HTTP requests require HTTPS (plain `http://` URLs are rejected).
//! - PKCE uses SHA-256 (`S256` challenge method) for public client security.
//! - Provider names are validated against directory traversal (`..` rejected).
//! - State parameter for CSRF protection is provided by the caller and validated
//!   at the application layer.

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config_loader::mask_sensitive;
use crate::AegisError;

// ---------------------------------------------------------------------------
// OAuthConfig
// ---------------------------------------------------------------------------

/// Configuration for an OAuth2 provider integration.
///
/// The `client_secret_env` field stores the **name** of the environment variable
/// that holds the OAuth2 client secret. The actual secret is read at runtime via
/// `std::env::var(client_secret_env)` and is never persisted in config files.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthConfig {
    /// OAuth2 client ID.
    pub client_id: String,

    /// Name of the environment variable holding the OAuth2 client secret.
    /// Must be a valid environment variable name (uppercase, underscores).
    pub client_secret_env: String,

    /// Authorization endpoint URL (must be HTTPS).
    pub auth_url: String,

    /// Token endpoint URL (must be HTTPS).
    pub token_url: String,

    /// OAuth2 scopes to request.
    pub scopes: Vec<String>,

    /// Redirect URI for the authorization callback.
    pub redirect_uri: String,
}

impl fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("client_id", &self.client_id)
            .field("client_secret_env", &self.client_secret_env)
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl OAuthConfig {
    /// Read the client secret from the configured environment variable.
    ///
    /// Returns an error if the variable is unset or empty.
    pub fn read_client_secret(&self) -> Result<String, AegisError> {
        let secret = std::env::var(&self.client_secret_env).map_err(|_| {
            AegisError::ConfigError(format!(
                "environment variable '{}' not set (required for OAuth2 client secret)",
                self.client_secret_env
            ))
        })?;
        if secret.is_empty() {
            return Err(AegisError::ConfigError(format!(
                "environment variable '{}' is empty",
                self.client_secret_env
            )));
        }
        Ok(secret)
    }
}

// ---------------------------------------------------------------------------
// OAuthToken
// ---------------------------------------------------------------------------

/// An OAuth2 token pair with expiry tracking.
///
/// Both `access_token` and `refresh_token` are masked in `Debug` and `Display`
/// output to prevent accidental exposure in logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// The short-lived access token for API calls.
    pub access_token: String,

    /// The long-lived refresh token for obtaining new access tokens.
    pub refresh_token: String,

    /// When the access token expires. `None` means unknown (treated as expired).
    pub expires_at: Option<DateTime<Utc>>,

    /// Scope granted by the authorization server (may differ from requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl OAuthToken {
    /// Check whether the access token has expired (with a 60-second safety margin).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp - chrono::Duration::seconds(60),
            None => true,
        }
    }
}

impl fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthToken")
            .field("access_token", &mask_sensitive(&self.access_token))
            .field("refresh_token", &mask_sensitive(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

impl fmt::Display for OAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OAuthToken(access={}, refresh={}, expires_at={:?})",
            mask_sensitive(&self.access_token),
            mask_sensitive(&self.refresh_token),
            self.expires_at,
        )
    }
}

// ---------------------------------------------------------------------------
// OAuthTokenStore trait
// ---------------------------------------------------------------------------

/// Trait for persistent OAuth2 token storage.
///
/// Implementations must store tokens securely (e.g., with restrictive file
/// permissions) since they contain sensitive credentials.
pub trait OAuthTokenStore: Send + Sync {
    /// Load the stored token, returning `None` if no token exists.
    fn load(&self) -> Result<Option<OAuthToken>, AegisError>;

    /// Persist a token to the store.
    fn save(&self, token: &OAuthToken) -> Result<(), AegisError>;

    /// Delete the stored token.
    fn delete(&self) -> Result<(), AegisError>;
}

// ---------------------------------------------------------------------------
// FileTokenStore
// ---------------------------------------------------------------------------

/// File-backed token store at `~/.aegis/oauth/{provider}/token.json`.
///
/// Tokens are stored as JSON with `0600` file permissions on Unix systems.
/// Provider names are validated to prevent directory traversal attacks.
pub struct FileTokenStore {
    path: PathBuf,
}

impl FileTokenStore {
    /// Create a new file token store for the given provider.
    ///
    /// The provider name must be alphanumeric (plus hyphens and underscores).
    /// Directory traversal components (`..`) are rejected.
    pub fn new(provider: &str) -> Result<Self, AegisError> {
        validate_provider_name(provider)?;

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let path = PathBuf::from(home)
            .join(".aegis")
            .join("oauth")
            .join(provider)
            .join("token.json");

        Ok(Self { path })
    }

    /// Create a file token store at an explicit path (for testing).
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Return the store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl OAuthTokenStore for FileTokenStore {
    fn load(&self) -> Result<Option<OAuthToken>, AegisError> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&self.path).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to read token file '{}': {e}",
                self.path.display()
            ))
        })?;

        let token: OAuthToken = serde_json::from_str(&content).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to parse token file '{}': {e}",
                self.path.display()
            ))
        })?;

        Ok(Some(token))
    }

    fn save(&self, token: &OAuthToken) -> Result<(), AegisError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to create token directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        let content = serde_json::to_string_pretty(token).map_err(|e| {
            AegisError::ConfigError(format!("failed to serialize token: {e}"))
        })?;

        std::fs::write(&self.path, &content).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to write token file '{}': {e}",
                self.path.display()
            ))
        })?;

        set_file_permissions_0600(&self.path)?;

        Ok(())
    }

    fn delete(&self) -> Result<(), AegisError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to delete token file '{}': {e}",
                    self.path.display()
                ))
            })?;
        }
        Ok(())
    }
}

/// Set a file's permissions to `0600` on Unix systems.
#[cfg(unix)]
fn set_file_permissions_0600(path: &Path) -> Result<(), AegisError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        AegisError::ConfigError(format!(
            "failed to set permissions on '{}': {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_file_permissions_0600(_path: &Path) -> Result<(), AegisError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// PKCE support
// ---------------------------------------------------------------------------

/// PKCE (Proof Key for Code Exchange) parameters.
///
/// Used to protect the authorization code flow for public clients.
/// The `code_verifier` is a high-entropy random string, and the
/// `code_challenge` is its SHA-256 hash encoded as base64url.
pub struct PkceChallenge {
    /// The random code verifier (kept secret, sent during token exchange).
    pub code_verifier: String,

    /// The SHA-256 challenge derived from the verifier (sent during authorization).
    pub code_challenge: String,
}

impl PkceChallenge {
    /// Generate a new PKCE challenge pair using SHA-256 (S256 method).
    ///
    /// The code_verifier is derived from cryptographically random UUIDs
    /// to produce a 43-character base64url string (per RFC 7636).
    pub fn generate() -> Self {
        // Generate 32 bytes of randomness from UUID v4 (uses getrandom).
        // Two UUID v4s provide 32 random bytes (16 bytes each, minus fixed bits,
        // but the resulting entropy is sufficient for PKCE).
        let u1 = uuid::Uuid::new_v4();
        let u2 = uuid::Uuid::new_v4();
        let mut random_bytes = [0u8; 32];
        random_bytes[..16].copy_from_slice(u1.as_bytes());
        random_bytes[16..].copy_from_slice(u2.as_bytes());

        let code_verifier = base64url_encode_no_pad(&random_bytes);
        let code_challenge = compute_s256_challenge(&code_verifier);

        Self {
            code_verifier,
            code_challenge,
        }
    }

    /// Compute the S256 challenge for a given verifier (for validation/testing).
    pub fn challenge_for(verifier: &str) -> String {
        compute_s256_challenge(verifier)
    }
}

/// Compute the S256 PKCE code_challenge from a code_verifier.
///
/// `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`
fn compute_s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    base64url_encode_no_pad(&hash)
}

/// Base64url encode without padding (RFC 4648 section 5).
fn base64url_encode_no_pad(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// Validate that a URL uses HTTPS and does not point to a private/loopback address.
///
/// This blocks SSRF attacks where an attacker might trick the OAuth flow into
/// making requests to internal services.
fn validate_token_url(url: &str) -> Result<(), AegisError> {
    // Must be HTTPS
    if !url.starts_with("https://") {
        return Err(AegisError::ConfigError(format!(
            "token URL must use HTTPS, got: {url}"
        )));
    }

    // Extract host from URL
    let host = extract_host(url).ok_or_else(|| {
        AegisError::ConfigError(format!("cannot parse host from token URL: {url}"))
    })?;

    // Block private/loopback addresses
    if is_private_or_loopback(&host) {
        return Err(AegisError::ConfigError(format!(
            "token URL points to private/loopback address (SSRF blocked): {host}"
        )));
    }

    Ok(())
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> Option<String> {
    // Strip scheme
    let after_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    // Take everything up to the first `/`, `?`, or `:`
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()?;
    // Strip port if present
    let host = if let Some((h, _port)) = host.rsplit_once(':') {
        // Verify port is numeric to avoid stripping IPv6 addresses
        if _port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    } else {
        host
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a hostname or IP address is private, loopback, or link-local.
fn is_private_or_loopback(host: &str) -> bool {
    // Direct IP checks
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return addr.is_loopback()
            || addr.is_private()
            || addr.is_link_local()
            || addr.is_unspecified()
            || addr.octets()[0] == 100 && addr.octets()[1] >= 64 && addr.octets()[1] <= 127; // CGNAT
    }

    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        return addr.is_loopback() || addr.is_unspecified();
    }

    // Hostname checks
    let lower = host.to_lowercase();
    lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".localhost")
}

/// Validate that a provider name is safe for use in file paths.
///
/// Rejects names containing `..`, `/`, `\`, null bytes, or names that are
/// empty or excessively long.
fn validate_provider_name(name: &str) -> Result<(), AegisError> {
    if name.is_empty() {
        return Err(AegisError::ConfigError(
            "provider name cannot be empty".into(),
        ));
    }

    if name.len() > 64 {
        return Err(AegisError::ConfigError(format!(
            "provider name too long ({} chars, max 64)",
            name.len()
        )));
    }

    if name.contains("..") {
        return Err(AegisError::ConfigError(format!(
            "provider name contains directory traversal: {name:?}"
        )));
    }

    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(AegisError::ConfigError(format!(
            "provider name contains invalid characters: {name:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// OAuthFlow
// ---------------------------------------------------------------------------

/// Orchestrates the OAuth2 authorization code flow with PKCE support.
///
/// Use `authorization_url()` to build the redirect URL, then `exchange_code()`
/// to swap the authorization code for tokens. Tokens can be refreshed via
/// `refresh_token()`, and `ensure_valid_token()` handles auto-refresh.
pub struct OAuthFlow {
    config: OAuthConfig,
}

impl OAuthFlow {
    /// Create a new OAuth flow from the given configuration.
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }

    /// Build the OAuth2 authorization URL with state and PKCE parameters.
    ///
    /// The `state` parameter is used for CSRF protection and must be validated
    /// by the caller when the callback is received.
    pub fn authorization_url(&self, state: &str, pkce: Option<&PkceChallenge>) -> String {
        let scope = self.config.scopes.join(" ");
        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.config.auth_url,
            url_encode(&self.config.client_id),
            url_encode(&self.config.redirect_uri),
            url_encode(&scope),
            url_encode(state),
        );

        if let Some(pkce) = pkce {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                url_encode(&pkce.code_challenge),
            ));
        }

        url
    }

    /// Exchange an authorization code for an OAuth2 token.
    ///
    /// Validates the token URL against SSRF before making the request.
    /// If PKCE was used during authorization, the `code_verifier` must be provided.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuthToken, AegisError> {
        validate_token_url(&self.config.token_url)?;

        let client_secret = self.config.read_client_secret()?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AegisError::ConfigError(format!("failed to create HTTP client: {e}")))?;

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &client_secret),
        ];

        let verifier_owned: String;
        if let Some(v) = code_verifier {
            verifier_owned = v.to_string();
            params.push(("code_verifier", &verifier_owned));
        }

        let resp = client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AegisError::ConfigError(format!("token exchange request failed: {e}")))?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            AegisError::ConfigError(format!("failed to parse token response: {e}"))
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("error").and_then(|v| v.as_str()))
                .unwrap_or("unknown error");
            return Err(AegisError::ConfigError(format!(
                "token exchange failed: {error_desc}"
            )));
        }

        parse_token_response(&body)
    }

    /// Refresh an expired token using the refresh token.
    ///
    /// Validates the token URL against SSRF before making the request.
    pub async fn refresh_token(&self, token: &OAuthToken) -> Result<OAuthToken, AegisError> {
        validate_token_url(&self.config.token_url)?;

        let client_secret = self.config.read_client_secret()?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AegisError::ConfigError(format!("failed to create HTTP client: {e}")))?;

        let resp = client
            .post(&self.config.token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token.refresh_token),
                ("client_id", &self.config.client_id),
                ("client_secret", &client_secret),
            ])
            .send()
            .await
            .map_err(|e| AegisError::ConfigError(format!("token refresh request failed: {e}")))?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            AegisError::ConfigError(format!("failed to parse refresh response: {e}"))
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("error").and_then(|v| v.as_str()))
                .unwrap_or("unknown error");
            return Err(AegisError::ConfigError(format!(
                "token refresh failed: {error_desc}"
            )));
        }

        let mut new_token = parse_token_response(&body)?;
        // Preserve refresh token if the server did not issue a new one
        if new_token.refresh_token.is_empty() {
            new_token.refresh_token = token.refresh_token.clone();
        }
        Ok(new_token)
    }

    /// Ensure a valid (non-expired) token is available.
    ///
    /// Loads the token from the store, auto-refreshes if expired, and saves
    /// the refreshed token back. Returns the valid token.
    pub async fn ensure_valid_token(
        &self,
        store: &dyn OAuthTokenStore,
    ) -> Result<OAuthToken, AegisError> {
        let token = store.load()?.ok_or_else(|| {
            AegisError::ConfigError(
                "no OAuth2 token found -- run the authorization flow first".into(),
            )
        })?;

        if !token.is_expired() {
            return Ok(token);
        }

        let new_token = self.refresh_token(&token).await?;
        store.save(&new_token)?;
        Ok(new_token)
    }
}

/// Parse a token endpoint JSON response into an `OAuthToken`.
fn parse_token_response(body: &serde_json::Value) -> Result<OAuthToken, AegisError> {
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AegisError::ConfigError("missing access_token in response".into()))?
        .to_string();

    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);

    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in);

    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(OAuthToken {
        access_token,
        refresh_token,
        expires_at: Some(expires_at),
        scope,
    })
}

/// Minimal percent-encoding for URL query parameters.
fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_no_embedded_secret() {
        // Verify that OAuthConfig stores the env var NAME, not the actual secret.
        let config = OAuthConfig {
            client_id: "my-client-id".into(),
            client_secret_env: "OAUTH_CLIENT_SECRET".into(),
            auth_url: "https://provider.example/authorize".into(),
            token_url: "https://provider.example/token".into(),
            scopes: vec!["read".into()],
            redirect_uri: "http://localhost:8080/callback".into(),
        };

        // Serialize to JSON and verify no actual secret is present
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("OAUTH_CLIENT_SECRET"),
            "should contain env var name"
        );
        // The field is called client_secret_env, not client_secret
        assert!(
            !json.contains("\"client_secret\""),
            "should not have a client_secret field with a raw secret"
        );

        // Debug output should not contain any secret
        let debug = format!("{config:?}");
        assert!(
            debug.contains("client_secret_env"),
            "debug should show the env var field name"
        );
    }

    #[test]
    fn test_token_masking() {
        let token = OAuthToken {
            access_token: "ya29.a0AfH6SMBxxxxxxxxxxxxxxxx".into(),
            refresh_token: "1//0gxxxxxxxxxxxxxxxxxxxxxxx".into(),
            expires_at: Some(Utc::now()),
            scope: Some("email profile".into()),
        };

        // Debug should mask tokens
        let debug = format!("{token:?}");
        assert!(
            debug.contains("ya29***"),
            "access_token should be masked in debug: {debug}"
        );
        assert!(
            debug.contains("1//0***"),
            "refresh_token should be masked in debug: {debug}"
        );
        assert!(
            !debug.contains("a0AfH6SMBxxxxxxxxxxxxxxxx"),
            "full access token must not appear in debug"
        );

        // Display should mask tokens
        let display = format!("{token}");
        assert!(display.contains("ya29***"), "access masked in display");
        assert!(display.contains("1//0***"), "refresh masked in display");
        assert!(
            !display.contains("a0AfH6SMBxxxxxxxxxxxxxxxx"),
            "full access token must not appear in display"
        );
    }

    #[test]
    fn test_authorization_url() {
        let config = OAuthConfig {
            client_id: "my-client".into(),
            client_secret_env: "SECRET_VAR".into(),
            auth_url: "https://auth.example.com/authorize".into(),
            token_url: "https://auth.example.com/token".into(),
            scopes: vec!["openid".into(), "email".into()],
            redirect_uri: "http://localhost:8080/callback".into(),
        };

        let flow = OAuthFlow::new(config);
        let pkce = PkceChallenge::generate();
        let url = flow.authorization_url("test-state-123", Some(&pkce));

        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("state=test-state-123"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        // Scopes should be space-delimited (URL-encoded)
        assert!(
            url.contains("scope=openid%20email"),
            "scope should be url-encoded: {url}"
        );
    }

    #[test]
    fn test_authorization_url_without_pkce() {
        let config = OAuthConfig {
            client_id: "my-client".into(),
            client_secret_env: "SECRET_VAR".into(),
            auth_url: "https://auth.example.com/authorize".into(),
            token_url: "https://auth.example.com/token".into(),
            scopes: vec!["read".into()],
            redirect_uri: "http://localhost:8080/callback".into(),
        };

        let flow = OAuthFlow::new(config);
        let url = flow.authorization_url("my-state", None);

        assert!(url.contains("state=my-state"));
        assert!(!url.contains("code_challenge"));
    }

    #[test]
    fn test_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        let store = FileTokenStore::with_path(path.clone());

        let token = OAuthToken {
            access_token: "test-access-token-12345".into(),
            refresh_token: "test-refresh-token-67890".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: None,
        };

        store.save(&token).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "token file must have 0600 permissions"
            );
        }

        // Verify roundtrip
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "test-access-token-12345");
        assert_eq!(loaded.refresh_token, "test-refresh-token-67890");

        // Verify delete
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_ssrf_blocked_token_url() {
        // Loopback IPv4
        assert!(validate_token_url("https://127.0.0.1/token").is_err());
        assert!(validate_token_url("https://127.0.0.2/token").is_err());

        // Localhost hostname
        assert!(validate_token_url("https://localhost/token").is_err());
        assert!(validate_token_url("https://something.localhost/token").is_err());

        // Private ranges
        assert!(validate_token_url("https://10.0.0.1/token").is_err());
        assert!(validate_token_url("https://192.168.1.1/token").is_err());
        assert!(validate_token_url("https://172.16.0.1/token").is_err());

        // Link-local
        assert!(validate_token_url("https://169.254.169.254/token").is_err());

        // .internal and .local
        assert!(validate_token_url("https://metadata.internal/token").is_err());
        assert!(validate_token_url("https://myhost.local/token").is_err());

        // Unspecified
        assert!(validate_token_url("https://0.0.0.0/token").is_err());

        // HTTP (not HTTPS) should be rejected
        assert!(validate_token_url("http://oauth.example.com/token").is_err());

        // Valid HTTPS to public host should pass
        assert!(validate_token_url("https://oauth.example.com/token").is_ok());
        assert!(validate_token_url("https://accounts.google.com/o/oauth2/token").is_ok());
    }

    #[test]
    fn test_pkce_challenge() {
        let pkce = PkceChallenge::generate();

        // Verifier should be non-empty and base64url-encoded (no padding)
        assert!(!pkce.code_verifier.is_empty());
        assert!(!pkce.code_verifier.contains('='));
        assert!(!pkce.code_verifier.contains('+'));
        assert!(!pkce.code_verifier.contains('/'));

        // Challenge should match S256(verifier)
        let expected = PkceChallenge::challenge_for(&pkce.code_verifier);
        assert_eq!(pkce.code_challenge, expected);

        // Generate two should produce different verifiers
        let pkce2 = PkceChallenge::generate();
        assert_ne!(
            pkce.code_verifier, pkce2.code_verifier,
            "two generated PKCE verifiers should differ"
        );
    }

    #[test]
    fn test_pkce_s256_known_vector() {
        // RFC 7636 Appendix B: code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // S256 challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = PkceChallenge::challenge_for(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_token_expiry_check() {
        // Not expired: 1 hour in the future
        let valid = OAuthToken {
            access_token: "valid".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: None,
        };
        assert!(!valid.is_expired());

        // Expired: 1 hour in the past
        let expired = OAuthToken {
            access_token: "expired".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            scope: None,
        };
        assert!(expired.is_expired());

        // No expiry -> treated as expired
        let no_exp = OAuthToken {
            access_token: "noexp".into(),
            refresh_token: "refresh".into(),
            expires_at: None,
            scope: None,
        };
        assert!(no_exp.is_expired());

        // Within 60s safety margin -> treated as expired
        let almost = OAuthToken {
            access_token: "almost".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(30)),
            scope: None,
        };
        assert!(almost.is_expired());

        // Beyond safety margin -> not expired
        let safe = OAuthToken {
            access_token: "safe".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(120)),
            scope: None,
        };
        assert!(!safe.is_expired());
    }

    #[test]
    fn test_path_traversal_rejected() {
        // Directory traversal in provider name
        assert!(FileTokenStore::new("../etc").is_err());
        assert!(FileTokenStore::new("provider/../evil").is_err());
        assert!(FileTokenStore::new("..").is_err());

        // Path separators rejected
        assert!(FileTokenStore::new("a/b").is_err());
        assert!(FileTokenStore::new("a\\b").is_err());

        // Null bytes rejected
        assert!(FileTokenStore::new("a\0b").is_err());

        // Empty name rejected
        assert!(FileTokenStore::new("").is_err());

        // Valid names should succeed
        assert!(FileTokenStore::new("google").is_ok());
        assert!(FileTokenStore::new("my-provider").is_ok());
        assert!(FileTokenStore::new("provider_v2").is_ok());
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(url_encode("test@example.com"), "test%40example.com");
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("https://example.com/path"), Some("example.com".into()));
        assert_eq!(extract_host("https://example.com:443/path"), Some("example.com".into()));
        assert_eq!(extract_host("https://10.0.0.1/token"), Some("10.0.0.1".into()));
        assert_eq!(extract_host("https://localhost/x"), Some("localhost".into()));
    }

    #[test]
    fn test_token_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-token.json");
        let store = FileTokenStore::with_path(path);

        // Initially empty
        assert!(store.load().unwrap().is_none());

        let token = OAuthToken {
            access_token: "access-123".into(),
            refresh_token: "refresh-456".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scope: Some("read write".into()),
        };

        store.save(&token).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "access-123");
        assert_eq!(loaded.refresh_token, "refresh-456");
        assert_eq!(loaded.scope, Some("read write".into()));

        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_is_private_or_loopback() {
        assert!(is_private_or_loopback("127.0.0.1"));
        assert!(is_private_or_loopback("10.0.0.1"));
        assert!(is_private_or_loopback("192.168.0.1"));
        assert!(is_private_or_loopback("172.16.0.1"));
        assert!(is_private_or_loopback("169.254.169.254"));
        assert!(is_private_or_loopback("0.0.0.0"));
        assert!(is_private_or_loopback("localhost"));
        assert!(is_private_or_loopback("foo.localhost"));
        assert!(is_private_or_loopback("host.local"));
        assert!(is_private_or_loopback("meta.internal"));

        assert!(!is_private_or_loopback("8.8.8.8"));
        assert!(!is_private_or_loopback("example.com"));
        assert!(!is_private_or_loopback("accounts.google.com"));
    }
}
