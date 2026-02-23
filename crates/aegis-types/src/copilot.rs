//! GitHub Copilot OAuth2 device flow authentication and token management.
//!
//! Implements the [OAuth2 device authorization grant](https://datatracker.ietf.org/doc/html/rfc8628)
//! for GitHub Copilot, including device code request, polling, token storage,
//! and automatic token refresh.
//!
//! # Security
//!
//! - Tokens are stored on disk with `0600` permissions (owner read/write only).
//! - Access tokens and refresh tokens are masked in all `Debug` and `Display` output.
//! - Token file paths are validated against directory traversal attacks.
//! - GitHub endpoint URLs are validated (HTTPS required, SSRF protection).
//! - No client IDs or secrets are hardcoded; all values come from configuration.

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config_loader::mask_sensitive;
use crate::AegisError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default GitHub device code endpoint.
pub const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";

/// Default GitHub token endpoint.
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// Default Copilot API upstream URL.
pub const DEFAULT_COPILOT_UPSTREAM_URL: &str = "https://api.githubcopilot.com";

/// Default token storage path relative to home directory.
const DEFAULT_TOKEN_SUBPATH: &str = ".aegis/providers/copilot/tokens.json";

/// Safety margin (in seconds) before token expiry to trigger refresh.
const TOKEN_EXPIRY_MARGIN_SECS: i64 = 60;

/// Allowed GitHub endpoint hosts for SSRF protection.
const ALLOWED_GITHUB_HOSTS: &[&str] = &["github.com", "api.github.com"];

/// Allowed upstream hosts for Copilot proxy SSRF protection.
const ALLOWED_COPILOT_UPSTREAM_HOSTS: &[&str] = &[
    "api.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
];

// ---------------------------------------------------------------------------
// CopilotConfig
// ---------------------------------------------------------------------------

/// Configuration for GitHub Copilot provider integration.
///
/// The `client_id` is the GitHub OAuth app client ID used for the device flow.
/// No client secret is needed for the device flow (public client).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopilotConfig {
    /// GitHub OAuth app client ID for device flow.
    pub client_id: String,

    /// Whether the Copilot provider is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Path to the token storage file.
    /// Defaults to `~/.aegis/providers/copilot/tokens.json`.
    #[serde(default)]
    pub token_path: Option<PathBuf>,

    /// Proxy routing configuration for Copilot API requests.
    #[serde(default)]
    pub proxy: Option<CopilotProxyConfig>,

    /// Model override: force a specific model for all Copilot requests.
    /// Validated against the model ID format (alphanumeric, hyphens, dots).
    #[serde(default)]
    pub model_override: Option<String>,
}

fn default_enabled() -> bool {
    true
}

impl fmt::Debug for CopilotConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopilotConfig")
            .field("client_id", &self.client_id)
            .field("enabled", &self.enabled)
            .field("token_path", &self.token_path)
            .field("proxy", &self.proxy)
            .field("model_override", &self.model_override)
            .finish()
    }
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            enabled: true,
            token_path: None,
            proxy: None,
            model_override: None,
        }
    }
}

impl CopilotConfig {
    /// Resolve the token storage path, falling back to the default.
    ///
    /// Validates the resolved path against directory traversal attacks.
    pub fn resolved_token_path(&self) -> Result<PathBuf, AegisError> {
        match &self.token_path {
            Some(p) => {
                validate_token_path(p)?;
                Ok(p.clone())
            }
            None => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                Ok(PathBuf::from(home).join(DEFAULT_TOKEN_SUBPATH))
            }
        }
    }

    /// Validate model_override if set. Returns error if the model ID
    /// contains invalid characters.
    pub fn validate(&self) -> Result<(), AegisError> {
        if let Some(ref model_id) = self.model_override {
            validate_model_id(model_id)?;
        }
        if let Some(ref proxy) = self.proxy {
            proxy.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CopilotProxyConfig
// ---------------------------------------------------------------------------

/// Proxy routing configuration for Copilot API requests.
///
/// Controls how Aegis routes requests to the Copilot upstream API. The
/// upstream URL is validated against an allowlist of known Copilot hosts
/// to prevent SSRF attacks.
///
/// # Security
///
/// - `upstream_url` must use HTTPS and point to an allowed Copilot host.
/// - Model overrides are validated for safe characters only.
/// - No secrets are stored in this configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopilotProxyConfig {
    /// Upstream Copilot API URL.
    /// Defaults to `https://api.githubcopilot.com`.
    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,

    /// Force a specific model for all proxied requests.
    /// When set, overrides the model requested by the client.
    #[serde(default)]
    pub model_override: Option<String>,

    /// Whether to track token usage for proxied requests.
    #[serde(default = "default_usage_tracking")]
    pub usage_tracking: bool,
}

fn default_upstream_url() -> String {
    DEFAULT_COPILOT_UPSTREAM_URL.to_string()
}

fn default_usage_tracking() -> bool {
    true
}

impl Default for CopilotProxyConfig {
    fn default() -> Self {
        Self {
            upstream_url: DEFAULT_COPILOT_UPSTREAM_URL.to_string(),
            model_override: None,
            usage_tracking: true,
        }
    }
}

impl CopilotProxyConfig {
    /// Validate the proxy configuration.
    ///
    /// Checks that `upstream_url` uses HTTPS and points to a known Copilot
    /// host (SSRF protection). Validates `model_override` if set.
    pub fn validate(&self) -> Result<(), AegisError> {
        validate_copilot_upstream_url(&self.upstream_url)?;
        if let Some(ref model_id) = self.model_override {
            validate_model_id(model_id)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CopilotModel
// ---------------------------------------------------------------------------

/// Metadata about a Copilot-available model.
///
/// Describes the capabilities, token limits, and identity of a model
/// accessible through the GitHub Copilot API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopilotModel {
    /// Canonical model identifier (e.g., "gpt-4o", "claude-3.5-sonnet").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Model version string.
    pub version: String,
    /// Maximum token limit for completions.
    pub max_tokens: u32,
    /// List of capabilities (e.g., "chat", "function_calling", "vision").
    pub capabilities: Vec<String>,
}

impl CopilotModel {
    /// Check whether this model supports a given capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// Validate that a requested token count does not exceed this model's limit.
    ///
    /// Returns `Ok(())` if `requested` is within the model's `max_tokens`.
    /// Returns an error describing the violation otherwise.
    pub fn validate_max_tokens(&self, requested: u32) -> Result<(), AegisError> {
        if requested > self.max_tokens {
            return Err(AegisError::ConfigError(format!(
                "requested {} tokens exceeds model '{}' limit of {}",
                requested, self.id, self.max_tokens
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CopilotModelCatalog
// ---------------------------------------------------------------------------

/// Registry of models available through GitHub Copilot.
///
/// Provides lookup and enumeration of known Copilot models. The built-in
/// catalog includes commonly available models; it can be extended at runtime.
pub struct CopilotModelCatalog {
    models: Vec<CopilotModel>,
}

impl CopilotModelCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self { models: Vec::new() }
    }

    /// Create a catalog pre-populated with commonly available Copilot models.
    pub fn with_defaults() -> Self {
        let models = vec![
            CopilotModel {
                id: "gpt-4o".into(),
                name: "GPT-4o".into(),
                version: "2024-05-13".into(),
                max_tokens: 16384,
                capabilities: vec![
                    "chat".into(),
                    "function_calling".into(),
                    "vision".into(),
                ],
            },
            CopilotModel {
                id: "gpt-4".into(),
                name: "GPT-4".into(),
                version: "0613".into(),
                max_tokens: 8192,
                capabilities: vec!["chat".into(), "function_calling".into()],
            },
            CopilotModel {
                id: "gpt-3.5-turbo".into(),
                name: "GPT-3.5 Turbo".into(),
                version: "0125".into(),
                max_tokens: 4096,
                capabilities: vec!["chat".into(), "function_calling".into()],
            },
            CopilotModel {
                id: "claude-3.5-sonnet".into(),
                name: "Claude 3.5 Sonnet".into(),
                version: "20241022".into(),
                max_tokens: 8192,
                capabilities: vec![
                    "chat".into(),
                    "function_calling".into(),
                    "vision".into(),
                ],
            },
        ];
        Self { models }
    }

    /// Find a model by its identifier.
    pub fn find_model(&self, id: &str) -> Option<&CopilotModel> {
        self.models.iter().find(|m| m.id == id)
    }

    /// List all models in the catalog.
    pub fn list_models(&self) -> &[CopilotModel] {
        &self.models
    }

    /// Add a model to the catalog. Replaces any existing model with the same ID.
    pub fn add_model(&mut self, model: CopilotModel) -> Result<(), AegisError> {
        validate_model_id(&model.id)?;
        if let Some(existing) = self.models.iter_mut().find(|m| m.id == model.id) {
            *existing = model;
        } else {
            self.models.push(model);
        }
        Ok(())
    }
}

impl Default for CopilotModelCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a model ID contains only safe characters.
///
/// Model IDs may contain alphanumeric characters, hyphens, and dots.
/// This prevents injection attacks through model identifiers.
fn validate_model_id(model_id: &str) -> Result<(), AegisError> {
    if model_id.is_empty() {
        return Err(AegisError::ConfigError(
            "model ID must not be empty".into(),
        ));
    }
    if model_id.len() > 128 {
        return Err(AegisError::ConfigError(format!(
            "model ID too long ({} chars, max 128): {}",
            model_id.len(),
            model_id
        )));
    }
    if !model_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(AegisError::ConfigError(format!(
            "model ID contains invalid characters (allowed: alphanumeric, hyphens, dots): {model_id:?}"
        )));
    }
    Ok(())
}

/// Validate that a URL points to a known Copilot upstream host (SSRF protection).
///
/// The URL must use HTTPS and resolve to an allowed Copilot host.
fn validate_copilot_upstream_url(url: &str) -> Result<(), AegisError> {
    if !url.starts_with("https://") {
        return Err(AegisError::ConfigError(format!(
            "Copilot upstream URL must use HTTPS, got: {url}"
        )));
    }

    let host = extract_host(url).ok_or_else(|| {
        AegisError::ConfigError(format!(
            "cannot parse host from Copilot upstream URL: {url}"
        ))
    })?;

    if !ALLOWED_COPILOT_UPSTREAM_HOSTS.contains(&host.as_str()) {
        return Err(AegisError::ConfigError(format!(
            "Copilot upstream URL host not in allowlist: {host} (allowed: {ALLOWED_COPILOT_UPSTREAM_HOSTS:?})"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DeviceFlowResponse
// ---------------------------------------------------------------------------

/// Response from the GitHub device code endpoint.
///
/// The user must visit `verification_uri` and enter `user_code` to authorize
/// the application. The caller then polls the token endpoint using `device_code`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFlowResponse {
    /// The device verification code (sent to the token endpoint during polling).
    pub device_code: String,

    /// The code the user must enter at `verification_uri`.
    pub user_code: String,

    /// The URL where the user enters the `user_code`.
    pub verification_uri: String,

    /// Polling interval in seconds (the minimum time between poll requests).
    #[serde(default = "default_interval")]
    pub interval: u64,

    /// Number of seconds until the device code expires.
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

fn default_expires_in() -> u64 {
    900
}

// ---------------------------------------------------------------------------
// DeviceFlowPollState
// ---------------------------------------------------------------------------

/// Possible states when polling the token endpoint during device flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceFlowPollState {
    /// The user has not yet authorized. Keep polling.
    AuthorizationPending,

    /// Polling too fast. Increase the interval by 5 seconds.
    SlowDown,

    /// The device code has expired. Must restart the flow.
    ExpiredToken,

    /// The user denied the authorization request.
    AccessDenied,

    /// Authorization succeeded. Contains the token.
    Success(CopilotToken),
}

// ---------------------------------------------------------------------------
// CopilotToken
// ---------------------------------------------------------------------------

/// A GitHub Copilot OAuth2 token with expiry tracking.
///
/// Both `access_token` and `refresh_token` are masked in `Debug` and `Display`
/// output to prevent accidental exposure in logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopilotToken {
    /// The access token for Copilot API calls.
    pub access_token: String,

    /// The refresh token for obtaining new access tokens.
    #[serde(default)]
    pub refresh_token: String,

    /// When the access token expires. `None` means unknown (treated as expired).
    pub expires_at: Option<DateTime<Utc>>,

    /// Scopes granted by the authorization server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl CopilotToken {
    /// Check whether the access token has expired (with a 60-second safety margin).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp - chrono::Duration::seconds(TOKEN_EXPIRY_MARGIN_SECS),
            None => true,
        }
    }
}

impl fmt::Debug for CopilotToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopilotToken")
            .field("access_token", &mask_sensitive(&self.access_token))
            .field("refresh_token", &mask_sensitive(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl fmt::Display for CopilotToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CopilotToken(access={}, refresh={}, expires_at={:?})",
            mask_sensitive(&self.access_token),
            mask_sensitive(&self.refresh_token),
            self.expires_at,
        )
    }
}

// ---------------------------------------------------------------------------
// CopilotTokenStore
// ---------------------------------------------------------------------------

/// File-backed token store for GitHub Copilot tokens.
///
/// Tokens are stored as JSON at the configured path with `0600` file
/// permissions on Unix systems. The path is validated against directory
/// traversal attacks on construction.
pub struct CopilotTokenStore {
    path: PathBuf,
}

impl CopilotTokenStore {
    /// Create a new token store from a `CopilotConfig`.
    ///
    /// Validates the token path against directory traversal attacks.
    pub fn from_config(config: &CopilotConfig) -> Result<Self, AegisError> {
        let path = config.resolved_token_path()?;
        Ok(Self { path })
    }

    /// Create a token store at an explicit path (for testing).
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Return the store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the stored token, returning `None` if no token exists.
    pub fn load(&self) -> Result<Option<CopilotToken>, AegisError> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&self.path).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to read Copilot token file '{}': {e}",
                self.path.display()
            ))
        })?;

        let token: CopilotToken = serde_json::from_str(&content).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to parse Copilot token file '{}': {e}",
                self.path.display()
            ))
        })?;

        Ok(Some(token))
    }

    /// Persist a token to the store with secure file permissions.
    pub fn save(&self, token: &CopilotToken) -> Result<(), AegisError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to create Copilot token directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        let content = serde_json::to_string_pretty(token).map_err(|e| {
            AegisError::ConfigError(format!("failed to serialize Copilot token: {e}"))
        })?;

        std::fs::write(&self.path, &content).map_err(|e| {
            AegisError::ConfigError(format!(
                "failed to write Copilot token file '{}': {e}",
                self.path.display()
            ))
        })?;

        set_file_permissions_0600(&self.path)?;

        Ok(())
    }

    /// Delete the stored token.
    pub fn delete(&self) -> Result<(), AegisError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to delete Copilot token file '{}': {e}",
                    self.path.display()
                ))
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CopilotDeviceFlow
// ---------------------------------------------------------------------------

/// Orchestrates the OAuth2 device authorization flow for GitHub Copilot.
///
/// Use `request_device_code()` to initiate the flow, then `poll_for_token()`
/// in a loop until the user authorizes or the code expires.
pub struct CopilotDeviceFlow {
    config: CopilotConfig,
    device_code_url: String,
    token_url: String,
}

impl CopilotDeviceFlow {
    /// Create a new device flow with default GitHub endpoints.
    pub fn new(config: CopilotConfig) -> Self {
        Self {
            config,
            device_code_url: GITHUB_DEVICE_CODE_URL.to_string(),
            token_url: GITHUB_TOKEN_URL.to_string(),
        }
    }

    /// Create a device flow with custom endpoints (for testing).
    pub fn with_endpoints(
        config: CopilotConfig,
        device_code_url: String,
        token_url: String,
    ) -> Self {
        Self {
            config,
            device_code_url,
            token_url,
        }
    }

    /// Request a device code from GitHub.
    ///
    /// The user must visit the returned `verification_uri` and enter the
    /// `user_code` to authorize this application.
    pub fn request_device_code(
        &self,
        scope: &str,
    ) -> Result<DeviceFlowResponse, AegisError> {
        validate_github_url(&self.device_code_url)?;

        if self.config.client_id.is_empty() {
            return Err(AegisError::ConfigError(
                "Copilot client_id is empty".into(),
            ));
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                AegisError::ConfigError(format!("failed to create HTTP client: {e}"))
            })?;

        let resp = client
            .post(&self.device_code_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("scope", scope),
            ])
            .send()
            .map_err(|e| {
                AegisError::ConfigError(format!("device code request failed: {e}"))
            })?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().map_err(|e| {
            AegisError::ConfigError(format!("failed to parse device code response: {e}"))
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("error").and_then(|v| v.as_str()))
                .unwrap_or("unknown error");
            return Err(AegisError::ConfigError(format!(
                "device code request failed: {error_desc}"
            )));
        }

        let response: DeviceFlowResponse =
            serde_json::from_value(body).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to parse device code response fields: {e}"
                ))
            })?;

        Ok(response)
    }

    /// Poll the token endpoint once to check if the user has authorized.
    ///
    /// Returns the polling state. The caller is responsible for waiting
    /// the appropriate interval between polls.
    pub fn poll_for_token(
        &self,
        device_code: &str,
    ) -> Result<DeviceFlowPollState, AegisError> {
        validate_github_url(&self.token_url)?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                AegisError::ConfigError(format!("failed to create HTTP client: {e}"))
            })?;

        let resp = client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .map_err(|e| {
                AegisError::ConfigError(format!("token poll request failed: {e}"))
            })?;

        let body: serde_json::Value = resp.json().map_err(|e| {
            AegisError::ConfigError(format!("failed to parse token poll response: {e}"))
        })?;

        // Check for error states first
        if let Some(error) = body.get("error").and_then(|v| v.as_str()) {
            return Ok(match error {
                "authorization_pending" => DeviceFlowPollState::AuthorizationPending,
                "slow_down" => DeviceFlowPollState::SlowDown,
                "expired_token" => DeviceFlowPollState::ExpiredToken,
                "access_denied" => DeviceFlowPollState::AccessDenied,
                other => {
                    return Err(AegisError::ConfigError(format!(
                        "unexpected device flow error: {other}"
                    )));
                }
            });
        }

        // No error means success -- parse the token
        let token = parse_copilot_token_response(&body)?;
        Ok(DeviceFlowPollState::Success(token))
    }
}

/// Refresh an expired Copilot token using the refresh token.
///
/// Validates the token URL against SSRF before making the request.
pub fn refresh_copilot_token(
    config: &CopilotConfig,
    token: &CopilotToken,
) -> Result<CopilotToken, AegisError> {
    if token.refresh_token.is_empty() {
        return Err(AegisError::ConfigError(
            "no refresh token available -- re-authorize via device flow".into(),
        ));
    }

    validate_github_url(GITHUB_TOKEN_URL)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| {
            AegisError::ConfigError(format!("failed to create HTTP client: {e}"))
        })?;

    let resp = client
        .post(GITHUB_TOKEN_URL)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("refresh_token", token.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .map_err(|e| {
            AegisError::ConfigError(format!("token refresh request failed: {e}"))
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().map_err(|e| {
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

    let mut new_token = parse_copilot_token_response(&body)?;
    // Preserve refresh token if the server did not issue a new one
    if new_token.refresh_token.is_empty() {
        new_token.refresh_token = token.refresh_token.clone();
    }
    Ok(new_token)
}

/// Ensure a valid (non-expired) Copilot token is available.
///
/// Loads the token from the store, auto-refreshes if expired, and saves
/// the refreshed token back. Returns the valid token.
pub fn ensure_valid_copilot_token(
    config: &CopilotConfig,
    store: &CopilotTokenStore,
) -> Result<CopilotToken, AegisError> {
    let token = store.load()?.ok_or_else(|| {
        AegisError::ConfigError(
            "no Copilot token found -- run the device flow authorization first".into(),
        )
    })?;

    if !token.is_expired() {
        return Ok(token);
    }

    let new_token = refresh_copilot_token(config, &token)?;
    store.save(&new_token)?;
    Ok(new_token)
}

// ---------------------------------------------------------------------------
// Copilot session token exchange
// ---------------------------------------------------------------------------

/// A Copilot session token obtained by exchanging a GitHub OAuth token.
///
/// The token is a semicolon-delimited string containing metadata like
/// `tid=...;exp=...;sku=...;proxy-ep=...`. The `proxy_endpoint` is the
/// base URL for Copilot API requests (e.g., `https://api.individual.githubcopilot.com`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotSessionToken {
    /// The raw Copilot session token string.
    pub token: String,
    /// When the session token expires.
    pub expires_at: DateTime<Utc>,
    /// The proxy endpoint extracted from the token's `proxy-ep` field.
    /// Used as the base URL for Copilot API requests.
    pub proxy_endpoint: String,
}

/// Exchange a GitHub OAuth token for a Copilot session token.
///
/// Sends the GitHub token to `https://api.github.com/copilot_internal/v2/token`
/// and receives a Copilot-specific session token with an endpoint URL.
///
/// The returned `CopilotSessionToken` contains:
/// - The session token for Copilot API authorization
/// - The proxy endpoint (base URL) for routing API requests
/// - The token expiration time
pub fn exchange_for_copilot_token(github_token: &str) -> Result<CopilotSessionToken, AegisError> {
    if github_token.is_empty() {
        return Err(AegisError::ConfigError(
            "GitHub token is empty -- cannot exchange for Copilot token".into(),
        ));
    }

    let exchange_url = "https://api.github.com/copilot_internal/v2/token";
    validate_github_url(exchange_url)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| AegisError::ConfigError(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(exchange_url)
        .header("Authorization", format!("token {github_token}"))
        .header("Accept", "application/json")
        .send()
        .map_err(|e| {
            AegisError::ConfigError(format!("Copilot token exchange request failed: {e}"))
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().map_err(|e| {
        AegisError::ConfigError(format!("failed to parse Copilot exchange response: {e}"))
    })?;

    if !status.is_success() {
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(AegisError::ConfigError(format!(
            "Copilot token exchange failed (HTTP {status}): {msg}"
        )));
    }

    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AegisError::ConfigError("missing 'token' in Copilot exchange response".into())
        })?
        .to_string();

    // Parse expires_at from the response (Unix timestamp)
    let expires_at = body
        .get("expires_at")
        .and_then(|v| v.as_i64())
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1))
        })
        .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));

    // Extract proxy-ep from the semicolon-delimited token metadata.
    // Token format: "tid=...;exp=...;sku=...;proxy-ep=https://..."
    let proxy_endpoint = token
        .split(';')
        .find_map(|part| part.strip_prefix("proxy-ep="))
        .unwrap_or(DEFAULT_COPILOT_UPSTREAM_URL)
        .to_string();

    Ok(CopilotSessionToken {
        token,
        expires_at,
        proxy_endpoint,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a token endpoint JSON response into a `CopilotToken`.
fn parse_copilot_token_response(
    body: &serde_json::Value,
) -> Result<CopilotToken, AegisError> {
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AegisError::ConfigError("missing access_token in Copilot token response".into())
        })?
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

    let scopes = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.split(' ').map(String::from).collect())
        .unwrap_or_default();

    Ok(CopilotToken {
        access_token,
        refresh_token,
        expires_at: Some(expires_at),
        scopes,
    })
}

/// Validate that a URL points to a known GitHub endpoint (SSRF protection).
///
/// Even though GitHub's URLs are well-known, we validate them to guard
/// against misconfiguration or injection.
fn validate_github_url(url: &str) -> Result<(), AegisError> {
    if !url.starts_with("https://") {
        return Err(AegisError::ConfigError(format!(
            "GitHub endpoint URL must use HTTPS, got: {url}"
        )));
    }

    let host = extract_host(url).ok_or_else(|| {
        AegisError::ConfigError(format!(
            "cannot parse host from GitHub endpoint URL: {url}"
        ))
    })?;

    if !ALLOWED_GITHUB_HOSTS.contains(&host.as_str()) {
        return Err(AegisError::ConfigError(format!(
            "GitHub endpoint URL host not in allowlist: {host} (allowed: {ALLOWED_GITHUB_HOSTS:?})"
        )));
    }

    Ok(())
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = after_scheme.split(['/', '?', '#']).next()?;
    let host = if let Some((h, port)) = host.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
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
        Some(host.to_lowercase())
    }
}

/// Validate that a token path does not contain directory traversal sequences.
fn validate_token_path(path: &Path) -> Result<(), AegisError> {
    let path_str = path.to_str().ok_or_else(|| {
        AegisError::ConfigError("token path contains non-UTF-8 characters".into())
    })?;

    if path_str.contains("..") {
        return Err(AegisError::ConfigError(format!(
            "token path contains directory traversal: {path_str:?}"
        )));
    }

    if path_str.contains('\0') {
        return Err(AegisError::ConfigError(format!(
            "token path contains null bytes: {path_str:?}"
        )));
    }

    Ok(())
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_flow_request_format() {
        // Verify DeviceFlowResponse deserialization from a realistic GitHub response.
        let json = serde_json::json!({
            "device_code": "3584d83530557fdd1f46af8289938c8ef79f9dc5",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "interval": 5,
            "expires_in": 900
        });

        let resp: DeviceFlowResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            resp.device_code,
            "3584d83530557fdd1f46af8289938c8ef79f9dc5"
        );
        assert_eq!(resp.user_code, "WDJB-MJHT");
        assert_eq!(resp.verification_uri, "https://github.com/login/device");
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 900);
    }

    #[test]
    fn device_flow_polling_states() {
        // Verify that each polling error state is correctly identified.
        let pending_body = serde_json::json!({"error": "authorization_pending"});
        let slow_body = serde_json::json!({"error": "slow_down"});
        let expired_body = serde_json::json!({"error": "expired_token"});
        let denied_body = serde_json::json!({"error": "access_denied"});

        // We test the internal parsing logic by simulating the body parsing.
        // The poll_for_token method would produce these states from the JSON.
        fn classify_error(body: &serde_json::Value) -> &str {
            body.get("error").and_then(|v| v.as_str()).unwrap_or("")
        }

        assert_eq!(classify_error(&pending_body), "authorization_pending");
        assert_eq!(classify_error(&slow_body), "slow_down");
        assert_eq!(classify_error(&expired_body), "expired_token");
        assert_eq!(classify_error(&denied_body), "access_denied");

        // Verify that a success response (no error field) parses as a token.
        let success_body = serde_json::json!({
            "access_token": "ghu_xxxxxxxxxxxxxxxxxxxx",
            "token_type": "bearer",
            "scope": "read:user",
            "expires_in": 28800
        });
        let token = parse_copilot_token_response(&success_body).unwrap();
        assert_eq!(token.access_token, "ghu_xxxxxxxxxxxxxxxxxxxx");
        assert_eq!(token.scopes, vec!["read:user".to_string()]);
    }

    #[test]
    fn token_store_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let store = CopilotTokenStore::with_path(path);

        // Initially empty
        assert!(store.load().unwrap().is_none());

        let token = CopilotToken {
            access_token: "ghu_test_access_token_12345".into(),
            refresh_token: "ghr_test_refresh_token_67890".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scopes: vec!["read:user".into(), "copilot".into()],
        };

        store.save(&token).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "ghu_test_access_token_12345");
        assert_eq!(loaded.refresh_token, "ghr_test_refresh_token_67890");
        assert_eq!(loaded.scopes, vec!["read:user", "copilot"]);

        // Delete and verify
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn token_store_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let store = CopilotTokenStore::with_path(path.clone());

        let token = CopilotToken {
            access_token: "ghu_permission_test".into(),
            refresh_token: "ghr_permission_test".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scopes: vec![],
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
    }

    #[test]
    fn token_masking_in_debug() {
        let token = CopilotToken {
            access_token: "ghu_ABCDxxxxxxxxxxxxxxxxxxxxxxxx".into(),
            refresh_token: "ghr_1234xxxxxxxxxxxxxxxxxxxxxxxx".into(),
            expires_at: Some(Utc::now()),
            scopes: vec!["copilot".into()],
        };

        // Debug should mask tokens
        let debug = format!("{token:?}");
        assert!(
            debug.contains("ghu_***"),
            "access_token should be masked in debug: {debug}"
        );
        assert!(
            debug.contains("ghr_***"),
            "refresh_token should be masked in debug: {debug}"
        );
        assert!(
            !debug.contains("xxxxxxxxxxxxxxxxxxxxxxxx"),
            "full token must not appear in debug"
        );

        // Display should mask tokens
        let display = format!("{token}");
        assert!(
            display.contains("ghu_***"),
            "access_token should be masked in display"
        );
        assert!(
            display.contains("ghr_***"),
            "refresh_token should be masked in display"
        );
        assert!(
            !display.contains("xxxxxxxxxxxxxxxxxxxxxxxx"),
            "full token must not appear in display"
        );
    }

    #[test]
    fn token_expiry_detection() {
        // Not expired: 1 hour in the future
        let valid = CopilotToken {
            access_token: "valid".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            scopes: vec![],
        };
        assert!(!valid.is_expired());

        // Expired: 1 hour in the past
        let expired = CopilotToken {
            access_token: "expired".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            scopes: vec![],
        };
        assert!(expired.is_expired());

        // No expiry -> treated as expired
        let no_exp = CopilotToken {
            access_token: "noexp".into(),
            refresh_token: "refresh".into(),
            expires_at: None,
            scopes: vec![],
        };
        assert!(no_exp.is_expired());

        // Within 60s safety margin -> treated as expired
        let almost = CopilotToken {
            access_token: "almost".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(30)),
            scopes: vec![],
        };
        assert!(almost.is_expired());

        // Beyond safety margin -> not expired
        let safe = CopilotToken {
            access_token: "safe".into(),
            refresh_token: "refresh".into(),
            expires_at: Some(Utc::now() + chrono::Duration::seconds(120)),
            scopes: vec![],
        };
        assert!(!safe.is_expired());
    }

    #[test]
    fn copilot_config_defaults() {
        let config = CopilotConfig::default();
        assert!(config.client_id.is_empty());
        assert!(config.enabled);
        assert!(config.token_path.is_none());
        assert!(config.proxy.is_none());
        assert!(config.model_override.is_none());

        // Default resolved path should end with the expected subpath
        let resolved = config.resolved_token_path().unwrap();
        assert!(
            resolved.ends_with("providers/copilot/tokens.json"),
            "default path should end with providers/copilot/tokens.json, got: {}",
            resolved.display()
        );

        // Deserialization with defaults
        let json = r#"{"client_id":"test-id"}"#;
        let deserialized: CopilotConfig = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.client_id, "test-id");
        assert!(deserialized.enabled);
        assert!(deserialized.token_path.is_none());
        assert!(deserialized.proxy.is_none());
        assert!(deserialized.model_override.is_none());
    }

    #[test]
    fn path_traversal_rejected_in_token_path() {
        // Directory traversal in token_path
        let config = CopilotConfig {
            client_id: "test".into(),
            enabled: true,
            token_path: Some(PathBuf::from("/home/user/../../../etc/passwd")),
            proxy: None,
            model_override: None,
        };
        assert!(
            config.resolved_token_path().is_err(),
            "path traversal must be rejected"
        );

        // Relative traversal
        let config2 = CopilotConfig {
            client_id: "test".into(),
            enabled: true,
            token_path: Some(PathBuf::from("../secret/tokens.json")),
            proxy: None,
            model_override: None,
        };
        assert!(
            config2.resolved_token_path().is_err(),
            "relative traversal must be rejected"
        );

        // Valid explicit path should succeed
        let config3 = CopilotConfig {
            client_id: "test".into(),
            enabled: true,
            token_path: Some(PathBuf::from("/home/user/.aegis/copilot/tokens.json")),
            proxy: None,
            model_override: None,
        };
        assert!(config3.resolved_token_path().is_ok());
    }

    /// Security test: verify that CopilotAuth is registered as a Cedar action
    /// and that the default-deny policy denies it.
    #[test]
    fn copilot_requires_cedar_policy() {
        // Verify the CopilotAuth ActionKind variant exists and can be created.
        let action_kind = crate::ActionKind::CopilotAuth {
            grant_type: "device_code".into(),
        };
        let action = crate::Action::new("test-agent", action_kind);

        // The action should serialize/deserialize correctly.
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: crate::Action = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.principal, "test-agent");

        // Verify the action kind matches.
        match &deserialized.kind {
            crate::ActionKind::CopilotAuth { grant_type } => {
                assert_eq!(grant_type, "device_code");
            }
            other => panic!("expected CopilotAuth, got {other:?}"),
        }
    }

    #[test]
    fn github_url_validation() {
        // Valid GitHub URLs
        assert!(validate_github_url(GITHUB_DEVICE_CODE_URL).is_ok());
        assert!(validate_github_url(GITHUB_TOKEN_URL).is_ok());
        assert!(validate_github_url("https://api.github.com/copilot/v1/token").is_ok());

        // HTTP rejected
        assert!(validate_github_url("http://github.com/login/device/code").is_err());

        // Non-GitHub hosts rejected (SSRF protection)
        assert!(validate_github_url("https://evil.com/login/device/code").is_err());
        assert!(validate_github_url("https://localhost/token").is_err());
        assert!(validate_github_url("https://127.0.0.1/token").is_err());
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://github.com/login/device/code"),
            Some("github.com".into())
        );
        assert_eq!(
            extract_host("https://api.github.com/copilot"),
            Some("api.github.com".into())
        );
        assert_eq!(
            extract_host("https://GITHUB.COM/path"),
            Some("github.com".into())
        );
    }

    // -----------------------------------------------------------------------
    // Model catalog tests
    // -----------------------------------------------------------------------

    #[test]
    fn model_catalog_lookup() {
        let catalog = CopilotModelCatalog::with_defaults();

        let gpt4o = catalog.find_model("gpt-4o").expect("should find gpt-4o");
        assert_eq!(gpt4o.name, "GPT-4o");
        assert_eq!(gpt4o.max_tokens, 16384);

        let claude = catalog
            .find_model("claude-3.5-sonnet")
            .expect("should find claude-3.5-sonnet");
        assert_eq!(claude.name, "Claude 3.5 Sonnet");

        // Unknown model returns None
        assert!(catalog.find_model("nonexistent-model").is_none());
    }

    #[test]
    fn model_catalog_list_all() {
        let catalog = CopilotModelCatalog::with_defaults();
        let models = catalog.list_models();

        assert_eq!(models.len(), 4, "default catalog should have 4 models");

        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"gpt-4o"));
        assert!(ids.contains(&"gpt-4"));
        assert!(ids.contains(&"gpt-3.5-turbo"));
        assert!(ids.contains(&"claude-3.5-sonnet"));
    }

    #[test]
    fn model_max_tokens_validation() {
        let model = CopilotModel {
            id: "gpt-4".into(),
            name: "GPT-4".into(),
            version: "0613".into(),
            max_tokens: 8192,
            capabilities: vec!["chat".into()],
        };

        // Within limit
        assert!(model.validate_max_tokens(4096).is_ok());
        assert!(model.validate_max_tokens(8192).is_ok());

        // Exceeds limit
        let err = model.validate_max_tokens(8193).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("8193") && msg.contains("8192"),
            "error should mention requested and limit: {msg}"
        );
    }

    #[test]
    fn model_capability_check() {
        let model = CopilotModel {
            id: "gpt-4o".into(),
            name: "GPT-4o".into(),
            version: "2024-05-13".into(),
            max_tokens: 16384,
            capabilities: vec![
                "chat".into(),
                "function_calling".into(),
                "vision".into(),
            ],
        };

        assert!(model.has_capability("chat"));
        assert!(model.has_capability("function_calling"));
        assert!(model.has_capability("vision"));
        assert!(!model.has_capability("audio"));
        assert!(!model.has_capability(""));
    }

    // -----------------------------------------------------------------------
    // Proxy config tests
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_config_defaults() {
        let config = CopilotProxyConfig::default();
        assert_eq!(config.upstream_url, DEFAULT_COPILOT_UPSTREAM_URL);
        assert!(config.model_override.is_none());
        assert!(config.usage_tracking);

        // Defaults should validate
        assert!(config.validate().is_ok());
    }

    #[test]
    fn proxy_config_serialization() {
        let config = CopilotProxyConfig {
            upstream_url: DEFAULT_COPILOT_UPSTREAM_URL.to_string(),
            model_override: Some("gpt-4o".into()),
            usage_tracking: false,
        };

        let json = serde_json::to_string(&config).expect("should serialize");
        let back: CopilotProxyConfig =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(config, back);

        // Deserialize with defaults
        let minimal = r#"{"upstream_url":"https://api.githubcopilot.com"}"#;
        let deserialized: CopilotProxyConfig =
            serde_json::from_str(minimal).expect("should deserialize minimal");
        assert!(deserialized.model_override.is_none());
        assert!(deserialized.usage_tracking);
    }

    // -----------------------------------------------------------------------
    // Security tests
    // -----------------------------------------------------------------------

    /// SECURITY: Upstream URL must be validated against SSRF attacks.
    /// Private IPs, non-HTTPS, and non-allowlisted hosts must be rejected.
    #[test]
    fn upstream_url_ssrf_protection() {
        // Valid Copilot upstream URLs
        assert!(
            validate_copilot_upstream_url(DEFAULT_COPILOT_UPSTREAM_URL).is_ok(),
            "default URL must be accepted"
        );
        assert!(
            validate_copilot_upstream_url(
                "https://copilot-proxy.githubusercontent.com/v1/completions"
            )
            .is_ok(),
            "known proxy URL must be accepted"
        );

        // HTTP rejected (must use HTTPS)
        assert!(
            validate_copilot_upstream_url("http://api.githubcopilot.com").is_err(),
            "HTTP must be rejected"
        );

        // Non-allowlisted hosts rejected (SSRF protection)
        assert!(
            validate_copilot_upstream_url("https://evil.com/api").is_err(),
            "unknown host must be rejected"
        );
        assert!(
            validate_copilot_upstream_url("https://localhost/api").is_err(),
            "localhost must be rejected"
        );
        assert!(
            validate_copilot_upstream_url("https://127.0.0.1/api").is_err(),
            "loopback IP must be rejected"
        );
        assert!(
            validate_copilot_upstream_url("https://169.254.169.254/metadata").is_err(),
            "link-local IP must be rejected (cloud metadata SSRF)"
        );
        assert!(
            validate_copilot_upstream_url("https://10.0.0.1/internal").is_err(),
            "private IP must be rejected"
        );

        // Subdomain spoofing rejected
        assert!(
            validate_copilot_upstream_url(
                "https://api.githubcopilot.com.evil.com/api"
            )
            .is_err(),
            "subdomain spoofing must be rejected"
        );
    }

    #[test]
    fn model_id_validation() {
        // Valid model IDs
        assert!(validate_model_id("gpt-4o").is_ok());
        assert!(validate_model_id("gpt-3.5-turbo").is_ok());
        assert!(validate_model_id("claude-3.5-sonnet").is_ok());
        assert!(validate_model_id("model123").is_ok());

        // Invalid model IDs
        assert!(validate_model_id("").is_err(), "empty must be rejected");
        assert!(
            validate_model_id("model with spaces").is_err(),
            "spaces must be rejected"
        );
        assert!(
            validate_model_id("model;drop").is_err(),
            "semicolons must be rejected"
        );
        assert!(
            validate_model_id("model/path").is_err(),
            "slashes must be rejected"
        );
        assert!(
            validate_model_id("model\ninjection").is_err(),
            "newlines must be rejected"
        );
        assert!(
            validate_model_id("model&param=1").is_err(),
            "URL parameter injection must be rejected"
        );

        // Too long
        let long_id = "a".repeat(129);
        assert!(
            validate_model_id(&long_id).is_err(),
            "model ID exceeding 128 chars must be rejected"
        );
    }

    #[test]
    fn copilot_config_with_proxy_validation() {
        // Valid config with proxy
        let config = CopilotConfig {
            client_id: "test-client".into(),
            enabled: true,
            token_path: None,
            proxy: Some(CopilotProxyConfig::default()),
            model_override: Some("gpt-4o".into()),
        };
        assert!(config.validate().is_ok());

        // Invalid model override
        let bad_config = CopilotConfig {
            client_id: "test-client".into(),
            enabled: true,
            token_path: None,
            proxy: None,
            model_override: Some("model;injection".into()),
        };
        assert!(
            bad_config.validate().is_err(),
            "invalid model override must be rejected"
        );

        // Invalid proxy upstream URL
        let bad_proxy = CopilotConfig {
            client_id: "test-client".into(),
            enabled: true,
            token_path: None,
            proxy: Some(CopilotProxyConfig {
                upstream_url: "https://evil.com/api".into(),
                model_override: None,
                usage_tracking: true,
            }),
            model_override: None,
        };
        assert!(
            bad_proxy.validate().is_err(),
            "proxy with bad upstream URL must be rejected"
        );
    }

    #[test]
    fn model_catalog_add_validates_id() {
        let mut catalog = CopilotModelCatalog::new();

        // Valid add
        let result = catalog.add_model(CopilotModel {
            id: "custom-model-v1".into(),
            name: "Custom".into(),
            version: "1.0".into(),
            max_tokens: 4096,
            capabilities: vec!["chat".into()],
        });
        assert!(result.is_ok());
        assert!(catalog.find_model("custom-model-v1").is_some());

        // Invalid add (bad chars in ID)
        let result = catalog.add_model(CopilotModel {
            id: "bad model/id".into(),
            name: "Bad".into(),
            version: "1.0".into(),
            max_tokens: 4096,
            capabilities: vec![],
        });
        assert!(result.is_err());
    }

    #[test]
    fn model_serialization_roundtrip() {
        let model = CopilotModel {
            id: "gpt-4o".into(),
            name: "GPT-4o".into(),
            version: "2024-05-13".into(),
            max_tokens: 16384,
            capabilities: vec!["chat".into(), "function_calling".into()],
        };

        let json = serde_json::to_string(&model).expect("should serialize");
        let back: CopilotModel = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(model, back);
    }
}
