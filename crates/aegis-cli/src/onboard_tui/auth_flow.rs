//! Auth flow executors for the onboarding wizard.
//!
//! Each executor drives a specific authentication mechanism (device flow,
//! PKCE browser OAuth, CLI token extraction, setup token) using the existing
//! infrastructure in `aegis-types/src/oauth.rs` and `aegis-types/src/copilot.rs`.
//!
//! All executors are synchronous (blocking) since the wizard runs in raw
//! terminal mode with a single-threaded event loop.

use std::path::PathBuf;
use std::time::Duration;

use aegis_types::oauth::{
    self, DeviceCodeResponse, DeviceFlowPollState, MiniMaxPollState, OAuthToken, PkceChallenge,
};
use aegis_types::provider_auth::{
    AuthFlowKind, ClientIdSource, DeviceFlowPollStyle, TokenExtraction,
};
use anyhow::{Context, Result, bail};

use super::callback_server;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// A successfully obtained auth token with metadata.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// The token string (API key, access token, or setup token).
    pub token: String,
    /// What kind of token this is.
    pub token_type: AuthTokenType,
    /// Optional refresh token (for OAuth flows). Stored for future token refresh support.
    #[allow(dead_code)]
    pub refresh_token: Option<String>,
    /// Optional base URL override (e.g., Copilot proxy endpoint).
    pub base_url_override: Option<String>,
}

/// The kind of auth token obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTokenType {
    /// Plain API key (reserved for future use when API key flow creates AuthToken).
    #[allow(dead_code)]
    ApiKey,
    OAuthAccess,
    SetupToken,
    CliExtracted,
}

// ---------------------------------------------------------------------------
// Device flow state (for wizard integration)
// ---------------------------------------------------------------------------

/// Ongoing device flow state tracked by the wizard.
pub struct DeviceFlowState {
    /// The device code response from the initial request.
    pub response: DeviceCodeResponse,
    /// Client ID used for polling.
    pub client_id: String,
    /// Token URL for polling.
    pub token_url: String,
    /// Grant type for polling.
    pub grant_type: String,
    /// PKCE code verifier (if PKCE was used).
    pub pkce_verifier: Option<String>,
    /// Polling style (standard or MiniMax).
    pub poll_style: DeviceFlowPollStyle,
    /// Current polling interval (may increase on slow_down).
    pub poll_interval: Duration,
    /// Time of last poll attempt.
    pub last_poll: std::time::Instant,
    /// Number of polls attempted.
    pub poll_count: u32,
}

/// Result of a single device flow poll tick.
#[derive(Debug)]
pub enum DevicePollResult {
    /// Still waiting for user authorization.
    Pending,
    /// Got a token.
    Success(AuthToken),
    /// The device code expired.
    Expired,
    /// The user denied authorization.
    Denied,
    /// An error occurred.
    Error(String),
    /// Not enough time has passed since last poll.
    TooSoon,
}

impl DeviceFlowState {
    /// Poll once if enough time has passed since the last poll.
    pub fn poll_tick(&mut self) -> DevicePollResult {
        // Check if enough time has elapsed since last poll.
        if self.last_poll.elapsed() < self.poll_interval {
            return DevicePollResult::TooSoon;
        }
        self.last_poll = std::time::Instant::now();
        self.poll_count += 1;

        match self.poll_style {
            DeviceFlowPollStyle::Standard => self.poll_standard(),
            DeviceFlowPollStyle::MiniMaxUserCode => self.poll_minimax(),
        }
    }

    fn poll_standard(&mut self) -> DevicePollResult {
        let result = if let Some(ref verifier) = self.pkce_verifier {
            oauth::poll_device_code_with_pkce(
                &self.token_url,
                &self.client_id,
                &self.response.device_code,
                verifier,
                &self.grant_type,
            )
        } else {
            oauth::poll_device_code(&self.token_url, &self.client_id, &self.response.device_code)
        };

        match result {
            Ok(DeviceFlowPollState::AuthorizationPending) => DevicePollResult::Pending,
            Ok(DeviceFlowPollState::SlowDown) => {
                self.poll_interval += Duration::from_secs(5);
                DevicePollResult::Pending
            }
            Ok(DeviceFlowPollState::ExpiredToken) => DevicePollResult::Expired,
            Ok(DeviceFlowPollState::AccessDenied) => DevicePollResult::Denied,
            Ok(DeviceFlowPollState::Success(token)) => {
                DevicePollResult::Success(oauth_token_to_auth_token(token))
            }
            Err(e) => DevicePollResult::Error(e.to_string()),
        }
    }

    fn poll_minimax(&mut self) -> DevicePollResult {
        let result = oauth::poll_minimax_device_code(
            &self.token_url,
            &self.client_id,
            &self.response.user_code,
            self.pkce_verifier.as_deref().unwrap_or(""),
        );

        match result {
            Ok(MiniMaxPollState::Pending) => {
                // MiniMax uses exponential backoff: interval * 1.5, max 10s
                let new_ms = (self.poll_interval.as_millis() as f64 * 1.5) as u64;
                self.poll_interval = Duration::from_millis(new_ms.min(10_000));
                DevicePollResult::Pending
            }
            Ok(MiniMaxPollState::Success(token)) => {
                DevicePollResult::Success(oauth_token_to_auth_token(token))
            }
            Ok(MiniMaxPollState::Error(msg)) => DevicePollResult::Error(msg),
            Err(e) => DevicePollResult::Error(e.to_string()),
        }
    }
}

fn oauth_token_to_auth_token(token: OAuthToken) -> AuthToken {
    AuthToken {
        token: token.access_token,
        token_type: AuthTokenType::OAuthAccess,
        refresh_token: if token.refresh_token.is_empty() {
            None
        } else {
            Some(token.refresh_token)
        },
        base_url_override: None,
    }
}

// ---------------------------------------------------------------------------
// Initiate device flow
// ---------------------------------------------------------------------------

/// Start a device flow by requesting a device code.
///
/// Returns a `DeviceFlowState` that the wizard polls on each tick.
pub fn start_device_flow(flow: &AuthFlowKind) -> Result<DeviceFlowState> {
    let (client_id, device_code_url, token_url, scope, use_pkce, grant_type, poll_style) =
        match flow {
            AuthFlowKind::DeviceFlow {
                client_id,
                device_code_url,
                token_url,
                scope,
                use_pkce,
                grant_type,
                poll_style,
            } => (
                *client_id,
                *device_code_url,
                *token_url,
                *scope,
                *use_pkce,
                *grant_type,
                *poll_style,
            ),
            _ => bail!("start_device_flow called with non-device-flow auth kind"),
        };

    let (response, pkce_verifier) = if use_pkce {
        let pkce = PkceChallenge::generate();
        let resp = oauth::request_device_code_with_pkce(device_code_url, client_id, scope, &pkce)
            .context("failed to request device code")?;
        (resp, Some(pkce.code_verifier))
    } else {
        let resp = oauth::request_device_code(device_code_url, client_id, scope)
            .context("failed to request device code")?;
        (resp, None)
    };

    let poll_interval = Duration::from_secs(response.interval.max(1));

    Ok(DeviceFlowState {
        response,
        client_id: client_id.to_string(),
        token_url: token_url.to_string(),
        grant_type: grant_type.to_string(),
        pkce_verifier,
        poll_style,
        poll_interval,
        last_poll: std::time::Instant::now() - poll_interval, // Allow immediate first poll
        poll_count: 0,
    })
}

// ---------------------------------------------------------------------------
// Copilot token exchange
// ---------------------------------------------------------------------------

/// Exchange a GitHub OAuth token for a Copilot session token.
///
/// Called after a successful GitHub device flow for the `github-copilot` provider.
pub fn exchange_copilot_token(github_token: &str) -> Result<AuthToken> {
    let session = aegis_types::copilot::exchange_for_copilot_token(github_token)
        .context("failed to exchange GitHub token for Copilot session token")?;

    Ok(AuthToken {
        token: session.token,
        token_type: AuthTokenType::OAuthAccess,
        refresh_token: None,
        base_url_override: Some(session.proxy_endpoint),
    })
}

// ---------------------------------------------------------------------------
// CLI token extraction
// ---------------------------------------------------------------------------

/// Try to extract a token from a CLI tool's config file.
pub fn extract_cli_token(flow: &AuthFlowKind) -> Result<Option<AuthToken>> {
    let (cli_name, config_rel_path, extraction) = match flow {
        AuthFlowKind::CliExtract {
            cli_name,
            config_rel_path,
            extraction,
        } => (*cli_name, *config_rel_path, extraction),
        _ => bail!("extract_cli_token called with non-CLI-extract auth kind"),
    };

    let home = std::env::var("HOME").context("HOME not set")?;
    let path = PathBuf::from(home).join(config_rel_path);

    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {cli_name} config at {}", path.display()))?;

    let token = match extraction {
        TokenExtraction::JsonField(field) => {
            let json: serde_json::Value = serde_json::from_str(&contents)
                .with_context(|| format!("failed to parse {cli_name} config as JSON"))?;
            extract_json_field(&json, field)
        }
        TokenExtraction::Regex(pattern) => {
            let re = regex::Regex::new(pattern)
                .with_context(|| format!("invalid regex for {cli_name} extraction"))?;
            re.captures(&contents)
                .and_then(|c| c.get(1).or_else(|| c.get(0)))
                .map(|m| m.as_str().to_string())
        }
    };

    match token {
        Some(t) if !t.is_empty() => Ok(Some(AuthToken {
            token: t,
            token_type: AuthTokenType::CliExtracted,
            refresh_token: None,
            base_url_override: None,
        })),
        _ => Ok(None),
    }
}

/// Extract a value from a JSON object by dot-separated path.
fn extract_json_field(json: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = json;
    for key in path.split('.') {
        current = current.get(key)?;
    }
    current.as_str().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// PKCE browser flow
// ---------------------------------------------------------------------------

/// PKCE browser flow state for the wizard.
pub struct PkceBrowserState {
    /// The PKCE challenge (verifier is needed for token exchange).
    pub pkce: PkceChallenge,
    /// The OAuth state parameter for CSRF protection.
    pub state: String,
    /// The authorization URL that was opened in the browser.
    pub auth_url: String,
    /// The client ID being used.
    pub client_id: String,
    /// The client secret (if available).
    pub client_secret: Option<String>,
    /// The token URL for code exchange.
    pub token_url: String,
    /// The redirect URI.
    pub redirect_uri: String,
    /// The callback server port.
    pub port: u16,
    /// The expected callback path.
    pub path: String,
}

/// Start a PKCE browser OAuth flow.
///
/// Generates PKCE challenge, builds the auth URL, opens the browser,
/// and returns a `PkceBrowserState` that the wizard uses to wait for
/// the callback.
pub fn start_pkce_browser_flow(flow: &AuthFlowKind) -> Result<PkceBrowserState> {
    let (client_id_source, auth_url, token_url, scopes, redirect_port, redirect_path) = match flow {
        AuthFlowKind::PkceBrowser {
            client_id_source,
            auth_url,
            token_url,
            scopes,
            redirect_port,
            redirect_path,
        } => (
            client_id_source,
            *auth_url,
            *token_url,
            *scopes,
            *redirect_port,
            *redirect_path,
        ),
        _ => bail!("start_pkce_browser_flow called with non-PKCE-browser auth kind"),
    };

    // Resolve client ID and optional secret.
    let (client_id, client_secret) = resolve_client_id(client_id_source)?;

    let pkce = PkceChallenge::generate();
    let state = uuid::Uuid::new_v4().to_string();
    let redirect_uri = format!("http://localhost:{redirect_port}{redirect_path}");

    // Build the authorization URL.
    let config = aegis_types::oauth::OAuthConfig {
        client_id: client_id.clone(),
        client_secret_env: String::new(), // Not used for URL building
        auth_url: auth_url.to_string(),
        token_url: token_url.to_string(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        redirect_uri: redirect_uri.clone(),
    };
    let oauth_flow = aegis_types::oauth::OAuthFlow::new(config);
    let full_auth_url = oauth_flow.authorization_url(&state, Some(&pkce));

    // Append access_type=offline and prompt=consent for Google
    let full_auth_url = if auth_url.contains("google.com") {
        format!("{full_auth_url}&access_type=offline&prompt=consent")
    } else {
        full_auth_url
    };

    // Try to open the browser.
    let _ = open_browser(&full_auth_url);

    Ok(PkceBrowserState {
        pkce,
        state,
        auth_url: full_auth_url,
        client_id,
        client_secret,
        token_url: token_url.to_string(),
        redirect_uri,
        port: redirect_port,
        path: redirect_path.to_string(),
    })
}

/// Wait for the PKCE browser callback and exchange the code for tokens.
///
/// This blocks until the callback is received or times out.
pub fn complete_pkce_browser_flow(state: &PkceBrowserState) -> Result<AuthToken> {
    let params = callback_server::wait_for_callback(
        state.port,
        &state.path,
        Duration::from_secs(300), // 5 minute timeout
    )
    .context("failed to receive OAuth callback")?;

    // Validate state for CSRF protection.
    if params.state != state.state {
        bail!(
            "OAuth state mismatch: expected '{}', got '{}'",
            state.state,
            params.state
        );
    }

    // Exchange the code for tokens.
    // We need to use blocking reqwest since we're in a sync context.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", &params.code),
        ("redirect_uri", &state.redirect_uri),
        ("client_id", &state.client_id),
        ("code_verifier", &state.pkce.code_verifier),
    ];

    let secret_owned;
    if let Some(ref secret) = state.client_secret {
        secret_owned = secret.clone();
        form.push(("client_secret", &secret_owned));
    }

    let resp = client
        .post(&state.token_url)
        .form(&form)
        .send()
        .context("token exchange request failed")?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().context("failed to parse token response")?;

    if !status.is_success() {
        let err = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        bail!("token exchange failed: {err}");
    }

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .context("missing access_token in response")?
        .to_string();

    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(AuthToken {
        token: access_token,
        token_type: AuthTokenType::OAuthAccess,
        refresh_token,
        base_url_override: None,
    })
}

/// Resolve a `ClientIdSource` to a (client_id, optional client_secret) pair.
fn resolve_client_id(source: &ClientIdSource) -> Result<(String, Option<String>)> {
    match source {
        ClientIdSource::Static {
            client_id,
            client_secret,
        } => Ok((client_id.to_string(), client_secret.map(|s| s.to_string()))),
        ClientIdSource::EnvVar { id_var, secret_var } => {
            let id = std::env::var(id_var)
                .with_context(|| format!("environment variable {id_var} not set"))?;
            let secret = secret_var.and_then(|v| std::env::var(v).ok());
            Ok((id, secret))
        }
        ClientIdSource::CliExtraction {
            cli_name,
            search_path,
            id_regex,
            secret_regex,
        } => {
            let home = std::env::var("HOME").context("HOME not set")?;
            let base = PathBuf::from(&home);

            // Use glob to find the file.
            let pattern = base.join(search_path).to_string_lossy().to_string();
            let mut found_id = None;
            let mut found_secret = None;

            for path in glob::glob(&pattern)
                .unwrap_or_else(|_| glob::glob("").unwrap())
                .flatten()
            {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if found_id.is_none() {
                        if let Ok(re) = regex::Regex::new(id_regex) {
                            found_id = re
                                .captures(&contents)
                                .and_then(|c| c.get(1).or_else(|| c.get(0)))
                                .map(|m| m.as_str().to_string());
                        }
                    }
                    if found_secret.is_none() {
                        if let Ok(re) = regex::Regex::new(secret_regex) {
                            found_secret = re
                                .captures(&contents)
                                .and_then(|c| c.get(1).or_else(|| c.get(0)))
                                .map(|m| m.as_str().to_string());
                        }
                    }
                    if found_id.is_some() {
                        break;
                    }
                }
            }

            match found_id {
                Some(id) => Ok((id, found_secret)),
                None => bail!("could not extract client ID from {cli_name} -- is it installed?"),
            }
        }
    }
}

/// Open a URL in the system's default browser.
fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = url;
        // Can't open browser on this platform.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_field_simple() {
        let json: serde_json::Value = serde_json::json!({"oauthAccessToken": "test-token-123"});
        assert_eq!(
            extract_json_field(&json, "oauthAccessToken"),
            Some("test-token-123".into())
        );
    }

    #[test]
    fn extract_json_field_nested() {
        let json: serde_json::Value = serde_json::json!({"auth": {"token": "nested-token"}});
        assert_eq!(
            extract_json_field(&json, "auth.token"),
            Some("nested-token".into())
        );
    }

    #[test]
    fn extract_json_field_missing() {
        let json: serde_json::Value = serde_json::json!({"other": "value"});
        assert_eq!(extract_json_field(&json, "nonexistent"), None);
    }

    #[test]
    fn oauth_token_conversion() {
        let oauth = OAuthToken {
            access_token: "access-123".into(),
            refresh_token: "refresh-456".into(),
            expires_at: None,
            scope: None,
        };
        let auth = oauth_token_to_auth_token(oauth);
        assert_eq!(auth.token, "access-123");
        assert_eq!(auth.token_type, AuthTokenType::OAuthAccess);
        assert_eq!(auth.refresh_token, Some("refresh-456".into()));
    }

    #[test]
    fn oauth_token_conversion_no_refresh() {
        let oauth = OAuthToken {
            access_token: "access".into(),
            refresh_token: String::new(),
            expires_at: None,
            scope: None,
        };
        let auth = oauth_token_to_auth_token(oauth);
        assert!(auth.refresh_token.is_none());
    }
}
