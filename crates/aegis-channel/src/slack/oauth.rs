//! Slack OAuth 2.0 flow stubs for app installation.
//!
//! Provides URL construction and token exchange scaffolding for the
//! Slack OAuth V2 flow. The `client_secret` is never stored in code
//! and must come from configuration.
//!
//! Reference: <https://api.slack.com/authentication/oauth-v2>

use serde::Deserialize;

use crate::channel::ChannelError;

/// Configuration for the Slack OAuth flow.
///
/// All secrets must come from external configuration (environment
/// variables, config files, or secret managers). Never hardcode secrets.
#[derive(Clone)]
pub struct SlackOAuthConfig {
    /// OAuth client ID from the Slack app settings.
    pub client_id: String,
    /// OAuth client secret from the Slack app settings.
    /// MUST NOT be hardcoded -- must come from config or environment.
    pub client_secret: String,
    /// Redirect URI registered in the Slack app settings.
    pub redirect_uri: String,
    /// OAuth scopes to request (e.g., "chat:write", "reactions:write").
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for SlackOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackOAuthConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Token response from the Slack OAuth V2 access endpoint.
#[derive(Clone, Deserialize)]
pub struct SlackTokenResponse {
    /// The bot access token (xoxb-...).
    pub access_token: String,
    /// The team/workspace ID.
    pub team_id: String,
    /// Granted scopes (comma-separated).
    pub scope: String,
    /// The bot user ID.
    pub bot_user_id: String,
}

impl std::fmt::Debug for SlackTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("team_id", &self.team_id)
            .field("scope", &self.scope)
            .field("bot_user_id", &self.bot_user_id)
            .finish()
    }
}

/// Slack OAuth V2 authorize endpoint.
const OAUTH_AUTHORIZE_URL: &str = "https://slack.com/oauth/v2/authorize";

/// Slack OAuth V2 token exchange endpoint.
const OAUTH_ACCESS_URL: &str = "https://slack.com/api/oauth.v2.access";

/// Build the Slack OAuth V2 authorization URL.
///
/// The `state` parameter should be a cryptographically random value
/// stored in the user's session to prevent CSRF attacks.
pub fn build_authorize_url(config: &SlackOAuthConfig, state: &str) -> String {
    let scopes = config.scopes.join(",");
    format!(
        "{OAUTH_AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
        url_encode(&config.client_id),
        url_encode(&scopes),
        url_encode(&config.redirect_uri),
        url_encode(state),
    )
}

/// Exchange an authorization code for an access token.
///
/// This is a stub that builds the correct HTTP request but requires a
/// running HTTP client to execute. In production, this would make the
/// actual POST request to Slack's token endpoint.
pub async fn exchange_code(
    config: &SlackOAuthConfig,
    code: &str,
) -> Result<SlackTokenResponse, ChannelError> {
    let client = reqwest::Client::new();

    let resp = client
        .post(OAUTH_ACCESS_URL)
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
        ])
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;

    if body.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let error = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(ChannelError::Api(format!(
            "OAuth token exchange failed: {error}"
        )));
    }

    // Extract the authed_user or bot token fields
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChannelError::Api("missing access_token in OAuth response".into()))?
        .to_string();

    let team_id = body
        .pointer("/team/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let bot_user_id = body
        .get("bot_user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(SlackTokenResponse {
        access_token,
        team_id,
        scope,
        bot_user_id,
    })
}

/// Minimal percent-encoding for URL query parameters.
///
/// Encodes characters that are unsafe in URL query strings.
fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_authorize_url_construction() {
        let config = SlackOAuthConfig {
            client_id: "123456.789012".to_string(),
            client_secret: "secret_value".to_string(), // not embedded in URL
            redirect_uri: "https://aegis.example.com/oauth/callback".to_string(),
            scopes: vec![
                "chat:write".to_string(),
                "reactions:write".to_string(),
                "pins:write".to_string(),
            ],
        };

        let state = "random_csrf_token_abc123";
        let url = build_authorize_url(&config, state);

        assert!(url.starts_with("https://slack.com/oauth/v2/authorize?"));
        assert!(url.contains("client_id=123456.789012"));
        assert!(url.contains("scope=chat%3Awrite%2Creactions%3Awrite%2Cpins%3Awrite"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Faegis.example.com%2Foauth%2Fcallback"));
        assert!(url.contains("state=random_csrf_token_abc123"));

        // client_secret must NOT appear in the authorize URL
        assert!(!url.contains("secret_value"));
        assert!(!url.contains("client_secret"));
    }

    #[test]
    fn test_oauth_url_encoding() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a:b,c"), "a%3Ab%2Cc");
        assert_eq!(
            url_encode("safe-value_123.test~ok"),
            "safe-value_123.test~ok"
        );
    }

    #[test]
    fn test_oauth_config_does_not_hardcode_secret() {
        // This test documents the requirement that client_secret comes
        // from configuration, not from source code. The struct requires
        // it to be provided at construction time.
        let config = SlackOAuthConfig {
            client_id: "id".to_string(),
            client_secret: std::env::var("SLACK_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: "https://example.com/callback".to_string(),
            scopes: vec!["chat:write".to_string()],
        };

        // The secret should be empty in test environments (no env var set)
        // In production, it would come from a config file or secret manager
        let url = build_authorize_url(&config, "state");
        assert!(!url.contains("client_secret"));
    }

    #[test]
    fn test_token_response_deserialization() {
        let json = r#"{
            "access_token": "xoxb-test-token-123",
            "team_id": "T12345",
            "scope": "chat:write,reactions:write",
            "bot_user_id": "U98765"
        }"#;

        let response: SlackTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.access_token, "xoxb-test-token-123");
        assert_eq!(response.team_id, "T12345");
        assert_eq!(response.scope, "chat:write,reactions:write");
        assert_eq!(response.bot_user_id, "U98765");
    }
}
