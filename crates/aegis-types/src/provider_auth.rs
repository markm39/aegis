//! Per-provider authentication flow configurations.
//!
//! Maps each LLM provider to its supported authentication methods (API key,
//! OAuth device flow, PKCE browser flow, CLI token extraction, setup token).
//! Used by the onboarding wizard to present the correct auth UI for each
//! provider.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Auth flow types
// ---------------------------------------------------------------------------

/// How a user can authenticate with a specific provider.
/// A provider may support multiple flows (user picks during onboarding).
#[derive(Debug, Clone)]
pub enum AuthFlowKind {
    /// Paste an API key manually.
    ApiKey,

    /// Run a CLI command externally, then paste the resulting token.
    SetupToken {
        /// Human-readable instructions shown to the user.
        instructions: &'static str,
    },

    /// Extract a token from another CLI tool's config files.
    CliExtract {
        /// Name of the CLI tool (e.g., "Claude Code").
        cli_name: &'static str,
        /// Path to the config file relative to `$HOME`.
        config_rel_path: &'static str,
        /// How to extract the token from the file.
        extraction: TokenExtraction,
    },

    /// OAuth2 Device Authorization Grant (RFC 8628).
    DeviceFlow {
        /// OAuth2 client ID.
        client_id: &'static str,
        /// Device code request endpoint.
        device_code_url: &'static str,
        /// Token endpoint (for polling and refresh).
        token_url: &'static str,
        /// Space-separated scopes.
        scope: &'static str,
        /// Whether to include a PKCE challenge in the device code request.
        use_pkce: bool,
        /// OAuth2 grant type string.
        grant_type: &'static str,
        /// Provider-specific polling behavior.
        poll_style: DeviceFlowPollStyle,
    },

    /// OAuth2 Authorization Code with PKCE + local browser callback.
    PkceBrowser {
        /// How to obtain the client ID (and optional secret).
        client_id_source: ClientIdSource,
        /// Authorization endpoint URL.
        auth_url: &'static str,
        /// Token endpoint URL.
        token_url: &'static str,
        /// Scopes to request.
        scopes: &'static [&'static str],
        /// Local port for the callback server.
        redirect_port: u16,
        /// Path component of the redirect URI.
        redirect_path: &'static str,
    },
}

/// How the client ID is obtained for a PKCE browser flow.
#[derive(Debug, Clone)]
pub enum ClientIdSource {
    /// Hardcoded client ID and optional secret.
    Static {
        client_id: &'static str,
        client_secret: Option<&'static str>,
    },
    /// Extract from an installed CLI tool's source/config.
    CliExtraction {
        cli_name: &'static str,
        /// Glob pattern for the file to search in (relative to `$HOME`).
        search_path: &'static str,
        /// Regex to extract the client ID.
        id_regex: &'static str,
        /// Regex to extract the client secret.
        secret_regex: &'static str,
    },
    /// Read from environment variables.
    EnvVar {
        id_var: &'static str,
        secret_var: Option<&'static str>,
    },
}

/// How to extract a token from a file.
#[derive(Debug, Clone)]
pub enum TokenExtraction {
    /// Parse as JSON and read a field by dot-separated path.
    JsonField(&'static str),
    /// Apply a regex and take the first capture group.
    Regex(&'static str),
}

/// Provider-specific polling behavior for device flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFlowPollStyle {
    /// Standard RFC 8628: poll with `device_code`, handle `authorization_pending`,
    /// `slow_down`, `expired_token`, `access_denied`.
    Standard,
    /// MiniMax variant: poll with `user_code`, handle `pending`/`success`/`error`,
    /// exponential backoff (interval * 1.5, max 10s).
    MiniMaxUserCode,
}

/// A short label for displaying the auth flow in the wizard.
impl AuthFlowKind {
    pub fn display_label(&self) -> &'static str {
        match self {
            AuthFlowKind::ApiKey => "Paste API Key",
            AuthFlowKind::SetupToken { .. } => "Setup Token (paste)",
            AuthFlowKind::CliExtract { cli_name, .. } => {
                // Return a static label since we can't format dynamically
                // with &'static str. The UI layer will use cli_name directly.
                match *cli_name {
                    "Claude Code" => "Extract from Claude Code",
                    "Gemini CLI" => "Extract from Gemini CLI",
                    _ => "Extract from CLI",
                }
            }
            AuthFlowKind::DeviceFlow { .. } => "OAuth Device Flow",
            AuthFlowKind::PkceBrowser { .. } => "OAuth Browser Login",
        }
    }
}

/// Credential type stored after successful authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Standard API key.
    #[default]
    ApiKey,
    /// OAuth2 access token (may have refresh token in token store).
    OAuthToken,
    /// Setup token from CLI tool.
    SetupToken,
    /// Token extracted from another CLI's config.
    CliExtracted,
}

// ---------------------------------------------------------------------------
// Per-provider auth flow registry
// ---------------------------------------------------------------------------

/// GitHub Copilot auth flows.
static COPILOT_FLOWS: &[AuthFlowKind] = &[AuthFlowKind::DeviceFlow {
    client_id: "Iv1.b507a08c87ecfe98",
    device_code_url: "https://github.com/login/device/code",
    token_url: "https://github.com/login/oauth/access_token",
    scope: "read:user",
    use_pkce: false,
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    poll_style: DeviceFlowPollStyle::Standard,
}];

/// Anthropic auth flows (ordered: most convenient first).
static ANTHROPIC_FLOWS: &[AuthFlowKind] = &[
    AuthFlowKind::CliExtract {
        cli_name: "Claude Code",
        config_rel_path: ".claude/.credentials.json",
        extraction: TokenExtraction::JsonField("oauthAccessToken"),
    },
    AuthFlowKind::SetupToken {
        instructions: "In a separate terminal, run:\n\n  claude setup-token\n\nThen paste the token here.",
    },
    AuthFlowKind::ApiKey,
];

/// Qwen Portal auth flows.
static QWEN_FLOWS: &[AuthFlowKind] = &[
    AuthFlowKind::DeviceFlow {
        client_id: "f0304373b74a44d2b584a3fb70ca9e56",
        device_code_url: "https://chat.qwen.ai/api/v1/oauth2/device/code",
        token_url: "https://chat.qwen.ai/api/v1/oauth2/token",
        scope: "openid profile email model.completion",
        use_pkce: true,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        poll_style: DeviceFlowPollStyle::Standard,
    },
    AuthFlowKind::ApiKey,
];

/// MiniMax auth flows.
static MINIMAX_FLOWS: &[AuthFlowKind] = &[
    AuthFlowKind::DeviceFlow {
        client_id: "78257093-7e40-4613-99e0-527b14b39113",
        device_code_url: "https://api.minimax.io/oauth/code",
        token_url: "https://api.minimax.io/oauth/token",
        scope: "group_id profile model.completion",
        use_pkce: true,
        grant_type: "urn:ietf:params:oauth:grant-type:user_code",
        poll_style: DeviceFlowPollStyle::MiniMaxUserCode,
    },
    AuthFlowKind::ApiKey,
];

/// Google Gemini auth flows.
static GOOGLE_FLOWS: &[AuthFlowKind] = &[
    AuthFlowKind::PkceBrowser {
        client_id_source: ClientIdSource::CliExtraction {
            cli_name: "Gemini CLI",
            search_path: ".npm/_npx/**/node_modules/@google/gemini-cli-core/dist/src/core/oauth2.js",
            id_regex: r"(\d+-[a-z0-9]+\.apps\.googleusercontent\.com)",
            secret_regex: r"(GOCSPX-[A-Za-z0-9_-]+)",
        },
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        scopes: &[
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        redirect_port: 8085,
        redirect_path: "/oauth2callback",
    },
    AuthFlowKind::ApiKey,
];

/// Default: API key only.
static API_KEY_ONLY: &[AuthFlowKind] = &[AuthFlowKind::ApiKey];

/// No auth needed (local services).
static NO_AUTH: &[AuthFlowKind] = &[];

/// Get the supported auth flows for a provider, ordered by preference.
///
/// The first flow in the list is the recommended default. Providers with
/// only one flow (API key) skip the auth method selection screen.
pub fn auth_flows_for(provider_id: &str) -> &'static [AuthFlowKind] {
    match provider_id {
        "anthropic" => ANTHROPIC_FLOWS,
        "github-copilot" => COPILOT_FLOWS,
        "qwen" => QWEN_FLOWS,
        "minimax" => MINIMAX_FLOWS,
        "google" => GOOGLE_FLOWS,
        // Local services: no auth required
        "ollama" | "vllm" => NO_AUTH,
        // Everything else: API key only
        _ => API_KEY_ONLY,
    }
}

/// Check if a provider requires an auth method selection step
/// (i.e., has more than one auth flow option).
pub fn has_multiple_auth_flows(provider_id: &str) -> bool {
    auth_flows_for(provider_id).len() > 1
}

/// Check if a provider needs any authentication at all.
pub fn needs_auth(provider_id: &str) -> bool {
    !auth_flows_for(provider_id).is_empty()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copilot_has_device_flow() {
        let flows = auth_flows_for("github-copilot");
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0], AuthFlowKind::DeviceFlow { .. }));
    }

    #[test]
    fn anthropic_has_three_flows() {
        let flows = auth_flows_for("anthropic");
        assert_eq!(flows.len(), 3);
        assert!(matches!(flows[0], AuthFlowKind::CliExtract { .. }));
        assert!(matches!(flows[1], AuthFlowKind::SetupToken { .. }));
        assert!(matches!(flows[2], AuthFlowKind::ApiKey));
    }

    #[test]
    fn qwen_has_device_flow_and_api_key() {
        let flows = auth_flows_for("qwen");
        assert_eq!(flows.len(), 2);
        assert!(matches!(flows[0], AuthFlowKind::DeviceFlow { use_pkce: true, .. }));
        assert!(matches!(flows[1], AuthFlowKind::ApiKey));
    }

    #[test]
    fn minimax_uses_user_code_poll_style() {
        let flows = auth_flows_for("minimax");
        assert!(matches!(
            flows[0],
            AuthFlowKind::DeviceFlow {
                poll_style: DeviceFlowPollStyle::MiniMaxUserCode,
                ..
            }
        ));
    }

    #[test]
    fn google_has_pkce_browser_flow() {
        let flows = auth_flows_for("google");
        assert_eq!(flows.len(), 2);
        assert!(matches!(flows[0], AuthFlowKind::PkceBrowser { .. }));
        assert!(matches!(flows[1], AuthFlowKind::ApiKey));
    }

    #[test]
    fn openai_is_api_key_only() {
        let flows = auth_flows_for("openai");
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0], AuthFlowKind::ApiKey));
    }

    #[test]
    fn ollama_needs_no_auth() {
        assert!(!needs_auth("ollama"));
        assert!(!needs_auth("vllm"));
    }

    #[test]
    fn multiple_auth_flows_check() {
        assert!(has_multiple_auth_flows("anthropic"));
        assert!(has_multiple_auth_flows("qwen"));
        assert!(has_multiple_auth_flows("minimax"));
        assert!(has_multiple_auth_flows("google"));
        assert!(!has_multiple_auth_flows("openai"));
        assert!(!has_multiple_auth_flows("github-copilot"));
    }

    #[test]
    fn display_labels() {
        assert_eq!(AuthFlowKind::ApiKey.display_label(), "Paste API Key");
        let flows = auth_flows_for("anthropic");
        assert_eq!(flows[0].display_label(), "Extract from Claude Code");
        assert_eq!(flows[1].display_label(), "Setup Token (paste)");
    }

    #[test]
    fn unknown_provider_defaults_to_api_key() {
        let flows = auth_flows_for("unknown-provider-xyz");
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0], AuthFlowKind::ApiKey));
    }
}
