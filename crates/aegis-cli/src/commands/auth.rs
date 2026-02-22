//! Provider auth profile management for orchestrator onboarding/runtime use.
//!
//! Stores profile metadata under `~/.aegis/auth/auth_profiles.toml`.
//! Secrets are referenced via environment-variable names and never persisted.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthProfile {
    id: String,
    provider: String,
    method: String,
    #[serde(default)]
    credential_env: Option<String>,
    created_at_utc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AuthStore {
    #[serde(default)]
    default_profile: Option<String>,
    #[serde(default)]
    profiles: Vec<AuthProfile>,
}

fn auth_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".aegis").join("auth")
}

fn auth_store_path() -> PathBuf {
    auth_dir().join("auth_profiles.toml")
}

fn normalize_method(method: Option<&str>) -> anyhow::Result<String> {
    let method = method.unwrap_or("oauth").trim().to_ascii_lowercase();
    match method.as_str() {
        "oauth" | "api-key" | "setup-token" => Ok(method),
        _ => Err(anyhow::anyhow!(
            "unsupported auth method '{method}'. Use oauth, api-key, or setup-token."
        )),
    }
}

fn default_credential_env(provider: &str, method: &str) -> Option<String> {
    let provider = provider.to_ascii_lowercase();
    match method {
        "oauth" => None,
        "api-key" => {
            if provider == "openai" {
                Some("OPENAI_API_KEY".to_string())
            } else if provider == "anthropic" {
                Some("ANTHROPIC_API_KEY".to_string())
            } else {
                Some(format!(
                    "{}_API_KEY",
                    provider.to_ascii_uppercase().replace('-', "_")
                ))
            }
        }
        "setup-token" => {
            if provider == "anthropic" {
                Some("ANTHROPIC_SETUP_TOKEN".to_string())
            } else {
                Some(format!(
                    "{}_SETUP_TOKEN",
                    provider.to_ascii_uppercase().replace('-', "_")
                ))
            }
        }
        _ => None,
    }
}

fn load_store(path: &Path) -> anyhow::Result<AuthStore> {
    if !path.exists() {
        return Ok(AuthStore::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read auth profile store at {}", path.display()))?;
    let store: AuthStore = toml::from_str(&content)
        .with_context(|| format!("failed to parse auth profile store at {}", path.display()))?;
    Ok(store)
}

fn save_store(path: &Path, store: &AuthStore) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid auth profile store path"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let toml = toml::to_string_pretty(store).context("failed to serialize auth profile store")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, toml).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), path.display()))?;
    lock_file_permissions(path)?;
    Ok(())
}

fn lock_file_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("failed to secure permissions on {}", path.display()))?;
    }
    Ok(())
}

fn auth_readiness(profile: &AuthProfile) -> (bool, String) {
    match profile.method.as_str() {
        "oauth" => (
            true,
            "oauth profile configured (provider session handled externally)".to_string(),
        ),
        "api-key" | "setup-token" => {
            let Some(var) = profile.credential_env.as_deref() else {
                return (
                    false,
                    format!("missing credential_env for {}", profile.method),
                );
            };
            if std::env::var(var)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some()
            {
                (true, format!("{var} is set"))
            } else {
                (false, format!("{var} is not set"))
            }
        }
        other => (false, format!("unknown auth method '{other}'")),
    }
}

fn resolve_profile<'a>(store: &'a AuthStore, target: Option<&str>) -> Option<&'a AuthProfile> {
    if let Some(target) = target {
        if let Some(found) = store.profiles.iter().find(|p| p.id == target) {
            return Some(found);
        }
        return store.profiles.iter().find(|p| p.provider == target);
    }
    if let Some(default_id) = store.default_profile.as_deref() {
        if let Some(found) = store.profiles.iter().find(|p| p.id == default_id) {
            return Some(found);
        }
    }
    store.profiles.first()
}

pub fn list() -> anyhow::Result<()> {
    let path = auth_store_path();
    let store = load_store(&path)?;
    if store.profiles.is_empty() {
        println!("No auth profiles configured. Use `aegis auth add <provider>`.");
        return Ok(());
    }

    println!("Auth profiles:");
    for profile in &store.profiles {
        let (ready, note) = auth_readiness(profile);
        let marker = if store.default_profile.as_deref() == Some(profile.id.as_str()) {
            "*"
        } else {
            " "
        };
        println!(
            "{} {}  provider={} method={} env={} ready={} ({})",
            marker,
            profile.id,
            profile.provider,
            profile.method,
            profile.credential_env.as_deref().unwrap_or("-"),
            ready,
            note
        );
    }
    Ok(())
}

pub fn add(
    provider: &str,
    method: Option<&str>,
    profile_id: Option<&str>,
    credential_env: Option<&str>,
    set_default: bool,
) -> anyhow::Result<()> {
    let provider = provider.trim().to_ascii_lowercase();
    if provider.is_empty() {
        return Err(anyhow::anyhow!("provider cannot be empty"));
    }
    let method = normalize_method(method)?;
    let profile_id = profile_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("{provider}:{method}"));
    let credential_env = credential_env
        .map(str::to_string)
        .or_else(|| default_credential_env(&provider, &method));

    let path = auth_store_path();
    let mut store = load_store(&path)?;
    let now = chrono::Utc::now().to_rfc3339();
    let profile = AuthProfile {
        id: profile_id.clone(),
        provider: provider.clone(),
        method: method.clone(),
        credential_env,
        created_at_utc: now,
    };

    if let Some(existing) = store.profiles.iter_mut().find(|p| p.id == profile_id) {
        *existing = profile;
    } else {
        store.profiles.push(profile);
    }

    if set_default || store.default_profile.is_none() {
        store.default_profile = Some(profile_id.clone());
    }

    save_store(&path, &store)?;
    println!(
        "Configured auth profile '{}' for provider '{}' (method={}).",
        profile_id, provider, method
    );
    if let Some(var) = default_credential_env(&provider, &method) {
        println!("Credential env hint: {var}");
    }
    Ok(())
}

pub fn login(provider: &str, method: Option<&str>, profile_id: Option<&str>) -> anyhow::Result<()> {
    let method = normalize_method(method)?;
    add(provider, Some(&method), profile_id, None, true)?;

    println!("Login flow guidance for provider '{provider}' (method={method}):");
    match (provider, method.as_str()) {
        ("openai", "oauth") => {
            println!("  1. Authenticate with your OpenAI/Codex account in the provider tool.");
            println!("  2. Re-run `aegis auth test openai` to verify readiness.");
        }
        ("anthropic", "setup-token") => {
            println!("  1. Generate a setup-token in your Anthropic/Claude workflow.");
            println!("  2. Export ANTHROPIC_SETUP_TOKEN, then run `aegis auth test anthropic`.");
        }
        (_, "api-key") => {
            println!("  1. Export the credential env var shown above.");
            println!("  2. Run `aegis auth test {provider}`.");
        }
        _ => {
            println!("  1. Complete provider authentication.");
            println!("  2. Run `aegis auth test {provider}`.");
        }
    }
    Ok(())
}

pub fn test(target: Option<&str>) -> anyhow::Result<()> {
    let path = auth_store_path();
    let store = load_store(&path)?;
    if store.profiles.is_empty() {
        println!("No auth profiles configured. Use `aegis auth add <provider>`.");
        return Ok(());
    }
    let Some(profile) = resolve_profile(&store, target) else {
        println!(
            "No auth profile found for '{}'.",
            target.unwrap_or("(default)")
        );
        return Ok(());
    };
    let (ready, note) = auth_readiness(profile);
    println!(
        "Auth test '{}' provider={} method={}: ready={} ({})",
        profile.id, profile.provider, profile.method, ready, note
    );
    Ok(())
}

/// Log out a provider by removing its auth profile and any stored OAuth tokens.
pub fn logout(provider: &str) -> anyhow::Result<()> {
    let provider = provider.trim().to_ascii_lowercase();
    if provider.is_empty() {
        return Err(anyhow::anyhow!("provider cannot be empty"));
    }

    let path = auth_store_path();
    let mut store = load_store(&path)?;

    let removed_count = store.profiles.len();
    store.profiles.retain(|p| p.provider != provider && p.id != provider);
    let removed = removed_count - store.profiles.len();

    if removed == 0 {
        println!("No auth profiles found for '{provider}'.");
    } else {
        // If the default profile was removed, clear it.
        if let Some(ref default_id) = store.default_profile {
            if !store.profiles.iter().any(|p| &p.id == default_id) {
                store.default_profile = store.profiles.first().map(|p| p.id.clone());
            }
        }
        save_store(&path, &store)?;
        println!("Removed {removed} auth profile(s) for '{provider}'.");
    }

    // Also remove any stored OAuth tokens for this provider.
    let token_store = aegis_types::oauth::FileTokenStore::new(&provider);
    if let Ok(ts) = token_store {
        if ts.path().exists() {
            use aegis_types::oauth::OAuthTokenStore;
            ts.delete()
                .map_err(|e| anyhow::anyhow!("failed to remove stored token: {e}"))?;
            println!("Removed stored OAuth token for '{provider}'.");
        }
    }

    Ok(())
}

/// Show the status of all configured auth profiles and their stored tokens.
pub fn status() -> anyhow::Result<()> {
    let path = auth_store_path();
    let store = load_store(&path)?;

    // Show profiles.
    if store.profiles.is_empty() {
        println!("No auth profiles configured.");
    } else {
        println!("Auth profiles:");
        for profile in &store.profiles {
            let (ready, note) = auth_readiness(profile);
            let default_marker = if store.default_profile.as_deref() == Some(profile.id.as_str()) {
                " (default)"
            } else {
                ""
            };
            println!(
                "  {}{}: provider={} method={} ready={} ({})",
                profile.id, default_marker, profile.provider, profile.method, ready, note
            );
        }
    }

    // Show stored OAuth tokens.
    let stored = aegis_types::oauth::list_stored_providers()
        .unwrap_or_default();

    if stored.is_empty() {
        println!("\nNo stored OAuth tokens.");
    } else {
        println!("\nStored OAuth tokens:");
        for provider in &stored {
            let token_store = aegis_types::oauth::FileTokenStore::new(provider);
            if let Ok(ts) = token_store {
                #[allow(unused_imports)]
                use aegis_types::oauth::OAuthTokenStore;
                match aegis_types::oauth::check_token_status(&ts) {
                    Ok(aegis_types::oauth::TokenStatus::Valid {
                        expires_in_secs,
                        scope,
                    }) => {
                        let scope_str = scope
                            .as_deref()
                            .unwrap_or("(none)");
                        let minutes = expires_in_secs / 60;
                        println!(
                            "  {provider}: valid (expires in {minutes}m, scope={scope_str})"
                        );
                    }
                    Ok(aegis_types::oauth::TokenStatus::Expired { has_refresh }) => {
                        let refresh_note = if has_refresh {
                            ", refresh token available"
                        } else {
                            ", no refresh token"
                        };
                        println!("  {provider}: expired{refresh_note}");
                    }
                    Ok(aegis_types::oauth::TokenStatus::NotFound) => {
                        println!("  {provider}: no token stored");
                    }
                    Err(e) => {
                        println!("  {provider}: error reading token: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Manually refresh an OAuth token for a provider.
pub fn refresh(provider: &str) -> anyhow::Result<()> {
    let provider = provider.trim().to_ascii_lowercase();
    if provider.is_empty() {
        return Err(anyhow::anyhow!("provider cannot be empty"));
    }

    let token_store = aegis_types::oauth::FileTokenStore::new(&provider)
        .map_err(|e| anyhow::anyhow!("invalid provider name: {e}"))?;

    use aegis_types::oauth::OAuthTokenStore;
    let token = token_store
        .load()
        .map_err(|e| anyhow::anyhow!("failed to load token: {e}"))?;

    let Some(token) = token else {
        return Err(anyhow::anyhow!(
            "No OAuth token stored for '{provider}'. Run `aegis auth login {provider}` first."
        ));
    };

    if !token.has_refresh_token() {
        return Err(anyhow::anyhow!(
            "Token for '{provider}' has no refresh token. Re-authenticate with `aegis auth login {provider}`."
        ));
    }

    if !token.is_expired() && !token.needs_refresh(300) {
        let secs = token.seconds_until_expiry().unwrap_or(0);
        println!(
            "Token for '{provider}' is still valid ({} minutes remaining). No refresh needed.",
            secs / 60
        );
        return Ok(());
    }

    // Look up OAuth config from the provider registry.
    let registry = aegis_types::oauth::OAuthProviderRegistry::with_defaults();
    let endpoints = registry.get(&provider).ok_or_else(|| {
        anyhow::anyhow!(
            "No OAuth endpoints configured for '{provider}'. \
             Supported providers: {}",
            registry.provider_names().join(", ")
        )
    })?;

    // Read client ID and secret from environment.
    let client_id = std::env::var(&endpoints.client_id_env).unwrap_or_default();
    if client_id.is_empty() {
        return Err(anyhow::anyhow!(
            "Set {} to refresh OAuth token for '{provider}'.",
            endpoints.client_id_env
        ));
    }

    let client_secret = endpoints
        .client_secret_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
        .unwrap_or_default();

    // Build the token refresh request.
    let config = aegis_types::oauth::OAuthConfig {
        client_id,
        client_secret_env: endpoints
            .client_secret_env
            .clone()
            .unwrap_or_default(),
        auth_url: endpoints.authorize_url.clone(),
        token_url: endpoints.token_url.clone(),
        scopes: endpoints.default_scopes.clone(),
        redirect_uri: "http://localhost:8080/callback".to_string(),
    };

    // Set the env var so OAuthConfig::read_client_secret works.
    if !client_secret.is_empty() {
        if let Some(ref env_name) = endpoints.client_secret_env {
            std::env::set_var(env_name, &client_secret);
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let flow = aegis_types::oauth::OAuthFlow::new(config);
    let new_token = rt
        .block_on(flow.refresh_token(&token))
        .map_err(|e| anyhow::anyhow!("token refresh failed: {e}"))?;

    token_store
        .save(&new_token)
        .map_err(|e| anyhow::anyhow!("failed to save refreshed token: {e}"))?;

    let secs = new_token.seconds_until_expiry().unwrap_or(0);
    println!(
        "Token refreshed for '{provider}'. Valid for {} minutes.",
        secs / 60
    );
    Ok(())
}
