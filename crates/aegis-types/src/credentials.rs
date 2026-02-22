//! Credential store for LLM provider API keys and tokens.
//!
//! Manages `~/.aegis/credentials.toml` with per-provider entries.
//! File permissions are set to 0600 (owner read/write only) to protect secrets.
//! Environment variables take precedence over stored credentials.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AegisError;
use crate::providers::ProviderInfo;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single provider credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredential {
    /// The API key or token.
    pub api_key: String,
    /// Selected model ID (if user chose during onboarding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Custom base URL override (if user provided one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

/// The full credential store, serialized as TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialStore {
    /// Provider credentials keyed by provider ID (e.g., "anthropic", "openai").
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderCredential>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl CredentialStore {
    /// Default path: `~/.aegis/credentials.toml`.
    pub fn default_path() -> Option<PathBuf> {
        aegis_dir().map(|d| d.join("credentials.toml"))
    }

    /// Load from the given path, or return an empty store if the file does not
    /// exist.
    pub fn load(path: &Path) -> Result<Self, AegisError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path).map_err(|e| {
            AegisError::ConfigError(format!("failed to read {}: {}", path.display(), e))
        })?;
        let store: Self = toml::from_str(&contents).map_err(|e| {
            AegisError::ConfigError(format!("failed to parse {}: {}", path.display(), e))
        })?;
        Ok(store)
    }

    /// Load from the default path.
    pub fn load_default() -> Result<Self, AegisError> {
        match Self::default_path() {
            Some(path) => Self::load(&path),
            None => Ok(Self::default()),
        }
    }

    /// Save to the given path. Creates parent directories and sets file
    /// permissions to 0600.
    pub fn save(&self, path: &Path) -> Result<(), AegisError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to create {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let contents = toml::to_string_pretty(self).map_err(|e| {
            AegisError::ConfigError(format!("failed to serialize credentials: {}", e))
        })?;

        fs::write(path, &contents).map_err(|e| {
            AegisError::ConfigError(format!("failed to write {}: {}", path.display(), e))
        })?;

        // Set restrictive permissions (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms).map_err(|e| {
                AegisError::ConfigError(format!(
                    "failed to set permissions on {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Save to the default path.
    pub fn save_default(&self) -> Result<(), AegisError> {
        match Self::default_path() {
            Some(path) => self.save(&path),
            None => Err(AegisError::ConfigError(
                "could not determine home directory".to_string(),
            )),
        }
    }

    /// Set a provider's credential.
    pub fn set(
        &mut self,
        provider_id: &str,
        api_key: String,
        model: Option<String>,
        base_url: Option<String>,
    ) {
        self.providers.insert(
            provider_id.to_string(),
            ProviderCredential {
                api_key,
                model,
                base_url,
            },
        );
    }

    /// Get a provider's credential.
    pub fn get(&self, provider_id: &str) -> Option<&ProviderCredential> {
        self.providers.get(provider_id)
    }

    /// Remove a provider's credential.
    pub fn remove(&mut self, provider_id: &str) -> Option<ProviderCredential> {
        self.providers.remove(provider_id)
    }

    /// Resolve the API key for a provider. Checks environment variables first
    /// (which take precedence), then falls back to the credential store.
    pub fn resolve_api_key(&self, provider: &ProviderInfo) -> Option<String> {
        // Environment variables take precedence.
        if let Ok(key) = std::env::var(provider.env_var) {
            if !key.is_empty() {
                return Some(key);
            }
        }
        for alt in provider.alt_env_vars {
            if let Ok(key) = std::env::var(alt) {
                if !key.is_empty() {
                    return Some(key);
                }
            }
        }
        // Fall back to stored credential.
        self.get(provider.id).map(|c| c.api_key.clone())
    }

    /// Resolve the model for a provider. Returns stored selection, or the
    /// provider's default.
    pub fn resolve_model(&self, provider: &ProviderInfo) -> String {
        self.get(provider.id)
            .and_then(|c| c.model.clone())
            .unwrap_or_else(|| provider.default_model.to_string())
    }

    /// Resolve the base URL for a provider. Returns stored override, or the
    /// provider's default.
    pub fn resolve_base_url(&self, provider: &ProviderInfo) -> String {
        self.get(provider.id)
            .and_then(|c| c.base_url.clone())
            .unwrap_or_else(|| provider.base_url.to_string())
    }

    /// Mask an API key for display (show first 4 and last 4 chars).
    pub fn mask_key(key: &str) -> String {
        if key.len() <= 12 {
            return "*".repeat(key.len());
        }
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    }
}

/// Get the `~/.aegis` directory path.
fn aegis_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".aegis"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn round_trip() {
        let mut store = CredentialStore::default();
        store.set(
            "anthropic",
            "test-key-12345".to_string(),
            Some("claude-opus-4-6".to_string()),
            None,
        );
        store.set(
            "openai",
            "test-key-67890".to_string(),
            None,
            Some("https://custom.openai.com".to_string()),
        );

        let toml_str = toml::to_string_pretty(&store).unwrap();
        let parsed: CredentialStore = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.providers.len(), 2);
        assert_eq!(
            parsed.get("anthropic").unwrap().api_key,
            "test-key-12345"
        );
        assert_eq!(
            parsed.get("anthropic").unwrap().model.as_deref(),
            Some("claude-opus-4-6")
        );
        assert_eq!(
            parsed.get("openai").unwrap().base_url.as_deref(),
            Some("https://custom.openai.com")
        );
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let store =
            CredentialStore::load(Path::new("/tmp/nonexistent-aegis-creds.toml")).unwrap();
        assert!(store.providers.is_empty());
    }

    #[test]
    fn save_and_load() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_owned();

        let mut store = CredentialStore::default();
        store.set("test", "key123".to_string(), None, None);
        store.save(&path).unwrap();

        // Verify file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let loaded = CredentialStore::load(&path).unwrap();
        assert_eq!(loaded.get("test").unwrap().api_key, "key123");
    }

    #[test]
    fn mask_key_works() {
        assert_eq!(CredentialStore::mask_key("short"), "*****");
        assert_eq!(
            CredentialStore::mask_key("abcdefghijk-xyz1234567890"),
            "abcd...7890"
        );
    }

    #[test]
    fn remove_works() {
        let mut store = CredentialStore::default();
        store.set("x", "key".to_string(), None, None);
        assert!(store.get("x").is_some());
        store.remove("x");
        assert!(store.get("x").is_none());
    }
}
