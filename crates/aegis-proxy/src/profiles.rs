//! Named API key profiles for multi-provider authentication.
//!
//! Allows per-agent API key selection based on named profiles.
//! Each profile specifies a provider, env var for the key, and
//! optional model allowlist.

use serde::{Deserialize, Serialize};

/// A named authentication profile mapping a provider to an env var.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthProfile {
    /// Unique profile name (e.g., "production-anthropic").
    pub name: String,
    /// Provider identifier (e.g., "anthropic", "openai").
    pub provider: String,
    /// Environment variable holding the API key (e.g., "ANTHROPIC_API_KEY").
    pub api_key_env_var: String,
    /// Optional allowlist of model IDs. Empty means all models are allowed.
    pub model_allowlist: Vec<String>,
}

/// Registry of named authentication profiles.
///
/// Provides lookup, key resolution, and model validation for
/// per-agent API key management.
pub struct ProfileRegistry {
    profiles: Vec<AuthProfile>,
}

impl ProfileRegistry {
    /// Create a new registry with the given profiles.
    pub fn new(profiles: Vec<AuthProfile>) -> Self {
        Self { profiles }
    }

    /// Find a profile by name.
    pub fn find(&self, name: &str) -> Option<&AuthProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Resolve the API key for a named profile by reading the configured env var.
    ///
    /// Returns an error if the profile does not exist or the env var is not set.
    pub fn resolve_key(&self, profile_name: &str) -> Result<String, String> {
        let profile = self
            .find(profile_name)
            .ok_or_else(|| format!("profile '{profile_name}' not found"))?;

        std::env::var(&profile.api_key_env_var).map_err(|_| {
            format!(
                "environment variable '{}' not set for profile '{profile_name}'",
                profile.api_key_env_var
            )
        })
    }

    /// Check whether a model is allowed under a given profile.
    ///
    /// Returns `true` if the profile exists and either has an empty allowlist
    /// (all models permitted) or the model is in the allowlist.
    /// Returns `false` if the profile does not exist.
    pub fn is_model_allowed(&self, profile_name: &str, model: &str) -> bool {
        match self.find(profile_name) {
            Some(profile) => {
                profile.model_allowlist.is_empty()
                    || profile.model_allowlist.iter().any(|m| m == model)
            }
            None => false,
        }
    }

    /// List all registered profiles.
    pub fn list(&self) -> &[AuthProfile] {
        &self.profiles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> ProfileRegistry {
        ProfileRegistry::new(vec![
            AuthProfile {
                name: "prod-anthropic".into(),
                provider: "anthropic".into(),
                api_key_env_var: "AEGIS_TEST_ANTHROPIC_KEY".into(),
                model_allowlist: vec![
                    "claude-sonnet-4-5-20250929".into(),
                    "claude-3-haiku-20240307".into(),
                ],
            },
            AuthProfile {
                name: "dev-openai".into(),
                provider: "openai".into(),
                api_key_env_var: "AEGIS_TEST_OPENAI_KEY".into(),
                model_allowlist: vec![],
            },
        ])
    }

    #[test]
    fn find_by_name() {
        let reg = test_registry();
        let profile = reg.find("prod-anthropic").unwrap();
        assert_eq!(profile.provider, "anthropic");
        assert_eq!(profile.api_key_env_var, "AEGIS_TEST_ANTHROPIC_KEY");
    }

    #[test]
    fn find_missing_returns_none() {
        let reg = test_registry();
        assert!(reg.find("nonexistent").is_none());
    }

    #[test]
    fn resolve_key_from_env() {
        let reg = test_registry();
        // Set the env var for testing
        std::env::set_var("AEGIS_TEST_OPENAI_KEY", "sk-test-1234");
        let key = reg.resolve_key("dev-openai").unwrap();
        assert_eq!(key, "sk-test-1234");
        std::env::remove_var("AEGIS_TEST_OPENAI_KEY");
    }

    #[test]
    fn resolve_key_missing_env_var() {
        let reg = test_registry();
        std::env::remove_var("AEGIS_TEST_ANTHROPIC_KEY");
        let err = reg.resolve_key("prod-anthropic").unwrap_err();
        assert!(err.contains("not set"));
        assert!(err.contains("AEGIS_TEST_ANTHROPIC_KEY"));
    }

    #[test]
    fn resolve_key_missing_profile() {
        let reg = test_registry();
        let err = reg.resolve_key("missing").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn model_allowed_with_allowlist() {
        let reg = test_registry();
        assert!(reg.is_model_allowed("prod-anthropic", "claude-sonnet-4-5-20250929"));
        assert!(!reg.is_model_allowed("prod-anthropic", "gpt-4-turbo"));
    }

    #[test]
    fn model_allowed_empty_allowlist_permits_all() {
        let reg = test_registry();
        assert!(reg.is_model_allowed("dev-openai", "gpt-4-turbo"));
        assert!(reg.is_model_allowed("dev-openai", "anything-goes"));
    }

    #[test]
    fn model_allowed_missing_profile_returns_false() {
        let reg = test_registry();
        assert!(!reg.is_model_allowed("missing", "any-model"));
    }

    #[test]
    fn list_returns_all_profiles() {
        let reg = test_registry();
        assert_eq!(reg.list().len(), 2);
        assert_eq!(reg.list()[0].name, "prod-anthropic");
        assert_eq!(reg.list()[1].name, "dev-openai");
    }

    #[test]
    fn auth_profile_serde_roundtrip() {
        let profile = AuthProfile {
            name: "test".into(),
            provider: "anthropic".into(),
            api_key_env_var: "MY_KEY".into(),
            model_allowlist: vec!["model-a".into()],
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: AuthProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, back);
    }
}
