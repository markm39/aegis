//! Skill lifecycle state machine.
//!
//! Each skill progresses through a defined sequence of states:
//! `Discovered -> Validated -> Loaded -> Active -> Disabled`.
//! Any state can transition to `Error`. Invalid transitions are rejected.

use std::fmt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::manifest::SkillManifest;

/// The lifecycle state of a skill instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkillState {
    /// Skill directory found and manifest parsed.
    Discovered,
    /// Manifest validated against security and correctness rules.
    Validated,
    /// Skill loaded into memory (entry point resolved).
    Loaded,
    /// Skill is active and serving.
    Active,
    /// Skill has been deactivated.
    Disabled,
    /// Skill encountered an error.
    Error(String),
}

impl fmt::Display for SkillState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovered => write!(f, "Discovered"),
            Self::Validated => write!(f, "Validated"),
            Self::Loaded => write!(f, "Loaded"),
            Self::Active => write!(f, "Active"),
            Self::Disabled => write!(f, "Disabled"),
            Self::Error(msg) => write!(f, "Error({msg})"),
        }
    }
}

/// A skill instance combining manifest, lifecycle state, and metadata.
#[derive(Debug, Clone)]
pub struct SkillInstance {
    /// The parsed manifest for this skill.
    pub manifest: SkillManifest,
    /// Current lifecycle state.
    pub state: SkillState,
    /// When the skill was loaded (set on transition to Loaded).
    pub loaded_at: Option<DateTime<Utc>>,
    /// Filesystem path to the skill directory.
    pub path: PathBuf,
}

impl SkillInstance {
    /// Create a new skill instance in the Discovered state.
    pub fn discover(manifest: SkillManifest, path: PathBuf) -> Self {
        Self {
            manifest,
            state: SkillState::Discovered,
            loaded_at: None,
            path,
        }
    }

    /// Transition from Discovered to Validated.
    ///
    /// Also runs manifest validation to confirm the manifest is sound.
    pub fn validate(&mut self) -> Result<()> {
        if self.state != SkillState::Discovered {
            bail!(
                "cannot validate skill '{}': expected state Discovered, got {}",
                self.manifest.name,
                self.state
            );
        }
        crate::manifest::validate_manifest(&self.manifest)?;
        self.state = SkillState::Validated;
        Ok(())
    }

    /// Transition from Validated to Loaded.
    pub fn load(&mut self) -> Result<()> {
        if self.state != SkillState::Validated {
            bail!(
                "cannot load skill '{}': expected state Validated, got {}",
                self.manifest.name,
                self.state
            );
        }
        self.loaded_at = Some(Utc::now());
        self.state = SkillState::Loaded;
        Ok(())
    }

    /// Transition from Loaded to Active.
    pub fn activate(&mut self) -> Result<()> {
        if self.state != SkillState::Loaded {
            bail!(
                "cannot activate skill '{}': expected state Loaded, got {}",
                self.manifest.name,
                self.state
            );
        }
        self.state = SkillState::Active;
        Ok(())
    }

    /// Transition from Active to Disabled.
    pub fn disable(&mut self) -> Result<()> {
        if self.state != SkillState::Active {
            bail!(
                "cannot disable skill '{}': expected state Active, got {}",
                self.manifest.name,
                self.state
            );
        }
        self.state = SkillState::Disabled;
        Ok(())
    }

    /// Transition any state to Error.
    pub fn set_error(&mut self, msg: String) {
        self.state = SkillState::Error(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_manifest;

    fn test_manifest() -> SkillManifest {
        parse_manifest(
            r#"
name = "test-skill"
version = "1.0.0"
description = "A test skill"
entry_point = "run.sh"
permissions = ["action::read"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_lifecycle_valid_transitions() {
        let manifest = test_manifest();
        let mut instance = SkillInstance::discover(manifest, PathBuf::from("/tmp/test-skill"));

        assert_eq!(instance.state, SkillState::Discovered);
        assert!(instance.loaded_at.is_none());

        instance.validate().unwrap();
        assert_eq!(instance.state, SkillState::Validated);

        instance.load().unwrap();
        assert_eq!(instance.state, SkillState::Loaded);
        assert!(instance.loaded_at.is_some());

        instance.activate().unwrap();
        assert_eq!(instance.state, SkillState::Active);

        instance.disable().unwrap();
        assert_eq!(instance.state, SkillState::Disabled);
    }

    #[test]
    fn test_lifecycle_invalid_transition() {
        let manifest = test_manifest();
        let mut instance = SkillInstance::discover(manifest, PathBuf::from("/tmp/test-skill"));

        // Discovered -> Active should fail (must go through Validated and Loaded first)
        let err = instance.activate().unwrap_err();
        assert!(
            err.to_string().contains("expected state Loaded"),
            "expected state error, got: {err}"
        );

        // Discovered -> Loaded should fail
        let err = instance.load().unwrap_err();
        assert!(
            err.to_string().contains("expected state Validated"),
            "expected state error, got: {err}"
        );

        // Discovered -> Disabled should fail
        let err = instance.disable().unwrap_err();
        assert!(
            err.to_string().contains("expected state Active"),
            "expected state error, got: {err}"
        );
    }

    #[test]
    fn test_lifecycle_error_from_any_state() {
        let states_to_test = [
            SkillState::Discovered,
            SkillState::Validated,
            SkillState::Loaded,
            SkillState::Active,
            SkillState::Disabled,
        ];

        for initial_state in &states_to_test {
            let manifest = test_manifest();
            let mut instance = SkillInstance {
                manifest,
                state: initial_state.clone(),
                loaded_at: None,
                path: PathBuf::from("/tmp/test"),
            };

            instance.set_error("something broke".to_string());
            assert_eq!(
                instance.state,
                SkillState::Error("something broke".to_string()),
                "set_error should work from state {initial_state}"
            );
        }
    }
}
