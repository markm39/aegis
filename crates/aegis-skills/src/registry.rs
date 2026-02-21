//! In-memory skill registry.
//!
//! [`SkillRegistry`] stores skill instances keyed by name, with lookup,
//! listing, and filtering operations.

use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::lifecycle::{SkillInstance, SkillState};

/// A registry of skill instances, keyed by skill name.
#[derive(Debug, Default)]
pub struct SkillRegistry {
    skills: HashMap<String, SkillInstance>,
}

impl SkillRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            skills: HashMap::new(),
        }
    }

    /// Register a skill instance. Rejects duplicates by name.
    pub fn register(&mut self, instance: SkillInstance) -> Result<()> {
        let name = instance.manifest.name.clone();
        if self.skills.contains_key(&name) {
            bail!("skill already registered: {name}");
        }
        self.skills.insert(name, instance);
        Ok(())
    }

    /// Look up a skill by name.
    pub fn get(&self, name: &str) -> Option<&SkillInstance> {
        self.skills.get(name)
    }

    /// Look up a skill by name, returning a mutable reference.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut SkillInstance> {
        self.skills.get_mut(name)
    }

    /// List all registered skills, sorted by name.
    pub fn list(&self) -> Vec<&SkillInstance> {
        let mut entries: Vec<&SkillInstance> = self.skills.values().collect();
        entries.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        entries
    }

    /// Remove a skill from the registry. The skill must be in Disabled state.
    pub fn remove(&mut self, name: &str) -> Result<SkillInstance> {
        let instance = self
            .skills
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("skill not found: {name}"))?;

        if instance.state != SkillState::Disabled {
            bail!(
                "cannot remove skill '{}': must be Disabled first, currently {}",
                name,
                instance.state
            );
        }

        Ok(self.skills.remove(name).expect("checked above"))
    }

    /// Return only skills in the Active state, sorted by name.
    pub fn active_skills(&self) -> Vec<&SkillInstance> {
        let mut active: Vec<&SkillInstance> = self
            .skills
            .values()
            .filter(|s| s.state == SkillState::Active)
            .collect();
        active.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::SkillInstance;
    use crate::manifest::parse_manifest;
    use std::path::PathBuf;

    fn make_instance(name: &str) -> SkillInstance {
        let toml = format!(
            r#"
name = "{name}"
version = "1.0.0"
description = "Skill {name}"
entry_point = "run.sh"
"#
        );
        let manifest = parse_manifest(&toml).unwrap();
        SkillInstance::discover(manifest, PathBuf::from(format!("/tmp/{name}")))
    }

    fn make_active_instance(name: &str) -> SkillInstance {
        let mut instance = make_instance(name);
        instance.validate().unwrap();
        instance.load().unwrap();
        instance.activate().unwrap();
        instance
    }

    #[test]
    fn test_registry_register_and_list() {
        let mut registry = SkillRegistry::new();

        registry.register(make_instance("charlie")).unwrap();
        registry.register(make_instance("alpha")).unwrap();
        registry.register(make_instance("bravo")).unwrap();

        let list = registry.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].manifest.name, "alpha");
        assert_eq!(list[1].manifest.name, "bravo");
        assert_eq!(list[2].manifest.name, "charlie");
    }

    #[test]
    fn test_registry_rejects_duplicate() {
        let mut registry = SkillRegistry::new();

        registry.register(make_instance("dupe")).unwrap();
        let err = registry.register(make_instance("dupe")).unwrap_err();
        assert!(
            err.to_string().contains("already registered"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn test_registry_remove_requires_disabled() {
        let mut registry = SkillRegistry::new();

        // Register an Active skill
        registry.register(make_active_instance("active-skill")).unwrap();

        // Removing an Active skill should fail
        let err = registry.remove("active-skill").unwrap_err();
        assert!(
            err.to_string().contains("must be Disabled"),
            "expected disabled-required error, got: {err}"
        );

        // Disable it, then remove
        registry.get_mut("active-skill").unwrap().disable().unwrap();
        let removed = registry.remove("active-skill").unwrap();
        assert_eq!(removed.manifest.name, "active-skill");
        assert!(registry.get("active-skill").is_none());
    }

    #[test]
    fn test_registry_active_skills() {
        let mut registry = SkillRegistry::new();

        // Add a mix of active and non-active skills
        registry.register(make_active_instance("active-b")).unwrap();
        registry.register(make_instance("discovered-only")).unwrap();
        registry.register(make_active_instance("active-a")).unwrap();

        let active = registry.active_skills();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].manifest.name, "active-a");
        assert_eq!(active[1].manifest.name, "active-b");
    }
}
