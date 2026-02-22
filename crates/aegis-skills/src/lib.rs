//! Skill manifest parsing, lifecycle management, registry, and discovery for Aegis.
//!
//! Skills are loadable packages that can register tools, commands, and hooks.
//! Each skill has a TOML manifest describing its metadata, permissions, and entry point.
//!
//! - [`SkillManifest`] -- parsed from `manifest.toml` inside a skill directory
//! - [`SkillState`] / [`SkillInstance`] -- lifecycle state machine
//! - [`SkillRegistry`] -- in-memory skill storage with lookup and filtering
//! - [`discover_skills`] -- filesystem scanning for skill directories
//! - [`SkillScanner`] -- security scanning of skill code before loading
//! - [`RegistryClient`] -- AegisHub remote registry client (install, update, sync)
//! - [`SkillPlugin`] -- plugin SDK trait for skill implementations
//! - [`SkillExecutor`] -- subprocess-based skill execution
//! - [`LoadCondition`] -- conditional skill loading based on environment

pub mod conditions;
pub mod discovery;
pub mod executor;
pub mod hub;
pub mod installer;
pub mod lifecycle;
pub mod manifest;
pub mod registry;
pub mod scanner;
pub mod sdk;

pub use conditions::{check_conditions, evaluate_conditions, LoadCondition, Platform};
pub use discovery::{bundled_skill_names, discover_bundled_skills, discover_skills};
pub use executor::{ExecutionMode, ExecutorConfig, SkillExecutor};
pub use hub::{RegistryClient, RegistryConfig, SkillSummary, UpdateAvailable};
pub use installer::{InstallSource, InstalledSkill, SkillInstaller};
pub use lifecycle::{SkillInstance, SkillState};
pub use manifest::{parse_manifest, parse_manifest_file, validate_manifest, SkillManifest};
pub use registry::SkillRegistry;
pub use scanner::{ScanFinding, ScanResult, Severity, SkillScanner};
pub use sdk::{
    Artifact, SkillCapabilities, SkillContext, SkillInput, SkillOutput, SkillPlugin,
};
