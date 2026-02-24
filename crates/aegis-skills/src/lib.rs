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
//! - [`SlashCommand`] / [`CommandRouter`] -- slash command parsing and dispatch
//! - [`SkillWatcher`] / [`HotReloader`] -- hot-reload of skills on filesystem changes

pub mod conditions;
pub mod discovery;
pub mod dispatch;
pub mod executor;
pub mod hot_reload;
pub mod hub;
pub mod installer;
pub mod lifecycle;
pub mod manifest;
pub mod registry;
pub mod scanner;
pub mod sdk;

pub use conditions::{check_conditions, evaluate_conditions, LoadCondition, Platform};
pub use discovery::{bundled_skill_names, discover_bundled_skills, discover_skills};
pub use dispatch::{
    auto_register_commands, parse_slash_command, CommandInfo, CommandRouter, CommandSource,
    ManifestCommand, SlashCommand,
};
pub use executor::{ExecutionMode, ExecutorConfig, SkillExecutor};
pub use hot_reload::{HotReloader, SkillChange, SkillWatcher, SkillWatcherConfig};
pub use hub::{RegistryClient, RegistryConfig, SkillSummary, UpdateAvailable};
pub use installer::{
    binary_exists, check_prerequisites, is_supported_os, InstallSource, InstalledSkill,
    PackageManagerInstaller, SkillInstaller,
};
pub use lifecycle::{SkillInstance, SkillState};
pub use manifest::{
    parse_manifest, parse_manifest_file, validate_manifest, InstallMethod, SkillManifest,
};
pub use registry::SkillRegistry;
pub use scanner::{ScanFinding, ScanResult, Severity, SkillScanner};
pub use sdk::{Artifact, SkillCapabilities, SkillContext, SkillInput, SkillOutput, SkillPlugin};
