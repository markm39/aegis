//! Hierarchical configuration loading with multiple sources merged in priority order.
//!
//! The priority chain (later overrides earlier):
//! 1. Built-in defaults ([`AegisConfig::default()`])
//! 2. System-wide: `/etc/aegis/config.toml`
//! 3. User-level: `~/.aegis/config.toml`
//! 4. Workspace-level: `./.aegis/config.toml`
//! 5. `AEGIS_*` environment variables
//! 6. CLI flags (not implemented here; caller provides overrides)
//!
//! Each field in the final [`EffectiveConfig`] is annotated with the
//! [`ConfigSource`] that determined its value.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::AegisConfig;
use crate::AegisError;

/// Maximum config file size in bytes. Files larger than this are rejected
/// to prevent resource exhaustion from malicious or corrupted configs.
const MAX_CONFIG_FILE_SIZE: u64 = 1024 * 1024; // 1 MB

/// Where a configuration value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigSource {
    /// Built-in default from `AegisConfig::default()`.
    BuiltinDefault,
    /// System-wide config file (e.g., `/etc/aegis/config.toml`).
    SystemFile(PathBuf),
    /// User-level config file (e.g., `~/.aegis/config.toml`).
    UserFile(PathBuf),
    /// Workspace-level config file (e.g., `./.aegis/config.toml`).
    WorkspaceFile(PathBuf),
    /// Environment variable.
    EnvVar(String),
    /// CLI flag override.
    CliFlag(String),
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::BuiltinDefault => write!(f, "built-in default"),
            ConfigSource::SystemFile(p) => write!(f, "system file: {}", p.display()),
            ConfigSource::UserFile(p) => write!(f, "user file: {}", p.display()),
            ConfigSource::WorkspaceFile(p) => write!(f, "workspace file: {}", p.display()),
            ConfigSource::EnvVar(name) => write!(f, "env var: {name}"),
            ConfigSource::CliFlag(name) => write!(f, "CLI flag: {name}"),
        }
    }
}

/// The result of hierarchical config loading: the merged config plus
/// provenance information for each field.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    /// The merged configuration.
    pub config: AegisConfig,
    /// Field path -> the source that determined its value.
    pub sources: HashMap<String, ConfigSource>,
    /// All config files that were found and loaded (in priority order).
    pub source_files: Vec<PathBuf>,
}

/// Hierarchical configuration loader.
///
/// Loads config from multiple sources and merges them with override semantics.
/// Later sources override earlier ones for any field that is present.
pub struct ConfigLoader {
    /// Override for the system config path (for testing).
    system_config_path: Option<PathBuf>,
    /// Override for the user config path (for testing).
    user_config_path: Option<PathBuf>,
    /// Override for the workspace config path (for testing).
    workspace_config_path: Option<PathBuf>,
    /// Whether to skip system file ownership checks (for testing).
    skip_ownership_check: bool,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Create a new loader with default paths.
    pub fn new() -> Self {
        Self {
            system_config_path: None,
            user_config_path: None,
            workspace_config_path: None,
            skip_ownership_check: false,
        }
    }

    /// Override the system config file path.
    #[must_use]
    pub fn with_system_path(mut self, path: PathBuf) -> Self {
        self.system_config_path = Some(path);
        self
    }

    /// Override the user config file path.
    #[must_use]
    pub fn with_user_path(mut self, path: PathBuf) -> Self {
        self.user_config_path = Some(path);
        self
    }

    /// Override the workspace config file path.
    #[must_use]
    pub fn with_workspace_path(mut self, path: PathBuf) -> Self {
        self.workspace_config_path = Some(path);
        self
    }

    /// Skip system file ownership validation (for testing only).
    #[cfg(test)]
    #[must_use]
    pub fn skip_ownership_check(mut self) -> Self {
        self.skip_ownership_check = true;
        self
    }

    /// Load and merge configuration from all sources.
    ///
    /// Returns the effective config with source annotations for each field.
    pub fn load(&self) -> Result<EffectiveConfig, AegisError> {
        let mut sources = HashMap::new();
        let mut source_files = Vec::new();

        // 1. Built-in defaults
        let default_config = AegisConfig::default();
        let mut merged = toml::Value::try_from(&default_config)
            .map_err(|e| AegisError::ConfigError(format!("failed to serialize defaults: {e}")))?;

        // Mark all top-level default fields
        if let toml::Value::Table(ref table) = merged {
            for key in table.keys() {
                sources.insert(key.clone(), ConfigSource::BuiltinDefault);
            }
        }

        // 2. System-wide config
        let system_path = self
            .system_config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/aegis/config.toml"));
        if system_path.exists() {
            if !self.skip_ownership_check {
                validate_system_file_ownership(&system_path)?;
            }
            let content = read_config_file(&system_path)?;
            let layer: toml::Value = toml::from_str(&content)
                .map_err(|e| AegisError::ConfigError(format!("invalid system config: {e}")))?;
            deep_merge(&mut merged, &layer);
            record_sources(&layer, &mut sources, ConfigSource::SystemFile(system_path.clone()));
            source_files.push(system_path);
        }

        // 3. User-level config
        let user_path = self.user_config_path.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".aegis").join("config.toml")
        });
        if user_path.exists() {
            let content = read_config_file(&user_path)?;
            let layer: toml::Value = toml::from_str(&content)
                .map_err(|e| AegisError::ConfigError(format!("invalid user config: {e}")))?;
            deep_merge(&mut merged, &layer);
            record_sources(&layer, &mut sources, ConfigSource::UserFile(user_path.clone()));
            source_files.push(user_path);
        }

        // 4. Workspace-level config
        let workspace_path = self
            .workspace_config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(".aegis/config.toml"));
        if workspace_path.exists() {
            let content = read_config_file(&workspace_path)?;
            let layer: toml::Value = toml::from_str(&content)
                .map_err(|e| AegisError::ConfigError(format!("invalid workspace config: {e}")))?;
            deep_merge(&mut merged, &layer);
            record_sources(
                &layer,
                &mut sources,
                ConfigSource::WorkspaceFile(workspace_path.clone()),
            );
            source_files.push(workspace_path);
        }

        // 5. Environment variable overrides
        apply_env_overrides(&mut merged, &mut sources)?;

        // Deserialize to AegisConfig
        let config: AegisConfig = merged
            .try_into()
            .map_err(|e| AegisError::ConfigError(format!("failed to parse merged config: {e}")))?;

        // 6. Validate the final config
        validate_config(&config)?;

        Ok(EffectiveConfig {
            config,
            sources,
            source_files,
        })
    }

    /// Discover all config layer files and their status.
    ///
    /// Returns information about each layer in precedence order (lowest to highest).
    pub fn discover_layers(&self) -> Vec<ConfigLayerInfo> {
        let mut layers = Vec::new();

        // System
        let system_path = self
            .system_config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/aegis/config.toml"));
        let system_exists = system_path.exists();
        let system_keys = if system_exists {
            count_top_level_keys(&system_path)
        } else {
            0
        };
        layers.push(ConfigLayerInfo {
            source: ConfigSource::SystemFile(system_path),
            exists: system_exists,
            key_count: system_keys,
        });

        // User
        let user_path = self.user_config_path.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".aegis").join("config.toml")
        });
        let user_exists = user_path.exists();
        let user_keys = if user_exists {
            count_top_level_keys(&user_path)
        } else {
            0
        };
        layers.push(ConfigLayerInfo {
            source: ConfigSource::UserFile(user_path),
            exists: user_exists,
            key_count: user_keys,
        });

        // Workspace
        let workspace_path = self
            .workspace_config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(".aegis/config.toml"));
        let workspace_exists = workspace_path.exists();
        let workspace_keys = if workspace_exists {
            count_top_level_keys(&workspace_path)
        } else {
            0
        };
        layers.push(ConfigLayerInfo {
            source: ConfigSource::WorkspaceFile(workspace_path),
            exists: workspace_exists,
            key_count: workspace_keys,
        });

        layers
    }
}

/// Read a config file with security checks: size limit, no null bytes.
fn read_config_file(path: &Path) -> Result<String, AegisError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        AegisError::ConfigError(format!("cannot read config file {}: {e}", path.display()))
    })?;

    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(AegisError::ConfigError(format!(
            "config file {} exceeds maximum size of {} bytes (actual: {} bytes)",
            path.display(),
            MAX_CONFIG_FILE_SIZE,
            metadata.len()
        )));
    }

    let content = std::fs::read_to_string(path).map_err(|e| {
        AegisError::ConfigError(format!("cannot read config file {}: {e}", path.display()))
    })?;

    // Reject null bytes -- these indicate a corrupted or malicious file.
    if content.contains('\0') {
        return Err(AegisError::ConfigError(format!(
            "config file {} contains null bytes",
            path.display()
        )));
    }

    Ok(content)
}

/// Validate that a system-wide config file is owned by root (UID 0).
///
/// On Unix, `/etc/aegis/config.toml` must be owned by root to prevent
/// privilege escalation via a user-writable system config.
#[cfg(unix)]
fn validate_system_file_ownership(path: &Path) -> Result<(), AegisError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).map_err(|e| {
        AegisError::ConfigError(format!(
            "cannot stat system config file {}: {e}",
            path.display()
        ))
    })?;

    if metadata.uid() != 0 {
        return Err(AegisError::ConfigError(format!(
            "system config file {} is not owned by root (uid={}); refusing to load for security",
            path.display(),
            metadata.uid()
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_system_file_ownership(_path: &Path) -> Result<(), AegisError> {
    // On non-Unix platforms, skip ownership validation.
    Ok(())
}

/// Deep-merge `overlay` into `base`. For tables, merge field-by-field.
/// For arrays and scalars, the overlay replaces the base value entirely.
fn deep_merge(base: &mut toml::Value, overlay: &toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
            for (key, overlay_val) in overlay_table {
                if let Some(base_val) = base_table.get_mut(key) {
                    deep_merge(base_val, overlay_val);
                } else {
                    base_table.insert(key.clone(), overlay_val.clone());
                }
            }
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

/// Record which source contributed each top-level (and nested) key.
fn record_sources(
    layer: &toml::Value,
    sources: &mut HashMap<String, ConfigSource>,
    source: ConfigSource,
) {
    if let toml::Value::Table(table) = layer {
        for (key, value) in table {
            sources.insert(key.clone(), source.clone());
            record_nested_sources(value, sources, &source, key);
        }
    }
}

/// Recursively record sources for nested table keys using dot-separated paths.
fn record_nested_sources(
    value: &toml::Value,
    sources: &mut HashMap<String, ConfigSource>,
    source: &ConfigSource,
    prefix: &str,
) {
    if let toml::Value::Table(table) = value {
        for (key, val) in table {
            let path = format!("{prefix}.{key}");
            sources.insert(path.clone(), source.clone());
            record_nested_sources(val, sources, source, &path);
        }
    }
}

/// Known environment variable mappings.
pub struct EnvMapping {
    /// Environment variable name.
    pub env_var: &'static str,
    /// Dot-separated TOML path segments.
    pub toml_path: &'static [&'static str],
}

/// All supported AEGIS_* environment variable mappings.
pub const ENV_MAPPINGS: &[EnvMapping] = &[
    EnvMapping {
        env_var: "AEGIS_SANDBOX_DIR",
        toml_path: &["sandbox_dir"],
    },
    EnvMapping {
        env_var: "AEGIS_LEDGER_PATH",
        toml_path: &["ledger_path"],
    },
    EnvMapping {
        env_var: "AEGIS_POLICY_PATH",
        toml_path: &["policy_paths"],
    },
    EnvMapping {
        env_var: "AEGIS_NAME",
        toml_path: &["name"],
    },
    EnvMapping {
        env_var: "AEGIS_ISOLATION",
        toml_path: &["isolation"],
    },
    // Nested pilot fields (double underscore = nesting)
    EnvMapping {
        env_var: "AEGIS_PILOT__STALL_TIMEOUT",
        toml_path: &["pilot", "stall", "timeout_secs"],
    },
    EnvMapping {
        env_var: "AEGIS_PILOT__MAX_NUDGES",
        toml_path: &["pilot", "stall", "max_nudges"],
    },
    EnvMapping {
        env_var: "AEGIS_PILOT__OUTPUT_BUFFER_LINES",
        toml_path: &["pilot", "output_buffer_lines"],
    },
    // Control plane fields
    EnvMapping {
        env_var: "AEGIS_CONTROL__HTTP_LISTEN",
        toml_path: &["pilot", "control", "http_listen"],
    },
    EnvMapping {
        env_var: "AEGIS_CONTROL__API_KEY",
        toml_path: &["pilot", "control", "api_key"],
    },
];

/// Apply environment variable overrides to the merged TOML value.
fn apply_env_overrides(
    merged: &mut toml::Value,
    sources: &mut HashMap<String, ConfigSource>,
) -> Result<(), AegisError> {
    for mapping in ENV_MAPPINGS {
        if let Ok(raw_value) = std::env::var(mapping.env_var) {
            // Sanitize: reject null bytes and control characters (except whitespace).
            validate_env_value(mapping.env_var, &raw_value)?;

            let toml_val = env_value_to_toml(mapping.env_var, mapping.toml_path, &raw_value)?;
            set_nested_value(merged, mapping.toml_path, toml_val);

            // Record source for each path segment
            let mut path_acc = String::new();
            for (i, segment) in mapping.toml_path.iter().enumerate() {
                if i > 0 {
                    path_acc.push('.');
                }
                path_acc.push_str(segment);
            }
            sources.insert(path_acc, ConfigSource::EnvVar(mapping.env_var.to_string()));
        }
    }
    Ok(())
}

/// Validate an environment variable value for security.
fn validate_env_value(var_name: &str, value: &str) -> Result<(), AegisError> {
    if value.contains('\0') {
        return Err(AegisError::ConfigError(format!(
            "environment variable {var_name} contains null bytes"
        )));
    }
    // Reject control characters (except tab, newline, carriage return).
    for ch in value.chars() {
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            return Err(AegisError::ConfigError(format!(
                "environment variable {var_name} contains control character U+{:04X}",
                ch as u32
            )));
        }
    }
    Ok(())
}

/// Convert an environment variable string to the appropriate TOML value
/// based on the target field path.
fn env_value_to_toml(
    env_var: &str,
    toml_path: &[&str],
    raw: &str,
) -> Result<toml::Value, AegisError> {
    let last = toml_path.last().unwrap_or(&"");

    // Special cases
    if env_var == "AEGIS_POLICY_PATH" {
        // Policy paths are an array -- split on `:` like PATH.
        let paths: Vec<toml::Value> = raw
            .split(':')
            .map(|s| toml::Value::String(s.to_string()))
            .collect();
        return Ok(toml::Value::Array(paths));
    }

    if env_var == "AEGIS_ISOLATION" {
        // IsolationConfig is a tagged enum. Map string values to TOML.
        return match raw.to_lowercase().as_str() {
            "seatbelt" => Ok(toml::Value::String("Seatbelt".to_string())),
            "docker" => Ok(toml::Value::String("Docker".to_string())),
            "process" => Ok(toml::Value::String("Process".to_string())),
            "none" => Ok(toml::Value::String("None".to_string())),
            _ => Err(AegisError::ConfigError(format!(
                "invalid AEGIS_ISOLATION value: {raw:?} (expected seatbelt, docker, process, or none)"
            ))),
        };
    }

    // Numeric fields
    if *last == "timeout_secs"
        || *last == "max_nudges"
        || *last == "output_buffer_lines"
        || *last == "poll_interval_secs"
    {
        let num: i64 = raw.parse().map_err(|e| {
            AegisError::ConfigError(format!(
                "environment variable {env_var} must be numeric: {e}"
            ))
        })?;
        return Ok(toml::Value::Integer(num));
    }

    // Default: string value
    Ok(toml::Value::String(raw.to_string()))
}

/// Set a value at a nested path in a TOML table, creating intermediate
/// tables as needed.
fn set_nested_value(root: &mut toml::Value, path: &[&str], value: toml::Value) {
    if path.is_empty() {
        return;
    }
    if path.len() == 1 {
        if let toml::Value::Table(table) = root {
            table.insert(path[0].to_string(), value);
        }
        return;
    }
    // Navigate/create intermediate tables
    if let toml::Value::Table(table) = root {
        let entry = table
            .entry(path[0].to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        set_nested_value(entry, &path[1..], value);
    }
}

/// Validate the merged configuration for security and correctness.
fn validate_config(config: &AegisConfig) -> Result<(), AegisError> {
    // sandbox_dir must be present and non-empty
    if config.sandbox_dir.as_os_str().is_empty() {
        return Err(AegisError::ConfigError(
            "sandbox_dir is required and cannot be empty".into(),
        ));
    }

    // Validate paths: no null bytes, no directory traversal, reasonable length
    validate_path("sandbox_dir", &config.sandbox_dir)?;
    validate_path("ledger_path", &config.ledger_path)?;
    for (i, p) in config.policy_paths.iter().enumerate() {
        validate_path(&format!("policy_paths[{i}]"), p)?;
    }
    if let Some(ref schema_path) = config.schema_path {
        validate_path("schema_path", schema_path)?;
    }

    // Validate HTTP listen port if specified
    if let Some(ref pilot) = config.pilot {
        if !pilot.control.http_listen.is_empty() {
            validate_listen_address("pilot.control.http_listen", &pilot.control.http_listen)?;
        }
    }

    Ok(())
}

/// Validate a path for security: no null bytes, no `..` components, reasonable length.
fn validate_path(field: &str, path: &Path) -> Result<(), AegisError> {
    let path_str = path.to_string_lossy();

    // Reject null bytes
    if path_str.contains('\0') {
        return Err(AegisError::ConfigError(format!(
            "{field}: path contains null bytes"
        )));
    }

    // Reject unreasonably long paths (4096 is typical PATH_MAX)
    if path_str.len() > 4096 {
        return Err(AegisError::ConfigError(format!(
            "{field}: path exceeds maximum length of 4096 characters"
        )));
    }

    // Reject directory traversal (`..` components)
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(AegisError::ConfigError(format!(
                "{field}: path contains directory traversal (\"..\" component): {}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Validate a listen address string has a valid port.
fn validate_listen_address(field: &str, addr: &str) -> Result<(), AegisError> {
    // Extract port from "host:port" format
    if let Some(port_str) = addr.rsplit(':').next() {
        if let Ok(port) = port_str.parse::<u32>() {
            if port == 0 || port > 65535 {
                return Err(AegisError::ConfigError(format!(
                    "{field}: port {port} is out of valid range (1-65535)"
                )));
            }
        }
    }
    Ok(())
}

/// Mask a sensitive field value for display or logging.
///
/// Returns the first 4 characters followed by "***", or just "***"
/// if the value is shorter than 4 characters.
pub fn mask_sensitive(value: &str) -> String {
    if value.len() < 4 {
        "***".to_string()
    } else {
        let prefix: String = value.chars().take(4).collect();
        format!("{prefix}***")
    }
}

/// Check if a field name refers to a sensitive value (tokens, keys, secrets).
pub fn is_sensitive_field(field_name: &str) -> bool {
    let lower = field_name.to_lowercase();
    lower.contains("token")
        || lower.contains("key")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("webhook_url")
}

/// Retrieve a value from a TOML tree using dot-separated key path.
///
/// For example, `"pilot.stall.timeout_secs"` navigates into `[pilot]` ->
/// `[stall]` -> `timeout_secs`. Returns `None` if any segment is missing.
pub fn get_dot_value(root: &toml::Value, path: &str) -> Option<toml::Value> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;
    for segment in &segments {
        match current {
            toml::Value::Table(table) => {
                current = table.get(*segment)?;
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

/// Set a value in a TOML tree using dot-separated key path.
///
/// Creates intermediate tables as needed. The value is parsed from a string
/// using TOML literal syntax: integers, floats, booleans, quoted strings, and
/// arrays are detected automatically. Bare strings are stored as TOML strings.
pub fn set_dot_value(
    root: &mut toml::Value,
    path: &str,
    raw_value: &str,
) -> Result<(), AegisError> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
        return Err(AegisError::ConfigError(
            "config key path must be non-empty with no empty segments".into(),
        ));
    }

    let parsed = parse_toml_literal(raw_value);
    set_nested_value(root, &segments, parsed);
    Ok(())
}

/// Parse a string as a TOML literal value.
///
/// Attempts, in order: integer, float, boolean, TOML inline value (arrays,
/// inline tables, quoted strings). Falls back to a plain string.
fn parse_toml_literal(raw: &str) -> toml::Value {
    // Boolean
    if raw == "true" {
        return toml::Value::Boolean(true);
    }
    if raw == "false" {
        return toml::Value::Boolean(false);
    }
    // Integer (only if it looks like one -- avoid parsing floats as int)
    if !raw.contains('.') {
        if let Ok(n) = raw.parse::<i64>() {
            return toml::Value::Integer(n);
        }
    }
    // Float
    if let Ok(f) = raw.parse::<f64>() {
        return toml::Value::Float(f);
    }
    // Try parsing as a TOML value expression (handles arrays, inline tables, quoted strings).
    // We wrap it as `v = <raw>` to get a valid TOML document.
    let attempt = format!("v = {raw}");
    if let Ok(table) = attempt.parse::<toml::Table>() {
        if let Some(val) = table.get("v") {
            return val.clone();
        }
    }
    // Fallback: plain string
    toml::Value::String(raw.to_string())
}

/// Format a TOML value as a human-readable string for display.
pub fn format_toml_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_toml_value).collect();
            format!("[{}]", items.join(", "))
        }
        toml::Value::Table(table) => {
            let entries: Vec<String> = table
                .iter()
                .map(|(k, v)| format!("{k} = {}", format_toml_value(v)))
                .collect();
            format!("{{{}}}", entries.join(", "))
        }
    }
}

/// Flatten a TOML value into dot-separated key-value pairs.
///
/// Used by `config list` to show all effective config values.
pub fn flatten_toml(
    value: &toml::Value,
    prefix: &str,
    out: &mut Vec<(String, String)>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_toml(val, &path, out);
            }
        }
        _ => {
            let display = if is_sensitive_field(prefix) {
                match value {
                    toml::Value::String(s) => mask_sensitive(s),
                    other => format_toml_value(other),
                }
            } else {
                format_toml_value(value)
            };
            out.push((prefix.to_string(), display));
        }
    }
}

/// Information about a config layer (file or source) for the `config layers` command.
#[derive(Debug, Clone)]
pub struct ConfigLayerInfo {
    /// The source type and path.
    pub source: ConfigSource,
    /// Whether the file exists.
    pub exists: bool,
    /// Number of top-level keys defined in this layer.
    pub key_count: usize,
}

/// Discover all config layer files and their status.
///
/// Returns information about each layer in precedence order (lowest to highest).
pub fn discover_layers(loader: &ConfigLoader) -> Vec<ConfigLayerInfo> {
    loader.discover_layers()
}

/// Count top-level keys in a TOML config file. Returns 0 on any error.
fn count_top_level_keys(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| content.parse::<toml::Table>().ok())
        .map(|table| table.len())
        .unwrap_or(0)
}

/// All known top-level config key names for tab completion.
pub const CONFIG_KEY_NAMES: &[&str] = &[
    "alerts",
    "allowed_network",
    "channel",
    "isolation",
    "ledger_path",
    "name",
    "observer",
    "pilot",
    "pilot.adapter",
    "pilot.control",
    "pilot.control.api_key",
    "pilot.control.http_listen",
    "pilot.control.poll_endpoint",
    "pilot.control.poll_interval_secs",
    "pilot.output_buffer_lines",
    "pilot.stall",
    "pilot.stall.max_nudges",
    "pilot.stall.nudge_message",
    "pilot.stall.timeout_secs",
    "pilot.uncertain_action",
    "policy_paths",
    "sandbox_dir",
    "schema_path",
    "usage_proxy",
    "usage_proxy.enabled",
    "usage_proxy.port",
];

/// Default `AegisConfig` used as the base layer in hierarchical loading.
impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            sandbox_dir: PathBuf::from("/tmp/aegis-sandbox"),
            policy_paths: vec![],
            schema_path: None,
            ledger_path: PathBuf::from("/tmp/aegis-audit.db"),
            allowed_network: vec![],
            isolation: crate::config::IsolationConfig::Process,
            observer: crate::config::ObserverConfig::default(),
            alerts: vec![],
            pilot: None,
            channel: None,
            usage_proxy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create a config file in a temp dir.
    fn write_config(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    use std::sync::Mutex;

    /// Global mutex to serialize tests that touch env vars or call loader.load().
    ///
    /// Environment variables are process-global state, so tests that set
    /// AEGIS_* env vars or call ConfigLoader::load() (which reads them)
    /// must not run concurrently.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Clear all AEGIS_* environment variables.
    fn clear_aegis_env_vars() {
        for mapping in ENV_MAPPINGS {
            std::env::remove_var(mapping.env_var);
        }
    }

    #[test]
    fn config_merge_priority_order() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_aegis_env_vars();
        let tmp = TempDir::new().unwrap();
        let system_dir = tmp.path().join("system");
        let user_dir = tmp.path().join("user");
        let workspace_dir = tmp.path().join("workspace");
        std::fs::create_dir_all(&system_dir).unwrap();
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::create_dir_all(&workspace_dir).unwrap();

        // System sets name to "system-name"
        let system_path = write_config(
            &system_dir,
            r#"
            name = "system-name"
            sandbox_dir = "/system/sandbox"
            ledger_path = "/system/audit.db"
            "#,
        );

        // User overrides name to "user-name"
        let user_path = write_config(
            &user_dir,
            r#"
            name = "user-name"
            sandbox_dir = "/user/sandbox"
            "#,
        );

        // Workspace overrides name to "workspace-name"
        let workspace_path = write_config(
            &workspace_dir,
            r#"
            name = "workspace-name"
            "#,
        );

        let loader = ConfigLoader::new()
            .with_system_path(system_path)
            .with_user_path(user_path)
            .with_workspace_path(workspace_path)
            .skip_ownership_check();

        let effective = loader.load().unwrap();

        // Workspace overrides user overrides system
        assert_eq!(effective.config.name, "workspace-name");
        // User overrides system for sandbox_dir
        assert_eq!(
            effective.config.sandbox_dir,
            PathBuf::from("/user/sandbox")
        );
        // System value preserved for ledger_path (not overridden)
        assert_eq!(
            effective.config.ledger_path,
            PathBuf::from("/system/audit.db")
        );
        // Three source files loaded
        assert_eq!(effective.source_files.len(), 3);
    }

    #[test]
    fn workspace_config_overrides_user() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_aegis_env_vars();
        let tmp = TempDir::new().unwrap();
        let user_dir = tmp.path().join("user");
        let workspace_dir = tmp.path().join("workspace");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::create_dir_all(&workspace_dir).unwrap();

        let user_path = write_config(
            &user_dir,
            r#"
            name = "user-agent"
            sandbox_dir = "/user/sandbox"
            "#,
        );

        let workspace_path = write_config(
            &workspace_dir,
            r#"
            name = "workspace-agent"
            "#,
        );

        let loader = ConfigLoader::new()
            .with_system_path(tmp.path().join("nonexistent/config.toml"))
            .with_user_path(user_path)
            .with_workspace_path(workspace_path)
            .skip_ownership_check();

        let effective = loader.load().unwrap();
        assert_eq!(effective.config.name, "workspace-agent");
        // sandbox_dir from user config persists
        assert_eq!(
            effective.config.sandbox_dir,
            PathBuf::from("/user/sandbox")
        );
    }

    #[test]
    fn env_var_overrides_file_config() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_aegis_env_vars();
        let tmp = TempDir::new().unwrap();
        let user_dir = tmp.path().join("user");
        std::fs::create_dir_all(&user_dir).unwrap();

        let user_path = write_config(
            &user_dir,
            r#"
            name = "file-agent"
            sandbox_dir = "/file/sandbox"
            "#,
        );

        // Set env var to override sandbox_dir
        std::env::set_var("AEGIS_SANDBOX_DIR", "/env/sandbox");

        let loader = ConfigLoader::new()
            .with_system_path(tmp.path().join("nonexistent/config.toml"))
            .with_user_path(user_path)
            .with_workspace_path(tmp.path().join("nonexistent/config.toml"))
            .skip_ownership_check();

        let effective = loader.load().unwrap();
        assert_eq!(
            effective.config.sandbox_dir,
            PathBuf::from("/env/sandbox")
        );

        // Source should be EnvVar
        assert!(matches!(
            effective.sources.get("sandbox_dir"),
            Some(ConfigSource::EnvVar(name)) if name == "AEGIS_SANDBOX_DIR"
        ));

        // Clean up env
        std::env::remove_var("AEGIS_SANDBOX_DIR");
    }

    #[test]
    fn sensitive_field_masking() {
        assert_eq!(mask_sensitive("sk-12345678"), "sk-1***");
        assert_eq!(mask_sensitive("abcd"), "abcd***");
        assert_eq!(mask_sensitive("abc"), "***");
        assert_eq!(mask_sensitive("ab"), "***");
        assert_eq!(mask_sensitive("a"), "***");
        assert_eq!(mask_sensitive(""), "***");
    }

    #[test]
    fn sensitive_field_detection() {
        assert!(is_sensitive_field("bot_token"));
        assert!(is_sensitive_field("api_key"));
        assert!(is_sensitive_field("access_token"));
        assert!(is_sensitive_field("webhook_url"));
        assert!(is_sensitive_field("API_KEY"));
        assert!(is_sensitive_field("secret"));
        assert!(is_sensitive_field("password"));
        assert!(!is_sensitive_field("name"));
        assert!(!is_sensitive_field("sandbox_dir"));
    }

    #[test]
    fn config_validation_rejects_traversal_paths() {
        let config = AegisConfig {
            sandbox_dir: PathBuf::from("/tmp/../etc/passwd"),
            ..AegisConfig::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("directory traversal"),
            "expected traversal error, got: {err}"
        );
    }

    #[test]
    fn config_validation_rejects_empty_sandbox() {
        let config = AegisConfig {
            sandbox_dir: PathBuf::from(""),
            ..AegisConfig::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("sandbox_dir is required"),
            "expected sandbox_dir error, got: {err}"
        );
    }

    #[test]
    fn config_validation_rejects_invalid_port() {
        use crate::config::{ControlConfig, PilotConfig};

        let config = AegisConfig {
            pilot: Some(PilotConfig {
                control: ControlConfig {
                    http_listen: "0.0.0.0:0".into(),
                    ..ControlConfig::default()
                },
                ..PilotConfig::default()
            }),
            ..AegisConfig::default()
        };
        let result = validate_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("out of valid range"),
            "expected port error, got: {err}"
        );
    }

    #[test]
    fn effective_config_shows_sources() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_aegis_env_vars();
        let tmp = TempDir::new().unwrap();
        let user_dir = tmp.path().join("user");
        std::fs::create_dir_all(&user_dir).unwrap();

        let user_path = write_config(
            &user_dir,
            r#"
            name = "sourced-agent"
            sandbox_dir = "/sourced/sandbox"
            "#,
        );

        let loader = ConfigLoader::new()
            .with_system_path(tmp.path().join("nonexistent/config.toml"))
            .with_user_path(user_path.clone())
            .with_workspace_path(tmp.path().join("nonexistent/config.toml"))
            .skip_ownership_check();

        let effective = loader.load().unwrap();

        // name came from user file
        assert!(matches!(
            effective.sources.get("name"),
            Some(ConfigSource::UserFile(p)) if *p == user_path
        ));

        // sandbox_dir came from user file
        assert!(matches!(
            effective.sources.get("sandbox_dir"),
            Some(ConfigSource::UserFile(p)) if *p == user_path
        ));

        // Default fields should be BuiltinDefault
        assert!(matches!(
            effective.sources.get("observer"),
            Some(ConfigSource::BuiltinDefault)
        ));
    }

    #[test]
    fn security_test_oversized_config_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("big.toml");
        // Write a file larger than 1 MB
        let mut f = std::fs::File::create(&path).unwrap();
        let big = vec![b'#'; (MAX_CONFIG_FILE_SIZE + 1) as usize];
        f.write_all(&big).unwrap();

        let result = read_config_file(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum size"),
            "expected size error, got: {err}"
        );
    }

    #[test]
    fn security_test_null_bytes_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("null.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"name = \"test\"\0extra").unwrap();

        let result = read_config_file(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("null bytes"),
            "expected null bytes error, got: {err}"
        );
    }

    #[test]
    fn security_test_traversal_path_rejected() {
        let result = validate_path("test_field", Path::new("/tmp/../etc/shadow"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("directory traversal"),
            "expected traversal error, got: {err}"
        );

        // Safe paths should pass
        assert!(validate_path("test_field", Path::new("/tmp/safe/path")).is_ok());
        assert!(validate_path("test_field", Path::new("relative/path")).is_ok());
    }

    #[test]
    fn security_test_env_null_bytes_rejected() {
        let result = validate_env_value("TEST_VAR", "hello\0world");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("null bytes"),
            "expected null bytes error, got: {err}"
        );
    }

    #[test]
    fn security_test_env_control_chars_rejected() {
        let result = validate_env_value("TEST_VAR", "hello\x01world");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("control character"),
            "expected control character error, got: {err}"
        );

        // Tab, newline, CR are allowed
        assert!(validate_env_value("TEST_VAR", "hello\tworld").is_ok());
        assert!(validate_env_value("TEST_VAR", "hello\nworld").is_ok());
        assert!(validate_env_value("TEST_VAR", "hello\rworld").is_ok());
    }

    #[test]
    fn deep_merge_tables() {
        let mut base: toml::Value = toml::from_str(
            r#"
            name = "base"
            [pilot]
            output_buffer_lines = 100
            [pilot.stall]
            timeout_secs = 120
            max_nudges = 5
            "#,
        )
        .unwrap();

        let overlay: toml::Value = toml::from_str(
            r#"
            name = "overlay"
            [pilot.stall]
            timeout_secs = 60
            "#,
        )
        .unwrap();

        deep_merge(&mut base, &overlay);

        let table = base.as_table().unwrap();
        assert_eq!(
            table["name"].as_str().unwrap(),
            "overlay"
        );
        // pilot.output_buffer_lines preserved from base
        assert_eq!(
            table["pilot"]["output_buffer_lines"].as_integer().unwrap(),
            100
        );
        // pilot.stall.timeout_secs overridden by overlay
        assert_eq!(
            table["pilot"]["stall"]["timeout_secs"].as_integer().unwrap(),
            60
        );
        // pilot.stall.max_nudges preserved from base
        assert_eq!(
            table["pilot"]["stall"]["max_nudges"].as_integer().unwrap(),
            5
        );
    }

    #[test]
    fn deep_merge_array_replaces() {
        let mut base: toml::Value = toml::from_str(
            r#"
            policy_paths = ["/base/policies"]
            "#,
        )
        .unwrap();

        let overlay: toml::Value = toml::from_str(
            r#"
            policy_paths = ["/overlay/a", "/overlay/b"]
            "#,
        )
        .unwrap();

        deep_merge(&mut base, &overlay);

        let arr = base["policy_paths"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap(), "/overlay/a");
        assert_eq!(arr[1].as_str().unwrap(), "/overlay/b");
    }

    #[test]
    fn mask_sensitive_works() {
        assert_eq!(mask_sensitive("xoxb-1234567890-abcdefgh"), "xoxb***");
        assert_eq!(mask_sensitive("sk-a"), "sk-a***");
        assert_eq!(mask_sensitive("sk-"), "***");
        assert_eq!(mask_sensitive(""), "***");
    }

    #[test]
    fn default_aegis_config() {
        let config = AegisConfig::default();
        assert_eq!(config.name, "default");
        assert_eq!(config.sandbox_dir, PathBuf::from("/tmp/aegis-sandbox"));
        assert!(config.policy_paths.is_empty());
        assert!(config.alerts.is_empty());
        assert!(config.pilot.is_none());
        assert!(config.channel.is_none());
    }

    #[test]
    fn config_source_display() {
        assert_eq!(ConfigSource::BuiltinDefault.to_string(), "built-in default");
        assert_eq!(
            ConfigSource::SystemFile(PathBuf::from("/etc/aegis/config.toml")).to_string(),
            "system file: /etc/aegis/config.toml"
        );
        assert_eq!(
            ConfigSource::EnvVar("AEGIS_SANDBOX_DIR".into()).to_string(),
            "env var: AEGIS_SANDBOX_DIR"
        );
        assert_eq!(
            ConfigSource::CliFlag("--sandbox-dir".into()).to_string(),
            "CLI flag: --sandbox-dir"
        );
    }

    #[test]
    fn isolation_env_var_parsing() {
        let result =
            env_value_to_toml("AEGIS_ISOLATION", &["isolation"], "seatbelt").unwrap();
        assert_eq!(result.as_str().unwrap(), "Seatbelt");

        let result =
            env_value_to_toml("AEGIS_ISOLATION", &["isolation"], "process").unwrap();
        assert_eq!(result.as_str().unwrap(), "Process");

        let result =
            env_value_to_toml("AEGIS_ISOLATION", &["isolation"], "none").unwrap();
        assert_eq!(result.as_str().unwrap(), "None");

        let result =
            env_value_to_toml("AEGIS_ISOLATION", &["isolation"], "invalid");
        assert!(result.is_err());
    }

    #[test]
    fn policy_path_env_splits_on_colon() {
        let result = env_value_to_toml(
            "AEGIS_POLICY_PATH",
            &["policy_paths"],
            "/path/a:/path/b:/path/c",
        )
        .unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_str().unwrap(), "/path/a");
        assert_eq!(arr[1].as_str().unwrap(), "/path/b");
        assert_eq!(arr[2].as_str().unwrap(), "/path/c");
    }

    #[test]
    fn get_dot_value_simple() {
        let root: toml::Value = toml::from_str(
            r#"
            name = "test"
            sandbox_dir = "/tmp/sandbox"
            "#,
        )
        .unwrap();
        assert_eq!(
            get_dot_value(&root, "name"),
            Some(toml::Value::String("test".into()))
        );
        assert_eq!(
            get_dot_value(&root, "sandbox_dir"),
            Some(toml::Value::String("/tmp/sandbox".into()))
        );
        assert_eq!(get_dot_value(&root, "nonexistent"), None);
    }

    #[test]
    fn get_dot_value_nested() {
        let root: toml::Value = toml::from_str(
            r#"
            [pilot]
            output_buffer_lines = 500
            [pilot.stall]
            timeout_secs = 120
            max_nudges = 3
            "#,
        )
        .unwrap();
        assert_eq!(
            get_dot_value(&root, "pilot.output_buffer_lines"),
            Some(toml::Value::Integer(500))
        );
        assert_eq!(
            get_dot_value(&root, "pilot.stall.timeout_secs"),
            Some(toml::Value::Integer(120))
        );
        assert_eq!(
            get_dot_value(&root, "pilot.stall.max_nudges"),
            Some(toml::Value::Integer(3))
        );
        assert_eq!(get_dot_value(&root, "pilot.stall.missing"), None);
        assert_eq!(get_dot_value(&root, "pilot.missing.deep"), None);
    }

    #[test]
    fn set_dot_value_creates_nested() {
        let mut root = toml::Value::Table(toml::map::Map::new());
        set_dot_value(&mut root, "pilot.stall.timeout_secs", "60").unwrap();
        assert_eq!(
            get_dot_value(&root, "pilot.stall.timeout_secs"),
            Some(toml::Value::Integer(60))
        );
    }

    #[test]
    fn set_dot_value_overwrites() {
        let mut root: toml::Value = toml::from_str(
            r#"
            name = "old"
            "#,
        )
        .unwrap();
        set_dot_value(&mut root, "name", "new").unwrap();
        assert_eq!(
            get_dot_value(&root, "name"),
            Some(toml::Value::String("new".into()))
        );
    }

    #[test]
    fn set_dot_value_rejects_empty_path() {
        let mut root = toml::Value::Table(toml::map::Map::new());
        assert!(set_dot_value(&mut root, "", "val").is_err());
        assert!(set_dot_value(&mut root, "a..b", "val").is_err());
    }

    #[test]
    fn parse_toml_literal_types() {
        assert_eq!(parse_toml_literal("true"), toml::Value::Boolean(true));
        assert_eq!(parse_toml_literal("false"), toml::Value::Boolean(false));
        assert_eq!(parse_toml_literal("42"), toml::Value::Integer(42));
        assert_eq!(parse_toml_literal("-7"), toml::Value::Integer(-7));
        assert_eq!(parse_toml_literal("3.14"), toml::Value::Float(3.14));
        assert_eq!(
            parse_toml_literal("hello"),
            toml::Value::String("hello".into())
        );
        // Quoted string
        assert_eq!(
            parse_toml_literal("\"quoted\""),
            toml::Value::String("quoted".into())
        );
        // Array
        let arr = parse_toml_literal("[1, 2, 3]");
        assert!(arr.is_array());
        assert_eq!(arr.as_array().unwrap().len(), 3);
    }

    #[test]
    fn flatten_toml_basic() {
        let root: toml::Value = toml::from_str(
            r#"
            name = "test"
            [pilot]
            output_buffer_lines = 500
            [pilot.stall]
            timeout_secs = 120
            "#,
        )
        .unwrap();
        let mut out = Vec::new();
        flatten_toml(&root, "", &mut out);
        // Should contain at least these keys
        let keys: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"name"));
        assert!(keys.contains(&"pilot.output_buffer_lines"));
        assert!(keys.contains(&"pilot.stall.timeout_secs"));
    }

    #[test]
    fn flatten_toml_masks_sensitive() {
        let root: toml::Value = toml::from_str(
            r#"
            [channel]
            bot_token = "xoxb-secret-1234567890"
            "#,
        )
        .unwrap();
        let mut out = Vec::new();
        flatten_toml(&root, "", &mut out);
        let token_entry = out.iter().find(|(k, _)| k == "channel.bot_token");
        assert!(token_entry.is_some());
        let (_, display) = token_entry.unwrap();
        assert!(display.contains("***"), "should mask token, got: {display}");
        assert!(!display.contains("1234567890"), "should not show full token");
    }

    #[test]
    fn format_toml_value_all_types() {
        assert_eq!(
            format_toml_value(&toml::Value::String("hello".into())),
            "hello"
        );
        assert_eq!(format_toml_value(&toml::Value::Integer(42)), "42");
        assert_eq!(format_toml_value(&toml::Value::Boolean(true)), "true");
        assert_eq!(format_toml_value(&toml::Value::Float(2.5)), "2.5");
        let arr = toml::Value::Array(vec![
            toml::Value::String("a".into()),
            toml::Value::String("b".into()),
        ]);
        assert_eq!(format_toml_value(&arr), "[a, b]");
    }

    #[test]
    fn discover_layers_returns_three_entries() {
        let tmp = TempDir::new().unwrap();
        let loader = ConfigLoader::new()
            .with_system_path(tmp.path().join("nonexistent/config.toml"))
            .with_user_path(tmp.path().join("nonexistent/config.toml"))
            .with_workspace_path(tmp.path().join("nonexistent/config.toml"));
        let layers = loader.discover_layers();
        // Always returns 3 layers: system, user, workspace
        assert_eq!(layers.len(), 3);
        // None exist since they're nonexistent paths
        assert!(!layers[0].exists);
        assert!(!layers[1].exists);
        assert!(!layers[2].exists);
    }

    #[test]
    fn discover_layers_detects_existing_files() {
        let tmp = TempDir::new().unwrap();
        let user_dir = tmp.path().join("user");
        std::fs::create_dir_all(&user_dir).unwrap();
        let user_path = write_config(&user_dir, "name = \"test\"\nsandbox_dir = \"/tmp\"\n");

        let loader = ConfigLoader::new()
            .with_system_path(tmp.path().join("nonexistent/config.toml"))
            .with_user_path(user_path)
            .with_workspace_path(tmp.path().join("nonexistent/config.toml"));
        let layers = loader.discover_layers();
        assert!(!layers[0].exists); // system
        assert!(layers[1].exists); // user
        assert_eq!(layers[1].key_count, 2); // name + sandbox_dir
        assert!(!layers[2].exists); // workspace
    }
}
