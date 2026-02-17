//! Configuration types for Aegis agent instances.
//!
//! [`AegisConfig`] is the top-level configuration loaded from `aegis.toml`,
//! controlling sandbox paths, policy locations, network rules, isolation
//! backend, and observer settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::AegisError;

/// Network protocol for access control rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Https => write!(f, "HTTPS"),
        }
    }
}

/// A network access rule specifying which host/port/protocol combinations are allowed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkRule {
    /// Hostname or IP address (e.g., `"api.openai.com"`).
    pub host: String,
    /// Port number; `None` means any port.
    pub port: Option<u16>,
    /// Protocol type.
    pub protocol: Protocol,
}

impl std::fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{} {}:{}", self.protocol, self.host, port),
            None => write!(f, "{} {}", self.protocol, self.host),
        }
    }
}

/// Observer configuration controlling how Aegis monitors filesystem activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObserverConfig {
    /// No filesystem observation.
    None,
    /// FSEvents-based observation (no privileges required).
    FsEvents {
        /// Whether to perform pre/post snapshot diffing (catches reads, rapid events).
        enable_snapshots: bool,
    },
    /// Endpoint Security logger (requires root + Full Disk Access).
    EndpointSecurity,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        ObserverConfig::FsEvents {
            enable_snapshots: true,
        }
    }
}

impl std::fmt::Display for ObserverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObserverConfig::None => write!(f, "None"),
            ObserverConfig::FsEvents { enable_snapshots: true } => {
                write!(f, "FsEvents (snapshots: enabled)")
            }
            ObserverConfig::FsEvents { enable_snapshots: false } => {
                write!(f, "FsEvents (snapshots: disabled)")
            }
            ObserverConfig::EndpointSecurity => write!(f, "Endpoint Security"),
        }
    }
}

/// OS-level isolation mechanism for the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationConfig {
    /// macOS Seatbelt (`sandbox-exec`) with an auto-generated SBPL profile.
    Seatbelt {
        /// Optional path to a hand-written SBPL file that overrides the generated profile.
        profile_overrides: Option<PathBuf>,
    },
    /// Simple process isolation (no OS-level sandbox). Relies on observer + policy only.
    Process,
    /// No isolation at all. The command runs unsandboxed.
    None,
}

impl std::fmt::Display for IsolationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationConfig::Seatbelt { profile_overrides: Some(path) } => {
                write!(f, "Seatbelt (overrides: {})", path.display())
            }
            IsolationConfig::Seatbelt { profile_overrides: None } => write!(f, "Seatbelt"),
            IsolationConfig::Process => write!(f, "Process"),
            IsolationConfig::None => write!(f, "None"),
        }
    }
}

/// Top-level configuration for an Aegis agent instance.
///
/// Loaded from `aegis.toml` and controls sandbox directory, policies,
/// audit storage, network rules, isolation backend, and observer settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    /// Human-readable name for this configuration (also the Cedar principal).
    pub name: String,
    /// Directory the sandboxed process operates within.
    pub sandbox_dir: PathBuf,
    /// Directories containing Cedar policy files (`.cedar`).
    pub policy_paths: Vec<PathBuf>,
    /// Optional path to a Cedar schema file for policy validation.
    pub schema_path: Option<PathBuf>,
    /// Path to the SQLite audit ledger database.
    pub ledger_path: PathBuf,
    /// Network access rules the sandbox enforces.
    pub allowed_network: Vec<NetworkRule>,
    /// Which OS-level isolation mechanism to use.
    pub isolation: IsolationConfig,
    /// How Aegis monitors filesystem activity during execution.
    #[serde(default)]
    pub observer: ObserverConfig,
}

impl AegisConfig {
    /// Parse a configuration from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, AegisError> {
        toml::from_str(content).map_err(|e| AegisError::ConfigError(e.to_string()))
    }

    /// Serialize the configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, AegisError> {
        toml::to_string_pretty(self).map_err(|e| AegisError::ConfigError(e.to_string()))
    }

    /// Create a default configuration for a named agent under `base_dir`.
    ///
    /// The sandbox directory defaults to `base_dir/sandbox`.
    pub fn default_for(name: &str, base_dir: &std::path::Path) -> Self {
        let sandbox_dir = base_dir.join("sandbox");
        Self::default_for_with_sandbox(name, base_dir, sandbox_dir)
    }

    /// Like [`default_for`](Self::default_for), but with an explicit sandbox directory.
    ///
    /// Used by `aegis init --dir` to point the sandbox at an existing project
    /// directory instead of creating a dedicated one.
    pub fn default_for_with_sandbox(
        name: &str,
        base_dir: &std::path::Path,
        sandbox_dir: PathBuf,
    ) -> Self {
        let policies_dir = base_dir.join("policies");
        let ledger_path = base_dir.join("audit.db");

        Self {
            name: name.to_string(),
            sandbox_dir,
            policy_paths: vec![policies_dir],
            schema_path: None,
            ledger_path,
            allowed_network: Vec::new(),
            isolation: IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
            observer: ObserverConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_toml_roundtrip() {
        let config = AegisConfig {
            name: "test".into(),
            sandbox_dir: PathBuf::from("/tmp/sandbox"),
            policy_paths: vec![PathBuf::from("/tmp/policies")],
            schema_path: None,
            ledger_path: PathBuf::from("/tmp/audit.db"),
            allowed_network: vec![NetworkRule {
                host: "api.openai.com".into(),
                port: Some(443),
                protocol: Protocol::Https,
            }],
            isolation: IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
            observer: ObserverConfig::default(),
        };

        let toml_str = config.to_toml().unwrap();
        let parsed = AegisConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.allowed_network.len(), 1);
        assert_eq!(parsed.allowed_network[0].host, "api.openai.com");
    }

    #[test]
    fn config_default_for() {
        let base = PathBuf::from("/home/user/.aegis/myagent");
        let config = AegisConfig::default_for("myagent", &base);
        assert_eq!(config.name, "myagent");
        assert_eq!(config.sandbox_dir, base.join("sandbox"));
        assert_eq!(config.ledger_path, base.join("audit.db"));
    }

    #[test]
    fn config_default_for_with_sandbox() {
        let base = PathBuf::from("/home/user/.aegis/myagent");
        let project = PathBuf::from("/home/user/my-project");
        let config = AegisConfig::default_for_with_sandbox("myagent", &base, project.clone());
        assert_eq!(config.name, "myagent");
        assert_eq!(config.sandbox_dir, project);
        assert_eq!(config.ledger_path, base.join("audit.db"));
    }

    #[test]
    fn isolation_config_variants() {
        let variants = vec![
            IsolationConfig::Seatbelt {
                profile_overrides: None,
            },
            IsolationConfig::Process,
            IsolationConfig::None,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: IsolationConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn observer_config_display() {
        assert_eq!(ObserverConfig::None.to_string(), "None");
        assert_eq!(
            ObserverConfig::FsEvents { enable_snapshots: true }.to_string(),
            "FsEvents (snapshots: enabled)"
        );
        assert_eq!(
            ObserverConfig::FsEvents { enable_snapshots: false }.to_string(),
            "FsEvents (snapshots: disabled)"
        );
        assert_eq!(
            ObserverConfig::EndpointSecurity.to_string(),
            "Endpoint Security"
        );
    }

    #[test]
    fn network_rule_display() {
        let rule_with_port = NetworkRule {
            host: "api.openai.com".into(),
            port: Some(443),
            protocol: Protocol::Https,
        };
        assert_eq!(rule_with_port.to_string(), "HTTPS api.openai.com:443");

        let rule_no_port = NetworkRule {
            host: "example.com".into(),
            port: None,
            protocol: Protocol::Tcp,
        };
        assert_eq!(rule_no_port.to_string(), "TCP example.com");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Https.to_string(), "HTTPS");
    }

    #[test]
    fn isolation_config_display() {
        assert_eq!(IsolationConfig::Process.to_string(), "Process");
        assert_eq!(IsolationConfig::None.to_string(), "None");
        assert_eq!(
            IsolationConfig::Seatbelt { profile_overrides: None }.to_string(),
            "Seatbelt"
        );
        assert_eq!(
            IsolationConfig::Seatbelt {
                profile_overrides: Some(PathBuf::from("/tmp/custom.sb"))
            }
            .to_string(),
            "Seatbelt (overrides: /tmp/custom.sb)"
        );
    }
}
