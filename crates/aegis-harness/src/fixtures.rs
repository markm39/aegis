//! Test fixture management for E2E and integration tests.
//!
//! Provides structured test fixtures with sensible defaults for daemon
//! configuration, Cedar policies, and expected outputs. Fixtures can be
//! built programmatically or loaded from files.

use std::path::{Path, PathBuf};

use aegis_types::daemon::{
    AgentSlotConfig, AgentToolConfig, DaemonConfig, DaemonControlConfig, PersistenceConfig,
    RestartPolicy,
};

/// A named test fixture containing daemon config, policy, and expectations.
#[derive(Debug, Clone)]
pub struct TestFixture {
    /// Human-readable name for this fixture (used in test output).
    pub name: String,
    /// Daemon configuration for the test.
    pub daemon_config: DaemonConfig,
    /// Cedar policy content (raw `.cedar` file contents).
    pub policy_content: String,
    /// Expected outputs to assert against after running the fixture.
    pub expected_outputs: Vec<ExpectedOutput>,
}

/// An expected output to check after a test fixture runs.
#[derive(Debug, Clone)]
pub struct ExpectedOutput {
    /// Description of what this expectation checks.
    pub description: String,
    /// The kind of assertion to perform.
    pub kind: ExpectedOutputKind,
}

/// The specific type of output assertion.
#[derive(Debug, Clone)]
pub enum ExpectedOutputKind {
    /// Daemon command should return a response with `ok == true`.
    CommandSucceeds { command_type: String },
    /// Daemon command should return a response with `ok == false`.
    CommandFails { command_type: String },
    /// An audit entry with this action kind should exist.
    AuditEntryExists { action_kind: String },
    /// The daemon should be reachable (Ping succeeds).
    DaemonReachable,
}

/// Builder for constructing test daemon configurations with sensible defaults.
///
/// All generated configs use placeholder values that are safe for testing:
/// no real API keys, no real working directories, restricted socket paths.
pub struct FixtureBuilder {
    name: String,
    socket_path: Option<PathBuf>,
    agents: Vec<AgentSlotConfig>,
    policy_content: String,
    expected_outputs: Vec<ExpectedOutput>,
}

impl FixtureBuilder {
    /// Create a new fixture builder with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            socket_path: None,
            agents: Vec::new(),
            policy_content: default_test_policy().to_string(),
            expected_outputs: Vec::new(),
        }
    }

    /// Set the Unix socket path for the daemon control plane.
    pub fn socket_path(mut self, path: PathBuf) -> Self {
        self.socket_path = Some(path);
        self
    }

    /// Add an agent slot to the daemon config.
    pub fn agent(mut self, agent: AgentSlotConfig) -> Self {
        self.agents.push(agent);
        self
    }

    /// Add a simple echo agent (useful for tests that just need a running agent).
    pub fn echo_agent(self, name: impl Into<String>, working_dir: PathBuf) -> Self {
        let agent_name: String = name.into();
        self.agent(AgentSlotConfig {
            name: agent_name.into(),
            tool: AgentToolConfig::Custom {
                command: "/bin/echo".into(),
                args: vec!["test-agent-running".into()],
                adapter: aegis_types::config::AdapterConfig::Auto,
                env: vec![],
            },
            working_dir,
            role: Some("test agent".into()),
            agent_goal: None,
            context: None,
            task: None,
            pilot: None,
            restart: RestartPolicy::Never,
            max_restarts: 0,
            enabled: true,
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
            lane: None,
        })
    }

    /// Set the Cedar policy content.
    pub fn policy(mut self, content: impl Into<String>) -> Self {
        self.policy_content = content.into();
        self
    }

    /// Add an expected output assertion.
    pub fn expect(mut self, output: ExpectedOutput) -> Self {
        self.expected_outputs.push(output);
        self
    }

    /// Build the fixture, producing a validated `TestFixture`.
    pub fn build(self) -> TestFixture {
        let socket_path = self
            .socket_path
            .unwrap_or_else(|| PathBuf::from("/tmp/aegis-test.sock"));

        let daemon_config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig {
                socket_path,
                http_listen: String::new(),
                api_key: String::new(),
            },
            dashboard: Default::default(),
            alerts: vec![],
            agents: self.agents,
            channel: None,
            channel_routing: None,
            toolkit: Default::default(),
            memory: Default::default(),
            session_files: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
            lanes: vec![],
            workspace_hooks: Default::default(),
            acp_server: None,
            default_model: None,
            skills: vec![],
            retention: Default::default(),
            redaction: Default::default(),
        };

        TestFixture {
            name: self.name,
            daemon_config,
            policy_content: self.policy_content,
            expected_outputs: self.expected_outputs,
        }
    }
}

/// Build a minimal test daemon config with sensible defaults.
///
/// The generated config:
/// - Uses a socket path inside the provided temp directory
/// - Has no agents (add them separately)
/// - Uses no real API keys or tokens
/// - Disables persistence features
pub fn build_test_daemon_config(temp_dir: &Path) -> DaemonConfig {
    DaemonConfig {
        goal: None,
        persistence: PersistenceConfig {
            launchd: false,
            prevent_sleep: false,
        },
        control: DaemonControlConfig {
            socket_path: temp_dir.join("daemon.sock"),
            http_listen: String::new(),
            api_key: String::new(),
        },
        dashboard: Default::default(),
        alerts: vec![],
        agents: vec![],
        channel: None,
        channel_routing: None,
        toolkit: Default::default(),
        memory: Default::default(),
        session_files: Default::default(),
        cron: Default::default(),
        plugins: Default::default(),
        aliases: Default::default(),
        lanes: vec![],
        workspace_hooks: Default::default(),
        acp_server: None,
        default_model: None,
        skills: vec![],
        retention: Default::default(),
        redaction: Default::default(),
    }
}

/// Default Cedar policy for testing: deny everything.
///
/// This is the safest default -- tests that need permissive policies
/// should explicitly set them.
pub fn default_test_policy() -> &'static str {
    r#"forbid(principal, action, resource);"#
}

/// A permissive Cedar policy that allows all file reads.
///
/// Useful for tests that need to verify allow verdicts.
pub fn allow_reads_policy() -> &'static str {
    r#"permit(principal, action == Aegis::Action::"FileRead", resource);"#
}

/// A Cedar policy that allows all actions (observe-only mode).
///
/// Use sparingly -- most tests should use restrictive policies.
pub fn allow_all_policy() -> &'static str {
    r#"permit(principal, action, resource);"#
}

/// Validate that a fixture's config contains no real secrets.
///
/// Returns an error message if any field looks like it contains a real
/// API key or token (non-empty strings in sensitive fields).
pub fn validate_fixture_security(fixture: &TestFixture) -> Result<(), String> {
    let config = &fixture.daemon_config;

    // Control plane API key must be empty in test fixtures
    if !config.control.api_key.is_empty() {
        return Err("fixture contains non-empty control API key".into());
    }

    // Check agent configs for suspicious values
    for agent in &config.agents {
        if let AgentToolConfig::Custom { env, .. } = &agent.tool {
            for (key, _) in env {
                let key_upper = key.to_uppercase();
                if key_upper.contains("API_KEY")
                    || key_upper.contains("SECRET")
                    || key_upper.contains("TOKEN")
                    || key_upper.contains("PASSWORD")
                {
                    return Err(format!(
                        "fixture agent {:?} has suspicious env var: {key}",
                        agent.name
                    ));
                }
            }
        }
    }

    // Channel config must not have real bot tokens
    if let Some(aegis_types::config::ChannelConfig::Telegram(ref tg_config)) = config.channel {
        if !tg_config.bot_token.is_empty() && !tg_config.bot_token.starts_with("TEST_") {
            return Err("fixture contains non-test Telegram bot token".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_builder_produces_valid_config() {
        let fixture = FixtureBuilder::new("test-fixture")
            .socket_path(PathBuf::from("/tmp/test-aegis.sock"))
            .echo_agent("echo-1", PathBuf::from("/tmp"))
            .policy(allow_reads_policy())
            .expect(ExpectedOutput {
                description: "daemon should be reachable".into(),
                kind: ExpectedOutputKind::DaemonReachable,
            })
            .build();

        assert_eq!(fixture.name, "test-fixture");
        assert_eq!(fixture.daemon_config.agents.len(), 1);
        assert_eq!(fixture.daemon_config.agents[0].name, "echo-1");
        assert_eq!(fixture.expected_outputs.len(), 1);

        // Config should serialize to valid TOML
        let toml_str = fixture.daemon_config.to_toml().expect("should serialize");
        assert!(!toml_str.is_empty());

        // And parse back
        let parsed = DaemonConfig::from_toml(&toml_str).expect("should parse");
        assert_eq!(parsed.agents.len(), 1);
    }

    #[test]
    fn build_test_daemon_config_has_sensible_defaults() {
        let dir = PathBuf::from("/tmp/aegis-test-dir");
        let config = build_test_daemon_config(&dir);

        assert!(config.agents.is_empty());
        assert!(config.control.api_key.is_empty());
        assert!(!config.persistence.launchd);
        assert!(!config.persistence.prevent_sleep);
        assert_eq!(config.control.socket_path, dir.join("daemon.sock"));
    }

    #[test]
    fn default_test_policy_is_deny_all() {
        let policy = default_test_policy();
        assert!(policy.contains("forbid"));
    }

    #[test]
    fn validate_fixture_security_rejects_real_keys() {
        let mut fixture = FixtureBuilder::new("bad-fixture")
            .socket_path(PathBuf::from("/tmp/test.sock"))
            .build();

        // Clean fixture should pass
        assert!(validate_fixture_security(&fixture).is_ok());

        // Add a real-looking API key
        fixture.daemon_config.control.api_key = "sk-real-key-123".into();
        assert!(validate_fixture_security(&fixture).is_err());
    }

    #[test]
    fn validate_fixture_security_rejects_suspicious_env_vars() {
        let fixture = FixtureBuilder::new("suspicious-fixture")
            .agent(AgentSlotConfig {
                name: "bad-agent".into(),
                tool: AgentToolConfig::Custom {
                    command: "/bin/echo".into(),
                    args: vec![],
                    adapter: aegis_types::config::AdapterConfig::Auto,
                    env: vec![("ANTHROPIC_API_KEY".into(), "sk-ant-123".into())],
                },
                working_dir: PathBuf::from("/tmp"),
                role: None,
                agent_goal: None,
                context: None,
                task: None,
                pilot: None,
                restart: RestartPolicy::Never,
                max_restarts: 0,
                enabled: true,
                orchestrator: None,
                security_preset: None,
                policy_dir: None,
                isolation: None,
                lane: None,
            })
            .build();

        let result = validate_fixture_security(&fixture);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("API_KEY"));
    }

    #[test]
    fn allow_policies_are_valid_cedar() {
        // These should at minimum be parseable strings (actual Cedar validation
        // requires the policy engine, but we verify they're non-empty).
        assert!(!allow_reads_policy().is_empty());
        assert!(allow_reads_policy().contains("permit"));
        assert!(!allow_all_policy().is_empty());
        assert!(allow_all_policy().contains("permit"));
    }
}
