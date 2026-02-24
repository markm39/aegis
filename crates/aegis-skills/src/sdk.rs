//! Plugin SDK -- defines the interface for skill plugins.
//!
//! Skills implement the [`SkillPlugin`] trait to declare their capabilities
//! and handle execution requests. The SDK also defines the input/output types
//! that flow between the executor and the skill process.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Core trait that all skill plugins must implement.
///
/// Skills are isolated execution units. The executor calls [`execute`](SkillPlugin::execute)
/// with a structured input and expects a structured output. The [`validate`](SkillPlugin::validate)
/// method checks that the skill's runtime requirements (binaries, config, etc.) are met.
#[async_trait]
pub trait SkillPlugin: Send + Sync {
    /// Unique name of this skill (must match manifest name).
    fn name(&self) -> &str;

    /// Semantic version of this skill.
    fn version(&self) -> &str;

    /// Human-readable description of what this skill does.
    fn description(&self) -> &str;

    /// Capabilities this skill provides (actions, required permissions).
    fn capabilities(&self) -> SkillCapabilities;

    /// Execute the skill with the given input.
    ///
    /// Returns a structured output on success. Errors indicate execution
    /// failures (not business-logic failures -- those go in `SkillOutput::messages`).
    async fn execute(&self, input: SkillInput) -> Result<SkillOutput>;

    /// Validate that the skill can run in the current environment.
    ///
    /// Checks for required binaries, configuration, permissions, etc.
    /// Returns `Ok(())` if everything is ready, or an error describing
    /// what is missing.
    async fn validate(&self) -> Result<()>;
}

/// Input passed to a skill for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInput {
    /// The action to perform (must be one of the skill's declared actions).
    pub action: String,
    /// Parameters for the action as a JSON value.
    pub parameters: serde_json::Value,
    /// Execution context (agent info, workspace, etc.).
    pub context: SkillContext,
}

/// Output returned from a skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillOutput {
    /// The primary result value.
    pub result: serde_json::Value,
    /// Artifacts produced by the skill (files, logs, etc.).
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    /// Human-readable messages (informational, warnings, etc.).
    #[serde(default)]
    pub messages: Vec<String>,
}

impl SkillOutput {
    /// Create a simple output with just a result value.
    pub fn simple(result: serde_json::Value) -> Self {
        Self {
            result,
            artifacts: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Create an output with a result and messages.
    pub fn with_messages(result: serde_json::Value, messages: Vec<String>) -> Self {
        Self {
            result,
            artifacts: Vec::new(),
            messages,
        }
    }
}

/// Context provided to a skill during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillContext {
    /// Name of the agent requesting the skill execution.
    #[serde(default)]
    pub agent_name: Option<String>,
    /// Session ID for audit correlation.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Path to the agent's workspace directory.
    #[serde(default)]
    pub workspace_path: Option<PathBuf>,
    /// Additional environment variables to pass to the skill process.
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
}

/// An artifact produced by a skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Human-readable name for this artifact.
    pub name: String,
    /// MIME type of the artifact content.
    #[serde(default = "default_mime_type")]
    pub content_type: String,
    /// Path to the artifact file (if file-based).
    pub path: Option<PathBuf>,
    /// Inline content (for small artifacts).
    pub content: Option<String>,
}

fn default_mime_type() -> String {
    "application/octet-stream".into()
}

/// Capabilities declared by a skill plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillCapabilities {
    /// Actions this skill can perform.
    pub actions: Vec<String>,
    /// Cedar permission names required to use this skill.
    #[serde(default)]
    pub required_permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_input_serialization() {
        let input = SkillInput {
            action: "calculate".into(),
            parameters: serde_json::json!({"expression": "2+2"}),
            context: SkillContext::default(),
        };

        let json = serde_json::to_string(&input).unwrap();
        let back: SkillInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, "calculate");
        assert_eq!(back.parameters["expression"], "2+2");
    }

    #[test]
    fn test_skill_output_serialization() {
        let output = SkillOutput {
            result: serde_json::json!(4),
            artifacts: vec![Artifact {
                name: "log.txt".into(),
                content_type: "text/plain".into(),
                path: Some(PathBuf::from("/tmp/log.txt")),
                content: None,
            }],
            messages: vec!["Calculation complete".into()],
        };

        let json = serde_json::to_string(&output).unwrap();
        let back: SkillOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.result, 4);
        assert_eq!(back.artifacts.len(), 1);
        assert_eq!(back.artifacts[0].name, "log.txt");
        assert_eq!(back.messages, vec!["Calculation complete"]);
    }

    #[test]
    fn test_skill_output_simple() {
        let output = SkillOutput::simple(serde_json::json!("ok"));
        assert_eq!(output.result, "ok");
        assert!(output.artifacts.is_empty());
        assert!(output.messages.is_empty());
    }

    #[test]
    fn test_skill_output_with_messages() {
        let output = SkillOutput::with_messages(serde_json::json!(42), vec!["done".into()]);
        assert_eq!(output.result, 42);
        assert_eq!(output.messages, vec!["done"]);
    }

    #[test]
    fn test_skill_context_default() {
        let ctx = SkillContext::default();
        assert!(ctx.agent_name.is_none());
        assert!(ctx.session_id.is_none());
        assert!(ctx.workspace_path.is_none());
        assert!(ctx.env_vars.is_empty());
    }

    #[test]
    fn test_skill_capabilities_default() {
        let caps = SkillCapabilities::default();
        assert!(caps.actions.is_empty());
        assert!(caps.required_permissions.is_empty());
    }

    #[test]
    fn test_skill_context_with_env_vars() {
        let mut ctx = SkillContext::default();
        ctx.agent_name = Some("agent-1".into());
        ctx.env_vars.insert("API_KEY".into(), "secret".into());

        let json = serde_json::to_string(&ctx).unwrap();
        let back: SkillContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_name.as_deref(), Some("agent-1"));
        assert_eq!(
            back.env_vars.get("API_KEY").map(|s| s.as_str()),
            Some("secret")
        );
    }

    #[test]
    fn test_artifact_serialization() {
        let artifact = Artifact {
            name: "result.json".into(),
            content_type: "application/json".into(),
            path: None,
            content: Some("{\"status\":\"ok\"}".into()),
        };

        let json = serde_json::to_string(&artifact).unwrap();
        let back: Artifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "result.json");
        assert!(back.path.is_none());
        assert_eq!(back.content.as_deref(), Some("{\"status\":\"ok\"}"));
    }
}
