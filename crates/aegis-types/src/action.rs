//! Actions that agents can perform, evaluated against Cedar policies.
//!
//! An [`Action`] pairs a principal with an [`ActionKind`] and is the primary
//! input to policy evaluation and audit logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// The specific type of action being performed, evaluated against Cedar policies.
///
/// Each variant maps to a Cedar `Action` entity (e.g., `Aegis::Action::"FileRead"`).
/// The fields carry context used for policy evaluation and audit logging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionKind {
    /// Read a file at the given path.
    FileRead {
        /// Absolute path to the file being read.
        path: PathBuf,
    },
    /// Write (create or modify) a file at the given path.
    FileWrite {
        /// Absolute path to the file being written.
        path: PathBuf,
    },
    /// Delete a file at the given path.
    FileDelete {
        /// Absolute path to the file being deleted.
        path: PathBuf,
    },
    /// Create a directory at the given path.
    DirCreate {
        /// Absolute path to the directory being created.
        path: PathBuf,
    },
    /// List the contents of a directory.
    DirList {
        /// Absolute path to the directory being listed.
        path: PathBuf,
    },
    /// Open a TCP connection to a remote host.
    NetConnect {
        /// Hostname or IP address of the remote endpoint.
        host: String,
        /// TCP port number.
        port: u16,
    },
    /// Make an HTTP request (higher-level than NetConnect).
    NetRequest {
        /// HTTP method (GET, POST, etc.).
        method: String,
        /// Full URL of the request.
        url: String,
    },
    /// Invoke an external tool or API.
    ToolCall {
        /// Name of the tool being called.
        tool: String,
        /// Tool-specific arguments as a JSON value.
        args: serde_json::Value,
    },
    /// Spawn a child process.
    ProcessSpawn {
        /// Command name or path.
        command: String,
        /// Command-line arguments.
        args: Vec<String>,
    },
    /// Record the exit of a child process.
    ProcessExit {
        /// Command name or path that exited.
        command: String,
        /// Process exit code (negative if terminated by signal).
        exit_code: i32,
    },
    /// API usage data extracted from an AI provider's response.
    ApiUsage {
        /// Provider name (e.g., "anthropic", "openai").
        provider: String,
        /// Model name from the API response.
        model: String,
        /// API endpoint path (e.g., "/v1/messages").
        endpoint: String,
        /// Input/prompt tokens consumed.
        input_tokens: u64,
        /// Output/completion tokens consumed.
        output_tokens: u64,
        /// Cache creation input tokens (Anthropic-specific, 0 otherwise).
        cache_creation_input_tokens: u64,
        /// Cache read input tokens (Anthropic-specific, 0 otherwise).
        cache_read_input_tokens: u64,
    },
    /// Security scan of a skill directory for dangerous code patterns.
    SkillScan {
        /// Path to the skill directory that was scanned.
        path: PathBuf,
        /// Whether the scan passed (no error-severity findings).
        passed: bool,
        /// Number of warning-severity findings.
        warning_count: usize,
        /// Number of error-severity findings.
        error_count: usize,
    },
    /// Automatic capture of a memory entry from agent conversation.
    MemoryCapture {
        /// The agent performing the capture.
        agent_id: String,
        /// Extraction category (e.g., "preference", "decision", "fact").
        category: String,
        /// The memory key being stored.
        key: String,
    },
}

/// A principal performing an action at a point in time.
///
/// This is the primary input to `PolicyEngine::evaluate()`. The principal
/// identifies the agent (e.g., `"claude-agent"`), and the kind specifies
/// what the agent is attempting to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// Unique identifier for this action instance.
    pub id: Uuid,
    /// When the action was created.
    pub timestamp: DateTime<Utc>,
    /// The agent or entity performing the action (maps to Cedar principal).
    pub principal: String,
    /// What the agent is doing.
    pub kind: ActionKind,
}

impl Action {
    /// Create a new action with an auto-generated ID and current timestamp.
    pub fn new(principal: impl Into<String>, kind: ActionKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            principal: principal.into(),
            kind,
        }
    }
}

impl ActionKind {
    /// Parse a JSON-serialized `ActionKind` and return its human-readable display string.
    ///
    /// Falls back to the raw JSON string if deserialization fails (e.g., for
    /// unknown variants or malformed JSON). This keeps display logic in sync
    /// with the `Display` impl and avoids duplicating the conversion elsewhere.
    pub fn display_from_json(json: &str) -> String {
        serde_json::from_str::<ActionKind>(json)
            .map(|kind| kind.to_string())
            .unwrap_or_else(|_| json.to_string())
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionKind::FileRead { path } => write!(f, "FileRead {}", path.display()),
            ActionKind::FileWrite { path } => write!(f, "FileWrite {}", path.display()),
            ActionKind::FileDelete { path } => write!(f, "FileDelete {}", path.display()),
            ActionKind::DirCreate { path } => write!(f, "DirCreate {}", path.display()),
            ActionKind::DirList { path } => write!(f, "DirList {}", path.display()),
            ActionKind::NetConnect { host, port } => write!(f, "NetConnect {host}:{port}"),
            ActionKind::NetRequest { method, url } => write!(f, "NetRequest {method} {url}"),
            ActionKind::ToolCall { tool, .. } => write!(f, "ToolCall {tool}"),
            ActionKind::ProcessSpawn { command, .. } => write!(f, "ProcessSpawn {command}"),
            ActionKind::ProcessExit { command, exit_code } => {
                write!(f, "ProcessExit {command} (code {exit_code})")
            }
            ActionKind::ApiUsage {
                provider,
                model,
                input_tokens,
                output_tokens,
                ..
            } => {
                write!(
                    f,
                    "ApiUsage {provider}/{model} in={input_tokens} out={output_tokens}"
                )
            }
            ActionKind::SkillScan {
                path,
                passed,
                warning_count,
                error_count,
            } => {
                let status = if *passed { "passed" } else { "BLOCKED" };
                write!(
                    f,
                    "SkillScan {} {status} (warnings={warning_count}, errors={error_count})",
                    path.display()
                )
            }
            ActionKind::MemoryCapture {
                agent_id,
                category,
                key,
            } => {
                write!(f, "MemoryCapture {agent_id}/{category}:{key}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_serialization_roundtrip() {
        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.principal, "test-agent");
        assert_eq!(deserialized.kind, action.kind);
    }

    #[test]
    fn action_kind_variants_serialize() {
        let variants = vec![
            ActionKind::FileRead {
                path: PathBuf::from("/a"),
            },
            ActionKind::FileWrite {
                path: PathBuf::from("/b"),
            },
            ActionKind::FileDelete {
                path: PathBuf::from("/c"),
            },
            ActionKind::DirCreate {
                path: PathBuf::from("/d"),
            },
            ActionKind::DirList {
                path: PathBuf::from("/e"),
            },
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
            ActionKind::NetRequest {
                method: "GET".into(),
                url: "https://example.com".into(),
            },
            ActionKind::ToolCall {
                tool: "shell".into(),
                args: serde_json::json!({"cmd": "ls"}),
            },
            ActionKind::ProcessSpawn {
                command: "echo".into(),
                args: vec!["hello".into()],
            },
            ActionKind::ProcessExit {
                command: "echo".into(),
                exit_code: 0,
            },
            ActionKind::ApiUsage {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                endpoint: "/v1/messages".into(),
                input_tokens: 100,
                output_tokens: 50,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 10,
            },
            ActionKind::SkillScan {
                path: PathBuf::from("/tmp/my-skill"),
                passed: true,
                warning_count: 1,
                error_count: 0,
            },
            ActionKind::MemoryCapture {
                agent_id: "agent-1".into(),
                category: "preference".into(),
                key: "editor".into(),
            },
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ActionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn display_from_json_valid() {
        let json = r#"{"FileRead":{"path":"/tmp/test.txt"}}"#;
        assert_eq!(
            ActionKind::display_from_json(json),
            "FileRead /tmp/test.txt"
        );

        let json = r#"{"NetConnect":{"host":"example.com","port":443}}"#;
        assert_eq!(
            ActionKind::display_from_json(json),
            "NetConnect example.com:443"
        );
    }

    #[test]
    fn display_from_json_invalid_falls_back() {
        assert_eq!(ActionKind::display_from_json("not json"), "not json");
        assert_eq!(ActionKind::display_from_json("{}"), "{}");

        let unknown = r#"{"CustomAction":{}}"#;
        assert_eq!(ActionKind::display_from_json(unknown), unknown);
    }

    #[test]
    fn action_kind_display() {
        assert_eq!(
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/f.txt")
            }
            .to_string(),
            "FileRead /tmp/f.txt"
        );
        assert_eq!(
            ActionKind::FileWrite {
                path: PathBuf::from("/a/b")
            }
            .to_string(),
            "FileWrite /a/b"
        );
        assert_eq!(
            ActionKind::FileDelete {
                path: PathBuf::from("/x")
            }
            .to_string(),
            "FileDelete /x"
        );
        assert_eq!(
            ActionKind::DirCreate {
                path: PathBuf::from("/d")
            }
            .to_string(),
            "DirCreate /d"
        );
        assert_eq!(
            ActionKind::DirList {
                path: PathBuf::from("/e")
            }
            .to_string(),
            "DirList /e"
        );
        assert_eq!(
            ActionKind::NetConnect {
                host: "h".into(),
                port: 80
            }
            .to_string(),
            "NetConnect h:80"
        );
        assert_eq!(
            ActionKind::NetRequest {
                method: "POST".into(),
                url: "https://x".into()
            }
            .to_string(),
            "NetRequest POST https://x"
        );
        assert_eq!(
            ActionKind::ToolCall {
                tool: "sh".into(),
                args: serde_json::json!({})
            }
            .to_string(),
            "ToolCall sh"
        );
        assert_eq!(
            ActionKind::ProcessSpawn {
                command: "ls".into(),
                args: vec!["-l".into()]
            }
            .to_string(),
            "ProcessSpawn ls"
        );
        assert_eq!(
            ActionKind::ProcessExit {
                command: "ls".into(),
                exit_code: 1
            }
            .to_string(),
            "ProcessExit ls (code 1)"
        );
        assert_eq!(
            ActionKind::ApiUsage {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-5-20250929".into(),
                endpoint: "/v1/messages".into(),
                input_tokens: 100,
                output_tokens: 50,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            }
            .to_string(),
            "ApiUsage anthropic/claude-sonnet-4-5-20250929 in=100 out=50"
        );
        assert_eq!(
            ActionKind::SkillScan {
                path: PathBuf::from("/tmp/skill"),
                passed: false,
                warning_count: 2,
                error_count: 1,
            }
            .to_string(),
            "SkillScan /tmp/skill BLOCKED (warnings=2, errors=1)"
        );
        assert_eq!(
            ActionKind::MemoryCapture {
                agent_id: "agent-1".into(),
                category: "preference".into(),
                key: "editor".into(),
            }
            .to_string(),
            "MemoryCapture agent-1/preference:editor"
        );
    }
}
