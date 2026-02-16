use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionKind {
    FileRead { path: PathBuf },
    FileWrite { path: PathBuf },
    FileDelete { path: PathBuf },
    DirCreate { path: PathBuf },
    DirList { path: PathBuf },
    NetConnect { host: String, port: u16 },
    NetRequest { method: String, url: String },
    ToolCall { tool: String, args: serde_json::Value },
    ProcessSpawn { command: String, args: Vec<String> },
    ProcessExit { command: String, exit_code: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub principal: String,
    pub kind: ActionKind,
}

impl Action {
    pub fn new(principal: impl Into<String>, kind: ActionKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            principal: principal.into(),
            kind,
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
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ActionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }
}
