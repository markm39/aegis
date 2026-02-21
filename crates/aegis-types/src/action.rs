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
    /// Establish a connection to an ACP (Agent Communication Protocol) server.
    AcpConnect {
        /// The endpoint URL being connected to (must be HTTPS).
        endpoint: String,
    },
    /// Send a message over an ACP connection.
    AcpSend {
        /// The endpoint URL the message is being sent to.
        endpoint: String,
        /// Size of the message payload in bytes.
        payload_size: usize,
    },
    /// Process an image received through a messaging channel.
    ImageProcess {
        /// SHA-256 hex digest of the raw image data (for audit trail).
        content_hash: String,
        /// Detected image format (e.g., "png", "jpeg").
        format: String,
        /// Size of the raw image data in bytes.
        size_bytes: u64,
    },
    /// OAuth2 token exchange (authorization code or refresh grant).
    OAuthExchange {
        /// Provider name (e.g., "google", "github").
        provider: String,
        /// OAuth2 grant type (e.g., "authorization_code", "refresh_token").
        grant_type: String,
    },
    /// Receive an incoming ACP message on the server side.
    ///
    /// Logged when the ACP server accepts and processes an inbound message
    /// from a remote agent. The source is the authenticated sender identity.
    AcpServerReceive {
        /// Authenticated sender identity (derived from the bearer token).
        source: String,
        /// ACP request method or message type.
        method: String,
        /// Size of the message payload in bytes.
        payload_size: usize,
    },
    /// Synthesize text to speech via an external TTS provider.
    TtsSynthesize {
        /// TTS provider name (e.g., "openai", "elevenlabs").
        provider: String,
        /// SHA-256 hex digest of the input text (raw text is never stored).
        text_hash: String,
        /// Voice ID used for synthesis.
        voice: String,
        /// Output audio format (e.g., "mp3", "wav", "ogg").
        format: String,
        /// Length of the input text in characters.
        text_length: usize,
    },
    /// Transcribe audio via OpenAI Whisper.
    TranscribeAudio {
        /// SHA-256 hex digest of the raw audio data (for audit trail).
        content_hash: String,
        /// Detected audio format (e.g., "mp3", "wav", "ogg").
        format: String,
        /// Size of the raw audio data in bytes.
        size_bytes: u64,
    },
    /// Process a video file with format detection and frame extraction.
    VideoProcess {
        /// SHA-256 hex digest of the raw video data (for audit trail).
        content_hash: String,
        /// Detected video format (e.g., "mp4", "webm", "avi", "mkv", "mov").
        format: String,
        /// Size of the raw video data in bytes.
        size_bytes: u64,
    },
    /// Translate an ACP message to/from a DaemonCommand.
    ///
    /// Logged when the ACP translator processes an inbound or outbound
    /// message. The method name is recorded but message content is never
    /// stored in the audit trail.
    AcpTranslate {
        /// ACP session identifier.
        session_id: String,
        /// ACP method being translated (e.g., "send", "status", "approve").
        method: String,
        /// Translation direction: "inbound" (ACP -> Daemon) or "outbound" (Daemon -> ACP).
        direction: String,
    },
    /// GitHub Copilot authentication via OAuth2 device flow.
    ///
    /// Gated by Cedar policy. Logged when a Copilot token is obtained
    /// or refreshed via the device flow or refresh grant.
    CopilotAuth {
        /// OAuth2 grant type (e.g., "device_code", "refresh_token").
        grant_type: String,
    },
    /// API call to Google AI Gemini, gated by Cedar policy.
    ///
    /// Logged when a request is made to the Gemini generateContent or
    /// streamGenerateContent endpoint. Token counts are extracted from
    /// the response usage metadata.
    GeminiApiCall {
        /// Gemini model name (e.g., "gemini-pro", "gemini-1.5-pro").
        model: String,
        /// Gemini API endpoint URL.
        endpoint: String,
        /// Input/prompt tokens consumed.
        input_tokens: u64,
        /// Output/completion tokens consumed.
        output_tokens: u64,
    },
    /// Process a file attachment through the attachment pipeline.
    ///
    /// Gated by Cedar policy. Logged when an attachment is received through
    /// a messaging channel and processed for content extraction or validation.
    /// MIME type is detected from magic bytes, never from file extensions.
    ProcessAttachment {
        /// SHA-256 hex digest of the raw attachment data (for audit trail).
        content_hash: String,
        /// Detected MIME type (e.g., "image/png", "audio/mpeg", "application/pdf").
        mime_type: String,
        /// Size of the raw attachment data in bytes.
        size_bytes: u64,
    },
    /// Create a new shared canvas session.
    ///
    /// Gated by Cedar policy. Logged when an agent creates a new canvas
    /// for collaborative state sharing.
    CanvasCreate {
        /// The canvas session UUID being created.
        canvas_id: String,
    },
    /// Update an existing shared canvas session.
    ///
    /// Gated by Cedar policy. Logged when an agent applies patches to
    /// a canvas session's state.
    CanvasUpdate {
        /// The canvas session UUID being updated.
        canvas_id: String,
    },
    /// Pair a new device with the daemon (pairing flow completion).
    ///
    /// Gated by Cedar policy. Logged when a device completes the pairing
    /// flow and is registered in the device registry. The device_id is the
    /// newly assigned identifier; the device name is sanitized before storage.
    DevicePair {
        /// Unique device identifier assigned during pairing.
        device_id: String,
        /// Sanitized device name.
        device_name: String,
        /// Device platform (e.g., "iOS", "Android", "macOS").
        platform: String,
    },
    /// Revoke a paired device, invalidating its authentication token.
    ///
    /// Gated by Cedar policy. Logged when a device's access is revoked.
    /// Revocation immediately clears the auth token hash, preventing any
    /// subsequent authentication attempts.
    DeviceRevoke {
        /// Device identifier being revoked.
        device_id: String,
    },
    /// Authenticate a device using its auth token.
    ///
    /// Gated by Cedar policy. Logged on each device authentication attempt.
    /// The token itself is never recorded; only the device_id is stored in
    /// the audit trail.
    DeviceAuth {
        /// Device identifier attempting authentication.
        device_id: String,
    },
    /// LLM completion request, gated by Cedar policy.
    ///
    /// Logged when a completion request is made through the provider
    /// abstraction layer. Token counts are extracted from the response.
    LlmComplete {
        /// Provider name (e.g., "anthropic", "openai", "google").
        provider: String,
        /// Model name (e.g., "claude-sonnet-4-20250514", "gpt-4o").
        model: String,
        /// API endpoint URL.
        endpoint: String,
        /// Input/prompt tokens consumed.
        input_tokens: u64,
        /// Output/completion tokens consumed.
        output_tokens: u64,
    },
    /// Render an A2UI (Agent-to-UI) component specification.
    ///
    /// Gated by Cedar policy. Logged when an agent submits a UiSpec
    /// for rendering. The spec_id uniquely identifies the specification
    /// being rendered; the component_count records how many components
    /// it contains for audit purposes.
    RenderA2UI {
        /// Unique identifier for the UiSpec being rendered.
        spec_id: String,
        /// Number of components in the specification.
        component_count: usize,
    },
    /// Generate a setup code with QR code for device pairing.
    ///
    /// Gated by Cedar policy. Logged when a setup code is generated for
    /// a new device pairing flow. The endpoint is the daemon URL encoded
    /// in the QR code.
    GenerateSetupCode {
        /// Daemon endpoint URL encoded in the setup code.
        endpoint: String,
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
            ActionKind::AcpConnect { endpoint } => {
                write!(f, "AcpConnect {endpoint}")
            }
            ActionKind::AcpSend {
                endpoint,
                payload_size,
            } => {
                write!(f, "AcpSend {endpoint} ({payload_size} bytes)")
            }
            ActionKind::ImageProcess {
                content_hash,
                format,
                size_bytes,
            } => {
                write!(f, "ImageProcess {format} ({size_bytes} bytes, hash={content_hash})")
            }
            ActionKind::OAuthExchange {
                provider,
                grant_type,
            } => {
                write!(f, "OAuthExchange {provider} ({grant_type})")
            }
            ActionKind::AcpServerReceive {
                source,
                method,
                payload_size,
            } => {
                write!(f, "AcpServerReceive {source} {method} ({payload_size} bytes)")
            }
            ActionKind::TtsSynthesize {
                provider,
                voice,
                format,
                text_length,
                ..
            } => {
                write!(f, "TtsSynthesize {provider}/{voice} {format} ({text_length} chars)")
            }
            ActionKind::TranscribeAudio {
                content_hash,
                format,
                size_bytes,
            } => {
                write!(f, "TranscribeAudio {format} ({size_bytes} bytes, hash={content_hash})")
            }
            ActionKind::VideoProcess {
                content_hash,
                format,
                size_bytes,
            } => {
                write!(f, "VideoProcess {format} ({size_bytes} bytes, hash={content_hash})")
            }
            ActionKind::AcpTranslate {
                session_id,
                method,
                direction,
            } => {
                write!(f, "AcpTranslate {direction} {method} (session={session_id})")
            }
            ActionKind::CopilotAuth { grant_type } => {
                write!(f, "CopilotAuth ({grant_type})")
            }
            ActionKind::GeminiApiCall {
                model,
                endpoint,
                input_tokens,
                output_tokens,
            } => {
                write!(
                    f,
                    "GeminiApiCall {model} {endpoint} in={input_tokens} out={output_tokens}"
                )
            }
            ActionKind::ProcessAttachment {
                content_hash,
                mime_type,
                size_bytes,
            } => {
                write!(f, "ProcessAttachment {mime_type} ({size_bytes} bytes, hash={content_hash})")
            }
            ActionKind::CanvasCreate { canvas_id } => {
                write!(f, "CanvasCreate {canvas_id}")
            }
            ActionKind::CanvasUpdate { canvas_id } => {
                write!(f, "CanvasUpdate {canvas_id}")
            }
            ActionKind::DevicePair {
                device_id,
                device_name,
                platform,
            } => {
                write!(f, "DevicePair {device_id} ({device_name}, {platform})")
            }
            ActionKind::DeviceRevoke { device_id } => {
                write!(f, "DeviceRevoke {device_id}")
            }
            ActionKind::DeviceAuth { device_id } => {
                write!(f, "DeviceAuth {device_id}")
            }
            ActionKind::LlmComplete {
                provider,
                model,
                endpoint,
                input_tokens,
                output_tokens,
            } => {
                write!(
                    f,
                    "LlmComplete {provider}/{model} {endpoint} in={input_tokens} out={output_tokens}"
                )
            }
            ActionKind::RenderA2UI {
                spec_id,
                component_count,
            } => {
                write!(f, "RenderA2UI {spec_id} ({component_count} components)")
            }
            ActionKind::GenerateSetupCode { endpoint } => {
                write!(f, "GenerateSetupCode {endpoint}")
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
            ActionKind::AcpConnect {
                endpoint: "https://acp.example.com".into(),
            },
            ActionKind::AcpSend {
                endpoint: "https://acp.example.com".into(),
                payload_size: 1024,
            },
            ActionKind::ImageProcess {
                content_hash: "abc123".into(),
                format: "png".into(),
                size_bytes: 2048,
            },
            ActionKind::OAuthExchange {
                provider: "google".into(),
                grant_type: "authorization_code".into(),
            },
            ActionKind::AcpServerReceive {
                source: "remote-agent".into(),
                method: "execute".into(),
                payload_size: 512,
            },
            ActionKind::TtsSynthesize {
                provider: "openai".into(),
                text_hash: "abc123".into(),
                voice: "alloy".into(),
                format: "mp3".into(),
                text_length: 42,
            },
            ActionKind::VideoProcess {
                content_hash: "deadbeef".into(),
                format: "mp4".into(),
                size_bytes: 4096,
            },
            ActionKind::CopilotAuth {
                grant_type: "device_code".into(),
            },
            ActionKind::GeminiApiCall {
                model: "gemini-pro".into(),
                endpoint: "https://generativelanguage.googleapis.com".into(),
                input_tokens: 100,
                output_tokens: 50,
            },
            ActionKind::ProcessAttachment {
                content_hash: "abc123".into(),
                mime_type: "image/png".into(),
                size_bytes: 2048,
            },
            ActionKind::CanvasCreate {
                canvas_id: "00000000-0000-0000-0000-000000000001".into(),
            },
            ActionKind::CanvasUpdate {
                canvas_id: "00000000-0000-0000-0000-000000000002".into(),
            },
            ActionKind::DevicePair {
                device_id: "d1234567-abcd-1234-abcd-1234567890ab".into(),
                device_name: "Test Phone".into(),
                platform: "iOS".into(),
            },
            ActionKind::DeviceRevoke {
                device_id: "d1234567-abcd-1234-abcd-1234567890ab".into(),
            },
            ActionKind::DeviceAuth {
                device_id: "d1234567-abcd-1234-abcd-1234567890ab".into(),
            },
            ActionKind::LlmComplete {
                provider: "anthropic".into(),
                model: "claude-sonnet-4-20250514".into(),
                endpoint: "https://api.anthropic.com".into(),
                input_tokens: 100,
                output_tokens: 50,
            },
            ActionKind::RenderA2UI {
                spec_id: "00000000-0000-0000-0000-000000000003".into(),
                component_count: 5,
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
        assert_eq!(
            ActionKind::AcpConnect {
                endpoint: "https://acp.example.com".into(),
            }
            .to_string(),
            "AcpConnect https://acp.example.com"
        );
        assert_eq!(
            ActionKind::AcpSend {
                endpoint: "https://acp.example.com".into(),
                payload_size: 512,
            }
            .to_string(),
            "AcpSend https://acp.example.com (512 bytes)"
        );
    }
}
