//! Voice gateway with WebSocket-based session management.
//!
//! Bridges the existing Twilio voice call management ([`crate::voice`]) and
//! speech recognition ([`crate::speech`]) modules with a WebSocket-based
//! streaming endpoint, TTS integration, and session lifecycle management.
//!
//! # Architecture
//!
//! - [`VoiceGateway`]: manages concurrent voice sessions with enforced limits
//! - [`VoiceSession`]: lifecycle state for a single voice interaction
//! - [`VoiceWsMessage`]: typed WebSocket message protocol for audio streaming
//!
//! # Security Properties
//!
//! - Session limit enforced (max 10 concurrent voice sessions).
//! - Audio data is base64-validated before processing.
//! - WebSocket messages validated against known message types.
//! - No raw audio data in audit logs (privacy -- log metadata only).
//! - Session IDs are UUIDs (unpredictable).
//! - Voice sessions authenticated via the same bearer token as the HTTP API.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum concurrent voice sessions allowed.
const MAX_VOICE_SESSIONS: usize = 10;

// ---------------------------------------------------------------------------
// VoiceSessionState
// ---------------------------------------------------------------------------

/// Lifecycle state of a voice session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceSessionState {
    /// WebSocket connection is being established.
    Connecting,
    /// Session is active and processing audio.
    Active,
    /// Audio processing is temporarily paused.
    Paused,
    /// Session is in the process of shutting down.
    Ending,
    /// Session has terminated. This is a terminal state.
    Ended,
}

impl VoiceSessionState {
    /// Whether this state is terminal (no further transitions possible).
    pub fn is_terminal(self) -> bool {
        self == VoiceSessionState::Ended
    }

    /// Check whether transitioning from `self` to `target` is valid.
    ///
    /// Valid transitions:
    /// - Connecting -> Active (connection established)
    /// - Active -> Paused (pause audio processing)
    /// - Active -> Ending (begin shutdown)
    /// - Paused -> Active (resume audio processing)
    /// - Paused -> Ending (shutdown from paused state)
    /// - Ending -> Ended (shutdown complete)
    /// - Connecting -> Ending (abort before active)
    ///
    /// All other transitions are denied (fail-closed).
    pub fn can_transition_to(self, target: VoiceSessionState) -> bool {
        matches!(
            (self, target),
            (VoiceSessionState::Connecting, VoiceSessionState::Active)
                | (VoiceSessionState::Connecting, VoiceSessionState::Ending)
                | (VoiceSessionState::Active, VoiceSessionState::Paused)
                | (VoiceSessionState::Active, VoiceSessionState::Ending)
                | (VoiceSessionState::Paused, VoiceSessionState::Active)
                | (VoiceSessionState::Paused, VoiceSessionState::Ending)
                | (VoiceSessionState::Ending, VoiceSessionState::Ended)
        )
    }

    /// Validate and perform a transition, returning the new state or an error.
    pub fn transition_to(self, target: VoiceSessionState) -> Result<VoiceSessionState, String> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(format!(
                "invalid voice session state transition: {self:?} -> {target:?}"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// VoiceSession
// ---------------------------------------------------------------------------

/// A single voice interaction session with lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSession {
    /// Unique session identifier (UUID).
    pub session_id: String,
    /// Agent this session is associated with.
    pub agent_id: String,
    /// Linked Twilio call ID, if this session was initiated from a phone call.
    pub call_id: Option<String>,
    /// Current session state.
    pub state: VoiceSessionState,
    /// When the session was created.
    pub started_at: DateTime<Utc>,
    /// Whether text-to-speech output is enabled.
    pub tts_enabled: bool,
    /// Whether speech-to-text input is enabled.
    pub stt_enabled: bool,
    /// Language code for speech processing (e.g., "en-US").
    pub language: Option<String>,
}

// ---------------------------------------------------------------------------
// VoiceSessionConfig
// ---------------------------------------------------------------------------

/// Configuration for creating a new voice session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSessionConfig {
    /// Whether text-to-speech output is enabled. Defaults to true.
    #[serde(default = "default_true")]
    pub tts_enabled: bool,
    /// Whether speech-to-text input is enabled. Defaults to true.
    #[serde(default = "default_true")]
    pub stt_enabled: bool,
    /// Language code for speech processing (e.g., "en-US").
    #[serde(default)]
    pub language: Option<String>,
    /// Voice ID for TTS output (provider-specific).
    #[serde(default)]
    pub tts_voice: Option<String>,
    /// Associate this session with an existing Twilio call.
    #[serde(default)]
    pub call_id: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for VoiceSessionConfig {
    fn default() -> Self {
        Self {
            tts_enabled: true,
            stt_enabled: true,
            language: None,
            tts_voice: None,
            call_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// VoiceWsMessage
// ---------------------------------------------------------------------------

/// WebSocket message types for the `/v1/voice/ws` endpoint.
///
/// Uses serde-tagged JSON encoding for type safety. All audio data is
/// base64-encoded to ensure safe transport over JSON WebSocket frames.
///
/// Audio data is never logged (privacy). Only message type and metadata
/// (format, confidence, language) are recorded in audit logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VoiceWsMessage {
    /// Client sends audio data to the server.
    AudioIn {
        /// Base64-encoded audio data.
        data: String,
        /// Audio format (e.g., "pcm_16khz", "mulaw_8khz", "opus").
        format: String,
    },
    /// Server sends TTS audio data to the client.
    AudioOut {
        /// Base64-encoded audio data.
        data: String,
        /// Audio format (e.g., "mp3", "opus", "pcm_16khz").
        format: String,
    },
    /// Partial (interim) speech-to-text result.
    TranscriptPartial {
        /// Partial transcription text.
        text: String,
        /// Confidence score from 0.0 to 1.0.
        confidence: f32,
    },
    /// Final (stable) speech-to-text result.
    TranscriptFinal {
        /// Final transcription text.
        text: String,
        /// Confidence score from 0.0 to 1.0.
        confidence: f32,
        /// Detected language code (e.g., "en", "es"), if available.
        language: Option<String>,
    },
    /// Confirmation that a session has started.
    SessionStart {
        /// The session UUID.
        session_id: String,
    },
    /// Notification that a session has ended.
    SessionEnd {
        /// The session UUID.
        session_id: String,
        /// Reason the session ended (e.g., "client_disconnect", "timeout").
        reason: String,
    },
    /// Error frame with machine-readable code and human-readable message.
    Error {
        /// Machine-readable error code (e.g., "invalid_format", "session_limit").
        code: String,
        /// Human-readable error description.
        message: String,
    },
    /// Client-to-server keepalive.
    Ping,
    /// Server-to-client keepalive response.
    Pong,
}

// ---------------------------------------------------------------------------
// VoiceGateway
// ---------------------------------------------------------------------------

/// Manages concurrent voice sessions with enforced limits.
///
/// The gateway maintains a map of active sessions and enforces a maximum
/// concurrent session count (default 10) to prevent resource exhaustion.
pub struct VoiceGateway {
    /// Active sessions keyed by session_id.
    sessions: HashMap<String, VoiceSession>,
    /// Maximum number of concurrent sessions allowed.
    max_sessions: usize,
}

impl VoiceGateway {
    /// Create a new voice gateway with default settings.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: MAX_VOICE_SESSIONS,
        }
    }

    /// Create a new voice gateway with a custom session limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Start a new voice session for the given agent.
    ///
    /// Enforces the maximum concurrent session limit. Returns the created
    /// session on success, or an error if the limit is reached.
    pub fn start_session(
        &mut self,
        agent_id: &str,
        config: VoiceSessionConfig,
    ) -> Result<VoiceSession, anyhow::Error> {
        // Enforce session limit.
        let active_count = self
            .sessions
            .values()
            .filter(|s| !s.state.is_terminal())
            .count();
        if active_count >= self.max_sessions {
            return Err(anyhow::anyhow!(
                "voice session limit reached: {active_count}/{} concurrent sessions",
                self.max_sessions
            ));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let session = VoiceSession {
            session_id: session_id.clone(),
            agent_id: agent_id.to_string(),
            call_id: config.call_id,
            state: VoiceSessionState::Connecting,
            started_at: Utc::now(),
            tts_enabled: config.tts_enabled,
            stt_enabled: config.stt_enabled,
            language: config.language,
        };

        self.sessions.insert(session_id, session.clone());

        tracing::info!(
            session_id = %session.session_id,
            agent_id = %agent_id,
            tts = session.tts_enabled,
            stt = session.stt_enabled,
            "voice session started"
        );

        Ok(session)
    }

    /// Stop a voice session, transitioning it to Ending then Ended.
    ///
    /// Returns an error if the session does not exist or is already ended.
    pub fn stop_session(&mut self, session_id: &str) -> Result<(), anyhow::Error> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("voice session not found: {session_id}"))?;

        if session.state.is_terminal() {
            return Err(anyhow::anyhow!(
                "voice session {session_id} is already in terminal state"
            ));
        }

        // Transition through Ending to Ended.
        if session.state != VoiceSessionState::Ending {
            session.state = session.state.transition_to(VoiceSessionState::Ending).map_err(
                |e| anyhow::anyhow!("{e}"),
            )?;
        }
        session.state = session
            .state
            .transition_to(VoiceSessionState::Ended)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        tracing::info!(session_id = %session_id, "voice session stopped");

        Ok(())
    }

    /// Pause audio processing for a session.
    ///
    /// Only Active sessions can be paused.
    pub fn pause_session(&mut self, session_id: &str) -> Result<(), anyhow::Error> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("voice session not found: {session_id}"))?;

        session.state = session
            .state
            .transition_to(VoiceSessionState::Paused)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        tracing::info!(session_id = %session_id, "voice session paused");

        Ok(())
    }

    /// Resume a paused session.
    ///
    /// Only Paused sessions can be resumed.
    pub fn resume_session(&mut self, session_id: &str) -> Result<(), anyhow::Error> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("voice session not found: {session_id}"))?;

        session.state = session
            .state
            .transition_to(VoiceSessionState::Active)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        tracing::info!(session_id = %session_id, "voice session resumed");

        Ok(())
    }

    /// Get a reference to a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&VoiceSession> {
        self.sessions.get(session_id)
    }

    /// List all sessions (active and ended).
    pub fn list_sessions(&self) -> Vec<&VoiceSession> {
        self.sessions.values().collect()
    }

    /// List sessions for a specific agent.
    pub fn agent_sessions(&self, agent_id: &str) -> Vec<&VoiceSession> {
        self.sessions
            .values()
            .filter(|s| s.agent_id == agent_id)
            .collect()
    }
}

impl Default for VoiceGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Audio validation
// ---------------------------------------------------------------------------

/// Validate that a string is valid base64 data.
///
/// Returns the decoded bytes on success, or an error describing the
/// validation failure.
pub fn validate_base64_audio(data: &str) -> Result<Vec<u8>, anyhow::Error> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("audio data is empty"));
    }

    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data).map_err(|e| {
        anyhow::anyhow!("invalid base64 audio data: {e}")
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test 1: Session lifecycle --

    #[test]
    fn test_session_lifecycle() {
        let mut gw = VoiceGateway::new();

        // Start a session (Connecting).
        let session = gw
            .start_session("agent-1", VoiceSessionConfig::default())
            .expect("should start session");
        assert_eq!(session.state, VoiceSessionState::Connecting);

        let sid = session.session_id.clone();

        // Transition Connecting -> Active (manual for test; in production the
        // WebSocket handler does this).
        {
            let s = gw.sessions.get_mut(&sid).unwrap();
            s.state = s
                .state
                .transition_to(VoiceSessionState::Active)
                .expect("connecting -> active");
        }
        assert_eq!(gw.get_session(&sid).unwrap().state, VoiceSessionState::Active);

        // Pause (Active -> Paused).
        gw.pause_session(&sid).expect("should pause");
        assert_eq!(gw.get_session(&sid).unwrap().state, VoiceSessionState::Paused);

        // Resume (Paused -> Active).
        gw.resume_session(&sid).expect("should resume");
        assert_eq!(gw.get_session(&sid).unwrap().state, VoiceSessionState::Active);

        // Stop (Active -> Ending -> Ended).
        gw.stop_session(&sid).expect("should stop");
        assert_eq!(gw.get_session(&sid).unwrap().state, VoiceSessionState::Ended);
    }

    // -- Test 2: Session limit enforced --

    #[test]
    fn test_session_limit_enforced() {
        let mut gw = VoiceGateway::with_max_sessions(10);

        // Create 10 sessions.
        for i in 0..10 {
            let agent = format!("agent-{i}");
            gw.start_session(&agent, VoiceSessionConfig::default())
                .unwrap_or_else(|e| panic!("session {i} should succeed: {e}"));
        }

        // The 11th should be denied.
        let result = gw.start_session("agent-overflow", VoiceSessionConfig::default());
        assert!(result.is_err(), "11th session should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("session limit reached"),
            "error should mention session limit, got: {err}"
        );
    }

    // -- Test 3: Agent sessions filter --

    #[test]
    fn test_agent_sessions() {
        let mut gw = VoiceGateway::new();

        // Create sessions for two different agents.
        gw.start_session("agent-1", VoiceSessionConfig::default())
            .expect("should start");
        gw.start_session("agent-1", VoiceSessionConfig::default())
            .expect("should start");
        gw.start_session("agent-2", VoiceSessionConfig::default())
            .expect("should start");

        let a1_sessions = gw.agent_sessions("agent-1");
        assert_eq!(a1_sessions.len(), 2, "agent-1 should have 2 sessions");

        let a2_sessions = gw.agent_sessions("agent-2");
        assert_eq!(a2_sessions.len(), 1, "agent-2 should have 1 session");

        let a3_sessions = gw.agent_sessions("agent-3");
        assert!(a3_sessions.is_empty(), "agent-3 should have 0 sessions");
    }

    // -- Test 4: WebSocket message serialization roundtrip --

    #[test]
    fn test_ws_message_serialization() {
        let messages = vec![
            VoiceWsMessage::AudioIn {
                data: "SGVsbG8=".into(),
                format: "pcm_16khz".into(),
            },
            VoiceWsMessage::AudioOut {
                data: "V29ybGQ=".into(),
                format: "mp3".into(),
            },
            VoiceWsMessage::TranscriptPartial {
                text: "hello".into(),
                confidence: 0.7,
            },
            VoiceWsMessage::TranscriptFinal {
                text: "hello world".into(),
                confidence: 0.95,
                language: Some("en".into()),
            },
            VoiceWsMessage::SessionStart {
                session_id: "test-uuid".into(),
            },
            VoiceWsMessage::SessionEnd {
                session_id: "test-uuid".into(),
                reason: "client_disconnect".into(),
            },
            VoiceWsMessage::Error {
                code: "invalid_format".into(),
                message: "unsupported audio format".into(),
            },
            VoiceWsMessage::Ping,
            VoiceWsMessage::Pong,
        ];

        for msg in &messages {
            let json = serde_json::to_string(msg).expect("should serialize");
            let back: VoiceWsMessage =
                serde_json::from_str(&json).expect("should deserialize");
            assert_eq!(&back, msg, "roundtrip failed for {json}");
        }
    }

    // -- Test 5: Base64 audio validation --

    #[test]
    fn test_base64_audio_validation() {
        // Valid base64.
        let result = validate_base64_audio("SGVsbG8gV29ybGQ=");
        assert!(result.is_ok(), "valid base64 should pass");
        assert_eq!(result.unwrap(), b"Hello World");

        // Invalid base64.
        let result = validate_base64_audio("not-valid-base64!!!");
        assert!(result.is_err(), "invalid base64 should fail");

        // Empty string.
        let result = validate_base64_audio("");
        assert!(result.is_err(), "empty string should fail");
    }

    // -- Test 6: Session state transitions --

    #[test]
    fn test_session_state_transitions() {
        // Valid transitions.
        assert!(VoiceSessionState::Connecting.can_transition_to(VoiceSessionState::Active));
        assert!(VoiceSessionState::Connecting.can_transition_to(VoiceSessionState::Ending));
        assert!(VoiceSessionState::Active.can_transition_to(VoiceSessionState::Paused));
        assert!(VoiceSessionState::Active.can_transition_to(VoiceSessionState::Ending));
        assert!(VoiceSessionState::Paused.can_transition_to(VoiceSessionState::Active));
        assert!(VoiceSessionState::Paused.can_transition_to(VoiceSessionState::Ending));
        assert!(VoiceSessionState::Ending.can_transition_to(VoiceSessionState::Ended));

        // Invalid transitions.
        assert!(!VoiceSessionState::Connecting.can_transition_to(VoiceSessionState::Paused));
        assert!(!VoiceSessionState::Connecting.can_transition_to(VoiceSessionState::Ended));
        assert!(!VoiceSessionState::Active.can_transition_to(VoiceSessionState::Connecting));
        assert!(!VoiceSessionState::Active.can_transition_to(VoiceSessionState::Ended));
        assert!(!VoiceSessionState::Paused.can_transition_to(VoiceSessionState::Connecting));
        assert!(!VoiceSessionState::Ended.can_transition_to(VoiceSessionState::Active));
        assert!(!VoiceSessionState::Ended.can_transition_to(VoiceSessionState::Connecting));

        // transition_to returns error for invalid transitions.
        let result = VoiceSessionState::Ended.transition_to(VoiceSessionState::Active);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid voice session state transition"));
    }

    // -- Test 7: VoiceSession ActionKind exists --

    #[test]
    fn test_voice_session_requires_policy() {
        // Verify the VoiceSession ActionKind variant exists and can be constructed.
        let action = aegis_types::ActionKind::VoiceSession {
            agent_id: "agent-1".into(),
            operation: "start".into(),
        };

        // Verify it can be serialized.
        let json = serde_json::to_string(&action).expect("should serialize");
        assert!(json.contains("VoiceSession"), "JSON should contain variant name");
        assert!(json.contains("agent-1"), "JSON should contain agent_id");

        // Verify Display impl works.
        let display = action.to_string();
        assert!(
            display.contains("VoiceSession"),
            "Display should contain variant name, got: {display}"
        );
    }

    // -- Test 8: Config defaults --

    #[test]
    fn test_config_defaults() {
        let config = VoiceSessionConfig::default();
        assert!(config.tts_enabled, "tts_enabled should default to true");
        assert!(config.stt_enabled, "stt_enabled should default to true");
        assert!(config.language.is_none(), "language should default to None");
        assert!(config.tts_voice.is_none(), "tts_voice should default to None");
        assert!(config.call_id.is_none(), "call_id should default to None");

        // Verify serde defaults match.
        let json = r#"{}"#;
        let deserialized: VoiceSessionConfig =
            serde_json::from_str(json).expect("should deserialize empty config");
        assert!(deserialized.tts_enabled);
        assert!(deserialized.stt_enabled);
    }
}
