//! Discord voice channel framework for agent-to-agent and agent-to-human audio.
//!
//! Provides the structural framework for managing voice channel state,
//! join/leave/mute/unmute operations, audio stream types, and voice activity
//! detection tracking. Actual audio codec processing (Opus encode/decode,
//! mixing, noise suppression) is delegated to `aegis-voice`.
//!
//! # Architecture
//!
//! - [`VoiceChannelConfig`]: connection parameters (guild, channel, token).
//! - [`VoiceChannelState`]: tracks participants, mute states, and activity.
//! - [`VoiceSession`]: manages join/leave lifecycle for a single connection.
//! - [`OpusFrame`] / [`AudioStream`]: typed wrappers for audio data flow.
//! - [`VoiceActivityEvent`]: voice activity detection (VAD) tracking.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::debug;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum participants allowed in a single voice channel.
const MAX_PARTICIPANTS: usize = 100;

/// Maximum length for a channel or guild ID.
const MAX_ID_LEN: usize = 64;

/// Maximum length for a participant display name.
const MAX_DISPLAY_NAME_LEN: usize = 128;

/// Default VAD silence threshold before marking a participant as not speaking.
const DEFAULT_VAD_SILENCE_TIMEOUT: Duration = Duration::from_millis(300);

/// Maximum Opus frame size in bytes (120ms at 510kbps stereo, rounded up).
const MAX_OPUS_FRAME_SIZE: usize = 7680;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for connecting to a Discord voice channel.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceChannelConfig {
    /// Discord guild (server) ID.
    pub guild_id: String,
    /// Discord voice channel ID.
    pub channel_id: String,
    /// Bot token for authentication.
    pub bot_token: String,
    /// Whether to self-deafen on join (don't receive audio).
    pub self_deaf: bool,
    /// Whether to self-mute on join.
    pub self_mute: bool,
}

impl std::fmt::Debug for VoiceChannelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceChannelConfig")
            .field("guild_id", &self.guild_id)
            .field("channel_id", &self.channel_id)
            .field("bot_token", &"[REDACTED]")
            .field("self_deaf", &self.self_deaf)
            .field("self_mute", &self.self_mute)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from voice channel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceError {
    /// The session is not currently connected.
    NotConnected,
    /// Already connected to a voice channel.
    AlreadyConnected,
    /// The participant is not in the channel.
    ParticipantNotFound { user_id: String },
    /// The participant is already in the channel.
    ParticipantAlreadyPresent { user_id: String },
    /// Too many participants in the channel.
    TooManyParticipants { limit: usize },
    /// Invalid ID format.
    InvalidId { value: String, reason: String },
    /// Invalid audio frame.
    InvalidFrame { reason: String },
}

impl std::fmt::Display for VoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "not connected to a voice channel"),
            Self::AlreadyConnected => write!(f, "already connected to a voice channel"),
            Self::ParticipantNotFound { user_id } => {
                write!(f, "participant {user_id:?} not found in channel")
            }
            Self::ParticipantAlreadyPresent { user_id } => {
                write!(f, "participant {user_id:?} already in channel")
            }
            Self::TooManyParticipants { limit } => {
                write!(f, "voice channel participant limit of {limit} exceeded")
            }
            Self::InvalidId { value, reason } => {
                write!(f, "invalid ID {value:?}: {reason}")
            }
            Self::InvalidFrame { reason } => {
                write!(f, "invalid audio frame: {reason}")
            }
        }
    }
}

impl std::error::Error for VoiceError {}

// ---------------------------------------------------------------------------
// Audio types
// ---------------------------------------------------------------------------

/// A single Opus-encoded audio frame.
///
/// Carries encoded audio data for one frame interval (typically 20ms).
/// Validation ensures frames are within the maximum size for Opus encoding.
#[derive(Debug, Clone)]
pub struct OpusFrame {
    /// Opus-encoded audio bytes.
    data: Vec<u8>,
    /// Frame duration in milliseconds (typically 20ms).
    duration_ms: u16,
    /// Sequence number for ordering.
    sequence: u32,
    /// RTP timestamp.
    timestamp: u32,
}

impl OpusFrame {
    /// Create a new Opus frame with validation.
    pub fn new(
        data: Vec<u8>,
        duration_ms: u16,
        sequence: u32,
        timestamp: u32,
    ) -> Result<Self, VoiceError> {
        if data.is_empty() {
            return Err(VoiceError::InvalidFrame {
                reason: "frame data is empty".to_string(),
            });
        }
        if data.len() > MAX_OPUS_FRAME_SIZE {
            return Err(VoiceError::InvalidFrame {
                reason: format!(
                    "frame size {} exceeds maximum {}",
                    data.len(),
                    MAX_OPUS_FRAME_SIZE
                ),
            });
        }
        if duration_ms == 0 || duration_ms > 120 {
            return Err(VoiceError::InvalidFrame {
                reason: format!("duration {duration_ms}ms out of range (1-120)"),
            });
        }
        Ok(Self {
            data,
            duration_ms,
            sequence,
            timestamp,
        })
    }

    /// The encoded audio bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Frame duration in milliseconds.
    pub fn duration_ms(&self) -> u16 {
        self.duration_ms
    }

    /// Sequence number.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// RTP timestamp.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

/// Direction of an audio stream (send or receive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Outbound audio (we are sending).
    Send,
    /// Inbound audio (we are receiving from a participant).
    Receive,
}

/// An audio stream associated with a participant.
///
/// Wraps a sequence of [`OpusFrame`]s with metadata about the stream source.
#[derive(Debug)]
pub struct AudioStream {
    /// User ID of the stream source.
    user_id: String,
    /// Stream direction.
    direction: StreamDirection,
    /// SSRC (Synchronization Source) identifier for the RTP stream.
    ssrc: u32,
    /// Buffered frames awaiting processing.
    buffer: Vec<OpusFrame>,
    /// Maximum buffer capacity (frames).
    buffer_capacity: usize,
}

impl AudioStream {
    /// Create a new audio stream.
    pub fn new(user_id: impl Into<String>, direction: StreamDirection, ssrc: u32) -> Self {
        Self {
            user_id: user_id.into(),
            direction,
            ssrc,
            buffer: Vec::new(),
            buffer_capacity: 50, // ~1 second at 20ms frames
        }
    }

    /// Push a frame into the buffer.
    ///
    /// If the buffer is full, the oldest frame is dropped.
    pub fn push_frame(&mut self, frame: OpusFrame) {
        if self.buffer.len() >= self.buffer_capacity {
            self.buffer.remove(0);
        }
        self.buffer.push(frame);
    }

    /// Drain all buffered frames.
    pub fn drain_frames(&mut self) -> Vec<OpusFrame> {
        std::mem::take(&mut self.buffer)
    }

    /// Number of buffered frames.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// The user ID associated with this stream.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The stream direction.
    pub fn direction(&self) -> StreamDirection {
        self.direction
    }

    /// The SSRC identifier.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }
}

// ---------------------------------------------------------------------------
// Voice Activity Detection
// ---------------------------------------------------------------------------

/// A voice activity detection event.
#[derive(Debug, Clone)]
pub struct VoiceActivityEvent {
    /// User ID of the speaker.
    pub user_id: String,
    /// Whether the user is currently speaking.
    pub speaking: bool,
    /// When this event was recorded.
    pub timestamp: Instant,
}

/// Tracks voice activity per participant.
#[derive(Debug)]
pub struct VoiceActivityTracker {
    /// Per-user last speaking timestamp.
    last_activity: HashMap<String, Instant>,
    /// Silence timeout before marking user as not speaking.
    silence_timeout: Duration,
}

impl VoiceActivityTracker {
    /// Create a new tracker with default silence timeout.
    pub fn new() -> Self {
        Self {
            last_activity: HashMap::new(),
            silence_timeout: DEFAULT_VAD_SILENCE_TIMEOUT,
        }
    }

    /// Create a tracker with a custom silence timeout.
    pub fn with_timeout(silence_timeout: Duration) -> Self {
        Self {
            last_activity: HashMap::new(),
            silence_timeout,
        }
    }

    /// Record voice activity from a user.
    pub fn record_activity(&mut self, user_id: &str) {
        self.last_activity
            .insert(user_id.to_string(), Instant::now());
    }

    /// Check if a user is currently speaking (has recent activity).
    pub fn is_speaking(&self, user_id: &str) -> bool {
        self.last_activity
            .get(user_id)
            .map(|last| last.elapsed() < self.silence_timeout)
            .unwrap_or(false)
    }

    /// Get all currently speaking users.
    pub fn speaking_users(&self) -> Vec<&str> {
        self.last_activity
            .iter()
            .filter(|(_, last)| last.elapsed() < self.silence_timeout)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Remove a user from tracking (e.g., when they leave the channel).
    pub fn remove_user(&mut self, user_id: &str) {
        self.last_activity.remove(user_id);
    }

    /// Clear all tracking data.
    pub fn clear(&mut self) {
        self.last_activity.clear();
    }
}

impl Default for VoiceActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Participant state
// ---------------------------------------------------------------------------

/// Mute/deafen state for a voice participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParticipantAudioState {
    /// Whether the participant is muted (not sending audio).
    pub muted: bool,
    /// Whether the participant is deafened (not receiving audio).
    pub deafened: bool,
    /// Whether the server has muted this participant.
    pub server_muted: bool,
    /// Whether the server has deafened this participant.
    pub server_deafened: bool,
}

impl ParticipantAudioState {
    /// Whether the participant can send audio (not muted or server-muted).
    pub fn can_send(&self) -> bool {
        !self.muted && !self.server_muted
    }

    /// Whether the participant can receive audio (not deafened or server-deafened).
    pub fn can_receive(&self) -> bool {
        !self.deafened && !self.server_deafened
    }
}

/// A participant in a voice channel.
#[derive(Debug, Clone)]
pub struct VoiceParticipant {
    /// Discord user ID.
    pub user_id: String,
    /// Display name.
    pub display_name: String,
    /// Audio mute/deafen state.
    pub audio_state: ParticipantAudioState,
    /// When the participant joined.
    pub joined_at: Instant,
}

// ---------------------------------------------------------------------------
// Voice channel state
// ---------------------------------------------------------------------------

/// Validates a Discord-style ID string.
fn validate_id(value: &str, kind: &str) -> Result<(), VoiceError> {
    if value.is_empty() {
        return Err(VoiceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} cannot be empty"),
        });
    }
    if value.len() > MAX_ID_LEN {
        return Err(VoiceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} exceeds maximum length of {MAX_ID_LEN}"),
        });
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(VoiceError::InvalidId {
            value: value.to_string(),
            reason: format!("{kind} contains invalid characters"),
        });
    }
    Ok(())
}

/// The current state of a voice channel, tracking all participants.
#[derive(Debug)]
pub struct VoiceChannelState {
    /// The guild ID.
    guild_id: String,
    /// The channel ID.
    channel_id: String,
    /// Connected participants keyed by user ID.
    participants: HashMap<String, VoiceParticipant>,
    /// Voice activity tracker.
    vad: VoiceActivityTracker,
}

impl VoiceChannelState {
    /// Create a new voice channel state.
    pub fn new(guild_id: impl Into<String>, channel_id: impl Into<String>) -> Self {
        Self {
            guild_id: guild_id.into(),
            channel_id: channel_id.into(),
            participants: HashMap::new(),
            vad: VoiceActivityTracker::new(),
        }
    }

    /// The guild ID.
    pub fn guild_id(&self) -> &str {
        &self.guild_id
    }

    /// The channel ID.
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    /// Number of participants currently in the channel.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Get a participant by user ID.
    pub fn get_participant(&self, user_id: &str) -> Option<&VoiceParticipant> {
        self.participants.get(user_id)
    }

    /// List all participant user IDs.
    pub fn participant_ids(&self) -> Vec<&str> {
        self.participants.keys().map(|k| k.as_str()).collect()
    }

    /// Add a participant to the channel.
    pub fn add_participant(
        &mut self,
        user_id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<(), VoiceError> {
        let user_id = user_id.into();
        let display_name = display_name.into();

        validate_id(&user_id, "user_id")?;

        if display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(VoiceError::InvalidId {
                value: display_name,
                reason: format!("display name exceeds maximum length of {MAX_DISPLAY_NAME_LEN}"),
            });
        }

        if self.participants.contains_key(&user_id) {
            return Err(VoiceError::ParticipantAlreadyPresent {
                user_id: user_id.clone(),
            });
        }

        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err(VoiceError::TooManyParticipants {
                limit: MAX_PARTICIPANTS,
            });
        }

        debug!(user_id = %user_id, channel = %self.channel_id, "participant joined voice channel");

        self.participants.insert(
            user_id.clone(),
            VoiceParticipant {
                user_id,
                display_name,
                audio_state: ParticipantAudioState::default(),
                joined_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Remove a participant from the channel.
    pub fn remove_participant(&mut self, user_id: &str) -> Result<VoiceParticipant, VoiceError> {
        self.vad.remove_user(user_id);
        self.participants
            .remove(user_id)
            .ok_or_else(|| VoiceError::ParticipantNotFound {
                user_id: user_id.to_string(),
            })
    }

    /// Set the mute state for a participant.
    pub fn set_muted(&mut self, user_id: &str, muted: bool) -> Result<(), VoiceError> {
        let p =
            self.participants
                .get_mut(user_id)
                .ok_or_else(|| VoiceError::ParticipantNotFound {
                    user_id: user_id.to_string(),
                })?;
        p.audio_state.muted = muted;
        debug!(user_id = %user_id, muted, "participant mute state changed");
        Ok(())
    }

    /// Set the deafen state for a participant.
    pub fn set_deafened(&mut self, user_id: &str, deafened: bool) -> Result<(), VoiceError> {
        let p =
            self.participants
                .get_mut(user_id)
                .ok_or_else(|| VoiceError::ParticipantNotFound {
                    user_id: user_id.to_string(),
                })?;
        p.audio_state.deafened = deafened;
        // Deafening also mutes by convention
        if deafened {
            p.audio_state.muted = true;
        }
        debug!(user_id = %user_id, deafened, "participant deafen state changed");
        Ok(())
    }

    /// Record voice activity from a participant.
    pub fn record_voice_activity(&mut self, user_id: &str) -> Result<(), VoiceError> {
        if !self.participants.contains_key(user_id) {
            return Err(VoiceError::ParticipantNotFound {
                user_id: user_id.to_string(),
            });
        }
        self.vad.record_activity(user_id);
        Ok(())
    }

    /// Check if a participant is currently speaking.
    pub fn is_speaking(&self, user_id: &str) -> bool {
        self.vad.is_speaking(user_id)
    }

    /// Get all currently speaking participants.
    pub fn speaking_participants(&self) -> Vec<&str> {
        self.vad.speaking_users()
    }

    /// Get a mutable reference to the VAD tracker.
    pub fn vad_tracker_mut(&mut self) -> &mut VoiceActivityTracker {
        &mut self.vad
    }
}

// ---------------------------------------------------------------------------
// Voice session
// ---------------------------------------------------------------------------

/// Connection status for a voice session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Not connected.
    Disconnected,
    /// Connecting (handshaking).
    Connecting,
    /// Connected and ready.
    Connected,
    /// Reconnecting after a drop.
    Reconnecting,
}

/// A voice session managing the connection lifecycle to a single channel.
///
/// This is the top-level struct that coordinates joining, leaving,
/// mute/unmute, and delegates audio processing to external codecs.
#[derive(Debug)]
pub struct VoiceSession {
    /// Channel configuration.
    config: VoiceChannelConfig,
    /// Current connection status.
    status: ConnectionStatus,
    /// Channel state (populated after connecting).
    state: Option<VoiceChannelState>,
}

impl VoiceSession {
    /// Create a new voice session (not yet connected).
    pub fn new(config: VoiceChannelConfig) -> Self {
        Self {
            config,
            status: ConnectionStatus::Disconnected,
            state: None,
        }
    }

    /// Current connection status.
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// The channel configuration.
    pub fn config(&self) -> &VoiceChannelConfig {
        &self.config
    }

    /// Get the channel state (available only when connected).
    pub fn state(&self) -> Option<&VoiceChannelState> {
        self.state.as_ref()
    }

    /// Get mutable access to the channel state.
    pub fn state_mut(&mut self) -> Option<&mut VoiceChannelState> {
        self.state.as_mut()
    }

    /// Simulate joining the voice channel.
    ///
    /// In a real implementation this would perform the Discord Gateway
    /// voice state update and UDP connection. Here we transition the
    /// state machine and initialize the channel state.
    pub fn join(&mut self) -> Result<(), VoiceError> {
        if self.status == ConnectionStatus::Connected {
            return Err(VoiceError::AlreadyConnected);
        }

        debug!(
            guild = %self.config.guild_id,
            channel = %self.config.channel_id,
            "joining voice channel"
        );

        self.status = ConnectionStatus::Connected;
        self.state = Some(VoiceChannelState::new(
            &self.config.guild_id,
            &self.config.channel_id,
        ));
        Ok(())
    }

    /// Leave the voice channel.
    pub fn leave(&mut self) -> Result<(), VoiceError> {
        if self.status == ConnectionStatus::Disconnected {
            return Err(VoiceError::NotConnected);
        }

        debug!(
            guild = %self.config.guild_id,
            channel = %self.config.channel_id,
            "leaving voice channel"
        );

        self.status = ConnectionStatus::Disconnected;
        self.state = None;
        Ok(())
    }

    /// Mute the bot in this session.
    pub fn mute(&mut self) -> Result<(), VoiceError> {
        if self.status != ConnectionStatus::Connected {
            return Err(VoiceError::NotConnected);
        }
        debug!("self-muting in voice channel");
        Ok(())
    }

    /// Unmute the bot in this session.
    pub fn unmute(&mut self) -> Result<(), VoiceError> {
        if self.status != ConnectionStatus::Connected {
            return Err(VoiceError::NotConnected);
        }
        debug!("self-unmuting in voice channel");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> VoiceChannelConfig {
        VoiceChannelConfig {
            guild_id: "guild_123".to_string(),
            channel_id: "chan_456".to_string(),
            bot_token: "token_abc".to_string(),
            self_deaf: false,
            self_mute: false,
        }
    }

    // -- Config serialization --

    #[test]
    fn config_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: VoiceChannelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // -- OpusFrame --

    #[test]
    fn opus_frame_valid() {
        let frame = OpusFrame::new(vec![0xDE, 0xAD], 20, 1, 960).unwrap();
        assert_eq!(frame.data(), &[0xDE, 0xAD]);
        assert_eq!(frame.duration_ms(), 20);
        assert_eq!(frame.sequence(), 1);
        assert_eq!(frame.timestamp(), 960);
    }

    #[test]
    fn opus_frame_empty_data_rejected() {
        let result = OpusFrame::new(vec![], 20, 1, 960);
        assert!(matches!(result, Err(VoiceError::InvalidFrame { .. })));
    }

    #[test]
    fn opus_frame_too_large_rejected() {
        let big = vec![0u8; MAX_OPUS_FRAME_SIZE + 1];
        let result = OpusFrame::new(big, 20, 1, 960);
        assert!(matches!(result, Err(VoiceError::InvalidFrame { .. })));
    }

    #[test]
    fn opus_frame_zero_duration_rejected() {
        let result = OpusFrame::new(vec![1], 0, 1, 960);
        assert!(matches!(result, Err(VoiceError::InvalidFrame { .. })));
    }

    #[test]
    fn opus_frame_excessive_duration_rejected() {
        let result = OpusFrame::new(vec![1], 121, 1, 960);
        assert!(matches!(result, Err(VoiceError::InvalidFrame { .. })));
    }

    // -- AudioStream --

    #[test]
    fn audio_stream_buffer() {
        let mut stream = AudioStream::new("user_1", StreamDirection::Receive, 42);
        assert_eq!(stream.user_id(), "user_1");
        assert_eq!(stream.direction(), StreamDirection::Receive);
        assert_eq!(stream.ssrc(), 42);
        assert_eq!(stream.buffered_count(), 0);

        let frame = OpusFrame::new(vec![1, 2, 3], 20, 0, 0).unwrap();
        stream.push_frame(frame);
        assert_eq!(stream.buffered_count(), 1);

        let frames = stream.drain_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(stream.buffered_count(), 0);
    }

    #[test]
    fn audio_stream_buffer_overflow_drops_oldest() {
        let mut stream = AudioStream::new("user_1", StreamDirection::Send, 1);
        // Default capacity is 50
        for i in 0..60 {
            let frame = OpusFrame::new(vec![i as u8], 20, i, i * 960).unwrap();
            stream.push_frame(frame);
        }
        assert_eq!(stream.buffered_count(), 50);
        let frames = stream.drain_frames();
        // First frame should be sequence 10 (oldest 10 were dropped)
        assert_eq!(frames[0].sequence(), 10);
    }

    // -- VoiceActivityTracker --

    #[test]
    fn vad_tracker_basic() {
        let mut vad = VoiceActivityTracker::new();
        assert!(!vad.is_speaking("user_1"));
        assert!(vad.speaking_users().is_empty());

        vad.record_activity("user_1");
        assert!(vad.is_speaking("user_1"));
        assert_eq!(vad.speaking_users().len(), 1);
    }

    #[test]
    fn vad_tracker_remove_user() {
        let mut vad = VoiceActivityTracker::new();
        vad.record_activity("user_1");
        vad.remove_user("user_1");
        assert!(!vad.is_speaking("user_1"));
    }

    #[test]
    fn vad_tracker_clear() {
        let mut vad = VoiceActivityTracker::new();
        vad.record_activity("user_1");
        vad.record_activity("user_2");
        vad.clear();
        assert!(vad.speaking_users().is_empty());
    }

    #[test]
    fn vad_tracker_default() {
        let vad = VoiceActivityTracker::default();
        assert!(vad.speaking_users().is_empty());
    }

    // -- ParticipantAudioState --

    #[test]
    fn audio_state_default() {
        let state = ParticipantAudioState::default();
        assert!(!state.muted);
        assert!(!state.deafened);
        assert!(!state.server_muted);
        assert!(!state.server_deafened);
        assert!(state.can_send());
        assert!(state.can_receive());
    }

    #[test]
    fn audio_state_muted_cannot_send() {
        let state = ParticipantAudioState {
            muted: true,
            ..Default::default()
        };
        assert!(!state.can_send());
        assert!(state.can_receive());
    }

    #[test]
    fn audio_state_server_muted_cannot_send() {
        let state = ParticipantAudioState {
            server_muted: true,
            ..Default::default()
        };
        assert!(!state.can_send());
    }

    #[test]
    fn audio_state_deafened_cannot_receive() {
        let state = ParticipantAudioState {
            deafened: true,
            ..Default::default()
        };
        assert!(!state.can_receive());
    }

    #[test]
    fn audio_state_server_deafened_cannot_receive() {
        let state = ParticipantAudioState {
            server_deafened: true,
            ..Default::default()
        };
        assert!(!state.can_receive());
    }

    // -- VoiceChannelState --

    #[test]
    fn channel_state_add_remove_participants() {
        let mut state = VoiceChannelState::new("guild_1", "chan_1");
        assert_eq!(state.guild_id(), "guild_1");
        assert_eq!(state.channel_id(), "chan_1");
        assert_eq!(state.participant_count(), 0);

        state.add_participant("user_1", "Alice").unwrap();
        assert_eq!(state.participant_count(), 1);
        assert!(state.get_participant("user_1").is_some());

        let removed = state.remove_participant("user_1").unwrap();
        assert_eq!(removed.user_id, "user_1");
        assert_eq!(state.participant_count(), 0);
    }

    #[test]
    fn channel_state_duplicate_participant_rejected() {
        let mut state = VoiceChannelState::new("g", "c");
        state.add_participant("user_1", "Alice").unwrap();
        let err = state.add_participant("user_1", "Alice2").unwrap_err();
        assert!(matches!(err, VoiceError::ParticipantAlreadyPresent { .. }));
    }

    #[test]
    fn channel_state_remove_nonexistent_participant() {
        let mut state = VoiceChannelState::new("g", "c");
        let err = state.remove_participant("ghost").unwrap_err();
        assert!(matches!(err, VoiceError::ParticipantNotFound { .. }));
    }

    #[test]
    fn channel_state_participant_limit() {
        let mut state = VoiceChannelState::new("g", "c");
        for i in 0..MAX_PARTICIPANTS {
            state
                .add_participant(format!("user_{i}"), format!("User {i}"))
                .unwrap();
        }
        let err = state.add_participant("overflow", "Overflow").unwrap_err();
        assert!(matches!(err, VoiceError::TooManyParticipants { .. }));
    }

    #[test]
    fn channel_state_mute_unmute() {
        let mut state = VoiceChannelState::new("g", "c");
        state.add_participant("user_1", "Alice").unwrap();

        state.set_muted("user_1", true).unwrap();
        assert!(state.get_participant("user_1").unwrap().audio_state.muted);

        state.set_muted("user_1", false).unwrap();
        assert!(!state.get_participant("user_1").unwrap().audio_state.muted);
    }

    #[test]
    fn channel_state_deafen_also_mutes() {
        let mut state = VoiceChannelState::new("g", "c");
        state.add_participant("user_1", "Alice").unwrap();

        state.set_deafened("user_1", true).unwrap();
        let p = state.get_participant("user_1").unwrap();
        assert!(p.audio_state.deafened);
        assert!(p.audio_state.muted);
    }

    #[test]
    fn channel_state_mute_nonexistent_fails() {
        let mut state = VoiceChannelState::new("g", "c");
        let err = state.set_muted("ghost", true).unwrap_err();
        assert!(matches!(err, VoiceError::ParticipantNotFound { .. }));
    }

    #[test]
    fn channel_state_voice_activity() {
        let mut state = VoiceChannelState::new("g", "c");
        state.add_participant("user_1", "Alice").unwrap();

        assert!(!state.is_speaking("user_1"));

        state.record_voice_activity("user_1").unwrap();
        assert!(state.is_speaking("user_1"));
    }

    #[test]
    fn channel_state_voice_activity_nonexistent_fails() {
        let mut state = VoiceChannelState::new("g", "c");
        let err = state.record_voice_activity("ghost").unwrap_err();
        assert!(matches!(err, VoiceError::ParticipantNotFound { .. }));
    }

    #[test]
    fn channel_state_participant_ids() {
        let mut state = VoiceChannelState::new("g", "c");
        state.add_participant("user_a", "A").unwrap();
        state.add_participant("user_b", "B").unwrap();
        let mut ids = state.participant_ids();
        ids.sort();
        assert_eq!(ids, vec!["user_a", "user_b"]);
    }

    // -- VoiceSession --

    #[test]
    fn session_lifecycle() {
        let mut session = VoiceSession::new(test_config());
        assert_eq!(session.status(), ConnectionStatus::Disconnected);
        assert!(session.state().is_none());

        session.join().unwrap();
        assert_eq!(session.status(), ConnectionStatus::Connected);
        assert!(session.state().is_some());

        session.leave().unwrap();
        assert_eq!(session.status(), ConnectionStatus::Disconnected);
        assert!(session.state().is_none());
    }

    #[test]
    fn session_double_join_rejected() {
        let mut session = VoiceSession::new(test_config());
        session.join().unwrap();
        let err = session.join().unwrap_err();
        assert!(matches!(err, VoiceError::AlreadyConnected));
    }

    #[test]
    fn session_leave_when_disconnected_fails() {
        let mut session = VoiceSession::new(test_config());
        let err = session.leave().unwrap_err();
        assert!(matches!(err, VoiceError::NotConnected));
    }

    #[test]
    fn session_mute_unmute_when_connected() {
        let mut session = VoiceSession::new(test_config());
        session.join().unwrap();
        session.mute().unwrap();
        session.unmute().unwrap();
    }

    #[test]
    fn session_mute_when_disconnected_fails() {
        let mut session = VoiceSession::new(test_config());
        let err = session.mute().unwrap_err();
        assert!(matches!(err, VoiceError::NotConnected));
    }

    #[test]
    fn session_unmute_when_disconnected_fails() {
        let mut session = VoiceSession::new(test_config());
        let err = session.unmute().unwrap_err();
        assert!(matches!(err, VoiceError::NotConnected));
    }

    #[test]
    fn session_config_accessor() {
        let session = VoiceSession::new(test_config());
        assert_eq!(session.config().guild_id, "guild_123");
        assert_eq!(session.config().channel_id, "chan_456");
    }

    #[test]
    fn session_state_mut_accessor() {
        let mut session = VoiceSession::new(test_config());
        session.join().unwrap();
        let state = session.state_mut().unwrap();
        state.add_participant("user_1", "Alice").unwrap();
        assert_eq!(session.state().unwrap().participant_count(), 1);
    }

    // -- ID validation --

    #[test]
    fn validate_id_empty_rejected() {
        let err = validate_id("", "test").unwrap_err();
        assert!(matches!(err, VoiceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_too_long_rejected() {
        let long = "a".repeat(MAX_ID_LEN + 1);
        let err = validate_id(&long, "test").unwrap_err();
        assert!(matches!(err, VoiceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_special_chars_rejected() {
        let err = validate_id("user@name", "test").unwrap_err();
        assert!(matches!(err, VoiceError::InvalidId { .. }));
    }

    #[test]
    fn validate_id_valid() {
        assert!(validate_id("user_123", "test").is_ok());
    }

    // -- Error Display --

    #[test]
    fn error_display() {
        assert_eq!(
            VoiceError::NotConnected.to_string(),
            "not connected to a voice channel"
        );
        assert_eq!(
            VoiceError::AlreadyConnected.to_string(),
            "already connected to a voice channel"
        );
        assert_eq!(
            VoiceError::ParticipantNotFound {
                user_id: "x".to_string()
            }
            .to_string(),
            "participant \"x\" not found in channel"
        );
        assert_eq!(
            VoiceError::TooManyParticipants { limit: 5 }.to_string(),
            "voice channel participant limit of 5 exceeded"
        );
    }

    // -- ConnectionStatus --

    #[test]
    fn connection_status_equality() {
        assert_eq!(
            ConnectionStatus::Disconnected,
            ConnectionStatus::Disconnected
        );
        assert_ne!(ConnectionStatus::Connected, ConnectionStatus::Disconnected);
        assert_ne!(ConnectionStatus::Connecting, ConnectionStatus::Reconnecting);
    }
}
