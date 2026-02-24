//! Bidirectional voice conversation (talk mode).
//!
//! Provides [`TalkMode`] which manages a voice conversation loop:
//!
//! 1. **Listen**: Capture audio from the microphone.
//! 2. **Transcribe**: Convert speech to text via STT.
//! 3. **Send**: Forward the text to an agent (via a callback).
//! 4. **Receive**: Get the agent's text response (via a callback).
//! 5. **Synthesize**: Convert the response to speech via TTS.
//! 6. **Play**: Play the audio through the system speaker.
//! 7. **Repeat**: Go to step 1.
//!
//! # Configuration
//!
//! [`TalkModeConfig`] controls STT/TTS providers, auto-listen behavior,
//! silence timeout, and VAD threshold.
//!
//! # Audio Playback
//!
//! Audio playback uses system commands:
//! - macOS: `afplay` (built-in)
//! - Linux: `aplay` (ALSA) or `paplay` (PulseAudio)
//! - Fallback: SoX `play`

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::Command;

use crate::capture::{AudioCapture, CaptureConfig};
use crate::stt::{SttConfig, SttProvider};
use crate::{VoiceError, VoiceResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for talk mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkModeConfig {
    /// STT provider configuration.
    #[serde(default)]
    pub stt: SttConfig,

    /// Audio capture configuration.
    #[serde(default)]
    pub capture: CaptureConfig,

    /// Whether to automatically listen for the next utterance after
    /// playing the response (continuous conversation).
    #[serde(default = "default_auto_listen")]
    pub auto_listen: bool,

    /// Silence timeout in milliseconds. If no speech is detected for
    /// this long after starting to listen, the listening window ends.
    #[serde(default = "default_silence_timeout_ms")]
    pub silence_timeout_ms: u64,

    /// VAD threshold for detecting speech (0.0 - 1.0).
    #[serde(default = "default_vad_threshold")]
    pub vad_threshold: f32,

    /// Duration to listen per turn, in seconds.
    #[serde(default = "default_listen_duration_secs")]
    pub listen_duration_secs: u64,
}

fn default_auto_listen() -> bool {
    true
}

fn default_silence_timeout_ms() -> u64 {
    1500
}

fn default_vad_threshold() -> f32 {
    0.02
}

fn default_listen_duration_secs() -> u64 {
    10
}

impl Default for TalkModeConfig {
    fn default() -> Self {
        Self {
            stt: SttConfig::default(),
            capture: CaptureConfig::default(),
            auto_listen: default_auto_listen(),
            silence_timeout_ms: default_silence_timeout_ms(),
            vad_threshold: default_vad_threshold(),
            listen_duration_secs: default_listen_duration_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// Agent bridge trait
// ---------------------------------------------------------------------------

/// Trait for sending user speech to an agent and receiving responses.
///
/// Implementors bridge talk mode to the actual agent (e.g., sending text
/// to a Claude Code session and receiving the response).
#[async_trait]
pub trait AgentBridge: Send + Sync {
    /// Send user text to the agent and receive the response.
    ///
    /// Returns the agent's text response. May return an empty string
    /// if the agent has no response.
    async fn send_and_receive(&self, user_text: &str) -> VoiceResult<String>;
}

// ---------------------------------------------------------------------------
// Audio playback
// ---------------------------------------------------------------------------

/// Available audio playback backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackBackend {
    /// macOS `afplay` command.
    Afplay,
    /// SoX `play` command.
    SoxPlay,
    /// Linux ALSA `aplay` command.
    Aplay,
}

impl std::fmt::Display for PlaybackBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybackBackend::Afplay => write!(f, "afplay"),
            PlaybackBackend::SoxPlay => write!(f, "play"),
            PlaybackBackend::Aplay => write!(f, "aplay"),
        }
    }
}

/// Detect which audio playback backend is available.
pub async fn detect_playback_backend() -> Option<PlaybackBackend> {
    if command_exists("afplay").await {
        return Some(PlaybackBackend::Afplay);
    }
    if command_exists("play").await {
        return Some(PlaybackBackend::SoxPlay);
    }
    if command_exists("aplay").await {
        return Some(PlaybackBackend::Aplay);
    }
    None
}

/// Play audio from a file using the detected backend.
pub async fn play_audio_file(path: &std::path::Path, backend: PlaybackBackend) -> VoiceResult<()> {
    let cmd_name = match backend {
        PlaybackBackend::Afplay => "afplay",
        PlaybackBackend::SoxPlay => "play",
        PlaybackBackend::Aplay => "aplay",
    };

    tracing::debug!(
        backend = %backend,
        path = %path.display(),
        "playing audio"
    );

    let status = Command::new(cmd_name)
        .arg(path.to_string_lossy().as_ref())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| VoiceError::TalkError(format!("failed to run {cmd_name}: {e}")))?;

    if !status.success() {
        return Err(VoiceError::TalkError(format!(
            "{cmd_name} exited with status: {status}"
        )));
    }

    Ok(())
}

/// Play audio bytes by writing to a temp file and playing.
pub async fn play_audio_bytes(
    audio: &[u8],
    extension: &str,
    backend: PlaybackBackend,
) -> VoiceResult<()> {
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("aegis_talk_{}.{extension}", std::process::id()));

    tokio::fs::write(&temp_path, audio)
        .await
        .map_err(|e| VoiceError::TalkError(format!("failed to write temp audio file: {e}")))?;

    let result = play_audio_file(&temp_path, backend).await;

    // Clean up temp file (best-effort).
    let _ = tokio::fs::remove_file(&temp_path).await;

    result
}

/// Check if a command exists on the system PATH.
async fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Talk mode events
// ---------------------------------------------------------------------------

/// Events emitted during a talk mode conversation.
#[derive(Debug, Clone)]
pub enum TalkEvent {
    /// Talk mode started listening for speech.
    Listening,
    /// Speech was captured and is being transcribed.
    Transcribing,
    /// User speech was transcribed to text.
    UserSaid(String),
    /// Agent is generating a response.
    Thinking,
    /// Agent responded with text.
    AgentSaid(String),
    /// Response is being synthesized to speech.
    Synthesizing,
    /// Audio is being played.
    Playing,
    /// An error occurred during the conversation turn.
    Error(String),
    /// Talk mode ended.
    Stopped,
}

// ---------------------------------------------------------------------------
// TalkMode
// ---------------------------------------------------------------------------

/// Bidirectional voice conversation manager.
///
/// Coordinates audio capture, STT transcription, agent communication,
/// TTS synthesis, and audio playback in a continuous conversation loop.
pub struct TalkMode {
    config: TalkModeConfig,
    capture: Arc<AudioCapture>,
    stt: Arc<dyn SttProvider>,
    tts: Arc<aegis_tts::manager::TtsManager>,
    agent: Arc<dyn AgentBridge>,
    playback: PlaybackBackend,
    running: Arc<AtomicBool>,
    event_tx: tokio::sync::mpsc::Sender<TalkEvent>,
}

impl TalkMode {
    /// Create a new talk mode instance.
    ///
    /// All components (capture, STT, TTS, agent bridge, playback) must be
    /// provided. Use the factory functions in each module to create them.
    pub fn new(
        config: TalkModeConfig,
        capture: AudioCapture,
        stt: Arc<dyn SttProvider>,
        tts: Arc<aegis_tts::manager::TtsManager>,
        agent: Arc<dyn AgentBridge>,
        playback: PlaybackBackend,
        event_tx: tokio::sync::mpsc::Sender<TalkEvent>,
    ) -> Self {
        Self {
            config,
            capture: Arc::new(capture),
            stt,
            tts,
            agent,
            playback,
            running: Arc::new(AtomicBool::new(false)),
            event_tx,
        }
    }

    /// Check if talk mode is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop talk mode. The conversation loop will exit on its next iteration.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("talk mode stopping");
    }

    /// Start the talk mode conversation loop in a background task.
    ///
    /// Returns a `JoinHandle` for the background task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let capture = self.capture.clone();
        let stt = self.stt.clone();
        let tts = self.tts.clone();
        let agent = self.agent.clone();
        let playback = self.playback;
        let running = self.running.clone();
        let event_tx = self.event_tx.clone();

        running.store(true, Ordering::Relaxed);

        tracing::info!(
            auto_listen = config.auto_listen,
            listen_duration = config.listen_duration_secs,
            "talk mode started"
        );

        tokio::spawn(async move {
            talk_loop(
                config, capture, stt, tts, agent, playback, running, event_tx,
            )
            .await;
        })
    }

    /// Run a single conversation turn (listen -> transcribe -> respond -> speak).
    ///
    /// Useful for non-loop usage where you want manual control over each turn.
    pub async fn single_turn(&self) -> VoiceResult<(String, String)> {
        conversation_turn(
            &self.config,
            &self.capture,
            self.stt.as_ref(),
            &self.tts,
            self.agent.as_ref(),
            self.playback,
            &self.event_tx,
        )
        .await
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &TalkModeConfig {
        &self.config
    }
}

/// Main talk mode conversation loop.
#[allow(clippy::too_many_arguments)]
async fn talk_loop(
    config: TalkModeConfig,
    capture: Arc<AudioCapture>,
    stt: Arc<dyn SttProvider>,
    tts: Arc<aegis_tts::manager::TtsManager>,
    agent: Arc<dyn AgentBridge>,
    playback: PlaybackBackend,
    running: Arc<AtomicBool>,
    event_tx: tokio::sync::mpsc::Sender<TalkEvent>,
) {
    while running.load(Ordering::Relaxed) {
        match conversation_turn(
            &config,
            &capture,
            stt.as_ref(),
            &tts,
            agent.as_ref(),
            playback,
            &event_tx,
        )
        .await
        {
            Ok((user_text, _agent_text)) => {
                tracing::debug!(user = %user_text, "conversation turn completed");
            }
            Err(e) => {
                tracing::warn!(error = %e, "conversation turn failed");
                let _ = event_tx.send(TalkEvent::Error(e.to_string())).await;
                // Brief pause before retrying after an error.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        if !config.auto_listen {
            break;
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = event_tx.send(TalkEvent::Stopped).await;
    tracing::info!("talk mode stopped");
}

/// Execute a single conversation turn.
///
/// Returns `(user_text, agent_response)` on success.
async fn conversation_turn(
    config: &TalkModeConfig,
    capture: &AudioCapture,
    stt: &dyn SttProvider,
    tts: &aegis_tts::manager::TtsManager,
    agent: &dyn AgentBridge,
    playback: PlaybackBackend,
    event_tx: &tokio::sync::mpsc::Sender<TalkEvent>,
) -> VoiceResult<(String, String)> {
    // Step 1: Listen.
    let _ = event_tx.send(TalkEvent::Listening).await;
    let audio = capture.record_bytes(config.listen_duration_secs).await?;

    // Check for voice activity.
    let samples = crate::capture::wav_to_samples(&audio);
    let vad_ratio = crate::capture::voice_activity_ratio(&samples, config.vad_threshold, 480);
    if vad_ratio < 0.05 {
        return Err(VoiceError::TalkError("no speech detected".to_string()));
    }

    // Step 2: Transcribe.
    let _ = event_tx.send(TalkEvent::Transcribing).await;
    let user_text = stt.transcribe(&audio).await?;

    if user_text.is_empty() {
        return Err(VoiceError::TalkError(
            "transcription returned empty text".to_string(),
        ));
    }

    let _ = event_tx.send(TalkEvent::UserSaid(user_text.clone())).await;
    tracing::info!(text = %user_text, "user said");

    // Step 3: Send to agent.
    let _ = event_tx.send(TalkEvent::Thinking).await;
    let agent_response = agent.send_and_receive(&user_text).await?;

    if agent_response.is_empty() {
        return Ok((user_text, agent_response));
    }

    let _ = event_tx
        .send(TalkEvent::AgentSaid(agent_response.clone()))
        .await;
    tracing::info!(text = %agent_response, "agent said");

    // Step 4: Synthesize.
    let _ = event_tx.send(TalkEvent::Synthesizing).await;
    let audio_bytes = tts
        .synthesize(&agent_response, None, None)
        .await
        .map_err(VoiceError::TtsError)?;

    // Step 5: Play.
    let _ = event_tx.send(TalkEvent::Playing).await;
    let extension = tts.list_voices().ok().map(|_| "mp3").unwrap_or("mp3");
    play_audio_bytes(&audio_bytes, extension, playback).await?;

    Ok((user_text, agent_response))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TalkModeConfig tests --

    #[test]
    fn talk_mode_config_defaults() {
        let config = TalkModeConfig::default();
        assert!(config.auto_listen);
        assert_eq!(config.silence_timeout_ms, 1500);
        assert!((config.vad_threshold - 0.02).abs() < f32::EPSILON);
        assert_eq!(config.listen_duration_secs, 10);
    }

    #[test]
    fn talk_mode_config_serialization_roundtrip() {
        let config = TalkModeConfig {
            auto_listen: false,
            silence_timeout_ms: 3000,
            vad_threshold: 0.1,
            listen_duration_secs: 15,
            ..TalkModeConfig::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let back: TalkModeConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.auto_listen);
        assert_eq!(back.silence_timeout_ms, 3000);
        assert!((back.vad_threshold - 0.1).abs() < f32::EPSILON);
        assert_eq!(back.listen_duration_secs, 15);
    }

    #[test]
    fn talk_mode_config_deserialize_defaults() {
        let json = "{}";
        let config: TalkModeConfig = serde_json::from_str(json).unwrap();
        assert!(config.auto_listen);
        assert_eq!(config.listen_duration_secs, 10);
    }

    // -- PlaybackBackend tests --

    #[test]
    fn playback_backend_display() {
        assert_eq!(PlaybackBackend::Afplay.to_string(), "afplay");
        assert_eq!(PlaybackBackend::SoxPlay.to_string(), "play");
        assert_eq!(PlaybackBackend::Aplay.to_string(), "aplay");
    }

    // -- TalkEvent tests --

    #[test]
    fn talk_event_debug() {
        // Just verify all variants can be created and debug-printed.
        let events = vec![
            TalkEvent::Listening,
            TalkEvent::Transcribing,
            TalkEvent::UserSaid("hello".to_string()),
            TalkEvent::Thinking,
            TalkEvent::AgentSaid("world".to_string()),
            TalkEvent::Synthesizing,
            TalkEvent::Playing,
            TalkEvent::Error("test error".to_string()),
            TalkEvent::Stopped,
        ];
        for event in events {
            let debug = format!("{event:?}");
            assert!(!debug.is_empty());
        }
    }
}
