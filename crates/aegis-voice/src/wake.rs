//! Wake word detection module.
//!
//! Provides [`WakeWordDetector`] that listens for a configurable wake phrase
//! (default: "hey aegis") by combining voice activity detection with
//! speech-to-text transcription.
//!
//! # Detection Flow
//!
//! 1. Capture short audio frames from the microphone.
//! 2. Run VAD (voice activity detection) to filter silence.
//! 3. When speech is detected, capture a full utterance.
//! 4. Transcribe the utterance using the configured STT provider.
//! 5. Check if the transcript contains the wake phrase.
//! 6. Emit a [`WakeEvent`] if the phrase is found.
//!
//! # Configuration
//!
//! The [`WakeWordConfig`] controls the wake phrase, VAD sensitivity,
//! and audio capture parameters.
//!
//! # Platform Support
//!
//! - macOS: Uses `say` command detection for speech capability, SoX for capture.
//! - Linux: Uses SoX or ALSA for capture.
//! - Fallback: Audio energy detection + STT keyword matching.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::capture::AudioCapture;
use crate::stt::SttProvider;
use crate::VoiceResult;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for wake word detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeWordConfig {
    /// The wake phrase to listen for (case-insensitive).
    #[serde(default = "default_wake_phrase")]
    pub phrase: String,

    /// VAD sensitivity threshold (0.0 - 1.0). Lower = more sensitive.
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f32,

    /// Whether wake word detection is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Duration of each listening window in seconds.
    #[serde(default = "default_listen_duration_secs")]
    pub listen_duration_secs: u64,

    /// Cooldown period in milliseconds between wake detections.
    /// Prevents multiple rapid triggers from the same utterance.
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
}

fn default_wake_phrase() -> String {
    "hey aegis".to_string()
}

fn default_sensitivity() -> f32 {
    0.02
}

fn default_enabled() -> bool {
    true
}

fn default_listen_duration_secs() -> u64 {
    3
}

fn default_cooldown_ms() -> u64 {
    2000
}

impl Default for WakeWordConfig {
    fn default() -> Self {
        Self {
            phrase: default_wake_phrase(),
            sensitivity: default_sensitivity(),
            enabled: default_enabled(),
            listen_duration_secs: default_listen_duration_secs(),
            cooldown_ms: default_cooldown_ms(),
        }
    }
}

// ---------------------------------------------------------------------------
// Wake event
// ---------------------------------------------------------------------------

/// Event emitted when the wake word is detected.
#[derive(Debug, Clone)]
pub struct WakeEvent {
    /// The transcript that contained the wake phrase.
    pub transcript: String,

    /// Timestamp when the wake word was detected.
    pub timestamp: std::time::Instant,

    /// The configured wake phrase that was matched.
    pub phrase: String,
}

// ---------------------------------------------------------------------------
// Phrase matching
// ---------------------------------------------------------------------------

/// Check if a transcript contains the wake phrase.
///
/// Performs case-insensitive matching. The transcript is normalized by
/// collapsing whitespace and trimming before comparison.
///
/// Returns `true` if the wake phrase is found anywhere in the transcript.
pub fn matches_wake_phrase(transcript: &str, phrase: &str) -> bool {
    if transcript.is_empty() || phrase.is_empty() {
        return false;
    }

    let normalized_transcript = normalize_text(transcript);
    let normalized_phrase = normalize_text(phrase);

    normalized_transcript.contains(&normalized_phrase)
}

/// Normalize text for comparison: lowercase, collapse whitespace, trim.
fn normalize_text(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    let collapsed: String = lowered
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    collapsed.trim().to_string()
}

// ---------------------------------------------------------------------------
// WakeWordDetector
// ---------------------------------------------------------------------------

/// Wake word detector that listens for a configurable phrase.
///
/// Runs a background loop that captures audio, transcribes it, and
/// checks for the wake phrase. When detected, sends a [`WakeEvent`]
/// through the provided channel.
///
/// # Usage
///
/// ```ignore
/// let (tx, mut rx) = tokio::sync::mpsc::channel(16);
/// let detector = WakeWordDetector::new(config, capture, stt, tx);
///
/// // Start listening in background.
/// let handle = detector.start();
///
/// // Wait for wake word.
/// if let Some(event) = rx.recv().await {
///     println!("Wake word detected: {}", event.transcript);
/// }
///
/// // Stop listening.
/// detector.stop();
/// handle.await.unwrap();
/// ```
pub struct WakeWordDetector {
    config: WakeWordConfig,
    capture: Arc<AudioCapture>,
    stt: Arc<dyn SttProvider>,
    event_tx: mpsc::Sender<WakeEvent>,
    running: Arc<AtomicBool>,
}

impl WakeWordDetector {
    /// Create a new wake word detector.
    ///
    /// The detector is created in a stopped state. Call [`start`](Self::start)
    /// to begin listening.
    pub fn new(
        config: WakeWordConfig,
        capture: AudioCapture,
        stt: Arc<dyn SttProvider>,
        event_tx: mpsc::Sender<WakeEvent>,
    ) -> Self {
        Self {
            config,
            capture: Arc::new(capture),
            stt,
            event_tx,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if the detector is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the detector. The background task will exit on its next iteration.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("wake word detector stopping");
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &WakeWordConfig {
        &self.config
    }

    /// Start listening for the wake word in a background task.
    ///
    /// Returns a `JoinHandle` for the background task. The task runs
    /// until [`stop`](Self::stop) is called or the event channel closes.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let capture = self.capture.clone();
        let stt = self.stt.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();

        running.store(true, Ordering::Relaxed);

        tracing::info!(
            phrase = %config.phrase,
            sensitivity = config.sensitivity,
            "wake word detector started"
        );

        tokio::spawn(async move {
            wake_loop(config, capture, stt, event_tx, running).await;
        })
    }
}

/// Main wake word detection loop.
///
/// Runs continuously until `running` is set to false or the event channel
/// closes.
async fn wake_loop(
    config: WakeWordConfig,
    capture: Arc<AudioCapture>,
    stt: Arc<dyn SttProvider>,
    event_tx: mpsc::Sender<WakeEvent>,
    running: Arc<AtomicBool>,
) {
    let cooldown = std::time::Duration::from_millis(config.cooldown_ms);
    let mut last_detection = std::time::Instant::now() - cooldown;

    while running.load(Ordering::Relaxed) {
        // Check cooldown.
        if last_detection.elapsed() < cooldown {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }

        // Capture audio.
        let audio = match capture.record_bytes(config.listen_duration_secs).await {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(error = %e, "wake word: audio capture failed");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        // Check for voice activity before transcribing (saves API calls).
        let samples = crate::capture::wav_to_samples(&audio);
        let vad_ratio =
            crate::capture::voice_activity_ratio(&samples, config.sensitivity, 480);
        if vad_ratio < 0.1 {
            // Less than 10% of frames have speech -- skip transcription.
            continue;
        }

        // Transcribe.
        let transcript = match stt.transcribe(&audio).await {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(error = %e, "wake word: transcription failed");
                continue;
            }
        };

        tracing::debug!(transcript = %transcript, "wake word: got transcript");

        // Check for wake phrase.
        if matches_wake_phrase(&transcript, &config.phrase) {
            let event = WakeEvent {
                transcript: transcript.clone(),
                timestamp: std::time::Instant::now(),
                phrase: config.phrase.clone(),
            };

            tracing::info!(
                transcript = %transcript,
                phrase = %config.phrase,
                "wake word detected"
            );

            last_detection = std::time::Instant::now();

            if event_tx.send(event).await.is_err() {
                tracing::debug!("wake word: event channel closed, stopping");
                break;
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    tracing::info!("wake word detector stopped");
}

// ---------------------------------------------------------------------------
// Standalone detection (non-loop)
// ---------------------------------------------------------------------------

/// Perform a single wake word check on provided audio data.
///
/// This is useful for testing or when you want to integrate wake word
/// detection into an existing audio pipeline without running the full
/// detector loop.
///
/// Returns `Some(WakeEvent)` if the wake phrase was found, `None` otherwise.
pub async fn check_wake_word(
    audio: &[u8],
    stt: &dyn SttProvider,
    phrase: &str,
    vad_threshold: f32,
) -> VoiceResult<Option<WakeEvent>> {
    let samples = crate::capture::wav_to_samples(audio);
    let vad_ratio = crate::capture::voice_activity_ratio(&samples, vad_threshold, 480);

    if vad_ratio < 0.1 {
        return Ok(None);
    }

    let transcript = stt.transcribe(audio).await?;

    if matches_wake_phrase(&transcript, phrase) {
        Ok(Some(WakeEvent {
            transcript,
            timestamp: std::time::Instant::now(),
            phrase: phrase.to_string(),
        }))
    } else {
        Ok(None)
    }
}

/// Check if macOS speech capabilities are available.
///
/// Detects the presence of the `say` command, which indicates macOS
/// speech synthesis is available. This can be used as a heuristic for
/// whether the system supports voice interaction.
pub async fn has_macos_speech() -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::process::Stdio;
        tokio::process::Command::new("which")
            .arg("say")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- WakeWordConfig tests --

    #[test]
    fn wake_config_defaults() {
        let config = WakeWordConfig::default();
        assert_eq!(config.phrase, "hey aegis");
        assert!((config.sensitivity - 0.02).abs() < f32::EPSILON);
        assert!(config.enabled);
        assert_eq!(config.listen_duration_secs, 3);
        assert_eq!(config.cooldown_ms, 2000);
    }

    #[test]
    fn wake_config_serialization_roundtrip() {
        let config = WakeWordConfig {
            phrase: "hello computer".to_string(),
            sensitivity: 0.05,
            enabled: false,
            listen_duration_secs: 5,
            cooldown_ms: 3000,
        };

        let json = serde_json::to_string(&config).unwrap();
        let back: WakeWordConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phrase, "hello computer");
        assert!((back.sensitivity - 0.05).abs() < f32::EPSILON);
        assert!(!back.enabled);
        assert_eq!(back.listen_duration_secs, 5);
        assert_eq!(back.cooldown_ms, 3000);
    }

    #[test]
    fn wake_config_deserialize_defaults() {
        let json = "{}";
        let config: WakeWordConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.phrase, "hey aegis");
        assert!(config.enabled);
    }

    // -- Wake phrase matching tests --

    #[test]
    fn matches_exact_phrase() {
        assert!(matches_wake_phrase("hey aegis", "hey aegis"));
    }

    #[test]
    fn matches_case_insensitive() {
        assert!(matches_wake_phrase("Hey Aegis", "hey aegis"));
        assert!(matches_wake_phrase("HEY AEGIS", "hey aegis"));
        assert!(matches_wake_phrase("hey aegis", "HEY AEGIS"));
    }

    #[test]
    fn matches_with_surrounding_text() {
        assert!(matches_wake_phrase(
            "um hey aegis what's up",
            "hey aegis"
        ));
        assert!(matches_wake_phrase(
            "so hey aegis can you help",
            "hey aegis"
        ));
    }

    #[test]
    fn matches_with_extra_whitespace() {
        assert!(matches_wake_phrase("hey  aegis", "hey aegis"));
        assert!(matches_wake_phrase("  hey   aegis  ", "hey aegis"));
    }

    #[test]
    fn no_match_different_phrase() {
        assert!(!matches_wake_phrase("hello world", "hey aegis"));
        assert!(!matches_wake_phrase("hey siri", "hey aegis"));
    }

    #[test]
    fn no_match_partial_phrase() {
        assert!(!matches_wake_phrase("hey", "hey aegis"));
        assert!(!matches_wake_phrase("aegis", "hey aegis"));
    }

    #[test]
    fn no_match_empty_inputs() {
        assert!(!matches_wake_phrase("", "hey aegis"));
        assert!(!matches_wake_phrase("hey aegis", ""));
        assert!(!matches_wake_phrase("", ""));
    }

    // -- normalize_text tests --

    #[test]
    fn normalize_text_lowercases() {
        assert_eq!(normalize_text("Hello World"), "hello world");
    }

    #[test]
    fn normalize_text_collapses_whitespace() {
        assert_eq!(normalize_text("hello   world"), "hello world");
        assert_eq!(normalize_text("  hello  world  "), "hello world");
    }

    #[test]
    fn normalize_text_trims() {
        assert_eq!(normalize_text("  hello  "), "hello");
    }

    #[test]
    fn normalize_text_empty() {
        assert_eq!(normalize_text(""), "");
        assert_eq!(normalize_text("   "), "");
    }

    // -- Custom wake phrase tests --

    #[test]
    fn custom_wake_phrase() {
        assert!(matches_wake_phrase("ok computer do this", "ok computer"));
        assert!(matches_wake_phrase("hello jarvis", "hello jarvis"));
        assert!(!matches_wake_phrase("ok computer do this", "hey aegis"));
    }
}
