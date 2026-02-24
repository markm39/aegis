//! Audio capture from microphone via system commands.
//!
//! Provides [`AudioCapture`] for recording audio from the system microphone
//! using subprocess-based backends. Supported backends:
//!
//! - **SoX** (`rec`): Cross-platform, feature-rich. Preferred when available.
//! - **arecord**: Linux ALSA-based recording.
//! - **macOS** (`osascript`): Fallback using AppleScript + QuickTime (limited).
//!
//! Also provides simple Voice Activity Detection (VAD) based on RMS energy
//! thresholds, suitable for detecting speech vs. silence in captured audio.
//!
//! # Audio Format
//!
//! All captures produce 16-bit signed PCM WAV data at the configured sample
//! rate and channel count. This is the most portable format for downstream
//! STT processing.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

use crate::{VoiceError, VoiceResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for audio capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Audio sample rate in Hz.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,

    /// Number of audio channels (1 = mono, 2 = stereo).
    #[serde(default = "default_channels")]
    pub channels: u16,

    /// RMS energy threshold for voice activity detection (0.0 - 1.0).
    /// Audio frames below this threshold are considered silence.
    #[serde(default = "default_vad_threshold")]
    pub vad_threshold: f32,

    /// Duration of silence (in milliseconds) before stopping capture.
    /// Only used when `stop_on_silence` is true.
    #[serde(default = "default_silence_timeout_ms")]
    pub silence_timeout_ms: u64,

    /// Whether to automatically stop capture after detecting silence.
    #[serde(default)]
    pub stop_on_silence: bool,

    /// Maximum recording duration in seconds. 0 means unlimited.
    #[serde(default = "default_max_duration_secs")]
    pub max_duration_secs: u64,
}

fn default_sample_rate() -> u32 {
    16000
}

fn default_channels() -> u16 {
    1
}

fn default_vad_threshold() -> f32 {
    0.02
}

fn default_silence_timeout_ms() -> u64 {
    1500
}

fn default_max_duration_secs() -> u64 {
    30
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            sample_rate: default_sample_rate(),
            channels: default_channels(),
            vad_threshold: default_vad_threshold(),
            silence_timeout_ms: default_silence_timeout_ms(),
            stop_on_silence: false,
            max_duration_secs: default_max_duration_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// Audio capture backend detection
// ---------------------------------------------------------------------------

/// Available audio capture backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// SoX `rec` command.
    Sox,
    /// Linux ALSA `arecord` command.
    Arecord,
}

impl std::fmt::Display for CaptureBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureBackend::Sox => write!(f, "sox"),
            CaptureBackend::Arecord => write!(f, "arecord"),
        }
    }
}

/// Detect which audio capture backend is available on this system.
///
/// Checks for `rec` (SoX) first, then `arecord` (ALSA). Returns `None`
/// if no supported backend is found.
pub async fn detect_backend() -> Option<CaptureBackend> {
    if command_exists("rec").await {
        return Some(CaptureBackend::Sox);
    }
    if command_exists("arecord").await {
        return Some(CaptureBackend::Arecord);
    }
    None
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
// AudioCapture
// ---------------------------------------------------------------------------

/// Microphone audio capture using system commands.
///
/// Records audio from the default microphone and writes it to a temporary
/// WAV file. The backend is auto-detected or can be specified explicitly.
pub struct AudioCapture {
    config: CaptureConfig,
    backend: CaptureBackend,
}

impl AudioCapture {
    /// Create a new `AudioCapture` with the given config and backend.
    pub fn new(config: CaptureConfig, backend: CaptureBackend) -> Self {
        Self { config, backend }
    }

    /// Create a new `AudioCapture`, auto-detecting the backend.
    ///
    /// Returns an error if no supported backend is found.
    pub async fn auto_detect(config: CaptureConfig) -> VoiceResult<Self> {
        let backend = detect_backend().await.ok_or_else(|| {
            VoiceError::CaptureError(
                "no audio capture backend found. Install SoX (rec) or ALSA (arecord).".to_string(),
            )
        })?;
        tracing::info!(backend = %backend, "detected audio capture backend");
        Ok(Self::new(config, backend))
    }

    /// Return the configured backend.
    pub fn backend(&self) -> CaptureBackend {
        self.backend
    }

    /// Return a reference to the capture configuration.
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    /// Record audio to the specified file path.
    ///
    /// Records for `duration_secs` seconds (or `max_duration_secs` from config
    /// if `duration_secs` is 0). The output is always a WAV file.
    ///
    /// Returns the path to the recorded WAV file.
    pub async fn record_to_file(
        &self,
        output_path: &std::path::Path,
        duration_secs: u64,
    ) -> VoiceResult<PathBuf> {
        let duration = if duration_secs > 0 {
            duration_secs
        } else {
            self.config.max_duration_secs
        };

        let output = output_path.to_path_buf();

        match self.backend {
            CaptureBackend::Sox => {
                self.record_sox(&output, duration).await?;
            }
            CaptureBackend::Arecord => {
                self.record_arecord(&output, duration).await?;
            }
        }

        Ok(output)
    }

    /// Record audio and return the raw WAV bytes.
    ///
    /// Creates a temporary file, records into it, reads the bytes, and
    /// cleans up the temp file.
    pub async fn record_bytes(&self, duration_secs: u64) -> VoiceResult<Vec<u8>> {
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("aegis_voice_{}.wav", std::process::id()));

        let path = self.record_to_file(&temp_path, duration_secs).await?;

        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| VoiceError::CaptureError(format!("failed to read recorded audio: {e}")))?;

        // Clean up temp file (best-effort).
        let _ = tokio::fs::remove_file(&path).await;

        Ok(bytes)
    }

    /// Record audio using SoX `rec` command.
    async fn record_sox(&self, output: &std::path::Path, duration_secs: u64) -> VoiceResult<()> {
        let mut cmd = Command::new("rec");
        cmd.arg("-r")
            .arg(self.config.sample_rate.to_string())
            .arg("-c")
            .arg(self.config.channels.to_string())
            .arg("-b")
            .arg("16")
            .arg("-e")
            .arg("signed-integer")
            .arg(output.to_string_lossy().as_ref());

        if duration_secs > 0 {
            cmd.arg("trim").arg("0").arg(duration_secs.to_string());
        }

        tracing::debug!(
            backend = "sox",
            output = %output.display(),
            duration = duration_secs,
            "starting audio capture"
        );

        let status = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| VoiceError::CaptureError(format!("failed to run rec: {e}")))?;

        if !status.success() {
            return Err(VoiceError::CaptureError(format!(
                "rec exited with status: {status}"
            )));
        }

        Ok(())
    }

    /// Record audio using ALSA `arecord` command.
    async fn record_arecord(
        &self,
        output: &std::path::Path,
        duration_secs: u64,
    ) -> VoiceResult<()> {
        let mut cmd = Command::new("arecord");
        cmd.arg("-f")
            .arg("S16_LE")
            .arg("-r")
            .arg(self.config.sample_rate.to_string())
            .arg("-c")
            .arg(self.config.channels.to_string())
            .arg("-t")
            .arg("wav");

        if duration_secs > 0 {
            cmd.arg("-d").arg(duration_secs.to_string());
        }

        cmd.arg(output.to_string_lossy().as_ref());

        tracing::debug!(
            backend = "arecord",
            output = %output.display(),
            duration = duration_secs,
            "starting audio capture"
        );

        let status = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| VoiceError::CaptureError(format!("failed to run arecord: {e}")))?;

        if !status.success() {
            return Err(VoiceError::CaptureError(format!(
                "arecord exited with status: {status}"
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Voice Activity Detection (VAD)
// ---------------------------------------------------------------------------

/// Compute the Root Mean Square (RMS) energy of 16-bit PCM audio samples.
///
/// The input `samples` should be signed 16-bit integers. The returned
/// value is normalized to the range [0.0, 1.0], where 0.0 is silence
/// and 1.0 is maximum amplitude.
///
/// Returns 0.0 for empty input.
pub fn compute_rms(samples: &[i16]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }

    let sum_of_squares: f64 = samples
        .iter()
        .map(|&s| {
            let sample = s as f64;
            sample * sample
        })
        .sum();

    let mean = sum_of_squares / samples.len() as f64;
    let rms = mean.sqrt();

    // Normalize to [0, 1] range (i16 max is 32767).
    (rms / 32767.0) as f32
}

/// Detect whether an audio frame contains voice activity.
///
/// Compares the RMS energy of the frame against the given `threshold`.
/// Returns `true` if the energy exceeds the threshold (speech detected).
pub fn detect_voice_activity(samples: &[i16], threshold: f32) -> bool {
    compute_rms(samples) > threshold
}

/// Extract 16-bit signed PCM samples from raw WAV file bytes.
///
/// Skips the standard 44-byte WAV header and interprets the remaining
/// data as little-endian 16-bit signed integers.
///
/// Returns an empty vec if the data is too short to contain samples.
pub fn wav_to_samples(wav_data: &[u8]) -> Vec<i16> {
    const WAV_HEADER_SIZE: usize = 44;

    if wav_data.len() <= WAV_HEADER_SIZE {
        return Vec::new();
    }

    let pcm_data = &wav_data[WAV_HEADER_SIZE..];

    pcm_data
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect()
}

/// Analyze WAV audio data and return the fraction of frames that contain
/// voice activity.
///
/// Splits the audio into frames of `frame_size` samples (default 480,
/// which is 30ms at 16kHz) and computes the fraction of frames whose
/// RMS energy exceeds `threshold`.
///
/// Returns a value in [0.0, 1.0] where 0.0 means all silence and 1.0
/// means all speech.
pub fn voice_activity_ratio(samples: &[i16], threshold: f32, frame_size: usize) -> f32 {
    if samples.is_empty() || frame_size == 0 {
        return 0.0;
    }

    let frames: Vec<&[i16]> = samples.chunks(frame_size).collect();
    let total_frames = frames.len();
    let active_frames = frames
        .iter()
        .filter(|frame| detect_voice_activity(frame, threshold))
        .count();

    active_frames as f32 / total_frames as f32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CaptureConfig tests --

    #[test]
    fn capture_config_defaults() {
        let config = CaptureConfig::default();
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.channels, 1);
        assert!((config.vad_threshold - 0.02).abs() < f32::EPSILON);
        assert_eq!(config.silence_timeout_ms, 1500);
        assert!(!config.stop_on_silence);
        assert_eq!(config.max_duration_secs, 30);
    }

    #[test]
    fn capture_config_serialization_roundtrip() {
        let config = CaptureConfig {
            sample_rate: 44100,
            channels: 2,
            vad_threshold: 0.05,
            silence_timeout_ms: 2000,
            stop_on_silence: true,
            max_duration_secs: 60,
        };

        let json = serde_json::to_string(&config).unwrap();
        let back: CaptureConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sample_rate, 44100);
        assert_eq!(back.channels, 2);
        assert!((back.vad_threshold - 0.05).abs() < f32::EPSILON);
        assert_eq!(back.silence_timeout_ms, 2000);
        assert!(back.stop_on_silence);
        assert_eq!(back.max_duration_secs, 60);
    }

    #[test]
    fn capture_config_deserialize_defaults() {
        let json = "{}";
        let config: CaptureConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.channels, 1);
    }

    // -- CaptureBackend tests --

    #[test]
    fn capture_backend_display() {
        assert_eq!(CaptureBackend::Sox.to_string(), "sox");
        assert_eq!(CaptureBackend::Arecord.to_string(), "arecord");
    }

    // -- RMS / VAD tests --

    #[test]
    fn rms_empty_input() {
        assert!((compute_rms(&[]) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn rms_silence() {
        let silence = vec![0i16; 100];
        assert!((compute_rms(&silence) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn rms_max_amplitude() {
        let max_signal = vec![i16::MAX; 100];
        let rms = compute_rms(&max_signal);
        // Should be close to 1.0 (max amplitude normalized).
        assert!(
            (rms - 1.0).abs() < 0.001,
            "RMS of max amplitude signal should be ~1.0, got {rms}"
        );
    }

    #[test]
    fn rms_known_value() {
        // A constant signal of 1000 (out of 32767) should give a known RMS.
        let signal = vec![1000i16; 100];
        let rms = compute_rms(&signal);
        let expected = 1000.0 / 32767.0;
        assert!(
            (rms - expected as f32).abs() < 0.001,
            "expected RMS ~{expected}, got {rms}"
        );
    }

    #[test]
    fn rms_mixed_signal() {
        // Alternating positive and negative values should still produce
        // the same RMS as constant absolute values.
        let signal: Vec<i16> = (0..100)
            .map(|i| if i % 2 == 0 { 5000 } else { -5000 })
            .collect();
        let rms = compute_rms(&signal);
        let expected = 5000.0 / 32767.0;
        assert!(
            (rms - expected as f32).abs() < 0.001,
            "expected RMS ~{expected}, got {rms}"
        );
    }

    #[test]
    fn vad_detects_silence() {
        let silence = vec![0i16; 480];
        assert!(!detect_voice_activity(&silence, 0.02));
    }

    #[test]
    fn vad_detects_speech() {
        let speech = vec![5000i16; 480];
        assert!(detect_voice_activity(&speech, 0.02));
    }

    #[test]
    fn vad_threshold_boundary() {
        // Create a signal just below and just above the threshold.
        let threshold = 0.1;
        let below_val = (threshold * 32767.0 * 0.9) as i16;
        let above_val = (threshold * 32767.0 * 1.2) as i16;

        let below = vec![below_val; 480];
        let above = vec![above_val; 480];

        assert!(!detect_voice_activity(&below, threshold));
        assert!(detect_voice_activity(&above, threshold));
    }

    // -- WAV parsing tests --

    #[test]
    fn wav_to_samples_too_short() {
        // Data shorter than WAV header should return empty.
        let short = vec![0u8; 20];
        assert!(wav_to_samples(&short).is_empty());
    }

    #[test]
    fn wav_to_samples_exact_header() {
        // Exactly 44 bytes (header only, no samples).
        let header = vec![0u8; 44];
        assert!(wav_to_samples(&header).is_empty());
    }

    #[test]
    fn wav_to_samples_parses_pcm() {
        // Create a minimal WAV-like buffer: 44 byte header + PCM data.
        let mut data = vec![0u8; 44]; // Dummy header.

        // Append 16-bit LE samples: 1000, -1000, 0.
        data.extend_from_slice(&1000i16.to_le_bytes());
        data.extend_from_slice(&(-1000i16).to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());

        let samples = wav_to_samples(&data);
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0], 1000);
        assert_eq!(samples[1], -1000);
        assert_eq!(samples[2], 0);
    }

    #[test]
    fn wav_to_samples_odd_byte_count() {
        // If there is an odd trailing byte after the header, it should be
        // ignored (chunks_exact drops the remainder).
        let mut data = vec![0u8; 44];
        data.extend_from_slice(&500i16.to_le_bytes());
        data.push(0xFF); // Trailing odd byte.

        let samples = wav_to_samples(&data);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0], 500);
    }

    // -- Voice activity ratio tests --

    #[test]
    fn voice_activity_ratio_all_silence() {
        let silence = vec![0i16; 960]; // Two 480-sample frames.
        let ratio = voice_activity_ratio(&silence, 0.02, 480);
        assert!((ratio - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn voice_activity_ratio_all_speech() {
        let speech = vec![10000i16; 960]; // Two 480-sample frames.
        let ratio = voice_activity_ratio(&speech, 0.02, 480);
        assert!((ratio - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn voice_activity_ratio_half_speech() {
        // First frame is speech, second is silence.
        let mut samples = vec![10000i16; 480];
        samples.extend(vec![0i16; 480]);
        let ratio = voice_activity_ratio(&samples, 0.02, 480);
        assert!(
            (ratio - 0.5).abs() < f32::EPSILON,
            "expected 0.5, got {ratio}"
        );
    }

    #[test]
    fn voice_activity_ratio_empty() {
        let ratio = voice_activity_ratio(&[], 0.02, 480);
        assert!((ratio - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn voice_activity_ratio_zero_frame_size() {
        let samples = vec![10000i16; 480];
        let ratio = voice_activity_ratio(&samples, 0.02, 0);
        assert!((ratio - 0.0).abs() < f32::EPSILON);
    }
}
