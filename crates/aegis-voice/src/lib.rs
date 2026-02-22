//! Voice interaction modules for Aegis.
//!
//! Provides wake word detection, bidirectional talk mode, audio capture,
//! and speech-to-text (STT) integration. These modules enable hands-free
//! voice interaction with Aegis agents.
//!
//! # Modules
//!
//! - [`capture`]: Microphone audio capture via system commands (SoX `rec`, `arecord`).
//! - [`stt`]: Speech-to-text provider trait with Whisper, Deepgram, and local backends.
//! - [`wake`]: Wake word detection ("hey aegis") using audio energy + STT.
//! - [`talk`]: Bidirectional voice conversation loop (listen -> transcribe -> respond -> speak).
//!
//! # Design
//!
//! All audio capture uses subprocess-based approaches (no heavy native
//! dependencies). Each module is independent and composable. Configuration
//! structs implement `Serialize`/`Deserialize` for toml/json config files.

pub mod capture;
pub mod stt;
pub mod talk;
pub mod wake;

/// Errors that can occur during voice operations.
#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    /// Audio capture failed.
    #[error("audio capture error: {0}")]
    CaptureError(String),

    /// Speech-to-text transcription failed.
    #[error("STT error: {0}")]
    SttError(String),

    /// Wake word detection error.
    #[error("wake word error: {0}")]
    WakeError(String),

    /// Talk mode error.
    #[error("talk mode error: {0}")]
    TalkError(String),

    /// TTS synthesis error (forwarded from aegis-tts).
    #[error("TTS error: {0}")]
    TtsError(#[from] aegis_tts::TtsError),

    /// HTTP request error.
    #[error("http error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// The operation was cancelled.
    #[error("operation cancelled")]
    Cancelled,
}

/// Convenience alias for voice operation results.
pub type VoiceResult<T> = Result<T, VoiceError>;
