//! Aegis high-speed computer-use toolkit (capture/input/window/tui/vision).
//!
//! This crate provides the low-latency building blocks for the orchestrator
//! to "see" and "act" like a human operator, while remaining policy-gated.

pub mod capture;
pub mod contract;
pub mod input;
pub mod tui;
pub mod vision;
pub mod window;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolkitError {
    #[error("toolkit unavailable: {0}")]
    Unavailable(String),
    #[error("toolkit error: {0}")]
    Other(String),
}

pub type ToolkitResult<T> = Result<T, ToolkitError>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrameMetadata {
    pub width: u32,
    pub height: u32,
    pub timestamp_ms: u128,
    pub frame_id: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureFrame {
    pub metadata: FrameMetadata,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InputLatency {
    pub latency_ms: u64,
}
