//! PTY-based supervisor for autonomous AI agent operation.
//!
//! Spawns an AI agent (Claude Code, Cursor, etc.) in a pseudo-terminal,
//! monitors output for permission prompts, and auto-approves or denies
//! them based on Cedar policy evaluation. Detects stalls and nudges the
//! agent to keep working.
//!
//! # Architecture
//!
//! - [`pty::PtySession`]: manages the child process in a pseudo-terminal
//! - [`adapter::AgentAdapter`]: trait for detecting permission prompts in output
//! - [`adapters`]: built-in adapters for Claude Code, generic regex, and passthrough
//! - [`stall::StallDetector`]: timer-based idle detection with nudge strategies
//! - [`output::OutputBuffer`]: ring buffer of recent output lines
//! - [`ansi`]: ANSI escape sequence stripping
//! - [`supervisor::PilotSupervisor`]: main poll loop orchestrating all components

pub mod adapter;
pub mod adapters;
pub mod ansi;
pub mod driver;
pub mod drivers;
pub mod json_stream;
pub mod jsonl;
pub mod output;
pub mod pty;
pub mod session;
pub mod stall;
pub mod supervisor;
pub mod tmux;
