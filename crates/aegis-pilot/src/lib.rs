//! PTY-based supervision primitives for probe execution.
//!
//! Spawns a target agent in a pseudo-terminal, monitors output for
//! permission prompts, and applies Cedar policy decisions during tests.
//! Detects stalls and provides session-level supervision utilities.
//!
//! # Architecture
//!
//! - [`pty::PtySession`]: manages the child process in a pseudo-terminal
//! - [`adapter::AgentAdapter`]: trait for detecting permission prompts in output
//! - [`adapters`]: built-in adapters for Claude Code, generic regex, and passthrough
//! - [`stall::StallDetector`]: timer-based idle detection with nudge strategies
//! - [`output::OutputBuffer`]: ring buffer of recent output lines
//! - [`ansi`]: ANSI escape sequence stripping
//! - [`supervisor::run`]: main poll loop orchestrating all components

pub mod adapter;
pub mod adapters;
pub mod ansi;
pub mod compaction;
pub mod json_events;
pub mod json_stream;
pub mod jsonl;
pub mod kill_tree;
pub mod ndjson_fmt;
pub mod output;
pub mod pty;
pub mod session;
pub mod stall;
pub mod supervisor;
pub mod tmux;
