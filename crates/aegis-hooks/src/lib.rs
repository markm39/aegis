//! User-extensible hook modules for Aegis agent supervision.
//!
//! This crate provides a system for users to write hook handlers in any
//! scripting language (JavaScript, TypeScript, Shell, Python) and have them
//! automatically discovered and executed at key lifecycle events.
//!
//! ## Quick Start
//!
//! Place script files in `.aegis/hooks/` with names matching event types:
//!
//! ```text
//! .aegis/hooks/
//!   pre_tool_use.sh     # Runs before each tool call
//!   on_message.py       # Runs on message events
//!   on_agent_start.js   # Runs when agents start
//! ```
//!
//! Or use `hooks.toml` for explicit configuration:
//!
//! ```toml
//! [[hooks]]
//! event = "pre_tool_use"
//! script = "check_permissions.sh"
//! timeout_ms = 5000
//!
//! [[hooks]]
//! event = "on_*"
//! script = "audit_logger.py"
//! ```
//!
//! ## Architecture
//!
//! - [`events`]: Event types and response structures for hook communication
//! - [`config`]: `hooks.toml` manifest parsing and configuration
//! - [`discovery`]: Automatic hook discovery from filesystem conventions
//! - [`runner`]: Script execution engine with timeout and error handling
//! - [`manager`]: High-level orchestrator integrating discovery and execution

pub mod config;
pub mod discovery;
pub mod events;
pub mod manager;
pub mod runner;
