//! In-agent command processing framework.
//!
//! This module provides a unified command system that can be used across
//! agents, the daemon, and external channels (TUI, Telegram, HTTP). Commands
//! are registered in a [`CommandRegistry`], looked up and dispatched by a
//! [`CommandRouter`], and each command implements the [`CommandDef`] trait.
//!
//! # Architecture
//!
//! - [`handler`]: Core types -- [`CommandContext`], [`CommandResult`], [`CommandDef`] trait.
//! - [`registry`]: [`CommandRegistry`] for storing and looking up commands.
//! - [`router`]: [`CommandRouter`] for parsing input, validating, checking
//!   permissions, and dispatching to handlers.
//! - [`builtins`]: Built-in commands (help, status, version) and
//!   [`register_builtins`] to populate a registry.
//!
//! # Security
//!
//! - Command names are validated against injection characters before lookup.
//! - Permission checks run before execution, using a caller-supplied closure
//!   that maps to Cedar policy evaluation.
//! - Each command declares the Cedar action it requires via
//!   [`CommandDef::required_action`].

pub mod builtins;
pub mod handler;
pub mod registry;
pub mod router;

pub use builtins::register_builtins;
pub use handler::{CommandContext, CommandDef, CommandResult};
pub use registry::CommandRegistry;
pub use router::CommandRouter;
