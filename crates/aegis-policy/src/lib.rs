//! Cedar policy engine for Aegis authorization.
//!
//! Evaluates actions against Cedar policies using the Aegis entity namespace.
//! Supports policy loading from files, hot-reload, and built-in templates.

pub mod builtin;
pub mod engine;
pub mod schema;

pub use engine::PolicyEngine;
pub use schema::{default_schema, AEGIS_SCHEMA};
