//! Tool definition, registry, and executor for the Aegis agent supervision platform.
//!
//! This crate provides the core abstraction for tools that agents can invoke:
//!
//! - [`ToolDefinition`] -- the trait every tool implements
//! - [`ToolOutput`] / [`ToolOutputMetadata`] -- structured execution results
//! - [`ToolInfo`] -- summary used in registry listings
//! - [`ToolRegistry`] -- thread-safe tool storage and lookup
//! - [`ToolExecutor`] -- security pipeline: policy gate, audit logging, timeout

pub mod definition;
pub mod executor;
pub mod registry;

pub use definition::{ToolDefinition, ToolInfo, ToolOutput, ToolOutputMetadata};
pub use executor::{
    AuditSink, ExecutionError, ExecutorConfig, PolicyDecision, PolicyGate, ToolAuditRecord,
    ToolExecutor,
};
pub use registry::ToolRegistry;
