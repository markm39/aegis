//! Deprecated: `aegis run` is now handled by `aegis wrap`.
//!
//! The `Commands::Run` match arm in `main.rs` delegates directly to
//! `wrap::run()` with a deprecation notice. This module is retained
//! only so that existing references (CLAUDE.md, tests, docs) don't
//! break immediately.
