//! Format Claude Code stream-json NDJSON output for human-readable display.
//!
//! This module re-exports the formatter from `aegis-pilot::ndjson_fmt` so that
//! both the daemon and the CLI can share the same implementation.

pub use aegis_pilot::ndjson_fmt::format_ndjson_line;
