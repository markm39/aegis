//! Helpers for safely parsing UUID and DateTime values from SQLite rows.
//!
//! These convert parse failures into `rusqlite::Error` instead of panicking,
//! which is critical because database rows may contain corrupt or legacy data.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Parse a UUID string from a SQLite column, returning a `rusqlite::Error` on failure.
pub(crate) fn parse_uuid(s: &str, col: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            col,
            rusqlite::types::Type::Text,
            Box::new(e),
        )
    })
}

/// Parse an RFC 3339 datetime string from a SQLite column, returning a `rusqlite::Error` on failure.
pub(crate) fn parse_datetime(s: &str, col: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.into())
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                col,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
}
