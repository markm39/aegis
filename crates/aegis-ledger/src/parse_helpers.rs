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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_valid() {
        let uuid = Uuid::new_v4();
        let result = parse_uuid(&uuid.to_string(), 0).unwrap();
        assert_eq!(result, uuid);
    }

    #[test]
    fn parse_uuid_invalid_returns_error() {
        let result = parse_uuid("not-a-uuid", 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_empty_returns_error() {
        let result = parse_uuid("", 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_datetime_valid_rfc3339() {
        use chrono::Datelike;
        let result = parse_datetime("2024-01-15T10:30:00+00:00", 1).unwrap();
        assert_eq!(result.year(), 2024);
        assert_eq!(result.month(), 1);
        assert_eq!(result.day(), 15);
    }

    #[test]
    fn parse_datetime_invalid_returns_error() {
        let result = parse_datetime("not-a-date", 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_datetime_empty_returns_error() {
        let result = parse_datetime("", 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_preserves_column_index_in_error() {
        let err = parse_uuid("bad", 7).unwrap_err();
        match err {
            rusqlite::Error::FromSqlConversionFailure(col, _, _) => assert_eq!(col, 7),
            other => panic!("expected FromSqlConversionFailure, got: {other:?}"),
        }
    }

    #[test]
    fn parse_datetime_preserves_column_index_in_error() {
        let err = parse_datetime("bad", 3).unwrap_err();
        match err {
            rusqlite::Error::FromSqlConversionFailure(col, _, _) => assert_eq!(col, 3),
            other => panic!("expected FromSqlConversionFailure, got: {other:?}"),
        }
    }
}
