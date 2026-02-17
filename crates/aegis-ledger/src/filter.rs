//! Composable filter for audit log queries.
//!
//! Builds a parameterized SQL WHERE clause dynamically from optional
//! filter criteria. All filters are AND-combined. Each `Some` field
//! adds a condition; `None` fields are ignored.

use chrono::{DateTime, Utc};

/// A composable filter for querying the audit log.
///
/// Use `Default::default()` for an empty filter (matches everything),
/// then set individual fields to narrow results.
#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    /// Only entries at or after this timestamp.
    pub from: Option<DateTime<Utc>>,
    /// Only entries at or before this timestamp.
    pub to: Option<DateTime<Utc>>,
    /// Only entries with this action_kind (substring match on the JSON).
    pub action_kind: Option<String>,
    /// Only entries with this decision ("Allow" or "Deny").
    pub decision: Option<String>,
    /// Only entries for this principal.
    pub principal: Option<String>,
    /// Only entries belonging to this session.
    pub session_id: Option<String>,
    /// Full-text search on the reason field (case-insensitive substring).
    pub reason_contains: Option<String>,
    /// Maximum number of entries to return.
    pub limit: Option<usize>,
    /// Number of entries to skip (for pagination).
    pub offset: Option<usize>,
}

/// A built SQL fragment with its positional parameters.
pub(crate) struct SqlFragment {
    /// The WHERE clause (without the "WHERE" keyword), or empty if no filters.
    pub where_clause: String,
    /// The positional parameter values, in order.
    pub params: Vec<Box<dyn rusqlite::types::ToSql>>,
    /// The LIMIT clause value, if any.
    pub limit: Option<usize>,
    /// The OFFSET clause value, if any.
    pub offset: Option<usize>,
}

impl AuditFilter {
    /// Build a SQL WHERE clause and parameter list from this filter.
    ///
    /// Parameters use positional `?N` placeholders starting from 1.
    /// The returned `SqlFragment` can be appended to a base query.
    pub(crate) fn to_sql(&self) -> SqlFragment {
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1usize;

        if let Some(ref from) = self.from {
            conditions.push(format!("timestamp >= ?{idx}"));
            params.push(Box::new(from.to_rfc3339()));
            idx += 1;
        }

        if let Some(ref to) = self.to {
            conditions.push(format!("timestamp <= ?{idx}"));
            params.push(Box::new(to.to_rfc3339()));
            idx += 1;
        }

        if let Some(ref action_kind) = self.action_kind {
            // action_kind is stored as JSON like {"FileRead":{"path":"/tmp/test.txt"}}
            // We match on the variant name at the start of the JSON string.
            conditions.push(format!("action_kind LIKE ?{idx}"));
            params.push(Box::new(format!("{{\"{}\":%", action_kind)));
            idx += 1;
        }

        if let Some(ref decision) = self.decision {
            conditions.push(format!("decision = ?{idx}"));
            params.push(Box::new(decision.clone()));
            idx += 1;
        }

        if let Some(ref principal) = self.principal {
            conditions.push(format!("principal = ?{idx}"));
            params.push(Box::new(principal.clone()));
            idx += 1;
        }

        if let Some(ref session_id) = self.session_id {
            conditions.push(format!("session_id = ?{idx}"));
            params.push(Box::new(session_id.clone()));
            idx += 1;
        }

        if let Some(ref reason_contains) = self.reason_contains {
            conditions.push(format!("reason LIKE '%' || ?{idx} || '%'"));
            params.push(Box::new(reason_contains.clone()));
            idx += 1;
        }

        // Suppress unused warning; idx tracks the next parameter slot and must
        // be kept in sync if new filter branches are added above.
        let _ = idx;

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            conditions.join(" AND ")
        };

        SqlFragment {
            where_clause,
            params,
            limit: self.limit,
            offset: self.offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_produces_no_where_clause() {
        let filter = AuditFilter::default();
        let sql = filter.to_sql();
        assert!(sql.where_clause.is_empty());
        assert!(sql.params.is_empty());
    }

    #[test]
    fn single_decision_filter() {
        let filter = AuditFilter {
            decision: Some("Deny".into()),
            ..Default::default()
        };
        let sql = filter.to_sql();
        assert_eq!(sql.where_clause, "decision = ?1");
        assert_eq!(sql.params.len(), 1);
    }

    #[test]
    fn combined_filters() {
        let filter = AuditFilter {
            decision: Some("Allow".into()),
            principal: Some("agent-1".into()),
            action_kind: Some("FileRead".into()),
            ..Default::default()
        };
        let sql = filter.to_sql();
        assert!(sql.where_clause.contains("decision = "));
        assert!(sql.where_clause.contains("principal = "));
        assert!(sql.where_clause.contains("action_kind LIKE "));
        assert_eq!(sql.params.len(), 3);
    }

    #[test]
    fn reason_search_filter() {
        let filter = AuditFilter {
            reason_contains: Some("violation".into()),
            ..Default::default()
        };
        let sql = filter.to_sql();
        assert!(sql.where_clause.contains("reason LIKE"));
        assert_eq!(sql.params.len(), 1);
    }

    #[test]
    fn time_range_filter() {
        let now = Utc::now();
        let filter = AuditFilter {
            from: Some(now - chrono::Duration::hours(1)),
            to: Some(now),
            ..Default::default()
        };
        let sql = filter.to_sql();
        assert!(sql.where_clause.contains("timestamp >= ?1"));
        assert!(sql.where_clause.contains("timestamp <= ?2"));
        assert_eq!(sql.params.len(), 2);
    }

    #[test]
    fn pagination_fields() {
        let filter = AuditFilter {
            limit: Some(20),
            offset: Some(40),
            ..Default::default()
        };
        let sql = filter.to_sql();
        assert_eq!(sql.limit, Some(20));
        assert_eq!(sql.offset, Some(40));
    }
}
