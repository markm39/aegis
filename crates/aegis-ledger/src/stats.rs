//! Aggregate statistics for compliance reporting.
//!
//! Computes summary metrics from audit entries: total counts, deny rates,
//! breakdowns by action kind and principal, and integrity status.

use serde::{Deserialize, Serialize};

use aegis_types::{ActionKind, AegisError};

use crate::filter::AuditFilter;
use crate::store::AuditStore;

/// Maximum number of top resources to include in stats.
const TOP_RESOURCES_LIMIT: usize = 10;

/// Summary statistics for a set of audit entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total number of audit entries.
    pub total_entries: usize,
    /// Total number of sessions.
    pub total_sessions: usize,
    /// Number of entries with an Allow decision.
    pub allow_count: usize,
    /// Number of entries with a Deny decision.
    pub deny_count: usize,
    /// Ratio of denied entries to total (0.0 to 1.0).
    pub deny_rate: f64,
    /// Entry counts grouped by action kind, sorted by count descending.
    pub entries_by_action: Vec<(String, usize)>,
    /// Entry counts grouped by principal, sorted by count descending.
    pub entries_by_principal: Vec<(String, usize)>,
    /// Whether the hash chain integrity is valid.
    pub integrity_valid: bool,
    /// Number of policy snapshot changes detected.
    pub policy_changes: usize,
    /// Top accessed resources (extracted from action_kind JSON), sorted by count descending.
    pub top_resources: Vec<(String, usize)>,
    /// Earliest entry timestamp, if any.
    pub earliest_entry: Option<String>,
    /// Latest entry timestamp, if any.
    pub latest_entry: Option<String>,
}

impl AuditStore {
    /// Compute aggregate statistics for entries matching the given filter.
    pub fn compute_stats(
        &self,
        filter: &AuditFilter,
        config_name: &str,
    ) -> Result<AuditStats, AegisError> {
        // Get decision counts
        let decision_counts = self.count_by_decision(filter)?;
        let allow_count = decision_counts
            .iter()
            .find(|(d, _)| d == "Allow")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let deny_count = decision_counts
            .iter()
            .find(|(d, _)| d == "Deny")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let total_entries = allow_count + deny_count;
        let deny_rate = if total_entries > 0 {
            deny_count as f64 / total_entries as f64
        } else {
            0.0
        };

        // Get action kind breakdown
        let entries_by_action = self.count_by_action_kind(filter)?;

        // Get principal breakdown
        let entries_by_principal = self.count_by_principal(filter)?;

        // Session count
        let total_sessions = self.count_sessions(config_name)?;

        // Integrity check
        let integrity = self.verify_integrity()?;

        // Policy change count
        let policy_changes = self.count_policy_snapshots(config_name)?;

        // Top resources
        let top_resources = self.top_resources(filter, TOP_RESOURCES_LIMIT)?;

        // Time range
        let (earliest_entry, latest_entry) = self.time_range()?;

        Ok(AuditStats {
            total_entries,
            total_sessions,
            allow_count,
            deny_count,
            deny_rate,
            entries_by_action,
            entries_by_principal,
            integrity_valid: integrity.valid,
            policy_changes,
            top_resources,
            earliest_entry,
            latest_entry,
        })
    }

    /// Count entries grouped by principal for entries matching the filter.
    fn count_by_principal(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<(String, usize)>, AegisError> {
        self.count_grouped_by("principal", filter)
    }

    /// Return the top N most-accessed resources, extracted from action_kind JSON.
    fn top_resources(
        &self,
        filter: &AuditFilter,
        limit: usize,
    ) -> Result<Vec<(String, usize)>, AegisError> {
        let raw = self.count_grouped_by("action_kind", filter)?;

        // Merge counts by human-readable resource name (multiple action_kind JSON
        // variants may map to the same display string via ActionKind::Display).
        let mut resource_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (action_kind, count) in &raw {
            let key = ActionKind::display_from_json(action_kind);
            *resource_counts.entry(key).or_insert(0) += count;
        }

        let mut sorted: Vec<(String, usize)> = resource_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);

        Ok(sorted)
    }

    /// Get the earliest and latest entry timestamps in a single query.
    fn time_range(&self) -> Result<(Option<String>, Option<String>), AegisError> {
        self.connection()
            .query_row(
                "SELECT MIN(timestamp), MAX(timestamp) FROM audit_log",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| AegisError::LedgerError(format!("time_range query failed: {e}")))
    }

    /// Count the total number of sessions for a config.
    fn count_sessions(&self, config_name: &str) -> Result<usize, AegisError> {
        self.connection()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE config_name = ?1",
                rusqlite::params![config_name],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c as usize)
            .map_err(|e| AegisError::LedgerError(format!("count_sessions failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{Action, ActionKind, Verdict};
    use std::path::PathBuf;

    use crate::test_helpers::test_db;

    fn populate(store: &mut AuditStore) {
        let entries = vec![
            ("alice", ActionKind::FileRead { path: PathBuf::from("/a") }, true),
            ("alice", ActionKind::FileWrite { path: PathBuf::from("/b") }, false),
            ("bob", ActionKind::FileRead { path: PathBuf::from("/c") }, true),
            ("bob", ActionKind::NetConnect { host: "x.com".into(), port: 443 }, false),
            ("alice", ActionKind::DirList { path: PathBuf::from("/d") }, true),
        ];
        for (principal, kind, allow) in entries {
            let action = Action::new(principal, kind);
            let verdict = if allow {
                Verdict::allow(action.id, "ok", None)
            } else {
                Verdict::deny(action.id, "nope", None)
            };
            store.append(&action, &verdict).unwrap();
        }
    }

    #[test]
    fn compute_stats_returns_correct_totals() {
        let (_tmp, mut store) = test_db();
        populate(&mut store);

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.allow_count, 3);
        assert_eq!(stats.deny_count, 2);
        assert!((stats.deny_rate - 0.4).abs() < 0.01);
        assert!(stats.integrity_valid);
    }

    #[test]
    fn compute_stats_action_breakdown() {
        let (_tmp, mut store) = test_db();
        populate(&mut store);

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        let total_by_action: usize = stats.entries_by_action.iter().map(|(_, c)| c).sum();
        assert_eq!(total_by_action, 5);
    }

    #[test]
    fn compute_stats_principal_breakdown() {
        let (_tmp, mut store) = test_db();
        populate(&mut store);

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        let alice = stats
            .entries_by_principal
            .iter()
            .find(|(p, _)| p == "alice")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let bob = stats
            .entries_by_principal
            .iter()
            .find(|(p, _)| p == "bob")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert_eq!(alice, 3);
        assert_eq!(bob, 2);
    }

    #[test]
    fn compute_stats_empty_ledger() {
        let (_tmp, store) = test_db();

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.deny_rate, 0.0);
        assert!(stats.integrity_valid);
    }

    #[test]
    fn compute_stats_time_range() {
        let (_tmp, mut store) = test_db();
        populate(&mut store);

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        assert!(stats.earliest_entry.is_some());
        assert!(stats.latest_entry.is_some());
    }

    #[test]
    fn compute_stats_top_resources() {
        let (_tmp, mut store) = test_db();
        populate(&mut store);

        let stats = store
            .compute_stats(&AuditFilter::default(), "test")
            .unwrap();

        assert!(!stats.top_resources.is_empty());
        let total: usize = stats.top_resources.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn extract_resource_display_file_read() {
        let json = r#"{"FileRead":{"path":"/tmp/test.txt"}}"#;
        let display = ActionKind::display_from_json(json);
        assert_eq!(display, "FileRead /tmp/test.txt");
    }

    #[test]
    fn extract_resource_display_net_connect() {
        let json = r#"{"NetConnect":{"host":"example.com","port":443}}"#;
        let display = ActionKind::display_from_json(json);
        assert_eq!(display, "NetConnect example.com:443");
    }

    #[test]
    fn extract_resource_display_invalid_json() {
        let display = ActionKind::display_from_json("not json");
        assert_eq!(display, "not json");
    }

    #[test]
    fn extract_resource_display_unknown_json() {
        // JSON that doesn't match ActionKind falls back to raw string
        let json = r#"{"CustomAction":{}}"#;
        let display = ActionKind::display_from_json(json);
        assert_eq!(display, json);
    }
}
