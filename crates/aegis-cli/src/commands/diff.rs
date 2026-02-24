//! Compare two audit sessions for forensic analysis.
//!
//! `aegis diff NAME --session1 UUID --session2 UUID` shows files accessed
//! in each session, highlighting differences.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use crate::commands::DATETIME_SHORT_FMT;
use crate::commands::init::open_store;

/// Run `aegis diff NAME --session1 UUID1 --session2 UUID2`.
pub fn run(config_name: &str, session1_str: &str, session2_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let s1_id: uuid::Uuid = session1_str
        .parse()
        .with_context(|| format!("invalid --session1 UUID: '{session1_str}'"))?;
    let s2_id: uuid::Uuid = session2_str
        .parse()
        .with_context(|| format!("invalid --session2 UUID: '{session2_str}'"))?;

    // Load session metadata
    let s1_meta = store
        .get_session(&s1_id)
        .context("failed to get session1")?
        .with_context(|| format!("session1 not found: {session1_str}; use 'aegis audit sessions {config_name}' to list sessions"))?;
    let s2_meta = store
        .get_session(&s2_id)
        .context("failed to get session2")?
        .with_context(|| format!("session2 not found: {session2_str}; use 'aegis audit sessions {config_name}' to list sessions"))?;

    // Load entries for each session
    let s1_entries = store
        .query_by_session(&s1_id)
        .context("failed to query session1 entries")?;
    let s2_entries = store
        .query_by_session(&s2_id)
        .context("failed to query session2 entries")?;

    // Build resource maps: action_kind -> set of resource paths
    let s1_resources = build_resource_map(&s1_entries);
    let s2_resources = build_resource_map(&s2_entries);

    // Compute set differences
    let all_keys: BTreeSet<&str> = s1_resources
        .keys()
        .chain(s2_resources.keys())
        .map(|k| k.as_str())
        .collect();

    // Print header
    println!("Session Comparison");
    println!("==================");
    let s1_short: String = session1_str.chars().take(8).collect();
    let s2_short: String = session2_str.chars().take(8).collect();
    println!(
        "Session A: {s1_short}... ({}, {} {})",
        s1_meta.start_time.format(DATETIME_SHORT_FMT),
        s1_meta.command,
        s1_meta.args.join(" "),
    );
    println!(
        "Session B: {s2_short}... ({}, {} {})",
        s2_meta.start_time.format(DATETIME_SHORT_FMT),
        s2_meta.command,
        s2_meta.args.join(" "),
    );
    println!();

    // Categorize resources into only-A, only-B, common
    let mut only_a: Vec<String> = Vec::new();
    let mut only_b: Vec<String> = Vec::new();
    let mut common: Vec<String> = Vec::new();

    for key in &all_keys {
        let in_a = s1_resources.contains_key(*key);
        let in_b = s2_resources.contains_key(*key);

        if in_a && !in_b {
            only_a.push(key.to_string());
        } else if !in_a && in_b {
            only_b.push(key.to_string());
        } else {
            common.push(key.to_string());
        }
    }

    print_section("Files only in A:", &only_a);
    print_section("Files only in B:", &only_b);
    print_section("Common files:", &common);

    // Action count comparison
    let a_count = s1_entries.len();
    let b_count = s2_entries.len();
    let diff = b_count as i64 - a_count as i64;
    let diff_str = if diff > 0 {
        format!("+{diff}")
    } else if diff < 0 {
        format!("{diff}")
    } else {
        "0".to_string()
    };

    println!("Actions: A={a_count} B={b_count} ({diff_str})");

    // Denied actions comparison
    let a_denied = s1_entries.iter().filter(|e| e.decision == "Deny").count();
    let b_denied = s2_entries.iter().filter(|e| e.decision == "Deny").count();
    if a_denied > 0 || b_denied > 0 {
        println!("Denied:  A={a_denied} B={b_denied}");
    }

    Ok(())
}

/// Print a labeled section of resource names, or "(none)" if empty.
fn print_section(header: &str, items: &[String]) {
    println!("{header}");
    if items.is_empty() {
        println!("  (none)");
    } else {
        for item in items {
            println!("  {item}");
        }
    }
    println!();
}

/// Build a map of "action_kind:resource" -> count from audit entries.
///
/// The action_kind is a JSON string like `{"FileRead":{"path":"/tmp/file.txt"}}`.
/// We extract the variant name and resource for display.
fn build_resource_map(entries: &[aegis_ledger::AuditEntry]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for entry in entries {
        // Try to extract a human-readable key from the action_kind JSON
        let key = aegis_types::ActionKind::display_from_json(&entry.action_kind);
        *map.entry(key).or_insert(0) += 1;
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_resource_map_counts() {
        let entries = vec![
            aegis_ledger::AuditEntry {
                entry_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                action_id: uuid::Uuid::new_v4(),
                action_kind: r#"{"FileRead":{"path":"/a"}}"#.to_string(),
                principal: "agent".to_string(),
                decision: "Allow".to_string(),
                reason: "ok".to_string(),
                policy_id: None,
                prev_hash: "genesis".to_string(),
                entry_hash: "abc".to_string(),
            },
            aegis_ledger::AuditEntry {
                entry_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                action_id: uuid::Uuid::new_v4(),
                action_kind: r#"{"FileRead":{"path":"/a"}}"#.to_string(),
                principal: "agent".to_string(),
                decision: "Allow".to_string(),
                reason: "ok".to_string(),
                policy_id: None,
                prev_hash: "abc".to_string(),
                entry_hash: "def".to_string(),
            },
        ];

        let map = build_resource_map(&entries);
        assert_eq!(map.get("FileRead /a"), Some(&2));
    }

    #[test]
    fn build_resource_map_multiple_actions() {
        let entries = vec![
            aegis_ledger::AuditEntry {
                entry_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                action_id: uuid::Uuid::new_v4(),
                action_kind: r#"{"FileRead":{"path":"/a"}}"#.to_string(),
                principal: "agent".to_string(),
                decision: "Allow".to_string(),
                reason: "ok".to_string(),
                policy_id: None,
                prev_hash: "genesis".to_string(),
                entry_hash: "abc".to_string(),
            },
            aegis_ledger::AuditEntry {
                entry_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                action_id: uuid::Uuid::new_v4(),
                action_kind: r#"{"FileWrite":{"path":"/b"}}"#.to_string(),
                principal: "agent".to_string(),
                decision: "Deny".to_string(),
                reason: "blocked".to_string(),
                policy_id: None,
                prev_hash: "abc".to_string(),
                entry_hash: "def".to_string(),
            },
        ];

        let map = build_resource_map(&entries);
        assert_eq!(map.get("FileRead /a"), Some(&1));
        assert_eq!(map.get("FileWrite /b"), Some(&1));
        assert_eq!(map.len(), 2);
    }
}
