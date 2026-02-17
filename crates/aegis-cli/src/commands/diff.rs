//! Compare two audit sessions for forensic analysis.
//!
//! `aegis diff NAME --session1 UUID --session2 UUID` shows files accessed
//! in each session, highlighting differences.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use aegis_ledger::AuditStore;

use crate::commands::init::load_config;

/// Run `aegis diff NAME --session1 UUID1 --session2 UUID2`.
pub fn run(config_name: &str, session1_str: &str, session2_str: &str) -> Result<()> {
    let config = load_config(config_name)?;
    let store = AuditStore::open(&config.ledger_path).context("failed to open audit store")?;

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
    println!(
        "Session A: {} ({}, {} {})",
        &session1_str[..8.min(session1_str.len())],
        s1_meta.start_time.format("%Y-%m-%d %H:%M"),
        s1_meta.command,
        s1_meta.args.join(" "),
    );
    println!(
        "Session B: {} ({}, {} {})",
        &session2_str[..8.min(session2_str.len())],
        s2_meta.start_time.format("%Y-%m-%d %H:%M"),
        s2_meta.command,
        s2_meta.args.join(" "),
    );
    println!();

    // Files only in A
    let mut only_a: Vec<(String, String)> = Vec::new();
    let mut only_b: Vec<(String, String)> = Vec::new();
    let mut common: Vec<(String, String)> = Vec::new();

    for key in &all_keys {
        let in_a = s1_resources.contains_key(*key);
        let in_b = s2_resources.contains_key(*key);

        if in_a && !in_b {
            only_a.push((key.to_string(), "(A only)".to_string()));
        } else if !in_a && in_b {
            only_b.push((key.to_string(), "(B only)".to_string()));
        } else {
            common.push((key.to_string(), "(both)".to_string()));
        }
    }

    println!("Files only in A:");
    if only_a.is_empty() {
        println!("  (none)");
    } else {
        for (resource, _) in &only_a {
            println!("  {resource}");
        }
    }
    println!();

    println!("Files only in B:");
    if only_b.is_empty() {
        println!("  (none)");
    } else {
        for (resource, _) in &only_b {
            println!("  {resource}");
        }
    }
    println!();

    println!("Common files:");
    if common.is_empty() {
        println!("  (none)");
    } else {
        for (resource, _) in &common {
            println!("  {resource}");
        }
    }
    println!();

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

/// Build a map of "action_kind:resource" -> count from audit entries.
///
/// The action_kind is a JSON string like `{"FileRead":{"path":"/tmp/file.txt"}}`.
/// We extract the variant name and resource for display.
fn build_resource_map(
    entries: &[aegis_ledger::AuditEntry],
) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for entry in entries {
        // Try to extract a human-readable key from the action_kind JSON
        let key = extract_resource_key(&entry.action_kind);
        *map.entry(key).or_insert(0) += 1;
    }
    map
}

/// Extract a display-friendly key from the action_kind JSON string.
pub fn extract_resource_key(action_kind: &str) -> String {
    // Parse as JSON to get the variant name and resource
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(action_kind) {
        if let Some(obj) = value.as_object() {
            if let Some((variant, inner)) = obj.iter().next() {
                // Extract the path or relevant field
                if let Some(path) = inner.get("path").and_then(|p| p.as_str()) {
                    return format!("{variant}  {path}");
                }
                if let Some(host) = inner.get("host").and_then(|h| h.as_str()) {
                    let port = inner.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                    return format!("{variant}  {host}:{port}");
                }
                if let Some(command) = inner.get("command").and_then(|c| c.as_str()) {
                    return format!("{variant}  {command}");
                }
                if let Some(tool) = inner.get("tool").and_then(|t| t.as_str()) {
                    return format!("{variant}  {tool}");
                }
                if let Some(url) = inner.get("url").and_then(|u| u.as_str()) {
                    return format!("{variant}  {url}");
                }
                return variant.clone();
            }
        }
    }
    action_kind.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_resource_key_file_read() {
        let json = r#"{"FileRead":{"path":"/tmp/test.txt"}}"#;
        let key = extract_resource_key(json);
        assert_eq!(key, "FileRead  /tmp/test.txt");
    }

    #[test]
    fn extract_resource_key_net_connect() {
        let json = r#"{"NetConnect":{"host":"example.com","port":443}}"#;
        let key = extract_resource_key(json);
        assert_eq!(key, "NetConnect  example.com:443");
    }

    #[test]
    fn extract_resource_key_process_spawn() {
        let json = r#"{"ProcessSpawn":{"command":"echo","args":["hello"]}}"#;
        let key = extract_resource_key(json);
        assert_eq!(key, "ProcessSpawn  echo");
    }

    #[test]
    fn extract_resource_key_invalid_json() {
        let key = extract_resource_key("not json");
        assert_eq!(key, "not json");
    }

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
        assert_eq!(map.get("FileRead  /a"), Some(&2));
    }

    #[test]
    fn extract_resource_key_tool_call() {
        let json = r#"{"ToolCall":{"tool":"write_file","args":null}}"#;
        let key = extract_resource_key(json);
        assert_eq!(key, "ToolCall  write_file");
    }

    #[test]
    fn extract_resource_key_empty_object() {
        let json = r#"{}"#;
        let key = extract_resource_key(json);
        // Empty JSON object -> no variant, returns raw string
        assert_eq!(key, "{}");
    }

    #[test]
    fn extract_resource_key_unknown_variant_no_fields() {
        let json = r#"{"CustomAction":{"unknown":"data"}}"#;
        let key = extract_resource_key(json);
        // No recognized field -> just the variant name
        assert_eq!(key, "CustomAction");
    }

    #[test]
    fn extract_resource_key_net_request() {
        let json = r#"{"NetRequest":{"method":"GET","url":"https://example.com"}}"#;
        let key = extract_resource_key(json);
        assert_eq!(key, "NetRequest  https://example.com");
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
        assert_eq!(map.get("FileRead  /a"), Some(&1));
        assert_eq!(map.get("FileWrite  /b"), Some(&1));
        assert_eq!(map.len(), 2);
    }
}
