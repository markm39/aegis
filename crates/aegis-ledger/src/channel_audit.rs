//! Channel audit logging for messaging channels (Telegram, etc.).
//!
//! Records metadata about messages flowing through channels without storing
//! raw content. Only a SHA-256 hash of the message content is recorded,
//! preserving privacy while enabling audit trail verification.

use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use aegis_types::AegisError;

use crate::store::AuditStore;

/// Direction of a channel message relative to the Aegis system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelDirection {
    /// Message received from an external source (e.g., user via Telegram).
    Inbound,
    /// Message sent to an external destination (e.g., notification to user).
    Outbound,
}

impl std::fmt::Display for ChannelDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDirection::Inbound => write!(f, "Inbound"),
            ChannelDirection::Outbound => write!(f, "Outbound"),
        }
    }
}

impl std::str::FromStr for ChannelDirection {
    type Err = AegisError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Inbound" => Ok(ChannelDirection::Inbound),
            "Outbound" => Ok(ChannelDirection::Outbound),
            _ => Err(AegisError::LedgerError(format!(
                "invalid channel direction: {s:?} (expected Inbound or Outbound)"
            ))),
        }
    }
}

/// A single entry in the channel audit log.
///
/// Records metadata about a message flowing through a channel without
/// storing the raw content. The `message_hash` is a SHA-256 digest of
/// the original message content, allowing verification without exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelAuditEntry {
    /// Unique identifier for this channel audit entry.
    pub entry_id: Uuid,
    /// Name of the channel (e.g., "telegram", "webhook").
    pub channel_name: String,
    /// Whether the message was inbound or outbound.
    pub direction: ChannelDirection,
    /// SHA-256 hex digest of the raw message content (never the content itself).
    pub message_hash: String,
    /// Number of recipients the message was sent to (0 for inbound).
    pub recipient_count: u32,
    /// Whether the message included interactive buttons (inline keyboards, etc.).
    pub has_buttons: bool,
    /// When this entry was created.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the previous channel audit entry (hash-chain linkage).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's contents.
    pub entry_hash: String,
}

/// Compute a SHA-256 hash of message content for audit logging.
///
/// The raw content is never stored -- only this hash is persisted in the
/// channel audit log. This allows verifying that a specific message was
/// sent/received without exposing the actual content.
pub fn hash_message_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the entry hash for a channel audit entry.
#[allow(clippy::too_many_arguments)]
fn compute_channel_entry_hash(
    entry_id: &Uuid,
    channel_name: &str,
    direction: &ChannelDirection,
    message_hash: &str,
    recipient_count: u32,
    has_buttons: bool,
    timestamp: &DateTime<Utc>,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry_id.to_string());
    hasher.update(channel_name);
    hasher.update(direction.to_string());
    hasher.update(message_hash);
    hasher.update(recipient_count.to_string());
    hasher.update(has_buttons.to_string());
    hasher.update(timestamp.to_rfc3339());
    hasher.update(prev_hash);
    hex::encode(hasher.finalize())
}

impl AuditStore {
    /// Insert a new channel audit entry.
    ///
    /// The `message_hash` must be a pre-computed SHA-256 hex digest of the
    /// message content. Use [`hash_message_content`] to compute it. Raw
    /// message content must never be passed to this method.
    pub fn insert_channel_audit(
        &mut self,
        channel_name: &str,
        direction: ChannelDirection,
        message_hash: &str,
        recipient_count: u32,
        has_buttons: bool,
    ) -> Result<ChannelAuditEntry, AegisError> {
        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let prev_hash = self.latest_channel_hash().unwrap_or_else(|| "genesis".to_string());

        let entry_hash = compute_channel_entry_hash(
            &entry_id,
            channel_name,
            &direction,
            message_hash,
            recipient_count,
            has_buttons,
            &timestamp,
            &prev_hash,
        );

        self.connection()
            .execute(
                "INSERT INTO channel_audit_log (entry_id, channel_name, direction, message_hash, recipient_count, has_buttons, timestamp, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    entry_id.to_string(),
                    channel_name,
                    direction.to_string(),
                    message_hash,
                    recipient_count,
                    has_buttons as i32,
                    timestamp.to_rfc3339(),
                    prev_hash,
                    entry_hash,
                ],
            )
            .map_err(|e| AegisError::LedgerError(format!("failed to insert channel audit entry: {e}")))?;

        let entry = ChannelAuditEntry {
            entry_id,
            channel_name: channel_name.to_string(),
            direction,
            message_hash: message_hash.to_string(),
            recipient_count,
            has_buttons,
            timestamp,
            prev_hash,
            entry_hash,
        };

        // Notify middleware
        self.notify_channel_middleware(&entry);

        Ok(entry)
    }

    /// Query the last N channel audit entries, ordered by id DESC.
    pub fn query_channel_audit_last(&self, n: usize) -> Result<Vec<ChannelAuditEntry>, AegisError> {
        let mut stmt = self
            .connection()
            .prepare(
                "SELECT entry_id, channel_name, direction, message_hash, recipient_count, has_buttons, timestamp, prev_hash, entry_hash
                 FROM channel_audit_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| AegisError::LedgerError(format!("query_channel_audit_last prepare: {e}")))?;

        let rows = stmt
            .query_map(params![n as i64], |row| {
                let direction_str: String = row.get(2)?;
                let direction: ChannelDirection = direction_str.parse().map_err(|e: AegisError| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
                    )
                })?;

                Ok(ChannelAuditEntry {
                    entry_id: crate::parse_helpers::parse_uuid(&row.get::<_, String>(0)?, 0)?,
                    channel_name: row.get(1)?,
                    direction,
                    message_hash: row.get(3)?,
                    recipient_count: row.get::<_, i64>(4).map(|v| v as u32)?,
                    has_buttons: row.get::<_, i32>(5).map(|v| v != 0)?,
                    timestamp: crate::parse_helpers::parse_datetime(&row.get::<_, String>(6)?, 6)?,
                    prev_hash: row.get(7)?,
                    entry_hash: row.get(8)?,
                })
            })
            .map_err(|e| AegisError::LedgerError(format!("query_channel_audit_last failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AegisError::LedgerError(format!("query_channel_audit_last read: {e}")))
    }

    /// Return the latest channel audit entry hash, or None if the table is empty.
    fn latest_channel_hash(&self) -> Option<String> {
        self.connection()
            .query_row(
                "SELECT entry_hash FROM channel_audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_db_path;

    #[test]
    fn channel_audit_entry_insert_and_query() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let msg_hash = hash_message_content("Hello, world!");
        let entry = store
            .insert_channel_audit("telegram", ChannelDirection::Outbound, &msg_hash, 1, true)
            .unwrap();

        assert_eq!(entry.channel_name, "telegram");
        assert_eq!(entry.direction, ChannelDirection::Outbound);
        assert_eq!(entry.message_hash, msg_hash);
        assert_eq!(entry.recipient_count, 1);
        assert!(entry.has_buttons);
        assert_eq!(entry.prev_hash, "genesis");

        let results = store.query_channel_audit_last(10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, entry.entry_id);
    }

    #[test]
    fn channel_audit_message_hash_not_content() {
        // Security test: verify that the raw message content is never stored.
        // Only the SHA-256 hash should appear in the entry.
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let secret_message = "This is a secret approval command with sensitive data";
        let msg_hash = hash_message_content(secret_message);

        let entry = store
            .insert_channel_audit("telegram", ChannelDirection::Inbound, &msg_hash, 0, false)
            .unwrap();

        // The entry must contain the hash, not the raw content
        assert_eq!(entry.message_hash, msg_hash);
        assert_ne!(entry.message_hash, secret_message);

        // Verify the hash is a valid SHA-256 hex string (64 hex chars)
        assert_eq!(entry.message_hash.len(), 64);
        assert!(entry.message_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify the raw content cannot be recovered from any field
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(
            !serialized.contains(secret_message),
            "raw message content must never appear in the serialized entry"
        );
    }

    #[test]
    fn channel_audit_hash_chain() {
        let tmp = test_db_path();
        let mut store = AuditStore::open(tmp.path()).unwrap();

        let h1 = hash_message_content("msg1");
        let e1 = store
            .insert_channel_audit("telegram", ChannelDirection::Outbound, &h1, 1, false)
            .unwrap();

        let h2 = hash_message_content("msg2");
        let e2 = store
            .insert_channel_audit("telegram", ChannelDirection::Inbound, &h2, 0, false)
            .unwrap();

        // Second entry's prev_hash should be the first entry's hash
        assert_eq!(e2.prev_hash, e1.entry_hash);
    }

    #[test]
    fn channel_direction_serialization() {
        // Test round-trip serialization of ChannelDirection
        let inbound = ChannelDirection::Inbound;
        let outbound = ChannelDirection::Outbound;

        assert_eq!(inbound.to_string(), "Inbound");
        assert_eq!(outbound.to_string(), "Outbound");

        assert_eq!("Inbound".parse::<ChannelDirection>().unwrap(), ChannelDirection::Inbound);
        assert_eq!("Outbound".parse::<ChannelDirection>().unwrap(), ChannelDirection::Outbound);
        assert!("Invalid".parse::<ChannelDirection>().is_err());

        // JSON serialization
        let json = serde_json::to_string(&inbound).unwrap();
        let back: ChannelDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inbound);
    }
}
