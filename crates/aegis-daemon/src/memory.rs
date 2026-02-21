//! SQLite-backed key-value memory store for agent context.
//!
//! Provides per-namespace key-value storage with full-text search (FTS5)
//! and optional vector embeddings for similarity search. Reuses the
//! existing rusqlite dependency from aegis-ledger.
//!
//! ## Temporal Decay
//!
//! When enabled, search results are weighted by recency using exponential
//! decay. A configurable half-life controls how quickly older memories
//! lose relevance. Decay only affects ranking weights -- it never deletes
//! entries.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};

use crate::embeddings::{blob_to_embedding, cosine_similarity, embedding_to_blob};

/// Compute temporal decay factor for a memory entry.
///
/// Returns a value in `[0.0, 1.0]` representing how relevant a memory is
/// based on its age. A memory exactly one half-life old returns ~0.5.
/// The formula is `0.5^(hours_since_update / half_life_hours)`.
///
/// Edge cases:
/// - Zero or negative age returns 1.0 (freshest possible).
/// - Very old entries approach 0.0 but never go negative.
/// - Invalid timestamps return 1.0 (fail-safe: never penalize on parse error).
pub fn compute_decay(updated_at: &str, half_life_hours: f64) -> f64 {
    let updated = match chrono::DateTime::parse_from_rfc3339(updated_at) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return 1.0, // fail-safe: don't penalize on bad timestamp
    };

    let now = Utc::now();
    let duration = now.signed_duration_since(updated);
    let hours = duration.num_milliseconds() as f64 / 3_600_000.0;

    if hours <= 0.0 {
        return 1.0;
    }

    if half_life_hours <= 0.0 {
        // Invalid half-life: fail-safe to no decay.
        return 1.0;
    }

    let decay = 0.5_f64.powf(hours / half_life_hours);
    decay.clamp(0.0, 1.0)
}

/// SQLite-backed key-value store with FTS5 full-text search.
pub struct MemoryStore {
    conn: Connection,
}

impl MemoryStore {
    /// Open or create a memory store at the given path.
    ///
    /// Creates the SQLite database file and runs schema migrations
    /// if needed. Enables WAL mode for concurrent read performance.
    pub fn new(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("open memory db: {}", path.display()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_memory (
                namespace TEXT NOT NULL,
                key       TEXT NOT NULL,
                value     TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            );",
        )?;

        // FTS5 external-content table backed by agent_memory.
        // We use content= to point at the main table so FTS shares storage.
        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS agent_memory_fts USING fts5(
                namespace,
                key,
                value,
                content=agent_memory,
                content_rowid=rowid
            );",
        )?;

        // Migration: add embedding column if it doesn't exist yet.
        // SQLite's ALTER TABLE ADD COLUMN is idempotent-safe when we check
        // for the column first.
        let has_embedding: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('agent_memory') WHERE name = 'embedding'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .map(|count| count > 0)?;

        if !has_embedding {
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN embedding BLOB;",
            )?;
        }

        // Migration: add quarantine columns if they don't exist yet.
        let has_quarantined: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('agent_memory') WHERE name = 'quarantined'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .map(|count| count > 0)?;

        if !has_quarantined {
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN quarantined INTEGER DEFAULT 0;",
            )?;
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN quarantine_reason TEXT;",
            )?;
        }

        // Migration: add temporal decay columns if they don't exist yet.
        let has_decay_factor: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('agent_memory') WHERE name = 'decay_factor'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .map(|count| count > 0)?;

        if !has_decay_factor {
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN decay_factor REAL DEFAULT 1.0;",
            )?;
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN access_count INTEGER DEFAULT 0;",
            )?;
            conn.execute_batch(
                "ALTER TABLE agent_memory ADD COLUMN last_accessed TEXT;",
            )?;
        }

        Ok(Self { conn })
    }

    /// Get a value by namespace and key. Returns `None` if the key does not exist.
    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT value FROM agent_memory WHERE namespace = ?1 AND key = ?2")?;

        let mut rows = stmt.query(params![namespace, key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Insert or update a key-value pair. Updates the FTS index accordingly.
    pub fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();

        // Delete old FTS entry if the row already exists.
        let old_rowid: Option<i64> = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))
            .ok();

        if let Some(rowid) = old_rowid {
            // Grab old values for FTS delete.
            let (old_val,): (String,) = self
                .conn
                .prepare_cached(
                    "SELECT value FROM agent_memory WHERE namespace = ?1 AND key = ?2",
                )?
                .query_row(params![namespace, key], |row| Ok((row.get(0)?,)))?;

            self.conn.execute(
                "INSERT INTO agent_memory_fts(agent_memory_fts, rowid, namespace, key, value) VALUES('delete', ?1, ?2, ?3, ?4)",
                params![rowid, namespace, key, old_val],
            )?;
        }

        // Upsert the main row.
        self.conn.execute(
            "INSERT INTO agent_memory (namespace, key, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![namespace, key, value, now],
        )?;

        // Insert new FTS entry.
        let new_rowid: i64 = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))?;

        self.conn.execute(
            "INSERT INTO agent_memory_fts(rowid, namespace, key, value) VALUES(?1, ?2, ?3, ?4)",
            params![new_rowid, namespace, key, value],
        )?;

        Ok(())
    }

    /// Delete a key. Returns `true` if the key existed and was removed.
    pub fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        // Remove FTS entry first.
        let maybe: Option<(i64, String)> = self
            .conn
            .prepare_cached(
                "SELECT rowid, value FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| Ok((row.get(0)?, row.get(1)?)))
            .ok();

        if let Some((rowid, old_val)) = maybe {
            self.conn.execute(
                "INSERT INTO agent_memory_fts(agent_memory_fts, rowid, namespace, key, value) VALUES('delete', ?1, ?2, ?3, ?4)",
                params![rowid, namespace, key, old_val],
            )?;
        }

        let deleted = self.conn.execute(
            "DELETE FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        )?;

        Ok(deleted > 0)
    }

    /// List key-value pairs in a namespace, ordered by most recently updated first.
    pub fn list(&self, namespace: &str, limit: usize) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, value FROM agent_memory WHERE namespace = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![namespace, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Full-text search within a namespace. Returns (key, value, score) tuples
    /// ordered by relevance.
    ///
    /// If `half_life_hours` is `Some`, temporal decay is applied: each result's
    /// raw FTS5 rank is multiplied by a decay factor based on its age. This
    /// causes newer entries to rank higher. The decay factor is always in
    /// `[0.0, 1.0]` and never deletes entries.
    ///
    /// FTS5 rank values are negative (more negative = more relevant), so
    /// we negate them before multiplying by decay to produce positive scores.
    pub fn search(
        &self,
        namespace: &str,
        query: &str,
        limit: usize,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<(String, String, f64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT m.key, m.value, f.rank, m.updated_at
             FROM agent_memory_fts f
             JOIN agent_memory m ON m.rowid = f.rowid
             WHERE agent_memory_fts MATCH ?1
               AND m.namespace = ?2",
        )?;

        let rows = stmt.query_map(params![query, namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut scored: Vec<(String, String, f64)> = Vec::new();
        for row in rows {
            let (key, value, rank, updated_at) = row?;
            // FTS5 rank is negative; negate to get a positive relevance score.
            let raw_score = -rank;
            let final_score = match half_life_hours {
                Some(hl) => raw_score * compute_decay(&updated_at, hl),
                None => raw_score,
            };
            scored.push((key, value, final_score));
        }

        // Sort by final score descending (higher = more relevant).
        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored)
    }

    /// Insert or update a key-value pair together with its embedding vector.
    ///
    /// The embedding is stored as a little-endian f32 BLOB alongside the
    /// text value. Also updates the FTS index.
    pub fn set_with_embedding(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        embedding: &[f32],
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let blob = embedding_to_blob(embedding);

        // Delete old FTS entry if the row already exists.
        let old_rowid: Option<i64> = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))
            .ok();

        if let Some(rowid) = old_rowid {
            let (old_val,): (String,) = self
                .conn
                .prepare_cached(
                    "SELECT value FROM agent_memory WHERE namespace = ?1 AND key = ?2",
                )?
                .query_row(params![namespace, key], |row| Ok((row.get(0)?,)))?;

            self.conn.execute(
                "INSERT INTO agent_memory_fts(agent_memory_fts, rowid, namespace, key, value) VALUES('delete', ?1, ?2, ?3, ?4)",
                params![rowid, namespace, key, old_val],
            )?;
        }

        // Upsert the main row with embedding.
        self.conn.execute(
            "INSERT INTO agent_memory (namespace, key, value, updated_at, embedding)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(namespace, key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at,
                embedding = excluded.embedding",
            params![namespace, key, value, now, blob],
        )?;

        // Insert new FTS entry.
        let new_rowid: i64 = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))?;

        self.conn.execute(
            "INSERT INTO agent_memory_fts(rowid, namespace, key, value) VALUES(?1, ?2, ?3, ?4)",
            params![new_rowid, namespace, key, value],
        )?;

        Ok(())
    }

    /// Search for entries whose embeddings are most similar to the query vector.
    ///
    /// Returns `(key, value, similarity_score)` tuples sorted by descending
    /// cosine similarity. Only entries that have an embedding are considered.
    ///
    /// If `half_life_hours` is `Some`, temporal decay is applied: each result's
    /// raw cosine similarity is multiplied by a decay factor based on its age.
    /// The decay factor is always in `[0.0, 1.0]` and never deletes entries.
    pub fn search_similar(
        &self,
        namespace: &str,
        query_embedding: &[f32],
        limit: usize,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<(String, String, f32)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, value, embedding, updated_at FROM agent_memory WHERE namespace = ?1 AND embedding IS NOT NULL",
        )?;

        let rows = stmt.query_map(params![namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut scored: Vec<(String, String, f32)> = Vec::new();
        for row in rows {
            let (key, value, blob, updated_at) = row?;
            let emb = blob_to_embedding(&blob);
            if emb.len() == query_embedding.len() {
                let raw_score = cosine_similarity(&emb, query_embedding);
                let final_score = match half_life_hours {
                    Some(hl) => raw_score * compute_decay(&updated_at, hl) as f32,
                    None => raw_score,
                };
                scored.push((key, value, final_score));
            }
        }

        // Sort by similarity descending.
        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored)
    }

    /// Store a value and mark it as quarantined with a reason string.
    ///
    /// The value is written to the database but flagged so that
    /// [`MemoryGuard::get_safe`](crate::memory_guard::MemoryGuard::get_safe)
    /// will skip it until an admin explicitly unquarantines it.
    pub fn set_quarantined(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        reason: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();

        // Delete old FTS entry if the row already exists.
        let old_rowid: Option<i64> = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))
            .ok();

        if let Some(rowid) = old_rowid {
            let (old_val,): (String,) = self
                .conn
                .prepare_cached(
                    "SELECT value FROM agent_memory WHERE namespace = ?1 AND key = ?2",
                )?
                .query_row(params![namespace, key], |row| Ok((row.get(0)?,)))?;

            self.conn.execute(
                "INSERT INTO agent_memory_fts(agent_memory_fts, rowid, namespace, key, value) VALUES('delete', ?1, ?2, ?3, ?4)",
                params![rowid, namespace, key, old_val],
            )?;
        }

        // Upsert the main row with quarantine flag.
        self.conn.execute(
            "INSERT INTO agent_memory (namespace, key, value, updated_at, quarantined, quarantine_reason)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)
             ON CONFLICT(namespace, key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at,
                quarantined = 1,
                quarantine_reason = excluded.quarantine_reason",
            params![namespace, key, value, now, reason],
        )?;

        // Insert new FTS entry.
        let new_rowid: i64 = self
            .conn
            .prepare_cached(
                "SELECT rowid FROM agent_memory WHERE namespace = ?1 AND key = ?2",
            )?
            .query_row(params![namespace, key], |row| row.get(0))?;

        self.conn.execute(
            "INSERT INTO agent_memory_fts(rowid, namespace, key, value) VALUES(?1, ?2, ?3, ?4)",
            params![new_rowid, namespace, key, value],
        )?;

        Ok(())
    }

    /// Check whether a key is currently quarantined.
    pub fn is_quarantined(&self, namespace: &str, key: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT quarantined FROM agent_memory WHERE namespace = ?1 AND key = ?2",
        )?;

        let mut rows = stmt.query(params![namespace, key])?;
        match rows.next()? {
            Some(row) => {
                let flag: i64 = row.get(0)?;
                Ok(flag != 0)
            }
            None => Ok(false),
        }
    }

    /// Clear the quarantine flag on a key, making it visible to safe reads again.
    pub fn unquarantine(&self, namespace: &str, key: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE agent_memory SET quarantined = 0, quarantine_reason = NULL WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        )?;
        Ok(())
    }

    /// List all quarantined entries in a namespace.
    ///
    /// Returns `(key, value, reason)` tuples.
    pub fn list_quarantined(&self, namespace: &str) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, value, COALESCE(quarantine_reason, '') FROM agent_memory WHERE namespace = ?1 AND quarantined = 1 ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map(params![namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Get a value only if it is NOT quarantined. Returns `None` for
    /// missing keys and for quarantined keys.
    pub fn get_safe(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT value FROM agent_memory WHERE namespace = ?1 AND key = ?2 AND (quarantined IS NULL OR quarantined = 0)",
        )?;

        let mut rows = stmt.query(params![namespace, key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Refresh a memory entry, resetting its `updated_at` timestamp to now
    /// and incrementing its `access_count`.
    ///
    /// This should be called when a memory is recalled so that frequently
    /// accessed memories maintain higher relevance under temporal decay.
    /// Does nothing if the key does not exist.
    pub fn refresh(&self, namespace: &str, key: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "UPDATE agent_memory
             SET updated_at = ?1,
                 last_accessed = ?1,
                 access_count = COALESCE(access_count, 0) + 1
             WHERE namespace = ?2 AND key = ?3",
            params![now, namespace, key],
        )?;

        Ok(())
    }

    /// Full-text search that skips quarantined entries and returns timestamps.
    ///
    /// Returns `(key, value, score, updated_at)` tuples ordered by relevance.
    /// Quarantined entries are excluded from results to prevent injection
    /// of flagged content into agent context.
    pub fn search_safe(
        &self,
        namespace: &str,
        query: &str,
        limit: usize,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<(String, String, f64, String)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT m.key, m.value, f.rank, m.updated_at
             FROM agent_memory_fts f
             JOIN agent_memory m ON m.rowid = f.rowid
             WHERE agent_memory_fts MATCH ?1
               AND m.namespace = ?2
               AND (m.quarantined IS NULL OR m.quarantined = 0)",
        )?;

        let rows = stmt.query_map(params![query, namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut scored: Vec<(String, String, f64, String)> = Vec::new();
        for row in rows {
            let (key, value, rank, updated_at) = row?;
            let raw_score = -rank;
            let final_score = match half_life_hours {
                Some(hl) => raw_score * compute_decay(&updated_at, hl),
                None => raw_score,
            };
            scored.push((key, value, final_score, updated_at));
        }

        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored)
    }

    /// Vector similarity search that skips quarantined entries and returns timestamps.
    ///
    /// Returns `(key, value, similarity, updated_at)` tuples sorted by descending
    /// cosine similarity. Quarantined entries are excluded.
    pub fn search_similar_safe(
        &self,
        namespace: &str,
        query_embedding: &[f32],
        limit: usize,
        half_life_hours: Option<f64>,
    ) -> Result<Vec<(String, String, f32, String)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, value, embedding, updated_at FROM agent_memory
             WHERE namespace = ?1
               AND embedding IS NOT NULL
               AND (quarantined IS NULL OR quarantined = 0)",
        )?;

        let rows = stmt.query_map(params![namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut scored: Vec<(String, String, f32, String)> = Vec::new();
        for row in rows {
            let (key, value, blob, updated_at) = row?;
            let emb = blob_to_embedding(&blob);
            if emb.len() == query_embedding.len() {
                let raw_score = cosine_similarity(&emb, query_embedding);
                let final_score = match half_life_hours {
                    Some(hl) => raw_score * compute_decay(&updated_at, hl) as f32,
                    None => raw_score,
                };
                scored.push((key, value, final_score, updated_at));
            }
        }

        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (MemoryStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::new(&dir.path().join("memory.db")).unwrap();
        (store, dir)
    }

    #[test]
    fn get_set_delete_roundtrip() {
        let (store, _dir) = test_store();

        // Missing key returns None.
        assert_eq!(store.get("ns1", "key1").unwrap(), None);

        // Set and get.
        store.set("ns1", "key1", "value1").unwrap();
        assert_eq!(store.get("ns1", "key1").unwrap(), Some("value1".into()));

        // Overwrite.
        store.set("ns1", "key1", "value2").unwrap();
        assert_eq!(store.get("ns1", "key1").unwrap(), Some("value2".into()));

        // Delete returns true if existed.
        assert!(store.delete("ns1", "key1").unwrap());
        assert_eq!(store.get("ns1", "key1").unwrap(), None);

        // Delete returns false if not found.
        assert!(!store.delete("ns1", "key1").unwrap());
    }

    #[test]
    fn list_ordering() {
        let (store, _dir) = test_store();

        store.set("ns1", "a", "first").unwrap();
        // Ensure different timestamps by updating:
        store.set("ns1", "b", "second").unwrap();
        store.set("ns1", "c", "third").unwrap();

        let items = store.list("ns1", 10).unwrap();
        assert_eq!(items.len(), 3);
        // Most recently updated should be first.
        assert_eq!(items[0].0, "c");
        assert_eq!(items[2].0, "a");

        // Limit works.
        let items = store.list("ns1", 1).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn fts_search_ranking() {
        let (store, _dir) = test_store();

        store
            .set("ns1", "task1", "implement the login page with authentication")
            .unwrap();
        store
            .set("ns1", "task2", "fix the logout button")
            .unwrap();
        store
            .set("ns1", "task3", "login flow redesign and login form validation")
            .unwrap();

        let results = store.search("ns1", "login", 10, None).unwrap();
        assert!(!results.is_empty());

        // All results should mention login.
        for (key, value, _rank) in &results {
            assert!(
                value.contains("login") || key.contains("login"),
                "result should be relevant to 'login': {key} = {value}"
            );
        }
    }

    #[test]
    fn namespace_isolation() {
        let (store, _dir) = test_store();

        store.set("ns1", "key1", "value1").unwrap();
        store.set("ns2", "key1", "value2").unwrap();

        assert_eq!(store.get("ns1", "key1").unwrap(), Some("value1".into()));
        assert_eq!(store.get("ns2", "key1").unwrap(), Some("value2".into()));

        // List only returns entries from the requested namespace.
        let ns1_items = store.list("ns1", 100).unwrap();
        assert_eq!(ns1_items.len(), 1);
        assert_eq!(ns1_items[0].1, "value1");

        let ns2_items = store.list("ns2", 100).unwrap();
        assert_eq!(ns2_items.len(), 1);
        assert_eq!(ns2_items[0].1, "value2");
    }

    #[test]
    fn missing_key_returns_none() {
        let (store, _dir) = test_store();

        assert_eq!(store.get("nonexistent", "nokey").unwrap(), None);
    }

    #[test]
    fn search_empty_namespace() {
        let (store, _dir) = test_store();

        let results = store.search("empty", "anything", 10, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn set_updates_fts_correctly() {
        let (store, _dir) = test_store();

        store.set("ns1", "task", "old description about cats").unwrap();

        // Search for old content should find it.
        let results = store.search("ns1", "cats", 10, None).unwrap();
        assert_eq!(results.len(), 1);

        // Update the value.
        store.set("ns1", "task", "new description about dogs").unwrap();

        // Old content should no longer match.
        let results = store.search("ns1", "cats", 10, None).unwrap();
        assert_eq!(results.len(), 0);

        // New content should match.
        let results = store.search("ns1", "dogs", 10, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn delete_removes_from_fts() {
        let (store, _dir) = test_store();

        store.set("ns1", "task", "searchable content here").unwrap();
        let results = store.search("ns1", "searchable", 10, None).unwrap();
        assert_eq!(results.len(), 1);

        store.delete("ns1", "task").unwrap();

        let results = store.search("ns1", "searchable", 10, None).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_memory_store_embedding_storage() {
        let (store, _dir) = test_store();

        let embedding = vec![1.0_f32, 0.0, 0.0, 0.0];
        store
            .set_with_embedding("ns1", "vec_key", "vector value", &embedding)
            .unwrap();

        // The value should be retrievable via the normal get method.
        assert_eq!(
            store.get("ns1", "vec_key").unwrap(),
            Some("vector value".into())
        );

        // Searching with the same embedding should return the entry with score ~1.0.
        let results = store.search_similar("ns1", &embedding, 10, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "vec_key");
        assert_eq!(results[0].1, "vector value");
        assert!((results[0].2 - 1.0).abs() < 1e-6, "exact match should have similarity ~1.0");
    }

    #[test]
    fn test_memory_search_similar_ranking() {
        let (store, _dir) = test_store();

        // Three orthogonal-ish vectors in 4D space.
        let emb_a = vec![1.0_f32, 0.0, 0.0, 0.0]; // points along x
        let emb_b = vec![0.0_f32, 1.0, 0.0, 0.0]; // points along y (orthogonal to query)
        let emb_c = vec![0.9_f32, 0.1, 0.0, 0.0]; // mostly along x (close to query)

        store.set_with_embedding("ns1", "a", "item a", &emb_a).unwrap();
        store.set_with_embedding("ns1", "b", "item b", &emb_b).unwrap();
        store.set_with_embedding("ns1", "c", "item c", &emb_c).unwrap();

        // Query along x axis -- should rank a first, then c, then b.
        let query = vec![1.0_f32, 0.0, 0.0, 0.0];
        let results = store.search_similar("ns1", &query, 10, None).unwrap();
        assert_eq!(results.len(), 3);

        // "a" is an exact match (similarity 1.0), should be first.
        assert_eq!(results[0].0, "a");
        assert!((results[0].2 - 1.0).abs() < 1e-6);

        // "c" is close to the query, should be second.
        assert_eq!(results[1].0, "c");
        assert!(results[1].2 > 0.9);

        // "b" is orthogonal, should be last with similarity ~0.0.
        assert_eq!(results[2].0, "b");
        assert!(results[2].2.abs() < 1e-6);

        // Verify descending order.
        assert!(results[0].2 >= results[1].2);
        assert!(results[1].2 >= results[2].2);
    }

    // -- Temporal decay tests ------------------------------------------------

    #[test]
    fn test_decay_halves_at_half_life() {
        // A memory exactly one half-life old should have decay ~0.5.
        let half_life = 24.0; // 24 hours
        let one_half_life_ago = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let decay = compute_decay(&one_half_life_ago, half_life);
        assert!(
            (decay - 0.5).abs() < 0.05,
            "decay at exactly one half-life should be ~0.5, got {decay}"
        );
    }

    #[test]
    fn test_decay_zero_age_returns_one() {
        // A memory just created should have decay 1.0.
        let now = Utc::now().to_rfc3339();
        let decay = compute_decay(&now, 168.0);
        assert!(
            (decay - 1.0).abs() < 0.01,
            "decay of a just-created memory should be ~1.0, got {decay}"
        );
    }

    #[test]
    fn test_decay_affects_search_ranking() {
        // Older memories should rank lower than newer ones with the same raw relevance.
        let (store, _dir) = test_store();

        // Insert an "old" entry by manually setting a past timestamp.
        let old_time = (Utc::now() - chrono::Duration::hours(168)).to_rfc3339(); // 1 week old
        store.set("ns1", "old_login", "login page with authentication").unwrap();
        store.conn.execute(
            "UPDATE agent_memory SET updated_at = ?1 WHERE namespace = 'ns1' AND key = 'old_login'",
            params![old_time],
        ).unwrap();

        // Also update the FTS index is already in place from set().
        // Insert a "new" entry (timestamp is now).
        store.set("ns1", "new_login", "login page with authentication").unwrap();

        // Search with decay enabled (half-life = 168h = 1 week).
        let results = store.search("ns1", "login", 10, Some(168.0)).unwrap();
        assert!(results.len() >= 2, "should find both entries");

        // The new entry should rank higher (appear first).
        assert_eq!(
            results[0].0, "new_login",
            "newer entry should rank higher with decay enabled"
        );
        assert_eq!(
            results[1].0, "old_login",
            "older entry should rank lower with decay enabled"
        );
        // The new entry's score should be higher.
        assert!(
            results[0].2 > results[1].2,
            "newer entry score ({}) should exceed older entry score ({})",
            results[0].2,
            results[1].2
        );
    }

    #[test]
    fn test_refresh_resets_decay() {
        let (store, _dir) = test_store();

        // Insert a memory and then backdated it.
        store.set("ns1", "task", "important task details").unwrap();
        let old_time = (Utc::now() - chrono::Duration::hours(168)).to_rfc3339();
        store.conn.execute(
            "UPDATE agent_memory SET updated_at = ?1 WHERE namespace = 'ns1' AND key = 'task'",
            params![old_time],
        ).unwrap();

        // Verify it's old.
        let updated_before: String = store.conn.prepare_cached(
            "SELECT updated_at FROM agent_memory WHERE namespace = 'ns1' AND key = 'task'",
        ).unwrap().query_row([], |row| row.get(0)).unwrap();
        let decay_before = compute_decay(&updated_before, 168.0);
        assert!(
            decay_before < 0.6,
            "before refresh, decay should be low (~0.5), got {decay_before}"
        );

        // Refresh the entry.
        store.refresh("ns1", "task").unwrap();

        // Verify updated_at was reset to approximately now.
        let updated_after: String = store.conn.prepare_cached(
            "SELECT updated_at FROM agent_memory WHERE namespace = 'ns1' AND key = 'task'",
        ).unwrap().query_row([], |row| row.get(0)).unwrap();
        let decay_after = compute_decay(&updated_after, 168.0);
        assert!(
            (decay_after - 1.0).abs() < 0.01,
            "after refresh, decay should be ~1.0, got {decay_after}"
        );

        // Verify access_count was incremented.
        let access_count: i64 = store.conn.prepare_cached(
            "SELECT access_count FROM agent_memory WHERE namespace = 'ns1' AND key = 'task'",
        ).unwrap().query_row([], |row| row.get(0)).unwrap();
        assert_eq!(access_count, 1, "access_count should be 1 after one refresh");

        // Refresh again and check access_count increments.
        store.refresh("ns1", "task").unwrap();
        let access_count: i64 = store.conn.prepare_cached(
            "SELECT access_count FROM agent_memory WHERE namespace = 'ns1' AND key = 'task'",
        ).unwrap().query_row([], |row| row.get(0)).unwrap();
        assert_eq!(access_count, 2, "access_count should be 2 after two refreshes");
    }

    #[test]
    fn test_per_category_half_life() {
        // Different categories can have different decay rates via the half_life parameter.
        let half_life_short = 24.0; // 24 hours
        let half_life_long = 720.0; // 30 days

        let one_day_ago = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

        let decay_short = compute_decay(&one_day_ago, half_life_short);
        let decay_long = compute_decay(&one_day_ago, half_life_long);

        // With a 24h half-life, a 24h-old entry should have decay ~0.5.
        assert!(
            (decay_short - 0.5).abs() < 0.05,
            "short half-life: 24h-old entry should have decay ~0.5, got {decay_short}"
        );

        // With a 720h half-life, a 24h-old entry should still have high decay (~0.977).
        assert!(
            decay_long > 0.95,
            "long half-life: 24h-old entry should have decay >0.95, got {decay_long}"
        );

        // The long half-life should always produce a higher decay for the same age.
        assert!(
            decay_long > decay_short,
            "longer half-life should produce higher decay for same age: {decay_long} > {decay_short}"
        );
    }

    #[test]
    fn test_decay_never_negative() {
        // Security test: decay_factor must always be in [0.0, 1.0].

        // Test with a very old timestamp.
        let ancient = "2000-01-01T00:00:00+00:00";
        let decay = compute_decay(ancient, 1.0);
        assert!(
            (0.0..=1.0).contains(&decay),
            "very old timestamp decay should be in [0.0, 1.0], got {decay}"
        );
        assert!(decay >= 0.0, "decay must never be negative, got {decay}");

        // Test with a future timestamp.
        let future = (Utc::now() + chrono::Duration::hours(1000)).to_rfc3339();
        let decay = compute_decay(&future, 168.0);
        assert!(
            (0.0..=1.0).contains(&decay),
            "future timestamp decay should be in [0.0, 1.0], got {decay}"
        );

        // Test with zero half-life (edge case).
        let now = Utc::now().to_rfc3339();
        let decay = compute_decay(&now, 0.0);
        assert!(
            (0.0..=1.0).contains(&decay),
            "zero half-life decay should be in [0.0, 1.0], got {decay}"
        );

        // Test with negative half-life (edge case).
        let decay = compute_decay(&now, -1.0);
        assert!(
            (0.0..=1.0).contains(&decay),
            "negative half-life decay should be in [0.0, 1.0], got {decay}"
        );

        // Test with invalid timestamp.
        let decay = compute_decay("not-a-timestamp", 168.0);
        assert_eq!(
            decay, 1.0,
            "invalid timestamp should return 1.0 (fail-safe), got {decay}"
        );

        // Test with extremely small half-life and old entry.
        let old = (Utc::now() - chrono::Duration::hours(10000)).to_rfc3339();
        let decay = compute_decay(&old, 0.001);
        assert!(
            (0.0..=1.0).contains(&decay),
            "extreme decay scenario should be in [0.0, 1.0], got {decay}"
        );

        // Run a sweep of many half-life values and timestamps.
        for hours_ago in [0, 1, 24, 168, 720, 8760, 87600] {
            for hl in [0.001, 0.1, 1.0, 24.0, 168.0, 720.0, 8760.0] {
                let ts = (Utc::now() - chrono::Duration::hours(hours_ago)).to_rfc3339();
                let d = compute_decay(&ts, hl);
                assert!(
                    (0.0..=1.0).contains(&d),
                    "decay({hours_ago}h ago, hl={hl}) = {d} is outside [0.0, 1.0]"
                );
            }
        }
    }
}
