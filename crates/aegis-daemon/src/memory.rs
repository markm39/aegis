//! SQLite-backed key-value memory store for agent context.
//!
//! Provides per-namespace key-value storage with full-text search (FTS5)
//! and optional vector embeddings for similarity search. Reuses the
//! existing rusqlite dependency from aegis-ledger.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::embeddings::{blob_to_embedding, cosine_similarity, embedding_to_blob};

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

    /// Full-text search within a namespace. Returns (key, value, rank) tuples
    /// ordered by FTS5 relevance (lower rank = more relevant).
    pub fn search(
        &self,
        namespace: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(String, String, f64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT m.key, m.value, f.rank
             FROM agent_memory_fts f
             JOIN agent_memory m ON m.rowid = f.rowid
             WHERE agent_memory_fts MATCH ?1
               AND m.namespace = ?2
             ORDER BY f.rank
             LIMIT ?3",
        )?;

        // FTS5 match query. We prefix-match on the value column.
        let rows = stmt.query_map(params![query, namespace, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
            ))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
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
    pub fn search_similar(
        &self,
        namespace: &str,
        query_embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(String, String, f32)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT key, value, embedding FROM agent_memory WHERE namespace = ?1 AND embedding IS NOT NULL",
        )?;

        let rows = stmt.query_map(params![namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;

        let mut scored: Vec<(String, String, f32)> = Vec::new();
        for row in rows {
            let (key, value, blob) = row?;
            let emb = blob_to_embedding(&blob);
            if emb.len() == query_embedding.len() {
                let score = cosine_similarity(&emb, query_embedding);
                scored.push((key, value, score));
            }
        }

        // Sort by similarity descending.
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

        let results = store.search("ns1", "login", 10).unwrap();
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

        let results = store.search("empty", "anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn set_updates_fts_correctly() {
        let (store, _dir) = test_store();

        store.set("ns1", "task", "old description about cats").unwrap();

        // Search for old content should find it.
        let results = store.search("ns1", "cats", 10).unwrap();
        assert_eq!(results.len(), 1);

        // Update the value.
        store.set("ns1", "task", "new description about dogs").unwrap();

        // Old content should no longer match.
        let results = store.search("ns1", "cats", 10).unwrap();
        assert_eq!(results.len(), 0);

        // New content should match.
        let results = store.search("ns1", "dogs", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn delete_removes_from_fts() {
        let (store, _dir) = test_store();

        store.set("ns1", "task", "searchable content here").unwrap();
        let results = store.search("ns1", "searchable", 10).unwrap();
        assert_eq!(results.len(), 1);

        store.delete("ns1", "task").unwrap();

        let results = store.search("ns1", "searchable", 10).unwrap();
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
        let results = store.search_similar("ns1", &embedding, 10).unwrap();
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
        let results = store.search_similar("ns1", &query, 10).unwrap();
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
}
