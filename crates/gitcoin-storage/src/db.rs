use gitcoin_core::error::StorageError;
use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::schema::init_schema;

/// Fragment metadata returned from queries.
#[derive(Debug, Clone)]
pub struct FragmentRecord {
    pub repo_hash: String,
    pub fragment_id: u32,
    pub share_id: u32,
    pub data: Vec<u8>,
    pub data_hash: String,
    pub stored_at: i64,
    pub last_challenged: Option<i64>,
}

/// SQLite-backed fragment store.
pub struct FragmentStore {
    conn: Connection,
}

impl FragmentStore {
    /// Open (or create) a fragment store at the given path.
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path).map_err(|e| StorageError::Database(e.to_string()))?;
        init_schema(&conn).map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Create an in-memory fragment store (for tests).
    pub fn in_memory() -> Result<Self, StorageError> {
        let conn =
            Connection::open_in_memory().map_err(|e| StorageError::Database(e.to_string()))?;
        init_schema(&conn).map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Store a fragment. Replaces any existing fragment with the same key.
    pub fn store_fragment(
        &self,
        repo_hash: &str,
        fragment_id: u32,
        share_id: u32,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let data_hash = gitcoin_crypto::hash::sha256_hex(data);
        let now = unix_now();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO fragments
                 (repo_hash, fragment_id, share_id, data, data_hash, stored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![repo_hash, fragment_id, share_id, data, data_hash, now],
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    /// Retrieve a specific fragment by (repo_hash, fragment_id, share_id).
    pub fn get_fragment(
        &self,
        repo_hash: &str,
        fragment_id: u32,
        share_id: u32,
    ) -> Result<FragmentRecord, StorageError> {
        self.conn
            .query_row(
                "SELECT repo_hash, fragment_id, share_id, data, data_hash, stored_at, last_challenged
                 FROM fragments
                 WHERE repo_hash = ?1 AND fragment_id = ?2 AND share_id = ?3",
                rusqlite::params![repo_hash, fragment_id, share_id],
                |row| {
                    Ok(FragmentRecord {
                        repo_hash: row.get(0)?,
                        fragment_id: row.get::<_, u32>(1)?,
                        share_id: row.get::<_, u32>(2)?,
                        data: row.get(3)?,
                        data_hash: row.get(4)?,
                        stored_at: row.get(5)?,
                        last_challenged: row.get(6)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StorageError::FragmentNotFound {
                    repo_hash: repo_hash.to_string(),
                    fragment_id,
                },
                other => StorageError::Database(other.to_string()),
            })
    }

    /// List all fragments for a given repo_hash.
    pub fn list_fragments(&self, repo_hash: &str) -> Result<Vec<FragmentRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT repo_hash, fragment_id, share_id, data, data_hash, stored_at, last_challenged
                 FROM fragments
                 WHERE repo_hash = ?1
                 ORDER BY fragment_id, share_id",
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let records = stmt
            .query_map(rusqlite::params![repo_hash], |row| {
                Ok(FragmentRecord {
                    repo_hash: row.get(0)?,
                    fragment_id: row.get::<_, u32>(1)?,
                    share_id: row.get::<_, u32>(2)?,
                    data: row.get(3)?,
                    data_hash: row.get(4)?,
                    stored_at: row.get(5)?,
                    last_challenged: row.get(6)?,
                })
            })
            .map_err(|e| StorageError::Database(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(records)
    }

    /// Delete a specific fragment.
    pub fn delete_fragment(
        &self,
        repo_hash: &str,
        fragment_id: u32,
        share_id: u32,
    ) -> Result<bool, StorageError> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM fragments WHERE repo_hash = ?1 AND fragment_id = ?2 AND share_id = ?3",
                rusqlite::params![repo_hash, fragment_id, share_id],
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(rows > 0)
    }

    /// Record a challenge result.
    pub fn record_challenge(
        &self,
        challenge_id: &str,
        repo_hash: &str,
        fragment_id: u32,
        success: bool,
        response_time_ms: u64,
    ) -> Result<(), StorageError> {
        let now = unix_now();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO challenges
                 (challenge_id, repo_hash, fragment_id, success, response_time, challenged_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![challenge_id, repo_hash, fragment_id, success, response_time_ms, now],
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Update last_challenged on the fragment
        self.conn
            .execute(
                "UPDATE fragments SET last_challenged = ?1
                 WHERE repo_hash = ?2 AND fragment_id = ?3",
                rusqlite::params![now, repo_hash, fragment_id],
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> FragmentStore {
        FragmentStore::in_memory().unwrap()
    }

    #[test]
    fn test_store_and_get() {
        let store = test_store();
        let data = b"fragment data here";
        store
            .store_fragment("abc123", 0, 1, data)
            .unwrap();

        let record = store.get_fragment("abc123", 0, 1).unwrap();
        assert_eq!(record.data, data);
        assert_eq!(record.repo_hash, "abc123");
        assert_eq!(record.fragment_id, 0);
        assert_eq!(record.share_id, 1);
    }

    #[test]
    fn test_get_not_found() {
        let store = test_store();
        let result = store.get_fragment("nonexistent", 0, 0);
        assert!(matches!(
            result,
            Err(StorageError::FragmentNotFound { .. })
        ));
    }

    #[test]
    fn test_list_fragments() {
        let store = test_store();
        store.store_fragment("repo1", 0, 1, b"a").unwrap();
        store.store_fragment("repo1", 0, 2, b"b").unwrap();
        store.store_fragment("repo1", 1, 1, b"c").unwrap();
        store.store_fragment("repo2", 0, 1, b"d").unwrap();

        let frags = store.list_fragments("repo1").unwrap();
        assert_eq!(frags.len(), 3);
    }

    #[test]
    fn test_delete_fragment() {
        let store = test_store();
        store.store_fragment("repo1", 0, 1, b"data").unwrap();
        assert!(store.delete_fragment("repo1", 0, 1).unwrap());
        assert!(!store.delete_fragment("repo1", 0, 1).unwrap()); // already deleted
    }

    #[test]
    fn test_record_challenge() {
        let store = test_store();
        store.store_fragment("repo1", 0, 1, b"data").unwrap();
        store
            .record_challenge("chal-1", "repo1", 0, true, 150)
            .unwrap();

        let record = store.get_fragment("repo1", 0, 1).unwrap();
        assert!(record.last_challenged.is_some());
    }

    #[test]
    fn test_replace_fragment() {
        let store = test_store();
        store.store_fragment("repo1", 0, 1, b"old").unwrap();
        store.store_fragment("repo1", 0, 1, b"new").unwrap();

        let record = store.get_fragment("repo1", 0, 1).unwrap();
        assert_eq!(record.data, b"new");
    }
}
