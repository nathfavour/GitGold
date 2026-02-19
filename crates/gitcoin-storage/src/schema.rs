use rusqlite::Connection;

/// Initialize the storage database schema.
pub fn init_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS fragments (
            repo_hash   TEXT NOT NULL,
            fragment_id INTEGER NOT NULL,
            share_id    INTEGER NOT NULL,
            data        BLOB NOT NULL,
            data_hash   TEXT NOT NULL,
            stored_at   INTEGER NOT NULL,
            last_challenged INTEGER,
            PRIMARY KEY (repo_hash, fragment_id, share_id)
        );

        CREATE TABLE IF NOT EXISTS challenges (
            challenge_id    TEXT PRIMARY KEY,
            repo_hash       TEXT NOT NULL,
            fragment_id     INTEGER NOT NULL,
            success         INTEGER NOT NULL,
            response_time   INTEGER NOT NULL,
            challenged_at   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_fragments_repo
            ON fragments (repo_hash);

        CREATE INDEX IF NOT EXISTS idx_challenges_repo_fragment
            ON challenges (repo_hash, fragment_id);
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='fragments'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_schema_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap(); // Should not error
    }
}
