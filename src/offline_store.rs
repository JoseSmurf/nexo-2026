use rusqlite::{params, Connection, OptionalExtension};

use crate::message::{content_hash, event_hash, CanonicalMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreInsertStatus {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub event_hash: String,
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub content: Vec<u8>,
}

pub struct OfflineStore {
    conn: Connection,
}

impl OfflineStore {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn insert_message(
        &self,
        msg: &CanonicalMessage,
        now_ms: u64,
        seen_ttl_ms: u64,
    ) -> Result<StoreInsertStatus, rusqlite::Error> {
        self.purge_seen_expired(now_ms)?;
        let ehash = event_hash(msg);
        let chash = content_hash(&msg.content);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO messages(event_hash, content_hash, sender_id, timestamp_utc_ms, content_blob)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ehash,
                chash,
                msg.sender_id,
                msg.timestamp_utc_ms as i64,
                msg.content
            ],
        )?;
        if inserted == 0 {
            return Ok(StoreInsertStatus::Duplicate);
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO seen_hashes(event_hash, expires_at_utc_ms) VALUES (?1, ?2)",
            params![ehash, now_ms.saturating_add(seen_ttl_ms) as i64],
        )?;
        Ok(StoreInsertStatus::Inserted)
    }

    pub fn is_seen(&self, event_hash: &str, now_ms: u64) -> Result<bool, rusqlite::Error> {
        self.purge_seen_expired(now_ms)?;
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM seen_hashes WHERE event_hash = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![event_hash])?;
        Ok(rows.next()?.is_some())
    }

    pub fn last_messages(&self, limit: usize) -> Result<Vec<StoredMessage>, rusqlite::Error> {
        if limit == 0 {
            return Err(rusqlite::Error::InvalidParameterName("limit".to_string()));
        }
        let limit = limit.min(1000);
        let mut stmt = self.conn.prepare(
            "SELECT event_hash, sender_id, timestamp_utc_ms, content_blob
             FROM messages
             ORDER BY rowid DESC
             LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![limit as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(StoredMessage {
                event_hash: row.get(0)?,
                sender_id: row.get(1)?,
                timestamp_utc_ms: row.get(2)?,
                content: row.get(3)?,
            });
        }
        Ok(out)
    }

    pub fn next_nonce(&self, sender_id: &str) -> Result<u64, rusqlite::Error> {
        if sender_id.trim().is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "sender_id".to_string(),
            ));
        }

        self.conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")?;

        let result = (|| -> Result<u64, rusqlite::Error> {
            let last: Option<i64> = self
                .conn
                .query_row(
                    "SELECT last_nonce FROM sender_counters WHERE sender_id = ?1",
                    params![sender_id],
                    |row| row.get(0),
                )
                .optional()?;

            let next = match last {
                Some(last_nonce) => last_nonce.checked_add(1).ok_or_else(|| {
                    rusqlite::Error::InvalidParameterName("nonce_overflow".to_string())
                })?,
                None => {
                    self.conn.execute(
                        "INSERT INTO sender_counters(sender_id, last_nonce) VALUES (?1, 0)",
                        params![sender_id],
                    )?;
                    1
                }
            };

            self.conn.execute(
                "UPDATE sender_counters SET last_nonce = ?2 WHERE sender_id = ?1",
                params![sender_id, next],
            )?;

            Ok(next as u64)
        })();

        match result {
            Ok(next) => {
                self.conn.execute_batch("COMMIT;")?;
                Ok(next)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                Err(err)
            }
        }
    }

    fn purge_seen_expired(&self, now_ms: u64) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM seen_hashes WHERE expires_at_utc_ms <= ?1",
            params![now_ms as i64],
        )?;
        Ok(())
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS messages (
                event_hash TEXT PRIMARY KEY NOT NULL,
                content_hash TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                timestamp_utc_ms INTEGER NOT NULL,
                content_blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seen_hashes (
                event_hash TEXT PRIMARY KEY NOT NULL,
                expires_at_utc_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_seen_hashes_expires ON seen_hashes(expires_at_utc_ms);
            CREATE TABLE IF NOT EXISTS sender_counters (
                sender_id TEXT PRIMARY KEY NOT NULL,
                last_nonce INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_by_event_hash_works() {
        let store = OfflineStore::open_in_memory().expect("store");
        let msg = CanonicalMessage::new("alice", 100, b"ping").expect("msg");

        let first = store.insert_message(&msg, 1_000, 500).expect("insert");
        assert_eq!(first, StoreInsertStatus::Inserted);

        let second = store.insert_message(&msg, 1_100, 500).expect("insert");
        assert_eq!(second, StoreInsertStatus::Duplicate);
    }

    #[test]
    fn seen_hash_ttl_expires() {
        let store = OfflineStore::open_in_memory().expect("store");
        let msg = CanonicalMessage::new("alice", 100, b"ping").expect("msg");
        let ehash = event_hash(&msg);

        let status = store.insert_message(&msg, 1_000, 100).expect("insert");
        assert_eq!(status, StoreInsertStatus::Inserted);
        assert!(store.is_seen(&ehash, 1_050).expect("seen"));
        assert!(!store.is_seen(&ehash, 1_100).expect("seen"));
    }

    #[test]
    fn next_nonce_is_monotonic_per_sender() {
        let store = OfflineStore::open_in_memory().expect("store");
        let n1 = store.next_nonce("alice").expect("n1");
        let n2 = store.next_nonce("alice").expect("n2");
        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
    }
}
