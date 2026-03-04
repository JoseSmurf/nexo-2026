use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use rusqlite::{params, Connection, OptionalExtension};

use crate::message::{
    content_hash, content_hash_bytes, event_hash, event_hash_bytes_from_parts, CanonicalMessage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreInsertStatus {
    Inserted,
    Duplicate,
}

pub struct RawMessageInput<'a> {
    pub sender_id: &'a str,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub content: &'a [u8],
    pub channel: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub event_hash: String,
    pub sender_id: String,
    pub channel: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
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
        self.insert_message_with_channel(msg, "global", now_ms, seen_ttl_ms)
    }

    pub fn insert_message_with_channel(
        &self,
        msg: &CanonicalMessage,
        channel: &str,
        now_ms: u64,
        seen_ttl_ms: u64,
    ) -> Result<StoreInsertStatus, rusqlite::Error> {
        validate_channel(channel)?;
        self.purge_seen_expired(now_ms)?;
        let ehash = event_hash(msg);
        let chash = content_hash(&msg.content);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO messages(event_hash, content_hash, sender_id, channel, timestamp_utc_ms, nonce, content_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ehash,
                chash,
                msg.sender_id,
                channel,
                msg.timestamp_utc_ms as i64,
                msg.nonce as i64,
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

    pub fn insert_raw_message_with_channel(
        &self,
        input: RawMessageInput<'_>,
        now_ms: u64,
        seen_ttl_ms: u64,
    ) -> Result<StoreInsertStatus, rusqlite::Error> {
        validate_channel(input.channel)?;
        self.purge_seen_expired(now_ms)?;
        let chash = content_hash(input.content);
        let chash_bytes = content_hash_bytes(input.content);
        let ehash_bytes = event_hash_bytes_from_parts(
            input.sender_id,
            input.timestamp_utc_ms,
            input.nonce,
            &chash_bytes,
        );
        let ehash = blake3::Hash::from(ehash_bytes).to_hex().to_string();
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO messages(event_hash, content_hash, sender_id, channel, timestamp_utc_ms, nonce, content_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ehash,
                chash,
                input.sender_id,
                input.channel,
                input.timestamp_utc_ms as i64,
                input.nonce as i64,
                input.content
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

    pub fn mark_seen(
        &self,
        event_hash: &str,
        expires_at_utc_ms: u64,
    ) -> Result<(), rusqlite::Error> {
        if event_hash.trim().is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "event_hash".to_string(),
            ));
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO seen_hashes(event_hash, expires_at_utc_ms) VALUES (?1, ?2)",
            params![event_hash, expires_at_utc_ms as i64],
        )?;
        Ok(())
    }

    pub fn is_forwarded(&self, event_hash: &str) -> Result<bool, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM forwarded_hashes WHERE event_hash = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![event_hash])?;
        Ok(rows.next()?.is_some())
    }

    pub fn mark_forwarded(
        &self,
        event_hash: &str,
        forwarded_at_ms: u64,
    ) -> Result<(), rusqlite::Error> {
        if event_hash.trim().is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "event_hash".to_string(),
            ));
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO forwarded_hashes(event_hash, forwarded_at_ms) VALUES (?1, ?2)",
            params![event_hash, forwarded_at_ms as i64],
        )?;
        Ok(())
    }

    pub fn last_messages(&self, limit: usize) -> Result<Vec<StoredMessage>, rusqlite::Error> {
        if limit == 0 {
            return Err(rusqlite::Error::InvalidParameterName("limit".to_string()));
        }
        let limit = limit.min(1000);
        let mut stmt = self.conn.prepare(
            "SELECT event_hash, sender_id, channel, timestamp_utc_ms, nonce, content_blob
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
                channel: row.get(2)?,
                timestamp_utc_ms: row.get(3)?,
                nonce: row.get(4)?,
                content: row.get(5)?,
            });
        }
        Ok(out)
    }

    pub fn messages_since(
        &self,
        since_ts_ms: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, rusqlite::Error> {
        if limit == 0 {
            return Err(rusqlite::Error::InvalidParameterName("limit".to_string()));
        }
        let limit = limit.min(1000);
        let mut stmt = self.conn.prepare(
            "SELECT event_hash, sender_id, channel, timestamp_utc_ms, nonce, content_blob
             FROM messages
             WHERE timestamp_utc_ms >= ?1
             ORDER BY timestamp_utc_ms ASC, rowid ASC
             LIMIT ?2",
        )?;
        let mut rows = stmt.query(params![since_ts_ms as i64, limit as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(StoredMessage {
                event_hash: row.get(0)?,
                sender_id: row.get(1)?,
                channel: row.get(2)?,
                timestamp_utc_ms: row.get(3)?,
                nonce: row.get(4)?,
                content: row.get(5)?,
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

    pub fn get_or_create_identity(&self) -> Result<([u8; 32], [u8; 64]), rusqlite::Error> {
        let found: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT pubkey, seckey FROM node_identity WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((pubkey, seckey)) = found {
            if pubkey.len() != 32 || seckey.len() != 64 {
                return Err(rusqlite::Error::InvalidParameterName(
                    "invalid node_identity length".to_string(),
                ));
            }
            let mut p = [0u8; 32];
            let mut s = [0u8; 64];
            p.copy_from_slice(&pubkey);
            s.copy_from_slice(&seckey);
            return Ok((p, s));
        }

        let mut seed = [0u8; 32];
        getrandom(&mut seed).map_err(|_| {
            rusqlite::Error::InvalidParameterName("identity_rng_failed".to_string())
        })?;
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        let seckey = signing.to_keypair_bytes();

        self.conn.execute(
            "INSERT INTO node_identity(id, pubkey, seckey) VALUES (1, ?1, ?2)",
            params![pubkey.to_vec(), seckey.to_vec()],
        )?;
        Ok((pubkey, seckey))
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
                channel TEXT NOT NULL DEFAULT 'global',
                timestamp_utc_ms INTEGER NOT NULL,
                nonce INTEGER NOT NULL,
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
            CREATE TABLE IF NOT EXISTS node_identity (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                pubkey BLOB NOT NULL,
                seckey BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS forwarded_hashes (
                event_hash TEXT PRIMARY KEY NOT NULL,
                forwarded_at_ms INTEGER NOT NULL
            );
            "#,
        )?;
        match self.conn.execute(
            "ALTER TABLE messages ADD COLUMN nonce INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
                if msg.contains("duplicate column name") => {}
            Err(e) => return Err(e),
        }
        match self.conn.execute(
            "ALTER TABLE messages ADD COLUMN channel TEXT NOT NULL DEFAULT 'global'",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
                if msg.contains("duplicate column name") => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

fn validate_channel(channel: &str) -> Result<(), rusqlite::Error> {
    if channel == "global" || channel == "ai" {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidParameterName("channel".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn replay_is_blocked_after_store_reopen() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nexo_seen_replay_{uniq}.db"));
        let msg = CanonicalMessage::new_with_nonce("alice", 100, 7, b"ping").expect("msg");
        let ehash = event_hash(&msg);

        {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store open");
            let status = store.insert_message(&msg, 1_000, 10_000).expect("insert");
            assert_eq!(status, StoreInsertStatus::Inserted);
        }

        {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store reopen");
            assert!(store.is_seen(&ehash, 1_100).expect("seen after reopen"));
            let status = store
                .insert_message(&msg, 1_100, 10_000)
                .expect("insert duplicate");
            assert_eq!(status, StoreInsertStatus::Duplicate);
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_identity_persists_across_reopen() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nexo_identity_{uniq}.db"));

        let (pubkey_a, seckey_a) = {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store open");
            store.get_or_create_identity().expect("identity")
        };

        let (pubkey_b, seckey_b) = {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store reopen");
            store.get_or_create_identity().expect("identity")
        };

        assert_eq!(pubkey_a, pubkey_b);
        assert_eq!(seckey_a, seckey_b);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn forwarded_hash_is_persistent() {
        let store = OfflineStore::open_in_memory().expect("store");
        assert!(!store.is_forwarded("abc").expect("not forwarded"));
        store.mark_forwarded("abc", 123).expect("mark");
        assert!(store.is_forwarded("abc").expect("forwarded"));
    }

    #[test]
    fn ai_channel_is_persisted() {
        let store = OfflineStore::open_in_memory().expect("store");
        let msg = CanonicalMessage::new_with_nonce("alice", 100, 1, b"prompt").expect("msg");
        let status = store
            .insert_message_with_channel(&msg, "ai", 1000, 1000)
            .expect("insert");
        assert_eq!(status, StoreInsertStatus::Inserted);
        let rows = store.last_messages(1).expect("rows");
        assert_eq!(rows[0].channel, "ai");
    }
}
