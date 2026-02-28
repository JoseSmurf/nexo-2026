use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::FinalDecision;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub request_id: String,
    pub calc_version: Option<String>,
    pub profile_name: String,
    pub profile_version: String,
    pub timestamp_utc_ms: u64,
    pub user_id: String,
    pub amount_cents: u64,
    pub risk_bps: u16,
    pub final_decision: FinalDecision,
    pub trace: serde_json::Value,
    pub audit_hash: String,
    #[serde(default = "default_hash_algo")]
    pub hash_algo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha3_shadow: Option<String>,
    #[serde(default)]
    pub prev_record_hash: Option<String>,
    #[serde(default)]
    pub record_hash: Option<String>,
}

fn default_hash_algo() -> String {
    "blake3".to_string()
}

#[derive(Clone)]
pub struct AuditStore {
    inner: Arc<AuditStoreInner>,
}

struct AuditStoreInner {
    path: PathBuf,
    max_records: usize,
    lock: Mutex<()>,
}

impl AuditStore {
    pub fn new(path: impl Into<PathBuf>, max_records: usize) -> Self {
        Self {
            inner: Arc::new(AuditStoreInner {
                path: path.into(),
                max_records,
                lock: Mutex::new(()),
            }),
        }
    }

    pub fn ready(&self) -> io::Result<()> {
        if let Some(parent) = self.inner.path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !self.inner.path.exists() {
            fs::write(&self.inner.path, "")?;
        }
        Ok(())
    }

    pub fn append(&self, record: &AuditRecord) -> io::Result<()> {
        self.ready()?;
        let _guard = self.inner.lock.lock().expect("audit store lock poisoned");
        let content = fs::read_to_string(&self.inner.path).unwrap_or_default();
        let mut lines: Vec<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect();
        let prev_hash = lines
            .last()
            .and_then(|line| serde_json::from_str::<AuditRecord>(line).ok())
            .and_then(|r| r.record_hash.clone());

        let mut chained = record.clone();
        chained.prev_record_hash = prev_hash;
        chained.record_hash = Some(compute_record_hash(&chained));

        lines.push(serde_json::to_string(&chained).map_err(io::Error::other)?);
        if lines.len() > self.inner.max_records {
            let keep_from = lines.len() - self.inner.max_records;
            lines = lines.split_off(keep_from);
        }
        let mut output = lines.join("\n");
        if !output.is_empty() {
            output.push('\n');
        }
        let tmp_path = self.inner.path.with_extension("jsonl.tmp");
        fs::write(&tmp_path, output)?;
        fs::rename(tmp_path, &self.inner.path)?;
        Ok(())
    }

    pub fn recent(&self, limit: usize) -> io::Result<Vec<AuditRecord>> {
        self.ready()?;
        let _guard = self.inner.lock.lock().expect("audit store lock poisoned");
        let content = fs::read_to_string(&self.inner.path).unwrap_or_default();
        let mut records = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<AuditRecord>(line) {
                records.push(rec);
            }
        }
        let keep = limit.min(records.len());
        Ok(records.into_iter().rev().take(keep).collect())
    }
}

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

fn compute_record_hash(record: &AuditRecord) -> String {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"audit_record_v2");
    hash_field(&mut h, b"request_id", record.request_id.as_bytes());
    hash_field(&mut h, b"profile_name", record.profile_name.as_bytes());
    hash_field(
        &mut h,
        b"profile_version",
        record.profile_version.as_bytes(),
    );
    hash_field(
        &mut h,
        b"calc_version",
        record.calc_version.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(&mut h, b"user_id", record.user_id.as_bytes());
    hash_field(&mut h, b"audit_hash", record.audit_hash.as_bytes());
    hash_field(&mut h, b"hash_algo", record.hash_algo.as_bytes());
    hash_field(
        &mut h,
        b"sha3_shadow",
        record.sha3_shadow.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(
        &mut h,
        b"final_decision",
        format!("{:?}", record.final_decision).as_bytes(),
    );
    hash_field(
        &mut h,
        b"trace_json",
        serde_json::to_string(&record.trace)
            .unwrap_or_else(|_| "[]".to_string())
            .as_bytes(),
    );
    hash_field(
        &mut h,
        b"prev_record_hash",
        record.prev_record_hash.as_deref().unwrap_or("").as_bytes(),
    );
    h.update(&record.timestamp_utc_ms.to_le_bytes());
    h.update(&record.amount_cents.to_le_bytes());
    h.update(&record.risk_bps.to_le_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FinalDecision;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_record(request_id: &str) -> AuditRecord {
        AuditRecord {
            request_id: request_id.to_string(),
            calc_version: Some("plca_v1".to_string()),
            profile_name: "br_default_v1".to_string(),
            profile_version: "2026.02".to_string(),
            timestamp_utc_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_millis() as u64,
            user_id: "u1".to_string(),
            amount_cents: 150_000,
            risk_bps: 1200,
            final_decision: FinalDecision::Approved,
            trace: serde_json::json!(["Approved"]),
            audit_hash: "abcd".repeat(16),
            hash_algo: "blake3".to_string(),
            sha3_shadow: None,
            prev_record_hash: None,
            record_hash: None,
        }
    }

    #[test]
    fn append_adds_chain_fields() {
        let path = std::env::temp_dir().join(format!(
            "nexo_audit_chain_{}.jsonl",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let store = AuditStore::new(&path, 10);
        let r1 = sample_record("req-1");
        let r2 = sample_record("req-2");

        store.append(&r1).expect("append r1");
        store.append(&r2).expect("append r2");

        let recent = store.recent(10).expect("recent");
        assert_eq!(recent.len(), 2);
        let newest = &recent[0];
        let older = &recent[1];

        assert!(older.record_hash.is_some());
        assert_eq!(older.prev_record_hash, None);
        assert!(newest.record_hash.is_some());
        assert_eq!(newest.prev_record_hash, older.record_hash);

        let _ = fs::remove_file(path);
    }
}
