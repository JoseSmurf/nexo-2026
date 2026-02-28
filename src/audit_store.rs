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
        lines.push(serde_json::to_string(record).map_err(io::Error::other)?);
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
