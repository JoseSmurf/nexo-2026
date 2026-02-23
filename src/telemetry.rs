use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;

use crate::FinalDecision;

#[derive(Debug, Default)]
pub struct Metrics {
    requests_total: AtomicU64,
    requests_error: AtomicU64,
    approved_total: AtomicU64,
    flagged_total: AtomicU64,
    blocked_total: AtomicU64,
    total_latency_ns: AtomicU64,
}

impl Metrics {
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn observe_success(&self, decision: FinalDecision, latency_ns: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);
        match decision {
            FinalDecision::Approved => self.approved_total.fetch_add(1, Ordering::Relaxed),
            FinalDecision::Flagged => self.flagged_total.fetch_add(1, Ordering::Relaxed),
            FinalDecision::Blocked => self.blocked_total.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn observe_error(&self, latency_ns: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.requests_error.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let total = self.requests_total.load(Ordering::Relaxed);
        let total_latency_ns = self.total_latency_ns.load(Ordering::Relaxed);
        MetricsSnapshot {
            requests_total: total,
            requests_error: self.requests_error.load(Ordering::Relaxed),
            approved_total: self.approved_total.load(Ordering::Relaxed),
            flagged_total: self.flagged_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            avg_latency_ns: if total == 0 {
                0.0
            } else {
                total_latency_ns as f64 / total as f64
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_error: u64,
    pub approved_total: u64,
    pub flagged_total: u64,
    pub blocked_total: u64,
    pub avg_latency_ns: f64,
}
