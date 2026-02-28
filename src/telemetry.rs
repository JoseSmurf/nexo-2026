use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::FinalDecision;

const LATENCY_SAMPLE_CAP: usize = 2048;

#[derive(Debug, Default)]
pub struct Metrics {
    requests_total: AtomicU64,
    requests_error: AtomicU64,
    approved_total: AtomicU64,
    flagged_total: AtomicU64,
    blocked_total: AtomicU64,
    total_latency_ns: AtomicU64,
    unauthorized_total: AtomicU64,
    request_timeout_total: AtomicU64,
    conflict_total: AtomicU64,
    too_many_requests_total: AtomicU64,
    latency_samples_ns: Mutex<Vec<u64>>,
}

impl Metrics {
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn observe_success(&self, decision: FinalDecision, latency_ns: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);
        self.observe_latency_sample(latency_ns);
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
        self.observe_latency_sample(latency_ns);
    }

    pub fn observe_http_status(&self, status_code: u16) {
        match status_code {
            401 => {
                self.unauthorized_total.fetch_add(1, Ordering::Relaxed);
            }
            408 => {
                self.request_timeout_total.fetch_add(1, Ordering::Relaxed);
            }
            409 => {
                self.conflict_total.fetch_add(1, Ordering::Relaxed);
            }
            429 => {
                self.too_many_requests_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn observe_latency_sample(&self, latency_ns: u64) {
        if let Ok(mut samples) = self.latency_samples_ns.lock() {
            if samples.len() >= LATENCY_SAMPLE_CAP {
                let drop_n = (LATENCY_SAMPLE_CAP / 8).max(1);
                let len = samples.len();
                samples.drain(0..drop_n.min(len));
            }
            samples.push(latency_ns);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let total = self.requests_total.load(Ordering::Relaxed);
        let total_latency_ns = self.total_latency_ns.load(Ordering::Relaxed);
        let (p95_latency_ns, p99_latency_ns) =
            if let Ok(samples_guard) = self.latency_samples_ns.lock() {
                percentile_pair(&samples_guard)
            } else {
                (0.0, 0.0)
            };
        MetricsSnapshot {
            requests_total: total,
            requests_error: self.requests_error.load(Ordering::Relaxed),
            approved_total: self.approved_total.load(Ordering::Relaxed),
            flagged_total: self.flagged_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            unauthorized_total: self.unauthorized_total.load(Ordering::Relaxed),
            request_timeout_total: self.request_timeout_total.load(Ordering::Relaxed),
            conflict_total: self.conflict_total.load(Ordering::Relaxed),
            too_many_requests_total: self.too_many_requests_total.load(Ordering::Relaxed),
            avg_latency_ns: if total == 0 {
                0.0
            } else {
                total_latency_ns as f64 / total as f64
            },
            p95_latency_ns,
            p99_latency_ns,
        }
    }
}

fn percentile_pair(samples: &[u64]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p95_idx = (((sorted.len() - 1) as f64) * 0.95).round() as usize;
    let p99_idx = (((sorted.len() - 1) as f64) * 0.99).round() as usize;
    (sorted[p95_idx] as f64, sorted[p99_idx] as f64)
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_error: u64,
    pub approved_total: u64,
    pub flagged_total: u64,
    pub blocked_total: u64,
    pub unauthorized_total: u64,
    pub request_timeout_total: u64,
    pub conflict_total: u64,
    pub too_many_requests_total: u64,
    pub avg_latency_ns: f64,
    pub p95_latency_ns: f64,
    pub p99_latency_ns: f64,
}
